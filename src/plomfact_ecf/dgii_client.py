"""Cliente de los servicios web oficiales de la DGII.

Las URL, rutas, métodos, nombres de parámetros y de campos se leen de la especificación
verificada (spec.py). El cliente:
  * usa solo HTTPS con verificación TLS obligatoria y tiempos de espera explícitos;
  * se autentica con el flujo de semilla firmada y renueva el token antes de su expiración;
  * distingue fallos "seguros" (la solicitud no salió) de fallos "ambiguos" (pudo llegar a la
    DGII), para que la cola nunca retransmita a ciegas un comprobante.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from lxml import etree
from urllib3.exceptions import NewConnectionError

from .errors import DgiiAuthError, DgiiTransportError, SpecNotVerifiedError
from .spec import Ambiente, DgiiSpec
from .xmlsign import Signer, parse_xml


@dataclass
class DgiiResponse:
    status_code: int
    body: bytes
    data: dict[str, Any] = field(default_factory=dict)
    request_summary: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str) -> Any:
        return _find_key(self.data, key)


def _find_key(data: Any, key: str) -> Any:
    """Busca un campo sin distinguir mayúsculas (JSON o XML convertido)."""
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() == key.lower():
                return v
        for v in data.values():
            r = _find_key(v, key)
            if r is not None:
                return r
    elif isinstance(data, list):
        for v in data:
            r = _find_key(v, key)
            if r is not None:
                return r
    return None


def _parse_body(body: bytes) -> dict[str, Any]:
    if not body.strip():
        return {}
    try:
        v = json.loads(body.decode("utf-8-sig"))
        return v if isinstance(v, dict) else {"items": v}
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        return _xml_to_dict(parse_xml(body))
    except Exception:
        return {}


def _xml_to_dict(el: etree._Element) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for child in el:
        if not isinstance(child.tag, str):
            continue
        name = etree.QName(child).localname
        val: Any = _xml_to_dict(child) if len(child) else (child.text or "").strip()
        if name in out:
            if not isinstance(out[name], list):
                out[name] = [out[name]]
            out[name].append(val)
        else:
            out[name] = val
    return out


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    v = re.sub(r"(\.\d{6})\d+", r"\1", value.strip())
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class DgiiClient:
    def __init__(self, spec: DgiiSpec, ambiente: Ambiente, signer: Signer,
                 session: requests.Session | None = None, timeout: tuple[float, float] = (10, 60)):
        self.spec = spec
        self.ambiente = ambiente
        self.signer = signer
        self.session = session or requests.Session()
        self.timeout = timeout
        self._token: str | None = None
        self._token_expira: datetime | None = None

    # ---------------------------------------------------------------- HTTP
    def _url(self, ruta: str) -> str:
        if ruta.startswith("https://"):
            return ruta
        if ruta.startswith("http://"):
            raise SpecNotVerifiedError("Ruta no segura (http) en la especificación")
        return f"{self.spec.base_url(self.ambiente)}/{ruta.lstrip('/')}"

    def _request(self, metodo: str, ruta: str, *, auth: bool, params: dict | None = None,
                 files: dict | None = None, retry_auth: bool = True) -> DgiiResponse:
        headers = {"Accept": "application/json, application/xml"}
        if auth:
            headers[self.spec.campo("encabezado_token")] = (
                self.spec.section("respuestas").get("prefijo_token", "") + self.token())
        url = self._url(ruta)
        try:
            r = self.session.request(metodo, url, params=params, files=files, headers=headers,
                                     timeout=self.timeout, verify=True, allow_redirects=False)
        except requests.exceptions.ConnectTimeout as exc:
            raise DgiiTransportError(f"Tiempo de conexión agotado: {exc}") from exc
        except requests.exceptions.SSLError as exc:
            raise DgiiTransportError(f"Error TLS con la DGII: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            # Fallo al establecer la conexión: la solicitud no salió (seguro reintentar).
            # Cualquier otro corte durante un envío deja el resultado incierto (ambiguo).
            reason = getattr(exc.args[0], "reason", None) if exc.args else None
            no_salio = isinstance(reason, NewConnectionError)
            raise DgiiTransportError(f"Conexión fallida: {exc}",
                                     ambiguous=files is not None and not no_salio) from exc
        except requests.exceptions.Timeout as exc:
            raise DgiiTransportError(f"Tiempo de respuesta agotado: {exc}",
                                     ambiguous=files is not None) from exc
        summary = {"metodo": metodo, "url": url, "params": params or {}, "http": r.status_code,
                   "en": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        resp = DgiiResponse(r.status_code, r.content, _parse_body(r.content), summary)
        if r.status_code == 401 and auth and retry_auth:
            self._token = None
            return self._request(metodo, ruta, auth=auth, params=params, files=files,
                                 retry_auth=False)
        if r.status_code == 401:
            raise DgiiAuthError("La DGII rechazó el token de autenticación")
        if r.status_code >= 500:
            raise DgiiTransportError(f"Error del servidor DGII HTTP {r.status_code}",
                                     ambiguous=files is not None)
        if 300 <= r.status_code < 400:
            raise DgiiTransportError(f"Redirección inesperada HTTP {r.status_code}")
        return resp

    # ---------------------------------------------------------------- autenticación
    def authenticate(self) -> None:
        ep = self.spec.endpoint("semilla")
        semilla = self._request(ep.metodo, ep.ruta, auth=False)
        if semilla.status_code != 200 or not semilla.body.strip():
            raise DgiiAuthError(f"No se obtuvo la semilla (HTTP {semilla.status_code})")
        firmada = self.signer.sign(semilla.body, incluir_fecha=False).xml
        ep2 = self.spec.endpoint("validar_semilla")
        if not ep2.campo_archivo:
            raise SpecNotVerifiedError("[endpoints.validar_semilla].campo_archivo vacío")
        r = self._request(ep2.metodo, ep2.ruta, auth=False,
                          files={ep2.campo_archivo: ("semilla.xml", firmada, "text/xml")})
        token = r.get(self.spec.campo("token"))
        if r.status_code != 200 or not token:
            raise DgiiAuthError(f"Validación de semilla rechazada (HTTP {r.status_code})")
        self._token = str(token)
        expira = _parse_datetime(r.get(self.spec.campo("token_expira")))
        # Si no se puede interpretar la expiración, el token se usa una sola vez.
        self._token_expira = expira or datetime.now(timezone.utc)

    def token(self) -> str:
        margen = timedelta(seconds=self.spec.token_margen_segundos())
        if (self._token is None or self._token_expira is None
                or datetime.now(timezone.utc) + margen >= self._token_expira):
            self.authenticate()
        assert self._token is not None
        return self._token

    # ---------------------------------------------------------------- servicios
    def submit_ecf(self, signed_xml: bytes, *, rnc_emisor: str, encf: str) -> DgiiResponse:
        ep = self.spec.endpoint("recepcion_ecf")
        nombre = self.spec.section("endpoints.recepcion_ecf").get("nombre_archivo")
        if not ep.campo_archivo or not nombre:
            raise SpecNotVerifiedError("[endpoints.recepcion_ecf] requiere campo_archivo y nombre_archivo")
        filename = nombre.format(rnc_emisor=rnc_emisor, encf=encf)
        return self._request(ep.metodo, ep.ruta, auth=True,
                             files={ep.campo_archivo: (filename, signed_xml, "text/xml")})

    def query_result(self, track_id: str) -> DgiiResponse:
        ep = self.spec.endpoint("consulta_resultado")
        p = ep.parametros.get("trackid")
        if not p:
            raise SpecNotVerifiedError("[endpoints.consulta_resultado.parametros].trackid vacío")
        return self._request(ep.metodo, ep.ruta, auth=True, params={p: track_id})

    def query_trackids(self, *, rnc_emisor: str, encf: str) -> DgiiResponse:
        ep = self.spec.endpoint("consulta_trackids")
        pr, pe = ep.parametros.get("rnc_emisor"), ep.parametros.get("encf")
        if not pr or not pe:
            raise SpecNotVerifiedError("[endpoints.consulta_trackids.parametros] incompleto")
        return self._request(ep.metodo, ep.ruta, auth=True, params={pr: rnc_emisor, pe: encf})

    def service_available(self) -> bool | None:
        """True/False si el servicio oficial de estatus está configurado; None si no lo está."""
        if not self.spec.has_endpoint("estatus_servicios"):
            return None
        ep = self.spec.endpoint("estatus_servicios")
        try:
            r = self._request(ep.metodo, ep.ruta, auth=False)
        except DgiiTransportError:
            return False
        return r.status_code == 200
