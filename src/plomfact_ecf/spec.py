"""Especificación técnica DGII cargada desde configuración.

Ningún endpoint, campo de respuesta, estado fiscal, regla de código de seguridad ni formato de QR
está escrito en el código. Todo se carga de un archivo TOML que el responsable fiscal completa
a partir de la documentación técnica oficial vigente de la DGII. Cada sección debe declarar:

    verificado = true
    fuente = "<documento oficial, versión, fecha y página>"

Una sección no verificada no puede usarse: el sistema falla de forma cerrada (SpecNotVerifiedError).
"""

from __future__ import annotations

import enum
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import SpecNotVerifiedError


class Ambiente(str, enum.Enum):
    PRECERTIFICACION = "precertificacion"
    CERTIFICACION = "certificacion"
    PRODUCCION = "produccion"


# Secciones obligatorias del archivo de especificación.
SECCIONES = (
    "ambientes.precertificacion",
    "ambientes.certificacion",
    "ambientes.produccion",
    "endpoints.semilla",
    "endpoints.validar_semilla",
    "endpoints.recepcion_ecf",
    "endpoints.consulta_resultado",
    "endpoints.consulta_trackids",
    "endpoints.estatus_servicios",
    "respuestas",
    "estados",
    "firma",
    "codigo_seguridad",
    "qr",
    "xml",
    "encf",
    "contingencia",
)

# Endpoints opcionales: si la sección existe vacía o no verificada, la función que la usa se deshabilita.
ENDPOINTS_OPCIONALES = {"consulta_trackids", "estatus_servicios"}


@dataclass(frozen=True)
class Endpoint:
    nombre: str
    metodo: str
    ruta: str
    parametros: dict[str, str]
    campo_archivo: str | None = None


class DgiiSpec:
    def __init__(self, data: dict[str, Any], origen: str = "<memoria>"):
        self._data = data
        self.origen = origen

    # ---------------------------------------------------------------- carga
    @classmethod
    def load(cls, path: str | Path) -> "DgiiSpec":
        p = Path(path)
        with p.open("rb") as fh:
            return cls(tomllib.load(fh), origen=str(p))

    # ---------------------------------------------------------------- acceso
    def _section(self, dotted: str) -> dict[str, Any]:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                raise SpecNotVerifiedError(f"Falta la sección [{dotted}] en {self.origen}")
            node = node[part]
        if not isinstance(node, dict):
            raise SpecNotVerifiedError(f"[{dotted}] debe ser una tabla TOML")
        return node

    def is_verified(self, dotted: str) -> bool:
        try:
            s = self._section(dotted)
        except SpecNotVerifiedError:
            return False
        return s.get("verificado") is True and bool(str(s.get("fuente", "")).strip())

    def section(self, dotted: str) -> dict[str, Any]:
        """Devuelve una sección solo si está verificada contra la documentación oficial."""
        s = self._section(dotted)
        if s.get("verificado") is not True or not str(s.get("fuente", "")).strip():
            raise SpecNotVerifiedError(
                f"La sección [{dotted}] no está verificada. Complétela con la documentación "
                f"oficial de la DGII y declare verificado=true y fuente=\"...\"."
            )
        return s

    def _required_str(self, dotted: str, key: str) -> str:
        v = self.section(dotted).get(key)
        if not isinstance(v, str) or not v.strip():
            raise SpecNotVerifiedError(f"[{dotted}].{key} está vacío")
        return v

    def unverified_sections(self) -> list[str]:
        return [s for s in SECCIONES if not self.is_verified(s)]

    def require_all_verified(self, *, allow_optional_missing: bool = True) -> None:
        pendientes = [
            s for s in self.unverified_sections()
            if not (allow_optional_missing and s.split(".")[-1] in ENDPOINTS_OPCIONALES)
        ]
        if pendientes:
            raise SpecNotVerifiedError(
                "Secciones de la especificación DGII sin verificar: " + ", ".join(pendientes)
            )

    # ---------------------------------------------------------------- valores
    def base_url(self, ambiente: Ambiente) -> str:
        url = self._required_str(f"ambientes.{ambiente.value}", "base_url")
        if not url.startswith("https://"):
            raise SpecNotVerifiedError("Los servicios DGII deben usarse exclusivamente por HTTPS")
        return url.rstrip("/")

    def endpoint(self, nombre: str) -> Endpoint:
        s = self.section(f"endpoints.{nombre}")
        metodo = str(s.get("metodo", "")).upper()
        ruta = str(s.get("ruta", ""))
        if metodo not in {"GET", "POST"} or not ruta:
            raise SpecNotVerifiedError(f"[endpoints.{nombre}] requiere metodo y ruta")
        return Endpoint(
            nombre=nombre,
            metodo=metodo,
            ruta=ruta,
            parametros=dict(s.get("parametros", {})),
            campo_archivo=s.get("campo_archivo") or None,
        )

    def has_endpoint(self, nombre: str) -> bool:
        return self.is_verified(f"endpoints.{nombre}")

    def campo(self, nombre: str) -> str:
        return self._required_str("respuestas", nombre)

    def campo_opcional(self, nombre: str) -> str | None:
        v = self.section("respuestas").get(nombre)
        return v if isinstance(v, str) and v else None

    def estados(self, grupo: str) -> frozenset[str]:
        v = self.section("estados").get(grupo, [])
        if not isinstance(v, list):
            raise SpecNotVerifiedError(f"[estados].{grupo} debe ser una lista")
        return frozenset(str(x) for x in v)

    def firma(self) -> dict[str, Any]:
        s = self.section("firma")
        for k in ("algoritmo_firma", "algoritmo_digest", "canonicalizacion",
                  "elemento_fecha_firma", "formato_fecha_firma"):
            if not s.get(k):
                raise SpecNotVerifiedError(f"[firma].{k} está vacío")
        return s

    def codigo_seguridad(self) -> dict[str, Any]:
        s = self.section("codigo_seguridad")
        if s.get("origen") != "SignatureValue":
            raise SpecNotVerifiedError(
                "[codigo_seguridad].origen soportado: 'SignatureValue'. Si la documentación "
                "oficial define otra regla, debe implementarse explícitamente."
            )
        if not isinstance(s.get("longitud"), int) or s["longitud"] <= 0:
            raise SpecNotVerifiedError("[codigo_seguridad].longitud debe ser un entero > 0")
        return s

    def qr_plantilla(self, ambiente: Ambiente, tipo_ecf: str) -> str:
        s = self.section("qr")
        especiales = s.get("plantillas_por_tipo", {}).get(ambiente.value, {})
        plantilla = especiales.get(tipo_ecf) or s.get("plantillas", {}).get(ambiente.value)
        if not plantilla:
            raise SpecNotVerifiedError(f"[qr].plantillas.{ambiente.value} está vacío")
        return plantilla

    def encf_regex(self) -> re.Pattern[str]:
        return re.compile(self._required_str("encf", "patron_regex"))

    def encf_tipos(self) -> dict[str, str]:
        tipos = self.section("encf").get("tipos", {})
        if not tipos:
            raise SpecNotVerifiedError("[encf].tipos está vacío")
        return {str(k): str(v) for k, v in tipos.items()}

    def encf_layout(self) -> tuple[str, int, int]:
        """(prefijo, longitud del código de tipo, longitud del secuencial)."""
        s = self.section("encf")
        prefijo = s.get("prefijo")
        lt, ls = s.get("longitud_tipo"), s.get("longitud_secuencial")
        if not isinstance(prefijo, str) or not isinstance(lt, int) or not isinstance(ls, int):
            raise SpecNotVerifiedError("[encf] requiere prefijo, longitud_tipo y longitud_secuencial")
        return prefijo, lt, ls

    def xml_rutas(self) -> dict[str, str]:
        """XPaths oficiales (según XSD) para leer datos fiscales del e-CF ya construido."""
        s = self.section("xml")
        rutas = s.get("rutas", {})
        for k in ("encf", "tipo_ecf", "rnc_emisor", "fecha_emision", "monto_total"):
            if not rutas.get(k):
                raise SpecNotVerifiedError(f"[xml.rutas].{k} está vacío")
        return dict(rutas)

    def xml_raiz(self, documento: str = "ecf") -> str:
        raices = self.section("xml").get("raices", {})
        v = raices.get(documento)
        if not v:
            raise SpecNotVerifiedError(f"[xml.raices].{documento} está vacío")
        return v

    def contingencia(self) -> dict[str, Any]:
        return self.section("contingencia")

    def token_margen_segundos(self) -> int:
        return int(self.section("respuestas").get("margen_renovacion_token_segundos", 60))
