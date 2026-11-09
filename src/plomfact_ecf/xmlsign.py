"""Generación, validación (XSD oficial) y firma digital XMLDSig de los e-CF.

El contenido del e-CF se construye a partir de un árbol ordenado cuyos nombres de elementos
provienen del XSD oficial de la DGII. Este módulo NO define la estructura fiscal: la valida
contra el XSD oficial que el emisor coloca en schemas/. Sin XSD no se firma nada.
"""

from __future__ import annotations

import base64

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Sequence
from zoneinfo import ZoneInfo

from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .credentials import SigningCredential
from .errors import SignatureError, SpecNotVerifiedError, XmlValidationError
from .spec import DgiiSpec

DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

# Un nodo es (nombre, valor) o (nombre, [hijos]). Los valores se escapan automáticamente.
Node = tuple[str, Any]


def build_xml(root: str, children: Sequence[Node]) -> bytes:
    el = etree.Element(root)
    _append(el, children)
    return etree.tostring(el, xml_declaration=True, encoding="UTF-8")


def _append(parent: etree._Element, children: Sequence[Node]) -> None:
    for name, value in children:
        if value is None:
            continue  # los elementos opcionales vacíos no se emiten
        child = etree.SubElement(parent, name)
        if isinstance(value, (list, tuple)):
            _append(child, value)
        elif isinstance(value, Decimal):
            child.text = format(value, "f")
        else:
            child.text = str(value)


def parse_xml(data: bytes) -> etree._Element:
    parser = etree.XMLParser(resolve_entities=False, no_network=True, remove_blank_text=False,
                             huge_tree=False)
    try:
        return etree.fromstring(data, parser)
    except etree.XMLSyntaxError as exc:
        raise XmlValidationError(f"XML mal formado: {exc}") from exc


class XsdValidator:
    def __init__(self, xsd_por_tipo: dict[str, str | Path]):
        self._paths = {k: Path(v) for k, v in xsd_por_tipo.items()}
        self._cache: dict[str, etree.XMLSchema] = {}

    def schema(self, clave: str) -> etree.XMLSchema:
        if clave not in self._cache:
            p = self._paths.get(clave)
            if not p or not p.is_file():
                raise XmlValidationError(
                    f"No hay XSD oficial configurado para '{clave}'. Descárguelo del portal de la "
                    "DGII y regístrelo en config/settings.toml [xsd]."
                )
            parser = etree.XMLParser(resolve_entities=False, no_network=True)
            self._cache[clave] = etree.XMLSchema(etree.parse(str(p), parser))
        return self._cache[clave]

    def validate(self, clave: str, data: bytes) -> None:
        schema = self.schema(clave)
        doc = parse_xml(data)
        if not schema.validate(doc):
            errores = "; ".join(f"línea {e.line}: {e.message}" for e in schema.error_log)
            raise XmlValidationError(f"El XML no cumple el XSD '{clave}': {errores}")


@dataclass(frozen=True)
class SignedDocument:
    xml: bytes
    signature_value: str
    fecha_firma: str


import xmlsec  # noqa: E402  (libxmlsec1: implementación de referencia de XMLDSig)

_C14N = {
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": xmlsec.constants.TransformInclC14N,
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments":
        xmlsec.constants.TransformInclC14NWithComments,
    "http://www.w3.org/2001/10/xml-exc-c14n#": xmlsec.constants.TransformExclC14N,
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments":
        xmlsec.constants.TransformExclC14NWithComments,
}
_DIGEST = {
    "http://www.w3.org/2001/04/xmlenc#sha256": xmlsec.constants.TransformSha256,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": xmlsec.constants.TransformSha384,
    "http://www.w3.org/2001/04/xmlenc#sha512": xmlsec.constants.TransformSha512,
}
_SIGNATURE = {
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": xmlsec.constants.TransformRsaSha256,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": xmlsec.constants.TransformRsaSha384,
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": xmlsec.constants.TransformRsaSha512,
}


class Signer:
    """Firma XMLDSig envolvente (Reference URI="") con RSA, según los algoritmos verificados."""

    def __init__(self, spec: DgiiSpec, credential: SigningCredential):
        f = spec.firma()
        try:
            self._sig = _SIGNATURE[f["algoritmo_firma"]]
            self._dig = _DIGEST[f["algoritmo_digest"]]
            self._c14n = _C14N[f["canonicalizacion"]]
        except KeyError as exc:
            raise SpecNotVerifiedError(f"Algoritmo no soportado por este módulo: {exc}") from exc
        self._fecha_el = f["elemento_fecha_firma"]
        self._fecha_fmt = f["formato_fecha_firma"]
        self._tz = ZoneInfo(f.get("zona_horaria", "America/Santo_Domingo"))
        if "prefijo_namespace_firma" not in f:
            raise SpecNotVerifiedError("[firma].prefijo_namespace_firma no definido ('' = sin prefijo)")
        self._prefijo = f["prefijo_namespace_firma"] or None
        self.credential = credential

    def sign(self, data: bytes, *, fecha_firma: datetime | None = None,
             incluir_fecha: bool = True) -> SignedDocument:
        root = parse_xml(data)
        if root.find(f".//{{{DSIG_NS}}}Signature") is not None:
            raise SignatureError("El documento ya está firmado; un XML firmado no se altera")
        fecha_txt = ""
        if incluir_fecha:
            if root.find(self._fecha_el) is not None:
                raise SignatureError(f"El elemento {self._fecha_el} ya existe")
            fecha_txt = (fecha_firma or datetime.now(self._tz)).astimezone(self._tz).strftime(
                self._fecha_fmt)
            etree.SubElement(root, self._fecha_el).text = fecha_txt
        sig = xmlsec.template.create(root, self._c14n, self._sig, ns=self._prefijo)
        root.append(sig)
        ref = xmlsec.template.add_reference(sig, self._dig, uri="")
        xmlsec.template.add_transform(ref, xmlsec.constants.TransformEnveloped)
        xmlsec.template.add_transform(ref, self._c14n)
        ki = xmlsec.template.ensure_key_info(sig)
        xmlsec.template.add_x509_data(ki)
        try:
            ctx = xmlsec.SignatureContext()
            key = xmlsec.Key.from_memory(self.credential.key_pem(), xmlsec.constants.KeyDataFormatPem)
            key.load_cert_from_memory(self.credential.cert_pem(), xmlsec.constants.KeyDataFormatCertPem)
            ctx.key = key
            ctx.sign(sig)
        except xmlsec.Error as exc:
            raise SignatureError(f"No se pudo firmar: {exc}") from exc
        out = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        return SignedDocument(out, signature_value(out), fecha_txt)


def verify_signature(data: bytes, credential_or_pem: SigningCredential | bytes) -> None:
    """Verifica la firma (y el digest) con la clave pública del certificado esperado."""
    if isinstance(credential_or_pem, SigningCredential):
        cert = credential_or_pem.certificate
    else:
        cert = x509.load_pem_x509_certificate(credential_or_pem)
    pub = cert.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    root = parse_xml(data)
    sigs = root.findall(f".//{{{DSIG_NS}}}Signature")
    if len(sigs) != 1:
        raise SignatureError(f"Se esperaba exactamente una firma; hay {len(sigs)}")
    refs = sigs[0].findall(f"{{{DSIG_NS}}}SignedInfo/{{{DSIG_NS}}}Reference")
    if len(refs) != 1 or refs[0].get("URI") != "":
        raise SignatureError("La firma debe tener una única referencia al documento completo")
    try:
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_memory(pub, xmlsec.constants.KeyDataFormatPem)
        ctx.verify(sigs[0])
    except xmlsec.Error as exc:
        raise SignatureError(f"Firma inválida: {exc}") from exc
    # El certificado incluido en la firma debe ser el esperado.
    x5 = sigs[0].find(f".//{{{DSIG_NS}}}X509Certificate")
    der = cert.public_bytes(serialization.Encoding.DER)
    if x5 is None or base64.b64decode("".join((x5.text or "").split())) != der:
        raise SignatureError("El certificado de la firma no corresponde al esperado")


def signature_value(data: bytes) -> str:
    sv = parse_xml(data).find(f".//{{{DSIG_NS}}}SignatureValue")
    if sv is None:
        raise SignatureError("El documento no tiene SignatureValue")
    return "".join((sv.text or "").split())


def security_code(spec: DgiiSpec, signed_xml: bytes) -> str:
    """Código de seguridad derivado de la firma según la regla configurada y verificada."""
    regla = spec.codigo_seguridad()
    sv = signature_value(signed_xml)
    n = regla["longitud"]
    if len(sv) < n:
        raise SignatureError("SignatureValue más corto que el código de seguridad")
    return sv[:n]


def read_fields(spec: DgiiSpec, xml: bytes) -> dict[str, str | None]:
    root = parse_xml(xml)
    out: dict[str, str | None] = {}
    for k, xp in spec.xml_rutas().items():
        if not xp:
            out[k] = None
            continue
        r = root.xpath(xp)
        if isinstance(r, list):
            r = r[0].text if r and hasattr(r[0], "text") else (str(r[0]) if r else None)
        out[k] = r.strip() if isinstance(r, str) else r
    return out
