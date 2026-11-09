"""Representación impresa del e-CF con código QR, código de seguridad y datos de verificación.

La URL del QR se arma con la plantilla oficial configurada en [qr] de la especificación
verificada. Los valores se toman del XML firmado (no de datos externos) para que la
representación coincida exactamente con el comprobante transmitido.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from string import Formatter
from urllib.parse import quote

import qrcode
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from .errors import SpecNotVerifiedError
from .spec import Ambiente, DgiiSpec
from .status import Estado, is_fiscally_valid

MARCADORES = {"RncEmisor", "RncComprador", "ENCF", "FechaEmision", "MontoTotal", "FechaFirma",
              "CodigoSeguridad"}


@dataclass
class DatosVerificacion:
    rnc_emisor: str
    encf: str
    tipo_ecf: str
    fecha_emision: str
    monto_total: str
    fecha_firma: str
    codigo_seguridad: str
    rnc_comprador: str | None = None

    def as_params(self) -> dict[str, str]:
        return {
            "RncEmisor": self.rnc_emisor, "RncComprador": self.rnc_comprador or "",
            "ENCF": self.encf, "FechaEmision": self.fecha_emision,
            "MontoTotal": self.monto_total, "FechaFirma": self.fecha_firma,
            "CodigoSeguridad": self.codigo_seguridad,
        }


def verification_url(spec: DgiiSpec, ambiente: Ambiente, datos: DatosVerificacion) -> str:
    plantilla = spec.qr_plantilla(ambiente, datos.tipo_ecf)
    usados = {f for _, f, _, _ in Formatter().parse(plantilla) if f}
    desconocidos = usados - MARCADORES
    if desconocidos:
        raise SpecNotVerifiedError(f"Marcadores no soportados en la plantilla QR: {desconocidos}")
    if not plantilla.startswith("https://"):
        raise SpecNotVerifiedError("La URL de verificación debe ser HTTPS")
    params = {k: quote(v, safe="") for k, v in datos.as_params().items()}
    return plantilla.format_map(params)


def qr_png(url: str) -> bytes:
    img = qrcode.make(url, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@dataclass
class LineaImpresa:
    descripcion: str
    cantidad: str
    precio: str
    monto: str


@dataclass
class DocumentoImpreso:
    razon_social_emisor: str
    tipo_nombre: str
    datos: DatosVerificacion
    estado: Estado
    lineas: list[LineaImpresa] = field(default_factory=list)
    comprador: str | None = None
    contingencia: bool = False


def render_pdf(spec: DgiiSpec, ambiente: Ambiente, doc: DocumentoImpreso) -> bytes:
    url = verification_url(spec, ambiente, doc.datos)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter, invariant=1)  # invariant: salida determinista
    w, h = letter
    y = h - 20 * mm
    c.setFont("Helvetica-Bold", 13)
    c.drawString(20 * mm, y, doc.razon_social_emisor)
    c.setFont("Helvetica", 9)
    y -= 6 * mm
    c.drawString(20 * mm, y, f"RNC: {doc.datos.rnc_emisor}")
    c.setFont("Helvetica-Bold", 11)
    c.drawRightString(w - 20 * mm, h - 20 * mm, doc.tipo_nombre)
    c.drawRightString(w - 20 * mm, h - 26 * mm, f"e-NCF: {doc.datos.encf}")
    c.setFont("Helvetica", 9)
    c.drawRightString(w - 20 * mm, h - 32 * mm, f"Fecha de emisión: {doc.datos.fecha_emision}")
    y -= 10 * mm
    if doc.comprador or doc.datos.rnc_comprador:
        c.drawString(20 * mm, y, f"Comprador: {doc.comprador or ''}  RNC/Cédula: "
                                 f"{doc.datos.rnc_comprador or ''}")
        y -= 8 * mm
    c.setFont("Helvetica-Bold", 9)
    for x, t in ((20, "Descripción"), (120, "Cant."), (145, "Precio"), (175, "Monto")):
        c.drawString(x * mm, y, t)
    c.setFont("Helvetica", 9)
    for ln in doc.lineas:
        y -= 5 * mm
        if y < 70 * mm:
            c.showPage()
            y = h - 20 * mm
        c.drawString(20 * mm, y, ln.descripcion[:60])
        c.drawRightString(135 * mm, y, ln.cantidad)
        c.drawRightString(165 * mm, y, ln.precio)
        c.drawRightString(195 * mm, y, ln.monto)
    y -= 8 * mm
    c.setFont("Helvetica-Bold", 11)
    c.drawRightString(195 * mm, y, f"Total: {doc.datos.monto_total}")

    # Bloque de verificación
    qr = ImageReader(io.BytesIO(qr_png(url)))
    c.drawImage(qr, 20 * mm, 15 * mm, 40 * mm, 40 * mm)
    c.setFont("Helvetica", 9)
    c.drawString(65 * mm, 48 * mm, f"Código de seguridad: {doc.datos.codigo_seguridad}")
    c.drawString(65 * mm, 42 * mm, f"Fecha de firma digital: {doc.datos.fecha_firma}")
    c.setFont("Helvetica-Bold", 9)
    if is_fiscally_valid(doc.estado):
        c.drawString(65 * mm, 34 * mm, "Comprobante aceptado por la DGII")
    else:
        c.setFillColorRGB(0.7, 0, 0)
        c.drawString(65 * mm, 34 * mm, "PENDIENTE DE ACEPTACIÓN DGII — aún sin validez fiscal")
        c.setFillColorRGB(0, 0, 0)
    if doc.contingencia:
        c.drawString(65 * mm, 28 * mm, "Emitido en contingencia")
    c.setFont("Helvetica", 6)
    c.drawString(65 * mm, 20 * mm, url[:140])
    c.save()
    return buf.getvalue()
