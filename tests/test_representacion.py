"""Representación impresa: URL de verificación, QR y PDF."""

from urllib.parse import parse_qs, urlparse

import pytest

from plomfact_ecf.errors import SpecNotVerifiedError
from plomfact_ecf.representation import (DatosVerificacion, DocumentoImpreso, render_pdf,
                                         verification_url)
from plomfact_ecf.spec import Ambiente
from plomfact_ecf.status import Estado

from conftest import build_content

DATOS = DatosVerificacion(rnc_emisor="101000001", encf="X9100000001", tipo_ecf="91",
                          fecha_emision="09-11-2026", monto_total="1180.00",
                          fecha_firma="09-11-2026 10:00:00", codigo_seguridad="a+/B=9",
                          rnc_comprador="131000002")


def test_url_verificacion_codifica_valores():
    from conftest import FIX
    from plomfact_ecf.spec import DgiiSpec
    spec = DgiiSpec.load(FIX / "spec_pruebas.toml")
    url = verification_url(spec, Ambiente.PRECERTIFICACION, DATOS)
    q = parse_qs(urlparse(url).query)
    assert q["cs"] == ["a+/B=9"] and q["ff"] == ["09-11-2026 10:00:00"] and q["n"] == ["X9100000001"]
    assert "+" not in url.split("cs=")[1] and " " not in url


def test_plantilla_por_tipo(spec):
    d = DatosVerificacion(**{**DATOS.__dict__, "tipo_ecf": "92"})
    assert "verificar-especial" in verification_url(spec, Ambiente.PRECERTIFICACION, d)


def test_marcador_desconocido_rechazado(spec):
    spec._data["qr"]["plantillas"]["precertificacion"] = "https://x.invalid/?a={Inventado}"
    with pytest.raises(SpecNotVerifiedError):
        verification_url(spec, Ambiente.PRECERTIFICACION, DATOS)


def test_pdf(spec):
    for estado in (Estado.EN_COLA, Estado.ACEPTADO):
        pdf = render_pdf(spec, Ambiente.PRECERTIFICACION, DocumentoImpreso(
            razon_social_emisor="Emisor", tipo_nombre="Documento simulado A", datos=DATOS,
            estado=estado))
        assert pdf.startswith(b"%PDF")


def test_representacion_usa_datos_del_xml_firmado(env):
    r = env.service.emit("91", build_content)
    d = env.service.verification_data(r.comprobante_id)
    assert (d.encf, d.monto_total, d.codigo_seguridad, d.fecha_firma) == \
        (r.encf, "1180.00", r.codigo_seguridad, r.fecha_firma)
    assert d.rnc_comprador == "131000002"
