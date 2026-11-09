"""Firma digital XMLDSig y código de seguridad."""

import copy
import tomllib

import pytest
from lxml import etree

from plomfact_ecf.credentials import generate_test_credential
from plomfact_ecf.errors import SignatureError, SpecNotVerifiedError, XmlValidationError
from plomfact_ecf.spec import DgiiSpec
from plomfact_ecf.xmlsign import (DSIG_NS, Signer, XsdValidator, build_xml, security_code,
                                  signature_value, verify_signature)

from conftest import FIX, build_content


@pytest.fixture
def signed(spec, credential):
    return Signer(spec, credential).sign(build_xml("DocumentoSim", build_content("X9100000001")))


def test_firma_valida_y_envolvente(signed, credential):
    verify_signature(signed.xml, credential)
    root = etree.fromstring(signed.xml)
    ref = root.find(f".//{{{DSIG_NS}}}Reference")
    assert ref.get("URI") == ""
    assert root[-1].tag == f"{{{DSIG_NS}}}Signature"
    assert root.find("FechaFirmaSim").text == signed.fecha_firma


@pytest.mark.parametrize("cambio", [(b"1180.00", b"1181.00"), (b"X9100000001", b"X9100000002"),
                                    (b"101000001", b"101000009")])
def test_alteracion_invalida_la_firma(signed, credential, cambio):
    with pytest.raises(SignatureError):
        verify_signature(signed.xml.replace(*cambio), credential)


def test_firma_con_otro_certificado_es_rechazada(signed):
    with pytest.raises(SignatureError):
        verify_signature(signed.xml, generate_test_credential("OTRO"))


def test_no_se_firma_dos_veces(spec, credential, signed):
    with pytest.raises(SignatureError):
        Signer(spec, credential).sign(signed.xml)


def test_codigo_seguridad_deriva_de_signature_value(spec, signed):
    cs = security_code(spec, signed.xml)
    assert len(cs) == 6
    assert signature_value(signed.xml).startswith(cs)
    assert cs == signed.signature_value[:6]


def test_firma_unica_por_documento(spec, credential):
    a = Signer(spec, credential).sign(build_xml("DocumentoSim", build_content("X9100000001")))
    b = Signer(spec, credential).sign(build_xml("DocumentoSim", build_content("X9100000002")))
    assert a.signature_value != b.signature_value


@pytest.mark.parametrize("c14n", ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
                                  "http://www.w3.org/2001/10/xml-exc-c14n#"])
@pytest.mark.parametrize("prefijo", ["", "ds"])
def test_variantes_de_canonicalizacion(credential, c14n, prefijo):
    d = tomllib.load(open(FIX / "spec_pruebas.toml", "rb"))
    d["firma"]["canonicalizacion"] = c14n
    d["firma"]["prefijo_namespace_firma"] = prefijo
    s = Signer(DgiiSpec(d), credential).sign(build_xml("DocumentoSim", build_content("X9100000001")))
    verify_signature(s.xml, credential)


def test_verificacion_cruzada_con_implementacion_independiente(credential):
    """signxml (implementación independiente en Python) valida la firma prefijada."""
    signxml = pytest.importorskip("signxml")
    d = tomllib.load(open(FIX / "spec_pruebas.toml", "rb"))
    d["firma"]["prefijo_namespace_firma"] = "ds"
    s = Signer(DgiiSpec(d), credential).sign(build_xml("DocumentoSim", build_content("X9100000001")))
    signxml.XMLVerifier().verify(s.xml, x509_cert=credential.cert_pem().decode(),
                                 expect_references=1)


def test_algoritmo_no_soportado(credential):
    d = tomllib.load(open(FIX / "spec_pruebas.toml", "rb"))
    d["firma"]["algoritmo_firma"] = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    with pytest.raises(SpecNotVerifiedError):
        Signer(DgiiSpec(d), credential)


def test_xsd_obligatorio(signed):
    with pytest.raises(XmlValidationError, match="No hay XSD"):
        XsdValidator({}).validate("91", signed.xml)
    XsdValidator({"91": FIX / "documento_sim.xsd"}).validate("91", signed.xml)


def test_escape_de_caracteres_especiales(spec, credential):
    contenido = build_content("X9100000001")
    contenido[0][1][3] = ("CompradorSim", "Pérez & Hijos <SRL> \"'")
    s = Signer(spec, credential).sign(build_xml("DocumentoSim", contenido))
    verify_signature(s.xml, credential)
    assert etree.fromstring(s.xml).find("Cabecera/CompradorSim").text == "Pérez & Hijos <SRL> \"'"


def test_xml_con_entidades_externas_rechazado():
    from plomfact_ecf.xmlsign import parse_xml
    xxe = b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>'
    root = parse_xml(xxe)
    assert "root:" not in (etree.tostring(root).decode())
