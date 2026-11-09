"""Certificados digitales: carga, validación, secretos y renovación segura."""

import os
from datetime import datetime, timedelta, timezone

import pytest

from plomfact_ecf.credentials import (CertificateRegistry, export_pkcs12, generate_test_credential,
                                      load_pkcs12, read_secret)
from plomfact_ecf.errors import CertificateError


def test_carga_pkcs12(tmp_path, credential):
    p = tmp_path / "c.p12"
    p.write_bytes(export_pkcs12(credential, b"secreta"))
    c = load_pkcs12(p, b"secreta")
    assert c.fingerprint == credential.fingerprint


def test_clave_incorrecta(tmp_path, credential):
    p = tmp_path / "c.p12"
    p.write_bytes(export_pkcs12(credential, b"secreta"))
    with pytest.raises(CertificateError):
        load_pkcs12(p, b"mala")


def test_certificado_vencido_y_futuro(tmp_path):
    vencido = generate_test_credential(days=1, not_before=datetime.now(timezone.utc) - timedelta(days=5))
    futuro = generate_test_credential(not_before=datetime.now(timezone.utc) + timedelta(days=5))
    for cred, msg in ((vencido, "venció"), (futuro, "aún no")):
        p = tmp_path / "x.p12"
        p.write_bytes(export_pkcs12(cred, b"k"))
        with pytest.raises(CertificateError, match=msg):
            load_pkcs12(p, b"k")


def test_secreto_por_variable_y_archivo(tmp_path, monkeypatch):
    monkeypatch.setenv("PF_TEST_SECRET", "abc")
    assert read_secret(env_var="PF_TEST_SECRET") == b"abc"
    f = tmp_path / "s"
    f.write_text("xyz\n")
    os.chmod(f, 0o644)
    with pytest.raises(CertificateError, match="chmod 600"):
        read_secret(file=f)
    os.chmod(f, 0o600)
    assert read_secret(file=f) == b"xyz"
    with pytest.raises(CertificateError):
        read_secret(env_var="NO_EXISTE_PF")


def test_certificado_activo_obligatorio(db, credential):
    reg = CertificateRegistry(db)
    with pytest.raises(CertificateError, match="no es el certificado activo"):
        reg.ensure_active(credential)
    reg.register(credential, activate=True)
    reg.ensure_active(credential)
    with pytest.raises(CertificateError):
        reg.ensure_active(generate_test_credential("OTRO"))


def test_renovacion_segura(db):
    reg = CertificateRegistry(db)
    viejo = generate_test_credential(days=30)
    reg.register(viejo, activate=True)
    peor = generate_test_credential(days=10)
    with pytest.raises(CertificateError, match="no extiende"):
        reg.rotate(peor)
    assert reg.active_fingerprint() == viejo.fingerprint
    nuevo = generate_test_credential(days=730)
    reg.rotate(nuevo)
    assert reg.active_fingerprint() == nuevo.fingerprint
    assert {c["fingerprint_sha256"] for c in reg.all()} == {viejo.fingerprint, nuevo.fingerprint}


def test_renovacion_no_altera_comprobantes_emitidos(env):
    from conftest import build_content
    from plomfact_ecf.xmlsign import verify_signature
    r = env.service.emit("91", build_content)
    viejo = env.cred
    nuevo = generate_test_credential(days=900)
    CertificateRegistry(env.db).rotate(nuevo)
    st = env.service.status(r.comprobante_id)
    assert st["certificado_fingerprint"] == viejo.fingerprint
    verify_signature(env.store.read(st["xml_firmado_sha256"]), viejo)
    with pytest.raises(CertificateError):  # el servicio con el certificado viejo ya no firma
        env.service.emit("91", build_content)
