"""Gestión del certificado digital del emisor electrónico.

  * El certificado se carga desde un archivo PKCS#12 (.p12/.pfx) emitido por una entidad de
    certificación autorizada. La contraseña nunca se guarda en la base de datos ni en el código:
    se lee de una variable de entorno o de un archivo de secretos con permisos restringidos.
  * Solo se registra la huella SHA-256, el sujeto, la serie y las fechas de validez.
  * Un certificado vencido, aún no vigente, o distinto del registrado como activo es rechazado.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from .db import Database, iso, utcnow
from .errors import CertificateError


@dataclass
class SigningCredential:
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    chain: list[x509.Certificate]

    @property
    def fingerprint(self) -> str:
        return self.certificate.fingerprint(hashes.SHA256()).hex()

    @property
    def not_after(self) -> datetime:
        return self.certificate.not_valid_after_utc

    @property
    def not_before(self) -> datetime:
        return self.certificate.not_valid_before_utc

    @property
    def subject(self) -> str:
        return self.certificate.subject.rfc4514_string()

    def cert_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def days_remaining(self, now: datetime | None = None) -> float:
        now = now or utcnow()
        return (self.not_after - now) / timedelta(days=1)


def read_secret(*, env_var: str | None = None, file: str | Path | None = None) -> bytes:
    """Lee un secreto desde una variable de entorno o un archivo con permisos 0600/0400."""
    if env_var:
        v = os.environ.get(env_var)
        if v:
            return v.encode("utf-8")
    if file:
        p = Path(file)
        mode = p.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise CertificateError(
                f"El archivo de secreto {p} es accesible por otros usuarios; use chmod 600"
            )
        return p.read_bytes().rstrip(b"\r\n")
    raise CertificateError("No se encontró el secreto del certificado (variable o archivo)")


def load_pkcs12(path: str | Path, password: bytes, now: datetime | None = None) -> SigningCredential:
    try:
        key, cert, chain = pkcs12.load_key_and_certificates(Path(path).read_bytes(), password)
    except Exception as exc:  # contraseña incorrecta o archivo dañado
        raise CertificateError(f"No se pudo abrir el certificado PKCS#12: {exc}") from exc
    if key is None or cert is None:
        raise CertificateError("El PKCS#12 debe contener la clave privada y el certificado")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CertificateError("Se requiere una clave RSA para la firma de e-CF")
    cred = SigningCredential(key, cert, list(chain or []))
    validate_credential(cred, now)
    return cred


def validate_credential(cred: SigningCredential, now: datetime | None = None) -> None:
    now = now or utcnow()
    if now < cred.not_before:
        raise CertificateError("El certificado aún no es válido")
    if now >= cred.not_after:
        raise CertificateError(f"El certificado venció el {iso(cred.not_after)}")
    try:
        ku = cred.certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (ku.digital_signature or ku.content_commitment):
            raise CertificateError("El certificado no permite firma digital (KeyUsage)")
    except x509.ExtensionNotFound:
        pass


class CertificateRegistry:
    """Registro de certificados conocidos y del certificado activo para firmar."""

    def __init__(self, db: Database):
        self.db = db

    def register(self, cred: SigningCredential, *, activate: bool) -> None:
        with self.db.transaction() as c:
            c.execute(
                "INSERT OR IGNORE INTO certificados(fingerprint_sha256, sujeto, serie, valido_desde,"
                " valido_hasta, registrado_en) VALUES (?,?,?,?,?,?)",
                (cred.fingerprint, cred.subject, format(cred.certificate.serial_number, "x"),
                 iso(cred.not_before), iso(cred.not_after), iso(utcnow())),
            )
            if activate:
                c.execute("UPDATE certificados SET activo = 0")
                c.execute("UPDATE certificados SET activo = 1 WHERE fingerprint_sha256 = ?",
                          (cred.fingerprint,))

    def active_fingerprint(self) -> str | None:
        r = self.db.conn.execute(
            "SELECT fingerprint_sha256 FROM certificados WHERE activo = 1").fetchone()
        return r[0] if r else None

    def ensure_active(self, cred: SigningCredential, now: datetime | None = None) -> None:
        validate_credential(cred, now)
        active = self.active_fingerprint()
        if active != cred.fingerprint:
            raise CertificateError(
                "El certificado cargado no es el certificado activo registrado. Complete el "
                "procedimiento de renovación (plomfact-ecf certificado-renovar)."
            )

    def rotate(self, new: SigningCredential, now: datetime | None = None) -> None:
        """Renovación segura: el nuevo certificado debe ser válido y vencer después del actual."""
        validate_credential(new, now)
        row = self.db.conn.execute(
            "SELECT valido_hasta FROM certificados WHERE activo = 1").fetchone()
        if row and datetime.fromisoformat(row[0]) >= new.not_after:
            raise CertificateError("El certificado nuevo no extiende la vigencia del actual")
        self.register(new, activate=True)

    def all(self) -> list[dict]:
        return [dict(r) for r in self.db.conn.execute("SELECT * FROM certificados")]


def generate_test_credential(common_name: str = "PRUEBAS PlomFact", days: int = 365,
                             not_before: datetime | None = None) -> SigningCredential:
    """Certificado AUTOFIRMADO solo para pruebas automatizadas. No es válido ante la DGII."""
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nb = not_before or (datetime.now(timezone.utc) - timedelta(minutes=5))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(nb + timedelta(days=days))
        .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False),
                       critical=True)
        .sign(key, hashes.SHA256())
    )
    return SigningCredential(key, cert, [])


def export_pkcs12(cred: SigningCredential, password: bytes) -> bytes:
    return pkcs12.serialize_key_and_certificates(
        b"plomfact", cred.private_key, cred.certificate, None,
        serialization.BestAvailableEncryption(password),
    )
