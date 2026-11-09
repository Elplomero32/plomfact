"""Conservación de evidencias fiscales: XML firmados, respuestas oficiales, representaciones
impresas y evidencias de transmisión.

  * Almacenamiento por contenido (SHA-256): el nombre del archivo es su huella. Un archivo
    nunca se sobrescribe con contenido distinto.
  * Archivos de solo lectura (0444) escritos de forma atómica (temporal + fsync + rename).
  * Cada registro se encadena con el anterior (hash_cadena): borrar, reordenar o alterar una
    evidencia rompe la cadena y verify() lo detecta.
  * La ruta raíz es configurable: migrar infraestructura = copiar el directorio y la base de datos.
    Las rutas se guardan relativas a la raíz, de modo que el traslado no altera el historial.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .db import Database, iso, utcnow
from .errors import ImmutableRecordError

TIPOS = {
    "XML_FIRMADO", "SOLICITUD_RECEPCION", "RESPUESTA_RECEPCION", "RESPUESTA_CONSULTA",
    "RESPUESTA_TRACKIDS", "REPRESENTACION_IMPRESA", "ERROR_TRANSMISION",
}

GENESIS = "0" * 64


@dataclass(frozen=True)
class Evidence:
    id: int
    sha256: str
    ruta: str


class EvidenceStore:
    def __init__(self, db: Database, root: str | Path):
        self.db = db
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, sha: str) -> Path:
        return self.root / sha[:2] / sha[2:4] / sha

    def _write(self, data: bytes) -> tuple[str, str]:
        sha = hashlib.sha256(data).hexdigest()
        p = self._path(sha)
        if p.exists():
            if hashlib.sha256(p.read_bytes()).hexdigest() != sha:
                raise ImmutableRecordError(f"Evidencia alterada en disco: {p}")
            return sha, str(p.relative_to(self.root))
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, p)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return sha, str(p.relative_to(self.root))

    def store(self, tipo: str, data: bytes, comprobante_id: int | None = None) -> Evidence:
        with self.db.transaction() as c:
            return self.store_in_tx(c, tipo, data, comprobante_id)

    def store_in_tx(self, c, tipo: str, data: bytes, comprobante_id: int | None) -> Evidence:
        """Registra la evidencia dentro de una transacción ya abierta (el archivo se escribe antes)."""
        if tipo not in TIPOS:
            raise ValueError(f"Tipo de evidencia desconocido: {tipo}")
        sha, ruta = self._write(data)
        prev = c.execute("SELECT hash_cadena FROM evidencias ORDER BY id DESC LIMIT 1").fetchone()
        creado = iso(utcnow())
        cadena = _chain(prev[0] if prev else GENESIS, comprobante_id, tipo, sha, creado)
        cur = c.execute(
            "INSERT INTO evidencias(comprobante_id, tipo, sha256, ruta, bytes, creado_en,"
            " hash_cadena) VALUES (?,?,?,?,?,?,?)",
            (comprobante_id, tipo, sha, ruta, len(data), creado, cadena),
        )
        return Evidence(int(cur.lastrowid), sha, ruta)

    def read(self, sha: str) -> bytes:
        data = self._path(sha).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ImmutableRecordError(f"Evidencia {sha} alterada")
        return data

    def for_document(self, comprobante_id: int) -> list[dict]:
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM evidencias WHERE comprobante_id=? ORDER BY id", (comprobante_id,))]

    def verify(self) -> list[str]:
        """Verifica archivos y cadena completa. Devuelve la lista de problemas (vacía = íntegro)."""
        problemas: list[str] = []
        prev = GENESIS
        for r in self.db.conn.execute("SELECT * FROM evidencias ORDER BY id"):
            esperado = _chain(prev, r["comprobante_id"], r["tipo"], r["sha256"], r["creado_en"])
            if esperado != r["hash_cadena"]:
                problemas.append(f"Cadena rota en evidencia #{r['id']}")
            p = self.root / r["ruta"]
            if not p.exists():
                problemas.append(f"Falta el archivo de la evidencia #{r['id']}")
            elif hashlib.sha256(p.read_bytes()).hexdigest() != r["sha256"]:
                problemas.append(f"Contenido alterado en evidencia #{r['id']}")
            prev = r["hash_cadena"]
        return problemas


def _chain(prev: str, comprobante_id: int | None, tipo: str, sha: str, creado: str) -> str:
    material = f"{prev}|{comprobante_id or ''}|{tipo}|{sha}|{creado}".encode()
    return hashlib.sha256(material).hexdigest()
