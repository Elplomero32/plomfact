"""Persistencia fiscal (SQLite) con migraciones versionadas e inmutabilidad a nivel de base de datos.

Principios para que actualizaciones y migraciones no alteren el historial fiscal:
  * Las migraciones son solo aditivas y se registran con una suma de verificación. Si una
    migración ya aplicada cambia en el código, el arranque falla (no se reescribe historia).
  * Triggers SQL impiden borrar comprobantes, e-NCF asignados, rangos, evidencias y eventos, y
    modificar los datos fiscales ya firmados o un estado fiscal final.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .errors import FiscalError

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "esquema inicial", """
CREATE TABLE certificados (
    id INTEGER PRIMARY KEY,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    sujeto TEXT NOT NULL,
    serie TEXT NOT NULL,
    valido_desde TEXT NOT NULL,
    valido_hasta TEXT NOT NULL,
    registrado_en TEXT NOT NULL,
    activo INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rangos_secuencia (
    id INTEGER PRIMARY KEY,
    ambiente TEXT NOT NULL,
    rnc_emisor TEXT NOT NULL,
    tipo_ecf TEXT NOT NULL,
    desde INTEGER NOT NULL CHECK (desde > 0),
    hasta INTEGER NOT NULL CHECK (hasta >= desde),
    vence TEXT,
    referencia_autorizacion TEXT NOT NULL CHECK (length(trim(referencia_autorizacion)) > 0),
    estado TEXT NOT NULL DEFAULT 'ACTIVO' CHECK (estado IN ('ACTIVO','ANULADO')),
    registrado_en TEXT NOT NULL
);

CREATE TABLE encf_asignados (
    id INTEGER PRIMARY KEY,
    ambiente TEXT NOT NULL,
    rnc_emisor TEXT NOT NULL,
    tipo_ecf TEXT NOT NULL,
    secuencial INTEGER NOT NULL,
    encf TEXT NOT NULL,
    rango_id INTEGER NOT NULL REFERENCES rangos_secuencia(id),
    estado TEXT NOT NULL DEFAULT 'ASIGNADO' CHECK (estado IN ('ASIGNADO','USADO','ANULADO')),
    asignado_en TEXT NOT NULL,
    UNIQUE (ambiente, rnc_emisor, encf),
    UNIQUE (ambiente, rnc_emisor, tipo_ecf, secuencial)
);

CREATE TABLE comprobantes (
    id INTEGER PRIMARY KEY,
    ambiente TEXT NOT NULL,
    rnc_emisor TEXT NOT NULL,
    encf TEXT NOT NULL,
    tipo_ecf TEXT NOT NULL,
    estado TEXT NOT NULL,
    estado_dgii TEXT,
    track_id TEXT,
    codigo_seguridad TEXT NOT NULL,
    fecha_firma TEXT NOT NULL,
    xml_firmado_sha256 TEXT NOT NULL,
    certificado_fingerprint TEXT NOT NULL,
    contingencia INTEGER NOT NULL DEFAULT 0,
    creado_en TEXT NOT NULL,
    actualizado_en TEXT NOT NULL,
    UNIQUE (ambiente, rnc_emisor, encf)
);

CREATE TABLE eventos_comprobante (
    id INTEGER PRIMARY KEY,
    comprobante_id INTEGER NOT NULL REFERENCES comprobantes(id),
    en TEXT NOT NULL,
    de_estado TEXT,
    a_estado TEXT NOT NULL,
    detalle TEXT
);

CREATE TABLE cola_transmision (
    id INTEGER PRIMARY KEY,
    comprobante_id INTEGER NOT NULL UNIQUE REFERENCES comprobantes(id),
    estado TEXT NOT NULL CHECK (estado IN ('PENDIENTE','ENVIANDO','ENVIADO','AMBIGUO','DETENIDO')),
    intentos INTEGER NOT NULL DEFAULT 0,
    proximo_intento TEXT NOT NULL,
    ultimo_error TEXT,
    actualizado_en TEXT NOT NULL
);

CREATE TABLE evidencias (
    id INTEGER PRIMARY KEY,
    comprobante_id INTEGER REFERENCES comprobantes(id),
    tipo TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    ruta TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    creado_en TEXT NOT NULL,
    hash_cadena TEXT NOT NULL UNIQUE
);

CREATE TABLE alertas (
    id INTEGER PRIMARY KEY,
    clave TEXT NOT NULL,
    tipo TEXT NOT NULL,
    severidad TEXT NOT NULL,
    mensaje TEXT NOT NULL,
    vence TEXT,
    creado_en TEXT NOT NULL,
    resuelta_en TEXT
);
CREATE UNIQUE INDEX alertas_abiertas ON alertas(clave, severidad) WHERE resuelta_en IS NULL;

CREATE TABLE habilitaciones (
    id INTEGER PRIMARY KEY,
    ambiente TEXT NOT NULL,
    rnc_emisor TEXT NOT NULL,
    referencia_autorizacion TEXT NOT NULL CHECK (length(trim(referencia_autorizacion)) > 0),
    registrado_por TEXT NOT NULL,
    registrado_en TEXT NOT NULL
);

-- ---------------------------------------------------------------- inmutabilidad
CREATE TRIGGER no_borrar_comprobantes BEFORE DELETE ON comprobantes
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: los comprobantes no se pueden borrar'); END;

CREATE TRIGGER no_alterar_datos_fiscales BEFORE UPDATE ON comprobantes
WHEN NEW.encf IS NOT OLD.encf OR NEW.ambiente IS NOT OLD.ambiente
  OR NEW.rnc_emisor IS NOT OLD.rnc_emisor OR NEW.tipo_ecf IS NOT OLD.tipo_ecf
  OR NEW.codigo_seguridad IS NOT OLD.codigo_seguridad OR NEW.fecha_firma IS NOT OLD.fecha_firma
  OR NEW.xml_firmado_sha256 IS NOT OLD.xml_firmado_sha256
  OR NEW.certificado_fingerprint IS NOT OLD.certificado_fingerprint
  OR NEW.creado_en IS NOT OLD.creado_en
  OR (OLD.track_id IS NOT NULL AND NEW.track_id IS NOT OLD.track_id)
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: datos fiscales firmados no se pueden modificar'); END;

CREATE TRIGGER estado_final_inmutable BEFORE UPDATE OF estado ON comprobantes
WHEN OLD.estado IN ('ACEPTADO','ACEPTADO_CONDICIONAL','RECHAZADO') AND NEW.estado IS NOT OLD.estado
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: estado fiscal final'); END;

CREATE TRIGGER no_borrar_encf BEFORE DELETE ON encf_asignados
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: e-NCF asignados no se pueden borrar'); END;

CREATE TRIGGER encf_no_reutilizable BEFORE UPDATE ON encf_asignados
WHEN NEW.encf IS NOT OLD.encf OR NEW.secuencial IS NOT OLD.secuencial
  OR NEW.rango_id IS NOT OLD.rango_id OR OLD.estado IN ('USADO','ANULADO')
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: e-NCF ya usado o anulado'); END;

CREATE TRIGGER no_borrar_rangos BEFORE DELETE ON rangos_secuencia
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: rangos autorizados no se pueden borrar'); END;

CREATE TRIGGER rangos_solo_anular BEFORE UPDATE ON rangos_secuencia
WHEN NEW.desde IS NOT OLD.desde OR NEW.hasta IS NOT OLD.hasta OR NEW.tipo_ecf IS NOT OLD.tipo_ecf
  OR NEW.rnc_emisor IS NOT OLD.rnc_emisor OR NEW.ambiente IS NOT OLD.ambiente
  OR NEW.referencia_autorizacion IS NOT OLD.referencia_autorizacion
  OR NEW.vence IS NOT OLD.vence OR OLD.estado = 'ANULADO'
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: un rango autorizado solo puede anularse'); END;

CREATE TRIGGER evidencias_append_only_u BEFORE UPDATE ON evidencias
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: evidencias'); END;
CREATE TRIGGER evidencias_append_only_d BEFORE DELETE ON evidencias
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: evidencias'); END;

CREATE TRIGGER eventos_append_only_u BEFORE UPDATE ON eventos_comprobante
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: eventos'); END;
CREATE TRIGGER eventos_append_only_d BEFORE DELETE ON eventos_comprobante
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: eventos'); END;

CREATE TRIGGER habilitaciones_append_only_u BEFORE UPDATE ON habilitaciones
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: habilitaciones'); END;
CREATE TRIGGER habilitaciones_append_only_d BEFORE DELETE ON habilitaciones
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: habilitaciones'); END;
"""),
    (2, "periodos de contingencia", """
CREATE TABLE contingencia_periodos (
    id INTEGER PRIMARY KEY,
    inicio TEXT NOT NULL,
    fin TEXT,
    motivo TEXT NOT NULL
);
CREATE UNIQUE INDEX contingencia_abierta ON contingencia_periodos((fin IS NULL)) WHERE fin IS NULL;
CREATE TRIGGER contingencia_cierre_unico BEFORE UPDATE ON contingencia_periodos
WHEN OLD.fin IS NOT NULL OR NEW.inicio IS NOT OLD.inicio OR NEW.motivo IS NOT OLD.motivo
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: periodo de contingencia cerrado'); END;
CREATE TRIGGER contingencia_no_borrar BEFORE DELETE ON contingencia_periodos
BEGIN SELECT RAISE(ABORT, 'INMUTABLE: periodo de contingencia'); END;
"""),
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _checksum(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA busy_timeout = 10000")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = FULL")
        self.migrate()

    def migrate(self) -> None:
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY, descripcion TEXT NOT NULL,"
            " checksum TEXT NOT NULL, aplicada_en TEXT NOT NULL)"
        )
        applied = {r["version"]: r["checksum"] for r in
                   self.conn.execute("SELECT version, checksum FROM schema_migrations")}
        versions = [m[0] for m in MIGRATIONS]
        if versions != sorted(versions) or len(set(versions)) != len(versions):
            raise FiscalError("Las migraciones deben tener versiones únicas y crecientes")
        for version, desc, sql in MIGRATIONS:
            cs = _checksum(sql)
            if version in applied:
                if applied[version] != cs:
                    raise FiscalError(
                        f"La migración {version} ya aplicada fue modificada. Las migraciones "
                        "fiscales son inmutables: agregue una migración nueva."
                    )
                continue
            with self.transaction():
                for stmt in _split_sql(sql):
                    self.conn.execute(stmt)
                self.conn.execute(
                    "INSERT INTO schema_migrations VALUES (?,?,?,?)",
                    (version, desc, cs, iso(utcnow())),
                )
        unknown = set(applied) - set(versions)
        if unknown:
            raise FiscalError(
                f"La base de datos tiene migraciones más nuevas que este código: {sorted(unknown)}. "
                "No se permite operar con una versión anterior de la aplicación."
            )

    @contextmanager
    def transaction(self, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def close(self) -> None:
        self.conn.close()


def _split_sql(script: str) -> list[str]:
    """Divide un script en sentencias respetando los bloques BEGIN...END de los triggers."""
    stmts: list[str] = []
    buf = ""
    for line in script.splitlines():
        if line.strip().startswith("--") and not buf.strip():
            continue
        buf += line + "\n"
        if sqlite3.complete_statement(buf):
            if buf.strip():
                stmts.append(buf.strip())
            buf = ""
    if buf.strip():
        raise FiscalError("Sentencia SQL incompleta en migración")
    return stmts
