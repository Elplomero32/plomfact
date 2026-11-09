"""Conservación de evidencias e integridad del historial ante actualizaciones y migraciones."""

import os
import shutil

import pytest

from plomfact_ecf import db as dbmod
from plomfact_ecf.archive import EvidenceStore
from plomfact_ecf.db import Database
from plomfact_ecf.errors import FiscalError, ImmutableRecordError

from conftest import build_content


def test_evidencias_inmutables_y_verificables(env):
    r = env.service.emit("91", build_content)
    env.queue.process_due()
    assert env.store.verify() == []
    ev = env.store.for_document(r.comprobante_id)
    assert all(oct(os.stat(env.store.root / e["ruta"]).st_mode)[-3:] == "444" for e in ev)
    for sql in ("UPDATE evidencias SET sha256='x'", "DELETE FROM evidencias",
                "DELETE FROM eventos_comprobante", "UPDATE eventos_comprobante SET detalle='x'"):
        with pytest.raises(Exception, match="INMUTABLE"):
            env.db.conn.execute(sql)


def test_alteracion_de_archivo_detectada(env):
    r = env.service.emit("91", build_content)
    e = env.store.for_document(r.comprobante_id)[0]
    p = env.store.root / e["ruta"]
    os.chmod(p, 0o644)
    p.write_bytes(b"alterado")
    assert any("alterado" in x for x in env.store.verify())
    with pytest.raises(ImmutableRecordError):
        env.store.read(e["sha256"])


def test_eliminacion_de_archivo_detectada(env):
    r = env.service.emit("91", build_content)
    e = env.store.for_document(r.comprobante_id)[0]
    p = env.store.root / e["ruta"]
    os.chmod(p, 0o644)
    p.unlink()
    assert any("Falta" in x for x in env.store.verify())


def test_cadena_detecta_registro_manipulado(tmp_path):
    d = Database(tmp_path / "a.sqlite3")
    s = EvidenceStore(d, tmp_path / "ev")
    for i in range(3):
        s.store("ERROR_TRANSMISION", f"e{i}".encode())
    d.conn.execute("DROP TRIGGER evidencias_append_only_u")  # ataque con acceso directo a la BD
    d.conn.execute("UPDATE evidencias SET creado_en='2000-01-01' WHERE id=2")
    assert any("Cadena rota" in x for x in s.verify())


def test_reapertura_conserva_historial(tmp_path, env):
    r = env.service.emit("91", build_content)
    env.queue.process_due()
    env.queue.poll_status()
    antes = env.service.status(r.comprobante_id)
    env.db.close()
    # "Migración de infraestructura": copiar base de datos y evidencias a otra ubicación
    nuevo = tmp_path / "servidor2"
    nuevo.mkdir()
    shutil.copy(env.db.path, nuevo / "fiscal.sqlite3")
    shutil.copytree(env.store.root, nuevo / "evidencias")
    d2 = Database(nuevo / "fiscal.sqlite3")
    s2 = EvidenceStore(d2, nuevo / "evidencias")
    despues = dict(d2.conn.execute("SELECT * FROM comprobantes WHERE id=?",
                                   (r.comprobante_id,)).fetchone())
    assert {k: antes[k] for k in despues} == despues
    assert s2.verify() == []


def test_migracion_modificada_es_rechazada(tmp_path, monkeypatch):
    p = tmp_path / "m.sqlite3"
    Database(p).close()
    v, desc, sql = dbmod.MIGRATIONS[0]
    monkeypatch.setattr(dbmod, "MIGRATIONS", [(v, desc, sql + "\n-- cambio"), *dbmod.MIGRATIONS[1:]])
    with pytest.raises(FiscalError, match="fue modificada"):
        Database(p)


def test_version_anterior_de_la_app_no_opera(tmp_path, monkeypatch):
    p = tmp_path / "m.sqlite3"
    Database(p).close()
    monkeypatch.setattr(dbmod, "MIGRATIONS", dbmod.MIGRATIONS[:1])
    with pytest.raises(FiscalError, match="más nuevas"):
        Database(p)


def test_nueva_migracion_aditiva_preserva_datos(tmp_path, monkeypatch, env):
    r = env.service.emit("91", build_content)
    path = env.db.path
    env.db.close()
    monkeypatch.setattr(dbmod, "MIGRATIONS", [*dbmod.MIGRATIONS,
                        (99, "columna nueva", "ALTER TABLE comprobantes ADD COLUMN nota TEXT;")])
    d = Database(path)
    row = d.conn.execute("SELECT encf, codigo_seguridad, nota FROM comprobantes WHERE id=?",
                         (r.comprobante_id,)).fetchone()
    assert row["encf"] == r.encf and row["codigo_seguridad"] == r.codigo_seguridad
    assert row["nota"] is None
