"""Numeración e-NCF: formato, rangos, concurrencia, agotamiento y vencimiento."""

import threading
from datetime import date, timedelta

import pytest

from plomfact_ecf.db import Database
from plomfact_ecf.errors import SequenceError
from plomfact_ecf.sequences import SequenceManager
from plomfact_ecf.spec import Ambiente

from conftest import RNC

P = Ambiente.PRECERTIFICACION


@pytest.fixture
def seq(db, spec):
    return SequenceManager(db, spec)


def rango(seq, desde=1, hasta=10, tipo="91", vence=None, amb=P):
    return seq.register_range(ambiente=amb, rnc_emisor=RNC, tipo_ecf=tipo, desde=desde,
                              hasta=hasta, vence=vence or date.today() + timedelta(days=30),
                              referencia_autorizacion="AUT-1")


def test_formato(seq):
    assert seq.format_encf("91", 1) == "X9100000001"
    assert seq.validate("X9200000123") == ("92", 123)
    for malo in ("X9300000001", "X910000001", "Y9100000001", "X91000000O1", ""):
        with pytest.raises(SequenceError):
            seq.validate(malo)
    with pytest.raises(SequenceError):
        seq.format_encf("91", 10 ** 8)  # excede longitud
    with pytest.raises(SequenceError):
        seq.format_encf("91", 0)


def test_asignacion_secuencial_sin_huecos(seq):
    rango(seq)
    assert [seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91").secuencial
            for _ in range(5)] == [1, 2, 3, 4, 5]


def test_agotamiento_pasa_al_siguiente_rango_y_luego_falla(seq):
    rango(seq, 1, 2)
    rango(seq, 50, 50)
    got = [seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91").encf for _ in range(3)]
    assert got == ["X9100000001", "X9100000002", "X9100000050"]
    with pytest.raises(SequenceError, match="No hay secuencias"):
        seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91")


def test_rango_vencido_no_se_usa(seq):
    rango(seq, 1, 10, vence=date.today() - timedelta(days=1))
    with pytest.raises(SequenceError):
        seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91")


def test_rango_anulado_no_se_usa(seq):
    rid = rango(seq)
    seq.annul_range(rid)
    with pytest.raises(SequenceError):
        seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91")
    with pytest.raises(Exception, match="INMUTABLE"):
        seq.db.conn.execute("UPDATE rangos_secuencia SET estado='ACTIVO' WHERE id=?", (rid,))


def test_ambientes_y_tipos_separados(seq):
    rango(seq, 1, 5, tipo="91")
    rango(seq, 1, 5, tipo="92")
    rango(seq, 1, 5, tipo="91", amb=Ambiente.CERTIFICACION)
    assert seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="92").encf == "X9200000001"
    assert seq.allocate(ambiente=Ambiente.CERTIFICACION, rnc_emisor=RNC, tipo_ecf="91").secuencial == 1
    with pytest.raises(SequenceError):
        seq.allocate(ambiente=Ambiente.PRODUCCION, rnc_emisor=RNC, tipo_ecf="91")


def test_rangos_superpuestos_rechazados(seq):
    rango(seq, 1, 10)
    for d, h in ((5, 20), (10, 10), (0 + 1, 3)):
        with pytest.raises(SequenceError, match="superpone"):
            rango(seq, d, h)


def test_rango_requiere_referencia_y_tipo_valido(seq):
    with pytest.raises(SequenceError):
        seq.register_range(ambiente=P, rnc_emisor=RNC, tipo_ecf="91", desde=1, hasta=2,
                           vence=None, referencia_autorizacion="  ")
    with pytest.raises(SequenceError):
        rango(seq, tipo="99")
    with pytest.raises(SequenceError):
        rango(seq, 10, 5)


def test_restantes(seq):
    rango(seq, 1, 10)
    rango(seq, 20, 24)
    for _ in range(3):
        seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91")
    assert seq.remaining(ambiente=P, rnc_emisor=RNC, tipo_ecf="91") == 12


def test_encf_no_se_reutiliza_ni_borra(seq):
    rango(seq)
    a = seq.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91")
    seq.mark_used(a.id)
    with pytest.raises(SequenceError):
        seq.mark_used(a.id)
    for sql in ("UPDATE encf_asignados SET estado='ASIGNADO'", "DELETE FROM encf_asignados",
                "UPDATE encf_asignados SET secuencial=99"):
        with pytest.raises(Exception, match="INMUTABLE"):
            seq.db.conn.execute(sql)
    with pytest.raises(Exception):
        seq.db.conn.execute(
            "INSERT INTO encf_asignados(ambiente, rnc_emisor, tipo_ecf, secuencial, encf, rango_id,"
            " asignado_en) VALUES (?,?,?,?,?,?,?)",
            (P.value, RNC, "91", 1, "X9100000001", a.rango_id, "x"))


def test_concurrencia_sin_duplicados(tmp_path, spec):
    path = tmp_path / "conc.sqlite3"
    base = Database(path)
    SequenceManager(base, spec).register_range(
        ambiente=P, rnc_emisor=RNC, tipo_ecf="91", desde=1, hasta=1000, vence=None,
        referencia_autorizacion="AUT")
    resultados: list[str] = []
    lock = threading.Lock()

    def trabajador():
        d = Database(path)
        m = SequenceManager(d, spec)
        for _ in range(25):
            e = m.allocate(ambiente=P, rnc_emisor=RNC, tipo_ecf="91").encf
            with lock:
                resultados.append(e)
        d.close()

    hilos = [threading.Thread(target=trabajador) for _ in range(8)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    assert len(resultados) == 200
    assert len(set(resultados)) == 200
    assert sorted(int(e[3:]) for e in resultados) == list(range(1, 201))
