"""Emisión → transmisión → consulta → validez fiscal."""

import pytest

from plomfact_ecf.errors import ImmutableRecordError, InvalidStateTransition
from plomfact_ecf.status import Estado, transition
from plomfact_ecf.xmlsign import verify_signature

from conftest import RNC, build_content


def test_emision_completa_aceptada(env):
    r = env.service.emit("91", build_content)
    assert r.encf == "X9100000001"
    assert r.estado == Estado.EN_COLA
    assert not r.fiscalmente_valido  # sin aceptación DGII no hay validez
    assert len(r.codigo_seguridad) == 6

    stats = env.queue.process_due()
    assert stats["enviados"] == 1
    st = env.service.status(r.comprobante_id)
    assert st["estado"] == "TRANSMITIDO" and st["track_id"] == "trk-1"
    assert not st["fiscalmente_valido"]

    env.queue.poll_status()
    st = env.service.status(r.comprobante_id)
    assert st["estado"] == "ACEPTADO" and st["estado_dgii"] == "SIM_OK"
    assert st["fiscalmente_valido"]

    # El XML recibido por la "DGII" es exactamente el archivado y su firma es válida
    xml = env.store.read(st["xml_firmado_sha256"])
    assert xml in env.fake.received[r.encf]
    verify_signature(xml, env.cred)

    tipos = [e["tipo"] for e in env.store.for_document(r.comprobante_id)]
    for t in ("XML_FIRMADO", "REPRESENTACION_IMPRESA", "RESPUESTA_RECEPCION", "RESPUESTA_CONSULTA"):
        assert t in tipos
    assert env.store.verify() == []


@pytest.mark.parametrize("estado_dgii,esperado,valido", [
    ("SIM_RECHAZO", "RECHAZADO", False),
    ("SIM_OK_COND", "ACEPTADO_CONDICIONAL", True),
    ("SIM_PROCESANDO", "EN_PROCESO", False),
    ("VALOR_NO_DOCUMENTADO", "REVISION_REQUERIDA", False),
])
def test_clasificacion_estados(env, estado_dgii, esperado, valido):
    env.fake.default_state = estado_dgii
    r = env.service.emit("91", build_content)
    env.queue.process_due()
    env.queue.poll_status()
    st = env.service.status(r.comprobante_id)
    assert st["estado"] == esperado
    assert st["fiscalmente_valido"] is valido


def test_en_proceso_luego_aceptado(env):
    env.fake.default_state = "SIM_PROCESANDO"
    r = env.service.emit("91", build_content)
    env.queue.process_due()
    env.queue.poll_status()
    assert env.service.status(r.comprobante_id)["estado"] == "EN_PROCESO"
    env.fake.state_of["trk-1"] = "SIM_OK"
    env.queue.poll_status()
    assert env.service.status(r.comprobante_id)["fiscalmente_valido"]


def test_estado_final_es_inmutable(env):
    r = env.service.emit("91", build_content)
    env.queue.process_due()
    env.queue.poll_status()
    with pytest.raises(InvalidStateTransition):
        transition(env.db, r.comprobante_id, Estado.RECHAZADO)
    with pytest.raises(Exception, match="INMUTABLE"):
        env.db.conn.execute("UPDATE comprobantes SET estado='RECHAZADO' WHERE id=?",
                            (r.comprobante_id,))
    with pytest.raises(Exception, match="INMUTABLE"):
        env.db.conn.execute("UPDATE comprobantes SET codigo_seguridad='XXXXXX'")
    with pytest.raises(Exception, match="INMUTABLE"):
        env.db.conn.execute("DELETE FROM comprobantes")


def test_no_se_puede_saltar_a_aceptado(env):
    r = env.service.emit("91", build_content)
    with pytest.raises(InvalidStateTransition):
        transition(env.db, r.comprobante_id, Estado.ACEPTADO)


def test_xml_que_no_cumple_xsd_no_se_emite(env):
    from plomfact_ecf.errors import XmlValidationError

    def malo(encf):
        c = build_content(encf)
        c[1] = ("Totales", [("TotalSim", "no-numerico")])
        return c
    with pytest.raises(XmlValidationError):
        env.service.emit("91", malo)
    # El e-NCF consumido no se reutiliza y queda reportado para anulación
    assert [p["encf"] for p in env.seq.assigned_unused()] == ["X9100000001"]
    r = env.service.emit("91", build_content)
    assert r.encf == "X9100000002"


def test_xml_con_encf_distinto_al_asignado_se_rechaza(env):
    from plomfact_ecf.errors import XmlValidationError
    with pytest.raises(XmlValidationError, match="encf"):
        env.service.emit("91", lambda encf: build_content("X9100000099"))


def test_xml_con_rnc_distinto_se_rechaza(env):
    from plomfact_ecf.errors import XmlValidationError
    with pytest.raises(XmlValidationError, match="rnc_emisor"):
        env.service.emit("91", lambda encf: build_content(encf, rnc="999999999"))
