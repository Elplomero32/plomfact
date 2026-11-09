"""Cola de transmisión, reintentos seguros, envíos ambiguos, contingencia y recuperación."""

import tomllib

import pytest

from plomfact_ecf.contingency import recover
from plomfact_ecf.spec import DgiiSpec
from plomfact_ecf.transmission import backoff

from conftest import FIX, build_content


def cola(env, cid):
    return dict(env.db.conn.execute("SELECT * FROM cola_transmision WHERE comprobante_id=?",
                                    (cid,)).fetchone())


def test_backoff_exponencial_acotado():
    assert [backoff(i).total_seconds() for i in (1, 2, 3)] == [30, 60, 120]
    assert backoff(50).total_seconds() == 3600


def test_conexion_rechazada_reintenta_sin_duplicar(env):
    r = env.service.emit("91", build_content)
    env.fake.fail_queue = ["refused"]
    assert env.queue.process_due()["reintentos"] == 1
    q = cola(env, r.comprobante_id)
    assert q["estado"] == "PENDIENTE" and q["intentos"] == 1
    assert env.queue.process_due() == {"enviados": 0, "reintentos": 0, "ambiguos": 0, "detenidos": 0}
    env.advance(31)
    assert env.queue.process_due()["enviados"] == 1
    assert len(env.fake.received) == 1


def test_timeout_tras_envio_no_reenvia_a_ciegas(env):
    r = env.service.emit("91", build_content)
    env.fake.fail_queue = ["timeout_after_send"]  # la DGII lo recibió pero no respondió
    assert env.queue.process_due()["ambiguos"] == 1
    assert cola(env, r.comprobante_id)["estado"] == "AMBIGUO"
    env.advance(31)
    assert env.queue.process_due()["enviados"] == 1
    st = env.service.status(r.comprobante_id)
    assert st["estado"] == "TRANSMITIDO" and st["track_id"] == "trk-1"
    # Solo hubo UNA recepción: el trackId se recuperó por consulta, no reenviando.
    assert sum(1 for m, p in env.fake.calls if p == "/sim/recepcion") == 1
    assert ("GET", "/sim/trackids") in env.fake.calls


def test_ambiguo_no_recibido_se_reenvia(env):
    r = env.service.emit("91", build_content)
    env.fake.fail_queue = ["500"]  # error de servidor: ambiguo
    assert env.queue.process_due()["ambiguos"] == 1
    env.advance(31)
    assert env.queue.process_due()["enviados"] == 1  # trackIds vacío → reenvío seguro
    assert env.service.status(r.comprobante_id)["track_id"] == "trk-1"


def test_ambiguo_sin_servicio_de_consulta_se_detiene(env, spec):
    d = tomllib.load(open(FIX / "spec_pruebas.toml", "rb"))
    d["endpoints"]["consulta_trackids"]["verificado"] = False
    env.queue.spec = env.client.spec = DgiiSpec(d)
    r = env.service.emit("91", build_content)
    env.fake.fail_queue = ["timeout_after_send"]
    env.queue.process_due()
    env.advance(31)
    assert env.queue.process_due()["detenidos"] == 1
    assert env.service.status(r.comprobante_id)["estado"] == "REVISION_REQUERIDA"
    assert cola(env, r.comprobante_id)["estado"] == "DETENIDO"


def test_rechazo_de_solicitud_se_detiene(env):
    r = env.service.emit("91", build_content)
    env.fake.fail_queue = ["400"]
    assert env.queue.process_due()["detenidos"] == 1
    st = env.service.status(r.comprobante_id)
    assert st["estado"] == "REVISION_REQUERIDA" and not st["fiscalmente_valido"]


def test_contingencia_se_activa_y_desactiva(env):
    env.fake.fail_queue = ["refused", "refused"]
    r1 = env.service.emit("91", build_content)
    assert not r1.contingencia
    env.queue.process_due()
    env.advance(31)
    env.queue.process_due()
    assert env.cont.active()  # 2 fallos consecutivos (umbral del fixture)
    r2 = env.service.emit("91", build_content)
    assert r2.contingencia and not r2.fiscalmente_valido
    env.advance(3600)
    env.queue.process_due()
    assert not env.cont.active()
    periodos = env.cont.periods()
    assert len(periodos) == 1 and periodos[0]["fin"] is not None
    env.queue.poll_status()
    for r in (r1, r2):
        assert env.service.status(r.comprobante_id)["fiscalmente_valido"]


def test_contingencia_vencida_reportada(env):
    from datetime import timedelta
    from plomfact_ecf.db import utcnow
    env.cont.activate("prueba")
    r = env.service.emit("91", build_content)
    assert env.cont.overdue() == []
    vencidos = env.cont.overdue(now=utcnow() + timedelta(hours=25))
    assert [v["id"] for v in vencidos] == [r.comprobante_id]


def test_recuperacion_tras_caida_en_pleno_envio(env):
    r = env.service.emit("91", build_content)
    env.db.conn.execute("UPDATE cola_transmision SET estado='ENVIANDO'")  # simula caída
    assert recover(env.db) == {"envios_interrumpidos": 1}
    assert cola(env, r.comprobante_id)["estado"] == "AMBIGUO"
    env.queue.process_due()
    assert env.service.status(r.comprobante_id)["estado"] == "TRANSMITIDO"


def test_comprobante_con_trackid_nunca_se_reenvia(env):
    r = env.service.emit("91", build_content)
    env.queue.process_due()
    env.db.conn.execute("UPDATE cola_transmision SET estado='PENDIENTE'")
    env.queue.process_due()
    assert sum(1 for m, p in env.fake.calls if p == "/sim/recepcion") == 1
    with pytest.raises(Exception, match="INMUTABLE"):
        env.db.conn.execute("UPDATE comprobantes SET track_id='otro'")


def test_ambiguo_con_respuesta_no_concluyente_no_reenvia(env, monkeypatch):
    import json
    r = env.service.emit("91", build_content)
    env.fake.fail_queue = ["500"]
    env.queue.process_due()
    original = env.fake.send

    def inconcluso(request, **kw):
        if "/sim/trackids" in request.url:
            return env.fake._resp(request, 200, json.dumps({"otro": "dato"}))
        return original(request, **kw)
    monkeypatch.setattr(env.fake, "send", inconcluso)
    env.advance(31)
    assert env.queue.process_due()["ambiguos"] == 1
    assert sum(1 for m, p in env.fake.calls if p == "/sim/recepcion") == 1
    assert cola(env, r.comprobante_id)["estado"] == "AMBIGUO"
