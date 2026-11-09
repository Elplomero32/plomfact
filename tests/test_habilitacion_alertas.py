"""Habilitación de producción, especificación verificada y alertas de vencimiento."""

from datetime import date, datetime, timedelta, timezone

import pytest

from plomfact_ecf.alerts import CRITICA, VENCIDO, ADVERTENCIA, ExpiryMonitor
from plomfact_ecf.credentials import CertificateRegistry, generate_test_credential
from plomfact_ecf.errors import ProductionGateError, SpecNotVerifiedError
from plomfact_ecf.gate import EmissionGate
from plomfact_ecf.sequences import SequenceManager
from plomfact_ecf.spec import Ambiente, DgiiSpec

from conftest import RNC, ROOT, build_content


def test_plantilla_oficial_vacia_bloquea_todo():
    spec = DgiiSpec.load(ROOT / "config" / "dgii_spec.example.toml")
    pend = spec.unverified_sections()
    assert "endpoints.recepcion_ecf" in pend and "estados" in pend and "qr" in pend
    with pytest.raises(SpecNotVerifiedError):
        spec.require_all_verified()
    with pytest.raises(SpecNotVerifiedError):
        spec.base_url(Ambiente.PRODUCCION)
    with pytest.raises(SpecNotVerifiedError):
        spec.estados("aceptados")


def test_seccion_sin_fuente_no_cuenta_como_verificada(spec):
    spec._data["estados"]["fuente"] = " "
    assert not spec.is_verified("estados")
    with pytest.raises(SpecNotVerifiedError):
        spec.estados("aceptados")


def test_emision_bloqueada_si_spec_no_verificada(env):
    env.spec._data["firma"]["verificado"] = False
    with pytest.raises(SpecNotVerifiedError):
        env.service.emit("91", build_content)


def test_produccion_bloqueada_sin_autorizacion(db, spec):
    g = EmissionGate(db, spec, produccion_habilitada=False)
    g.assert_can_emit(Ambiente.CERTIFICACION, RNC)
    with pytest.raises(ProductionGateError, match="deshabilitada"):
        g.assert_can_emit(Ambiente.PRODUCCION, RNC)
    g = EmissionGate(db, spec, produccion_habilitada=True)
    with pytest.raises(ProductionGateError, match="autorización"):
        g.assert_can_emit(Ambiente.PRODUCCION, RNC)
    with pytest.raises(ProductionGateError):
        g.register_authorization(ambiente=Ambiente.PRODUCCION, rnc_emisor=RNC, referencia=" ",
                                 registrado_por="x")
    g.register_authorization(ambiente=Ambiente.PRODUCCION, rnc_emisor=RNC,
                             referencia="Comunicación DGII ref. SIMULADA", registrado_por="Contador")
    g.assert_can_emit(Ambiente.PRODUCCION, RNC)
    with pytest.raises(Exception, match="INMUTABLE"):
        db.conn.execute("DELETE FROM habilitaciones")


def _monitor(db, spec, now=None):
    return ExpiryMonitor(db, SequenceManager(db, spec), sinks=[],
                         clock=lambda: now or datetime.now(timezone.utc))


def test_alerta_sin_certificado(db, spec):
    a = _monitor(db, spec).check()
    assert any(x.tipo == "CERTIFICADO" and x.severidad == CRITICA for x in a)


@pytest.mark.parametrize("dias,sev", [(100, None), (40, ADVERTENCIA), (10, CRITICA)])
def test_alerta_certificado_por_vencer(db, spec, dias, sev):
    CertificateRegistry(db).register(generate_test_credential(days=dias), activate=True)
    a = [x for x in _monitor(db, spec).check() if x.tipo == "CERTIFICADO"]
    assert (a[0].severidad if a else None) == sev


def test_certificado_vencido(db, spec):
    CertificateRegistry(db).register(generate_test_credential(days=10), activate=True)
    a = _monitor(db, spec, now=datetime.now(timezone.utc) + timedelta(days=20)).check()
    assert any(x.tipo == "CERTIFICADO" and x.severidad == VENCIDO for x in a)


def test_alertas_secuencias(db, spec, credential):
    CertificateRegistry(db).register(credential, activate=True)
    seq = SequenceManager(db, spec)
    seq.register_range(ambiente=Ambiente.PRECERTIFICACION, rnc_emisor=RNC, tipo_ecf="91", desde=1,
                       hasta=40, vence=date.today() + timedelta(days=5), referencia_autorizacion="A")
    a = _monitor(db, spec).check()
    tipos = {(x.clave.split(":")[0], x.severidad) for x in a if x.tipo == "SECUENCIA"}
    assert ("rango", CRITICA) in tipos           # vence en 5 días
    assert ("disponibles", CRITICA) in tipos     # 40 restantes < 50


def test_alertas_no_se_duplican_y_se_notifican_una_vez(db, spec):
    enviados = []
    m = ExpiryMonitor(db, SequenceManager(db, spec), sinks=[enviados.append])
    m.check()
    m.check()
    assert len(enviados) == 1 and len(m.open_alerts()) == 1


def test_canal_de_alerta_caido_no_detiene_el_control(db, spec):
    def roto(a):
        raise RuntimeError("smtp caído")
    m = ExpiryMonitor(db, SequenceManager(db, spec), sinks=[roto])
    assert m.check()


def test_encf_sin_uso_se_alerta(env):
    from plomfact_ecf.db import utcnow
    env.seq.allocate(ambiente=Ambiente.PRECERTIFICACION, rnc_emisor=RNC, tipo_ecf="91")
    m = ExpiryMonitor(env.db, env.seq, sinks=[], clock=lambda: utcnow() + timedelta(hours=2))
    assert any(a.clave == "encf:sin_uso" for a in m.check())
