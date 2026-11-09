"""Autenticación (semilla firmada → token) y llamadas autenticadas."""

from datetime import timedelta

import pytest

from plomfact_ecf.dgii_client import DgiiClient
from plomfact_ecf.errors import DgiiAuthError, SpecNotVerifiedError
from plomfact_ecf.spec import Ambiente


def test_autenticacion_y_reuso_de_token(env):
    env.client.authenticate()
    t = env.client.token()
    assert t == "T1" and env.fake.seed_count == 1
    env.client.query_result("trk-x")
    env.client.query_result("trk-y")
    assert env.fake.seed_count == 1  # el token vigente se reutiliza


def test_renovacion_antes_de_expirar(env):
    env.fake.token_ttl = timedelta(seconds=30)  # menor que el margen de 60 s
    env.client.query_result("a")
    env.client.query_result("b")
    assert env.fake.seed_count == 2


def test_token_revocado_reautentica(env):
    env.client.query_result("a")
    env.fake.tokens.clear()
    r = env.client.query_result("a")
    assert r.status_code == 200 and env.fake.seed_count == 2


def test_semilla_firmada_con_otro_certificado_falla(env):
    from plomfact_ecf.credentials import generate_test_credential
    env.fake.credential = generate_test_credential("INTRUSO")
    with pytest.raises(Exception):
        env.client.authenticate()


def test_solo_https(env, spec):
    import tomllib
    from plomfact_ecf.spec import DgiiSpec
    from conftest import FIX
    d = tomllib.load(open(FIX / "spec_pruebas.toml", "rb"))
    d["ambientes"]["precertificacion"]["base_url"] = "http://inseguro.invalid"
    c = DgiiClient(DgiiSpec(d), Ambiente.PRECERTIFICACION, env.signer, session=env.client.session)
    with pytest.raises(SpecNotVerifiedError, match="HTTPS"):
        c.authenticate()


def test_estatus_servicio(env):
    assert env.client.service_available() is True
    env.fake.down = True
    assert env.client.service_available() is False
