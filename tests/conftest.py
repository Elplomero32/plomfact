"""Fixtures compartidos. Todo lo "DGII" aquí es SIMULADO (dominio .invalid)."""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from requests.adapters import BaseAdapter
from urllib3.exceptions import MaxRetryError, NewConnectionError

from plomfact_ecf.archive import EvidenceStore
from plomfact_ecf.contingency import ContingencyManager
from plomfact_ecf.credentials import CertificateRegistry, generate_test_credential
from plomfact_ecf.db import Database
from plomfact_ecf.dgii_client import DgiiClient
from plomfact_ecf.gate import EmissionGate
from plomfact_ecf.sequences import SequenceManager
from plomfact_ecf.service import EmissionService
from plomfact_ecf.spec import Ambiente, DgiiSpec
from plomfact_ecf.transmission import TransmissionQueue
from plomfact_ecf.xmlsign import Signer, XsdValidator, verify_signature

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent
RNC = "101000001"


class FakeDgii(BaseAdapter):
    """Servidor DGII simulado con fallos programables."""

    def __init__(self, credential):
        super().__init__()
        self.credential = credential
        self.tokens: set[str] = set()
        self.token_ttl = timedelta(hours=1)
        self.received: dict[str, bytes] = {}       # encf -> xml
        self.track_of: dict[str, str] = {}          # encf -> trackid
        self.state_of: dict[str, str] = {}          # trackid -> estado
        self.default_state = "SIM_OK"
        self.calls: list[tuple[str, str]] = []
        self.fail_queue: list[str] = []             # "refused" | "timeout_after_send" | "500" | "400"
        self.seed_count = 0
        self.down = False

    def _resp(self, req, code: int, body: bytes | str, ctype="application/json"):
        r = requests.Response()
        r.status_code = code
        r._content = body.encode() if isinstance(body, str) else body
        r.headers["Content-Type"] = ctype
        r.url = req.url
        r.request = req
        return r

    def send(self, request, **kwargs):
        u = urlparse(request.url)
        path = u.path
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        self.calls.append((request.method, path))
        assert kwargs.get("verify") not in (False, None, ""), "TLS debe verificarse siempre"
        if self.down:
            raise requests.exceptions.ConnectionError(
                MaxRetryError(None, request.url, NewConnectionError(None, "refused")))
        if path == "/sim/semilla":
            self.seed_count += 1
            return self._resp(request, 200,
                              f"<SemillaSim><valor>{self.seed_count}abc</valor></SemillaSim>",
                              "text/xml")
        if path == "/sim/validar-semilla":
            body = request.body
            xml = body[body.index(b"<?xml"):body.rindex(b">") + 1]
            verify_signature(xml, self.credential)
            tok = f"T{len(self.tokens) + 1}"
            self.tokens.add(tok)
            exp = (datetime.now(timezone.utc) + self.token_ttl).isoformat()
            return self._resp(request, 200, json.dumps({"tokenSim": tok, "expiraSim": exp}))
        if path == "/sim/estatus":
            return self._resp(request, 200, "{}")
        if request.headers.get("X-Token-Sim", "").removeprefix("Sim ") not in self.tokens:
            return self._resp(request, 401, "{}")
        if path == "/sim/recepcion":
            if self.fail_queue:
                f = self.fail_queue.pop(0)
                if f == "refused":
                    raise requests.exceptions.ConnectionError(
                        MaxRetryError(None, request.url, NewConnectionError(None, "refused")))
                if f == "timeout_after_send":
                    self._receive(request)
                    raise requests.exceptions.ReadTimeout("timeout")
                if f == "500":
                    return self._resp(request, 500, "{}")
                if f == "400":
                    return self._resp(request, 400, json.dumps({"mensajesSim": ["inválido"]}))
            encf = self._receive(request)
            return self._resp(request, 200, json.dumps({"seguimientoSim": self.track_of[encf]}))
        if path == "/sim/resultado":
            tid = q["id_sim"]
            return self._resp(request, 200, json.dumps(
                {"seguimientoSim": tid, "estadoSim": self.state_of.get(tid, "SIM_NO_EXISTE"),
                 "mensajesSim": []}))
        if path == "/sim/trackids":
            encf = q["encf_sim"]
            if encf in self.track_of:
                return self._resp(request, 200, json.dumps(
                    [{"seguimientoSim": self.track_of[encf], "estadoSim": "SIM_PROCESANDO"}]))
            return self._resp(request, 200, "[]")
        return self._resp(request, 404, "{}")

    def _receive(self, request) -> str:
        body = request.body
        m = re.search(rb'filename="(\d+)(X\d+)\.xml"', body)
        encf = m.group(2).decode()
        self.received[encf] = body
        if encf not in self.track_of:
            tid = f"trk-{len(self.track_of) + 1}"
            self.track_of[encf] = tid
            self.state_of[tid] = self.default_state
        return encf

    def receptions(self, encf: str) -> int:
        return sum(1 for m, p in self.calls if p == "/sim/recepcion")

    def close(self):
        pass


@pytest.fixture
def spec() -> DgiiSpec:
    return DgiiSpec.load(FIX / "spec_pruebas.toml")


@pytest.fixture
def db(tmp_path) -> Database:
    d = Database(tmp_path / "fiscal.sqlite3")
    yield d
    d.close()


@pytest.fixture
def credential():
    return generate_test_credential()


def build_content(encf: str, *, total="1180.00", tipo="91", rnc=RNC):
    return [
        ("Cabecera", [("NumeroSim", encf), ("TipoSim", tipo), ("EmisorSim", rnc),
                      ("CompradorSim", "131000002"), ("FechaSim", "09-11-2026")]),
        ("Totales", [("TotalSim", Decimal(total))]),
    ]


class Env:
    pass


@pytest.fixture
def env(tmp_path, spec, db, credential):
    e = Env()
    e.spec, e.db, e.cred = spec, db, credential
    e.fake = FakeDgii(credential)
    session = requests.Session()
    session.mount("https://", e.fake)
    e.signer = Signer(spec, credential)
    e.client = DgiiClient(spec, Ambiente.PRECERTIFICACION, e.signer, session=session)
    e.store = EvidenceStore(db, tmp_path / "evidencias")
    e.cont = ContingencyManager(db, spec)
    e.clock_now = [datetime.now(timezone.utc)]
    e.queue = TransmissionQueue(db, spec, e.client, e.store, e.cont, clock=lambda: e.clock_now[0])
    e.gate = EmissionGate(db, spec, produccion_habilitada=False)
    CertificateRegistry(db).register(credential, activate=True)
    e.seq = SequenceManager(db, spec)
    e.seq.register_range(ambiente=Ambiente.PRECERTIFICACION, rnc_emisor=RNC, tipo_ecf="91",
                         desde=1, hasta=100, vence=date.today() + timedelta(days=365),
                         referencia_autorizacion="AUT-SIM-001")
    e.service = EmissionService(
        db=db, spec=spec, ambiente=Ambiente.PRECERTIFICACION, rnc_emisor=RNC,
        razon_social="Emisor Simulado SRL", credential=credential,
        xsd=XsdValidator({"91": FIX / "documento_sim.xsd", "92": FIX / "documento_sim.xsd"}),
        store=e.store, queue=e.queue, gate=e.gate, contingency=e.cont)

    def advance(seconds: float):
        e.clock_now[0] += timedelta(seconds=seconds)
    e.advance = advance
    return e
