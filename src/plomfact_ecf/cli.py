"""Herramienta de operación: plomfact-ecf <comando> --config config/settings.toml"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import date

from .alerts import ExpiryMonitor
from .archive import EvidenceStore
from .contingency import ContingencyManager, recover
from .credentials import CertificateRegistry, load_pkcs12, read_secret
from .db import Database
from .dgii_client import DgiiClient
from .errors import FiscalError
from .gate import EmissionGate
from .sequences import SequenceManager
from .settings import Settings
from .spec import Ambiente, DgiiSpec
from .transmission import TransmissionQueue
from .xmlsign import Signer


def _cred(s: Settings, archivo=None):
    return load_pkcs12(archivo or s.certificado,
                       read_secret(env_var=s.clave_env, file=s.clave_archivo))


def _queue(s: Settings, db: Database, spec: DgiiSpec) -> TransmissionQueue:
    cred = _cred(s)
    CertificateRegistry(db).ensure_active(cred)
    client = DgiiClient(spec, s.ambiente, Signer(spec, cred))
    return TransmissionQueue(db, spec, client, EvidenceStore(db, s.evidencias),
                             ContingencyManager(db, spec))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(prog="plomfact-ecf")
    ap.add_argument("--config", default="config/settings.toml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verificar-spec", help="Lista las secciones DGII pendientes de verificación")
    sub.add_parser("estado", help="Resumen operativo")
    c = sub.add_parser("certificado-registrar", help="Registra y activa el certificado inicial")
    c.add_argument("--archivo")
    c = sub.add_parser("certificado-renovar", help="Rota al certificado renovado")
    c.add_argument("--archivo", required=True)
    c = sub.add_parser("rango-registrar", help="Registra un rango de e-NCF autorizado por la DGII")
    c.add_argument("--tipo", required=True)
    c.add_argument("--desde", type=int, required=True)
    c.add_argument("--hasta", type=int, required=True)
    c.add_argument("--vence", type=date.fromisoformat)
    c.add_argument("--referencia", required=True, help="Referencia oficial de la autorización")
    c = sub.add_parser("habilitar", help="Registra la autorización oficial para un ambiente")
    c.add_argument("--ambiente", required=True, choices=[a.value for a in Ambiente])
    c.add_argument("--referencia", required=True)
    c.add_argument("--por", required=True)
    sub.add_parser("transmitir", help="Procesa la cola y consulta estados (ejecutar periódicamente)")
    sub.add_parser("alertas", help="Revisa vencimientos y muestra alertas abiertas")
    sub.add_parser("integridad", help="Verifica la integridad de las evidencias")
    sub.add_parser("recuperar", help="Recuperación tras caída del proceso")
    a = ap.parse_args(argv)

    s = Settings.load(a.config)
    spec = DgiiSpec.load(s.spec)
    out: object
    try:
        if a.cmd == "verificar-spec":
            out = {"pendientes": spec.unverified_sections()}
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 1 if out["pendientes"] else 0
        db = Database(s.base_datos)
        if a.cmd == "estado":
            cont = ContingencyManager(db, spec)
            out = {
                "ambiente": s.ambiente.value,
                "spec_pendiente": spec.unverified_sections(),
                "certificado_activo": CertificateRegistry(db).active_fingerprint(),
                "contingencia": cont.active() if spec.is_verified("contingencia") else None,
                "por_estado": {r[0]: r[1] for r in db.conn.execute(
                    "SELECT estado, COUNT(*) FROM comprobantes GROUP BY estado")},
                "cola": {r[0]: r[1] for r in db.conn.execute(
                    "SELECT estado, COUNT(*) FROM cola_transmision GROUP BY estado")},
            }
        elif a.cmd == "certificado-registrar":
            reg = CertificateRegistry(db)
            if reg.active_fingerprint():
                raise FiscalError("Ya hay un certificado activo; use certificado-renovar")
            cred = _cred(s, a.archivo)
            reg.register(cred, activate=True)
            out = {"activo": cred.fingerprint, "vence": cred.not_after.isoformat()}
        elif a.cmd == "certificado-renovar":
            cred = _cred(s, a.archivo)
            CertificateRegistry(db).rotate(cred)
            out = {"activo": cred.fingerprint, "vence": cred.not_after.isoformat(),
                   "aviso": "Actualice 'certificado.archivo' en settings.toml al nuevo archivo"}
        elif a.cmd == "rango-registrar":
            rid = SequenceManager(db, spec).register_range(
                ambiente=s.ambiente, rnc_emisor=s.rnc_emisor, tipo_ecf=a.tipo, desde=a.desde,
                hasta=a.hasta, vence=a.vence, referencia_autorizacion=a.referencia)
            out = {"rango_id": rid}
        elif a.cmd == "habilitar":
            EmissionGate(db, spec, produccion_habilitada=s.produccion_habilitada) \
                .register_authorization(ambiente=Ambiente(a.ambiente), rnc_emisor=s.rnc_emisor,
                                        referencia=a.referencia, registrado_por=a.por)
            out = {"habilitado": a.ambiente}
        elif a.cmd == "transmitir":
            spec.require_all_verified()
            recover(db)
            q = _queue(s, db, spec)
            out = {"cola": q.process_due(), "estados": q.poll_status()}
        elif a.cmd == "alertas":
            m = ExpiryMonitor(db, SequenceManager(db, spec), umbrales=s.umbrales)
            m.check()
            out = m.open_alerts()
        elif a.cmd == "integridad":
            problemas = EvidenceStore(db, s.evidencias).verify()
            out = {"integro": not problemas, "problemas": problemas}
        elif a.cmd == "recuperar":
            out = recover(db)
        else:  # pragma: no cover
            raise AssertionError(a.cmd)
    except FiscalError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
