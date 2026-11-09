"""Cola de transmisión con reintentos seguros y consulta de estados por trackId.

Garantías:
  * Un comprobante con trackId nunca se vuelve a enviar.
  * Un envío ambiguo (timeout/corte tras enviar, error 5xx, caída del proceso) no se reenvía
    hasta confirmar con la DGII —consultando los trackId del e-NCF— que no fue recibido. Si ese
    servicio no está configurado, el comprobante se detiene para revisión manual.
  * Rechazos de la solicitud (4xx) no se reintentan automáticamente: requieren revisión.
  * Reintentos con espera exponencial acotada. Toda solicitud y respuesta se archiva.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Callable

from .archive import EvidenceStore
from .contingency import ContingencyManager
from .db import Database, iso, utcnow
from .dgii_client import DgiiClient, DgiiResponse
from .errors import DgiiTransportError, SpecNotVerifiedError
from .spec import DgiiSpec
from .status import Estado, classify_dgii_state, is_not_found, transition

log = logging.getLogger("plomfact_ecf.transmision")


def backoff(intentos: int, base: int = 30, tope: int = 3600) -> timedelta:
    return timedelta(seconds=min(tope, base * (2 ** max(0, intentos - 1))))


def _evidence_payload(resp: DgiiResponse) -> bytes:
    meta = json.dumps(resp.request_summary, ensure_ascii=False, sort_keys=True).encode()
    return meta + b"\n" + resp.body


class TransmissionQueue:
    def __init__(self, db: Database, spec: DgiiSpec, client: DgiiClient, store: EvidenceStore,
                 contingency: ContingencyManager, *, clock: Callable[[], datetime] = utcnow):
        self.db = db
        self.spec = spec
        self.client = client
        self.store = store
        self.contingency = contingency
        self.clock = clock

    # ---------------------------------------------------------------- cola
    def enqueue_in_tx(self, c, comprobante_id: int) -> None:
        c.execute(
            "INSERT INTO cola_transmision(comprobante_id, estado, proximo_intento, actualizado_en)"
            " VALUES (?, 'PENDIENTE', ?, ?)",
            (comprobante_id, iso(self.clock()), iso(self.clock())),
        )

    def _claim(self, cola_id: int, desde: str) -> bool:
        with self.db.transaction() as c:
            return c.execute(
                "UPDATE cola_transmision SET estado='ENVIANDO', actualizado_en=? WHERE id=? AND estado=?",
                (iso(self.clock()), cola_id, desde)).rowcount == 1

    def _set(self, cola_id: int, estado: str, *, error: str | None = None,
             reintentar: bool = False) -> None:
        with self.db.transaction() as c:
            row = c.execute("SELECT intentos FROM cola_transmision WHERE id=?", (cola_id,)).fetchone()
            intentos = row["intentos"] + (1 if reintentar else 0)
            prox = self.clock() + backoff(intentos) if reintentar else self.clock()
            c.execute(
                "UPDATE cola_transmision SET estado=?, intentos=?, proximo_intento=?, ultimo_error=?,"
                " actualizado_en=? WHERE id=?",
                (estado, intentos, iso(prox), error, iso(self.clock()), cola_id))

    def process_due(self, limit: int = 50) -> dict[str, int]:
        stats = {"enviados": 0, "reintentos": 0, "ambiguos": 0, "detenidos": 0}
        rows = self.db.conn.execute(
            "SELECT q.id, q.estado, q.comprobante_id, c.encf, c.rnc_emisor, c.track_id,"
            " c.xml_firmado_sha256 FROM cola_transmision q JOIN comprobantes c"
            " ON c.id = q.comprobante_id WHERE q.estado IN ('PENDIENTE','AMBIGUO')"
            " AND q.proximo_intento <= ? ORDER BY q.id LIMIT ?",
            (iso(self.clock()), limit)).fetchall()
        for r in rows:
            if not self._claim(r["id"], r["estado"]):
                continue  # otro proceso lo tomó
            res = self._process_one(r)
            stats[res] += 1
        return stats

    def _process_one(self, r) -> str:
        cid = r["comprobante_id"]
        if r["track_id"]:  # defensa: jamás reenviar
            self._set(r["id"], "ENVIADO")
            return "enviados"
        if r["estado"] == "AMBIGUO":
            decision = self._resolve_ambiguous(r)
            if decision != "reenviar":
                return decision
        xml = self.store.read(r["xml_firmado_sha256"])
        try:
            resp = self.client.submit_ecf(xml, rnc_emisor=r["rnc_emisor"], encf=r["encf"])
        except DgiiTransportError as exc:
            self.store.store("ERROR_TRANSMISION", f"{iso(self.clock())} {exc}".encode(), cid)
            self.contingency.record_failure(str(exc))
            if exc.ambiguous:
                self._set(r["id"], "AMBIGUO", error=str(exc), reintentar=True)
                return "ambiguos"
            self._set(r["id"], "PENDIENTE", error=str(exc), reintentar=True)
            return "reintentos"
        self.store.store("RESPUESTA_RECEPCION", _evidence_payload(resp), cid)
        self.contingency.record_success()
        track = resp.get(self.spec.campo("trackid"))
        if resp.status_code in (200, 201, 202) and track:
            self._set(r["id"], "ENVIADO")
            transition(self.db, cid, Estado.TRANSMITIDO, "Recibido por la DGII",
                       track_id=str(track))
            return "enviados"
        self._set(r["id"], "DETENIDO", error=f"HTTP {resp.status_code} sin trackId")
        transition(self.db, cid, Estado.REVISION_REQUERIDA,
                   f"Recepción no aceptada HTTP {resp.status_code}: {resp.body[:500]!r}")
        return "detenidos"

    def _resolve_ambiguous(self, r) -> str:
        cid = r["comprobante_id"]
        try:
            resp = self.client.query_trackids(rnc_emisor=r["rnc_emisor"], encf=r["encf"])
        except SpecNotVerifiedError:
            self._set(r["id"], "DETENIDO", error="Envío ambiguo sin servicio de consulta de trackId")
            transition(self.db, cid, Estado.REVISION_REQUERIDA,
                       "Envío ambiguo: verifique en la DGII antes de retransmitir")
            return "detenidos"
        except DgiiTransportError as exc:
            self.contingency.record_failure(str(exc))
            self._set(r["id"], "AMBIGUO", error=str(exc), reintentar=True)
            return "ambiguos"
        self.store.store("RESPUESTA_TRACKIDS", _evidence_payload(resp), cid)
        track = resp.get(self.spec.campo("trackid"))
        if track:
            self._set(r["id"], "ENVIADO")
            transition(self.db, cid, Estado.TRANSMITIDO, "trackId recuperado tras envío ambiguo",
                       track_id=str(track))
            return "enviados"
        lista_vacia = resp.status_code == 200 and resp.data == {"items": []}
        if lista_vacia or is_not_found(self.spec, resp.get(self.spec.campo("estado"))):
            return "reenviar"  # la DGII confirma explícitamente que no lo tiene
        self._set(r["id"], "AMBIGUO", error=f"Consulta trackIds HTTP {resp.status_code}",
                  reintentar=True)
        return "ambiguos"

    # ---------------------------------------------------------------- estados
    def poll_status(self, limit: int = 100) -> dict[str, int]:
        stats: dict[str, int] = {}
        rows = self.db.conn.execute(
            "SELECT id, track_id FROM comprobantes WHERE track_id IS NOT NULL AND estado IN"
            " ('TRANSMITIDO','EN_PROCESO','REVISION_REQUERIDA') ORDER BY id LIMIT ?",
            (limit,)).fetchall()
        for r in rows:
            try:
                resp = self.client.query_result(r["track_id"])
            except DgiiTransportError as exc:
                self.contingency.record_failure(str(exc))
                stats["error"] = stats.get("error", 0) + 1
                continue
            self.store.store("RESPUESTA_CONSULTA", _evidence_payload(resp), r["id"])
            valor = resp.get(self.spec.campo("estado"))
            nuevo = classify_dgii_state(self.spec, None if valor is None else str(valor))
            mensajes = self.spec.campo_opcional("mensajes")
            detalle = json.dumps(resp.get(mensajes) if mensajes else None, ensure_ascii=False)
            actual = self.db.conn.execute("SELECT estado FROM comprobantes WHERE id=?",
                                          (r["id"],)).fetchone()[0]
            if not (nuevo == Estado.REVISION_REQUERIDA and actual == nuevo.value):
                transition(self.db, r["id"], nuevo, f"DGII: {valor} {detalle}",
                           estado_dgii=None if valor is None else str(valor))
            stats[nuevo.value] = stats.get(nuevo.value, 0) + 1
        return stats
