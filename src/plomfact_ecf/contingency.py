"""Contingencia y recuperación.

  * Se activa cuando la DGII no está disponible (fallos consecutivos de transmisión o servicio
    oficial de estatus caído). Durante la contingencia la emisión sigue: los comprobantes se
    firman, se archivan y quedan en cola marcados como emitidos en contingencia, SIN validez
    fiscal hasta su aceptación.
  * El plazo máximo de regularización proviene de la especificación verificada [contingencia].
  * recover() repara estados tras una caída del proceso: un envío interrumpido nunca se reenvía
    a ciegas; pasa a AMBIGUO para resolverse consultando a la DGII.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .db import Database, iso, utcnow
from .spec import DgiiSpec


class ContingencyManager:
    def __init__(self, db: Database, spec: DgiiSpec):
        self.db = db
        self.spec = spec
        self._fallos = 0

    @property
    def umbral(self) -> int:
        return int(self.spec.contingencia().get("fallos_consecutivos_para_activar", 3))

    def active(self) -> bool:
        return self.db.conn.execute(
            "SELECT 1 FROM contingencia_periodos WHERE fin IS NULL").fetchone() is not None

    def activate(self, motivo: str) -> None:
        if self.active():
            return
        with self.db.transaction() as c:
            c.execute("INSERT INTO contingencia_periodos(inicio, motivo) VALUES (?,?)",
                      (iso(utcnow()), motivo))

    def deactivate(self) -> None:
        with self.db.transaction() as c:
            c.execute("UPDATE contingencia_periodos SET fin=? WHERE fin IS NULL", (iso(utcnow()),))

    def record_failure(self, motivo: str) -> None:
        self._fallos += 1
        if self._fallos >= self.umbral:
            self.activate(motivo)

    def record_success(self) -> None:
        self._fallos = 0
        if self.active():
            self.deactivate()

    def deadline_hours(self) -> int:
        return int(self.spec.contingencia().get("plazo_maximo_regularizacion_horas", 0))

    def overdue(self, now: datetime | None = None) -> list[dict]:
        """Comprobantes de contingencia aún sin transmitir que superaron el plazo oficial."""
        horas = self.deadline_hours()
        if horas <= 0:
            return []
        limite = (now or utcnow()) - timedelta(hours=horas)
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM comprobantes WHERE contingencia=1 AND track_id IS NULL"
            " AND creado_en <= ?", (iso(limite),))]

    def periods(self) -> list[dict]:
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM contingencia_periodos ORDER BY id")]


def recover(db: Database) -> dict[str, int]:
    """Recuperación tras reinicio. Idempotente."""
    with db.transaction() as c:
        interrumpidos = c.execute(
            "UPDATE cola_transmision SET estado='AMBIGUO', ultimo_error=?, actualizado_en=?"
            " WHERE estado='ENVIANDO'",
            ("Proceso interrumpido durante el envío; resolver consultando a la DGII",
             iso(utcnow())),
        ).rowcount
    return {"envios_interrumpidos": interrumpidos}
