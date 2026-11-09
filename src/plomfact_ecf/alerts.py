"""Control de vencimientos y alertas: certificados, secuencias autorizadas y contingencia.

Las alertas se guardan en la base de datos (una sola alerta abierta por clave y severidad) y se
envían a los canales configurados (registro, correo, webhook interno...).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Callable, Iterable, Protocol

from .db import Database, iso, utcnow
from .sequences import SequenceManager
from .spec import Ambiente

log = logging.getLogger("plomfact_ecf.alertas")

INFO, ADVERTENCIA, CRITICA, VENCIDO = "INFO", "ADVERTENCIA", "CRITICA", "VENCIDO"


@dataclass(frozen=True)
class Alert:
    clave: str
    tipo: str
    severidad: str
    mensaje: str
    vence: str | None = None


class AlertSink(Protocol):
    def __call__(self, alert: Alert) -> None: ...


def log_sink(alert: Alert) -> None:
    lvl = logging.WARNING if alert.severidad in (INFO, ADVERTENCIA) else logging.CRITICAL
    log.log(lvl, "[%s] %s: %s", alert.severidad, alert.tipo, alert.mensaje)


@dataclass
class Umbrales:
    certificado_dias: tuple[int, int] = (60, 15)     # (advertencia, crítica)
    rango_dias: tuple[int, int] = (30, 7)
    rango_restantes: tuple[int, int] = (500, 50)
    contingencia_horas_criticas: int = 12


def _severidad(valor: float, adv: float, crit: float) -> str | None:
    if valor <= 0:
        return VENCIDO
    if valor <= crit:
        return CRITICA
    if valor <= adv:
        return ADVERTENCIA
    return None


class ExpiryMonitor:
    def __init__(self, db: Database, sequences: SequenceManager, *,
                 umbrales: Umbrales | None = None, sinks: Iterable[AlertSink] = (log_sink,),
                 clock: Callable[[], datetime] = utcnow):
        self.db = db
        self.seq = sequences
        self.u = umbrales or Umbrales()
        self.sinks = list(sinks)
        self.clock = clock

    def _raise(self, a: Alert) -> bool:
        with self.db.transaction() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO alertas(clave, tipo, severidad, mensaje, vence, creado_en)"
                " VALUES (?,?,?,?,?,?)",
                (a.clave, a.tipo, a.severidad, a.mensaje, a.vence, iso(self.clock())),
            )
            nueva = cur.rowcount == 1
        if nueva:
            for s in self.sinks:
                try:
                    s(a)
                except Exception:  # un canal caído no debe detener el control
                    log.exception("Fallo enviando alerta por un canal")
        return nueva

    def _resolve(self, clave: str) -> None:
        with self.db.transaction() as c:
            c.execute("UPDATE alertas SET resuelta_en=? WHERE clave=? AND resuelta_en IS NULL",
                      (iso(self.clock()), clave))

    def check(self) -> list[Alert]:
        alerts: list[Alert] = []
        now = self.clock()
        hoy = now.date()

        # Certificado activo
        cert = self.db.conn.execute(
            "SELECT * FROM certificados WHERE activo=1").fetchone()
        if cert is None:
            alerts.append(Alert("certificado:activo", "CERTIFICADO", CRITICA,
                                "No hay certificado digital activo registrado"))
        else:
            dias = (datetime.fromisoformat(cert["valido_hasta"]) - now) / timedelta(days=1)
            sev = _severidad(dias, *self.u.certificado_dias)
            clave = f"certificado:{cert['fingerprint_sha256']}"
            if sev:
                alerts.append(Alert(clave, "CERTIFICADO", sev,
                                    f"El certificado {cert['sujeto']} vence en {max(dias, 0):.0f} días",
                                    cert["valido_hasta"]))
            else:
                self._resolve(clave)

        # Rangos autorizados: vencimiento y disponibilidad
        for r in self.seq.active_ranges():
            clave = f"rango:{r['id']}"
            if r["vence"]:
                dias = (date.fromisoformat(r["vence"]) - hoy).days + 1
                sev = _severidad(dias, *self.u.rango_dias)
                if sev:
                    alerts.append(Alert(clave + ":vence", "SECUENCIA", sev,
                                        f"El rango #{r['id']} tipo {r['tipo_ecf']} vence el {r['vence']}",
                                        r["vence"]))
        for amb, rnc, tipo in {(r["ambiente"], r["rnc_emisor"], r["tipo_ecf"])
                               for r in self.seq.active_ranges()}:
            restantes = self.seq.remaining(ambiente=Ambiente(amb), rnc_emisor=rnc, tipo_ecf=tipo,
                                           today=hoy)
            sev = _severidad(restantes, *self.u.rango_restantes)
            clave = f"disponibles:{amb}:{rnc}:{tipo}"
            if sev:
                alerts.append(Alert(clave, "SECUENCIA", sev,
                                    f"Quedan {restantes} e-NCF tipo {tipo} ({amb})"))
            else:
                self._resolve(clave)

        # e-NCF asignados sin uso: requieren gestión (anulación oficial)
        pendientes = self.seq.assigned_unused()
        viejos = [p for p in pendientes
                  if now - datetime.fromisoformat(p["asignado_en"]) > timedelta(hours=1)]
        if viejos:
            alerts.append(Alert("encf:sin_uso", "SECUENCIA", ADVERTENCIA,
                                f"{len(viejos)} e-NCF asignados no se emitieron y deben anularse "
                                "según el procedimiento oficial"))

        # Comprobantes emitidos en contingencia pendientes de regularizar
        for row in self.db.conn.execute(
                "SELECT c.id, c.encf, c.creado_en, c.estado FROM comprobantes c WHERE c.contingencia=1"
                " AND c.estado IN ('FIRMADO','EN_COLA','REVISION_REQUERIDA')"):
            alerts.append(Alert(f"contingencia:{row['id']}", "CONTINGENCIA", ADVERTENCIA,
                                f"{row['encf']} emitido en contingencia pendiente de transmisión"))

        for a in alerts:
            self._raise(a)
        return alerts

    def open_alerts(self) -> list[dict]:
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM alertas WHERE resuelta_en IS NULL ORDER BY id")]
