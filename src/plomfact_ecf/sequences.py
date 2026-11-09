"""Gestión de secuencias autorizadas de e-NCF.

  * Solo se asignan números dentro de rangos autorizados registrados con su referencia oficial.
  * La asignación es atómica (transacción BEGIN IMMEDIATE + restricciones UNIQUE), por lo que
    dos procesos concurrentes nunca obtienen el mismo e-NCF.
  * Un e-NCF asignado nunca se reutiliza ni se borra (triggers en db.py), aunque la emisión falle:
    queda como ASIGNADO y se reporta para su anulación según el procedimiento oficial.
  * El formato (prefijo, longitudes, tipos válidos, patrón) proviene de la especificación verificada.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

from .db import Database, iso, utcnow
from .errors import SequenceError
from .spec import Ambiente, DgiiSpec


@dataclass(frozen=True)
class AssignedEncf:
    id: int
    encf: str
    tipo_ecf: str
    secuencial: int
    rango_id: int


class SequenceManager:
    def __init__(self, db: Database, spec: DgiiSpec):
        self.db = db
        self.spec = spec

    # ---------------------------------------------------------------- formato
    def format_encf(self, tipo: str, secuencial: int) -> str:
        prefijo, lt, ls = self.spec.encf_layout()
        if tipo not in self.spec.encf_tipos() or len(tipo) != lt:
            raise SequenceError(f"Tipo de e-CF no válido: {tipo}")
        if secuencial <= 0 or len(str(secuencial)) > ls:
            raise SequenceError(f"Secuencial fuera del formato oficial: {secuencial}")
        encf = f"{prefijo}{tipo}{secuencial:0{ls}d}"
        self.validate(encf)
        return encf

    def validate(self, encf: str) -> tuple[str, int]:
        prefijo, lt, ls = self.spec.encf_layout()
        if not self.spec.encf_regex().fullmatch(encf):
            raise SequenceError(f"e-NCF con formato inválido: {encf!r}")
        if len(encf) != len(prefijo) + lt + ls or not encf.startswith(prefijo):
            raise SequenceError(f"e-NCF con longitud inválida: {encf!r}")
        tipo = encf[len(prefijo):len(prefijo) + lt]
        if tipo not in self.spec.encf_tipos():
            raise SequenceError(f"Tipo de e-CF no autorizado en el e-NCF: {tipo}")
        return tipo, int(encf[len(prefijo) + lt:])

    # ---------------------------------------------------------------- rangos
    def register_range(self, *, ambiente: Ambiente, rnc_emisor: str, tipo_ecf: str, desde: int,
                       hasta: int, vence: date | None, referencia_autorizacion: str) -> int:
        if not referencia_autorizacion.strip():
            raise SequenceError("Se requiere la referencia oficial de autorización del rango")
        # valida formato de los extremos
        self.format_encf(tipo_ecf, desde)
        self.format_encf(tipo_ecf, hasta)
        if hasta < desde:
            raise SequenceError("Rango inválido: hasta < desde")
        with self.db.transaction() as c:
            overlap = c.execute(
                "SELECT id FROM rangos_secuencia WHERE ambiente=? AND rnc_emisor=? AND tipo_ecf=?"
                " AND NOT (hasta < ? OR desde > ?)",
                (ambiente.value, rnc_emisor, tipo_ecf, desde, hasta),
            ).fetchone()
            if overlap:
                raise SequenceError(f"El rango se superpone con el rango registrado #{overlap[0]}")
            cur = c.execute(
                "INSERT INTO rangos_secuencia(ambiente, rnc_emisor, tipo_ecf, desde, hasta, vence,"
                " referencia_autorizacion, registrado_en) VALUES (?,?,?,?,?,?,?,?)",
                (ambiente.value, rnc_emisor, tipo_ecf, desde, hasta,
                 vence.isoformat() if vence else None, referencia_autorizacion.strip(),
                 iso(utcnow())),
            )
            return int(cur.lastrowid)

    def annul_range(self, rango_id: int) -> None:
        with self.db.transaction() as c:
            c.execute("UPDATE rangos_secuencia SET estado='ANULADO' WHERE id=?", (rango_id,))

    # ---------------------------------------------------------------- asignación
    def allocate(self, *, ambiente: Ambiente, rnc_emisor: str, tipo_ecf: str,
                 today: date | None = None) -> AssignedEncf:
        today = today or datetime.now().date()
        with self.db.transaction() as c:
            rangos = c.execute(
                "SELECT id, desde, hasta, vence FROM rangos_secuencia WHERE ambiente=? AND"
                " rnc_emisor=? AND tipo_ecf=? AND estado='ACTIVO' ORDER BY desde",
                (ambiente.value, rnc_emisor, tipo_ecf),
            ).fetchall()
            for r in rangos:
                if r["vence"] and date.fromisoformat(r["vence"]) < today:
                    continue
                last = c.execute(
                    "SELECT MAX(secuencial) FROM encf_asignados WHERE rango_id=?", (r["id"],)
                ).fetchone()[0]
                siguiente = (last + 1) if last is not None else r["desde"]
                if siguiente > r["hasta"]:
                    continue
                encf = self.format_encf(tipo_ecf, siguiente)
                cur = c.execute(
                    "INSERT INTO encf_asignados(ambiente, rnc_emisor, tipo_ecf, secuencial, encf,"
                    " rango_id, asignado_en) VALUES (?,?,?,?,?,?,?)",
                    (ambiente.value, rnc_emisor, tipo_ecf, siguiente, encf, r["id"], iso(utcnow())),
                )
                return AssignedEncf(int(cur.lastrowid), encf, tipo_ecf, siguiente, r["id"])
        raise SequenceError(
            f"No hay secuencias autorizadas vigentes para el tipo {tipo_ecf} en {ambiente.value}. "
            "Solicite un nuevo rango a la DGII y regístrelo."
        )

    def mark_used(self, encf_id: int) -> None:
        with self.db.transaction() as c:
            n = c.execute("UPDATE encf_asignados SET estado='USADO' WHERE id=? AND estado='ASIGNADO'",
                          (encf_id,)).rowcount
            if n != 1:
                raise SequenceError("El e-NCF no está disponible para uso")

    def mark_annulled(self, encf_id: int) -> None:
        with self.db.transaction() as c:
            c.execute("UPDATE encf_asignados SET estado='ANULADO' WHERE id=? AND estado='ASIGNADO'",
                      (encf_id,))

    # ---------------------------------------------------------------- consultas
    def remaining(self, *, ambiente: Ambiente, rnc_emisor: str, tipo_ecf: str,
                  today: date | None = None) -> int:
        today = today or datetime.now().date()
        total = 0
        for r in self.db.conn.execute(
            "SELECT id, desde, hasta, vence FROM rangos_secuencia WHERE ambiente=? AND rnc_emisor=?"
            " AND tipo_ecf=? AND estado='ACTIVO'", (ambiente.value, rnc_emisor, tipo_ecf)):
            if r["vence"] and date.fromisoformat(r["vence"]) < today:
                continue
            last = self.db.conn.execute(
                "SELECT MAX(secuencial) FROM encf_asignados WHERE rango_id=?", (r["id"],)
            ).fetchone()[0]
            usados_hasta = last if last is not None else r["desde"] - 1
            total += max(0, r["hasta"] - usados_hasta)
        return total

    def active_ranges(self) -> list[dict]:
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM rangos_secuencia WHERE estado='ACTIVO'")]

    def assigned_unused(self) -> list[dict]:
        """e-NCF asignados que no llegaron a emitirse: deben gestionarse (anulación oficial)."""
        return [dict(r) for r in self.db.conn.execute(
            "SELECT * FROM encf_asignados WHERE estado='ASIGNADO' ORDER BY id")]
