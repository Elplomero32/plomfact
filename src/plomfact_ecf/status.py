"""Estados fiscales internos y regla de validez fiscal.

Regla central: un comprobante es fiscalmente válido SOLO si la DGII devolvió un estado que la
especificación verificada clasifica como aceptado (o aceptado condicional). Firmado, en cola,
transmitido, en proceso, desconocido o en contingencia NO es válido.
"""

from __future__ import annotations

import enum

from .db import Database, iso, utcnow
from .errors import InvalidStateTransition
from .spec import DgiiSpec


class Estado(str, enum.Enum):
    FIRMADO = "FIRMADO"
    EN_COLA = "EN_COLA"
    TRANSMITIDO = "TRANSMITIDO"           # la DGII entregó trackId
    EN_PROCESO = "EN_PROCESO"
    ACEPTADO = "ACEPTADO"
    ACEPTADO_CONDICIONAL = "ACEPTADO_CONDICIONAL"
    RECHAZADO = "RECHAZADO"
    REVISION_REQUERIDA = "REVISION_REQUERIDA"  # respuesta no reconocida o envío detenido


FINALES = {Estado.ACEPTADO, Estado.ACEPTADO_CONDICIONAL, Estado.RECHAZADO}
VALIDOS = {Estado.ACEPTADO, Estado.ACEPTADO_CONDICIONAL}

TRANSICIONES: dict[Estado, set[Estado]] = {
    Estado.FIRMADO: {Estado.EN_COLA},
    Estado.EN_COLA: {Estado.TRANSMITIDO, Estado.REVISION_REQUERIDA},
    Estado.TRANSMITIDO: {Estado.EN_PROCESO, *FINALES, Estado.REVISION_REQUERIDA},
    Estado.EN_PROCESO: {Estado.EN_PROCESO, *FINALES, Estado.REVISION_REQUERIDA},
    Estado.REVISION_REQUERIDA: {Estado.EN_COLA, Estado.TRANSMITIDO, Estado.EN_PROCESO, *FINALES,
                                Estado.REVISION_REQUERIDA},
    Estado.ACEPTADO: set(),
    Estado.ACEPTADO_CONDICIONAL: set(),
    Estado.RECHAZADO: set(),
}


def classify_dgii_state(spec: DgiiSpec, valor: str | None) -> Estado:
    """Traduce el estado devuelto por la DGII con los valores oficiales configurados."""
    if valor is None:
        return Estado.REVISION_REQUERIDA
    v = str(valor).strip()
    grupos = [
        ("aceptados", Estado.ACEPTADO),
        ("aceptados_condicional", Estado.ACEPTADO_CONDICIONAL),
        ("rechazados", Estado.RECHAZADO),
        ("en_proceso", Estado.EN_PROCESO),
    ]
    coincidencias = [e for g, e in grupos if v in spec.estados(g)]
    if len(coincidencias) != 1:
        # Valor no listado (o listado en dos grupos): nunca se asume aceptación.
        return Estado.REVISION_REQUERIDA
    return coincidencias[0]


def is_not_found(spec: DgiiSpec, valor: str | None) -> bool:
    return valor is not None and str(valor).strip() in spec.estados("no_encontrado")


def is_fiscally_valid(estado: Estado | str) -> bool:
    return Estado(estado) in VALIDOS


def transition(db: Database, comprobante_id: int, nuevo: Estado, detalle: str = "",
               *, estado_dgii: str | None = None, track_id: str | None = None) -> None:
    with db.transaction() as c:
        row = c.execute("SELECT estado FROM comprobantes WHERE id=?", (comprobante_id,)).fetchone()
        if row is None:
            raise InvalidStateTransition(f"Comprobante {comprobante_id} inexistente")
        actual = Estado(row["estado"])
        if nuevo not in TRANSICIONES[actual]:
            raise InvalidStateTransition(f"Transición no permitida: {actual.value} → {nuevo.value}")
        sets, params = ["estado=?", "actualizado_en=?"], [nuevo.value, iso(utcnow())]
        if estado_dgii is not None:
            sets.append("estado_dgii=?")
            params.append(estado_dgii)
        if track_id is not None:
            sets.append("track_id=?")
            params.append(track_id)
        c.execute(f"UPDATE comprobantes SET {', '.join(sets)} WHERE id=?", (*params, comprobante_id))
        c.execute(
            "INSERT INTO eventos_comprobante(comprobante_id, en, de_estado, a_estado, detalle)"
            " VALUES (?,?,?,?,?)",
            (comprobante_id, iso(utcnow()), actual.value, nuevo.value, detalle[:4000]),
        )
