"""Control de habilitación por ambiente.

  * Cualquier ambiente exige la especificación DGII completamente verificada.
  * PRODUCCIÓN exige además: (1) haber registrado la autorización oficial obtenida al concluir el
    proceso de certificación (referencia del documento/comunicación de la DGII) y (2) que la
    configuración local habilite producción explícitamente. Ambas condiciones son necesarias.
"""

from __future__ import annotations

from .db import Database, iso, utcnow
from .errors import ProductionGateError
from .spec import Ambiente, DgiiSpec


class EmissionGate:
    def __init__(self, db: Database, spec: DgiiSpec, *, produccion_habilitada: bool):
        self.db = db
        self.spec = spec
        self.produccion_habilitada = produccion_habilitada

    def register_authorization(self, *, ambiente: Ambiente, rnc_emisor: str, referencia: str,
                               registrado_por: str) -> None:
        if not referencia.strip() or not registrado_por.strip():
            raise ProductionGateError("Referencia de autorización y responsable son obligatorios")
        with self.db.transaction() as c:
            c.execute(
                "INSERT INTO habilitaciones(ambiente, rnc_emisor, referencia_autorizacion,"
                " registrado_por, registrado_en) VALUES (?,?,?,?,?)",
                (ambiente.value, rnc_emisor, referencia.strip(), registrado_por.strip(),
                 iso(utcnow())),
            )

    def authorization(self, ambiente: Ambiente, rnc_emisor: str) -> dict | None:
        r = self.db.conn.execute(
            "SELECT * FROM habilitaciones WHERE ambiente=? AND rnc_emisor=? ORDER BY id DESC LIMIT 1",
            (ambiente.value, rnc_emisor)).fetchone()
        return dict(r) if r else None

    def assert_can_emit(self, ambiente: Ambiente, rnc_emisor: str) -> None:
        self.spec.require_all_verified()
        if ambiente is Ambiente.PRODUCCION:
            if not self.produccion_habilitada:
                raise ProductionGateError(
                    "Producción deshabilitada en la configuración (produccion_habilitada=false)")
            if self.authorization(Ambiente.PRODUCCION, rnc_emisor) is None:
                raise ProductionGateError(
                    "No se ha registrado la autorización de la DGII para emitir en producción. "
                    "Complete el proceso de certificación y registre la referencia oficial.")
