"""Orquestación de la emisión de e-CF.

Flujo de emit():
  1. Habilitación del ambiente (spec verificada; producción autorizada).
  2. Certificado activo y vigente.
  3. Asignación atómica del e-NCF dentro de un rango autorizado.
  4. Construcción del XML con los datos del comprobante (estructura del XSD oficial).
  5. Firma digital XMLDSig + validación contra el XSD oficial + verificación de la firma.
  6. Verificación cruzada: el XML firmado contiene el e-NCF, tipo y RNC asignados.
  7. Persistencia atómica: comprobante, uso del e-NCF, evidencia del XML y entrada en la cola.
  8. Representación impresa archivada.
El comprobante queda EN_COLA: no tiene validez fiscal hasta que la DGII lo acepte.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Sequence

from .archive import EvidenceStore
from .contingency import ContingencyManager
from .credentials import CertificateRegistry, SigningCredential
from .db import Database, iso, utcnow
from .errors import FiscalError, XmlValidationError
from .gate import EmissionGate
from .representation import DatosVerificacion, DocumentoImpreso, LineaImpresa, render_pdf
from .sequences import SequenceManager
from .spec import Ambiente, DgiiSpec
from .status import Estado, is_fiscally_valid
from .transmission import TransmissionQueue
from .xmlsign import Node, Signer, XsdValidator, build_xml, read_fields, security_code, \
    verify_signature

# El constructor recibe el e-NCF asignado y devuelve los hijos del elemento raíz del e-CF,
# con los nombres de elementos del XSD oficial.
XmlContentBuilder = Callable[[str], Sequence[Node]]


@dataclass(frozen=True)
class EmissionResult:
    comprobante_id: int
    encf: str
    codigo_seguridad: str
    fecha_firma: str
    estado: Estado
    contingencia: bool

    @property
    def fiscalmente_valido(self) -> bool:
        return is_fiscally_valid(self.estado)


class EmissionService:
    def __init__(self, *, db: Database, spec: DgiiSpec, ambiente: Ambiente, rnc_emisor: str,
                 razon_social: str, credential: SigningCredential, xsd: XsdValidator,
                 store: EvidenceStore, queue: TransmissionQueue, gate: EmissionGate,
                 contingency: ContingencyManager):
        self.db, self.spec, self.ambiente = db, spec, ambiente
        self.rnc_emisor, self.razon_social = rnc_emisor, razon_social
        self.credential = credential
        self.signer = Signer(spec, credential)
        self.xsd, self.store, self.queue, self.gate = xsd, store, queue, gate
        self.contingency = contingency
        self.seq = SequenceManager(db, spec)
        self.registry = CertificateRegistry(db)

    def emit(self, tipo_ecf: str, build_content: XmlContentBuilder, *,
             lineas: Sequence[LineaImpresa] = (), comprador: str | None = None,
             fecha_firma: datetime | None = None) -> EmissionResult:
        self.gate.assert_can_emit(self.ambiente, self.rnc_emisor)
        self.registry.ensure_active(self.credential)
        asignado = self.seq.allocate(ambiente=self.ambiente, rnc_emisor=self.rnc_emisor,
                                     tipo_ecf=tipo_ecf)
        # A partir de aquí, si algo falla el e-NCF queda ASIGNADO (nunca se reutiliza) y se
        # reporta para su anulación.
        xml = build_xml(self.spec.xml_raiz("ecf"), build_content(asignado.encf))
        signed = self.signer.sign(xml, fecha_firma=fecha_firma)
        self.xsd.validate(tipo_ecf, signed.xml)
        verify_signature(signed.xml, self.credential)
        campos = read_fields(self.spec, signed.xml)
        esperado = {"encf": asignado.encf, "tipo_ecf": tipo_ecf, "rnc_emisor": self.rnc_emisor}
        for k, v in esperado.items():
            if campos.get(k) != v:
                raise XmlValidationError(f"El XML firmado tiene {k}={campos.get(k)!r}; se esperaba {v!r}")
        for k in ("fecha_emision", "monto_total"):
            if not campos.get(k):
                raise XmlValidationError(f"El XML firmado no contiene {k}")
        codigo = security_code(self.spec, signed.xml)
        contingencia = self.contingency.active()
        ahora = iso(utcnow())

        with self.db.transaction() as c:
            cur = c.execute(
                "INSERT INTO comprobantes(ambiente, rnc_emisor, encf, tipo_ecf, estado,"
                " codigo_seguridad, fecha_firma, xml_firmado_sha256, certificado_fingerprint,"
                " contingencia, creado_en, actualizado_en) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.ambiente.value, self.rnc_emisor, asignado.encf, tipo_ecf,
                 Estado.EN_COLA.value, codigo, signed.fecha_firma,
                 hashlib.sha256(signed.xml).hexdigest(), self.credential.fingerprint,
                 int(contingencia), ahora, ahora))
            cid = int(cur.lastrowid)
            n = c.execute("UPDATE encf_asignados SET estado='USADO' WHERE id=? AND estado='ASIGNADO'",
                          (asignado.id,)).rowcount
            if n != 1:
                raise FiscalError("El e-NCF asignado ya no está disponible")
            self.store.store_in_tx(c, "XML_FIRMADO", signed.xml, cid)
            c.execute("INSERT INTO eventos_comprobante(comprobante_id, en, de_estado, a_estado,"
                      " detalle) VALUES (?,?,?,?,?)",
                      (cid, ahora, None, Estado.FIRMADO.value, "Firmado y validado contra XSD"))
            c.execute("INSERT INTO eventos_comprobante(comprobante_id, en, de_estado, a_estado,"
                      " detalle) VALUES (?,?,?,?,?)",
                      (cid, ahora, Estado.FIRMADO.value, Estado.EN_COLA.value,
                       "En cola de transmisión" + (" (contingencia)" if contingencia else "")))
            self.queue.enqueue_in_tx(c, cid)

        self.archive_representation(cid, lineas=lineas, comprador=comprador)
        return EmissionResult(cid, asignado.encf, codigo, signed.fecha_firma, Estado.EN_COLA,
                              contingencia)

    def verification_data(self, comprobante_id: int) -> DatosVerificacion:
        row = self.db.conn.execute("SELECT * FROM comprobantes WHERE id=?",
                                   (comprobante_id,)).fetchone()
        xml = self.store.read(row["xml_firmado_sha256"])
        campos = read_fields(self.spec, xml)
        return DatosVerificacion(
            rnc_emisor=row["rnc_emisor"], encf=row["encf"], tipo_ecf=row["tipo_ecf"],
            fecha_emision=campos["fecha_emision"] or "", monto_total=campos["monto_total"] or "",
            fecha_firma=row["fecha_firma"], codigo_seguridad=row["codigo_seguridad"],
            rnc_comprador=campos.get("rnc_comprador"),
        )

    def archive_representation(self, comprobante_id: int, *, lineas: Sequence[LineaImpresa] = (),
                               comprador: str | None = None) -> bytes:
        row = self.db.conn.execute("SELECT * FROM comprobantes WHERE id=?",
                                   (comprobante_id,)).fetchone()
        pdf = render_pdf(self.spec, self.ambiente, DocumentoImpreso(
            razon_social_emisor=self.razon_social,
            tipo_nombre=self.spec.encf_tipos()[row["tipo_ecf"]],
            datos=self.verification_data(comprobante_id),
            estado=Estado(row["estado"]),
            lineas=list(lineas), comprador=comprador, contingencia=bool(row["contingencia"]),
        ))
        self.store.store("REPRESENTACION_IMPRESA", pdf, comprobante_id)
        return pdf

    def status(self, comprobante_id: int) -> dict:
        row = dict(self.db.conn.execute("SELECT * FROM comprobantes WHERE id=?",
                                        (comprobante_id,)).fetchone())
        row["fiscalmente_valido"] = is_fiscally_valid(row["estado"])
        return row
