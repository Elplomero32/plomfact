# Arquitectura

## Principio de diseño: nada oficial en el código

Los datos que define la DGII (URLs de los ambientes, rutas y métodos de los servicios, nombres
de parámetros y campos, valores de estado, algoritmos de firma, formato del e-NCF, plantilla del
QR, regla del código de seguridad, plazos de contingencia) viven en `config/dgii_spec.toml`.
`spec.py` solo entrega una sección si declara `verificado = true` y una `fuente` (documento,
versión, página). Si la DGII publica una nueva versión de su documentación, se actualiza ese
archivo, no el código.

Las pruebas usan `tests/fixtures/spec_pruebas.toml`: valores **inventados a propósito**, con hosts
`.invalid`, para que nunca se confundan con los oficiales.

## Módulos

```
src/plomfact_ecf/
├── spec.py            Especificación DGII verificada (falla cerrado)
├── settings.py        Configuración local del emisor (sin secretos)
├── db.py              SQLite: migraciones con checksum + triggers de inmutabilidad
├── credentials.py     Certificado PKCS#12, secretos, registro y rotación
├── xmlsign.py         Construcción XML, validación XSD, firma/verificación XMLDSig, código de seguridad
├── sequences.py       Rangos autorizados y asignación atómica de e-NCF
├── dgii_client.py     Autenticación por semilla, recepción, consultas (HTTPS + TLS obligatorio)
├── transmission.py    Cola con reintentos seguros, resolución de envíos ambiguos, consulta de estados
├── status.py          Máquina de estados fiscal y regla de validez
├── archive.py         Evidencias por contenido, solo lectura, encadenadas por hash
├── representation.py  URL de verificación, QR y PDF
├── contingency.py     Detección de contingencia, plazos, recuperación tras caída
├── alerts.py          Vencimientos de certificados, rangos, disponibilidad de e-NCF
├── gate.py            Habilitación por ambiente (producción requiere autorización registrada)
├── service.py         Orquestación de la emisión
└── cli.py             Herramienta de operación
```

## Flujo de emisión (`EmissionService.emit`)

1. `gate`: especificación completa y verificada; en producción, autorización oficial registrada
   **y** `produccion_habilitada = true`.
2. Certificado activo, vigente y con uso de firma digital.
3. e-NCF asignado de forma atómica dentro de un rango autorizado y vigente.
4. XML construido con los nombres de elementos del XSD oficial (los aporta PlomFact).
5. Inserción de la fecha/hora de firma, firma XMLDSig envolvente, validación XSD, verificación
   de la firma.
6. Verificación cruzada: el XML firmado contiene el e-NCF, tipo y RNC asignados.
7. Una sola transacción: comprobante, e-NCF marcado USADO, evidencia del XML y entrada en cola.
8. Representación impresa archivada.

El resultado es `EN_COLA`, **sin validez fiscal**.

## Estados

```
FIRMADO → EN_COLA → TRANSMITIDO(trackId) → EN_PROCESO → ACEPTADO
                                                       → ACEPTADO_CONDICIONAL
                                                       → RECHAZADO
            cualquier respuesta no reconocida / envío detenido → REVISION_REQUERIDA
```

- `is_fiscally_valid` es verdadero **solo** para `ACEPTADO` y `ACEPTADO_CONDICIONAL`, y esos
  estados solo se alcanzan si la DGII devolvió un valor listado en `[estados]`.
- Un valor no documentado (o listado en dos grupos) nunca se interpreta como aceptación.
- Los estados finales no cambian (trigger SQL).

## Garantías de integridad

| Riesgo | Protección |
|---|---|
| e-NCF duplicado | `BEGIN IMMEDIATE` + `UNIQUE(ambiente, rnc, encf)` y `UNIQUE(..., secuencial)`; prueba con 8 hilos |
| e-NCF reutilizado tras error | Nunca se borra ni vuelve a `ASIGNADO`; se reporta para anulación |
| Fuera de rango / vencido | Asignación solo dentro de rangos `ACTIVO` y no vencidos; formato validado |
| Reenvío duplicado | Con trackId jamás se reenvía; un envío ambiguo se resuelve consultando trackIds |
| Alterar un comprobante firmado | Trigger bloquea cambios a e-NCF, código de seguridad, hash del XML, certificado, trackId |
| Alterar evidencias | Archivos 0444 por hash + cadena de hashes en BD; `plomfact-ecf integridad` |
| Actualización que reescribe historia | Migraciones con checksum; versión anterior de la app no puede abrir una BD más nueva |
| Producción sin certificación | Doble condición en `gate.py` |

## Firma digital

Se usa **libxmlsec1** (bindings `xmlsec`), la implementación de referencia de XMLDSig. Durante el
desarrollo se comprobó que `signxml` genera firmas inválidas con canonicalización inclusiva y
firma sin prefijo de namespace; por eso solo se usa en pruebas, como verificador independiente
en la variante con prefijo.

Algoritmos soportados (se eligen en `[firma]`): RSA-SHA256/384/512, digest SHA-256/384/512,
C14N 1.0 inclusiva o exclusiva (con o sin comentarios). Cualquier otro valor bloquea la firma.
