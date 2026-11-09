# Verificación contra la documentación oficial de la DGII

Complete `config/dgii_spec.toml` con la documentación publicada en el portal de la DGII
(Facturación Electrónica → Documentación sobre e-CF). Documentos de referencia identificados:

- *Descripción Técnica Servicios DGII*
- *Descripción Técnica Emisores Electrónicos*
- *Informe Técnico e-CF*
- *Formatos XML* y XSD oficiales por tipo de e-CF
- *Firmado de e-CF*
- *Proceso de Certificación para ser Emisor Electrónico*

> En la sesión de desarrollo el portal de la DGII rechazó el acceso automatizado (HTTP 403), por
> lo que **ningún valor oficial fue copiado al código ni a la plantilla**. Esta lista debe
> completarla una persona con acceso a los documentos.

Por cada sección: copie el valor exacto, anote en `fuente` el documento, versión, fecha y página,
haga que lo revise una segunda persona y marque `verificado = true`.

| Sección | Qué verificar |
|---|---|
| `ambientes.*` | URL base HTTPS de cada ambiente (pruebas, certificación, producción) |
| `endpoints.semilla` / `validar_semilla` | Ruta, método, nombre del campo del archivo firmado |
| `endpoints.recepcion_ecf` | Ruta, método, campo del archivo, **convención del nombre del archivo** |
| `endpoints.consulta_resultado` | Ruta y nombre del parámetro del trackId |
| `endpoints.consulta_trackids` | (Recomendado) consulta de trackIds por RNC y e-NCF: evita reenvíos a ciegas |
| `endpoints.estatus_servicios` | (Opcional) servicio de estado de disponibilidad |
| `respuestas` | Encabezado y prefijo del token; nombres exactos de token, expiración, trackId, estado, mensajes |
| `estados` | Valores exactos de aceptado, aceptado condicional, rechazado, en proceso, no encontrado |
| `firma` | URIs de algoritmo de firma, digest y canonicalización; prefijo de namespace; elemento y formato de la fecha/hora de firma; zona horaria |
| `codigo_seguridad` | Regla oficial (implementada: primeros N caracteres de `SignatureValue`); confirme N |
| `qr` | Plantilla de la URL de consulta por ambiente y, si aplica, por tipo de e-CF |
| `xml` | Elemento raíz y XPaths de e-NCF, tipo, RNC emisor/comprador, fecha de emisión y monto total |
| `encf` | Prefijo, longitudes, patrón y catálogo de tipos de e-CF |
| `contingencia` | Plazo oficial para regularizar lo emitido en contingencia |

Además:

- Descargue los **XSD oficiales** a `schemas/` y relaciónelos por tipo en `config/settings.toml`.
- Revise las reglas de **escape de caracteres** publicadas. El módulo escapa los caracteres
  reservados de XML (`& < > " '`); si la DGII exige reglas adicionales, aplíquelas al armar el
  contenido y valide con los ejemplos oficiales.
- Si la documentación define reglas no implementadas (por ejemplo, un flujo distinto para algún
  tipo de comprobante o un servicio de anulación de rangos), deben programarse explícitamente:
  la configuración rechaza valores que el código no sabe tratar.

Comando de control: `plomfact-ecf verificar-spec` (código de salida 1 mientras haya pendientes).
