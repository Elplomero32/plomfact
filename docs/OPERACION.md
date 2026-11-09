# Operación

## 1. Preparación
1. Obtener el certificado digital de persona física/jurídica para firma, emitido por una entidad
   de certificación autorizada. Guardarlo fuera del repositorio (`secrets/`, permisos 600).
2. Proveer la contraseña por variable de entorno (`PLOMFACT_CERT_PASSWORD`) o archivo 600.
   Nunca en `settings.toml`, en la base de datos ni en el control de versiones.
3. Completar y verificar `config/dgii_spec.toml` (ver `VERIFICACION_DGII.md`).
4. `plomfact-ecf certificado-registrar`

## 2. Certificación oficial
1. `ambiente = "precertificacion"`: registrar los rangos de prueba que asigne la DGII
   (`plomfact-ecf rango-registrar --tipo .. --desde .. --hasta .. --vence .. --referencia ..`).
2. Ejecutar los set de pruebas que exija la DGII; `plomfact-ecf transmitir` envía la cola y
   consulta estados. Evidencias en `data/evidencias`.
3. Repetir en `certificacion` según indique el proceso oficial.
4. Al recibir la autorización: `plomfact-ecf habilitar --ambiente produccion --referencia "<ref.
   oficial>" --por "<responsable>"` y luego `produccion_habilitada = true`. Sin ambos pasos la
   emisión en producción falla.

## 3. Tareas periódicas
| Tarea | Frecuencia sugerida |
|---|---|
| `plomfact-ecf transmitir` | cada 1–5 min (cola + estados; incluye recuperación) |
| `plomfact-ecf alertas` | diaria |
| `plomfact-ecf integridad` | diaria/semanal y antes/después de cada migración |
| Respaldo de `data/` (BD + evidencias) | diario, fuera del servidor, cifrado |

Los canales de alerta se conectan pasando funciones `sinks` a `ExpiryMonitor` (correo, webhook…).

## 4. Renovaciones
- **Certificado**: obtener el nuevo antes del umbral crítico; `plomfact-ecf certificado-renovar
  --archivo <nuevo.p12>`. Solo se acepta si es válido y vence después del actual. Los comprobantes
  ya emitidos conservan la firma y la huella del certificado anterior.
- **Secuencias**: al alertar por vencimiento o pocos e-NCF disponibles, solicitar un nuevo rango
  a la DGII y registrarlo con su referencia. Los rangos no se editan; solo se anulan.
- **e-NCF asignados sin uso** (fallo antes de emitir): aparecen en alertas; gestionar su anulación
  por el procedimiento oficial y luego `SequenceManager.mark_annulled`.
- **Especificación DGII**: cuando la DGII publique una versión nueva, actualizar el archivo,
  re-verificar y probar en precertificación antes de producción.

## 5. Contingencia
- Se activa tras N fallos consecutivos (`[contingencia]`). La emisión continúa: los comprobantes se
  firman, archivan y quedan en cola marcados *emitido en contingencia* y la representación impresa
  indica *pendiente de aceptación*.
- Al volver el servicio, la cola transmite y la contingencia se cierra (periodo registrado).
- Los comprobantes que superen el plazo oficial aparecen en `ContingencyManager.overdue()`.
- Caída del proceso en pleno envío: `recuperar` (incluido en `transmitir`) pasa el envío a
  AMBIGUO; antes de reenviar se consulta a la DGII si ya lo tiene.
- `REVISION_REQUERIDA`: requiere revisión humana; nunca se considera válido.

## 6. Actualizaciones y migración de infraestructura
- Las migraciones de BD son **solo aditivas** y se registran con checksum. Editar una ya aplicada
  impide el arranque. Una versión anterior de la aplicación no abre una BD migrada.
- Las evidencias se guardan con rutas relativas: migrar = detener el servicio, ejecutar
  `integridad`, copiar `data/` completo, apuntar `settings.toml` y volver a ejecutar `integridad`.
- Los triggers impiden borrar o reescribir comprobantes, e-NCF, rangos, eventos, evidencias y
  habilitaciones con SQL ordinario. Quien tenga acceso administrativo podría eliminar triggers:
  por eso la cadena de hashes de evidencias (`integridad`) detecta esa manipulación, y el acceso
  al servidor y a los respaldos debe restringirse.
