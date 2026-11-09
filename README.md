# PlomFact e-CF — Módulo de integración fiscal con la DGII

Módulo en Python para que PlomFact opere como **emisor electrónico de e-CF** ante la Dirección
General de Impuestos Internos (DGII) de la República Dominicana: firma, transmisión, consulta de
estado, numeración e-NCF, representación impresa, contingencia y conservación de evidencias.

> **Estado: listo para iniciar la certificación, no para producción.**
> El código no contiene ningún endpoint, nombre de campo, estado fiscal, formato de QR ni regla
> de código de seguridad de la DGII. Todos esos datos se cargan desde `config/dgii_spec.toml`, que
> debe completarse **exclusivamente** con la documentación técnica oficial vigente. Mientras una
> sección no esté marcada `verificado = true` con su `fuente`, la función que la usa queda bloqueada.

## Inicio rápido

```bash
pip install -e ".[test]"
pytest                                   # 90 pruebas, sin red (DGII simulada)

cp config/dgii_spec.example.toml config/dgii_spec.toml   # completar desde la documentación DGII
cp config/settings.example.toml  config/settings.toml    # datos del emisor (sin secretos)
plomfact-ecf verificar-spec              # lista lo que falta verificar
```

## Documentación

| Documento | Contenido |
|---|---|
| [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) | Módulos, flujo de emisión, estados, garantías |
| [docs/VERIFICACION_DGII.md](docs/VERIFICACION_DGII.md) | Lista de verificación contra la documentación oficial |
| [docs/OPERACION.md](docs/OPERACION.md) | Certificación, puesta en producción, renovaciones, contingencia, migraciones |

## Requisitos cubiertos

| # | Requisito | Dónde |
|---|---|---|
| 1 | Credenciales y certificados | `credentials.py` |
| 2 | Autenticación, recepción y consulta | `dgii_client.py` |
| 3 | XML conforme al formato oficial | `xmlsign.py` (validación obligatoria contra XSD oficial) |
| 4 | Firma digital | `xmlsign.py` (XMLDSig vía libxmlsec1) |
| 5 | Representación impresa con QR y código de seguridad | `representation.py` |
| 6 | Secuencias e-NCF sin duplicados ni fuera de rango | `sequences.py` + restricciones SQL |
| 7–8 | Vencimientos, alertas y renovación segura | `alerts.py`, `CertificateRegistry.rotate` |
| 9 | Cola de transmisión y reintentos seguros | `transmission.py` |
| 10 | Estados por trackId | `TransmissionQueue.poll_status` |
| 11 | Conservación de evidencias | `archive.py` |
| 12 | Contingencia y recuperación | `contingency.py` |
| 13 | Sin validez fiscal sin aceptación DGII | `status.py` |
| 14 | Pruebas automatizadas | `tests/` |
