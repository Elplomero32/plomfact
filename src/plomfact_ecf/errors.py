"""Errores del módulo fiscal. Todos los fallos fiscales se reportan con excepciones explícitas."""


class FiscalError(Exception):
    """Base de todos los errores fiscales."""


class SpecNotVerifiedError(FiscalError):
    """La especificación DGII no está verificada contra la documentación oficial."""


class ProductionGateError(FiscalError):
    """La emisión en el ambiente solicitado no está habilitada."""


class CertificateError(FiscalError):
    """Certificado digital inválido, vencido o no autorizado."""


class SequenceError(FiscalError):
    """Secuencia e-NCF agotada, vencida, inválida o duplicada."""


class XmlValidationError(FiscalError):
    """El XML no cumple el esquema oficial (XSD)."""


class SignatureError(FiscalError):
    """Error al firmar o verificar la firma digital."""


class DgiiTransportError(FiscalError):
    """Fallo de comunicación con los servicios de la DGII."""

    def __init__(self, message: str, *, ambiguous: bool = False):
        super().__init__(message)
        # ambiguous=True: el envío pudo haber llegado a la DGII (p. ej. timeout tras enviar).
        self.ambiguous = ambiguous


class DgiiAuthError(DgiiTransportError):
    """La DGII rechazó la autenticación."""


class ImmutableRecordError(FiscalError):
    """Intento de modificar un registro fiscal inmutable."""


class InvalidStateTransition(FiscalError):
    """Transición de estado fiscal no permitida."""
