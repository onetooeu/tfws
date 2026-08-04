class TFWSError(Exception):
    """Base TFWS error."""

    default_code = "tfws_error"

    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        self.code = code or self.default_code
        self.message = message

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


class ValidationError(TFWSError):
    default_code = "validation_error"


class CryptoError(TFWSError):
    default_code = "crypto_error"


class PolicyError(TFWSError):
    default_code = "policy_error"


class InteroperabilityError(TFWSError):
    """Stable CBOR/COSE interoperability failure."""

    default_code = "interoperability_error"
