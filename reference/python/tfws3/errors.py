class TFWSError(Exception):
    """Base TFWS error."""

class ValidationError(TFWSError):
    pass

class CryptoError(TFWSError):
    pass

class PolicyError(TFWSError):
    pass
