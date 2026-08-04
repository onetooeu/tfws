"""TFWS 3.0 fail-closed bootstrap reference."""
from .canonical import decode_manifest_cbor
from .crypto import verify_manifest_cose_conformance

__all__ = ["decode_manifest_cbor", "verify_manifest_cose_conformance"]
__version__ = "3.0.0-alpha.1"
