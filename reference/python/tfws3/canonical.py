from __future__ import annotations
import json
from typing import Any
from .errors import ValidationError

MAX_SAFE_INTEGER = 9_007_199_254_740_991

def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValidationError(f"integer outside interoperable range at {path}")
        return
    if isinstance(value, float):
        raise ValidationError(f"floating point values are forbidden in TFWS core at {path}")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _validate(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"non-string object key at {path}")
            _validate(item, f"{path}.{key}")
        return
    raise ValidationError(f"unsupported value type at {path}: {type(value).__name__}")

def canonicalize(value: Any) -> bytes:
    """Deterministic JCS-compatible encoding for the TFWS integer-only core profile."""
    _validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle, parse_float=lambda _: (_ for _ in ()).throw(ValidationError("floats are forbidden")))
