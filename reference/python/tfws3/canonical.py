from __future__ import annotations
import json
from typing import Any
from .errors import InteroperabilityError, PolicyError, ValidationError

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_CBOR_BYTES = 1_048_576
MAX_CBOR_DEPTH = 32
MAX_CBOR_COLLECTION_ITEMS = 4096
MAX_CBOR_STRING_BYTES = 1_048_576


class _CborTag:
    def __init__(self, tag: int, value: Any):
        self.tag = tag
        self.value = value


class _CborDecoder:
    def __init__(
        self,
        data: bytes,
        *,
        allow_bytes: bool,
        allow_tags: bool,
        allow_null: bool,
    ):
        if not isinstance(data, bytes):
            raise InteroperabilityError(
                "CBOR input must be bytes", code="malformed_cbor"
            )
        if len(data) > MAX_CBOR_BYTES:
            raise InteroperabilityError(
                "CBOR input exceeds resource limit", code="resource_limit"
            )
        self.data = data
        self.offset = 0
        self.allow_bytes = allow_bytes
        self.allow_tags = allow_tags
        self.allow_null = allow_null

    def _fail(self, message: str, code: str = "malformed_cbor") -> None:
        raise InteroperabilityError(message, code=code)

    def _take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.data):
            self._fail("truncated CBOR input")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def _argument(self, additional: int, kind: str) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            if additional == 31:
                self._fail(
                    f"indefinite-length {kind} is forbidden",
                    "non_deterministic_cbor",
                )
            self._fail("invalid CBOR additional information")
        value = int.from_bytes(self._take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 4_294_967_296}[width]
        if value < minimum:
            self._fail(
                f"non-preferred CBOR encoding for {kind}",
                "non_deterministic_cbor",
            )
        return value

    def item(self, depth: int = 0) -> Any:
        if depth > MAX_CBOR_DEPTH:
            self._fail("CBOR nesting depth exceeds resource limit", "resource_limit")
        if self.offset >= len(self.data):
            self._fail("truncated CBOR input")
        start = self.offset
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F

        if major in (0, 1):
            value = self._argument(additional, "integer")
            number = value if major == 0 else -1 - value
            if abs(number) > MAX_SAFE_INTEGER:
                self._fail(
                    "CBOR integer is outside interoperable range",
                    "unsupported_cbor_type",
                )
            return number

        if major in (2, 3):
            length = self._argument(
                additional, "byte string" if major == 2 else "text string"
            )
            if length > MAX_CBOR_STRING_BYTES:
                self._fail("CBOR string exceeds resource limit", "resource_limit")
            raw = self._take(length)
            if major == 2:
                if not self.allow_bytes:
                    self._fail(
                        "byte strings are not valid manifest values",
                        "unsupported_cbor_type",
                    )
                return raw
            try:
                return raw.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise InteroperabilityError(
                    "CBOR text is not valid UTF-8", code="malformed_cbor"
                ) from exc

        if major == 4:
            length = self._argument(additional, "array")
            if length > MAX_CBOR_COLLECTION_ITEMS:
                self._fail("CBOR array exceeds resource limit", "resource_limit")
            return [self.item(depth + 1) for _ in range(length)]

        if major == 5:
            length = self._argument(additional, "map")
            if length > MAX_CBOR_COLLECTION_ITEMS:
                self._fail("CBOR map exceeds resource limit", "resource_limit")
            result: dict[Any, Any] = {}
            previous_key_encoding: bytes | None = None
            for _ in range(length):
                key_start = self.offset
                key = self.item(depth + 1)
                key_encoding = self.data[key_start:self.offset]
                if not isinstance(key, (str, int, bytes)):
                    self._fail(
                        "unsupported CBOR map key type",
                        "unsupported_cbor_type",
                    )
                if previous_key_encoding is not None:
                    previous_order = (len(previous_key_encoding), previous_key_encoding)
                    current_order = (len(key_encoding), key_encoding)
                    if current_order <= previous_order:
                        self._fail(
                            "CBOR map keys are duplicate or out of order",
                            "non_deterministic_cbor",
                        )
                previous_key_encoding = key_encoding
                if key in result:
                    self._fail("duplicate CBOR map key", "non_deterministic_cbor")
                result[key] = self.item(depth + 1)
            return result

        if major == 6:
            tag = self._argument(additional, "tag")
            if not self.allow_tags:
                self._fail("CBOR tags are not supported", "unsupported_cbor_type")
            return _CborTag(tag, self.item(depth + 1))

        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22 and self.allow_null:
                return None
            self._fail("unsupported CBOR simple or floating-point value", "unsupported_cbor_type")

        self._fail(f"unsupported CBOR major type at byte {start}", "unsupported_cbor_type")


def _decode_cbor_document(
    data: bytes,
    *,
    allow_bytes: bool = False,
    allow_tags: bool = False,
    allow_null: bool = False,
) -> Any:
    decoder = _CborDecoder(
        data,
        allow_bytes=allow_bytes,
        allow_tags=allow_tags,
        allow_null=allow_null,
    )
    value = decoder.item()
    if decoder.offset != len(data):
        raise InteroperabilityError(
            "trailing data after CBOR document", code="malformed_cbor"
        )
    return value


def _validate_manifest_cbor_value(value: Any, path: str = "$") -> None:
    if isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise InteroperabilityError(
                f"integer outside interoperable range at {path}",
                code="unsupported_cbor_type",
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_manifest_cbor_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InteroperabilityError(
                    f"non-text manifest map key at {path}",
                    code="unsupported_cbor_type",
                )
            _validate_manifest_cbor_value(item, f"{path}.{key}")
        return
    raise InteroperabilityError(
        f"unsupported manifest CBOR value at {path}",
        code="unsupported_cbor_type",
    )


def decode_manifest_cbor(data: bytes) -> dict:
    """Decode deterministic TFWS manifest CBOR and validate its abstract model."""
    value = _decode_cbor_document(data)
    if not isinstance(value, dict):
        raise InteroperabilityError(
            "manifest CBOR root must be a map", code="manifest_policy_invalid"
        )
    _validate_manifest_cbor_value(value)
    from .models import validate_manifest

    try:
        validate_manifest(value)
    except (
        ValidationError,
        PolicyError,
        TypeError,
        ValueError,
        AttributeError,
        KeyError,
    ) as exc:
        raise InteroperabilityError(
            "decoded manifest violates the TFWS profile",
            code="manifest_policy_invalid",
        ) from exc
    return value

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
