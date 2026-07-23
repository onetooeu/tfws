from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from .errors import PolicyError, ValidationError

BASELINE = ("ed25519", "ml-dsa-65")
KNOWN_REQUIRED_CAPABILITIES = {
    "core.v1",
    "identity.v1",
    "recovery.v1",
    "transparency.v1",
}
MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def parse_rfc3339(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"invalid RFC3339 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ValidationError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_key_descriptors(data: dict, *, allow_unbound_development: bool) -> None:
    keys = data.get("keys")
    if not isinstance(keys, list):
        raise ValidationError("keys must be an array")
    if not keys and allow_unbound_development and data.get("environment") == "development":
        return
    if len(keys) != len(BASELINE):
        raise PolicyError("hybrid baseline requires exactly two active key descriptors")
    seen_algorithms: set[str] = set()
    seen_ids: set[tuple[str, str]] = set()
    for index, descriptor in enumerate(keys):
        expected_fields = {
            "algorithm",
            "key_id",
            "public_key_sha256",
            "public_key_uri",
            "status",
            "usage",
        }
        if not isinstance(descriptor, dict) or set(descriptor) != expected_fields:
            raise ValidationError(f"key descriptor {index} has invalid fields")
        algorithm = descriptor["algorithm"]
        if algorithm not in BASELINE or algorithm in seen_algorithms:
            raise PolicyError("missing, duplicate or unsupported baseline key")
        seen_algorithms.add(algorithm)
        key_id = descriptor["key_id"]
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValidationError(f"key descriptor {index} has invalid key_id")
        identity = (algorithm, key_id)
        if identity in seen_ids:
            raise ValidationError("duplicate key identity")
        seen_ids.add(identity)
        expected_uri = f"/.well-known/keys/{algorithm}.pem"
        if descriptor["public_key_uri"] != expected_uri:
            raise PolicyError(f"baseline public key URI must be {expected_uri}")
        if not _is_lower_hex(descriptor["public_key_sha256"], 64):
            raise ValidationError(f"key descriptor {index} has invalid SHA-256")
        if descriptor["status"] != "active" or descriptor["usage"] != ["release"]:
            raise PolicyError("baseline keys must be active release keys")
    if seen_algorithms != set(BASELINE):
        raise PolicyError("hybrid baseline key set is incomplete")


def validate_manifest(
    data: dict,
    *,
    allow_nonproduction: bool = True,
    allow_unbound_development: bool = True,
) -> None:
    required = {
        "artifacts",
        "capabilities",
        "environment",
        "key_epoch",
        "keys",
        "operator",
        "signature_policy",
        "subject",
        "tfws_version",
        "updated_at",
    }
    missing = required - set(data)
    if missing:
        raise ValidationError(f"missing manifest fields: {sorted(missing)}")
    unknown = set(data) - (required | {"expires_at", "identity"})
    if unknown:
        raise ValidationError(f"unknown manifest fields: {sorted(unknown)}")
    if data["tfws_version"] != "3.0":
        raise ValidationError("unsupported tfws_version")

    parsed = urlparse(data["subject"])
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValidationError(
            "subject must be an HTTPS origin without credentials/path/query/fragment"
        )

    if data["environment"] not in {"development", "staging", "production"}:
        raise ValidationError("invalid environment")
    if not allow_nonproduction and data["environment"] != "production":
        raise PolicyError("non-production manifest cannot pass production gate")

    if (
        not isinstance(data["key_epoch"], int)
        or isinstance(data["key_epoch"], bool)
        or not 1 <= data["key_epoch"] <= MAX_SAFE_INTEGER
    ):
        raise ValidationError("key_epoch must be a positive interoperable integer")

    policy = data["signature_policy"]
    if (
        not isinstance(policy, dict)
        or set(policy) != {"policy_id", "required_algorithms"}
        or policy.get("policy_id") != "tfws.hybrid.baseline.v1"
        or tuple(policy.get("required_algorithms", [])) != BASELINE
    ):
        raise PolicyError(
            "baseline requires ordered ed25519 + ml-dsa-65 and forbids downgrade"
        )

    validate_key_descriptors(
        data,
        allow_unbound_development=allow_unbound_development,
    )

    caps = data["capabilities"]
    if not isinstance(caps, dict) or set(caps) != {"required", "optional"}:
        raise ValidationError("capabilities must contain required and optional arrays")
    required_caps = caps["required"]
    optional_caps = caps["optional"]
    if not isinstance(required_caps, list) or not isinstance(optional_caps, list):
        raise ValidationError("capabilities.required and optional must be arrays")
    if (
        len(required_caps) != len(set(required_caps))
        or len(optional_caps) != len(set(optional_caps))
        or set(required_caps) & set(optional_caps)
    ):
        raise ValidationError("capabilities must be unique and disjoint")
    unknown_required = set(required_caps) - KNOWN_REQUIRED_CAPABILITIES
    if unknown_required:
        raise PolicyError(f"unknown mandatory capabilities: {sorted(unknown_required)}")

    updated = parse_rfc3339(data["updated_at"])
    if "expires_at" in data and parse_rfc3339(data["expires_at"]) <= updated:
        raise ValidationError("expires_at must be after updated_at")

    operator = data["operator"]
    if (
        not isinstance(operator, dict)
        or not set(operator) <= {"jurisdiction", "name"}
        or not str(operator.get("name", "")).strip()
    ):
        raise ValidationError("operator has invalid fields or missing name")
    jurisdiction = operator.get("jurisdiction")
    if jurisdiction is not None and (
        not isinstance(jurisdiction, str)
        or len(jurisdiction) != 2
        or not jurisdiction.isascii()
        or not jurisdiction.isupper()
    ):
        raise ValidationError("operator.jurisdiction must be an ISO-style uppercase code")

    if not isinstance(data["artifacts"], list):
        raise ValidationError("artifacts must be an array")
    for index, artifact in enumerate(data["artifacts"]):
        if not isinstance(artifact, dict) or set(artifact) != {
            "media_type",
            "sha512",
            "uri",
        }:
            raise ValidationError(f"artifact {index} has invalid fields")
        if not isinstance(artifact["uri"], str) or not artifact["uri"]:
            raise ValidationError(f"artifact {index} has invalid URI")
        if not isinstance(artifact["media_type"], str) or not artifact["media_type"]:
            raise ValidationError(f"artifact {index} has invalid media type")
        if not _is_lower_hex(artifact["sha512"], 128):
            raise ValidationError(f"artifact {index} has invalid sha512")
