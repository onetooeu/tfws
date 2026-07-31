#!/usr/bin/env python3
"""Generate deterministic structural CBOR/COSE conformance vectors for TFWS issue #7.

The committed corpus deliberately uses a deterministic fixture signature scheme
for byte-level and cross-language structural interoperability. Production
cryptographic correctness remains covered by the OpenSSL provider tests.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROFILE = "A2-COSE-04"
CORPUS_VERSION = "1"
COSE_CONTENT_TYPE = "application/tfws+cbor"
COSE_TYPE = 'application/cose; cose-type="cose-sign"'
ED25519_ALG = -19
ML_DSA_65_ALG = -49
ED25519_SIG_LEN = 64
ML_DSA_65_SIG_LEN = 3309
KID = b"release-1"
EXPECTED_BINDINGS = {
    "ed25519": {
        "key_id": "release-1",
        "public_key_uri": "/.well-known/keys/ed25519.pem",
        "public_key_sha256": "7fe64728f1a7bb8c6c103f49c0e2ed0e999678229256c7aab813634cc6c85ba9",
    },
    "ml-dsa-65": {
        "key_id": "release-1",
        "public_key_uri": "/.well-known/keys/ml-dsa-65.pem",
        "public_key_sha256": "85acf51bf7260bc7009f1b3d6b8a4f6d0442bf21ea91a86fe7cbb282edb317cb",
    },
}


class VectorError(ValueError):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


@dataclass(frozen=True)
class Tag:
    number: int
    value: Any


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("CBOR argument must be non-negative")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError("CBOR integer too large")


def cbor_encode(value: Any) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor_encode(item) for item in value)
    if isinstance(value, dict):
        encoded = [(cbor_encode(key), key, item) for key, item in value.items()]
        encoded.sort(key=lambda entry: (len(entry[0]), entry[0]))
        return _head(5, len(encoded)) + b"".join(
            key_bytes + cbor_encode(item) for key_bytes, _key, item in encoded
        )
    if isinstance(value, Tag):
        return _head(6, value.number) + cbor_encode(value.value)
    raise TypeError(f"unsupported CBOR value: {type(value).__name__}")


class Decoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _read(self, length: int) -> bytes:
        end = self.pos + length
        if end > len(self.data):
            raise VectorError("malformed_cbor", "truncated CBOR")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            value = self._read(1)[0]
            if value < 24:
                raise VectorError("non_deterministic_cbor", "non-preferred CBOR argument")
            return value
        if additional == 25:
            value = int.from_bytes(self._read(2), "big")
            if value <= 0xFF:
                raise VectorError("non_deterministic_cbor", "non-preferred CBOR argument")
            return value
        if additional == 26:
            value = int.from_bytes(self._read(4), "big")
            if value <= 0xFFFF:
                raise VectorError("non_deterministic_cbor", "non-preferred CBOR argument")
            return value
        if additional == 27:
            value = int.from_bytes(self._read(8), "big")
            if value <= 0xFFFFFFFF:
                raise VectorError("non_deterministic_cbor", "non-preferred CBOR argument")
            return value
        if additional == 31:
            raise VectorError("non_deterministic_cbor", "indefinite-length CBOR is unsupported")
        raise VectorError("malformed_cbor", "reserved CBOR additional information")

    def item(self) -> Any:
        start = self.pos
        initial = self._read(1)[0]
        major = initial >> 5
        additional = initial & 31

        if major in (0, 1):
            argument = self._argument(additional)
            return argument if major == 0 else -1 - argument
        if major in (2, 3):
            length = self._argument(additional)
            raw = self._read(length)
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise VectorError("malformed_cbor", "invalid UTF-8") from exc
        if major == 4:
            length = self._argument(additional)
            return [self.item() for _ in range(length)]
        if major == 5:
            length = self._argument(additional)
            result: dict[Any, Any] = {}
            previous_key_bytes: bytes | None = None
            for _ in range(length):
                key_start = self.pos
                key = self.item()
                key_bytes = self.data[key_start:self.pos]
                if previous_key_bytes is not None and (
                    len(key_bytes), key_bytes
                ) <= (len(previous_key_bytes), previous_key_bytes):
                    if key in result:
                        raise VectorError("non_deterministic_cbor", "duplicate CBOR map key")
                    raise VectorError("non_deterministic_cbor", "CBOR map key order")
                if key in result:
                    raise VectorError("non_deterministic_cbor", "duplicate CBOR map key")
                previous_key_bytes = key_bytes
                result[key] = self.item()
            return result
        if major == 6:
            return Tag(self._argument(additional), self.item())
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise VectorError("unsupported_cbor_type", "unsupported CBOR simple/float value")

        raise VectorError("malformed_cbor", f"unsupported major type at {start}")


def cbor_decode_exact(data: bytes) -> Any:
    decoder = Decoder(data)
    value = decoder.item()
    if decoder.pos != len(data):
        raise VectorError("malformed_cbor", "trailing CBOR data")
    if cbor_encode(value) != data:
        raise VectorError("non_deterministic_cbor", "CBOR is not canonical")
    return value


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_signature(algorithm: int, message: bytes) -> bytes:
    if algorithm == ED25519_ALG:
        prefix = b"\x13"
        length = ED25519_SIG_LEN
    elif algorithm == ML_DSA_65_ALG:
        prefix = b"\x31"
        length = ML_DSA_65_SIG_LEN
    else:
        raise VectorError("invalid_algorithm", f"unsupported algorithm: {algorithm}")
    digest = hashlib.sha256(prefix + message).digest()
    return (digest * ((length + len(digest) - 1) // len(digest)))[:length]


def body_protected(*, content_type: str = COSE_CONTENT_TYPE, cose_type: str = COSE_TYPE, extra: dict[int, Any] | None = None) -> bytes:
    headers: dict[int, Any] = {3: content_type, 16: cose_type}
    if extra:
        headers.update(extra)
    return cbor_encode(headers)


def signature_protected(algorithm: int, kid: bytes = KID, extra: dict[int, Any] | None = None) -> bytes:
    headers: dict[int, Any] = {1: algorithm, 4: kid}
    if extra:
        headers.update(extra)
    return cbor_encode(headers)


def sig_structure(body: bytes, protected: bytes, payload: bytes) -> bytes:
    return cbor_encode(["Signature", body, protected, b"", payload])


def make_envelope(payload: bytes, body: bytes, signatures: list[tuple[bytes, bytes]]) -> bytes:
    return cbor_encode(
        Tag(
            98,
            [
                body,
                {},
                payload,
                [[protected, {}, signature] for protected, signature in signatures],
            ],
        )
    )


def validate_manifest(manifest: dict[str, Any]) -> None:
    try:
        if manifest["tfws_version"] != "3.0":
            raise VectorError("manifest_policy_invalid", "unsupported version")
        if manifest["environment"] not in {"development", "staging", "production"}:
            raise VectorError("manifest_policy_invalid", "invalid environment")
        if manifest["signature_policy"] != {
            "policy_id": "tfws.hybrid.baseline.v1",
            "required_algorithms": ["ed25519", "ml-dsa-65"],
        }:
            raise VectorError("manifest_policy_invalid", "hybrid baseline downgrade")
        keys = manifest["keys"]
        if len(keys) != 2 or [entry["algorithm"] for entry in keys] != ["ed25519", "ml-dsa-65"]:
            raise VectorError("manifest_policy_invalid", "invalid baseline descriptors")
        for entry in keys:
            algorithm = entry["algorithm"]
            if entry["key_id"] != "release-1":
                raise VectorError("manifest_policy_invalid", "invalid key id")
            if entry["public_key_uri"] != f"/.well-known/keys/{algorithm}.pem":
                raise VectorError("manifest_policy_invalid", "invalid public key URI")
            digest = entry["public_key_sha256"]
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise VectorError("manifest_policy_invalid", "invalid public key digest")
            if entry["status"] != "active" or entry["usage"] != ["release"]:
                raise VectorError("manifest_policy_invalid", "invalid key status or usage")
    except KeyError as exc:
        raise VectorError("manifest_policy_invalid", f"missing manifest field: {exc}") from exc


def encode_manifest(manifest: dict[str, Any]) -> bytes:
    validate_manifest(manifest)
    return cbor_encode(manifest)


def decode_manifest(data: bytes) -> dict[str, Any]:
    value = cbor_decode_exact(data)
    if not isinstance(value, dict):
        raise VectorError("manifest_policy_invalid", "manifest must be a map")
    validate_manifest(value)
    return value


def _descriptor(manifest: dict[str, Any], algorithm_name: str) -> dict[str, Any]:
    matching = [entry for entry in manifest["keys"] if entry["algorithm"] == algorithm_name]
    if len(matching) != 1:
        raise VectorError("hybrid_baseline_incomplete", "missing or duplicate descriptor")
    return matching[0]


def build_positive(manifest: dict[str, Any]) -> tuple[bytes, bytes]:
    payload = encode_manifest(manifest)
    body = body_protected()
    signatures: list[tuple[bytes, bytes]] = []
    for algorithm, name in ((ED25519_ALG, "ed25519"), (ML_DSA_65_ALG, "ml-dsa-65")):
        descriptor = _descriptor(manifest, name)
        protected = signature_protected(algorithm, descriptor["key_id"].encode("utf-8"))
        message = sig_structure(body, protected, payload)
        signatures.append((protected, fixture_signature(algorithm, message)))
    return payload, make_envelope(payload, body, signatures)


def verify_cose(envelope: bytes) -> dict[str, Any]:
    value = cbor_decode_exact(envelope)
    if not isinstance(value, Tag) or value.number != 98:
        raise VectorError("invalid_cose_structure", "COSE tag 98 is required")
    outer = value.value
    if not isinstance(outer, list) or len(outer) != 4:
        raise VectorError("invalid_cose_structure", "COSE outer array must have four items")
    body, body_unprotected, payload, signatures = outer
    if not isinstance(body, bytes) or body_unprotected != {} or not isinstance(payload, bytes):
        raise VectorError("invalid_cose_structure", "invalid COSE body fields")
    body_headers = cbor_decode_exact(body)
    if not isinstance(body_headers, dict):
        raise VectorError("invalid_cose_structure", "body protected must be a map")
    if set(body_headers) != {3, 16}:
        raise VectorError("unsupported_header", "unsupported protected body header")
    if body_headers[3] != COSE_CONTENT_TYPE:
        raise VectorError("invalid_content_type", "invalid COSE content type")
    if body_headers[16] != COSE_TYPE:
        raise VectorError("invalid_type", "invalid COSE typ")
    manifest = decode_manifest(payload)
    if not isinstance(signatures, list) or len(signatures) != 2:
        raise VectorError("invalid_cose_structure", "hybrid signatures array must contain two entries")
    expected = ((ED25519_ALG, "ed25519", ED25519_SIG_LEN), (ML_DSA_65_ALG, "ml-dsa-65", ML_DSA_65_SIG_LEN))
    for entry, (algorithm, name, expected_len) in zip(signatures, expected):
        if not isinstance(entry, list) or len(entry) != 3:
            raise VectorError("invalid_cose_structure", "invalid signature entry")
        protected, unprotected, signature = entry
        if not isinstance(protected, bytes) or unprotected != {} or not isinstance(signature, bytes):
            raise VectorError("invalid_cose_structure", "invalid signature fields")
        headers = cbor_decode_exact(protected)
        if not isinstance(headers, dict) or set(headers) != {1, 4}:
            raise VectorError("unsupported_header", "unsupported signature protected header")
        if headers[1] != algorithm:
            raise VectorError("invalid_algorithm", "invalid or reordered algorithm")
        if headers[4] != KID:
            raise VectorError("invalid_kid", "invalid key identifier")
        if len(signature) != expected_len:
            raise VectorError("signature_invalid", "invalid signature length")
        descriptor = _descriptor(manifest, name)
        expected_binding = EXPECTED_BINDINGS[name]
        if descriptor != {
            "algorithm": name,
            **expected_binding,
            "status": "active",
            "usage": ["release"],
        }:
            raise VectorError("key_binding_mismatch", "public-key binding mismatch")
        expected_signature = fixture_signature(algorithm, sig_structure(body, protected, payload))
        if signature != expected_signature:
            raise VectorError("signature_invalid", "signature invalid")
    return manifest


def _hex(data: bytes) -> str:
    return data.hex()


def _negative(case_id: str, case_class: str, input_type: str, data: bytes, expected_category: str) -> dict[str, Any]:
    return {
        "id": case_id,
        "class": case_class,
        "input_type": input_type,
        "bytes_hex": _hex(data),
        "sha256": sha256_hex(data),
        "expected_category": expected_category,
    }


def _mutate_payload(envelope_obj: Tag, new_payload: bytes) -> bytes:
    outer = copy.deepcopy(envelope_obj.value)
    outer[2] = new_payload
    return cbor_encode(Tag(98, outer))


def build_corpus(manifest: dict[str, Any]) -> dict[str, Any]:
    payload, envelope = build_positive(manifest)
    envelope_obj = cbor_decode_exact(envelope)
    assert isinstance(envelope_obj, Tag)
    outer = envelope_obj.value
    signatures = outer[3]

    negative: list[dict[str, Any]] = []
    negative.append(_negative("malformed-cbor", "malformed_cbor", "manifest_cbor", b"", "malformed_cbor"))
    negative.append(_negative("truncated-cbor", "truncated_cbor", "manifest_cbor", payload[:-1], "malformed_cbor"))
    negative.append(_negative("noncanonical-cbor", "noncanonical_cbor", "manifest_cbor", b"\xb8\x00", "non_deterministic_cbor"))
    negative.append(_negative("duplicate-key-cbor", "duplicate_key", "manifest_cbor", bytes.fromhex("a2616101616102"), "non_deterministic_cbor"))

    unsupported_body = body_protected(extra={99: True})
    negative.append(_negative(
        "unsupported-mandatory-header",
        "unsupported_mandatory_field",
        "cose",
        make_envelope(payload, unsupported_body, [(entry[0], entry[2]) for entry in signatures]),
        "unsupported_header",
    ))

    payload_mutation = copy.deepcopy(manifest)
    payload_mutation["operator"]["name"] = "Example Organizatioo"
    negative.append(_negative(
        "payload-substitution",
        "payload_substitution",
        "cose",
        _mutate_payload(envelope_obj, encode_manifest(payload_mutation)),
        "signature_invalid",
    ))

    substituted_body = body_protected(content_type="application/tfws+cbos")
    negative.append(_negative(
        "protected-header-substitution",
        "protected_header_substitution",
        "cose",
        make_envelope(payload, substituted_body, [(entry[0], entry[2]) for entry in signatures]),
        "invalid_content_type",
    ))

    negative.append(_negative(
        "missing-ed25519-signature",
        "missing_ed25519_signature",
        "cose",
        make_envelope(payload, outer[0], [(signatures[1][0], signatures[1][2])]),
        "invalid_cose_structure",
    ))
    negative.append(_negative(
        "missing-ml-dsa-65-signature",
        "missing_ml_dsa_65_signature",
        "cose",
        make_envelope(payload, outer[0], [(signatures[0][0], signatures[0][2])]),
        "invalid_cose_structure",
    ))
    negative.append(_negative(
        "duplicate-signature-component",
        "duplicate_signature_component",
        "cose",
        make_envelope(payload, outer[0], [(signatures[0][0], signatures[0][2]), (signatures[0][0], signatures[0][2])]),
        "invalid_algorithm",
    ))

    unknown_protected = signature_protected(-999)
    negative.append(_negative(
        "unknown-mandatory-algorithm",
        "unknown_mandatory_algorithm",
        "cose",
        make_envelope(payload, outer[0], [(signatures[0][0], signatures[0][2]), (unknown_protected, signatures[1][2])]),
        "invalid_algorithm",
    ))
    negative.append(_negative(
        "algorithm-substitution",
        "algorithm_substitution",
        "cose",
        make_envelope(payload, outer[0], [(signatures[1][0], signatures[1][2]), (signatures[0][0], signatures[0][2])]),
        "invalid_algorithm",
    ))
    negative.append(_negative(
        "algorithm-mismatch",
        "algorithm_mismatch",
        "cose",
        make_envelope(payload, outer[0], [(signatures[0][0], signatures[0][2]), (signatures[1][0], signatures[0][2])]),
        "signature_invalid",
    ))

    wrong_kid = signature_protected(ED25519_ALG, b"release-2")
    negative.append(_negative(
        "wrong-key-identifier",
        "wrong_key_identifier",
        "cose",
        make_envelope(payload, outer[0], [(wrong_kid, signatures[0][2]), (signatures[1][0], signatures[1][2])]),
        "invalid_kid",
    ))

    wrong_descriptor = copy.deepcopy(manifest)
    wrong_descriptor["keys"][0]["public_key_uri"] = "/.well-known/keys/replaced.pem"
    negative.append(_negative(
        "wrong-public-key-descriptor",
        "wrong_public_key_descriptor",
        "cose",
        _mutate_payload(envelope_obj, cbor_encode(wrong_descriptor)),
        "manifest_policy_invalid",
    ))

    wrong_sha = copy.deepcopy(manifest)
    original_sha = wrong_sha["keys"][0]["public_key_sha256"]
    wrong_sha["keys"][0]["public_key_sha256"] = ("0" if original_sha[0] != "0" else "1") + original_sha[1:]
    negative.append(_negative(
        "wrong-sha256-key-binding",
        "wrong_sha256_key_binding",
        "cose",
        _mutate_payload(envelope_obj, encode_manifest(wrong_sha)),
        "key_binding_mismatch",
    ))

    invalid_ed = bytearray(signatures[0][2])
    invalid_ed[-1] ^= 1
    negative.append(_negative(
        "invalid-ed25519-signature",
        "invalid_ed25519_signature",
        "cose",
        make_envelope(payload, outer[0], [(signatures[0][0], bytes(invalid_ed)), (signatures[1][0], signatures[1][2])]),
        "signature_invalid",
    ))

    invalid_ml = bytearray(signatures[1][2])
    invalid_ml[-1] ^= 1
    negative.append(_negative(
        "invalid-ml-dsa-65-signature",
        "invalid_ml_dsa_65_signature",
        "cose",
        make_envelope(payload, outer[0], [(signatures[0][0], signatures[0][2]), (signatures[1][0], bytes(invalid_ml))]),
        "signature_invalid",
    ))

    return {
        "corpus_version": CORPUS_VERSION,
        "profile": PROFILE,
        "provenance": {
            "source_manifest": "test-vectors/manifest.valid.json",
            "generator": "scripts/generate_issue7_cbor_cose_vectors.py",
            "base_commit": "bf28bd8b405fe3610aa117e82b8ab91fc76a16a3",
            "network_input": False,
            "random_input": False,
            "timestamp_input": False,
            "fixture_warning": "Structural deterministic signatures; not production cryptographic known-answer vectors.",
        },
        "fixture_crypto": {
            "scheme": "sha256-prefix-repeat-v1",
            "ed25519_prefix_hex": "13",
            "ml_dsa_65_prefix_hex": "31",
            "ed25519_signature_bytes": ED25519_SIG_LEN,
            "ml_dsa_65_signature_bytes": ML_DSA_65_SIG_LEN,
        },
        "positive": {
            "id": "positive-hybrid-envelope-v1",
            "manifest": manifest,
            "manifest_cbor_hex": _hex(payload),
            "manifest_cbor_sha256": sha256_hex(payload),
            "cose_hex": _hex(envelope),
            "cose_sha256": sha256_hex(envelope),
            "expected_category": "valid",
        },
        "negative": negative,
    }


def corpus_bytes(corpus: dict[str, Any]) -> bytes:
    return (json.dumps(corpus, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def validate_corpus(corpus: dict[str, Any]) -> None:
    if corpus.get("corpus_version") != CORPUS_VERSION or corpus.get("profile") != PROFILE:
        raise VectorError("schema_invalid", "invalid corpus version or profile")
    positive = corpus.get("positive")
    negative = corpus.get("negative")
    if not isinstance(positive, dict) or not isinstance(negative, list) or len(negative) != 18:
        raise VectorError("schema_invalid", "invalid positive or negative vector inventory")
    required_positive = {
        "id", "manifest", "manifest_cbor_hex", "manifest_cbor_sha256", "cose_hex", "cose_sha256", "expected_category"
    }
    if set(positive) != required_positive:
        raise VectorError("schema_invalid", "invalid positive vector fields")
    ids: set[str] = {positive["id"]}
    classes: set[str] = set()
    for case in negative:
        if set(case) != {"id", "class", "input_type", "bytes_hex", "sha256", "expected_category"}:
            raise VectorError("schema_invalid", "invalid negative vector fields")
        if case["id"] in ids:
            raise VectorError("schema_invalid", "duplicate vector id")
        ids.add(case["id"])
        classes.add(case["class"])
        raw = bytes.fromhex(case["bytes_hex"])
        if sha256_hex(raw) != case["sha256"]:
            raise VectorError("schema_invalid", f"digest mismatch: {case['id']}")
    required_classes = {
        "malformed_cbor", "truncated_cbor", "noncanonical_cbor", "duplicate_key",
        "unsupported_mandatory_field", "payload_substitution", "protected_header_substitution",
        "missing_ed25519_signature", "missing_ml_dsa_65_signature", "duplicate_signature_component",
        "unknown_mandatory_algorithm", "algorithm_substitution", "algorithm_mismatch",
        "wrong_key_identifier", "wrong_public_key_descriptor", "wrong_sha256_key_binding",
        "invalid_ed25519_signature", "invalid_ml_dsa_65_signature",
    }
    if classes != required_classes:
        raise VectorError("schema_invalid", "negative class inventory mismatch")


def self_test(corpus: dict[str, Any]) -> dict[str, str]:
    validate_corpus(corpus)
    positive = corpus["positive"]
    manifest_bytes = bytes.fromhex(positive["manifest_cbor_hex"])
    cose_bytes = bytes.fromhex(positive["cose_hex"])
    if sha256_hex(manifest_bytes) != positive["manifest_cbor_sha256"]:
        raise VectorError("digest_invalid", "positive manifest digest mismatch")
    if sha256_hex(cose_bytes) != positive["cose_sha256"]:
        raise VectorError("digest_invalid", "positive COSE digest mismatch")
    if decode_manifest(manifest_bytes) != positive["manifest"]:
        raise VectorError("semantic_mismatch", "positive manifest semantic mismatch")
    if verify_cose(cose_bytes) != positive["manifest"]:
        raise VectorError("semantic_mismatch", "positive COSE semantic mismatch")

    results = {positive["id"]: "valid"}
    for case in corpus["negative"]:
        raw = bytes.fromhex(case["bytes_hex"])
        try:
            if case["input_type"] == "manifest_cbor":
                decode_manifest(raw)
            elif case["input_type"] == "cose":
                verify_cose(raw)
            else:
                raise VectorError("schema_invalid", "unknown input type")
        except VectorError as exc:
            if exc.category != case["expected_category"]:
                raise AssertionError(
                    f"{case['id']}: expected {case['expected_category']}, got {exc.category}: {exc}"
                ) from exc
            results[case["id"]] = exc.category
        else:
            raise AssertionError(f"negative vector unexpectedly accepted: {case['id']}")
    return results


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("manifest must be a JSON object")
    return value


def write_outputs(corpus: dict[str, Any], output: Path, digest_output: Path) -> None:
    data = corpus_bytes(corpus)
    output.parent.mkdir(parents=True, exist_ok=True)
    digest_output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    digest_output.write_text(f"{sha256_hex(data)}  {output.name}\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--digest-output", type=Path, required=True)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    corpus = build_corpus(load_manifest(args.manifest))
    validate_corpus(corpus)
    if args.self_test:
        self_test(corpus)

    expected_data = corpus_bytes(corpus)
    expected_digest = f"{sha256_hex(expected_data)}  {args.output.name}\n"

    if args.check:
        if args.output.read_bytes() != expected_data:
            raise SystemExit("committed corpus differs from deterministic regeneration")
        if args.digest_output.read_text(encoding="utf-8") != expected_digest:
            raise SystemExit("committed digest file differs from deterministic regeneration")
        if args.schema is not None:
            schema = json.loads(args.schema.read_text(encoding="utf-8"))
            if schema.get("$id") != "https://tfws.example/schema/issue7-cbor-cose-cross-language-v1.schema.json":
                raise SystemExit("unexpected vector schema identifier")
    else:
        write_outputs(corpus, args.output, args.digest_output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
