from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .canonical import canonicalize
from .errors import CryptoError, ValidationError
from .models import BASELINE, parse_rfc3339, validate_manifest

OPENSSL_MIN = (3, 5, 0)


def _run(args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            args,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CryptoError(f"command failed: {args[0]}") from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise CryptoError(
            f"command failed ({result.returncode}): {' '.join(args)}: {message}"
        )
    return result.stdout


def require_openssl() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise CryptoError("OpenSSL 3.5+ is required")
    version = _run([exe, "version"]).decode("utf-8", "strict").split()
    try:
        numbers = tuple(int(part) for part in version[1].split(".")[:3])
    except Exception as exc:
        raise CryptoError("unable to parse OpenSSL version") from exc
    if numbers < OPENSSL_MIN:
        raise CryptoError(
            f"OpenSSL {OPENSSL_MIN[0]}.{OPENSSL_MIN[1]}+ required, found {version[1]}"
        )
    algorithms = _run([exe, "list", "-signature-algorithms"]).decode(
        "utf-8", "replace"
    ).lower()
    if "ed25519" not in algorithms or "ml-dsa-65" not in algorithms:
        raise CryptoError("OpenSSL provider lacks Ed25519 or ML-DSA-65")
    return exe


def _secure_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def generate_keyset(directory: Path, *, key_id: str = "release-1") -> dict:
    openssl = require_openssl()
    directory.mkdir(parents=True, exist_ok=False)
    private = directory / "private"
    public = directory / "public"
    private.mkdir(mode=0o700)
    public.mkdir(mode=0o755)
    algorithms = {"ed25519": "ED25519", "ml-dsa-65": "ML-DSA-65"}
    output = {"key_id": key_id, "algorithms": {}}
    for name, openssl_name in algorithms.items():
        temp = Path(tempfile.mkdtemp(prefix="tfws-keygen-"))
        try:
            raw_private = temp / "private.pem"
            _run(
                [
                    openssl,
                    "genpkey",
                    "-algorithm",
                    openssl_name,
                    "-out",
                    str(raw_private),
                ]
            )
            private_bytes = raw_private.read_bytes()
            public_bytes = _run(
                [openssl, "pkey", "-in", str(raw_private), "-pubout"]
            )
            private_path = private / f"{name}.pem"
            public_path = public / f"{name}.pem"
            _secure_write(private_path, private_bytes)
            public_path.write_bytes(public_bytes)
            public_path.chmod(0o644)
            output["algorithms"][name] = {
                "private": str(private_path),
                "public": str(public_path),
            }
        finally:
            shutil.rmtree(temp, ignore_errors=True)
    return output


def public_key_descriptors(
    public_key_dir: Path, *, key_id: str = "release-1"
) -> list[dict]:
    descriptors = []
    for algorithm in BASELINE:
        path = public_key_dir / f"{algorithm}.pem"
        if not path.is_file():
            raise CryptoError(f"missing public key: {path}")
        data = path.read_bytes()
        if b"PRIVATE KEY" in data:
            raise CryptoError(f"private key supplied as public key: {path}")
        descriptors.append(
            {
                "algorithm": algorithm,
                "key_id": key_id,
                "public_key_uri": f"/.well-known/keys/{algorithm}.pem",
                "public_key_sha256": hashlib.sha256(data).hexdigest(),
                "status": "active",
                "usage": ["release"],
            }
        )
    return descriptors


def bind_public_keys(
    manifest: dict, public_key_dir: Path, *, key_id: str = "release-1"
) -> dict:
    bound = dict(manifest)
    bound["keys"] = public_key_descriptors(public_key_dir, key_id=key_id)
    validate_manifest(bound, allow_unbound_development=False)
    return bound


def _validate_key_binding(
    manifest: dict, public_key_dir: Path, *, key_id: str | None = None
) -> dict[str, dict]:
    validate_manifest(manifest, allow_unbound_development=False)
    descriptors = {entry["algorithm"]: entry for entry in manifest["keys"]}
    for algorithm in BASELINE:
        descriptor = descriptors[algorithm]
        if key_id is not None and descriptor["key_id"] != key_id:
            raise CryptoError(f"manifest key_id mismatch for {algorithm}")
        path = public_key_dir / f"{algorithm}.pem"
        if not path.is_file():
            raise CryptoError(f"missing public key: {path}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != descriptor["public_key_sha256"]:
            raise CryptoError(f"public key hash mismatch for {algorithm}")
    return descriptors


def payload_hash(manifest: dict) -> tuple[bytes, str]:
    validate_manifest(manifest, allow_unbound_development=False)
    canonical = canonicalize(manifest)
    return canonical, hashlib.sha512(canonical).hexdigest()


def signature_message(
    *, subject: str, payload_sha512: str, created: str, key_epoch: int
) -> bytes:
    if any("\n" in item or "\r" in item for item in (subject, payload_sha512, created)):
        raise ValidationError("signature metadata contains newline")
    text = (
        "TFWS3-SIGNATURE-V1\n"
        f"subject={subject}\n"
        "media_type=application/tfws+json\n"
        f"payload_sha512={payload_sha512}\n"
        f"created={created}\n"
        f"key_epoch={key_epoch}\n"
        "policy=tfws.hybrid.baseline.v1\n"
    )
    return text.encode("utf-8")


def _sign_one(openssl: str, private_key: Path, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="tfws-sign-") as temp:
        msg = Path(temp) / "message.bin"
        signature = Path(temp) / "signature.bin"
        msg.write_bytes(message)
        _run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private_key),
                "-rawin",
                "-in",
                str(msg),
                "-out",
                str(signature),
            ]
        )
        return signature.read_bytes()


def _verify_one(
    openssl: str, public_key: Path, message: bytes, signature_bytes: bytes
) -> None:
    if not public_key.is_file():
        raise CryptoError(f"missing public key: {public_key}")
    with tempfile.TemporaryDirectory(prefix="tfws-verify-") as temp:
        msg = Path(temp) / "message.bin"
        signature = Path(temp) / "signature.bin"
        msg.write_bytes(message)
        signature.write_bytes(signature_bytes)
        _run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
                "-rawin",
                "-in",
                str(msg),
                "-sigfile",
                str(signature),
            ]
        )


def sign_manifest(
    manifest: dict,
    key_dir: Path,
    *,
    created: str | None = None,
    key_id: str = "release-1"
) -> dict:
    openssl = require_openssl()
    descriptors = _validate_key_binding(
        manifest, key_dir / "public", key_id=key_id
    )
    _, digest = payload_hash(manifest)
    created = created or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    message = signature_message(
        subject=manifest["subject"],
        payload_sha512=digest,
        created=created,
        key_epoch=manifest["key_epoch"],
    )
    signatures = []
    for algorithm in BASELINE:
        private = key_dir / "private" / f"{algorithm}.pem"
        if not private.is_file():
            raise CryptoError(f"missing private key: {private}")
        signature = _sign_one(openssl, private, message)
        signatures.append(
            {
                "algorithm": algorithm,
                "key_id": key_id,
                "public_key_uri": descriptors[algorithm]["public_key_uri"],
                "value": base64.b64encode(signature).decode("ascii"),
            }
        )
    return {
        "bundle_version": "1",
        "subject": manifest["subject"],
        "payload_sha512": digest,
        "created": created,
        "key_epoch": manifest["key_epoch"],
        "policy_id": "tfws.hybrid.baseline.v1",
        "signatures": signatures,
    }


def verify_bundle(manifest: dict, bundle: dict, public_key_dir: Path) -> dict:
    openssl = require_openssl()
    descriptors = _validate_key_binding(manifest, public_key_dir)
    if not isinstance(bundle, dict) or set(bundle) != {
        "bundle_version",
        "created",
        "key_epoch",
        "payload_sha512",
        "policy_id",
        "signatures",
        "subject",
    }:
        raise CryptoError("signature bundle has invalid fields")
    if bundle.get("bundle_version") != "1":
        raise CryptoError("unsupported signature bundle version")
    parse_rfc3339(bundle.get("created"))
    _, digest = payload_hash(manifest)
    if (
        bundle.get("payload_sha512") != digest
        or bundle.get("subject") != manifest["subject"]
        or bundle.get("key_epoch") != manifest["key_epoch"]
    ):
        raise CryptoError("bundle metadata does not match manifest")
    if bundle.get("policy_id") != "tfws.hybrid.baseline.v1":
        raise CryptoError("unapproved or downgraded signature policy")
    message = signature_message(
        subject=manifest["subject"],
        payload_sha512=digest,
        created=bundle["created"],
        key_epoch=manifest["key_epoch"],
    )
    seen: set[str] = set()
    results = []
    entries = bundle.get("signatures", [])
    if not isinstance(entries, list):
        raise CryptoError("signatures must be an array")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "algorithm", "key_id", "public_key_uri", "value"
        }:
            raise CryptoError("signature entry has invalid fields")
        algorithm = entry.get("algorithm")
        if algorithm in seen:
            raise CryptoError(f"duplicate signature algorithm: {algorithm}")
        if algorithm not in BASELINE:
            raise CryptoError(f"unsupported signature algorithm: {algorithm}")
        seen.add(algorithm)
        descriptor = descriptors[algorithm]
        if entry["key_id"] != descriptor["key_id"]:
            raise CryptoError(f"signature key_id mismatch for {algorithm}")
        if entry["public_key_uri"] != descriptor["public_key_uri"]:
            raise CryptoError(f"signature public key URI mismatch for {algorithm}")
        try:
            signature = base64.b64decode(entry["value"], validate=True)
        except Exception as exc:
            raise CryptoError(f"invalid base64 signature for {algorithm}") from exc
        _verify_one(openssl, public_key_dir / f"{algorithm}.pem", message, signature)
        results.append({"algorithm": algorithm, "valid": True})
    if seen != set(BASELINE):
        raise CryptoError(f"hybrid baseline incomplete; found {sorted(seen)}")
    return {
        "valid": True,
        "policy": "tfws.hybrid.baseline.v1",
        "payload_sha512": digest,
        "signatures": results,
    }
