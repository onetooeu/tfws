from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from .canonical import load_json
from .crypto import bind_public_keys, generate_keyset, sign_manifest, verify_bundle
from .errors import TFWSError
from .eventlog import append_event, merkle_root, read_events, verify_chain
from .models import validate_manifest


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def new_manifest(domain: str, operator: str, environment: str) -> dict:
    parsed = urlparse(domain if "://" in domain else "https://" + domain)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("invalid HTTPS domain")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "tfws_version": "3.0",
        "subject": f"https://{parsed.hostname}",
        "environment": environment,
        "operator": {"name": operator},
        "key_epoch": 1,
        "keys": [],
        "signature_policy": {
            "policy_id": "tfws.hybrid.baseline.v1",
            "required_algorithms": ["ed25519", "ml-dsa-65"],
        },
        "capabilities": {
            "required": [
                "core.v1",
                "identity.v1",
                "transparency.v1",
                "recovery.v1",
            ],
            "optional": [],
        },
        "artifacts": [],
        "updated_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90))
        .isoformat()
        .replace("+00:00", "Z"),
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="tfws", description="TFWS 3.0 fail-closed bootstrap CLI"
    )
    sub = root.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen")
    keygen.add_argument("--out", type=Path, required=True)
    keygen.add_argument("--key-id", default="release-1")

    init = sub.add_parser("init")
    init.add_argument("--domain", required=True)
    init.add_argument("--operator", required=True)
    init.add_argument(
        "--environment",
        choices=["development", "staging", "production"],
        default="development",
    )
    init.add_argument("--out", type=Path, required=True)

    bind = sub.add_parser("bind-keys")
    bind.add_argument("--manifest", type=Path, required=True)
    bind.add_argument("--public-keys", type=Path, required=True)
    bind.add_argument("--out", type=Path, required=True)
    bind.add_argument("--key-id", default="release-1")

    sign = sub.add_parser("sign")
    sign.add_argument("--manifest", type=Path, required=True)
    sign.add_argument("--keys", type=Path, required=True)
    sign.add_argument("--out", type=Path, required=True)
    sign.add_argument("--key-id", default="release-1")

    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--public-keys", type=Path, required=True)
    verify.add_argument("--production", action="store_true")

    event = sub.add_parser("event-append")
    event.add_argument("--log", type=Path, required=True)
    event.add_argument("--type", required=True)
    event.add_argument("--subject", required=True)
    event.add_argument("--payload", default="{}")

    checklog = sub.add_parser("event-verify")
    checklog.add_argument("--log", type=Path, required=True)
    return root


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "keygen":
            print(json.dumps(generate_keyset(args.out, key_id=args.key_id), indent=2))
            return 0
        if args.command == "init":
            manifest = new_manifest(args.domain, args.operator, args.environment)
            validate_manifest(manifest)
            write_json(args.out, manifest)
            return 0
        if args.command == "bind-keys":
            write_json(
                args.out,
                bind_public_keys(
                    load_json(args.manifest),
                    args.public_keys,
                    key_id=args.key_id,
                ),
            )
            return 0
        if args.command == "sign":
            write_json(
                args.out,
                sign_manifest(load_json(args.manifest), args.keys, key_id=args.key_id),
            )
            return 0
        if args.command == "verify":
            manifest = load_json(args.manifest)
            validate_manifest(manifest, allow_nonproduction=not args.production)
            print(
                json.dumps(
                    verify_bundle(
                        manifest, load_json(args.bundle), args.public_keys
                    ),
                    indent=2,
                )
            )
            return 0
        if args.command == "event-append":
            print(
                json.dumps(
                    append_event(
                        args.log,
                        event_type=args.type,
                        subject=args.subject,
                        payload=json.loads(args.payload),
                    ),
                    indent=2,
                )
            )
            return 0
        if args.command == "event-verify":
            events = read_events(args.log)
            verify_chain(events)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "events": len(events),
                        "merkle_root": merkle_root(events),
                    },
                    indent=2,
                )
            )
            return 0
    except (TFWSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
