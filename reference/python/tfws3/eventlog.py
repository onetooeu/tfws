from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .canonical import canonicalize
from .errors import ValidationError


def hash_event(event: dict) -> str:
    return hashlib.sha256(canonicalize(event)).hexdigest()


def details_commitment(details: bytes) -> str:
    return hashlib.sha256(details).hexdigest()


def append_event(
    path: Path,
    *,
    event_type: str,
    subject: str,
    payload: dict,
    private_details: bytes = b"",
) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    events = read_events(path) if path.exists() else []
    verify_chain(events)
    previous = hash_event(events[-1]) if events else None
    event = {
        "event_id": str(uuid.uuid4()),
        "sequence": len(events),
        "event_type": event_type,
        "subject": subject,
        "occurred_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "previous_event_hash": previous,
        "details_commitment": details_commitment(private_details),
        "payload": payload,
    }
    line = canonicalize(event) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return event


def read_events(path: Path) -> list[dict]:
    events = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValidationError(f"invalid event JSON at line {number}") from exc
    return events


def verify_chain(events: list[dict]) -> None:
    previous = None
    for index, event in enumerate(events):
        if event.get("sequence") != index:
            raise ValidationError(f"invalid event sequence at {index}")
        if event.get("previous_event_hash") != previous:
            raise ValidationError(f"broken event chain at {index}")
        previous = hash_event(event)


def merkle_root(events: list[dict]) -> str:
    leaves = [bytes.fromhex(hash_event(event)) for event in events]
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    layer = leaves
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [
            hashlib.sha256(
                b"TFWS3-MERKLE-NODE\x00" + layer[i] + layer[i + 1]
            ).digest()
            for i in range(0, len(layer), 2)
        ]
    return layer[0].hex()
