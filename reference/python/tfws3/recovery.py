from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from .errors import PolicyError, ValidationError
from .models import parse_rfc3339


@dataclass(frozen=True)
class GuardianApproval:
    guardian_id: str
    ed25519_valid: bool
    ml_dsa_65_valid: bool


@dataclass(frozen=True)
class RecoveryRequest:
    subject: str
    old_epoch: int
    new_epoch: int
    reason: str
    created_at: str
    execute_after: str


def evaluate_recovery(
    request: RecoveryRequest,
    approvals: list[GuardianApproval],
    *,
    allowed_guardians: set[str],
    threshold: int,
    now: datetime | None = None,
) -> dict:
    if request.new_epoch <= request.old_epoch:
        raise ValidationError("recovery must increase key epoch")
    if not request.reason.strip():
        raise ValidationError("recovery reason is required")
    created = parse_rfc3339(request.created_at)
    execute_after = parse_rfc3339(request.execute_after)
    if execute_after <= created:
        raise ValidationError("recovery time lock must be positive")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    approved = {
        approval.guardian_id
        for approval in approvals
        if approval.guardian_id in allowed_guardians
        and approval.ed25519_valid
        and approval.ml_dsa_65_valid
    }
    if threshold < 1 or threshold > len(allowed_guardians):
        raise PolicyError("invalid guardian threshold")
    if len(approved) < threshold:
        raise PolicyError(f"guardian threshold not met: {len(approved)}/{threshold}")
    return {
        "authorized": now >= execute_after,
        "time_lock_satisfied": now >= execute_after,
        "approvals": sorted(approved),
        "threshold": threshold,
    }
