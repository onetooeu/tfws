from __future__ import annotations

from dataclasses import dataclass
from .errors import PolicyError, ValidationError


@dataclass(frozen=True)
class Checkpoint:
    log_id: str
    tree_size: int
    root_hash: str
    timestamp: str

    def validate(self) -> None:
        if not self.log_id or self.tree_size < 0:
            raise ValidationError("invalid checkpoint identity or size")
        if len(self.root_hash) != 64 or any(c not in "0123456789abcdef" for c in self.root_hash):
            raise ValidationError("invalid checkpoint root hash")


@dataclass(frozen=True)
class WitnessStatement:
    witness_id: str
    checkpoint: Checkpoint
    valid_signature: bool


def verify_witness_quorum(
    checkpoint: Checkpoint,
    statements: list[WitnessStatement],
    *,
    minimum: int,
    allowed_witnesses: set[str],
) -> dict:
    checkpoint.validate()
    if minimum < 1 or minimum > len(allowed_witnesses):
        raise PolicyError("invalid witness quorum policy")
    accepted: set[str] = set()
    conflicts: list[str] = []
    for statement in statements:
        if statement.witness_id not in allowed_witnesses or not statement.valid_signature:
            continue
        candidate = statement.checkpoint
        candidate.validate()
        if (
            candidate.log_id != checkpoint.log_id
            or candidate.tree_size != checkpoint.tree_size
            or candidate.root_hash != checkpoint.root_hash
        ):
            conflicts.append(statement.witness_id)
            continue
        accepted.add(statement.witness_id)
    if conflicts:
        raise PolicyError(f"split-view evidence from witnesses: {sorted(conflicts)}")
    if len(accepted) < minimum:
        raise PolicyError(f"witness quorum not met: {len(accepted)}/{minimum}")
    return {"valid": True, "witnesses": sorted(accepted), "quorum": minimum}


def detect_incompatible_checkpoints(left: Checkpoint, right: Checkpoint) -> bool:
    left.validate()
    right.validate()
    return (
        left.log_id == right.log_id
        and left.tree_size == right.tree_size
        and left.root_hash != right.root_hash
    )
