import unittest
from datetime import datetime, timezone

from tfws3.errors import PolicyError
from tfws3.recovery import GuardianApproval, RecoveryRequest, evaluate_recovery
from tfws3.transparency import (
    Checkpoint,
    WitnessStatement,
    detect_incompatible_checkpoints,
    verify_witness_quorum,
)


class TransparencyRecoveryTests(unittest.TestCase):
    def test_witness_quorum(self):
        checkpoint = Checkpoint("log-1", 10, "a" * 64, "2026-07-21T00:00:00Z")
        statements = [
            WitnessStatement("w1", checkpoint, True),
            WitnessStatement("w2", checkpoint, True),
            WitnessStatement("w3", checkpoint, True),
        ]
        result = verify_witness_quorum(
            checkpoint,
            statements,
            minimum=3,
            allowed_witnesses={"w1", "w2", "w3", "w4", "w5"},
        )
        self.assertTrue(result["valid"])

    def test_split_view_rejected(self):
        checkpoint = Checkpoint("log-1", 10, "a" * 64, "2026-07-21T00:00:00Z")
        conflicting = Checkpoint("log-1", 10, "b" * 64, "2026-07-21T00:00:00Z")
        self.assertTrue(detect_incompatible_checkpoints(checkpoint, conflicting))
        with self.assertRaises(PolicyError):
            verify_witness_quorum(
                checkpoint,
                [WitnessStatement("w1", conflicting, True)],
                minimum=1,
                allowed_witnesses={"w1"},
            )

    def test_recovery_threshold_and_timelock(self):
        request = RecoveryRequest(
            subject="https://example.com",
            old_epoch=1,
            new_epoch=2,
            reason="lost operational key",
            created_at="2026-07-21T00:00:00Z",
            execute_after="2026-07-22T00:00:00Z",
        )
        approvals = [
            GuardianApproval("g1", True, True),
            GuardianApproval("g2", True, True),
            GuardianApproval("g3", True, True),
        ]
        early = evaluate_recovery(
            request,
            approvals,
            allowed_guardians={"g1", "g2", "g3", "g4", "g5"},
            threshold=3,
            now=datetime(2026, 7, 21, 12, tzinfo=timezone.utc),
        )
        self.assertFalse(early["authorized"])
        late = evaluate_recovery(
            request,
            approvals,
            allowed_guardians={"g1", "g2", "g3", "g4", "g5"},
            threshold=3,
            now=datetime(2026, 7, 22, 1, tzinfo=timezone.utc),
        )
        self.assertTrue(late["authorized"])

    def test_recovery_requires_hybrid_approval(self):
        request = RecoveryRequest(
            "https://example.com", 1, 2, "incident", "2026-07-21T00:00:00Z", "2026-07-22T00:00:00Z"
        )
        with self.assertRaises(PolicyError):
            evaluate_recovery(
                request,
                [GuardianApproval("g1", True, False)],
                allowed_guardians={"g1"},
                threshold=1,
                now=datetime(2026, 7, 23, tzinfo=timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
