"""Independent witness ledger adversarial tests."""

import base64
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import (
    CheckpointSignatureInvalid,
    CheckpointSigner,
    CheckpointVerifier,
)
from proofos.continuity import Phase, advance, open_operation
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import (
    InMemoryWitnessLedger,
    WitnessEquivocationError,
    WitnessGapError,
    WitnessIntegrityError,
    WitnessRollbackError,
    WitnessSignerDriftError,
)

OPERATION = "op_witness"
TASK = "TASK-W"
T0 = 1_800_100_000.0
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1", "verifier-v1": "v1"}


def checkpoints():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_witness", task_id=TASK)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    events = sink.list_execution(journal.execution_id)
    first = open_operation(
        OPERATION,
        journal.execution_id,
        TASK,
        REQS,
        ASSIGNED,
        events=events,
        now=T0,
    )
    second = advance(
        first,
        Phase.ACTION_COMPLETE,
        events=events,
        now=T0 + 1,
    )
    third = advance(
        second,
        Phase.AWAITING_INDEPENDENT_EVIDENCE,
        events=events,
        now=T0 + 2,
    )
    return first, second, third


class WitnessLedgerTests(unittest.TestCase):
    def setUp(self):
        self.first, self.second, self.third = checkpoints()
        self.signer = CheckpointSigner.generate("checkpoint-publisher-v1")
        self.verifier = CheckpointVerifier.from_b64(self.signer.public_key_b64())
        self.witness = InMemoryWitnessLedger("independent-witness-a")
        self.signed_first = self.signer.sign(self.first, issued_at=T0 + 1)
        self.signed_second = self.signer.sign(self.second, issued_at=T0 + 2)
        self.signed_third = self.signer.sign(self.third, issued_at=T0 + 3)

    def test_sequential_checkpoints_form_a_verifiable_witness_chain(self):
        first = self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        second = self.witness.observe(
            self.signed_second, self.second, self.verifier, observed_at=T0 + 3
        )

        self.assertEqual(first.checkpoint_version, 1)
        self.assertEqual(second.checkpoint_version, 2)
        self.assertEqual(second.previous_record_hash, first.record_hash)
        self.assertTrue(self.witness.verify(OPERATION)[0])

    def test_exact_replay_is_idempotent(self):
        first = self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        replay = self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 9
        )

        self.assertEqual(replay, first)
        self.assertEqual(len(self.witness.history(OPERATION)), 1)

    def test_rollback_is_rejected(self):
        self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        self.witness.observe(
            self.signed_second, self.second, self.verifier, observed_at=T0 + 3
        )

        with self.assertRaises(WitnessRollbackError):
            self.witness.observe(
                self.signed_first, self.first, self.verifier, observed_at=T0 + 4
            )

    def test_first_observation_cannot_start_at_version_two(self):
        with self.assertRaises(WitnessGapError):
            self.witness.observe(
                self.signed_second, self.second, self.verifier, observed_at=T0 + 3
            )

    def test_gap_after_first_version_is_rejected(self):
        self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        with self.assertRaises(WitnessGapError):
            self.witness.observe(
                self.signed_third, self.third, self.verifier, observed_at=T0 + 4
            )

    def test_same_version_different_checkpoint_is_equivocation(self):
        self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        conflicting = replace(self.first, task_id="OTHER-TASK")
        signed_conflict = self.signer.sign(conflicting, issued_at=T0 + 1)

        with self.assertRaises(WitnessEquivocationError):
            self.witness.observe(
                signed_conflict, conflicting, self.verifier, observed_at=T0 + 3
            )

    def test_signer_drift_is_rejected(self):
        self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        other = CheckpointSigner.generate("checkpoint-publisher-v2")
        other_verifier = CheckpointVerifier.from_b64(other.public_key_b64())
        signed_second = other.sign(self.second, issued_at=T0 + 2)

        with self.assertRaises(WitnessSignerDriftError):
            self.witness.observe(
                signed_second, self.second, other_verifier, observed_at=T0 + 3
            )

    def test_execution_drift_is_rejected(self):
        self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        changed = replace(self.second, execution_id="exec_other")
        signed_changed = self.signer.sign(changed, issued_at=T0 + 2)

        with self.assertRaises(WitnessEquivocationError):
            self.witness.observe(
                signed_changed, changed, self.verifier, observed_at=T0 + 3
            )

    def test_tampered_witness_record_is_detected(self):
        first = self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )
        self.witness._records[OPERATION][0] = replace(
            first, checkpoint_digest="f" * 64
        )

        ok, problems = self.witness.verify(OPERATION)
        self.assertFalse(ok)
        self.assertTrue(any("content hash" in problem for problem in problems))

    def test_observation_cannot_predate_signature(self):
        with self.assertRaises(WitnessIntegrityError):
            self.witness.observe(
                self.signed_first, self.first, self.verifier, observed_at=T0
            )

    def test_non_finite_observation_time_is_rejected(self):
        with self.assertRaises(WitnessIntegrityError):
            self.witness.observe(
                self.signed_first,
                self.first,
                self.verifier,
                observed_at=float("nan"),
            )

    def test_forged_checkpoint_signature_is_rejected_without_append(self):
        raw = bytearray(base64.b64decode(self.signed_first.signature))
        raw[-1] ^= 1
        forged = replace(
            self.signed_first,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )

        with self.assertRaises(CheckpointSignatureInvalid):
            self.witness.observe(forged, self.first, self.verifier, observed_at=T0 + 2)
        self.assertEqual(self.witness.history(OPERATION), ())

    def test_witness_record_carries_no_verdict_or_evidence_authority(self):
        fields = set(self.witness.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        ).__dataclass_fields__)
        for forbidden in (
            "verdict",
            "decision",
            "status",
            "evidence",
            "capabilities",
            "tools",
        ):
            self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()
