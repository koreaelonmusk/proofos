"""Transactional Firestore witness ledger adversarial tests."""

import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import Phase, advance, open_operation
from proofos.firestore_witness import (
    FirestoreWitnessLedger,
    WitnessUnavailableError,
)
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import (
    WitnessEquivocationError,
    WitnessGapError,
    WitnessIntegrityError,
    WitnessRollbackError,
)
from tests.fake_firestore import FakeFirestore, fake_transactional


OPERATION = "op_firestore_witness"
TASK = "TASK-FW"
T0 = 1_800_200_000.0
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1", "verifier-v1": "v1"}


def checkpoints():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_firestore_witness", task_id=TASK)
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


class FirestoreWitnessLedgerTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeFirestore()
        self.first, self.second, self.third = checkpoints()
        self.signer = CheckpointSigner.generate("checkpoint-publisher-v1")
        self.verifier = CheckpointVerifier.from_b64(self.signer.public_key_b64())
        self.signed_first = self.signer.sign(self.first, issued_at=T0 + 1)
        self.signed_second = self.signer.sign(self.second, issued_at=T0 + 2)
        self.signed_third = self.signer.sign(self.third, issued_at=T0 + 3)
        self.ledger = self._ledger()

    def _ledger(self, witness_id="independent-witness-firestore"):
        return FirestoreWitnessLedger(
            self.client,
            witness_id,
            transactional=fake_transactional,
        )

    def observe_first(self, ledger=None):
        ledger = ledger or self.ledger
        return ledger.observe(
            self.signed_first,
            self.first,
            self.verifier,
            observed_at=T0 + 2,
        )

    def test_records_survive_fresh_ledger_instance(self):
        first = self.observe_first()
        restarted = self._ledger()

        history = restarted.history(OPERATION)

        self.assertEqual(history, (first,))
        self.assertEqual(restarted.verify(OPERATION), (True, ()))

    def test_sequential_records_form_durable_hash_chain(self):
        first = self.observe_first()
        second = self.ledger.observe(
            self.signed_second,
            self.second,
            self.verifier,
            observed_at=T0 + 3,
        )

        self.assertEqual(second.previous_record_hash, first.record_hash)
        self.assertEqual(
            [record.checkpoint_version for record in self.ledger.history(OPERATION)],
            [1, 2],
        )
        self.assertEqual(self.ledger.verify(OPERATION), (True, ()))

    def test_exact_replay_after_restart_is_idempotent(self):
        first = self.observe_first()
        restarted = self._ledger()

        replay = restarted.observe(
            self.signed_first,
            self.first,
            self.verifier,
            observed_at=T0 + 9,
        )

        self.assertEqual(replay, first)
        self.assertEqual(len(restarted.history(OPERATION)), 1)

    def test_first_observation_cannot_skip_version_one(self):
        with self.assertRaises(WitnessGapError):
            self.ledger.observe(
                self.signed_second,
                self.second,
                self.verifier,
                observed_at=T0 + 3,
            )

    def test_gap_after_persisted_version_is_rejected(self):
        self.observe_first()

        with self.assertRaises(WitnessGapError):
            self._ledger().observe(
                self.signed_third,
                self.third,
                self.verifier,
                observed_at=T0 + 4,
            )

    def test_rollback_after_restart_is_rejected(self):
        self.observe_first()
        self.ledger.observe(
            self.signed_second,
            self.second,
            self.verifier,
            observed_at=T0 + 3,
        )

        with self.assertRaises(WitnessRollbackError):
            self._ledger().observe(
                self.signed_first,
                self.first,
                self.verifier,
                observed_at=T0 + 4,
            )

    def test_same_version_conflict_after_restart_is_equivocation(self):
        self.observe_first()
        conflicting = replace(self.first, task_id="OTHER-TASK")
        signed_conflict = self.signer.sign(conflicting, issued_at=T0 + 1)

        with self.assertRaises(WitnessEquivocationError):
            self._ledger().observe(
                signed_conflict,
                conflicting,
                self.verifier,
                observed_at=T0 + 3,
            )

    def test_tampered_head_is_detected(self):
        self.observe_first()
        head_path = f"witness_operations/{OPERATION}"
        self.client.docs[head_path]["head_record_hash"] = "f" * 64

        ok, problems = self.ledger.verify(OPERATION)

        self.assertFalse(ok)
        self.assertTrue(any("head hash" in problem for problem in problems))

    def test_missing_record_behind_head_fails_closed(self):
        self.observe_first()
        record_path = (
            f"witness_operations/{OPERATION}/records/"
            "000000000001"
        )
        del self.client.docs[record_path]

        with self.assertRaises(WitnessIntegrityError):
            self._ledger().observe(
                self.signed_second,
                self.second,
                self.verifier,
                observed_at=T0 + 3,
            )

    def test_witness_identity_drift_is_rejected_on_read(self):
        self.observe_first()

        with self.assertRaises(WitnessIntegrityError):
            self._ledger("different-witness").history(OPERATION)

    def test_storage_read_failure_is_not_treated_as_empty_history(self):
        self.client.stream_error = self.client.unavailable()

        with self.assertRaises(WitnessUnavailableError):
            self.ledger.history(OPERATION)

    def test_concurrent_exact_first_write_resolves_as_idempotent_replay(self):
        competing = self._ledger()

        def write_same_checkpoint():
            competing.observe(
                self.signed_first,
                self.first,
                self.verifier,
                observed_at=T0 + 2,
            )

        self.client.before_commit = write_same_checkpoint
        result = self.observe_first()

        self.assertEqual(result.checkpoint_digest, self.signed_first.checkpoint_digest)
        self.assertEqual(len(self._ledger().history(OPERATION)), 1)

    def test_concurrent_conflicting_first_write_is_equivocation(self):
        competing = self._ledger()
        conflicting = replace(self.first, task_id="OTHER-TASK")
        signed_conflict = self.signer.sign(conflicting, issued_at=T0 + 1)

        def write_conflict():
            competing.observe(
                signed_conflict,
                conflicting,
                self.verifier,
                observed_at=T0 + 2,
            )

        self.client.before_commit = write_conflict

        with self.assertRaises(WitnessEquivocationError):
            self.observe_first()
        self.assertEqual(len(self._ledger().history(OPERATION)), 1)


if __name__ == "__main__":
    unittest.main()
