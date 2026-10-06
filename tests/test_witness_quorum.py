"""N-of-M witness quorum adversarial tests."""

import base64
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import open_operation
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import InMemoryWitnessLedger
from proofos.witness_quorum import (
    InvalidQuorumPolicy,
    UnknownWitnessError,
    WitnessQuorumNotMet,
    WitnessReceiptConflictError,
    WitnessVote,
    evaluate_witness_quorum,
    require_witness_quorum,
)
from proofos.witness_receipt import (
    WitnessReceiptSignatureInvalid,
    WitnessReceiptSigner,
    WitnessReceiptVerifier,
)

T0 = 1_800_400_000.0
OP = "op_quorum"
TASK = "TASK-Q"
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1"}


def checkpoint(task_id=TASK):
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_quorum", task_id=task_id)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    return open_operation(
        OP,
        journal.execution_id,
        task_id,
        REQS,
        ASSIGNED,
        events=sink.list_execution(journal.execution_id),
        now=T0,
    )


def votes_for(names=("witness-a", "witness-b", "witness-c")):
    cp = checkpoint()
    checkpoint_signer = CheckpointSigner.generate("checkpoint-publisher-v1")
    checkpoint_verifier = CheckpointVerifier.from_b64(
        checkpoint_signer.public_key_b64()
    )
    envelope = checkpoint_signer.sign(cp, issued_at=T0 + 1)

    votes = {}
    verifiers = {}
    signers = {}
    for offset, name in enumerate(names, start=2):
        record = InMemoryWitnessLedger(name).observe(
            envelope,
            cp,
            checkpoint_verifier,
            observed_at=T0 + offset,
        )
        signer = WitnessReceiptSigner.generate(name)
        receipt = signer.sign(record, issued_at=T0 + offset + 1)
        votes[name] = WitnessVote(receipt=receipt, record=record)
        verifiers[name] = WitnessReceiptVerifier.from_b64(
            signer.public_key_b64(),
            name,
        )
        signers[name] = signer
    return cp, votes, verifiers, signers


class WitnessQuorumTests(unittest.TestCase):
    def setUp(self):
        self.cp, self.votes, self.verifiers, self.signers = votes_for()

    def test_two_of_three_distinct_witnesses_reach_quorum(self):
        result = evaluate_witness_quorum(
            [self.votes["witness-a"], self.votes["witness-b"]],
            self.verifiers,
            required=2,
        )
        self.assertTrue(result.quorum_met)
        self.assertEqual(result.count, 2)
        self.assertEqual(
            result.counted_witnesses,
            ("witness-a", "witness-b"),
        )
        self.assertEqual(result.checkpoint_digest, self.votes["witness-a"].receipt.checkpoint_digest)

    def test_duplicate_witness_does_not_count_twice(self):
        vote = self.votes["witness-a"]
        result = evaluate_witness_quorum(
            [vote, vote],
            self.verifiers,
            required=2,
        )
        self.assertFalse(result.quorum_met)
        self.assertEqual(result.count, 1)

    def test_multiple_valid_receipts_from_one_witness_still_count_once(self):
        vote = self.votes["witness-a"]
        later_receipt = self.signers["witness-a"].sign(
            vote.record,
            issued_at=vote.receipt.issued_at + 10,
        )
        result = evaluate_witness_quorum(
            [vote, WitnessVote(later_receipt, vote.record)],
            self.verifiers,
            required=2,
        )
        self.assertFalse(result.quorum_met)
        self.assertEqual(result.counted_witnesses, ("witness-a",))

    def test_require_quorum_raises_when_threshold_is_unmet(self):
        with self.assertRaises(WitnessQuorumNotMet):
            require_witness_quorum(
                [self.votes["witness-a"]],
                self.verifiers,
                required=2,
            )

    def test_unknown_witness_is_rejected_not_ignored(self):
        unknown_signer = WitnessReceiptSigner.generate("witness-x")
        record = replace(self.votes["witness-a"].record, witness_id="witness-x", record_hash="")
        record = replace(record, record_hash=record.compute_hash())
        receipt = unknown_signer.sign(record, issued_at=T0 + 10)

        with self.assertRaises(UnknownWitnessError):
            evaluate_witness_quorum(
                [WitnessVote(receipt, record)],
                self.verifiers,
                required=2,
            )

    def test_forged_receipt_is_rejected(self):
        vote = self.votes["witness-a"]
        raw = bytearray(base64.b64decode(vote.receipt.signature))
        raw[0] ^= 1
        forged = replace(
            vote.receipt,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(WitnessReceiptSignatureInvalid):
            evaluate_witness_quorum(
                [WitnessVote(forged, vote.record)],
                self.verifiers,
                required=1,
            )

    def test_conflicting_checkpoint_commitments_fail_closed(self):
        conflicting_cp = checkpoint(task_id="OTHER-TASK")
        checkpoint_signer = CheckpointSigner.generate("checkpoint-publisher-v1")
        checkpoint_verifier = CheckpointVerifier.from_b64(
            checkpoint_signer.public_key_b64()
        )
        envelope = checkpoint_signer.sign(conflicting_cp, issued_at=T0 + 1)
        record = InMemoryWitnessLedger("witness-b").observe(
            envelope,
            conflicting_cp,
            checkpoint_verifier,
            observed_at=T0 + 3,
        )
        signer = self.signers["witness-b"]
        conflicting_receipt = signer.sign(record, issued_at=T0 + 4)

        with self.assertRaises(WitnessReceiptConflictError):
            evaluate_witness_quorum(
                [
                    self.votes["witness-a"],
                    WitnessVote(conflicting_receipt, record),
                ],
                self.verifiers,
                required=2,
            )

    def test_required_quorum_cannot_exceed_registered_witnesses(self):
        with self.assertRaises(InvalidQuorumPolicy):
            evaluate_witness_quorum([], self.verifiers, required=4)

    def test_required_quorum_must_be_positive(self):
        with self.assertRaises(InvalidQuorumPolicy):
            evaluate_witness_quorum([], self.verifiers, required=0)

    def test_boolean_is_not_a_valid_quorum_threshold(self):
        with self.assertRaises(InvalidQuorumPolicy):
            evaluate_witness_quorum([], self.verifiers, required=True)

    def test_empty_vote_set_is_non_authorizing(self):
        result = evaluate_witness_quorum([], self.verifiers, required=2)
        self.assertFalse(result.quorum_met)
        self.assertEqual(result.count, 0)
        fields = set(result.__dataclass_fields__)
        for forbidden in ("verdict", "decision", "verified", "evidence"):
            self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()
