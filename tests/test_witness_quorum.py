"""Pinned witness quorum adversarial tests."""

import base64
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import open_operation
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import InMemoryWitnessLedger
from proofos.witness_quorum import (
    WitnessQuorumPolicy,
    WitnessQuorumPolicyError,
    WitnessQuorumScopeError,
    WitnessQuorumState,
    WitnessVote,
    evaluate_witness_quorum,
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


def checkpoint(task_id=TASK, operation_id=OP, execution_id="exec_quorum"):
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id=execution_id, task_id=task_id)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    return open_operation(
        operation_id,
        journal.execution_id,
        task_id,
        REQS,
        ASSIGNED,
        events=sink.list_execution(journal.execution_id),
        now=T0,
    )


def fixture(names=("witness-a", "witness-b", "witness-c")):
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
            envelope, cp, checkpoint_verifier, observed_at=T0 + offset
        )
        signer = WitnessReceiptSigner.generate(name)
        receipt = signer.sign(record, issued_at=T0 + offset + 1)
        votes[name] = WitnessVote(receipt, record)
        verifiers[name] = WitnessReceiptVerifier.from_b64(
            signer.public_key_b64(), name
        )
        signers[name] = signer

    policy = WitnessQuorumPolicy("witness-policy-v1", tuple(names), 2)
    return cp, votes, verifiers, signers, policy


class WitnessQuorumTests(unittest.TestCase):
    def setUp(self):
        (
            self.cp,
            self.votes,
            self.verifiers,
            self.signers,
            self.policy,
        ) = fixture()
        self.pin = self.policy.digest()

    def evaluate(self, votes, **kwargs):
        return evaluate_witness_quorum(
            votes,
            verifiers=kwargs.get("verifiers", self.verifiers),
            policy=kwargs.get("policy", self.policy),
            expected_policy_digest=kwargs.get("pin", self.pin),
        )

    def test_two_of_three_reaches_quorum(self):
        result = self.evaluate(
            [self.votes["witness-a"], self.votes["witness-b"]]
        )
        self.assertEqual(result.state, WitnessQuorumState.QUORUM)
        self.assertEqual(result.count, 2)
        self.assertTrue(result.quorum_met)

    def test_one_of_three_is_insufficient(self):
        result = self.evaluate([self.votes["witness-a"]])
        self.assertEqual(result.state, WitnessQuorumState.INSUFFICIENT)
        self.assertFalse(result.quorum_met)

    def test_empty_vote_set_is_non_authorizing(self):
        result = self.evaluate([])
        self.assertEqual(result.state, WitnessQuorumState.INSUFFICIENT)
        self.assertEqual(result.count, 0)

    def test_duplicate_witness_does_not_count_twice(self):
        vote = self.votes["witness-a"]
        result = self.evaluate([vote, vote])
        self.assertEqual(result.count, 1)
        self.assertEqual(result.state, WitnessQuorumState.INSUFFICIENT)

    def test_multiple_valid_receipts_from_one_witness_count_once(self):
        vote = self.votes["witness-a"]
        later = self.signers["witness-a"].sign(
            vote.record, issued_at=vote.receipt.issued_at + 10
        )
        result = self.evaluate([vote, WitnessVote(later, vote.record)])
        self.assertEqual(result.counted_witnesses, ("witness-a",))

    def test_unconfigured_witness_is_rejected(self):
        unknown_signer = WitnessReceiptSigner.generate("witness-x")
        record = replace(
            self.votes["witness-a"].record,
            witness_id="witness-x",
            record_hash="",
        )
        record = replace(record, record_hash=record.compute_hash())
        receipt = unknown_signer.sign(record, issued_at=T0 + 10)

        with self.assertRaises(WitnessQuorumPolicyError):
            self.evaluate([WitnessVote(receipt, record)])

    def test_missing_verifier_is_rejected(self):
        verifiers = dict(self.verifiers)
        del verifiers["witness-a"]
        with self.assertRaises(WitnessQuorumPolicyError):
            self.evaluate([self.votes["witness-a"]], verifiers=verifiers)

    def test_two_witness_labels_cannot_share_one_public_key(self):
        verifiers = dict(self.verifiers)
        verifiers["witness-b"] = WitnessReceiptVerifier.from_b64(
            self.signers["witness-a"].public_key_b64(),
            "witness-b",
        )
        with self.assertRaisesRegex(WitnessQuorumPolicyError, "share one Ed25519 public key"):
            self.evaluate([], verifiers=verifiers)

    def test_forged_receipt_is_rejected(self):
        vote = self.votes["witness-a"]
        raw = bytearray(base64.b64decode(vote.receipt.signature))
        raw[0] ^= 1
        forged = replace(
            vote.receipt,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(WitnessReceiptSignatureInvalid):
            self.evaluate([WitnessVote(forged, vote.record)])

    def test_cross_witness_conflict_is_split_view(self):
        changed = replace(
            self.votes["witness-b"].record,
            checkpoint_digest="f" * 64,
            record_hash="",
        )
        changed = replace(changed, record_hash=changed.compute_hash())
        receipt = self.signers["witness-b"].sign(changed, issued_at=T0 + 10)
        result = self.evaluate(
            [self.votes["witness-a"], WitnessVote(receipt, changed)]
        )
        self.assertEqual(result.state, WitnessQuorumState.SPLIT_VIEW)
        self.assertGreaterEqual(len(result.conflicting_commitment_hashes), 2)

    def test_same_witness_conflicting_commitment_is_split_view(self):
        vote = self.votes["witness-a"]
        changed = replace(
            vote.record,
            checkpoint_digest="e" * 64,
            record_hash="",
        )
        changed = replace(changed, record_hash=changed.compute_hash())
        receipt = self.signers["witness-a"].sign(changed, issued_at=T0 + 10)
        result = self.evaluate([vote, WitnessVote(receipt, changed)])
        self.assertEqual(result.state, WitnessQuorumState.SPLIT_VIEW)

    def test_different_scope_is_rejected_not_counted(self):
        vote = self.votes["witness-b"]
        changed = replace(
            vote.record,
            operation_id="other-operation",
            record_hash="",
        )
        changed = replace(changed, record_hash=changed.compute_hash())
        receipt = self.signers["witness-b"].sign(changed, issued_at=T0 + 10)
        with self.assertRaises(WitnessQuorumScopeError):
            self.evaluate([self.votes["witness-a"], WitnessVote(receipt, changed)])

    def test_policy_digest_must_match_external_pin(self):
        with self.assertRaises(WitnessQuorumPolicyError):
            self.evaluate([self.votes["witness-a"]], pin="0" * 64)

    def test_policy_threshold_cannot_be_invalid(self):
        with self.assertRaises(WitnessQuorumPolicyError):
            WitnessQuorumPolicy("bad", ("witness-a",), 2)
        with self.assertRaises(WitnessQuorumPolicyError):
            WitnessQuorumPolicy("bad", ("witness-a",), True)

    def test_quorum_result_carries_no_verdict_or_capability_authority(self):
        result = self.evaluate(
            [self.votes["witness-a"], self.votes["witness-b"]]
        )
        fields = set(result.__dataclass_fields__)
        for forbidden in (
            "verdict",
            "decision",
            "verified",
            "evidence",
            "capabilities",
            "tools",
        ):
            self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()
