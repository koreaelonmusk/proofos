"""Proof-carrying witness gossip bundle adversarial tests."""

import base64
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import open_operation
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import InMemoryWitnessLedger
from proofos.witness_gossip import (
    MalformedWitnessGossip,
    WitnessGossipBindingError,
    WitnessGossipBundle,
    WitnessGossipSignatureInvalid,
    WitnessGossipSigner,
    WitnessGossipVerifier,
)
from proofos.witness_quorum import (
    WitnessQuorumPolicy,
    WitnessQuorumResult,
    WitnessQuorumState,
    WitnessVote,
    evaluate_witness_quorum,
)
from proofos.witness_receipt import WitnessReceiptSigner, WitnessReceiptVerifier

T0 = 1_800_500_000.0
OP = "op_gossip"
TASK = "TASK-G"
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1"}


def fixture():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_gossip", task_id=TASK)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    cp = open_operation(
        OP,
        journal.execution_id,
        TASK,
        REQS,
        ASSIGNED,
        events=sink.list_execution(journal.execution_id),
        now=T0,
    )
    checkpoint_signer = CheckpointSigner.generate("checkpoint-publisher-v1")
    checkpoint_verifier = CheckpointVerifier.from_b64(
        checkpoint_signer.public_key_b64()
    )
    envelope = checkpoint_signer.sign(cp, issued_at=T0 + 1)

    votes = []
    verifiers = {}
    witness_signers = {}
    witnesses = []
    for offset, witness_id in enumerate(
        ("witness-a", "witness-b", "witness-c"), start=2
    ):
        record = InMemoryWitnessLedger(witness_id).observe(
            envelope,
            cp,
            checkpoint_verifier,
            observed_at=T0 + offset,
        )
        signer = WitnessReceiptSigner.generate(witness_id)
        receipt = signer.sign(record, issued_at=T0 + offset + 1)
        votes.append(WitnessVote(receipt, record))
        verifiers[witness_id] = WitnessReceiptVerifier.from_b64(
            signer.public_key_b64(),
            witness_id,
        )
        witness_signers[witness_id] = signer
        witnesses.append((witness_id, signer.public_key_b64()))

    policy = WitnessQuorumPolicy("gossip-policy-v1", tuple(witnesses), 2)
    result = evaluate_witness_quorum(
        votes[:2],
        verifiers=verifiers,
        policy=policy,
        expected_policy_digest=policy.digest(),
    )
    return cp, tuple(votes), verifiers, witness_signers, policy, result


class WitnessGossipTests(unittest.TestCase):
    def setUp(self):
        (
            self.cp,
            self.votes,
            self.verifiers,
            self.witness_signers,
            self.policy,
            self.result,
        ) = fixture()
        self.signer = WitnessGossipSigner.generate("gossip-publisher-v1")
        self.verifier = WitnessGossipVerifier.from_b64(
            self.signer.public_key_b64(),
            "gossip-publisher-v1",
        )
        self.bundle = self.signer.sign(
            policy=self.policy,
            result=self.result,
            votes=self.votes[:2],
            issued_at=T0 + 10,
        )

    def test_round_trip_recomputes_quorum_independently(self):
        parsed = WitnessGossipBundle.from_dict(self.bundle.to_dict())
        result = self.verifier.verify(
            parsed,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(result.state, WitnessQuorumState.QUORUM)
        self.assertEqual(result.counted_witnesses, ("witness-a", "witness-b"))

    def test_outer_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.bundle.signature))
        raw[0] ^= 1
        forged = replace(
            self.bundle,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(WitnessGossipSignatureInvalid):
            self.verifier.verify(
                forged,
                expected_policy_digest=self.policy.digest(),
            )

    def test_publisher_cannot_sign_a_false_quorum_claim_into_truth(self):
        false_result = replace(
            self.result,
            state=WitnessQuorumState.INSUFFICIENT,
        )
        lying_bundle = self.signer.sign(
            policy=self.policy,
            result=false_result,
            votes=self.votes[:2],
            issued_at=T0 + 10,
        )
        with self.assertRaises(WitnessGossipBindingError):
            self.verifier.verify(
                lying_bundle,
                expected_policy_digest=self.policy.digest(),
            )

    def test_inner_witness_tampering_fails_even_when_outer_bundle_is_resigned(self):
        vote = self.votes[0]
        changed_record = replace(
            vote.record,
            checkpoint_digest="f" * 64,
            record_hash="",
        )
        changed_record = replace(
            changed_record,
            record_hash=changed_record.compute_hash(),
        )
        tampered_votes = (WitnessVote(vote.receipt, changed_record), self.votes[1])
        resigned = self.signer.sign(
            policy=self.policy,
            result=self.result,
            votes=tampered_votes,
            issued_at=T0 + 10,
        )
        with self.assertRaises(ValueError):
            self.verifier.verify(
                resigned,
                expected_policy_digest=self.policy.digest(),
            )

    def test_policy_substitution_fails_external_pin(self):
        changed_policy = WitnessQuorumPolicy(
            "gossip-policy-v1",
            self.policy.witnesses,
            1,
        )
        resigned = self.signer.sign(
            policy=changed_policy,
            result=self.result,
            votes=self.votes[:2],
            issued_at=T0 + 10,
        )
        with self.assertRaises(ValueError):
            self.verifier.verify(
                resigned,
                expected_policy_digest=self.policy.digest(),
            )

    def test_strict_parser_rejects_authority_injection_field(self):
        raw = self.bundle.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedWitnessGossip):
            WitnessGossipBundle.from_dict(raw)

    def test_split_view_survives_transport_and_recomputation(self):
        second = self.votes[1]
        changed_record = replace(
            second.record,
            checkpoint_digest="e" * 64,
            record_hash="",
        )
        changed_record = replace(
            changed_record,
            record_hash=changed_record.compute_hash(),
        )
        changed_receipt = self.witness_signers["witness-b"].sign(
            changed_record,
            issued_at=T0 + 20,
        )
        split_votes = (self.votes[0], WitnessVote(changed_receipt, changed_record))
        split_result = evaluate_witness_quorum(
            split_votes,
            verifiers=self.verifiers,
            policy=self.policy,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(split_result.state, WitnessQuorumState.SPLIT_VIEW)

        bundle = self.signer.sign(
            policy=self.policy,
            result=split_result,
            votes=split_votes,
            issued_at=T0 + 21,
        )
        verified = self.verifier.verify(
            bundle,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(verified.state, WitnessQuorumState.SPLIT_VIEW)
        self.assertFalse(verified.quorum_met)

    def test_bundle_carries_no_completion_or_capability_authority(self):
        fields = set(WitnessGossipBundle.__dataclass_fields__)
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
