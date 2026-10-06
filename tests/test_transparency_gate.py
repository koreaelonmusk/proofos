"""Transparency acceptance gate integration tests."""

import unittest
from dataclasses import replace

from proofos.quorum_certificate import (
    QuorumCertificateBindingError,
    QuorumCertificateSigner,
    QuorumCertificateVerifier,
)
from proofos.transparency_gate import (
    TransparencyGateError,
    TransparencyResult,
    TransparencyState,
    evaluate_transparency,
)
from proofos.witness import WitnessRecord
from proofos.witness_gossip import WitnessGossipSigner, WitnessGossipVerifier
from proofos.witness_quorum import (
    WitnessQuorumState,
    WitnessVote,
    evaluate_witness_quorum,
)
from tests.test_witness_gossip import T0, fixture


class TransparencyAcceptanceTests(unittest.TestCase):
    def setUp(self):
        (
            self.cp,
            self.votes,
            self.verifiers,
            self.witness_signers,
            self.policy,
            self.quorum,
        ) = fixture()
        self.gossip_signer = WitnessGossipSigner.generate("gossip-publisher-v1")
        self.gossip_verifier = WitnessGossipVerifier.from_b64(
            self.gossip_signer.public_key_b64(),
            "gossip-publisher-v1",
        )
        self.quorum_bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=self.quorum,
            votes=self.votes[:2],
            issued_at=T0 + 30,
        )
        self.cert_signer = QuorumCertificateSigner.generate("quorum-aggregator-v1")
        self.cert_verifier = QuorumCertificateVerifier.from_b64(
            self.cert_signer.public_key_b64(),
            "quorum-aggregator-v1",
        )
        self.certificate = self.cert_signer.sign(self.quorum, issued_at=T0 + 31)

    def test_valid_gossip_and_certificate_are_accepted(self):
        result = evaluate_transparency(
            self.quorum_bundle,
            gossip_verifier=self.gossip_verifier,
            expected_policy_digest=self.policy.digest(),
            certificate=self.certificate,
            certificate_verifier=self.cert_verifier,
        )
        self.assertEqual(result.state, TransparencyState.ACCEPTED)
        self.assertTrue(result.accepted)
        self.assertEqual(result.counted_witnesses, ("witness-a", "witness-b"))

    def test_quorum_without_certificate_holds(self):
        result = evaluate_transparency(
            self.quorum_bundle,
            gossip_verifier=self.gossip_verifier,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(result.state, TransparencyState.HOLD_CERTIFICATE_REQUIRED)
        self.assertFalse(result.accepted)

    def test_insufficient_gossip_holds_without_certificate(self):
        insufficient = evaluate_witness_quorum(
            self.votes[:1],
            verifiers=self.verifiers,
            policy=self.policy,
            expected_policy_digest=self.policy.digest(),
        )
        bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=insufficient,
            votes=self.votes[:1],
            issued_at=T0 + 30,
        )
        result = evaluate_transparency(
            bundle,
            gossip_verifier=self.gossip_verifier,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(result.state, TransparencyState.HOLD_INSUFFICIENT)

    def test_split_view_is_explicitly_rejected(self):
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
            issued_at=T0 + 40,
        )
        split_votes = (
            self.votes[0],
            WitnessVote(changed_receipt, changed_record),
        )
        split = evaluate_witness_quorum(
            split_votes,
            verifiers=self.verifiers,
            policy=self.policy,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(split.state, WitnessQuorumState.SPLIT_VIEW)
        bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=split,
            votes=split_votes,
            issued_at=T0 + 41,
        )

        result = evaluate_transparency(
            bundle,
            gossip_verifier=self.gossip_verifier,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(result.state, TransparencyState.REJECTED_SPLIT_VIEW)

    def test_certificate_bound_to_other_quorum_is_rejected(self):
        changed = replace(self.quorum, checkpoint_digest="f" * 64)
        with self.assertRaises(QuorumCertificateBindingError):
            evaluate_transparency(
                self.quorum_bundle,
                gossip_verifier=self.gossip_verifier,
                expected_policy_digest=self.policy.digest(),
                certificate=self.cert_signer.sign(changed, issued_at=T0 + 31),
                certificate_verifier=self.cert_verifier,
            )

    def test_non_quorum_evidence_cannot_smuggle_certificate(self):
        insufficient = evaluate_witness_quorum(
            self.votes[:1],
            verifiers=self.verifiers,
            policy=self.policy,
            expected_policy_digest=self.policy.digest(),
        )
        bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=insufficient,
            votes=self.votes[:1],
            issued_at=T0 + 30,
        )
        with self.assertRaises(TransparencyGateError):
            evaluate_transparency(
                bundle,
                gossip_verifier=self.gossip_verifier,
                expected_policy_digest=self.policy.digest(),
                certificate=self.certificate,
                certificate_verifier=self.cert_verifier,
            )

    def test_gate_result_carries_no_completion_authority(self):
        fields = set(TransparencyResult.__dataclass_fields__)
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
