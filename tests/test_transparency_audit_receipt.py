"""Signed transparency audit receipt adversarial tests."""

import base64
import math
import unittest
from dataclasses import replace

from proofos.quorum_certificate import (
    QuorumCertificateSigner,
    QuorumCertificateVerifier,
)
from proofos.transparency_audit_receipt import (
    TRANSPARENCY_AUDIT_RECEIPT_VERSION,
    MalformedTransparencyAuditReceipt,
    TransparencyAuditReceipt,
    TransparencyAuditReceiptBindingError,
    TransparencyAuditReceiptSignatureInvalid,
    TransparencyAuditReceiptSigner,
    TransparencyAuditReceiptVerifier,
)
from proofos.transparency_gate import TransparencyState, evaluate_transparency
from proofos.witness_gossip import WitnessGossipSigner, WitnessGossipVerifier
from proofos.witness_quorum import WitnessVote, evaluate_witness_quorum
from tests.test_witness_gossip import T0, fixture


class TransparencyAuditReceiptTests(unittest.TestCase):
    def setUp(self):
        (
            self.checkpoint,
            self.votes,
            self.verifiers,
            self.witness_signers,
            self.policy,
            self.quorum,
        ) = fixture()

        self.gossip_signer = WitnessGossipSigner.generate("gossip-publisher-v1")
        self.bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=self.quorum,
            votes=self.votes[:2],
            issued_at=T0 + 50,
        )
        gossip_verifier = WitnessGossipVerifier.from_b64(
            self.gossip_signer.public_key_b64(),
            "gossip-publisher-v1",
        )

        self.certificate_signer = QuorumCertificateSigner.generate(
            "quorum-aggregator-v1"
        )
        self.certificate = self.certificate_signer.sign(
            self.quorum,
            issued_at=T0 + 51,
        )
        certificate_verifier = QuorumCertificateVerifier.from_b64(
            self.certificate_signer.public_key_b64(),
            "quorum-aggregator-v1",
        )

        self.result = evaluate_transparency(
            self.bundle,
            gossip_verifier=gossip_verifier,
            expected_policy_digest=self.policy.digest(),
            certificate=self.certificate,
            certificate_verifier=certificate_verifier,
        )

        self.signer = TransparencyAuditReceiptSigner.generate("external-auditor-v1")
        self.verifier = TransparencyAuditReceiptVerifier.from_b64(
            self.signer.public_key_b64(),
            "external-auditor-v1",
        )
        self.receipt = self.signer.sign(
            self.result,
            self.bundle,
            self.certificate,
            issued_at=T0 + 52,
        )

    def test_round_trip_verifies_against_recomputed_audit(self):
        parsed = TransparencyAuditReceipt.from_dict(self.receipt.to_dict())
        self.verifier.verify(
            parsed,
            self.result,
            self.bundle,
            self.certificate,
        )
        self.assertEqual(parsed.version, TRANSPARENCY_AUDIT_RECEIPT_VERSION)

    def test_split_view_receipt_round_trips_with_empty_digest_sentinel(self):
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
            issued_at=T0 + 60,
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
        split_bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=split,
            votes=split_votes,
            issued_at=T0 + 61,
        )
        gossip_verifier = WitnessGossipVerifier.from_b64(
            self.gossip_signer.public_key_b64(),
            "gossip-publisher-v1",
        )
        split_result = evaluate_transparency(
            split_bundle,
            gossip_verifier=gossip_verifier,
            expected_policy_digest=self.policy.digest(),
        )
        self.assertEqual(split_result.state, TransparencyState.REJECTED_SPLIT_VIEW)
        receipt = self.signer.sign(
            split_result,
            split_bundle,
            None,
            issued_at=T0 + 62,
        )
        parsed = TransparencyAuditReceipt.from_dict(receipt.to_dict())
        self.assertEqual(parsed.checkpoint_digest, "")
        self.verifier.verify(parsed, split_result, split_bundle, None)

    def test_accepted_result_cannot_be_signed_without_certificate_artifact(self):
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            self.signer.sign(
                self.result,
                self.bundle,
                None,
                issued_at=T0 + 52,
            )

    def test_accepted_receipt_cannot_be_verified_without_certificate_artifact(self):
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            self.verifier.verify(
                self.receipt,
                self.result,
                self.bundle,
                None,
            )

    def test_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.receipt.signature))
        raw[0] ^= 1
        forged = replace(
            self.receipt,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(TransparencyAuditReceiptSignatureInvalid):
            self.verifier.verify(
                forged,
                self.result,
                self.bundle,
                self.certificate,
            )

    def test_recomputed_result_drift_is_rejected(self):
        changed = replace(self.result, checkpoint_digest="f" * 64)
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            self.verifier.verify(
                self.receipt,
                changed,
                self.bundle,
                self.certificate,
            )

    def test_gossip_artifact_drift_is_rejected(self):
        changed = replace(self.bundle, checkpoint_digest="e" * 64)
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            self.verifier.verify(
                self.receipt,
                self.result,
                changed,
                self.certificate,
            )

    def test_certificate_artifact_drift_is_rejected(self):
        changed = replace(self.certificate, checkpoint_digest="d" * 64)
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            self.verifier.verify(
                self.receipt,
                self.result,
                self.bundle,
                changed,
            )

    def test_materialized_unsupported_version_is_rejected(self):
        future = replace(
            self.receipt,
            version="proofos.transparency-audit-receipt.v2",
        )
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            self.verifier.verify(
                future,
                self.result,
                self.bundle,
                self.certificate,
            )

    def test_unknown_authority_field_is_rejected(self):
        raw = self.receipt.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedTransparencyAuditReceipt):
            TransparencyAuditReceipt.from_dict(raw)

    def test_non_finite_issued_at_is_rejected(self):
        with self.assertRaises(ValueError):
            self.signer.sign(
                self.result,
                self.bundle,
                self.certificate,
                issued_at=math.nan,
            )

    def test_auditor_identity_substitution_is_rejected(self):
        verifier = TransparencyAuditReceiptVerifier.from_b64(
            self.signer.public_key_b64(),
            "different-auditor",
        )
        with self.assertRaises(TransparencyAuditReceiptBindingError):
            verifier.verify(
                self.receipt,
                self.result,
                self.bundle,
                self.certificate,
            )

    def test_receipt_carries_no_completion_or_execution_authority(self):
        fields = set(TransparencyAuditReceipt.__dataclass_fields__)
        for forbidden in (
            "verdict",
            "decision",
            "verified",
            "evidence",
            "capabilities",
            "tools",
            "execution_authority",
        ):
            self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()
