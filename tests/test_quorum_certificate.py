"""Signed quorum certificate adversarial tests."""

import base64
import math
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import open_operation
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.quorum_certificate import (
    MalformedQuorumCertificate,
    QuorumCertificate,
    QuorumCertificateBindingError,
    QuorumCertificateSignatureInvalid,
    QuorumCertificateSigner,
    QuorumCertificateVerifier,
)
from proofos.verifier import Requirement
from proofos.witness import InMemoryWitnessLedger
from proofos.witness_quorum import (
    WitnessQuorumPolicy,
    WitnessVote,
    evaluate_witness_quorum,
)
from proofos.witness_receipt import (
    WitnessReceiptSigner,
    WitnessReceiptVerifier,
)

T0 = 1_800_500_000.0
OP = "op_certificate"
TASK = "TASK-CERT"
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1"}


def quorum_result():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_certificate", task_id=TASK)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    checkpoint = open_operation(
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
    envelope = checkpoint_signer.sign(checkpoint, issued_at=T0 + 1)

    votes = []
    verifiers = {}
    policy_entries = []
    for offset, witness_id in enumerate(
        ("witness-a", "witness-b", "witness-c"),
        start=2,
    ):
        record = InMemoryWitnessLedger(witness_id).observe(
            envelope,
            checkpoint,
            checkpoint_verifier,
            observed_at=T0 + offset,
        )
        signer = WitnessReceiptSigner.generate(witness_id)
        receipt = signer.sign(record, issued_at=T0 + offset + 1)
        verifier = WitnessReceiptVerifier.from_b64(
            signer.public_key_b64(),
            witness_id,
        )
        verifiers[witness_id] = verifier
        policy_entries.append((witness_id, verifier.public_key_b64()))
        votes.append(WitnessVote(receipt, record))

    policy = WitnessQuorumPolicy(
        "certificate-policy-v1",
        tuple(policy_entries),
        2,
    )
    result = evaluate_witness_quorum(
        votes[:2],
        verifiers=verifiers,
        policy=policy,
        expected_policy_digest=policy.digest(),
    )
    insufficient = evaluate_witness_quorum(
        votes[:1],
        verifiers=verifiers,
        policy=policy,
        expected_policy_digest=policy.digest(),
    )
    return result, insufficient


class QuorumCertificateTests(unittest.TestCase):
    def setUp(self):
        self.result, self.insufficient = quorum_result()
        self.signer = QuorumCertificateSigner.generate("quorum-aggregator-v1")
        self.verifier = QuorumCertificateVerifier.from_b64(
            self.signer.public_key_b64(),
            "quorum-aggregator-v1",
        )
        self.certificate = self.signer.sign(self.result, issued_at=T0 + 10)

    def test_round_trip_verifies_against_recomputed_quorum(self):
        parsed = QuorumCertificate.from_dict(self.certificate.to_dict())
        self.verifier.verify(parsed, self.result)
        self.assertEqual(parsed.checkpoint_digest, self.result.checkpoint_digest)

    def test_non_quorum_result_cannot_be_certified(self):
        with self.assertRaises(QuorumCertificateBindingError):
            self.signer.sign(self.insufficient, issued_at=T0 + 10)

    def test_materialized_unsupported_version_is_rejected(self):
        future = replace(self.certificate, version="proofos.quorum-certificate.v2")
        with self.assertRaises(QuorumCertificateBindingError):
            self.verifier.verify(future, self.result)

    def test_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.certificate.signature))
        raw[0] ^= 1
        forged = replace(
            self.certificate,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(QuorumCertificateSignatureInvalid):
            self.verifier.verify(forged, self.result)

    def test_policy_digest_drift_is_rejected(self):
        changed = replace(self.result, policy_digest="f" * 64)
        with self.assertRaises(QuorumCertificateBindingError):
            self.verifier.verify(self.certificate, changed)

    def test_checkpoint_digest_drift_is_rejected(self):
        changed = replace(self.result, checkpoint_digest="e" * 64)
        with self.assertRaises(QuorumCertificateBindingError):
            self.verifier.verify(self.certificate, changed)

    def test_counted_witness_drift_is_rejected(self):
        changed = replace(self.result, counted_witnesses=("witness-a",))
        with self.assertRaises(QuorumCertificateBindingError):
            self.verifier.verify(self.certificate, changed)

    def test_unknown_field_is_rejected(self):
        raw = self.certificate.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedQuorumCertificate):
            QuorumCertificate.from_dict(raw)

    def test_unsorted_or_duplicate_witnesses_are_rejected(self):
        raw = self.certificate.to_dict()
        raw["counted_witnesses"] = ["witness-b", "witness-a", "witness-a"]
        with self.assertRaises(MalformedQuorumCertificate):
            QuorumCertificate.from_dict(raw)

    def test_non_finite_issued_at_is_rejected(self):
        with self.assertRaises(ValueError):
            self.signer.sign(self.result, issued_at=math.nan)

    def test_certificate_carries_no_verdict_or_evidence_authority(self):
        fields = set(QuorumCertificate.__dataclass_fields__)
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
