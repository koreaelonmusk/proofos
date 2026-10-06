"""Signed witness receipt contract tests."""

import base64
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import open_operation
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import InMemoryWitnessLedger
from proofos.witness_receipt import (
    MalformedWitnessReceipt,
    WitnessReceipt,
    WitnessReceiptBindingError,
    WitnessReceiptSignatureInvalid,
    WitnessReceiptSigner,
    WitnessReceiptVerifier,
)

T0 = 1_800_300_000.0
OP = "op_receipt"
TASK = "TASK-R"
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1"}


def witnessed():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_receipt", task_id=TASK)
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
    record = InMemoryWitnessLedger("witness-a").observe(
        envelope,
        checkpoint,
        checkpoint_verifier,
        observed_at=T0 + 2,
    )
    return record


class WitnessReceiptTests(unittest.TestCase):
    def setUp(self):
        self.record = witnessed()
        self.signer = WitnessReceiptSigner.generate("witness-a")
        self.verifier = WitnessReceiptVerifier.from_b64(
            self.signer.public_key_b64(),
            "witness-a",
        )
        self.receipt = self.signer.sign(self.record, issued_at=T0 + 3)

    def test_round_trip_verifies(self):
        parsed = WitnessReceipt.from_dict(self.receipt.to_dict())
        self.verifier.verify(parsed, self.record)
        self.assertEqual(parsed.witness_record_hash, self.record.record_hash)

    def test_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.receipt.signature))
        raw[0] ^= 1
        forged = replace(
            self.receipt,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(WitnessReceiptSignatureInvalid):
            self.verifier.verify(forged, self.record)

    def test_witness_id_tampering_is_rejected(self):
        forged = replace(self.receipt, witness_id="witness-b")
        with self.assertRaises(WitnessReceiptBindingError):
            self.verifier.verify(forged, self.record)

    def test_record_binding_drift_is_rejected(self):
        changed = replace(self.record, checkpoint_digest="f" * 64)
        changed = replace(changed, record_hash=changed.compute_hash())
        with self.assertRaises(WitnessReceiptBindingError):
            self.verifier.verify(self.receipt, changed)

    def test_signer_cannot_sign_another_witness_record(self):
        other = replace(self.record, witness_id="witness-b")
        other = replace(other, record_hash=other.compute_hash())
        with self.assertRaises(WitnessReceiptBindingError):
            self.signer.sign(other, issued_at=T0 + 3)

    def test_receipt_cannot_predate_observation(self):
        with self.assertRaises(ValueError):
            self.signer.sign(
                self.record,
                issued_at=self.record.observed_at - 1,
            )

    def test_non_finite_record_observation_time_is_rejected(self):
        malformed = replace(self.record, observed_at=float("nan"), record_hash="")
        malformed = replace(malformed, record_hash=malformed.compute_hash())

        with self.assertRaises(WitnessReceiptBindingError):
            self.signer.sign(malformed, issued_at=T0 + 3)
        with self.assertRaises(WitnessReceiptBindingError):
            self.verifier.verify(self.receipt, malformed)

    def test_unknown_field_is_rejected(self):
        raw = self.receipt.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedWitnessReceipt):
            WitnessReceipt.from_dict(raw)

    def test_missing_field_is_rejected(self):
        raw = self.receipt.to_dict()
        del raw["witness_record_hash"]
        with self.assertRaises(MalformedWitnessReceipt):
            WitnessReceipt.from_dict(raw)

    def test_invalid_digest_shape_is_rejected(self):
        raw = self.receipt.to_dict()
        raw["checkpoint_digest"] = "bad"
        with self.assertRaises(MalformedWitnessReceipt):
            WitnessReceipt.from_dict(raw)

    def test_receipt_has_no_verdict_or_capability_authority(self):
        fields = set(WitnessReceipt.__dataclass_fields__)
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
