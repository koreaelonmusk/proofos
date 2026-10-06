"""Signed checkpoint contract tests."""

import base64
import unittest
from dataclasses import replace

from proofos.checkpoint_attestation import (
    CHECKPOINT_SIGNATURE_VERSION,
    CheckpointBindingError,
    CheckpointSignatureInvalid,
    CheckpointSigner,
    CheckpointVerifier,
    MalformedCheckpointAttestation,
    SignedCheckpoint,
    digest_checkpoint,
)
from proofos.continuity import Phase, advance, open_operation
from proofos.journal import InMemoryJournalSink, Journal, EventType
from proofos.verifier import Requirement

OPERATION = "op_signed_checkpoint"
TASK = "TASK-1"
ASSIGNED = {"executor-v1": "v1", "verifier-v1": "v1"}
REQS = (Requirement("tests"), Requirement("runtime", 300))
T0 = 1_800_000_000.0


def checkpoint():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_signed_checkpoint", task_id=TASK)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    events = sink.list_execution(journal.execution_id)
    return advance(
        open_operation(
            OPERATION,
            journal.execution_id,
            TASK,
            REQS,
            ASSIGNED,
            events=events,
            now=T0,
        ),
        Phase.AWAITING_INDEPENDENT_EVIDENCE,
        events=events,
        now=T0 + 1,
    )


class SignedCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.checkpoint = checkpoint()
        self.signer = CheckpointSigner.generate("checkpoint-publisher-v1")
        self.verifier = CheckpointVerifier.from_b64(self.signer.public_key_b64())
        self.signed = self.signer.sign(self.checkpoint, issued_at=T0 + 2)

    def test_round_trip_verifies(self):
        parsed = SignedCheckpoint.from_dict(self.signed.to_dict())
        self.verifier.verify(parsed, self.checkpoint)
        self.assertEqual(parsed.version, CHECKPOINT_SIGNATURE_VERSION)
        self.assertEqual(parsed.checkpoint_digest, digest_checkpoint(self.checkpoint))

    def test_checkpoint_content_drift_is_rejected(self):
        changed = replace(self.checkpoint, task_id="OTHER")
        with self.assertRaises(CheckpointBindingError):
            self.verifier.verify(self.signed, changed)

    def test_journal_head_drift_is_rejected(self):
        changed = replace(self.checkpoint, last_journal_hash="f" * 64)
        with self.assertRaises(CheckpointBindingError):
            self.verifier.verify(self.signed, changed)

    def test_checkpoint_version_drift_is_rejected(self):
        changed = replace(
            self.checkpoint,
            checkpoint_version=self.checkpoint.checkpoint_version + 1,
        )
        with self.assertRaises(CheckpointBindingError):
            self.verifier.verify(self.signed, changed)

    def test_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.signed.signature))
        raw[0] ^= 1
        forged = replace(
            self.signed,
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(CheckpointSignatureInvalid):
            self.verifier.verify(forged, self.checkpoint)

    def test_signed_field_tampering_is_rejected(self):
        forged = replace(self.signed, signer_id="attacker")
        with self.assertRaises(CheckpointSignatureInvalid):
            self.verifier.verify(forged, self.checkpoint)

    def test_unknown_envelope_field_is_rejected(self):
        raw = self.signed.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedCheckpointAttestation):
            SignedCheckpoint.from_dict(raw)

    def test_missing_envelope_field_is_rejected(self):
        raw = self.signed.to_dict()
        del raw["checkpoint_digest"]
        with self.assertRaises(MalformedCheckpointAttestation):
            SignedCheckpoint.from_dict(raw)

    def test_invalid_journal_hash_shape_is_rejected(self):
        raw = self.signed.to_dict()
        raw["last_journal_hash"] = "not-a-sha256"
        with self.assertRaises(MalformedCheckpointAttestation):
            SignedCheckpoint.from_dict(raw)

    def test_signature_cannot_predate_checkpoint(self):
        with self.assertRaises(ValueError):
            self.signer.sign(self.checkpoint, issued_at=self.checkpoint.updated_at - 1)

    def test_envelope_carries_no_verdict_or_evidence(self):
        fields = set(SignedCheckpoint.__dataclass_fields__)
        for forbidden in ("verdict", "decision", "status", "evidence", "capabilities"):
            self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()
