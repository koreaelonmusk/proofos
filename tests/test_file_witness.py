"""Durable filesystem witness ledger tests."""

import json
import math
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from proofos.checkpoint_attestation import CheckpointSigner, CheckpointVerifier
from proofos.continuity import Phase, advance, open_operation
from proofos.file_witness import FileWitnessLedger
from proofos.journal import EventType, InMemoryJournalSink, Journal
from proofos.verifier import Requirement
from proofos.witness import (
    WitnessEquivocationError,
    WitnessGapError,
    WitnessIntegrityError,
    WitnessRollbackError,
)

OP = "op/file/../witness"
TASK = "TASK-FILE"
T0 = 1_800_200_000.0
REQS = (Requirement("tests"),)
ASSIGNED = {"executor-v1": "v1"}


def fixture():
    sink = InMemoryJournalSink()
    journal = Journal(sink, execution_id="exec_file_witness", task_id=TASK)
    journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
    events = sink.list_execution(journal.execution_id)
    first = open_operation(OP, journal.execution_id, TASK, REQS, ASSIGNED, events, T0)
    second = advance(first, Phase.ACTION_COMPLETE, events, now=T0 + 1)
    third = advance(second, Phase.AWAITING_INDEPENDENT_EVIDENCE, events, now=T0 + 2)
    signer = CheckpointSigner.generate("checkpoint-publisher-v1")
    verifier = CheckpointVerifier.from_b64(signer.public_key_b64())
    return (
        first,
        second,
        third,
        signer,
        verifier,
        signer.sign(first, T0 + 1),
        signer.sign(second, T0 + 2),
        signer.sign(third, T0 + 3),
    )


class FileWitnessLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "witness"
        (
            self.first,
            self.second,
            self.third,
            self.signer,
            self.verifier,
            self.signed_first,
            self.signed_second,
            self.signed_third,
        ) = fixture()
        self.ledger = FileWitnessLedger(self.root, "witness-a")

    def observe_first(self):
        return self.ledger.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 2
        )

    def test_history_survives_a_fresh_ledger_instance(self):
        first = self.observe_first()
        self.ledger.observe(
            self.signed_second, self.second, self.verifier, observed_at=T0 + 3
        )

        reopened = FileWitnessLedger(self.root, "witness-a")
        history = reopened.history(OP)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0], first)
        self.assertTrue(reopened.verify(OP)[0])

    def test_exact_replay_is_idempotent_on_disk(self):
        first = self.observe_first()
        replay = self.ledger.observe(
            self.signed_first, self.first, self.verifier, observed_at=T0 + 9
        )

        self.assertEqual(replay, first)
        self.assertEqual(len(self.ledger.history(OP)), 1)

    def test_rollback_is_rejected_after_restart(self):
        self.observe_first()
        self.ledger.observe(
            self.signed_second, self.second, self.verifier, observed_at=T0 + 3
        )
        reopened = FileWitnessLedger(self.root, "witness-a")

        with self.assertRaises(WitnessRollbackError):
            reopened.observe(
                self.signed_first, self.first, self.verifier, observed_at=T0 + 4
            )

    def test_gap_is_rejected_after_restart(self):
        self.observe_first()
        reopened = FileWitnessLedger(self.root, "witness-a")

        with self.assertRaises(WitnessGapError):
            reopened.observe(
                self.signed_third, self.third, self.verifier, observed_at=T0 + 4
            )

    def test_same_version_conflict_is_rejected(self):
        self.observe_first()
        changed = replace(self.first, task_id="OTHER")
        signed_changed = self.signer.sign(changed, issued_at=T0 + 1)

        with self.assertRaises(WitnessEquivocationError):
            self.ledger.observe(
                signed_changed, changed, self.verifier, observed_at=T0 + 3
            )

    def test_tampered_durable_record_is_rejected_on_read(self):
        self.observe_first()
        record_path = next(self.ledger._operation_dir(OP).glob("*.json"))
        raw = json.loads(record_path.read_text(encoding="utf-8"))
        raw["checkpoint_digest"] = "f" * 64
        record_path.write_text(json.dumps(raw), encoding="utf-8")

        with self.assertRaises(WitnessIntegrityError):
            FileWitnessLedger(self.root, "witness-a").history(OP)

    def test_unexpected_storage_entry_is_rejected(self):
        self.observe_first()
        directory = self.ledger._operation_dir(OP)
        (directory / "notes.txt").write_text("not a witness record", encoding="utf-8")

        with self.assertRaises(WitnessIntegrityError):
            self.ledger.history(OP)

    def test_operation_id_never_becomes_a_path_component(self):
        self.observe_first()
        directory = self.ledger._operation_dir(OP)

        self.assertEqual(directory.parent, self.root)
        self.assertNotIn("..", directory.name)
        self.assertNotIn("/", directory.name)
        self.assertEqual(len(directory.name), 64)

    def test_symlink_record_is_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        self.observe_first()
        directory = self.ledger._operation_dir(OP)
        target = directory / "000000000001.json"
        link = directory / "000000000002.json"
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")

        with self.assertRaises(WitnessIntegrityError):
            self.ledger.history(OP)

    def test_non_finite_observation_time_is_rejected(self):
        with self.assertRaises(WitnessIntegrityError):
            self.ledger.observe(
                self.signed_first,
                self.first,
                self.verifier,
                observed_at=math.nan,
            )

    def test_created_record_is_owner_only_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX mode bits unavailable")
        self.observe_first()
        path = next(self.ledger._operation_dir(OP).glob("*.json"))
        mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
