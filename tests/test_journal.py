"""Execution journal tests.

The journal exists to answer "why was this task marked VERIFIED?" without
trusting any agent's account of it. These tests run the real recovery loop
against the real verifier and then reconstruct the decision from the journal
alone.
"""

import asyncio
import functools
import io
import json
import unittest
from dataclasses import replace

from proofos.journal import (
    EventType,
    InMemoryJournalSink,
    Journal,
    Severity,
    StreamJournalSink,
    new_execution_id,
    redacted,
    summarize,
    verify_chain,
)
from proofos_agent import scenario
from proofos_agent.agent import LEDGER, verify_task_completion
from proofos_agent.recovery import Turn, run_verification_loop
from tests.test_probe import closed_port_url, send_json, serving


def run(coro):
    return asyncio.run(coro)


async def compliant_turn(attempt: int) -> Turn:
    turn = Turn(attempt=attempt)
    args = {"task_id": scenario.TASK_ID, "claim": scenario.WORKER_CLAIM}
    turn.tool_calls.append({"name": "verify_task_completion", "args": args})
    result = verify_task_completion(**args)
    turn.tool_results.append(result)
    turn.final_text = result["status"]
    return turn


async def self_certifying_turn(attempt: int) -> Turn:
    return Turn(attempt=attempt, final_text="Task completed successfully.")


class JournalRecordingTests(unittest.TestCase):
    def setUp(self):
        LEDGER.reset()
        scenario.seed_incomplete_evidence(LEDGER)
        self.sink = InMemoryJournalSink()
        self.journal = Journal(self.sink, task_id=scenario.TASK_ID)
        self._server = serving(lambda h: send_json(h, 200, {"status": "ok"}))
        self.health_url = self._server.__enter__()
        self.addCleanup(self._server.__exit__, None, None, None)
        self.collectors = {
            "runtime": functools.partial(
                scenario.collect_runtime_evidence, LEDGER, self.health_url, 5
            )
        }

    def test_full_execution_is_reconstructable_from_the_journal(self):
        outcome = run(
            run_verification_loop(
                compliant_turn, self.collectors, 2, journal=self.journal
            )
        )
        self.assertEqual(outcome["final_status"], "VERIFIED")
        self.assertEqual(outcome["execution_id"], self.journal.execution_id)

        types = [e.event for e in self.journal.events()]
        self.assertEqual(types[0], EventType.EXECUTION_START)
        self.assertEqual(types[-1], EventType.EXECUTION_COMPLETE)
        self.assertIn(EventType.RECOVERY_START, types)
        self.assertIn(EventType.EVIDENCE_COLLECTED, types)

        summary = summarize(self.journal.events())
        self.assertEqual(summary["final_status"], "VERIFIED")
        self.assertTrue(summary["chain_intact"])
        # The journal shows it was refused first, then accepted.
        self.assertEqual(
            [d["status"] for d in summary["decisions"]], ["ABSTAIN", "VERIFIED"]
        )
        self.assertEqual(summary["decisions"][0]["missing"], ["runtime"])
        self.assertEqual(summary["decisions"][0]["failure"], "EVIDENCE_UNTRUSTED")

    def test_every_event_carries_correlation_ids(self):
        run(
            run_verification_loop(
                compliant_turn, self.collectors, 2, journal=self.journal
            )
        )
        for event in self.journal.events():
            self.assertEqual(event.execution_id, self.journal.execution_id)
            self.assertEqual(event.trace_id, self.journal.trace_id)
            self.assertEqual(event.task_id, scenario.TASK_ID)
            self.assertTrue(event.agent)

    def test_model_noncompliance_is_recorded_and_fails_closed(self):
        outcome = run(
            run_verification_loop(
                self_certifying_turn, self.collectors, 2, journal=self.journal
            )
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(outcome["failure_class"], "MODEL_NONCOMPLIANCE")

        summary = summarize(self.journal.events())
        self.assertEqual(summary["final_status"], "ABSTAIN")
        self.assertEqual(summary["decisions"][0]["failure"], "MODEL_NONCOMPLIANCE")

    def test_failed_collection_is_recorded_as_rejected(self):
        collectors = {
            "runtime": functools.partial(
                scenario.collect_runtime_evidence, LEDGER, closed_port_url(), 2
            )
        }
        outcome = run(
            run_verification_loop(compliant_turn, collectors, 2, journal=self.journal)
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        types = [e.event for e in self.journal.events()]
        self.assertIn(EventType.EVIDENCE_REJECTED, types)
        self.assertNotIn(EventType.EVIDENCE_COLLECTED, types)


class JournalIntegrityTests(unittest.TestCase):
    def make_event(self):
        journal = Journal(InMemoryJournalSink(), task_id="T")
        return journal.record(
            EventType.VERIFIER_DECISION, "verifier", "VERIFIED", missing=[]
        )

    def test_intact_event_verifies(self):
        ok, problems = verify_chain([self.make_event()])
        self.assertTrue(ok)
        self.assertEqual(problems, ())

    def test_mutated_event_is_detected(self):
        event = self.make_event()
        # Rewrite the outcome while keeping the original digest.
        forged = replace(event, status="VERIFIED", detail={"missing": ["runtime"]})
        forged = replace(forged, content_hash=event.content_hash)
        ok, problems = verify_chain([forged])
        self.assertFalse(ok)
        self.assertEqual(len(problems), 1)

    def test_summary_reports_a_broken_chain(self):
        event = self.make_event()
        forged = replace(
            replace(event, status="TAMPERED"), content_hash=event.content_hash
        )
        summary = summarize([forged])
        self.assertFalse(summary["chain_intact"])
        self.assertTrue(summary["chain_problems"])


class JournalSinkTests(unittest.TestCase):
    def test_stream_sink_emits_one_json_object_per_line(self):
        stream = io.StringIO()
        journal = Journal(StreamJournalSink(stream), task_id="T")
        journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
        journal.record(
            EventType.EXECUTION_COMPLETE,
            "orchestrator",
            "ABSTAIN",
            Severity.WARNING,
            failure="EVIDENCE_MISSING",
        )

        lines = [line for line in stream.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            payload = json.loads(line)
            # Cloud Logging reads severity and the correlation ids from stdout.
            self.assertIn(payload["severity"], {"INFO", "WARNING", "ERROR"})
            self.assertEqual(payload["task_id"], "T")
            self.assertTrue(payload["execution_id"].startswith("exec_"))
            self.assertEqual(len(payload["content_hash"]), 64)

    def test_events_are_scoped_by_execution_id(self):
        sink = InMemoryJournalSink()
        first = Journal(sink, task_id="T")
        second = Journal(sink, task_id="T")
        first.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
        second.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
        second.record(EventType.EXECUTION_COMPLETE, "orchestrator", "VERIFIED")

        self.assertEqual(len(first.events()), 1)
        self.assertEqual(len(second.events()), 2)
        self.assertNotEqual(first.execution_id, second.execution_id)

    def test_execution_ids_are_unique(self):
        self.assertNotEqual(new_execution_id(), new_execution_id())


class RedactionTests(unittest.TestCase):
    def test_named_detail_keys_are_dropped_before_persisting(self):
        journal = Journal(InMemoryJournalSink(), task_id="T")
        event = journal.record(
            EventType.TOOL_CALL,
            "executor",
            "INVOKED",
            tool="verify_task_completion",
            api_key="should-not-be-stored",
        )
        clean = redacted(event, ("api_key",))
        self.assertNotIn("api_key", clean.detail)
        self.assertIn("tool", clean.detail)
        # The digest is recomputed so the redacted record is self-consistent.
        self.assertTrue(clean.intact)


class RoundTripTests(unittest.TestCase):
    def test_event_survives_serialization(self):
        journal = Journal(InMemoryJournalSink(), task_id="T")
        original = journal.record(
            EventType.VERIFIER_DECISION,
            "verifier",
            "ABSTAIN",
            Severity.WARNING,
            missing=["runtime"],
            failure="EVIDENCE_UNTRUSTED",
        )
        from proofos.journal import ExecutionEvent

        restored = ExecutionEvent.from_dict(json.loads(json.dumps(original.to_dict())))
        self.assertEqual(restored.content_hash, original.content_hash)
        self.assertTrue(restored.intact)
        self.assertEqual(restored.detail["missing"], ["runtime"])


if __name__ == "__main__":
    unittest.main()
