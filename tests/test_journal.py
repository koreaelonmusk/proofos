"""Execution journal tests.

The journal exists to answer "why was this task marked VERIFIED?" without
trusting any agent's account of it. These tests run the real recovery loop
against the real verifier and then reconstruct the decision from the journal
alone, then attack the chain directly.
"""

import asyncio
import functools
import io
import json
import unittest
from dataclasses import replace

from proofos.journal import (
    GENESIS_HASH,
    EventDraft,
    EventType,
    ExecutionEvent,
    FanoutJournalSink,
    InMemoryJournalSink,
    Journal,
    JournalUnavailableError,
    Severity,
    StreamJournalSink,
    new_event_id,
    new_execution_id,
    redacted,
    summarize,
    verify_events,
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


def draft(execution_id="exec_test", sequence_hint=0, **overrides):
    base = dict(
        event_id=new_event_id(),
        execution_id=execution_id,
        task_id="T",
        event=EventType.VERIFIER_DECISION,
        agent="verifier",
        status="ABSTAIN",
        trace_id="trace",
        timestamp=1000.0 + sequence_hint,
        severity=Severity.WARNING,
        payload={},
    )
    base.update(overrides)
    return EventDraft(**base)


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
        self.assertTrue(outcome["audit_intact"])

        types = [e.event for e in self.journal.events()]
        self.assertEqual(types[0], EventType.EXECUTION_START)
        self.assertEqual(types[-1], EventType.EXECUTION_COMPLETE)
        self.assertIn(EventType.RECOVERY_START, types)
        self.assertIn(EventType.EVIDENCE_COLLECTED, types)

        summary = summarize(self.journal.events())
        self.assertEqual(summary["final_status"], "VERIFIED")
        self.assertTrue(summary["chain_intact"])
        self.assertEqual(
            [d["status"] for d in summary["decisions"]], ["ABSTAIN", "VERIFIED"]
        )
        self.assertEqual(summary["decisions"][0]["missing"], ["runtime"])
        self.assertEqual(summary["decisions"][0]["failure"], "EVIDENCE_UNTRUSTED")

    def test_sequences_are_contiguous_and_chained(self):
        run(
            run_verification_loop(
                compliant_turn, self.collectors, 2, journal=self.journal
            )
        )
        events = self.journal.events()
        self.assertEqual([e.sequence for e in events], list(range(len(events))))
        self.assertEqual(events[0].previous_hash, GENESIS_HASH)
        for earlier, later in zip(events, events[1:]):
            self.assertEqual(later.previous_hash, earlier.content_hash)

        ok, problems = self.journal.verify()
        self.assertTrue(ok, problems)

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
            self.assertTrue(event.event_id)

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


class AuditLossTests(unittest.TestCase):
    """Losing the audit trail can only ever downgrade an outcome."""

    class BrokenSink(InMemoryJournalSink):
        def append(self, draft):
            raise JournalUnavailableError("storage is down")

    class FlakySink(InMemoryJournalSink):
        """Fails only on the decision event, so most of the trail survives."""

        def append(self, draft):
            if draft.event is EventType.VERIFIER_DECISION:
                raise RuntimeError("write timeout")
            return super().append(draft)

    def setUp(self):
        LEDGER.reset()
        scenario.seed_incomplete_evidence(LEDGER)
        self._server = serving(lambda h: send_json(h, 200, {"status": "ok"}))
        self.health_url = self._server.__enter__()
        self.addCleanup(self._server.__exit__, None, None, None)
        self.collectors = {
            "runtime": functools.partial(
                scenario.collect_runtime_evidence, LEDGER, self.health_url, 5
            )
        }

    def test_storage_failure_cannot_produce_verified(self):
        journal = Journal(self.BrokenSink(), task_id=scenario.TASK_ID)
        outcome = run(
            run_verification_loop(compliant_turn, self.collectors, 2, journal=journal)
        )
        # The verifier itself would have reached VERIFIED on attempt 2.
        self.assertEqual(
            outcome["attempts"][-1]["verifier_decision"]["status"], "VERIFIED"
        )
        # The execution is not presented as verified, because it was not recorded.
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(outcome["failure_class"], "AUDIT_UNAVAILABLE")
        self.assertFalse(outcome["audit_intact"])

    def test_partial_storage_failure_also_downgrades(self):
        journal = Journal(self.FlakySink(), task_id=scenario.TASK_ID)
        outcome = run(
            run_verification_loop(compliant_turn, self.collectors, 2, journal=journal)
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(outcome["failure_class"], "AUDIT_UNAVAILABLE")
        self.assertTrue(outcome["audit_failures"])

    def test_an_arbitrary_storage_exception_is_wrapped_not_leaked(self):
        class ExplodingSink(InMemoryJournalSink):
            def append(self, draft):
                raise ZeroDivisionError("nonsense from the driver")

        journal = Journal(ExplodingSink(), task_id="T")
        with self.assertRaises(JournalUnavailableError):
            journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")


class ChainIntegrityTests(unittest.TestCase):
    """Editing, removing, duplicating, or reordering must all be detectable."""

    def build(self, count=4):
        sink = InMemoryJournalSink()
        journal = Journal(sink, execution_id="exec_chain", task_id="T")
        for index in range(count):
            journal.record(
                EventType.AGENT_TURN, "executor", f"STEP{index}", attempt=index
            )
        return sink, journal

    def test_intact_chain_verifies(self):
        _, journal = self.build()
        ok, problems = journal.verify()
        self.assertTrue(ok)
        self.assertEqual(problems, ())

    def test_edited_event_breaks_the_chain(self):
        _, journal = self.build()
        events = list(journal.events())
        # Rewrite a middle event's outcome, keeping its original digest.
        forged = replace(events[1], status="VERIFIED")
        forged = replace(forged, content_hash=events[1].content_hash)
        ok, problems = verify_events(events[:1] + [forged] + events[2:])
        self.assertFalse(ok)
        self.assertTrue(any("content hash" in p for p in problems))

    def test_missing_event_in_the_middle_is_detected(self):
        _, journal = self.build()
        events = list(journal.events())
        without_middle = events[:2] + events[3:]
        ok, problems = verify_events(without_middle)
        self.assertFalse(ok)
        self.assertTrue(any("missing sequences" in p for p in problems))

    def test_truncated_head_is_detected(self):
        _, journal = self.build()
        events = list(journal.events())
        ok, problems = verify_events(events[1:])
        self.assertFalse(ok)
        self.assertTrue(any("does not start at sequence 0" in p for p in problems))

    def test_duplicate_sequence_is_detected(self):
        _, journal = self.build()
        events = list(journal.events())
        impostor = replace(events[2], event_id=new_event_id(), status="VERIFIED")
        ok, problems = verify_events(list(events) + [impostor])
        self.assertFalse(ok)
        self.assertTrue(any("duplicate sequence" in p for p in problems))

    def test_out_of_order_input_is_reordered_by_sequence_not_position(self):
        _, journal = self.build()
        events = list(journal.events())
        shuffled = [events[3], events[0], events[2], events[1]]
        ok, problems = verify_events(shuffled)
        self.assertTrue(ok, problems)
        # Verification sorts by the explicit sequence, never by arrival order.
        self.assertEqual(
            [e.sequence for e in sorted(shuffled, key=lambda e: e.sequence)],
            [0, 1, 2, 3],
        )

    def test_an_event_moved_to_a_different_position_breaks_linkage(self):
        _, journal = self.build()
        events = list(journal.events())
        moved = replace(events[3], sequence=1)
        moved = replace(moved, content_hash=moved.compute_hash())
        ok, problems = verify_events(events[:1] + [moved] + events[2:])
        self.assertFalse(ok)
        self.assertTrue(any("does not follow its predecessor" in p for p in problems))

    def test_empty_chain_is_vacuously_intact(self):
        sink = InMemoryJournalSink()
        ok, problems = sink.verify_chain("exec_nothing")
        self.assertTrue(ok)
        self.assertEqual(problems, ())


class IsolationTests(unittest.TestCase):
    """Executions must not contaminate each other."""

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

    def test_each_execution_starts_its_own_sequence_at_zero(self):
        sink = InMemoryJournalSink()
        first = Journal(sink, execution_id="exec_a", task_id="T")
        second = Journal(sink, execution_id="exec_b", task_id="T")
        first.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
        first.record(EventType.EXECUTION_COMPLETE, "orchestrator", "VERIFIED")
        second.record(EventType.EXECUTION_START, "orchestrator", "STARTED")

        self.assertEqual([e.sequence for e in first.events()], [0, 1])
        self.assertEqual([e.sequence for e in second.events()], [0])
        self.assertTrue(sink.verify_chain("exec_a")[0])
        self.assertTrue(sink.verify_chain("exec_b")[0])

    def test_a_verified_event_from_another_execution_does_not_transfer(self):
        sink = InMemoryJournalSink()
        old = Journal(sink, execution_id="exec_old", task_id="T")
        old.record(EventType.EXECUTION_COMPLETE, "orchestrator", "VERIFIED")

        fresh = Journal(sink, execution_id="exec_new", task_id="T")
        fresh.record(EventType.EXECUTION_START, "orchestrator", "STARTED")

        self.assertEqual(summarize(fresh.events())["final_status"], "INCOMPLETE")

    def test_execution_ids_are_unique(self):
        self.assertNotEqual(new_execution_id(), new_execution_id())


class IdempotencyTests(unittest.TestCase):
    def test_replaying_the_same_event_id_does_not_append_twice(self):
        sink = InMemoryJournalSink()
        first = sink.append(draft(event_id="evt_fixed"))
        second = sink.append(draft(event_id="evt_fixed", status="VERIFIED"))

        self.assertEqual(first.sequence, second.sequence)
        self.assertEqual(first.content_hash, second.content_hash)
        # The retry must not rewrite history into a different outcome.
        self.assertEqual(second.status, "ABSTAIN")
        self.assertEqual(len(sink.list_execution("exec_test")), 1)

    def test_distinct_event_ids_append_separately(self):
        sink = InMemoryJournalSink()
        sink.append(draft())
        sink.append(draft())
        self.assertEqual(len(sink.list_execution("exec_test")), 2)


class SinkTests(unittest.TestCase):
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
        for index, line in enumerate(lines):
            payload = json.loads(line)
            self.assertIn(payload["severity"], {"INFO", "WARNING", "ERROR"})
            self.assertEqual(payload["task_id"], "T")
            self.assertEqual(payload["sequence"], index)
            self.assertTrue(payload["execution_id"].startswith("exec_"))
            self.assertEqual(len(payload["content_hash"]), 64)

    def test_fanout_replicates_the_same_chain_to_every_sink(self):
        primary = InMemoryJournalSink()
        replica = InMemoryJournalSink()
        journal = Journal(
            FanoutJournalSink(primary, replica), execution_id="exec_fan", task_id="T"
        )
        journal.record(EventType.EXECUTION_START, "orchestrator", "STARTED")
        journal.record(EventType.EXECUTION_COMPLETE, "orchestrator", "VERIFIED")

        primary_events = primary.list_execution("exec_fan")
        replica_events = replica.list_execution("exec_fan")
        # Only the primary assigns sequences, so the copies cannot diverge.
        self.assertEqual(
            [e.content_hash for e in primary_events],
            [e.content_hash for e in replica_events],
        )
        self.assertTrue(replica.verify_chain("exec_fan")[0])


class RedactionTests(unittest.TestCase):
    def test_named_payload_keys_are_dropped(self):
        journal = Journal(InMemoryJournalSink(), task_id="T")
        event = journal.record(
            EventType.TOOL_CALL,
            "executor",
            "INVOKED",
            tool="verify_task_completion",
            api_key="should-not-be-stored",
        )
        clean = redacted(event, ("api_key",))
        self.assertNotIn("api_key", clean.payload)
        self.assertIn("tool", clean.payload)
        self.assertTrue(clean.intact)


class SerializationTests(unittest.TestCase):
    def test_event_survives_a_json_round_trip(self):
        journal = Journal(InMemoryJournalSink(), task_id="T")
        original = journal.record(
            EventType.VERIFIER_DECISION,
            "verifier",
            "ABSTAIN",
            Severity.WARNING,
            missing=["runtime"],
            failure="EVIDENCE_UNTRUSTED",
        )
        restored = ExecutionEvent.from_dict(json.loads(json.dumps(original.to_dict())))
        self.assertEqual(restored.content_hash, original.content_hash)
        self.assertTrue(restored.intact)
        self.assertEqual(restored.payload["missing"], ["runtime"])
        self.assertEqual(restored.sequence, original.sequence)
        self.assertEqual(restored.previous_hash, original.previous_hash)

    def test_a_whole_chain_survives_a_round_trip(self):
        sink = InMemoryJournalSink()
        journal = Journal(sink, execution_id="exec_rt", task_id="T")
        for index in range(5):
            journal.record(EventType.AGENT_TURN, "executor", f"S{index}", i=index)

        wire = json.dumps([e.to_dict() for e in journal.events()])
        restored = [ExecutionEvent.from_dict(d) for d in json.loads(wire)]
        ok, problems = verify_events(restored)
        self.assertTrue(ok, problems)

    def test_malformed_record_is_rejected(self):
        for bad in (
            {},
            {"event_id": "e"},
            {"event_id": "e", "execution_id": "x", "task_id": "T", "sequence": "NaN"},
        ):
            with self.assertRaises(ValueError):
                ExecutionEvent.from_dict(bad)

    def test_unknown_event_type_is_rejected(self):
        journal = Journal(InMemoryJournalSink(), task_id="T")
        record = journal.record(EventType.AGENT_TURN, "executor", "S").to_dict()
        record["event"] = "NOT_A_REAL_EVENT"
        with self.assertRaises(ValueError):
            ExecutionEvent.from_dict(record)


if __name__ == "__main__":
    unittest.main()
