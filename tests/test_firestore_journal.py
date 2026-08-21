"""Firestore journal adapter contract tests.

These exercise the adapter against an in-process stand-in. They prove the
adapter's *logic*: sequencing, chain linkage, idempotency, transactional
rollback, and fail-closed handling of storage faults.

They prove nothing about Firestore itself. Real write/read against a real
project is NOT PROVEN and no assertion here should be read otherwise.
"""

import unittest

from google.api_core.exceptions import ServiceUnavailable

from proofos.firestore_journal import FirestoreJournalSink, _sequence_id
from proofos.journal import (
    GENESIS_HASH,
    EventDraft,
    EventType,
    ExecutionEvent,
    Journal,
    JournalUnavailableError,
    Severity,
    new_event_id,
    summarize,
    verify_events,
)
from tests.fake_firestore import FakeFirestore, fake_transactional

EXEC = "exec_fs"


def draft(execution_id=EXEC, event_id=None, status="ABSTAIN", task_id="T", **payload):
    return EventDraft(
        event_id=event_id or new_event_id(),
        execution_id=execution_id,
        task_id=task_id,
        event=EventType.VERIFIER_DECISION,
        agent="verifier",
        status=status,
        trace_id="trace",
        timestamp=1000.0,
        severity=Severity.WARNING,
        payload=payload,
    )


class FirestoreAdapterTestCase(unittest.TestCase):
    def setUp(self):
        self.client = FakeFirestore()
        self.sink = FirestoreJournalSink(
            self.client, transactional=fake_transactional
        )

    def append_many(self, count, execution_id=EXEC, task_id="T"):
        return [
            self.sink.append(draft(execution_id=execution_id, task_id=task_id, i=i))
            for i in range(count)
        ]


class SequencingTests(FirestoreAdapterTestCase):
    def test_sequences_start_at_zero_and_increment(self):
        events = self.append_many(4)
        self.assertEqual([e.sequence for e in events], [0, 1, 2, 3])

    def test_chain_head_advances_with_each_append(self):
        events = self.append_many(3)
        head = self.client.docs[f"executions/{EXEC}"]
        self.assertEqual(head["next_sequence"], 3)
        self.assertEqual(head["head_hash"], events[-1].content_hash)

    def test_first_event_follows_the_genesis_hash(self):
        events = self.append_many(2)
        self.assertEqual(events[0].previous_hash, GENESIS_HASH)
        self.assertEqual(events[1].previous_hash, events[0].content_hash)

    def test_document_ids_are_zero_padded_but_sequence_is_the_authority(self):
        self.append_many(2)
        paths = self.client.event_paths(EXEC)
        self.assertTrue(paths[0].endswith(_sequence_id(0)))
        # Ordering comes from the stored field, not the id.
        self.assertEqual(
            [r["sequence"] for r in self.client.event_records(EXEC)], [0, 1]
        )


class ReadOrderingTests(FirestoreAdapterTestCase):
    def test_events_are_ordered_by_sequence_not_by_stream_order(self):
        self.append_many(5)
        # The fake deliberately streams in reverse; the adapter must not care.
        self.assertEqual(
            [e.sequence for e in self.sink.list_execution(EXEC)], [0, 1, 2, 3, 4]
        )

    def test_arbitrary_stream_order_still_reconstructs_the_chain(self):
        self.append_many(5)
        self.client.set_stream_order(lambda paths: [paths[2], paths[0], paths[4], paths[1], paths[3]])
        events = self.sink.list_execution(EXEC)
        self.assertEqual([e.sequence for e in events], [0, 1, 2, 3, 4])
        ok, problems = verify_events(events)
        self.assertTrue(ok, problems)


class RoundTripTests(FirestoreAdapterTestCase):
    def test_hashes_are_reproducible_after_reading_back(self):
        written = self.append_many(4)
        reloaded = self.sink.list_execution(EXEC)
        self.assertEqual(
            [e.content_hash for e in written], [e.content_hash for e in reloaded]
        )
        for event in reloaded:
            self.assertTrue(event.intact)

    def test_chain_verifies_after_reload(self):
        self.append_many(6)
        ok, problems = self.sink.verify_chain(EXEC)
        self.assertTrue(ok, problems)

    def test_payload_survives_persistence(self):
        self.sink.append(draft(missing=["runtime"], failure="EVIDENCE_UNTRUSTED"))
        event = self.sink.list_execution(EXEC)[0]
        self.assertEqual(event.payload["missing"], ["runtime"])
        self.assertEqual(event.payload["failure"], "EVIDENCE_UNTRUSTED")

    def test_summary_reconstructs_the_decision_from_storage(self):
        journal = Journal(self.sink, execution_id=EXEC, task_id="T")
        journal.record(
            EventType.VERIFIER_DECISION,
            "verifier",
            "ABSTAIN",
            Severity.WARNING,
            missing=["runtime"],
            failure="EVIDENCE_UNTRUSTED",
            attempt=1,
        )
        journal.record(
            EventType.VERIFIER_DECISION, "verifier", "VERIFIED", attempt=2, missing=[]
        )
        journal.record(EventType.EXECUTION_COMPLETE, "orchestrator", "VERIFIED")

        summary = summarize(self.sink.list_execution(EXEC))
        self.assertEqual(summary["final_status"], "VERIFIED")
        self.assertTrue(summary["chain_intact"])
        self.assertEqual(
            [d["status"] for d in summary["decisions"]], ["ABSTAIN", "VERIFIED"]
        )


class TamperTests(FirestoreAdapterTestCase):
    def test_edited_stored_event_is_detected(self):
        self.append_many(4)
        path = self.client.event_paths(EXEC)[1]
        self.client.docs[path]["status"] = "VERIFIED"

        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)
        self.assertTrue(any("content hash" in p for p in problems))

    def test_rehashed_stored_event_still_breaks_the_chain(self):
        # A tamperer who recomputes the digest still cannot fix the linkage of
        # every subsequent event.
        self.append_many(4)
        path = self.client.event_paths(EXEC)[1]
        record = self.client.docs[path]
        record["status"] = "VERIFIED"
        record["content_hash"] = ExecutionEvent.from_dict(record).compute_hash()

        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)
        self.assertTrue(any("does not follow its predecessor" in p for p in problems))

    def test_deleted_middle_event_is_detected(self):
        self.append_many(5)
        path = self.client.event_paths(EXEC)[2]
        del self.client.docs[path]

        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)
        self.assertTrue(any("missing sequences" in p for p in problems))

    def test_truncated_tail_leaves_the_head_pointer_inconsistent(self):
        events = self.append_many(4)
        del self.client.docs[self.client.event_paths(EXEC)[-1]]

        remaining = self.sink.list_execution(EXEC)
        self.assertEqual(len(remaining), 3)
        # The chain head still records the removed event, so the deletion is
        # detectable even though the shortened chain is internally consistent.
        head = self.client.docs[f"executions/{EXEC}"]
        self.assertEqual(head["next_sequence"], 4)
        self.assertEqual(head["head_hash"], events[-1].content_hash)
        self.assertNotEqual(remaining[-1].content_hash, head["head_hash"])

    def test_forged_duplicate_sequence_is_detected(self):
        self.append_many(3)
        original = self.client.docs[self.client.event_paths(EXEC)[1]]
        forged = dict(original)
        forged["event_id"] = new_event_id()
        forged["status"] = "VERIFIED"
        forged["content_hash"] = ExecutionEvent.from_dict(forged).compute_hash()
        self.client.docs[f"executions/{EXEC}/events/impostor"] = forged

        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)
        self.assertTrue(any("duplicate sequence" in p for p in problems))


class MalformedRecordTests(FirestoreAdapterTestCase):
    def test_malformed_record_raises_rather_than_being_skipped(self):
        self.append_many(3)
        path = self.client.event_paths(EXEC)[1]
        del self.client.docs[path]["sequence"]

        with self.assertRaises(JournalUnavailableError):
            self.sink.list_execution(EXEC)

    def test_verify_chain_reports_malformed_records_instead_of_raising(self):
        self.append_many(3)
        self.client.docs[self.client.event_paths(EXEC)[1]]["timestamp"] = "not-a-number"

        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)
        self.assertTrue(problems)

    def test_non_mapping_record_is_rejected(self):
        self.append_many(1)
        self.client.docs[self.client.event_paths(EXEC)[0]] = ["not", "a", "mapping"]

        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)

    def test_unknown_event_type_is_rejected(self):
        self.append_many(2)
        self.client.docs[self.client.event_paths(EXEC)[0]]["event"] = "FABRICATED"

        with self.assertRaises(JournalUnavailableError):
            self.sink.list_execution(EXEC)


class IdempotencyTests(FirestoreAdapterTestCase):
    def test_retrying_the_same_event_id_appends_once(self):
        first = self.sink.append(draft(event_id="evt_fixed"))
        second = self.sink.append(draft(event_id="evt_fixed", status="VERIFIED"))

        self.assertEqual(first.sequence, second.sequence)
        self.assertEqual(first.content_hash, second.content_hash)
        # A retry must not rewrite the recorded outcome.
        self.assertEqual(second.status, "ABSTAIN")
        self.assertEqual(len(self.sink.list_execution(EXEC)), 1)

    def test_idempotent_retry_does_not_advance_the_chain_head(self):
        self.sink.append(draft(event_id="evt_fixed"))
        self.sink.append(draft(event_id="evt_fixed"))
        self.assertEqual(self.client.docs[f"executions/{EXEC}"]["next_sequence"], 1)

    def test_dangling_idempotency_index_is_reported_as_partial_write(self):
        self.sink.append(draft(event_id="evt_fixed"))
        # Simulate a partially applied write: the index survives, the event
        # does not.
        del self.client.docs[self.client.event_paths(EXEC)[0]]

        with self.assertRaises(JournalUnavailableError):
            self.sink.append(draft(event_id="evt_fixed"))


class ConcurrencyTests(FirestoreAdapterTestCase):
    def test_a_lost_sequence_race_retries_instead_of_overwriting(self):
        self.sink.append(draft(event_id="evt_a"))

        # While this append is in flight, another writer claims the next
        # sequence. The in-flight create must fail rather than overwrite, and
        # the adapter must retry onto a fresh sequence.
        def interleaved_writer():
            self.sink.append(draft(event_id="evt_intruder"))

        self.client.before_commit = interleaved_writer
        event = self.sink.append(draft(event_id="evt_b"))

        self.assertEqual(event.sequence, 2)
        events = self.sink.list_execution(EXEC)
        self.assertEqual([e.sequence for e in events], [0, 1, 2])
        self.assertEqual(
            [e.event_id for e in events], ["evt_a", "evt_intruder", "evt_b"]
        )
        ok, problems = verify_events(events)
        self.assertTrue(ok, problems)

    def test_no_two_events_share_a_sequence(self):
        for index in range(6):
            if index == 3:
                self.client.before_commit = lambda: self.sink.append(
                    draft(event_id="evt_race")
                )
            self.sink.append(draft(event_id=f"evt_{index}"))

        sequences = [e.sequence for e in self.sink.list_execution(EXEC)]
        self.assertEqual(len(sequences), len(set(sequences)))
        self.assertEqual(sequences, sorted(sequences))


class StorageFaultTests(FirestoreAdapterTestCase):
    def test_commit_failure_raises_and_writes_nothing(self):
        self.client.commit_error = ServiceUnavailable("backend down")
        with self.assertRaises(JournalUnavailableError):
            self.sink.append(draft())
        self.assertEqual(self.client.event_paths(EXEC), [])

    def test_read_failure_during_append_is_reported_as_audit_loss(self):
        self.client.read_error = ServiceUnavailable("backend down")
        with self.assertRaises(JournalUnavailableError):
            self.sink.append(draft())

    def test_stream_failure_is_reported_as_audit_loss(self):
        self.append_many(2)
        self.client.stream_error = ServiceUnavailable("backend down")
        with self.assertRaises(JournalUnavailableError):
            self.sink.list_execution(EXEC)

    def test_verify_chain_reports_storage_failure_instead_of_raising(self):
        self.append_many(2)
        self.client.stream_error = ServiceUnavailable("backend down")
        ok, problems = self.sink.verify_chain(EXEC)
        self.assertFalse(ok)
        self.assertTrue(problems)

    def test_failed_append_leaves_the_chain_head_untouched(self):
        self.append_many(2)
        head_before = dict(self.client.docs[f"executions/{EXEC}"])
        self.client.commit_error = ServiceUnavailable("backend down")
        with self.assertRaises(JournalUnavailableError):
            self.sink.append(draft())
        self.assertEqual(self.client.docs[f"executions/{EXEC}"], head_before)


class IsolationTests(FirestoreAdapterTestCase):
    def test_executions_are_stored_under_separate_paths(self):
        self.append_many(2, execution_id="exec_a")
        self.append_many(3, execution_id="exec_b")

        self.assertEqual(len(self.sink.list_execution("exec_a")), 2)
        self.assertEqual(len(self.sink.list_execution("exec_b")), 3)
        self.assertTrue(self.sink.verify_chain("exec_a")[0])
        self.assertTrue(self.sink.verify_chain("exec_b")[0])

    def test_each_execution_has_its_own_sequence_space(self):
        self.append_many(3, execution_id="exec_a")
        self.append_many(1, execution_id="exec_b")
        self.assertEqual(
            [e.sequence for e in self.sink.list_execution("exec_a")], [0, 1, 2]
        )
        self.assertEqual([e.sequence for e in self.sink.list_execution("exec_b")], [0])

    def test_events_for_one_task_do_not_appear_under_another(self):
        self.append_many(2, execution_id="exec_a", task_id="TASK-A")
        self.append_many(2, execution_id="exec_b", task_id="TASK-B")

        for event in self.sink.list_execution("exec_a"):
            self.assertEqual(event.task_id, "TASK-A")
        for event in self.sink.list_execution("exec_b"):
            self.assertEqual(event.task_id, "TASK-B")

    def test_an_old_verified_execution_does_not_satisfy_a_new_one(self):
        old = Journal(self.sink, execution_id="exec_old", task_id="TASK-A")
        old.record(EventType.EXECUTION_COMPLETE, "orchestrator", "VERIFIED")

        fresh = Journal(self.sink, execution_id="exec_new", task_id="TASK-A")
        fresh.record(EventType.EXECUTION_START, "orchestrator", "STARTED")

        self.assertEqual(
            summarize(self.sink.list_execution("exec_new"))["final_status"],
            "INCOMPLETE",
        )

    def test_unknown_execution_returns_nothing_rather_than_borrowing_history(self):
        self.append_many(2, execution_id="exec_a")
        self.assertEqual(self.sink.list_execution("exec_absent"), ())


class ApiCompatibilityTests(unittest.TestCase):
    """The installed client must expose what the adapter calls.

    This checks construction and API shape only. It performs no network I/O and
    is not evidence that Firestore persistence works.
    """

    def test_google_cloud_firestore_is_importable_and_has_the_expected_api(self):
        from google.cloud import firestore

        self.assertTrue(callable(firestore.transactional))
        self.assertTrue(hasattr(firestore, "Client"))
        for method in ("collection", "transaction"):
            self.assertTrue(
                hasattr(firestore.Client, method), f"Client.{method} missing"
            )

    def test_adapter_defaults_to_the_real_transactional_helper(self):
        from google.cloud import firestore

        sink = FirestoreJournalSink(FakeFirestore())
        self.assertIs(sink._transactional, firestore.transactional)

    def test_adapter_uses_the_real_already_exists_exception(self):
        from google.api_core.exceptions import AlreadyExists

        sink = FirestoreJournalSink(FakeFirestore())
        self.assertIs(sink._already_exists, AlreadyExists)


class BackendSelectionTests(unittest.TestCase):
    def test_default_backend_needs_no_credentials(self):
        import os

        from proofos.journal_backend import build_journal_backend

        saved = os.environ.pop("PROOFOS_JOURNAL_BACKEND", None)
        try:
            backend = build_journal_backend()
        finally:
            if saved is not None:
                os.environ["PROOFOS_JOURNAL_BACKEND"] = saved
        self.assertEqual(backend.backend, "memory")

    def test_firestore_backend_uses_an_injected_client(self):
        import os

        from proofos.journal_backend import build_journal_backend

        os.environ["PROOFOS_JOURNAL_BACKEND"] = "firestore"
        try:
            backend = build_journal_backend(client=FakeFirestore())
        finally:
            os.environ.pop("PROOFOS_JOURNAL_BACKEND", None)

        self.assertEqual(backend.backend, "firestore")
        self.assertIsInstance(backend.durable_sink, FirestoreJournalSink)


if __name__ == "__main__":
    unittest.main()
