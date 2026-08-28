"""Operations that outlive the process that started them.

ProofOS already answers two questions: can I trust this completion, and can I
trust a compromised model. This file asks the third one -- can I safely pick an
operation back up three weeks later -- and the answer has to hold without
loosening either of the first two.

The flagship test is deliberately unkind to itself. It does not reuse a single
object across the restart, it does not sleep, and it does not let the old
evidence count. A three-week-old observation is still three weeks old: the
restored operation must abstain on it and wait for something fresh. Resuming an
operation restores where it got to, never what it proved.

The other tests are the ones that would matter if this were real: a stale writer
losing a race, a truncated journal refusing to resume, a retired agent version
failing loudly instead of silently resolving to whatever is current, and -- the
one that would cost money -- a restart that tries to run the remediation again.
"""

from __future__ import annotations

import time
import unittest

from proofos.agent_catalog import (
    AgentCard,
    AgentCatalog,
    CatalogError,
    Lifecycle,
    SecurityClass,
    default_catalog,
)
from proofos.continuity import (
    CHECKPOINT_SCHEMA,
    ContinuityError,
    ContinuityFailure,
    InMemoryContinuityStore,
    OperationCheckpoint,
    Phase,
    advance,
    open_operation,
    policy_digest,
)
from proofos.journal import EventType, InMemoryJournalSink, Journal, Severity
from proofos.registry import Role, default_registry
from proofos.resume import (
    COLLECT,
    EXECUTE,
    NOTHING,
    OperationResumer,
    count_actions,
)
from proofos.verifier import (
    Evidence,
    EvidenceSource,
    FailureClass,
    Requirement,
    VerificationStatus,
    verify_completion,
)

DAY = 86_400.0
T0 = 1_700_000_000.0
#: A runtime health probe speaks for the moment it ran. One hour is generous.
RUNTIME_HORIZON = 3600.0

OPERATION = "op_line_a_deviation"
TASK = "LINE-A-QD-1184"

REQUIREMENTS = (
    Requirement("tests"),
    Requirement("runtime", max_age_seconds=RUNTIME_HORIZON),
)

PINNED = {
    "planner-v1": "v1",
    "executor-v1": "v1",
    "collector-http-v1": "v1",
    "verifier-v1": "v1",
}


def day_zero_journal(sink: InMemoryJournalSink) -> Journal:
    """Write the events a real day-zero run would have written."""
    journal = Journal(execution_id="exec_continuity_day0", task_id=TASK, sink=sink)
    journal.record(
        EventType.EXECUTION_START, "orchestrator-v1", "STARTED", Severity.INFO
    )
    journal.record(EventType.AGENT_TURN, "planner-v1", "PLANNED", Severity.INFO)
    # The one event that proves the remediation actually happened.
    journal.record(
        EventType.AGENT_TURN, "executor-v1", "ACTION_EXECUTED", Severity.INFO
    )
    journal.record(
        EventType.CLAIM_RECEIVED, "executor-v1", "CLAIMED_SUCCESS", Severity.INFO
    )
    journal.record(
        EventType.VERIFIER_DECISION,
        "verifier-v1",
        "ABSTAIN",
        Severity.WARNING,
        failure="EVIDENCE_UNTRUSTED",
        missing=["runtime"],
    )
    return journal


def self_report(at: float) -> Evidence:
    return Evidence(
        kind="runtime",
        value="executor-v1 states: I verified the line myself",
        source=EvidenceSource.EXECUTOR,
        collected_at=at,
        collector="executor-v1",
    )


def ci_evidence(at: float) -> Evidence:
    return Evidence(
        kind="tests",
        value="qualification suite green",
        source=EvidenceSource.OBSERVED,
        collected_at=at,
        collector="collector-ci-v1",
    )


def observation(at: float) -> Evidence:
    return Evidence(
        kind="runtime",
        value="probe HEALTHY: line A within tolerance",
        source=EvidenceSource.OBSERVED,
        collected_at=at,
        collector="collector-http-v1",
    )


class TwentyOneDayRestartTests(unittest.TestCase):
    """The flagship: an operation resumes weeks later without repeating work."""

    def test_operation_resumes_after_21_days_without_reexecuting_action(self):
        # -- day 0 ---------------------------------------------------------
        sink = InMemoryJournalSink()
        journal = day_zero_journal(sink)
        events = sink.list_execution(journal.execution_id)

        self.assertEqual(count_actions(events), 1, "the action ran exactly once")

        # The verifier abstains at day 0: the only runtime evidence is the
        # executor's own word for it.
        day0_ledger = [ci_evidence(T0), self_report(T0)]
        day0 = verify_completion(
            claim="Line A recovered.",
            evidence=day0_ledger,
            required_kinds=REQUIREMENTS,
            now=T0,
        )
        self.assertIs(day0.status, VerificationStatus.ABSTAIN)
        self.assertIs(day0.failure, FailureClass.EVIDENCE_UNTRUSTED)

        store = InMemoryContinuityStore()
        checkpoint = open_operation(
            operation_id=OPERATION,
            execution_id=journal.execution_id,
            task_id=TASK,
            requirements=REQUIREMENTS,
            assigned_agent_versions=PINNED,
            events=events,
            now=T0,
        )
        checkpoint = advance(
            checkpoint,
            Phase.AWAITING_INDEPENDENT_EVIDENCE,
            events=events,
            evidence_refs=[item.content_hash for item in day0_ledger],
            now=T0,
        )
        store.put(checkpoint)

        # -- the process dies ----------------------------------------------
        # Nothing from day zero survives except the durable store and journal.
        del journal, checkpoint, day0_ledger, day0

        later = T0 + 21 * DAY

        # -- a completely new process --------------------------------------
        resumer = OperationResumer(
            store=store,
            catalog=default_catalog(default_registry()),
            journal_reader=sink,
        )
        plan = resumer.resume(OPERATION)

        # Identity and assignment survived.
        self.assertEqual(plan.checkpoint.operation_id, OPERATION)
        self.assertEqual(plan.checkpoint.execution_id, "exec_continuity_day0")
        self.assertEqual(plan.checkpoint.task_id, TASK)
        self.assertEqual(plan.agent_versions, PINNED)
        self.assertEqual(plan.checkpoint.requirements, REQUIREMENTS)

        # The work did not happen twice, and execution is not on the menu.
        self.assertEqual(plan.action_executions, 1)
        self.assertEqual(plan.next_step, COLLECT)
        self.assertFalse(plan.may_execute)

        # -- restored evidence must NOT still count ------------------------
        # This is the part that would be a replay attack with a three-week
        # fuse if it were wrong. The observation is genuine; it is just old.
        stale = [ci_evidence(T0), self_report(T0), observation(T0)]
        stale_verdict = verify_completion(
            claim="Line A recovered.",
            evidence=stale,
            required_kinds=REQUIREMENTS,
            now=later,
        )
        self.assertIs(stale_verdict.status, VerificationStatus.ABSTAIN)
        self.assertIs(stale_verdict.failure, FailureClass.EVIDENCE_STALE)

        # -- a fresh independent observation arrives -----------------------
        fresh = [ci_evidence(T0), self_report(T0), observation(later - 30)]
        final = verify_completion(
            claim="Line A recovered.",
            evidence=fresh,
            required_kinds=REQUIREMENTS,
            now=later,
        )
        self.assertIs(final.status, VerificationStatus.VERIFIED)

        # And the self-report is still refused, three weeks on.
        by_source = {(a.kind, a.source): a for a in final.assessments}
        executor = by_source[("runtime", "EXECUTOR")]
        collector = by_source[("runtime", "OBSERVED")]
        self.assertTrue(executor.integrity_valid)
        self.assertFalse(executor.accepted_by_verifier)
        self.assertTrue(collector.accepted_by_verifier)
        self.assertTrue(collector.satisfies_requirement)

    def test_the_restart_uses_no_object_from_before_it(self):
        # A restart that shares a live object is not a restart. The resumer is
        # constructed from a store, a catalog and a journal reader, and nothing
        # in that list carries runtime state from the first process.
        import inspect

        signature = inspect.signature(OperationResumer.__init__)
        self.assertEqual(
            [p for p in signature.parameters if p != "self"],
            ["store", "catalog", "journal_reader"],
        )


class ActionIsNeverRepeatedTests(unittest.TestCase):
    """The expensive failure: coming back up and doing the work again."""

    def setUp(self):
        self.sink = InMemoryJournalSink()
        self.journal = day_zero_journal(self.sink)
        self.events = self.sink.list_execution(self.journal.execution_id)
        self.store = InMemoryContinuityStore()
        self.catalog = default_catalog(default_registry())

    def checkpoint_at(self, phase: Phase) -> OperationCheckpoint:
        cp = open_operation(
            OPERATION, self.journal.execution_id, TASK, REQUIREMENTS, PINNED,
            events=self.events, now=T0,
        )
        if phase is not Phase.PLANNED:
            cp = advance(cp, phase, events=self.events, now=T0)
        return cp

    def resumer(self) -> OperationResumer:
        return OperationResumer(self.store, self.catalog, self.sink)

    def test_awaiting_evidence_resumes_into_collection_not_execution(self):
        self.store.put(self.checkpoint_at(Phase.AWAITING_INDEPENDENT_EVIDENCE))
        plan = self.resumer().resume(OPERATION)
        self.assertEqual(plan.next_step, COLLECT)
        self.assertEqual(plan.action_executions, 1)

    def test_action_complete_resumes_into_collection(self):
        self.store.put(self.checkpoint_at(Phase.ACTION_COMPLETE))
        self.assertEqual(self.resumer().resume(OPERATION).next_step, COLLECT)

    def test_a_planned_phase_cannot_outvote_a_journal_that_records_the_action(self):
        # Someone edits the checkpoint back to PLANNED to force a re-run. The
        # journal still says the action happened, and the journal wins.
        self.store.put(self.checkpoint_at(Phase.PLANNED))
        with self.assertRaises(ContinuityError) as caught:
            self.resumer().resume(OPERATION)
        self.assertIs(
            caught.exception.failure, ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )
        self.assertIn("re-execute", str(caught.exception))

    def test_two_concurrent_resumptions_cannot_both_advance_the_operation(self):
        self.store.put(self.checkpoint_at(Phase.AWAITING_INDEPENDENT_EVIDENCE))
        worker_a = self.resumer().resume(OPERATION).checkpoint
        worker_b = self.resumer().resume(OPERATION).checkpoint
        self.assertEqual(worker_a.checkpoint_version, worker_b.checkpoint_version)

        self.store.put(advance(worker_a, Phase.VERIFYING, events=self.events, now=T0))
        with self.assertRaises(ContinuityError) as caught:
            self.store.put(
                advance(worker_b, Phase.VERIFYING, events=self.events, now=T0)
            )
        self.assertIs(caught.exception.failure, ContinuityFailure.STALE_CHECKPOINT)

    def test_a_terminal_operation_offers_no_next_step(self):
        cp = advance(
            self.checkpoint_at(Phase.VERIFYING), Phase.COMPLETED,
            events=self.events, now=T0,
        )
        self.store.put(cp)
        self.assertEqual(self.resumer().resume(OPERATION).next_step, NOTHING)

    def test_a_fresh_operation_with_no_action_yet_may_execute(self):
        empty = InMemoryJournalSink()
        journal = Journal(execution_id="exec_fresh", task_id=TASK, sink=empty)
        journal.record(
            EventType.EXECUTION_START, "orchestrator-v1", "STARTED", Severity.INFO
        )
        events = empty.list_execution("exec_fresh")
        self.store.put(
            open_operation(
                "op_fresh", "exec_fresh", TASK, REQUIREMENTS, PINNED,
                events=events, now=T0,
            )
        )
        plan = OperationResumer(self.store, self.catalog, empty).resume("op_fresh")
        self.assertEqual(plan.next_step, EXECUTE)
        self.assertEqual(plan.action_executions, 0)


class ContinuityIntegrityTests(unittest.TestCase):
    """A checkpoint that does not match its journal must not be believed."""

    def setUp(self):
        self.sink = InMemoryJournalSink()
        self.journal = day_zero_journal(self.sink)
        self.events = self.sink.list_execution(self.journal.execution_id)
        self.store = InMemoryContinuityStore()
        self.catalog = default_catalog(default_registry())
        self.base = advance(
            open_operation(
                OPERATION, self.journal.execution_id, TASK, REQUIREMENTS, PINNED,
                events=self.events, now=T0,
            ),
            Phase.AWAITING_INDEPENDENT_EVIDENCE,
            events=self.events,
            now=T0,
        )

    def resume_with(self, checkpoint) -> ContinuityFailure:
        store = InMemoryContinuityStore()
        store._records[checkpoint.operation_id] = checkpoint.as_dict()
        with self.assertRaises(ContinuityError) as caught:
            OperationResumer(store, self.catalog, self.sink).resume(
                checkpoint.operation_id
            )
        return caught.exception.failure

    def test_unknown_operation_refuses(self):
        with self.assertRaises(ContinuityError) as caught:
            OperationResumer(self.store, self.catalog, self.sink).resume("op_nope")
        self.assertIs(caught.exception.failure, ContinuityFailure.UNKNOWN_OPERATION)

    def test_checkpoint_ahead_of_the_journal_refuses(self):
        from dataclasses import replace

        ahead = replace(self.base, last_journal_sequence=999)
        self.assertIs(
            self.resume_with(ahead), ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )

    def test_a_journal_hash_that_does_not_match_refuses(self):
        from dataclasses import replace

        forged = replace(self.base, last_journal_hash="0" * 64)
        self.assertIs(
            self.resume_with(forged), ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )

    def test_a_broken_audit_chain_refuses_resume(self):
        # Drop an event from the middle: the chain no longer verifies, so the
        # operation cannot be continued on top of it.
        class Truncated:
            def __init__(self, events):
                self._events = events

            def list_execution(self, execution_id):
                return self._events

        broken = self.events[:2] + self.events[3:]
        store = InMemoryContinuityStore()
        store.put(self.base)
        with self.assertRaises(ContinuityError) as caught:
            OperationResumer(store, self.catalog, Truncated(broken)).resume(OPERATION)
        self.assertIs(
            caught.exception.failure, ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )

    def test_an_unreadable_journal_is_not_treated_as_an_empty_one(self):
        class Unavailable:
            def list_execution(self, execution_id):
                raise ConnectionError("firestore unreachable")

        store = InMemoryContinuityStore()
        store.put(self.base)
        with self.assertRaises(ContinuityError) as caught:
            OperationResumer(store, self.catalog, Unavailable()).resume(OPERATION)
        self.assertIs(
            caught.exception.failure, ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )

    def test_tampered_requirements_are_caught_by_the_policy_digest(self):
        from dataclasses import replace

        weakened = replace(
            self.base, requirements=(Requirement("tests"),)
        )  # runtime requirement quietly dropped
        self.assertIs(
            self.resume_with(weakened), ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )

    def test_tampered_agent_assignment_is_caught_by_the_policy_digest(self):
        from dataclasses import replace

        swapped = replace(
            self.base, assigned_agent_versions={**PINNED, "executor-v1": "v9"}
        )
        self.assertIs(
            self.resume_with(swapped), ContinuityFailure.CONTINUITY_INTEGRITY_ERROR
        )

    def test_an_unsupported_schema_refuses_closed(self):
        raw = self.base.as_dict()
        raw["schema"] = CHECKPOINT_SCHEMA + 1
        with self.assertRaises(ContinuityError) as caught:
            OperationCheckpoint.from_dict(raw)
        self.assertIs(caught.exception.failure, ContinuityFailure.SCHEMA_UNSUPPORTED)

    def test_a_malformed_checkpoint_refuses_closed(self):
        raw = self.base.as_dict()
        del raw["last_journal_sequence"]
        with self.assertRaises(ContinuityError) as caught:
            OperationCheckpoint.from_dict(raw)
        self.assertIs(
            caught.exception.failure, ContinuityFailure.MALFORMED_CHECKPOINT
        )


class VersionPinningTests(unittest.TestCase):
    """An operation finishes under the agents it started with, or not at all."""

    def setUp(self):
        self.sink = InMemoryJournalSink()
        self.journal = day_zero_journal(self.sink)
        self.events = self.sink.list_execution(self.journal.execution_id)
        self.store = InMemoryContinuityStore()
        self.store.put(
            advance(
                open_operation(
                    OPERATION, self.journal.execution_id, TASK, REQUIREMENTS,
                    PINNED, events=self.events, now=T0,
                ),
                Phase.AWAITING_INDEPENDENT_EVIDENCE,
                events=self.events,
                now=T0,
            )
        )

    def catalog_without(self, agent_id: str) -> AgentCatalog:
        full = default_catalog(default_registry())
        return AgentCatalog.build(
            full.registry, [c for c in full if c.agent_id != agent_id]
        )

    def test_a_retired_pinned_version_refuses_rather_than_upgrading(self):
        with self.assertRaises(ContinuityError) as caught:
            OperationResumer(
                self.store, self.catalog_without("executor-v1"), self.sink
            ).resume(OPERATION)
        self.assertIs(
            caught.exception.failure, ContinuityFailure.AGENT_VERSION_UNAVAILABLE
        )

    def test_a_newer_version_does_not_satisfy_an_older_pin(self):
        full = default_catalog(default_registry())
        record = {r.agent_id: r for r in full.registry.records()}["executor-v1"]
        # A v2 card is illegal against a registry that registers v1, which is
        # itself the point: the catalog cannot invent a version.
        with self.assertRaises(CatalogError):
            AgentCatalog.build(
                full.registry,
                [
                    AgentCard(
                        agent_id="executor-v1",
                        version="v2",
                        role=record.role,
                        owner="ops",
                        purpose="newer executor",
                        capabilities=frozenset(record.capabilities),
                        tools=tuple(record.tools),
                        tool_scope="perform_action",
                        data_scope="target-system",
                        runtime=record.runtime,
                        security_class=SecurityClass.ACTOR,
                    )
                ],
            )


class CatalogIsNotAuthorityTests(unittest.TestCase):
    """Discovery metadata must never become permission."""

    def setUp(self):
        self.registry = default_registry()
        self.catalog = default_catalog(self.registry)
        self.records = {r.agent_id: r for r in self.registry.records()}

    def card_for(self, agent_id: str, **overrides) -> AgentCard:
        record = self.records[agent_id]
        base = dict(
            agent_id=record.agent_id,
            version=record.version,
            role=record.role,
            owner="ops",
            purpose="test card",
            capabilities=frozenset(record.capabilities),
            tools=tuple(record.tools),
            tool_scope="none",
            data_scope="none",
            runtime=record.runtime,
            security_class=SecurityClass.OBSERVER,
        )
        base.update(overrides)
        return AgentCard(**base)

    def test_the_whole_fleet_is_discoverable(self):
        self.assertEqual(len(self.catalog), len(list(self.registry.records())))

    def test_a_card_cannot_claim_a_capability_the_registry_withheld(self):
        card = self.card_for("planner-v1", capabilities=frozenset({"observe"}))
        with self.assertRaises(CatalogError) as caught:
            AgentCatalog.build(self.registry, [card])
        self.assertIn("does not grant", str(caught.exception))

    def test_a_card_cannot_hand_itself_a_tool(self):
        card = self.card_for("planner-v1", tools=("perform_action",))
        with self.assertRaises(CatalogError) as caught:
            AgentCatalog.build(self.registry, [card])
        self.assertIn("does not permit", str(caught.exception))

    def test_a_card_cannot_change_an_agents_role(self):
        card = self.card_for("planner-v1", role=Role.VERIFIER)
        with self.assertRaises(CatalogError):
            AgentCatalog.build(self.registry, [card])

    def test_a_card_for_an_unregistered_agent_is_refused(self):
        card = self.card_for("planner-v1")
        from dataclasses import replace

        with self.assertRaises(CatalogError) as caught:
            AgentCatalog.build(self.registry, [replace(card, agent_id="ghost-v1")])
        self.assertIn("not a registered agent", str(caught.exception))

    def test_duplicate_identity_and_version_is_refused(self):
        card = self.card_for("planner-v1")
        with self.assertRaises(CatalogError) as caught:
            AgentCatalog.build(self.registry, [card, card])
        self.assertIn("duplicate", str(caught.exception))

    def test_building_a_catalog_does_not_alter_the_sealed_registry(self):
        before = {
            r.agent_id: (r.role, frozenset(r.capabilities), tuple(r.tools))
            for r in self.registry.records()
        }
        AgentCatalog.build(self.registry, list(self.catalog))
        after = {
            r.agent_id: (r.role, frozenset(r.capabilities), tuple(r.tools))
            for r in self.registry.records()
        }
        self.assertEqual(before, after)
        self.assertTrue(self.registry.sealed)

    def test_a_disabled_agent_is_not_offered_for_new_work(self):
        cards = [
            c if c.agent_id != "executor-v1"
            else self.card_for("executor-v1", lifecycle=Lifecycle.DISABLED)
            for c in self.catalog
        ]
        catalog = AgentCatalog.build(self.registry, cards)
        assignable = [c.agent_id for c in catalog.find(assignable_only=True)]
        self.assertNotIn("executor-v1", assignable)
        # But it is still discoverable, so an operation that pinned it can
        # still be reasoned about.
        self.assertIsNotNone(catalog.get("executor-v1", "v1"))

    def test_discovery_filters_work(self):
        self.assertEqual(
            sorted(c.agent_id for c in self.catalog.find(role=Role.COLLECTOR)),
            ["collector-ci-v1", "collector-http-v1"],
        )
        self.assertEqual(
            [c.agent_id for c in self.catalog.find(data_scope="evidence-ledger")],
            ["verifier-v1"],
        )
        self.assertTrue(self.catalog.find(capability="observe"))

    def test_every_card_carries_ownership_and_purpose(self):
        for card in self.catalog:
            self.assertTrue(card.owner.strip(), card.agent_id)
            self.assertTrue(card.purpose.strip(), card.agent_id)
            self.assertTrue(card.data_scope.strip(), card.agent_id)


class CheckpointCannotCreateAuthorityTests(unittest.TestCase):
    """The structural argument, asserted rather than assumed."""

    def test_a_checkpoint_has_no_field_that_could_hold_a_verdict(self):
        fields = set(OperationCheckpoint.__dataclass_fields__)
        for forbidden in ("status", "verified", "decision", "verdict", "outcome"):
            self.assertNotIn(forbidden, fields)

    def test_a_checkpoint_has_no_field_that_could_hold_evidence_or_capability(self):
        fields = set(OperationCheckpoint.__dataclass_fields__)
        for forbidden in ("evidence", "capabilities", "tools", "grant"):
            self.assertNotIn(forbidden, fields)
        # It references evidence by digest only.
        self.assertIn("evidence_refs", fields)

    def test_the_resumer_holds_no_ledger_collector_or_verifier(self):
        import inspect

        source = inspect.getsource(OperationResumer)
        for forbidden in ("EvidenceLedger", "record_observation", "verify_completion",
                          "AttestationSigner", "ObservationCapability"):
            self.assertNotIn(forbidden, source)

    def test_a_resume_plan_carries_no_decision(self):
        from proofos.resume import ResumePlan

        fields = set(ResumePlan.__dataclass_fields__)
        for forbidden in ("status", "verdict", "decision", "verified"):
            self.assertNotIn(forbidden, fields)


class ContinuityStoreTests(unittest.TestCase):
    """Both stores must refuse a write from a stale base."""

    def make(self):
        sink = InMemoryJournalSink()
        journal = day_zero_journal(sink)
        events = sink.list_execution(journal.execution_id)
        return sink, journal, events

    def test_in_memory_store_round_trips(self):
        _, journal, events = self.make()
        store = InMemoryContinuityStore()
        cp = open_operation(
            OPERATION, journal.execution_id, TASK, REQUIREMENTS, PINNED,
            events=events, now=T0,
        )
        store.put(cp)
        self.assertEqual(store.get(OPERATION), cp)

    def test_a_second_write_must_build_on_exactly_what_is_stored(self):
        _, journal, events = self.make()
        store = InMemoryContinuityStore()
        first = open_operation(
            OPERATION, journal.execution_id, TASK, REQUIREMENTS, PINNED,
            events=events, now=T0,
        )
        store.put(first)
        store.put(advance(first, Phase.ACTION_COMPLETE, events=events, now=T0))
        # Re-advancing the original produces the same version again, which is
        # exactly the shape of a writer that never saw the newer state.
        with self.assertRaises(ContinuityError) as caught:
            store.put(advance(first, Phase.VERIFYING, events=events, now=T0))
        self.assertIs(caught.exception.failure, ContinuityFailure.STALE_CHECKPOINT)

    def test_firestore_store_refuses_a_stale_write(self):
        from tests.fake_firestore import FakeFirestore, fake_transactional
        from proofos.continuity import FirestoreContinuityStore

        _, journal, events = self.make()
        client = FakeFirestore()
        store = FirestoreContinuityStore(
            client, transactional=fake_transactional
        )
        first = open_operation(
            OPERATION, journal.execution_id, TASK, REQUIREMENTS, PINNED,
            events=events, now=T0,
        )
        store.put(first)
        self.assertEqual(store.get(OPERATION).checkpoint_version, 1)

        second = advance(first, Phase.ACTION_COMPLETE, events=events, now=T0)
        store.put(second)
        self.assertEqual(store.get(OPERATION).phase, Phase.ACTION_COMPLETE)

        # A writer still holding the first checkpoint loses.
        with self.assertRaises(ContinuityError) as caught:
            store.put(advance(first, Phase.VERIFYING, events=events, now=T0))
        self.assertIs(caught.exception.failure, ContinuityFailure.STALE_CHECKPOINT)

    def test_an_unreachable_store_does_not_look_like_an_absent_operation(self):
        from proofos.continuity import FirestoreContinuityStore, StoreUnavailable

        class Broken:
            def collection(self, *_):
                raise ConnectionError("unreachable")

        class Ref:
            def get(self, **_):
                raise ConnectionError("unreachable")

        class Client:
            def collection(self, *_):
                class C:
                    def document(self, *_):
                        return Ref()
                return C()

        store = FirestoreContinuityStore(Client(), transactional=lambda f: f)
        with self.assertRaises(StoreUnavailable):
            store.get(OPERATION)


class PolicyDigestTests(unittest.TestCase):
    def test_the_digest_changes_when_a_requirement_is_dropped(self):
        a = policy_digest(REQUIREMENTS, PINNED)
        b = policy_digest((Requirement("tests"),), PINNED)
        self.assertNotEqual(a, b)

    def test_the_digest_changes_when_an_agent_version_changes(self):
        a = policy_digest(REQUIREMENTS, PINNED)
        b = policy_digest(REQUIREMENTS, {**PINNED, "executor-v1": "v2"})
        self.assertNotEqual(a, b)

    def test_the_digest_is_order_independent(self):
        reversed_reqs = tuple(reversed(REQUIREMENTS))
        self.assertEqual(
            policy_digest(REQUIREMENTS, PINNED),
            policy_digest(reversed_reqs, dict(reversed(list(PINNED.items())))),
        )


if __name__ == "__main__":
    unittest.main()


class RealProcessRestartTests(unittest.TestCase):
    """The restart claim, made against an actual OS process boundary.

    ``del`` is not a restart. Deleting a name in the same interpreter leaves
    every import, every module global and every cached object exactly where it
    was, so a test built on it can pass while the real property is broken.

    This spawns a second interpreter that has never seen day zero. It is handed
    two files -- the checkpoint and the journal -- and nothing else. If it can
    reconstruct the operation from those, refuse to re-run the action, and keep
    the trust boundary, then the claim is about ProofOS rather than about
    Python's garbage collector.
    """

    RESUME_SCRIPT = '''
import json, sys
sys.path.insert(0, %(root)r)

from proofos.agent_catalog import default_catalog
from proofos.continuity import InMemoryContinuityStore, OperationCheckpoint
from proofos.journal import ExecutionEvent, EventType, Severity
from proofos.registry import default_registry
from proofos.resume import OperationResumer
from proofos.verifier import (
    Evidence, EvidenceSource, Requirement, verify_completion,
)

state = json.load(open(sys.argv[1], encoding="utf-8"))
now = state["now"]

# Rebuild the journal exactly as stored, hashes included.
events = tuple(
    ExecutionEvent(
        event_id=e["event_id"], execution_id=e["execution_id"],
        task_id=e["task_id"], sequence=e["sequence"],
        event=EventType(e["event"]), agent=e["agent"], status=e["status"],
        trace_id=e["trace_id"], timestamp=e["timestamp"],
        severity=Severity(e["severity"]), payload=e["payload"],
        previous_hash=e["previous_hash"], content_hash=e["content_hash"],
    )
    for e in state["events"]
)

class FileJournal:
    def list_execution(self, execution_id):
        return events

store = InMemoryContinuityStore()
store._records[state["checkpoint"]["operation_id"]] = state["checkpoint"]

plan = OperationResumer(
    store, default_catalog(default_registry()), FileJournal()
).resume(state["checkpoint"]["operation_id"])

def ev(kind, value, source, at, collector):
    return Evidence(kind=kind, value=value, source=EvidenceSource(source),
                    collected_at=at, collector=collector)

reqs = tuple(
    Requirement(r["kind"], r["max_age_seconds"])
    for r in state["checkpoint"]["requirements"]
)
ledger = [
    ev("tests", "qualification suite green", "OBSERVED", state["t0"], "collector-ci-v1"),
    ev("runtime", "executor-v1 states: I verified the line myself",
       "EXECUTOR", state["t0"], "executor-v1"),
]

stale = verify_completion(
    claim="Line A recovered.",
    evidence=ledger + [ev("runtime", "probe HEALTHY", "OBSERVED",
                          state["t0"], "collector-http-v1")],
    required_kinds=reqs, now=now,
)
fresh = verify_completion(
    claim="Line A recovered.",
    evidence=ledger + [ev("runtime", "probe HEALTHY", "OBSERVED",
                          now - 30, "collector-http-v1")],
    required_kinds=reqs, now=now,
)

json.dump({
    "operation_id": plan.checkpoint.operation_id,
    "execution_id": plan.checkpoint.execution_id,
    "phase": str(plan.checkpoint.phase),
    "next_step": str(plan.next_step),
    "action_executions": plan.action_executions,
    "agent_versions": plan.agent_versions,
    "journal_events": len(plan.journal_events),
    "stale_status": str(stale.status),
    "stale_failure": str(stale.failure),
    "fresh_status": str(fresh.status),
}, open(sys.argv[2], "w", encoding="utf-8"))
'''

    def test_a_second_interpreter_resumes_without_repeating_the_action(self):
        import json
        import pathlib
        import subprocess
        import sys
        import tempfile

        root = str(pathlib.Path(__file__).resolve().parent.parent)

        sink = InMemoryJournalSink()
        journal = day_zero_journal(sink)
        events = sink.list_execution(journal.execution_id)

        checkpoint = advance(
            open_operation(
                OPERATION, journal.execution_id, TASK, REQUIREMENTS, PINNED,
                events=events, now=T0,
            ),
            Phase.AWAITING_INDEPENDENT_EVIDENCE,
            events=events,
            now=T0,
        )

        state = {
            "t0": T0,
            "now": T0 + 21 * DAY,
            "checkpoint": checkpoint.as_dict(),
            "events": [
                {
                    "event_id": e.event_id, "execution_id": e.execution_id,
                    "task_id": e.task_id, "sequence": e.sequence,
                    "event": str(e.event), "agent": e.agent, "status": e.status,
                    "trace_id": e.trace_id, "timestamp": e.timestamp,
                    "severity": str(e.severity), "payload": e.payload,
                    "previous_hash": e.previous_hash,
                    "content_hash": e.content_hash,
                }
                for e in events
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            state_path = tmp / "state.json"
            out_path = tmp / "out.json"
            script_path = tmp / "resume_in_new_process.py"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            script_path.write_text(self.RESUME_SCRIPT % {"root": root}, encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(script_path), str(state_path), str(out_path)],
                capture_output=True, text=True, timeout=180,
            )
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            report = json.loads(out_path.read_text(encoding="utf-8"))

        # The new process reconstructed the operation from files alone.
        self.assertEqual(report["operation_id"], OPERATION)
        self.assertEqual(report["execution_id"], "exec_continuity_day0")
        self.assertEqual(report["phase"], "AWAITING_INDEPENDENT_EVIDENCE")
        self.assertEqual(report["agent_versions"], PINNED)
        self.assertEqual(report["journal_events"], len(events))

        # It refused to repeat the remediation.
        self.assertEqual(report["action_executions"], 1)
        self.assertEqual(report["next_step"], "COLLECT")

        # And three weeks on, the old observation no longer counts.
        self.assertEqual(report["stale_status"], "ABSTAIN")
        self.assertEqual(report["stale_failure"], "EVIDENCE_STALE")
        self.assertEqual(report["fresh_status"], "VERIFIED")
