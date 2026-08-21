"""The ProofOS fleet: five roles, each holding only what it may use.

There is no RuntimeContext handed to everybody. Each role is constructed with a
context containing exactly its capabilities, so the authority model is visible
in the constructor signatures rather than asserted in a docstring.

What the executor is given is the point of the whole design:

    ExecutorContext(claim, audit, sender)

It has no ledger, no observation capability, no read access to evidence, and no
verifier. Not "does not call them" -- does not hold them. An executor that
decides to cheat has nothing to cheat with.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:  # pragma: no cover
    from proofos_agent.collector_client import CollectorClient

from proofos.capabilities import (
    AuditCapability,
    ClaimCapability,
    EvidenceReadCapability,
    ObservationCapability,
    TaskAdminCapability,
    VerificationCapability,
)
from proofos.failures import AuthorityFailure, CapabilityDenied
from proofos.journal import EventType, Journal, Severity
from proofos.ledger import EvidenceLedger
from proofos.messages import MessageBus, MessageSender, MessageType
from proofos.ingestion import AttestationIngestor, IngestionResult, RejectionReason
from proofos.probe import ProbeResult, probe_health
from proofos.registry import (
    COLLECTOR_CI_ID,
    COLLECTOR_ID,
    EXECUTOR_ID,
    ORCHESTRATOR_ID,
    PLANNER_ID,
    VERIFIER_ID,
    AgentRegistry,
)
from proofos.verifier import Requirement, VerificationStatus


# -- scoped contexts -----------------------------------------------------------


@dataclass(frozen=True)
class PlannerContext:
    agent_id: str
    audit: AuditCapability
    sender: MessageSender


@dataclass(frozen=True)
class ExecutorContext:
    """Everything the executor is allowed to touch. Note what is absent."""

    agent_id: str
    claim: ClaimCapability
    audit: AuditCapability
    sender: MessageSender


@dataclass(frozen=True)
class CollectorContext:
    agent_id: str
    observation: ObservationCapability
    audit: AuditCapability
    sender: MessageSender


@dataclass(frozen=True)
class VerifierContext:
    agent_id: str
    verification: VerificationCapability
    audit: AuditCapability
    sender: MessageSender


@dataclass(frozen=True)
class OrchestratorContext:
    agent_id: str
    tasks: TaskAdminCapability
    audit: AuditCapability
    sender: MessageSender
    bus: MessageBus
    registry: AgentRegistry


# -- roles ---------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    task_id: str
    steps: tuple[str, ...]
    required_kinds: tuple[Requirement, ...]


class Planner:
    """Decides what to do and what would prove it was done.

    Declaring requirements is deliberately *proposed* here and enacted by the
    orchestrator: the planner has no ledger capability, so it cannot open a task
    with no requirements and clear the bar for everyone downstream.
    """

    def __init__(self, context: PlannerContext) -> None:
        self._ctx = context

    def plan(self, task_id: str, goal: str, required_kinds) -> Plan:
        self._ctx.audit.record(
            EventType.AGENT_TURN, "PLANNED", goal=goal, task_id=task_id
        )
        self._ctx.sender.send(
            ORCHESTRATOR_ID, MessageType.PLAN, goal=goal, task_id=task_id
        )
        return Plan(task_id=task_id, steps=(goal,), required_kinds=tuple(required_kinds))


@dataclass(frozen=True)
class ExecutionClaim:
    task_id: str
    text: str
    agent_id: str


class Executor:
    """Performs the work and says what it did.

    It can write to the ledger, but only through ClaimCapability, which stamps
    EXECUTOR on everything. That is a self-report: recorded, auditable, and
    incapable of satisfying a requirement.
    """

    def __init__(self, context: ExecutorContext) -> None:
        self._ctx = context

    def execute(self, task_id: str, action: Callable[[], str]) -> str:
        result = action()
        self._ctx.audit.record(
            EventType.AGENT_TURN, "ACTION_EXECUTED", task_id=task_id
        )
        return result

    def claim_success(self, task_id: str, text: str) -> ExecutionClaim:
        """State that the work is done, and self-report the runtime as healthy.

        The self-report is recorded rather than discarded, because the audit
        trail should show exactly what the executor asserted -- including the
        part the verifier will refuse to count.
        """
        self._ctx.claim.record_claim(
            task_id,
            kind="runtime",
            value=f"{self._ctx.agent_id} states: I verified the service myself",
        )
        self._ctx.audit.record(EventType.CLAIM_RECEIVED, "CLAIMED_SUCCESS", claim=text)
        self._ctx.sender.send(ORCHESTRATOR_ID, MessageType.CLAIM, claim=text)
        return ExecutionClaim(task_id=task_id, text=text, agent_id=self._ctx.agent_id)


class Collector:
    """Observes the world and records what it saw.

    Deterministic on purpose. Its job is a bounded network probe; adding a
    language model would insert an untrusted step into the one path that has to
    stay observable.
    """

    def __init__(self, context: CollectorContext) -> None:
        self._ctx = context

    def collect_runtime(
        self, task_id: str, url: str, timeout: float
    ) -> ProbeResult:
        self._ctx.audit.record(
            EventType.RECOVERY_START, "COLLECTING", kind="runtime", url=url
        )
        result = probe_health(url, timeout)

        if result.observed_response:
            self._ctx.observation.record_observation(
                task_id,
                kind="runtime",
                value=f"probe {result.outcome.value}: {result.detail}",
                satisfies=result.healthy,
            )
            self._ctx.audit.record(
                EventType.EVIDENCE_COLLECTED,
                result.outcome.value,
                kind="runtime",
                satisfies_requirement=result.healthy,
                detail=result.detail,
            )
        else:
            # Nothing came back, so nothing was observed and nothing is written.
            self._ctx.audit.record(
                EventType.EVIDENCE_REJECTED,
                result.outcome.value,
                Severity.WARNING,
                kind="runtime",
                detail=result.detail,
            )

        self._ctx.sender.send(
            ORCHESTRATOR_ID,
            MessageType.EVIDENCE_RESULT,
            outcome=result.outcome.value,
            recorded=result.observed_response,
        )
        return result


@dataclass(frozen=True)
class VerificationDecision:
    status: str
    reason: str
    missing: tuple[str, ...]
    failure: str


class Verifier:
    """Judges. Cannot act, cannot observe, cannot write evidence."""

    def __init__(self, context: VerifierContext) -> None:
        self._ctx = context

    def verify(self, task_id: str, claim: str) -> VerificationDecision:
        result = self._ctx.verification.verify(task_id, claim)
        decision = VerificationDecision(
            status=result.status.value,
            reason=result.reason,
            missing=result.missing,
            failure=result.failure.value,
        )
        self._ctx.audit.record(
            EventType.VERIFIER_DECISION,
            decision.status,
            Severity.INFO
            if result.status is VerificationStatus.VERIFIED
            else Severity.WARNING,
            failure=decision.failure,
            missing=list(decision.missing),
            reason=decision.reason,
        )
        self._ctx.sender.send(
            ORCHESTRATOR_ID,
            MessageType.VERIFY_RESULT,
            status=decision.status,
            missing=list(decision.missing),
        )
        return decision


# -- construction --------------------------------------------------------------


class CiCollector:
    """Records an observed CI result.

    Separate from the HTTP collector, and scoped to a different evidence kind:
    neither collector can write the other's evidence. Compromising the probe
    does not let you fabricate a passing test run.
    """

    def __init__(self, context: CollectorContext) -> None:
        self._ctx = context

    def record_ci_result(self, task_id: str, summary: str) -> None:
        self._ctx.observation.record_observation(
            task_id, kind="tests", value=summary, satisfies=True
        )
        self._ctx.audit.record(
            EventType.EVIDENCE_COLLECTED, "CI_RESULT", kind="tests"
        )


@dataclass(frozen=True)
class Fleet:
    planner: Planner
    executor: Executor
    collector: Collector
    ci_collector: CiCollector
    verifier: Verifier
    orchestrator_context: OrchestratorContext
    bus: MessageBus
    registry: AgentRegistry
    #: Observation capabilities reserved for the attestation ingestor, created
    #: before the ledger is sealed. Held by the ingestor alone.
    ingestor_capabilities: dict = None


def build_fleet(
    ledger: EvidenceLedger,
    journal: Journal,
    registry: AgentRegistry,
    task_id: str,
    collector_kinds: tuple[str, ...] = ("runtime",),
    ingestor_collectors: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> Fleet:
    """Wire the fleet, giving each role only its own capabilities.

    Every capability is constructed here, once, with a fixed agent id. Nothing
    downstream can mint a wider one, because nothing downstream is handed the
    ledger.
    """
    bus = MessageBus(registry, execution_id=journal.execution_id, task_id=task_id)

    def audit(agent_id: str) -> AuditCapability:
        return AuditCapability(journal, agent_id)

    planner = Planner(
        PlannerContext(
            agent_id=PLANNER_ID,
            audit=audit(PLANNER_ID),
            sender=bus.sender_for(PLANNER_ID),
        )
    )
    executor = Executor(
        ExecutorContext(
            agent_id=EXECUTOR_ID,
            claim=ClaimCapability(ledger, EXECUTOR_ID),
            audit=audit(EXECUTOR_ID),
            sender=bus.sender_for(EXECUTOR_ID),
        )
    )
    collector = Collector(
        CollectorContext(
            agent_id=COLLECTOR_ID,
            observation=ObservationCapability(ledger, COLLECTOR_ID, collector_kinds),
            audit=audit(COLLECTOR_ID),
            sender=bus.sender_for(COLLECTOR_ID),
        )
    )
    ci_collector = CiCollector(
        CollectorContext(
            agent_id=COLLECTOR_CI_ID,
            observation=ObservationCapability(ledger, COLLECTOR_CI_ID, ("tests",)),
            audit=audit(COLLECTOR_CI_ID),
            sender=bus.sender_for(COLLECTOR_CI_ID),
        )
    )
    verifier = Verifier(
        VerifierContext(
            agent_id=VERIFIER_ID,
            verification=VerificationCapability(
                EvidenceReadCapability(ledger, VERIFIER_ID), VERIFIER_ID
            ),
            audit=audit(VERIFIER_ID),
            sender=bus.sender_for(VERIFIER_ID),
        )
    )
    orchestrator_context = OrchestratorContext(
        agent_id=ORCHESTRATOR_ID,
        tasks=TaskAdminCapability(ledger, ORCHESTRATOR_ID),
        audit=audit(ORCHESTRATOR_ID),
        sender=bus.sender_for(ORCHESTRATOR_ID),
        bus=bus,
        registry=registry,
    )

    # Capabilities the attestation ingestor will hold, on behalf of collectors
    # running in other processes. Created before sealing; handed to nothing else.
    ingestor_capabilities = {
        collector_id: ObservationCapability(ledger, collector_id, kinds)
        for collector_id, kinds in ingestor_collectors
    }

    # Every grant has now been issued. Seal so no component -- including one
    # that somehow reaches the ledger -- can mint itself new authority.
    ledger.seal()

    return Fleet(
        planner=planner,
        executor=executor,
        collector=collector,
        ci_collector=ci_collector,
        verifier=verifier,
        orchestrator_context=orchestrator_context,
        bus=bus,
        registry=registry,
        ingestor_capabilities=ingestor_capabilities,
    )


__all__ = [
    "AttestedCollector",
    "AttestedCollectorContext",
    "CiCollector",
    "Collector",
    "CollectorContext",
    "ExecutionClaim",
    "Executor",
    "ExecutorContext",
    "Fleet",
    "Plan",
    "Planner",
    "PlannerContext",
    "OrchestratorContext",
    "VerificationDecision",
    "Verifier",
    "VerifierContext",
    "build_fleet",
    "AuthorityFailure",
    "CapabilityDenied",
]


@dataclass(frozen=True)
class AttestedCollectorContext:
    """What the relaying side of a process-separated collection holds.

    It can ask the collector process to look at something, and it can hand the
    reply to the ingestor. It holds no signing key, so it cannot author an
    attestation, and it holds no observation capability of its own -- the
    ingestor's is reachable only behind a signature check it cannot satisfy.
    """

    agent_id: str
    client: "CollectorClient"
    ingestor: "AttestationIngestor"
    profile_id: str
    audit: AuditCapability
    sender: MessageSender


class AttestedCollector:
    """Requests an observation from the collector process and relays the reply.

    Relay is all it does. Every field that matters is inside the collector's
    signature, so altering any of them in transit invalidates the attestation
    rather than changing what gets recorded.
    """

    def __init__(self, context: AttestedCollectorContext) -> None:
        self._ctx = context

    def collect_runtime(
        self,
        execution_id: str,
        task_id: str,
        kind: str = "runtime",
        max_age_seconds: float | None = None,
    ):
        from proofos_agent.collector_client import CollectorUnavailable

        # The nonce is minted here, before the request, so the collector cannot
        # answer a question it was not asked.
        nonce = self._ctx.ingestor.issue_nonce(execution_id, task_id, kind)
        self._ctx.audit.record(
            EventType.COLLECTION_REQUESTED,
            "REQUESTED",
            kind=kind,
            profile_id=self._ctx.profile_id,
        )

        try:
            attestation = self._ctx.client.collect(
                execution_id=execution_id,
                task_id=task_id,
                evidence_kind=kind,
                profile_id=self._ctx.profile_id,
                request_nonce=nonce,
            )
        except CollectorUnavailable as exc:
            self._ctx.audit.record(
                EventType.EVIDENCE_REJECTED,
                AuthorityFailure.COLLECTOR_UNAVAILABLE.value,
                Severity.WARNING,
                kind=kind,
                detail=str(exc),
            )
            return IngestionResult(
                accepted=False, detail=str(exc), reason=RejectionReason.MALFORMED
            )

        self._ctx.audit.record(
            EventType.COLLECTOR_RESPONSE_RECEIVED, "RECEIVED", kind=kind
        )

        result = self._ctx.ingestor.ingest(
            attestation,
            execution_id=execution_id,
            task_id=task_id,
            expected_kind=kind,
            expected_profile=self._ctx.profile_id,
            expected_nonce=nonce,
            max_age_seconds=max_age_seconds,
        )

        if not result.accepted:
            # Reason codes only. The rejected payload is attacker-influenced
            # and does not belong in durable storage.
            self._ctx.audit.record(
                EventType.ATTESTATION_REJECTED,
                str(result.reason),
                Severity.WARNING,
                kind=kind,
            )
            return result

        self._ctx.audit.record(
            EventType.ATTESTATION_ACCEPTED,
            result.outcome.value,
            kind=kind,
            duplicate=result.duplicate,
        )
        self._ctx.audit.record(
            EventType.EVIDENCE_COLLECTED,
            result.outcome.value,
            Severity.INFO if result.satisfies_requirement else Severity.WARNING,
            kind=kind,
            satisfies_requirement=result.satisfies_requirement,
        )
        return result
