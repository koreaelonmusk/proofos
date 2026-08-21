"""Scoped capabilities.

The authority boundary in ProofOS is not a prompt and not a comment. It is
which object a component is holding.

A component receives a narrow capability that can only do its job. The executor
holds a capability that is *structurally incapable* of producing OBSERVED
evidence -- not one that is asked politely not to. The collector holds one that
can write observations but has no way to reach a verdict. The verifier holds a
read-only view and a deterministic rule engine, and no way to act on the world.

Capabilities keep their backing store in a private attribute and expose no
accessor for it, so holding a narrow capability does not hand you a wide one.
Python offers no true private state, so this is enforced by construction and by
tests that walk an object's reachable references -- not by the interpreter. That
limit is real and is stated plainly rather than papered over.
"""

from __future__ import annotations

import time
from typing import Iterable

from .failures import CapabilityDenied
from .journal import EventType, Journal, Severity
from .ledger import EvidenceLedger, ObservationGrant
from .verifier import (
    Evidence,
    EvidenceSource,
    Requirement,
    VerificationResult,
    verify_completion,
)


class Capability:
    """Names of the authorities a role may hold.

    Kept as plain constants so a registry can reason about them as data without
    importing the objects that implement them.
    """

    PLAN = "plan"
    EXECUTE = "execute"
    CLAIM = "claim"
    OBSERVE = "observe"
    WRITE_OBSERVED_EVIDENCE = "write_observed_evidence"
    READ_EVIDENCE = "read_evidence"
    VERIFY = "verify"
    APPEND_AUDIT = "append_audit"
    ORCHESTRATE = "orchestrate"
    REQUEST_RECOVERY = "request_recovery"

    ALL = frozenset(
        {
            PLAN,
            EXECUTE,
            CLAIM,
            OBSERVE,
            WRITE_OBSERVED_EVIDENCE,
            READ_EVIDENCE,
            VERIFY,
            APPEND_AUDIT,
            ORCHESTRATE,
            REQUEST_RECOVERY,
        }
    )


class ClaimCapability:
    """What the executor holds.

    It can say what it did. Everything it writes is stamped EXECUTOR, which the
    verifier can never count toward a requirement. There is no argument, flag,
    or method here that produces OBSERVED evidence -- the source is not a
    parameter, it is a constant of the class.
    """

    __slots__ = ("_ledger", "agent_id")

    def __init__(self, ledger: EvidenceLedger, agent_id: str) -> None:
        self._ledger = ledger
        self.agent_id = agent_id

    def record_claim(self, task_id: str, kind: str, value: str) -> Evidence:
        """Record a self-report. Never satisfies a requirement."""
        evidence = Evidence(
            kind=kind,
            value=value,
            source=EvidenceSource.EXECUTOR,
            collected_at=time.time(),
            collector=self.agent_id,
        )
        self._ledger.record(task_id, evidence)
        return evidence


class ObservationCapability:
    """What a collector holds.

    It can write OBSERVED evidence, but only for the evidence kinds it was
    scoped to, and only stamped with its own runtime-assigned identity. It has
    no path to a verdict: nothing here returns or writes a verification result.
    """

    __slots__ = ("_ledger", "agent_id", "_grant")

    def __init__(
        self,
        ledger: EvidenceLedger,
        agent_id: str,
        allowed_kinds: Iterable[str],
    ) -> None:
        self._ledger = ledger
        self.agent_id = agent_id
        # The grant is the authority. Holding this capability is what makes an
        # OBSERVED write possible; reaching the ledger without one does not.
        self._grant: ObservationGrant = ledger.grant_observation(
            agent_id, tuple(allowed_kinds)
        )

    @property
    def allowed_kinds(self) -> frozenset[str]:
        return self._grant.kinds

    def record_observation(
        self,
        task_id: str,
        kind: str,
        value: str,
        satisfies: bool,
        collected_at: float | None = None,
    ) -> Evidence:
        """Record something actually observed.

        ``satisfies`` says whether the observation met its contract. It does not
        say whether the task is complete -- that is the verifier's judgement,
        made over every requirement, and this capability cannot reach it.
        """
        evidence = Evidence(
            kind=kind,
            value=value,
            source=EvidenceSource.OBSERVED,
            valid=satisfies,
            collected_at=time.time() if collected_at is None else collected_at,
            collector=self.agent_id,
        )
        self._ledger.record(task_id, evidence, self._grant)
        return evidence


class EvidenceReadCapability:
    """A read-only view of the ledger. Holding it grants no way to write."""

    __slots__ = ("_ledger", "agent_id")

    def __init__(self, ledger: EvidenceLedger, agent_id: str) -> None:
        self._ledger = ledger
        self.agent_id = agent_id

    def requirements(self, task_id: str) -> tuple[Requirement, ...]:
        return self._ledger.requirements(task_id)

    def evidence(self, task_id: str) -> tuple[Evidence, ...]:
        return self._ledger.evidence(task_id)

    def knows(self, task_id: str) -> bool:
        return self._ledger.knows(task_id)


class VerificationCapability:
    """What the verifier holds: read access and a deterministic rule engine.

    There is no method here that performs work, collects evidence, or writes to
    the ledger. The verifier can judge and nothing else, which is what stops it
    from manufacturing the evidence it then judges.
    """

    __slots__ = ("_reader", "agent_id")

    def __init__(self, reader: EvidenceReadCapability, agent_id: str) -> None:
        self._reader = reader
        self.agent_id = agent_id

    def verify(self, task_id: str, claim: str) -> VerificationResult:
        return verify_completion(
            claim=claim,
            evidence=self._reader.evidence(task_id),
            required_kinds=self._reader.requirements(task_id),
        )


class AuditCapability:
    """Append to the execution journal under a fixed, runtime-assigned identity.

    The agent name on an audit record comes from this object, not from anything
    the caller passes, so a component cannot write history as someone else.
    """

    __slots__ = ("_journal", "agent_id")

    def __init__(self, journal: Journal, agent_id: str) -> None:
        self._journal = journal
        self.agent_id = agent_id

    @property
    def execution_id(self) -> str:
        return self._journal.execution_id

    def record(
        self,
        event: EventType,
        status: str,
        severity: Severity = Severity.INFO,
        **payload,
    ):
        return self._journal.record(event, self.agent_id, status, severity, **payload)


class TaskAdminCapability:
    """Opening a task and declaring what would prove it.

    Held by the orchestrator alone. If an executor could declare requirements it
    could declare none, and an empty requirement set is the shortest path to
    certifying your own work.
    """

    __slots__ = ("_ledger", "agent_id")

    def __init__(self, ledger: EvidenceLedger, agent_id: str) -> None:
        self._ledger = ledger
        self.agent_id = agent_id

    def open_task(
        self, task_id: str, required_kinds: tuple[Requirement, ...]
    ) -> None:
        if not required_kinds:
            raise CapabilityDenied(
                self.agent_id,
                "open a task with no requirements",
                "a task nothing can fail is not a task",
            )
        self._ledger.open_task(task_id, required_kinds)
