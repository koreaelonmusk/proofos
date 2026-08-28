"""Durable operation context for work that outlives the process running it.

An incident opened on a Monday can still be waiting for evidence three weeks
later, long after the process that opened it has gone. ProofOS already survives
that at the audit layer -- the journal is durable and hash-chained -- but the
runtime had no way to pick an operation back up and continue it safely.

This module adds that, under one rule that shapes everything else:

    A checkpoint is a bookmark, not a verdict.

So ``OperationCheckpoint`` has no field for a decision, no field for evidence
content, and no field for capabilities. There is nothing here to forge, because
there is nothing here that a forgery would buy. It remembers *where* an
operation got to and *who* was assigned; the answer to "is it complete?" still
comes from the verification kernel reading the ledger, every single time.

Two consequences worth stating plainly:

* Restored evidence references do not restore evidence. A three-week-old
  observation is still three weeks old, and a requirement with a freshness
  horizon will refuse it. Resuming an operation does not resurrect its proof.
* Restored phase does not restore permission. The phase can only ever narrow
  what happens next, never widen it -- an operation that has already acted can
  move toward collection and verification, and can never move back to acting.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Iterable, Protocol

from .integrity import content_hash
from .journal import ExecutionEvent, verify_events
from .verifier import Requirement

#: Bumped when the stored shape changes in a way older readers cannot handle.
#: An unknown version refuses closed rather than being parsed optimistically.
CHECKPOINT_SCHEMA = 1


class Phase(StrEnum):
    """How far an operation has got. The smallest set that is still truthful."""

    PLANNED = "PLANNED"
    ACTION_COMPLETE = "ACTION_COMPLETE"
    AWAITING_INDEPENDENT_EVIDENCE = "AWAITING_INDEPENDENT_EVIDENCE"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    ABSTAINED = "ABSTAINED"


#: Phases from which the executor may still be called. Everything after the
#: action has run is one-way: the classic restart bug is a process coming back
#: up and doing the work a second time.
MAY_EXECUTE = frozenset({Phase.PLANNED})

TERMINAL = frozenset({Phase.COMPLETED, Phase.ABSTAINED})


class ContinuityFailure(StrEnum):
    """Why an operation could not be safely continued. None means success."""

    NONE = "NONE"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    STALE_CHECKPOINT = "STALE_CHECKPOINT"
    CONTINUITY_INTEGRITY_ERROR = "CONTINUITY_INTEGRITY_ERROR"
    AGENT_VERSION_UNAVAILABLE = "AGENT_VERSION_UNAVAILABLE"
    AGENT_VERSION_MISMATCH = "AGENT_VERSION_MISMATCH"
    SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"
    MALFORMED_CHECKPOINT = "MALFORMED_CHECKPOINT"
    OPERATION_TERMINAL = "OPERATION_TERMINAL"


class ContinuityError(RuntimeError):
    """Raised when continuity state cannot be trusted. Never downgraded."""

    def __init__(self, failure: ContinuityFailure, detail: str) -> None:
        super().__init__(f"{failure}: {detail}")
        self.failure = failure
        self.detail = detail


class StoreUnavailable(ContinuityError):
    """The store could not answer. Absence of an answer is not absence of work."""

    def __init__(self, detail: str) -> None:
        super().__init__(ContinuityFailure.STORE_UNAVAILABLE, detail)


@dataclass(frozen=True)
class OperationCheckpoint:
    """Where an operation got to, and who was assigned. Nothing more.

    Note what is absent: no status, no verdict, no evidence values, no
    capabilities. ``evidence_refs`` holds content hashes so a reader can tell
    whether the ledger it has matches the ledger the checkpoint was written
    against -- it is an integrity aid, not a way to carry proof forward.
    """

    operation_id: str
    execution_id: str
    task_id: str
    phase: Phase
    #: agent_id -> pinned version. Resume resolves these exactly or refuses.
    assigned_agent_versions: dict[str, str]
    requirements: tuple[Requirement, ...]
    #: Digest of the requirements and pinned versions, so a tampered checkpoint
    #: is detectable without trusting any single field.
    policy_digest: str
    evidence_refs: tuple[str, ...]
    last_journal_sequence: int
    last_journal_hash: str
    created_at: float
    updated_at: float
    checkpoint_version: int = 1
    schema: int = CHECKPOINT_SCHEMA

    def as_dict(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "phase": str(self.phase),
            "assigned_agent_versions": dict(self.assigned_agent_versions),
            "requirements": [
                {"kind": r.kind, "max_age_seconds": r.max_age_seconds}
                for r in self.requirements
            ],
            "policy_digest": self.policy_digest,
            "evidence_refs": list(self.evidence_refs),
            "last_journal_sequence": self.last_journal_sequence,
            "last_journal_hash": self.last_journal_hash,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "checkpoint_version": self.checkpoint_version,
            "schema": self.schema,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "OperationCheckpoint":
        try:
            schema = int(data["schema"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ContinuityError(
                ContinuityFailure.MALFORMED_CHECKPOINT, f"unreadable schema: {exc}"
            ) from exc
        if schema != CHECKPOINT_SCHEMA:
            raise ContinuityError(
                ContinuityFailure.SCHEMA_UNSUPPORTED,
                f"checkpoint schema {schema} is not supported by this build "
                f"(expected {CHECKPOINT_SCHEMA})",
            )
        try:
            return cls(
                operation_id=data["operation_id"],
                execution_id=data["execution_id"],
                task_id=data["task_id"],
                phase=Phase(data["phase"]),
                assigned_agent_versions=dict(data["assigned_agent_versions"]),
                requirements=tuple(
                    Requirement(r["kind"], r.get("max_age_seconds"))
                    for r in data["requirements"]
                ),
                policy_digest=data["policy_digest"],
                evidence_refs=tuple(data.get("evidence_refs", ())),
                last_journal_sequence=int(data["last_journal_sequence"]),
                last_journal_hash=data["last_journal_hash"],
                created_at=float(data["created_at"]),
                updated_at=float(data["updated_at"]),
                checkpoint_version=int(data["checkpoint_version"]),
                schema=schema,
            )
        except ContinuityError:
            raise
        except Exception as exc:  # noqa: BLE001 - any malformation fails closed
            raise ContinuityError(
                ContinuityFailure.MALFORMED_CHECKPOINT,
                f"{type(exc).__name__}: {exc}",
            ) from exc


def policy_digest(
    requirements: Iterable[Requirement], assigned: dict[str, str]
) -> str:
    """A digest over the parts of an operation that must not drift."""
    return content_hash(
        {
            "requirements": sorted(
                (r.kind, r.max_age_seconds) for r in requirements
            ),
            "assigned": sorted(assigned.items()),
        }
    )


def open_operation(
    operation_id: str,
    execution_id: str,
    task_id: str,
    requirements: Iterable[Requirement],
    assigned_agent_versions: dict[str, str],
    events: Iterable[ExecutionEvent] = (),
    now: float | None = None,
) -> OperationCheckpoint:
    """Create the first checkpoint for an operation."""
    stamp = time.time() if now is None else now
    requirements = tuple(requirements)
    assigned = dict(assigned_agent_versions)
    head_sequence, head_hash = journal_head(events)
    return OperationCheckpoint(
        operation_id=operation_id,
        execution_id=execution_id,
        task_id=task_id,
        phase=Phase.PLANNED,
        assigned_agent_versions=assigned,
        requirements=requirements,
        policy_digest=policy_digest(requirements, assigned),
        evidence_refs=(),
        last_journal_sequence=head_sequence,
        last_journal_hash=head_hash,
        created_at=stamp,
        updated_at=stamp,
    )


def journal_head(events: Iterable[ExecutionEvent]) -> tuple[int, str]:
    """The sequence and content hash of the last event, or the empty head."""
    ordered = sorted(events, key=lambda e: e.sequence)
    if not ordered:
        return (-1, "")
    last = ordered[-1]
    return (last.sequence, last.content_hash)


def advance(
    checkpoint: OperationCheckpoint,
    phase: Phase,
    events: Iterable[ExecutionEvent] = (),
    evidence_refs: Iterable[str] | None = None,
    now: float | None = None,
) -> OperationCheckpoint:
    """Produce the next checkpoint. Never mutates the one handed in.

    ``checkpoint_version`` increments so a writer working from a stale read is
    refused by the store rather than silently winning.
    """
    if checkpoint.phase in TERMINAL:
        raise ContinuityError(
            ContinuityFailure.OPERATION_TERMINAL,
            f"{checkpoint.operation_id} already finished as {checkpoint.phase}",
        )
    head_sequence, head_hash = journal_head(events)
    if head_sequence < checkpoint.last_journal_sequence:
        raise ContinuityError(
            ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
            f"journal head {head_sequence} is behind the recorded position "
            f"{checkpoint.last_journal_sequence}",
        )
    return replace(
        checkpoint,
        phase=phase,
        evidence_refs=tuple(
            checkpoint.evidence_refs if evidence_refs is None else evidence_refs
        ),
        last_journal_sequence=head_sequence,
        last_journal_hash=head_hash,
        updated_at=time.time() if now is None else now,
        checkpoint_version=checkpoint.checkpoint_version + 1,
    )


# -- storage -------------------------------------------------------------------


class ContinuityStore(Protocol):
    """Where checkpoints live. Any backing store must be compare-and-set."""

    def get(self, operation_id: str) -> OperationCheckpoint | None: ...

    def put(self, checkpoint: OperationCheckpoint) -> None:
        """Store the checkpoint, refusing a write from a stale base."""


@dataclass
class InMemoryContinuityStore:
    """A deterministic store for tests and single-process runs."""

    _records: dict[str, dict] = field(default_factory=dict)

    def get(self, operation_id: str) -> OperationCheckpoint | None:
        raw = self._records.get(operation_id)
        return None if raw is None else OperationCheckpoint.from_dict(raw)

    def put(self, checkpoint: OperationCheckpoint) -> None:
        existing = self._records.get(checkpoint.operation_id)
        # Compare-and-set only has meaning once there is something to compare
        # against. A first write is accepted at whatever version it carries;
        # every write after that must build on exactly what is stored.
        if existing is not None:
            expected = int(existing["checkpoint_version"]) + 1
            if checkpoint.checkpoint_version != expected:
                raise ContinuityError(
                    ContinuityFailure.STALE_CHECKPOINT,
                    f"{checkpoint.operation_id}: expected version {expected}, "
                    f"got {checkpoint.checkpoint_version}",
                )
        self._records[checkpoint.operation_id] = checkpoint.as_dict()


OPERATIONS_COLLECTION = "operations"


class FirestoreContinuityStore:
    """Checkpoints in the same database that already holds the journal.

    Written transactionally against the stored ``checkpoint_version``, so two
    workers resuming the same operation cannot both commit. Continuity
    documents live in their own collection and never touch the execution
    documents the audit trail is built from.
    """

    def __init__(
        self,
        client,
        root: str = OPERATIONS_COLLECTION,
        transactional=None,
    ) -> None:
        self._client = client
        self._root = root
        if transactional is None:
            from google.cloud import firestore  # local import: optional dependency

            transactional = firestore.transactional
        self._transactional = transactional

    def _ref(self, operation_id: str):
        return self._client.collection(self._root).document(operation_id)

    def get(self, operation_id: str) -> OperationCheckpoint | None:
        try:
            snapshot = self._ref(operation_id).get()
        except Exception as exc:  # noqa: BLE001 - an unreachable store is not "no work"
            raise StoreUnavailable(f"{type(exc).__name__}: {exc}") from exc
        if not getattr(snapshot, "exists", False):
            return None
        return OperationCheckpoint.from_dict(snapshot.to_dict())

    def put(self, checkpoint: OperationCheckpoint) -> None:
        ref = self._ref(checkpoint.operation_id)
        payload = checkpoint.as_dict()

        @self._transactional
        def operation(transaction):
            snapshot = ref.get(transaction=transaction)
            if getattr(snapshot, "exists", False):
                stored = snapshot.to_dict()
                expected = int(stored["checkpoint_version"]) + 1
                if checkpoint.checkpoint_version != expected:
                    raise ContinuityError(
                        ContinuityFailure.STALE_CHECKPOINT,
                        f"{checkpoint.operation_id}: expected version "
                        f"{expected}, got {checkpoint.checkpoint_version}",
                    )
            transaction.set(ref, payload)

        try:
            operation(self._client.transaction())
        except ContinuityError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise StoreUnavailable(f"{type(exc).__name__}: {exc}") from exc


def chain_is_intact(events: Iterable[ExecutionEvent]) -> tuple[bool, tuple[str, ...]]:
    """Re-export so callers do not have to reach into the journal module."""
    return verify_events(events)


__all__ = [
    "CHECKPOINT_SCHEMA",
    "ContinuityError",
    "ContinuityFailure",
    "ContinuityStore",
    "FirestoreContinuityStore",
    "InMemoryContinuityStore",
    "MAY_EXECUTE",
    "OperationCheckpoint",
    "Phase",
    "StoreUnavailable",
    "TERMINAL",
    "advance",
    "chain_is_intact",
    "journal_head",
    "open_operation",
    "policy_digest",
]
