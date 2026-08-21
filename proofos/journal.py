"""Append-only, hash-chained execution journal.

The journal is the audit trail. Every consequential step of an execution --
the claim, each verification decision, each recovery attempt, each observation
collected -- is appended as an immutable event.

This is deliberately one append-only log rather than eight entity tables. The
question a journal has to answer is "why was this task marked VERIFIED?", and
the honest answer is the ordered list of what actually happened. Replaying the
events for an execution_id reconstructs the decision without trusting any
agent's summary.

Two properties make the log defensible once it leaves the process:

* Each event carries an explicit ``sequence``. Storage ordering is never
  trusted; the sequence is the order.
* Each event's hash covers the previous event's hash, so removing, reordering,
  or editing any event in the middle breaks the chain from that point on.

Neither property makes storage an authority. The journal records what the
runtime decided; it can never be the thing that decides.

Events are emitted as single-line JSON with a ``severity`` field, which is the
shape Google Cloud Logging ingests from stdout on Cloud Run without any client
library. That keeps the dependency surface at zero.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Iterable, Protocol, TextIO

from .integrity import content_hash

GENESIS_HASH = "0" * 64


class EventType(StrEnum):
    EXECUTION_START = "EXECUTION_START"
    CLAIM_RECEIVED = "CLAIM_RECEIVED"
    AGENT_TURN = "AGENT_TURN"
    TOOL_CALL = "TOOL_CALL"
    VERIFIER_DECISION = "VERIFIER_DECISION"
    RECOVERY_START = "RECOVERY_START"
    EVIDENCE_COLLECTED = "EVIDENCE_COLLECTED"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    EXECUTION_COMPLETE = "EXECUTION_COMPLETE"


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class JournalUnavailableError(RuntimeError):
    """Raised when an event could not be durably appended.

    Callers must treat this as loss of auditability, never as a neutral event.
    """


def new_execution_id() -> str:
    return f"exec_{uuid.uuid4().hex[:16]}"


def new_trace_id() -> str:
    return uuid.uuid4().hex


def new_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


@dataclass(frozen=True)
class EventDraft:
    """An event before the sink has placed it in the chain.

    A draft has no sequence, no previous_hash, and no content_hash. Only a sink
    assigns those, which is what stops a caller from choosing its own position
    in history or backdating a record.
    """

    event_id: str
    execution_id: str
    task_id: str
    event: EventType
    agent: str
    status: str
    trace_id: str
    timestamp: float
    severity: Severity = Severity.INFO
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionEvent:
    """One immutable, chained record of something that happened."""

    event_id: str
    execution_id: str
    task_id: str
    sequence: int
    event: EventType
    agent: str
    status: str
    trace_id: str
    timestamp: float
    severity: Severity = Severity.INFO
    payload: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    content_hash: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if not self.content_hash:
            object.__setattr__(self, "content_hash", self.compute_hash())

    def compute_hash(self) -> str:
        return content_hash(
            {
                "event_id": self.event_id,
                "execution_id": self.execution_id,
                "task_id": self.task_id,
                "sequence": self.sequence,
                "event": str(self.event),
                "agent": self.agent,
                "status": self.status,
                "trace_id": self.trace_id,
                "timestamp": self.timestamp,
                "severity": str(self.severity),
                "payload": self.payload,
                "previous_hash": self.previous_hash,
            }
        )

    @property
    def intact(self) -> bool:
        """False if the record's content no longer matches its own digest."""
        return self.content_hash == self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "sequence": self.sequence,
            "event": str(self.event),
            "agent": self.agent,
            "status": self.status,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "severity": str(self.severity),
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionEvent":
        """Rebuild an event from storage.

        Raises ValueError on a malformed record rather than materializing a
        partially-populated event that would later be mistaken for real
        history.
        """
        try:
            return cls(
                event_id=str(data["event_id"]),
                execution_id=str(data["execution_id"]),
                task_id=str(data["task_id"]),
                sequence=int(data["sequence"]),
                event=EventType(data["event"]),
                agent=str(data["agent"]),
                status=str(data["status"]),
                trace_id=str(data["trace_id"]),
                timestamp=float(data["timestamp"]),
                severity=Severity(data.get("severity", Severity.INFO)),
                payload=dict(data.get("payload") or {}),
                previous_hash=str(data.get("previous_hash", GENESIS_HASH)),
                content_hash=str(data.get("content_hash", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed journal record: {exc}") from exc


def finalize(draft: EventDraft, sequence: int, previous_hash: str) -> ExecutionEvent:
    """Place a draft in the chain at ``sequence``, following ``previous_hash``."""
    return ExecutionEvent(
        event_id=draft.event_id,
        execution_id=draft.execution_id,
        task_id=draft.task_id,
        sequence=sequence,
        event=draft.event,
        agent=draft.agent,
        status=draft.status,
        trace_id=draft.trace_id,
        timestamp=draft.timestamp,
        severity=draft.severity,
        payload=draft.payload,
        previous_hash=previous_hash,
    )


class JournalSink(Protocol):
    """Somewhere events are durably appended."""

    def append(self, draft: EventDraft) -> ExecutionEvent: ...

    def store(self, event: ExecutionEvent) -> None: ...

    def list_execution(self, execution_id: str) -> tuple[ExecutionEvent, ...]: ...

    def verify_chain(self, execution_id: str) -> tuple[bool, tuple[str, ...]]: ...


def verify_events(events: Iterable[ExecutionEvent]) -> tuple[bool, tuple[str, ...]]:
    """Check a set of events forms an unbroken chain.

    Detects edited records, gaps, duplicate sequences, and reordering. It does
    not prove who wrote the records.
    """
    ordered = sorted(events, key=lambda e: e.sequence)
    problems: list[str] = []

    if not ordered:
        return True, ()

    seen: dict[int, str] = {}
    for event in ordered:
        if event.sequence in seen and seen[event.sequence] != event.event_id:
            problems.append(f"duplicate sequence {event.sequence}")
        seen[event.sequence] = event.event_id

    expected_sequences = list(range(ordered[0].sequence, ordered[-1].sequence + 1))
    actual = sorted({e.sequence for e in ordered})
    missing = [s for s in expected_sequences if s not in actual]
    if missing:
        problems.append(f"missing sequences {missing}")

    if ordered[0].sequence != 0:
        problems.append(f"chain does not start at sequence 0 (starts at {ordered[0].sequence})")

    previous = GENESIS_HASH
    for event in ordered:
        if not event.intact:
            problems.append(
                f"sequence {event.sequence} does not match its content hash"
            )
        if event.previous_hash != previous:
            problems.append(f"sequence {event.sequence} does not follow its predecessor")
        previous = event.content_hash

    return (not problems), tuple(problems)


class _ChainingSink:
    """Shared bookkeeping: assign sequences and link each event to the last."""

    def __init__(self) -> None:
        self._events: dict[str, list[ExecutionEvent]] = {}
        self._event_ids: dict[str, dict[str, ExecutionEvent]] = {}

    def append(self, draft: EventDraft) -> ExecutionEvent:
        existing = self._event_ids.setdefault(draft.execution_id, {})
        # Idempotent retry: the same event_id must not be appended twice.
        if draft.event_id in existing:
            return existing[draft.event_id]

        chain = self._events.setdefault(draft.execution_id, [])
        sequence = len(chain)
        previous_hash = chain[-1].content_hash if chain else GENESIS_HASH
        event = finalize(draft, sequence, previous_hash)
        chain.append(event)
        existing[draft.event_id] = event
        self._emit(event)
        return event

    def store(self, event: ExecutionEvent) -> None:
        """Store an already-chained event verbatim, without re-sequencing it."""
        existing = self._event_ids.setdefault(event.execution_id, {})
        if event.event_id in existing:
            return
        self._events.setdefault(event.execution_id, []).append(event)
        existing[event.event_id] = event
        self._emit(event)

    def list_execution(self, execution_id: str) -> tuple[ExecutionEvent, ...]:
        return tuple(sorted(self._events.get(execution_id, []), key=lambda e: e.sequence))

    def verify_chain(self, execution_id: str) -> tuple[bool, tuple[str, ...]]:
        return verify_events(self.list_execution(execution_id))

    def _emit(self, event: ExecutionEvent) -> None:
        """Hook for sinks that also write somewhere."""


class InMemoryJournalSink(_ChainingSink):
    """Reference sink. Durable only for the life of the process."""

    def all(self) -> tuple[ExecutionEvent, ...]:
        return tuple(
            event for chain in self._events.values() for event in chain
        )


class StreamJournalSink(_ChainingSink):
    """Emit newline-delimited JSON, the form Cloud Logging ingests from stdout."""

    def __init__(self, stream: TextIO | None = None) -> None:
        super().__init__()
        self._stream = stream

    def _emit(self, event: ExecutionEvent) -> None:
        stream = self._stream if self._stream is not None else sys.stdout
        stream.write(json.dumps(event.to_dict(), default=str) + "\n")
        stream.flush()


class FanoutJournalSink:
    """Append through a primary sink, then replicate the finalized event.

    Only the primary assigns sequence numbers. Replicas store the event
    verbatim, so every copy shares one chain rather than inventing its own.
    """

    def __init__(self, primary: JournalSink, *replicas: JournalSink) -> None:
        self._primary = primary
        self._replicas = replicas

    def append(self, draft: EventDraft) -> ExecutionEvent:
        event = self._primary.append(draft)
        for replica in self._replicas:
            replica.store(event)
        return event

    def store(self, event: ExecutionEvent) -> None:
        self._primary.store(event)
        for replica in self._replicas:
            replica.store(event)

    def list_execution(self, execution_id: str) -> tuple[ExecutionEvent, ...]:
        return self._primary.list_execution(execution_id)

    def verify_chain(self, execution_id: str) -> tuple[bool, tuple[str, ...]]:
        return self._primary.verify_chain(execution_id)


class Journal:
    """Records what happened during one execution."""

    def __init__(
        self,
        sink: JournalSink,
        execution_id: str | None = None,
        task_id: str = "",
        trace_id: str | None = None,
    ) -> None:
        self.sink = sink
        self.execution_id = execution_id or new_execution_id()
        self.task_id = task_id
        self.trace_id = trace_id or new_trace_id()

    def record(
        self,
        event: EventType,
        agent: str,
        status: str,
        severity: Severity = Severity.INFO,
        event_id: str | None = None,
        **payload: Any,
    ) -> ExecutionEvent:
        """Append one event. Raises JournalUnavailableError if it cannot.

        Passing an explicit ``event_id`` makes the append idempotent, so a
        retried request records the step once rather than twice.
        """
        draft = EventDraft(
            event_id=event_id or new_event_id(),
            execution_id=self.execution_id,
            task_id=self.task_id,
            event=event,
            agent=agent,
            status=status,
            trace_id=self.trace_id,
            timestamp=time.time(),
            severity=severity,
            payload=payload,
        )
        try:
            return self.sink.append(draft)
        except JournalUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - any storage failure is loss of audit
            raise JournalUnavailableError(
                f"could not append {event} for {self.execution_id}: "
                f"{type(exc).__name__}"
            ) from exc

    def events(self) -> tuple[ExecutionEvent, ...]:
        return self.sink.list_execution(self.execution_id)

    def verify(self) -> tuple[bool, tuple[str, ...]]:
        return self.sink.verify_chain(self.execution_id)


def summarize(events: Iterable[ExecutionEvent]) -> dict[str, Any]:
    """Reduce a journal to the answer to 'why was this decided that way?'."""
    ordered = sorted(events, key=lambda e: e.sequence)
    if not ordered:
        return {"execution_id": None, "final_status": "UNKNOWN", "steps": []}

    decisions = [e for e in ordered if e.event is EventType.VERIFIER_DECISION]
    completion = [e for e in ordered if e.event is EventType.EXECUTION_COMPLETE]
    ok, problems = verify_events(ordered)

    return {
        "execution_id": ordered[0].execution_id,
        "task_id": ordered[0].task_id,
        "trace_id": ordered[0].trace_id,
        "started_at": ordered[0].timestamp,
        "final_status": completion[-1].status if completion else "INCOMPLETE",
        "decisions": [
            {
                "status": e.status,
                "failure": e.payload.get("failure"),
                "missing": e.payload.get("missing"),
                "attempt": e.payload.get("attempt"),
            }
            for e in decisions
        ],
        "chain_intact": ok,
        "chain_problems": list(problems),
        "steps": [
            {
                "sequence": e.sequence,
                "event": str(e.event),
                "agent": e.agent,
                "status": e.status,
                "timestamp": e.timestamp,
            }
            for e in ordered
        ],
    }


def redacted(event: ExecutionEvent, keys: tuple[str, ...]) -> ExecutionEvent:
    """Return a copy with the named payload keys removed.

    Journals are written to logs and to durable storage, so anything that could
    carry a secret should be dropped before it is appended. Redaction changes
    the content, so the copy is rehashed and will no longer chain -- redact
    before appending, not after.
    """
    payload = {k: v for k, v in event.payload.items() if k not in keys}
    return replace(event, payload=payload, content_hash="")
