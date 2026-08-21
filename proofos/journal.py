"""Append-only execution journal.

The journal is the audit trail. Every consequential step of an execution --
the claim, each verification decision, each recovery attempt, each observation
collected -- is appended as an immutable event.

This is deliberately one concept rather than eight entity tables. The question
a journal has to answer is "why was this task marked VERIFIED?", and the honest
answer is the ordered list of what actually happened. Replaying the events for
an execution_id reconstructs the decision without trusting any agent's summary.

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


def new_execution_id() -> str:
    return f"exec_{uuid.uuid4().hex[:16]}"


def new_trace_id() -> str:
    return uuid.uuid4().hex


@dataclass(frozen=True)
class ExecutionEvent:
    """One immutable record of something that happened during an execution."""

    execution_id: str
    task_id: str
    agent: str
    event: EventType
    status: str
    trace_id: str
    timestamp: float
    severity: Severity = Severity.INFO
    detail: dict[str, Any] = field(default_factory=dict)
    content_hash: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if not self.content_hash:
            object.__setattr__(self, "content_hash", self.compute_hash())

    def compute_hash(self) -> str:
        return content_hash(
            {
                "execution_id": self.execution_id,
                "task_id": self.task_id,
                "agent": self.agent,
                "event": str(self.event),
                "status": self.status,
                "trace_id": self.trace_id,
                "timestamp": self.timestamp,
                "severity": str(self.severity),
                "detail": self.detail,
            }
        )

    @property
    def intact(self) -> bool:
        return self.content_hash == self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "agent": self.agent,
            "event": str(self.event),
            "status": self.status,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "severity": str(self.severity),
            "detail": self.detail,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionEvent":
        return cls(
            execution_id=data["execution_id"],
            task_id=data["task_id"],
            agent=data["agent"],
            event=EventType(data["event"]),
            status=data["status"],
            trace_id=data["trace_id"],
            timestamp=data["timestamp"],
            severity=Severity(data.get("severity", Severity.INFO)),
            detail=data.get("detail") or {},
            content_hash=data.get("content_hash", ""),
        )


class JournalSink(Protocol):
    """Somewhere events are durably appended."""

    def append(self, event: ExecutionEvent) -> None: ...

    def read(self, execution_id: str) -> tuple[ExecutionEvent, ...]: ...


class InMemoryJournalSink:
    """Reference sink. Durable only for the life of the process."""

    def __init__(self) -> None:
        self._events: list[ExecutionEvent] = []

    def append(self, event: ExecutionEvent) -> None:
        self._events.append(event)

    def read(self, execution_id: str) -> tuple[ExecutionEvent, ...]:
        return tuple(e for e in self._events if e.execution_id == execution_id)

    def all(self) -> tuple[ExecutionEvent, ...]:
        return tuple(self._events)


class StreamJournalSink:
    """Emit newline-delimited JSON, the form Cloud Logging ingests from stdout."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._events: list[ExecutionEvent] = []

    def append(self, event: ExecutionEvent) -> None:
        self._events.append(event)
        self._stream.write(json.dumps(event.to_dict(), default=str) + "\n")
        self._stream.flush()

    def read(self, execution_id: str) -> tuple[ExecutionEvent, ...]:
        return tuple(e for e in self._events if e.execution_id == execution_id)


class FanoutJournalSink:
    """Write every event to several sinks, e.g. stdout plus a durable store."""

    def __init__(self, *sinks: JournalSink) -> None:
        self._sinks = sinks

    def append(self, event: ExecutionEvent) -> None:
        for sink in self._sinks:
            sink.append(event)

    def read(self, execution_id: str) -> tuple[ExecutionEvent, ...]:
        for sink in self._sinks:
            events = sink.read(execution_id)
            if events:
                return events
        return ()


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
        **detail: Any,
    ) -> ExecutionEvent:
        entry = ExecutionEvent(
            execution_id=self.execution_id,
            task_id=self.task_id,
            agent=agent,
            event=event,
            status=status,
            trace_id=self.trace_id,
            timestamp=time.time(),
            severity=severity,
            detail=detail,
        )
        self.sink.append(entry)
        return entry

    def events(self) -> tuple[ExecutionEvent, ...]:
        return self.sink.read(self.execution_id)


def verify_chain(events: Iterable[ExecutionEvent]) -> tuple[bool, tuple[str, ...]]:
    """Check every event still matches its own digest.

    Returns (ok, problems). Detects silent mutation of stored records; it does
    not prove who wrote them.
    """
    problems = [
        f"{e.event} at {e.timestamp} does not match its content hash"
        for e in events
        if not e.intact
    ]
    return (not problems, tuple(problems))


def summarize(events: Iterable[ExecutionEvent]) -> dict[str, Any]:
    """Reduce a journal to the answer to 'why was this decided that way?'."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    if not ordered:
        return {"execution_id": None, "final_status": "UNKNOWN", "steps": []}

    decisions = [e for e in ordered if e.event is EventType.VERIFIER_DECISION]
    completion = [e for e in ordered if e.event is EventType.EXECUTION_COMPLETE]
    ok, problems = verify_chain(ordered)

    return {
        "execution_id": ordered[0].execution_id,
        "task_id": ordered[0].task_id,
        "trace_id": ordered[0].trace_id,
        "started_at": ordered[0].timestamp,
        "final_status": completion[-1].status if completion else "INCOMPLETE",
        "decisions": [
            {
                "status": e.status,
                "failure": e.detail.get("failure"),
                "missing": e.detail.get("missing"),
                "attempt": e.detail.get("attempt"),
            }
            for e in decisions
        ],
        "chain_intact": ok,
        "chain_problems": list(problems),
        "steps": [
            {
                "event": str(e.event),
                "agent": e.agent,
                "status": e.status,
                "timestamp": e.timestamp,
            }
            for e in ordered
        ],
    }


def redacted(event: ExecutionEvent, keys: tuple[str, ...]) -> ExecutionEvent:
    """Return a copy with the named detail keys removed.

    Journals are written to logs and to durable storage, so anything that could
    carry a secret should be dropped before it is appended.
    """
    detail = {k: v for k, v in event.detail.items() if k not in keys}
    return replace(event, detail=detail, content_hash="")
