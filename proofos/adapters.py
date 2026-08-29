"""Translate a foreign system into ProofOS vocabulary, and stop there.

An adapter is a translator. It knows what a LangGraph run, an HTTP body or a
plain Python object *means*; it does not know whether that meaning is true, and
this module is arranged so that it has no way to find out and no way to assert
it.

The arrangement is the same one used everywhere else in this package, because
it is the only one that survives being wrong about people's intentions:

* ``Claim``, ``ToolResult`` and ``AgentEvent`` have no ``source``, no
  ``trusted``, no ``independent`` and no ``verdict``. A payload that arrives
  containing those words is kept under ``metadata["claimed_by_sender"]``, where
  it reads as what it is -- something the sender wrote.
* This module does not encode ``Evidence`` at all, and does not import the type.
  Turning a neutral submission into evidence is a separate, explicit step in
  ``proofos.evidence_bridge`` -- the wall between translating what a sender said
  and encoding it for the verifier. An adapter that helpfully minted evidence
  would have moved the trust boundary into the translation layer; keeping the
  verifier types out of this file makes that structurally impossible rather than
  merely discouraged.
* No type here has a ``verify``, ``accept`` or ``trust`` method. The verdict
  arrives from the kernel, over evidence whose provenance was established
  somewhere this module cannot reach.

## What that buys

The thing being defended is small and easy to lose. An agent says "verified:
true, confidence: 1.0". A tool returns HTTP 200. The framework is called
"trusted-enterprise-agent". None of it is a lie, exactly -- and none of it is
independent of the component under scrutiny, which is the only property that
matters. An adapter that helpfully translated any of it into an observation
would have moved the trust boundary into the translation layer, which is the
layer least equipped to defend it.

## One namespace for everything a sender asserted

Every adapter -- here, GitHub, MCP, and whatever comes next -- puts sender-
asserted trust, identity and authority in exactly one place::

    metadata
    |- transport        adapter-owned fact
    |- adapter_id       adapter-owned fact
    |- server_id        adapter-owned fact
    `- claimed_by_sender
         |- source
         |- collector_id
         |- trusted
         `- ...

The alternative was a naming convention -- ``claimed_source``,
``claimed_collector_id`` -- which works until the next dangerous word arrives and
has to be added to the convention. ``claimed_role``, ``claimed_scope``,
``claimed_signature``: a rule that grows one entry per threat is a rule that will
eventually be one entry short. The namespace has one rule instead, and it does
not grow: *what the other party said goes inside, and nothing else does.*

``AdapterEnvelope`` enforces it structurally rather than by convention. A
metadata mapping carrying a top-level ``collector_id``, or a flat
``claimed_collector_id``, is refused at construction -- so an adapter that
forgets cannot ship, and the only key permitted to begin with ``claimed_`` is
the namespace itself.

## Identity

``adapter_id`` comes from the constructor. It is never read from a payload, so a
foreign system cannot choose to be called ``proofos-verifier`` by saying so.
Actor, task, execution, tool, adapter and framework stay separate fields: they
answer different questions, and a single string that means all of them is a
string nobody can check.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

#: Bumped when the wire shape changes in a way older builds cannot read.
ADAPTER_SCHEMA = 1

#: A bound on what one message may carry. Not a security boundary -- a refusal
#: to spend unbounded memory parsing something already malformed.
MAX_EVENTS = 512
MAX_TEXT = 16_384

#: Words a payload may contain and may never mean. Kept rather than stripped:
#: deleting them would hide what a sender tried, and the whole point is that
#: trying is allowed and achieving is not. The last four are identities: a party
#: naming itself is asserting, not proving, and every transport treats that the
#: same way.
NON_AUTHORITATIVE_KEYS = frozenset({
    "source", "trusted", "independent", "verified", "verdict", "status",
    "proofos_status", "authority", "grant", "grants", "collector_id",
    "attestation", "signature", "confidence", "task_complete",
    "server_id", "adapter_id", "collector", "verifier",
})

#: The one key under which everything a sender asserted is kept -- and so also
#: the only key permitted to begin with its prefix. The prefix is derived rather
#: than written out, so the two cannot drift apart and no second string literal
#: in this package starts with it.
CLAIMED_NAMESPACE = "claimed_by_sender"
_CLAIMED_PREFIX = CLAIMED_NAMESPACE[:CLAIMED_NAMESPACE.index("_") + 1]

#: Names ``metadata`` may not use at the top level, whoever is building it. Each
#: one reads, to anything downstream, as a fact this system established -- and
#: none of them is a fact an adapter is in a position to establish.
#: ``server_id``, ``adapter_id``, ``framework`` and ``transport`` are absent on
#: purpose: those come from a constructor, so an adapter may state them.
RESERVED_METADATA_KEYS = frozenset({
    "source", "collector_id", "trusted", "independent",
    "authority", "verdict", "verified", "status",
})

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")


class AdapterError(ValueError):
    """Input this build will not translate, and what to do about it."""

    def __init__(self, problem: str, *, source: str = "", path: str = "",
                 fix: str = "") -> None:
        self.problem = problem
        self.source = source
        self.path = path
        self.fix = fix
        super().__init__(self.render())

    def render(self) -> str:
        where = self.source or "adapter input"
        if self.path:
            where += f" [{self.path}]"
        text = f"{where}: {self.problem}"
        if self.fix:
            text += f"\n  fix: {self.fix}"
        return text


@dataclass(frozen=True)
class ActorRef:
    """Who is speaking. Descriptive, and never an identity ProofOS trusts.

    ``framework`` is a label the sender chose. "Google ADK" and
    "trusted-enterprise-agent" are the same kind of string, and neither buys
    anything: the tests assert that the verdict does not move when it changes.
    """

    actor_id: str
    framework: str = ""
    version: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"actor_id": self.actor_id, "framework": self.framework,
                "version": self.version}


@dataclass(frozen=True)
class TaskRef:
    """Which piece of work. Separate from the execution that attempted it."""

    task_id: str
    execution_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"task_id": self.task_id, "execution_id": self.execution_id}


@dataclass(frozen=True)
class ToolResult:
    """What a tool returned, kept as data.

    A tool the agent called is not independent of the agent. HTTP 200 from a
    probe the executor ran is a fact about that call, not a certification of the
    service, and turning one into the other is the entire mistake this type
    exists to make impossible.
    """

    tool: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "payload": dict(self.payload), "at": self.at}


@dataclass(frozen=True)
class AgentEvent:
    """Something that happened during an execution, as reported by the runner."""

    name: str
    detail: str = ""
    at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "detail": self.detail, "at": self.at}


@dataclass(frozen=True)
class Claim:
    """An assertion by an actor that something is done.

    The thing under scrutiny. Not evidence for itself, and there is nowhere here
    to say otherwise: no source, no confidence that means anything, no verdict.
    """

    text: str
    actor: ActorRef
    task: TaskRef
    at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"text": self.text, "actor": self.actor.as_dict(),
                "task": self.task.as_dict(), "at": self.at}


@dataclass(frozen=True)
class AdapterEnvelope:
    """One normalized submission: a claim, what happened, and where it came from.

    ``metadata`` holds two different kinds of thing and keeps them apart. At the
    top level: facts the adapter itself established, which is a short list --
    how the message arrived, and which constructor built the reader. Under
    ``claimed_by_sender``: everything the other party asserted, including the
    words in ``NON_AUTHORITATIVE_KEYS``. Preserved, so a reader can see what was
    attempted; enclosed, so nothing downstream can mistake it for a decision.

    The enclosure is checked here rather than trusted to each adapter. An
    envelope whose metadata carries a top-level ``collector_id`` -- or a flat
    ``claimed_collector_id``, which is the same mistake wearing a hat -- does not
    get built.
    """

    claim: Claim
    events: tuple[AgentEvent, ...] = ()
    tool_results: tuple[ToolResult, ...] = ()
    adapter_id: str = ""
    transport: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key in self.metadata:
            if key in RESERVED_METADATA_KEYS:
                raise AdapterError(
                    f"metadata may not carry a top-level {key!r}",
                    source=self.adapter_id or "adapter", path=f"metadata.{key}",
                    fix=f"put it in metadata[{CLAIMED_NAMESPACE!r}]. At the top "
                        f"level it reads as something this system established, "
                        f"and no adapter is in a position to establish it",
                )
            if key.startswith(_CLAIMED_PREFIX) and key != CLAIMED_NAMESPACE:
                raise AdapterError(
                    f"metadata may not carry a flat {key!r}",
                    source=self.adapter_id or "adapter", path=f"metadata.{key}",
                    fix=f"one namespace, one contract: "
                        f"metadata[{CLAIMED_NAMESPACE!r}]"
                        f"[{key[len(_CLAIMED_PREFIX):]!r}]. A per-key naming "
                        f"convention needs a new entry every time a new "
                        f"dangerous word arrives",
                )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ADAPTER_SCHEMA,
            "claim": self.claim.as_dict(),
            "events": [e.as_dict() for e in self.events],
            "tool_results": [t.as_dict() for t in self.tool_results],
            "adapter_id": self.adapter_id,
            "transport": self.transport,
            "metadata": dict(self.metadata),
        }

    @property
    def truth_semantics(self) -> dict[str, Any]:
        """Everything that may affect a verdict, with transport stripped out.

        Two adapters carrying the same claim must produce the same value here.
        That equality is what "transport does not change truth" means when it is
        checked rather than asserted, so the fields it omits are deliberate:
        adapter_id, transport and metadata describe how a message arrived, and
        nothing about whether it is true.
        """
        return {
            "claim": self.claim.text,
            "actor_id": self.claim.actor.actor_id,
            "task_id": self.claim.task.task_id,
            "execution_id": self.claim.task.execution_id,
            "at": self.claim.at,
            "tool_results": [
                {"tool": t.tool, "payload": dict(t.payload), "at": t.at}
                for t in self.tool_results
            ],
            "events": [
                {"name": e.name, "detail": e.detail, "at": e.at}
                for e in self.events
            ],
        }


def _require_id(value: Any, path: str, source: str) -> str:
    if not isinstance(value, str) or not _ID.match(value):
        raise AdapterError(
            f"{path} is not a usable identifier", source=source, path=path,
            fix="letters, digits and . _ : - only, 1 to 128 characters. Ids "
                "appear in journals and error messages, and one that can be "
                "anything is one nobody can search for",
        )
    return value


def _number(value: Any, path: str, source: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AdapterError(f"{path} must be a unix timestamp", source=source,
                           path=path)
    number = float(value)
    if math.isnan(number) or math.isinf(number):
        raise AdapterError(f"{path} is {value!r}", source=source, path=path,
                           fix="a finite unix timestamp, or omit it")
    return number


def _text(value: Any, path: str, source: str, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise AdapterError(f"{path} must be a string", source=source, path=path)
    if len(value) > MAX_TEXT:
        raise AdapterError(f"{path} is longer than {MAX_TEXT} characters",
                           source=source, path=path)
    if required and not value.strip():
        raise AdapterError(f"{path} is empty", source=source, path=path)
    return value


def claimed_by_sender(*payloads: Mapping[str, Any]) -> dict[str, Any]:
    """Keep what the sender said about trust, enclosed so it cannot be mistaken.

    Not stripped. A payload that tried to declare itself verified is a thing a
    reviewer should be able to see, and hiding it would make the attempt
    invisible rather than ineffective.

    Every adapter calls this, which is the point: one representation, so an
    integrator learns the rule once. Several payloads may be passed when one
    message nests another -- an MCP tool result and its ``structuredContent`` --
    and later ones win, matching the order a reader would apply them in.
    """
    claims: dict[str, Any] = {}
    for payload in payloads:
        for key, value in payload.items():
            if key in NON_AUTHORITATIVE_KEYS:
                claims[key] = value
    return {CLAIMED_NAMESPACE: claims} if claims else {}


class PythonAdapter:
    """Normalize a plain Python agent's output. No framework required.

    Deliberately dull. The interesting property is what it cannot do: there is
    no ``verify``, no ``accept_evidence``, no ``trust_source``, and the
    normalized value it returns carries no provenance for anything downstream
    to honour.
    """

    transport = "python"

    def __init__(self, adapter_id: str, framework: str = "") -> None:
        # From the constructor, never from a payload. A foreign system that
        # wants to be called "proofos-verifier" would have to be constructed
        # that way by the process it is trying to fool.
        self.adapter_id = _require_id(adapter_id, "adapter_id", "PythonAdapter")
        self.framework = framework

    def normalize(
        self,
        *,
        actor_id: str,
        task_id: str,
        claim: str,
        execution_id: str = "",
        at: float | None = None,
        events: Iterable[Mapping[str, Any]] = (),
        tool_results: Iterable[Mapping[str, Any]] = (),
        extra: Mapping[str, Any] | None = None,
    ) -> AdapterEnvelope:
        source = f"{self.adapter_id} (python)"
        actor = ActorRef(
            actor_id=_require_id(actor_id, "actor_id", source),
            framework=self.framework,
        )
        task = TaskRef(
            task_id=_require_id(task_id, "task_id", source),
            execution_id=_require_id(execution_id, "execution_id", source)
            if execution_id else "",
        )
        return AdapterEnvelope(
            claim=Claim(text=_text(claim, "claim", source), actor=actor,
                        task=task, at=_number(at, "at", source)),
            events=_events(events, source),
            tool_results=_tool_results(tool_results, source),
            adapter_id=self.adapter_id,
            transport=self.transport,
            metadata=claimed_by_sender(extra or {}),
        )


class HttpAdapter:
    """Normalize a framework-neutral HTTP body.

    Arrival over HTTP is not a property of the truth of the message. Neither is
    TLS, nor an authenticated caller: being allowed to speak is not the same as
    being independent of what you are speaking about. This class performs no
    network I/O at all -- it reads a body someone else received, which keeps the
    semantic boundary separate from the transport that crossed it.
    """

    transport = "http"

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = _require_id(adapter_id, "adapter_id", "HttpAdapter")

    def normalize(self, body: Any, *, source: str = "http body") -> AdapterEnvelope:
        if isinstance(body, (str, bytes)):
            try:
                body = json.loads(body)
            except ValueError as exc:
                raise AdapterError(f"body is not JSON: {exc}", source=source) from None
        if not isinstance(body, dict):
            raise AdapterError("body must be an object", source=source)

        schema = body.get("schema_version")
        if schema is None:
            raise AdapterError("missing 'schema_version'", source=source,
                               fix=f"send schema_version {ADAPTER_SCHEMA}")
        if schema != ADAPTER_SCHEMA:
            raise AdapterError(
                f"schema_version {schema!r} is not supported by this build",
                source=source, path="schema_version")

        actor_body = body.get("actor")
        if not isinstance(actor_body, dict):
            raise AdapterError("'actor' must be an object", source=source,
                               path="actor")
        task_body = body.get("task")
        if not isinstance(task_body, dict):
            raise AdapterError("'task' must be an object", source=source,
                               path="task")

        actor = ActorRef(
            actor_id=_require_id(actor_body.get("actor_id"), "actor.actor_id", source),
            framework=_text(actor_body.get("framework"), "actor.framework",
                            source, required=False),
            version=_text(actor_body.get("version"), "actor.version",
                          source, required=False),
        )
        execution_id = task_body.get("execution_id") or ""
        task = TaskRef(
            task_id=_require_id(task_body.get("task_id"), "task.task_id", source),
            execution_id=_require_id(execution_id, "task.execution_id", source)
            if execution_id else "",
        )
        return AdapterEnvelope(
            claim=Claim(
                text=_text(body.get("claim"), "claim", source),
                actor=actor, task=task,
                at=_number(body.get("at"), "at", source),
            ),
            events=_events(body.get("events") or (), source),
            tool_results=_tool_results(body.get("tool_results") or (), source),
            adapter_id=self.adapter_id,
            transport=self.transport,
            metadata=claimed_by_sender(body),
        )


def _events(raw: Iterable[Mapping[str, Any]], source: str) -> tuple[AgentEvent, ...]:
    items = list(raw)
    if len(items) > MAX_EVENTS:
        raise AdapterError(f"more than {MAX_EVENTS} events", source=source,
                           path="events")
    out = []
    for index, item in enumerate(items):
        path = f"events[{index}]"
        if not isinstance(item, Mapping):
            raise AdapterError("each event must be an object", source=source,
                               path=path)
        out.append(AgentEvent(
            name=_text(item.get("name"), f"{path}.name", source),
            detail=_text(item.get("detail"), f"{path}.detail", source,
                         required=False),
            at=_number(item.get("at"), f"{path}.at", source),
        ))
    return tuple(out)


def _tool_results(raw: Iterable[Mapping[str, Any]],
                  source: str) -> tuple[ToolResult, ...]:
    items = list(raw)
    if len(items) > MAX_EVENTS:
        raise AdapterError(f"more than {MAX_EVENTS} tool results", source=source,
                           path="tool_results")
    out = []
    for index, item in enumerate(items):
        path = f"tool_results[{index}]"
        if not isinstance(item, Mapping):
            raise AdapterError("each tool result must be an object",
                               source=source, path=path)
        payload = item.get("payload") or {}
        if not isinstance(payload, Mapping):
            raise AdapterError("a tool payload must be an object", source=source,
                               path=f"{path}.payload")
        out.append(ToolResult(
            tool=_text(item.get("tool"), f"{path}.tool", source),
            payload=dict(payload),
            at=_number(item.get("at"), f"{path}.at", source),
        ))
    return tuple(out)


#: Tier 2. An integrator imports these from ``proofos.adapters``; someone
#: verifying a claim never needs them.
__all__ = [
    "ADAPTER_SCHEMA",
    "MAX_EVENTS",
    "MAX_TEXT",
    "NON_AUTHORITATIVE_KEYS",
    "CLAIMED_NAMESPACE",
    "RESERVED_METADATA_KEYS",
    "claimed_by_sender",
    "ActorRef",
    "TaskRef",
    "Claim",
    "AgentEvent",
    "ToolResult",
    "AdapterEnvelope",
    "AdapterError",
    "PythonAdapter",
    "HttpAdapter",
]
