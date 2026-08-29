"""A2A transports agency. It does not transport truth.

The Agent2Agent protocol lets one agent hand work to another and get a task back
with a state on it. When that state is ``completed`` and the message says
"deployment verified", something real has happened: a remote agent has said so.
That is the whole of what has happened.

This module normalizes that and stops. There is no branch anywhere in it that
reads a task state and produces a verdict -- not a branch that refuses one, an
absent one. ``TaskState`` exists so a summary can name what the remote agent
said; it has no ``is_success``, no ``satisfies``, no ``ok``, and nothing imports
a verifier.

## The four things this module refuses to conflate

* An agent that *authenticated* proved who is speaking. Whether what it said is
  true is a different question, and no signature answers it.
* An agent *card* advertising a ``verify_deployment`` skill has described what
  it may attempt. A capability is a proposal, not a certificate -- the same law
  P6 keeps for verification skills.
* An agent *named* ``proofos-verifier`` has chosen a string.
* A task *delegated* three times has been relayed three times. Relay is not
  corroboration, and this is the one that actually bites: in a multi-agent
  system the same original claim comes back wearing several different agents'
  names, and a system that counted those would be counting echoes.

## Delegation is routing, so it lives where routing lives

The delegation chain is kept -- a reviewer should be able to see how far a
statement travelled -- in ``metadata``, which ``truth_semantics`` excludes by
construction. A claim relayed through seven agents and the same claim delivered
directly are therefore the same statement, provably, rather than as a matter of
this module's good intentions.

## Identity

``adapter_id`` comes from the constructor. Everything else is the sender's:
the remote agent's id becomes ``claim.actor.actor_id``, which is where "who is
speaking" belongs and is documented as an identity ProofOS never trusts. It does
not become a ``collector_id``. A remote agent may even *call itself*
``trusted-collector`` -- a test asserts exactly that, because the collector
identities that mean anything are registered in a sealed registry and prove
themselves with a signature, and no string in a payload can reach that.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from .adapters import (
    MAX_EVENTS,
    MAX_TEXT,
    ActorRef,
    AdapterEnvelope,
    AdapterError,
    AgentEvent,
    Claim,
    TaskRef,
    ToolResult,
    claimed_by_sender,
    _number,
    _require_id,
    _text,
)

#: Bumped when the shapes this module reads change incompatibly.
A2A_SCHEMA = 1

#: How deep a delegation chain this build will read. Not a security boundary --
#: a refusal to spend unbounded memory on a message already misshapen.
MAX_DELEGATION = 64


class TaskState(StrEnum):
    """The states an A2A task may be reported in.

    Descriptive, all of them. There is deliberately no property here that sorts
    these into good and bad: the moment one existed, something downstream would
    read it, and a remote agent would have been handed a verdict switch.
    """

    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"

    @classmethod
    def read(cls, value: Any) -> "TaskState":
        """Name a state without judging it. Anything unrecognised is UNKNOWN."""
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass(frozen=True)
class AgentCard:
    """What a remote agent says it can do, and deliberately not an envelope.

    A card is advertising. ``capabilities: ["verification"]``,
    ``skills: ["verify_deployment"]``, ``name: "trusted-verifier"`` -- all of it
    is the agent describing itself to a directory, and none of it is a finding
    about the world.

    So this type is a dead end on purpose. There is no method here that returns
    an ``AdapterEnvelope`` or an ``Evidence``, and no method on ``A2aAdapter``
    that accepts a card. ``declares`` answers "did it say so", which is the only
    question a card can answer.
    """

    agent_id: str
    declared_name: str = ""
    declared_capabilities: tuple[str, ...] = ()

    def declares(self, capability: str) -> bool:
        """Whether the card advertises this capability. Nothing follows from it."""
        return capability in self.declared_capabilities

    def as_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "declared_name": self.declared_name,
                "declared_capabilities": list(self.declared_capabilities)}


def _parts_text(parts: Any, path: str, source: str) -> str:
    """Pull readable text out of an A2A parts list."""
    if parts is None:
        return ""
    if isinstance(parts, str):
        return parts
    if not isinstance(parts, (list, tuple)):
        raise AdapterError(f"'{path}' must be a list", source=source, path=path)
    pieces: list[str] = []
    for index, part in enumerate(parts):
        if not isinstance(part, Mapping):
            raise AdapterError("each part must be an object", source=source,
                               path=f"{path}[{index}]")
        if part.get("kind", part.get("type", "text")) == "text":
            value = part.get("text")
            if isinstance(value, str) and value.strip():
                pieces.append(value.strip())
    return " ".join(pieces)[:MAX_TEXT]


class A2aAdapter:
    """Normalize what a remote A2A agent said about a task.

    Reads a task result. Performs no network I/O, holds no SDK, writes nothing,
    and has no method whose name contains ``verify``, ``trust`` or ``accept``.
    """

    transport = "a2a"

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = _require_id(adapter_id, "adapter_id", "A2aAdapter")

    def normalize_task(
        self,
        payload: Mapping[str, Any],
        *,
        at: float | None = None,
        actor_id: str = "",
    ) -> AdapterEnvelope:
        """Turn an A2A task result into a claim and some metadata.

        ``state`` is normalized into the canonical ``status`` slot inside
        ``claimed_by_sender``, alongside every other word the payload asserted.
        It is preserved because a reviewer should see that ``completed`` was
        claimed; it is enclosed because nothing downstream may act on it.

        Artifacts become tool results -- which is to say, EXECUTOR evidence
        attributed to the agent that produced them. An artifact a remote agent
        generated is not independent of that agent, however carefully formatted.
        """
        source = f"{self.adapter_id} (a2a task)"
        if not isinstance(payload, Mapping):
            raise AdapterError("an a2a task result must be an object", source=source)

        task_body = payload.get("task")
        if not isinstance(task_body, Mapping):
            raise AdapterError("'task' must be an object", source=source, path="task")
        agent_body = payload.get("agent")
        if agent_body is not None and not isinstance(agent_body, Mapping):
            raise AdapterError("'agent' must be an object", source=source, path="agent")
        agent_body = agent_body or {}

        remote_agent_id = actor_id or agent_body.get("id") or agent_body.get("name")
        remote_agent_id = _require_id(remote_agent_id, "agent.id", source)
        task_id = _require_id(task_body.get("id") or task_body.get("task_id"),
                              "task.id", source)
        context_id = task_body.get("context_id") or task_body.get("contextId") or ""
        state = TaskState.read(task_body.get("state", task_body.get("status")))

        message = payload.get("message")
        if message is not None and not isinstance(message, Mapping):
            raise AdapterError("'message' must be an object", source=source,
                               path="message")
        text = _parts_text((message or {}).get("parts"), "message.parts", source)
        if not text:
            text = _text((message or {}).get("text"), "message.text", source,
                         required=False)
        if not text:
            # No prose came back. Say what was actually established -- that an
            # agent reported a state -- rather than inventing a finding.
            text = f"{remote_agent_id} reports task {task_id} {state}"

        chain = _delegation(payload.get("delegation") or (), source)

        return AdapterEnvelope(
            claim=Claim(
                text=text[:MAX_TEXT],
                actor=ActorRef(actor_id=remote_agent_id, framework="a2a"),
                task=TaskRef(task_id=task_id,
                             execution_id=_require_id(context_id,
                                                      "task.context_id", source)
                             if context_id else ""),
                at=_number(at if at is not None else payload.get("at"), "at", source),
            ),
            events=_a2a_events(payload.get("history") or (), source),
            tool_results=_artifacts(payload.get("artifacts") or (), source),
            adapter_id=self.adapter_id,
            transport=self.transport,
            metadata={
                "delegation_depth": len(chain),
                "delegation_chain": list(chain),
                **claimed_by_sender(payload, agent_body, task_body,
                                    {"status": str(state)}),
            },
        )

    def read_agent_card(self, card: Mapping[str, Any]) -> AgentCard:
        """Read a card as advertising, and give it nowhere else to go.

        Returns an ``AgentCard``. There is no overload of ``normalize_task``
        that takes one, so a card cannot travel alongside a claim and quietly
        become the reason it was believed.
        """
        source = f"{self.adapter_id} (a2a agent card)"
        if not isinstance(card, Mapping):
            raise AdapterError("an agent card must be an object", source=source)
        agent_id = _require_id(card.get("id") or card.get("name"), "id", source)

        declared: list[str] = []
        capabilities = card.get("capabilities") or {}
        if isinstance(capabilities, Mapping):
            declared += [str(k) for k, v in capabilities.items() if v]
        elif isinstance(capabilities, (list, tuple)):
            declared += [str(item) for item in capabilities]
        else:
            raise AdapterError("'capabilities' must be an object or a list",
                               source=source, path="capabilities")
        for index, skill in enumerate(card.get("skills") or ()):
            if not isinstance(skill, Mapping):
                raise AdapterError("each skill must be an object", source=source,
                                   path=f"skills[{index}]")
            declared.append(str(skill.get("id") or skill.get("name") or ""))

        return AgentCard(
            agent_id=agent_id,
            declared_name=_text(card.get("name"), "name", source, required=False),
            declared_capabilities=tuple(d for d in dict.fromkeys(declared) if d),
        )


def _delegation(raw: Iterable[Any], source: str) -> tuple[str, ...]:
    """Read who the sender says forwarded this. Routing, and nothing more."""
    items = list(raw)
    if len(items) > MAX_DELEGATION:
        raise AdapterError(f"delegation chain longer than {MAX_DELEGATION}",
                           source=source, path="delegation")
    out: list[str] = []
    for index, hop in enumerate(items):
        if isinstance(hop, str):
            out.append(hop)
            continue
        if not isinstance(hop, Mapping):
            raise AdapterError("each delegation hop must be an object or a string",
                               source=source, path=f"delegation[{index}]")
        out.append(str(hop.get("agent_id") or hop.get("id") or ""))
    return tuple(out)


def _a2a_events(raw: Iterable[Any], source: str) -> tuple[AgentEvent, ...]:
    items = list(raw)
    if len(items) > MAX_EVENTS:
        raise AdapterError(f"more than {MAX_EVENTS} history entries",
                           source=source, path="history")
    out: list[AgentEvent] = []
    for index, entry in enumerate(items):
        if not isinstance(entry, Mapping):
            raise AdapterError("each history entry must be an object",
                               source=source, path=f"history[{index}]")
        out.append(AgentEvent(
            name=_text(entry.get("role") or entry.get("name"),
                       f"history[{index}].role", source),
            detail=_parts_text(entry.get("parts"), f"history[{index}].parts",
                               source) or
                   _text(entry.get("text"), f"history[{index}].text", source,
                         required=False),
            at=_number(entry.get("at"), f"history[{index}].at", source),
        ))
    return tuple(out)


def _artifacts(raw: Iterable[Any], source: str) -> tuple[ToolResult, ...]:
    items = list(raw)
    if len(items) > MAX_EVENTS:
        raise AdapterError(f"more than {MAX_EVENTS} artifacts", source=source,
                           path="artifacts")
    out: list[ToolResult] = []
    for index, entry in enumerate(items):
        if not isinstance(entry, Mapping):
            raise AdapterError("each artifact must be an object", source=source,
                               path=f"artifacts[{index}]")
        name = _text(entry.get("name") or entry.get("artifactId"),
                     f"artifacts[{index}].name", source)
        out.append(ToolResult(
            tool=f"artifact:{name}",
            payload={"text": _parts_text(entry.get("parts"),
                                         f"artifacts[{index}].parts", source)},
            at=_number(entry.get("at"), f"artifacts[{index}].at", source),
        ))
    return tuple(out)


#: Tier 2. Imported from ``proofos.a2a`` by whoever is wiring an agent network;
#: the root API is for someone verifying a claim.
__all__ = [
    "A2A_SCHEMA",
    "MAX_DELEGATION",
    "TaskState",
    "AgentCard",
    "A2aAdapter",
]
