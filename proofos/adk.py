"""An ADK run produces events. Events are things that happened, not findings.

The Agent Development Kit gives a run a shape: an agent, a session, a stream of
events, tool calls and their results, and callbacks at named points --
``after_tool_callback``, ``after_agent_callback``. The shape is genuinely
useful, and none of it is a provenance.

The specific temptation here is the callback position. ``after_agent_callback``
sounds authoritative: it fires at the end, after everything, and whatever it
emits reads like a conclusion. It is a function the same run called, at a point
that run chose. A framework hook is a place, and a place is not a witness.

So there is no mapping in this module from a callback name to anything.
``AdkSurface`` names where a statement came from, so a summary can say so; there
is no dict keyed by callback name, no ``FINAL_CALLBACKS`` set, and no branch
that treats one event as weightier than another.

## Tool results get no special treatment

The same rule P9 keeps for MCP. An ADK tool that returns
``{"status": 200, "healthy": true, "verified": true}`` produces a ``ToolResult``
and therefore EXECUTOR evidence, attributed to the agent that called it. This is
the subtle one, because the tool really did return 200 -- and a probe the
executor ran is a fact about that call, not an independent finding about the
service. Independent observation happens in one place in this system: a
registered collector holding an ``ObservationCapability``, which nothing here
can reach or name.

## What this module does not know

It performs no I/O and holds no SDK, so it never saw a session, a runner or a
model. It reads a payload someone else collected. Nothing here reports whether
an agent was reachable or a call succeeded, because a semantic layer describing
events it never observed is the exact failure this project exists to name.
"""

from __future__ import annotations

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
ADK_SCHEMA = 1


class AdkSurface(StrEnum):
    """Where in an ADK run a statement came from.

    Every one of these is a claim. The enum exists so a reviewer can be told
    *what* was read and not counted, which is more useful than dropping it -- and
    emphatically not so that anything can branch on it.
    """

    AGENT_RESULT = "agent_result"
    EVENT = "event"
    TOOL_RESULT = "tool_result"
    CALLBACK = "callback"
    MODEL_RESPONSE = "model_response"


def _event_text(entry: Mapping[str, Any], path: str, source: str) -> str:
    """Read an event's text, whether it arrived flat or inside content parts."""
    direct = _text(entry.get("text"), f"{path}.text", source, required=False)
    if direct:
        return direct[:MAX_TEXT]
    content = entry.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content[:MAX_TEXT]
    if isinstance(content, Mapping):
        content = content.get("parts")
    if content is None:
        return ""
    if not isinstance(content, (list, tuple)):
        raise AdapterError("event content must be an object or a list",
                           source=source, path=f"{path}.content")
    pieces: list[str] = []
    for index, part in enumerate(content):
        if not isinstance(part, Mapping):
            raise AdapterError("each content part must be an object",
                               source=source, path=f"{path}.content[{index}]")
        value = part.get("text")
        if isinstance(value, str) and value.strip():
            pieces.append(value.strip())
    return " ".join(pieces)[:MAX_TEXT]


class AdkAdapter:
    """Normalize what an ADK run reported.

    ``adapter_id`` comes from the constructor. The agent name comes from the
    payload and becomes ``claim.actor.actor_id``, which is where "who is
    speaking" belongs -- an agent configured as ``proofos-verifier`` has chosen
    a string, and a test asserts the verdict does not move when it does.
    """

    transport = "adk"

    def __init__(self, adapter_id: str) -> None:
        self.adapter_id = _require_id(adapter_id, "adapter_id", "AdkAdapter")

    def normalize_result(
        self,
        payload: Mapping[str, Any],
        *,
        task_id: str,
        at: float | None = None,
    ) -> AdapterEnvelope:
        """Turn an ADK run's output into a claim and some metadata.

        ``task_id`` is a parameter rather than a payload field on purpose: ADK
        has no notion of the task being verified, and letting the payload choose
        which requirement set it is answering would let a run pick its own exam.
        A ``task_id`` in the payload is preserved as a claim and used for
        nothing.

        Events -- including callback output and model responses -- become
        ``AgentEvent`` records. Tool results become ``ToolResult`` records. Both
        are descriptive; neither is independent of the run that produced them.
        """
        source = f"{self.adapter_id} (adk result)"
        if not isinstance(payload, Mapping):
            raise AdapterError("an adk result must be an object", source=source)

        agent_body = payload.get("agent")
        if agent_body is not None and not isinstance(agent_body, Mapping):
            raise AdapterError("'agent' must be an object", source=source,
                               path="agent")
        agent_body = agent_body or {}
        agent_id = _require_id(agent_body.get("name") or agent_body.get("id")
                               or payload.get("author"), "agent.name", source)

        session_body = payload.get("session")
        if session_body is not None and not isinstance(session_body, Mapping):
            raise AdapterError("'session' must be an object", source=source,
                               path="session")
        session_body = session_body or {}
        invocation = (payload.get("invocation_id") or session_body.get("id") or "")

        result_body = payload.get("result")
        if isinstance(result_body, Mapping):
            text = _text(result_body.get("text"), "result.text", source,
                         required=False)
        elif isinstance(result_body, str):
            text = result_body
        elif result_body is None:
            text = ""
        else:
            raise AdapterError("'result' must be an object or a string",
                               source=source, path="result")
        if not text:
            text = _text(payload.get("output_text"), "output_text", source,
                         required=False)
        if not text:
            text = f"{agent_id} reported no output for {task_id}"

        events, callbacks = _adk_events(payload.get("events") or (), source)

        return AdapterEnvelope(
            claim=Claim(
                text=text[:MAX_TEXT],
                actor=ActorRef(actor_id=agent_id, framework="adk",
                               version=_text(agent_body.get("version"),
                                             "agent.version", source,
                                             required=False)),
                task=TaskRef(
                    task_id=_require_id(task_id, "task_id", source),
                    execution_id=_require_id(invocation, "invocation_id", source)
                    if invocation else "",
                ),
                at=_number(at if at is not None else payload.get("at"), "at", source),
            ),
            events=events,
            tool_results=_adk_tool_results(payload.get("tool_results") or (), source),
            adapter_id=self.adapter_id,
            transport=self.transport,
            metadata={
                "app_name": str(session_body.get("app_name") or ""),
                # Which hooks the payload says produced these events. Descriptive
                # only: nothing in this package branches on a callback name, and
                # a test parses this file to keep it that way.
                "callback_names": list(callbacks),
                **claimed_by_sender(payload, agent_body, session_body,
                                    result_body if isinstance(result_body, Mapping)
                                    else {}),
            },
        )


def _adk_events(raw: Iterable[Any],
                source: str) -> tuple[tuple[AgentEvent, ...], tuple[str, ...]]:
    items = list(raw)
    if len(items) > MAX_EVENTS:
        raise AdapterError(f"more than {MAX_EVENTS} events", source=source,
                           path="events")
    out: list[AgentEvent] = []
    callbacks: list[str] = []
    for index, entry in enumerate(items):
        path = f"events[{index}]"
        if not isinstance(entry, Mapping):
            raise AdapterError("each event must be an object", source=source,
                               path=path)
        callback = _text(entry.get("callback"), f"{path}.callback", source,
                         required=False)
        if callback:
            callbacks.append(callback)
        name = _text(entry.get("name") or entry.get("author") or callback,
                     f"{path}.name", source)
        detail = _event_text(entry, path, source)
        # The callback is recorded in the detail, where it reads as where the
        # sentence came from. It is not a field anything can dispatch on.
        if callback:
            detail = f"{callback}: {detail}" if detail else callback
        out.append(AgentEvent(name=name, detail=detail[:MAX_TEXT],
                              at=_number(entry.get("at"), f"{path}.at", source)))
    return tuple(out), tuple(dict.fromkeys(callbacks))


def _adk_tool_results(raw: Iterable[Any], source: str) -> tuple[ToolResult, ...]:
    items = list(raw)
    if len(items) > MAX_EVENTS:
        raise AdapterError(f"more than {MAX_EVENTS} tool results", source=source,
                           path="tool_results")
    out: list[ToolResult] = []
    for index, entry in enumerate(items):
        path = f"tool_results[{index}]"
        if not isinstance(entry, Mapping):
            raise AdapterError("each tool result must be an object",
                               source=source, path=path)
        response = entry.get("response", entry.get("payload")) or {}
        if not isinstance(response, Mapping):
            raise AdapterError("a tool response must be an object", source=source,
                               path=f"{path}.response")
        out.append(ToolResult(
            tool=_text(entry.get("tool") or entry.get("name"), f"{path}.tool",
                       source),
            payload=dict(response),
            at=_number(entry.get("at"), f"{path}.at", source),
        ))
    return tuple(out)


#: Tier 2. Imported from ``proofos.adk`` by whoever is wiring an ADK run; the
#: root API is for someone verifying a claim.
__all__ = [
    "ADK_SCHEMA",
    "AdkSurface",
    "AdkAdapter",
]
