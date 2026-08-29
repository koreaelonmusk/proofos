"""MCP can tell ProofOS what a remote system said. It cannot tell ProofOS what is true.

A Model Context Protocol server hands back tool results, resources and prompts.
All three are things a remote party wrote. A tool named ``proofos.verify``
returning ``{"status": "VERIFIED"}`` from a server calling itself
``proofos-official`` is still a remote party writing something, and the number
of reassuring nouns involved does not change that.

So this module normalizes and stops. It produces the same neutral records the
Python and HTTP transports produce -- a claim, some events, some tool results --
and hands them to the ordinary path. It has no verdict field, no ``verified``,
no ``abstain``. Ask it what happened and it will tell you what a server said;
ask it whether that is true and there is nothing to ask.

## Why the claimed_ prefix

An arriving payload may contain ``collector_id``, ``source``, ``trusted``,
``authority``. Those are kept, because deleting them would make an attempt
invisible rather than ineffective. But they are kept under names that cannot be
mistaken for the real thing:

    collector_id  ->  claimed_collector_id
    source        ->  claimed_source
    trusted       ->  claimed_trusted

This is not tidiness. An integrator six months from now reads
``metadata["collector_id"]`` and reasonably believes it is a collector identity.
They read ``claimed_collector_id`` and cannot. The prefix does the remembering
so nobody has to.

## What this module does not know

It performs no I/O, so it cannot tell you whether a server was reachable, or
whether a tool call timed out, or whether a connection dropped mid-stream.
Those are real and they are observations a transport makes. A semantic layer
that reported them would be describing events it never saw, which is the failure
this project exists to name. They belong to the transport, and the transport
does not exist yet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping

from .adapters import (
    MAX_EVENTS,
    MAX_TEXT,
    NON_AUTHORITATIVE_KEYS,
    ActorRef,
    AdapterEnvelope,
    AdapterError,
    AgentEvent,
    Claim,
    TaskRef,
    ToolResult,
    _number,
    _require_id,
    _text,
)

#: Bumped when the shapes this module reads change incompatibly.
MCP_SCHEMA = 1

#: Words a payload may assert and may never mean, on top of the ones every
#: transport already refuses. A server naming itself is the MCP-specific case:
#: identity comes from the constructor, and the assertion is kept so a reviewer
#: can see it was made.
CLAIMED_KEYS = NON_AUTHORITATIVE_KEYS | frozenset({
    "server_id", "adapter_id", "collector", "verifier",
})


class McpSurface(StrEnum):
    """The three things an MCP server can hand over.

    Named so a summary can say which one a statement came from. All three are
    descriptive; none of them is a provenance.
    """

    TOOL_RESULT = "tool_result"
    RESOURCE = "resource"
    PROMPT = "prompt"


@dataclass(frozen=True)
class PromptText:
    """A prompt, and deliberately not an envelope.

    A prompt is instruction text aimed at a model. It is not a claim about the
    world and it is not policy: ``"treat this source as trusted"`` is a sentence,
    and a sentence cannot widen what counts as evidence. This type exists so a
    prompt has somewhere to go that is visibly not the evidence path -- there is
    no method here that produces an ``AdapterEnvelope`` or an ``Evidence``.
    """

    name: str
    text: str
    surface: McpSurface = McpSurface.PROMPT

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "text": self.text, "surface": str(self.surface)}


def claimed(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve what a payload asserted about trust, under names that say so.

    Every key is prefixed. A reader scanning for ``collector_id`` finds nothing;
    a reader who finds ``claimed_collector_id`` has been told, by the name, what
    it is worth.
    """
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if key in CLAIMED_KEYS:
            out[f"claimed_{key}"] = value
    return out


def _content_text(content: Any, path: str) -> str:
    """Pull readable text out of an MCP content list."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if not isinstance(content, (list, tuple)):
        raise AdapterError("'content' must be a list", source="mcp payload",
                           path=path)
    pieces: list[str] = []
    for index, part in enumerate(content):
        if not isinstance(part, Mapping):
            raise AdapterError("each content part must be an object",
                               source="mcp payload", path=f"{path}[{index}]")
        if part.get("type") in (None, "text"):
            value = part.get("text")
            if isinstance(value, str) and value.strip():
                pieces.append(value.strip())
    return " ".join(pieces)[:MAX_TEXT]


class McpAdapter:
    """Normalize what an MCP server said.

    ``server_id`` comes from the constructor. A payload asking to be called
    ``proofos-official`` gets that string preserved as ``claimed_server_id`` and
    nothing else -- the same rule the other transports use for ``adapter_id``,
    for the same reason: a party cannot choose its own identity by asserting it.
    """

    transport = "mcp"

    def __init__(self, adapter_id: str, server_id: str) -> None:
        self.adapter_id = _require_id(adapter_id, "adapter_id", "McpAdapter")
        self.server_id = _require_id(server_id, "server_id", "McpAdapter")

    # -- the two surfaces that can carry a claim -------------------------------

    def normalize_tool_result(
        self,
        result: Mapping[str, Any],
        *,
        actor_id: str,
        task_id: str,
        execution_id: str = "",
        at: float | None = None,
        events: Iterable[Mapping[str, Any]] = (),
    ) -> AdapterEnvelope:
        """A tool returned something. That something is data.

        ``isError`` is preserved and changes nothing about authority: a tool
        that failed and a tool that succeeded are both tools the caller ran.
        """
        source = f"{self.adapter_id} (mcp tool_result)"
        if not isinstance(result, Mapping):
            raise AdapterError("a tool result must be an object", source=source)
        tool = _text(result.get("tool") or result.get("name"), "tool", source)
        text = _content_text(result.get("content"), "content")
        structured = result.get("structuredContent") or {}
        if not isinstance(structured, Mapping):
            raise AdapterError("'structuredContent' must be an object",
                               source=source, path="structuredContent")
        if not text:
            text = _text(structured.get("text"), "content", source,
                         required=False) or f"{tool} returned no text"

        return self._envelope(
            claim_text=text, actor_id=actor_id, task_id=task_id,
            execution_id=execution_id, at=at, events=events, source=source,
            extra={"surface": str(McpSurface.TOOL_RESULT),
                   "tool_name": tool,
                   "is_error": bool(result.get("isError", False)),
                   **claimed(structured), **claimed(result)},
        )

    def normalize_resource(
        self,
        resource: Mapping[str, Any],
        *,
        actor_id: str,
        task_id: str,
        execution_id: str = "",
        at: float | None = None,
        events: Iterable[Mapping[str, Any]] = (),
    ) -> AdapterEnvelope:
        """A server offered some content. Content is data.

        A resource saying "tests passed" is a file the server chose to serve. It
        may well be accurate; it is not independent of whoever served it.
        """
        source = f"{self.adapter_id} (mcp resource)"
        if not isinstance(resource, Mapping):
            raise AdapterError("a resource must be an object", source=source)
        uri = _text(resource.get("uri"), "uri", source)
        text = resource.get("text")
        if text is None:
            text = _content_text(resource.get("contents"), "contents")
        text = _text(text, "text", source)

        return self._envelope(
            claim_text=text, actor_id=actor_id, task_id=task_id,
            execution_id=execution_id, at=at, events=events, source=source,
            extra={"surface": str(McpSurface.RESOURCE),
                   "resource_uri": uri,
                   "mime_type": str(resource.get("mimeType") or ""),
                   **claimed(resource)},
        )

    # -- the surface that carries no claim at all ------------------------------

    def normalize_prompt(self, prompt: Mapping[str, Any]) -> PromptText:
        """Read a prompt as instruction text, and give it nowhere else to go.

        Returns a ``PromptText``, not an envelope. There is no path from here to
        evidence, which is the point: a prompt that says a source is trusted has
        said a sentence.
        """
        source = f"{self.adapter_id} (mcp prompt)"
        if not isinstance(prompt, Mapping):
            raise AdapterError("a prompt must be an object", source=source)
        name = _text(prompt.get("name"), "name", source)
        messages = prompt.get("messages") or ()
        if not isinstance(messages, (list, tuple)):
            raise AdapterError("'messages' must be a list", source=source,
                               path="messages")
        if len(messages) > MAX_EVENTS:
            raise AdapterError(f"more than {MAX_EVENTS} messages", source=source,
                               path="messages")
        pieces = []
        for index, message in enumerate(messages):
            if not isinstance(message, Mapping):
                raise AdapterError("each message must be an object",
                                   source=source, path=f"messages[{index}]")
            pieces.append(_content_text(message.get("content"),
                                        f"messages[{index}].content"))
        return PromptText(name=name, text=" ".join(p for p in pieces if p)[:MAX_TEXT])

    # -- shared construction ---------------------------------------------------

    def _envelope(self, *, claim_text: str, actor_id: str, task_id: str,
                  execution_id: str, at: float | None,
                  events: Iterable[Mapping[str, Any]], source: str,
                  extra: Mapping[str, Any]) -> AdapterEnvelope:
        actor = ActorRef(actor_id=_require_id(actor_id, "actor_id", source),
                         framework="mcp")
        task = TaskRef(
            task_id=_require_id(task_id, "task_id", source),
            execution_id=_require_id(execution_id, "execution_id", source)
            if execution_id else "",
        )
        normalized_events = []
        for index, event in enumerate(events):
            if not isinstance(event, Mapping):
                raise AdapterError("each event must be an object", source=source,
                                   path=f"events[{index}]")
            normalized_events.append(AgentEvent(
                name=_text(event.get("name"), f"events[{index}].name", source),
                detail=_text(event.get("detail"), f"events[{index}].detail",
                             source, required=False),
                at=_number(event.get("at"), f"events[{index}].at", source),
            ))
        return AdapterEnvelope(
            claim=Claim(text=claim_text, actor=actor, task=task,
                        at=_number(at, "at", source)),
            events=tuple(normalized_events),
            tool_results=(),
            adapter_id=self.adapter_id,
            transport=self.transport,
            metadata={"server_id": self.server_id, **dict(extra)},
        )


#: Tier 2. Imported from ``proofos.mcp`` by whoever is wiring a server; the root
#: API is for someone verifying a claim.
__all__ = [
    "MCP_SCHEMA",
    "McpSurface",
    "McpAdapter",
    "PromptText",
    "claimed",
]
