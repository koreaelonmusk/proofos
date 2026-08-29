"""A translation boundary for external agent data. It moves words, not authority.

Any framework -- LangGraph, CrewAI, AutoGen, a raw HTTP webhook -- can describe
an actor, a task, a claim, an event, or a tool's output in its own shape. This
module receives one such description as ordinary data and returns a neutral,
immutable ``NormalizedRecord``. That is the whole job. The record is a faithful
copy of what the caller said, in a stable form the rest of the platform can
read without knowing the sender's dialect.

What this module deliberately cannot do is the reason it is safe to point any
framework at it:

    * It imports nothing from the ProofOS trusted core. It cannot construct an
      ``Evidence``, cannot name ``EvidenceSource.OBSERVED``, cannot produce a
      ``VerificationStatus``, and cannot call ``verify_completion`` -- you
      cannot call what you never import. This is enforced by test, not trust.
    * A field the sender called ``"verified"``, ``"trusted"``, ``"status"``, or
      ``"source": "OBSERVED"`` is copied through as opaque data and promoted to
      nothing. An external string is a declaration; only the verifier, fed
      independently collected evidence, decides what is VERIFIED.
    * There is no ``verify``, ``trust``, ``grant``, ``collect``, ``execute``,
      ``run``, or ``invoke`` here, under any name. The adapter is an interpreter
      at the door, never a seat on the bench.

So an external payload that shouts success arrives here and leaves as a record
that proves nothing. To become trusted, a claim must travel the ordinary
ProofOS path: a collector the runtime authorised observes reality, and the
verifier reads that observation. Different route, and only then a different
answer. This file only makes sure the door does not double as the bench.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

__all__ = [
    "RecordKind",
    "NormalizedRecord",
    "AdapterError",
    "normalize",
    "normalize_actor",
    "normalize_task",
    "normalize_claim",
    "normalize_event",
    "normalize_tool_output",
    "normalize_all",
]


class RecordKind(StrEnum):
    """What an external payload is describing.

    A representation label, not a trust class. Nothing here says a record is
    believed; it only says what shape of thing the caller handed over.
    """

    ACTOR = "actor"
    TASK = "task"
    CLAIM = "claim"
    EVENT = "event"
    TOOL_OUTPUT = "tool_output"


class AdapterError(ValueError):
    """External data could not be translated into a neutral record.

    Raised rather than guessed. A record with no identity or no content, or one
    carrying a value that is not plain data (a live object, a callable), is
    refused -- the alternative is to invent a default that would give meaning
    the sender never supplied.
    """


#: Per kind, the external keys that may carry the record's identity, in
#: preference order. The first present key with a non-empty scalar wins. This is
#: dialect translation, nothing more: an identity is a name for a thing, never a
#: statement about whether the thing is real or trusted.
_IDENTITY_KEYS: dict[RecordKind, tuple[str, ...]] = {
    RecordKind.ACTOR: ("id", "actor_id", "agent_id", "name"),
    RecordKind.TASK: ("id", "task_id"),
    RecordKind.CLAIM: ("id", "claim_id"),
    RecordKind.EVENT: ("id", "event_id"),
    RecordKind.TOOL_OUTPUT: ("id", "tool_call_id", "call_id", "tool", "name"),
}

#: Per kind, the external keys that may carry the substantive content, in
#: preference order. The content is copied as text; it is never parsed for a
#: verdict. A tool output field literally reading ``"success"`` becomes the
#: string ``"success"`` and stays a string.
_CONTENT_KEYS: dict[RecordKind, tuple[str, ...]] = {
    RecordKind.ACTOR: ("role", "description", "name"),
    RecordKind.TASK: ("description", "goal", "title", "name"),
    RecordKind.CLAIM: ("claim", "statement", "text", "message"),
    RecordKind.EVENT: ("event", "type", "message", "name"),
    RecordKind.TOOL_OUTPUT: ("output", "result", "content", "value"),
}


@dataclass(frozen=True)
class NormalizedRecord:
    """A neutral, immutable copy of what an external sender said.

    Every field is a translation of the caller's words. None of them is a
    finding. In particular there is deliberately no ``source`` of type
    ``EvidenceSource``, no ``status`` of type ``VerificationStatus``, and no
    ``trusted`` flag: a record cannot express provenance authority or a verdict,
    because the types that mean those things are never imported here.

    ``declarations`` holds the entire original payload, frozen. Whatever the
    sender asserted -- including ``"verified": true`` or ``"source":
    "OBSERVED"`` -- is preserved there verbatim, as data a reader may inspect
    and a verifier will ignore. Reading a value out of ``declarations`` returns
    exactly what was sent and confers nothing.
    """

    record_kind: RecordKind
    identity: str
    content: str
    declarations: Mapping[str, object]
    origin_label: str = "external"

    def declaration(self, key: str, default: object = None) -> object:
        """Read one preserved external value. Inert: returns data, grants nothing."""
        return self.declarations.get(key, default)


def _freeze(value: object) -> object:
    """Return a deeply immutable, alias-isolated copy of plain data.

    Mappings become read-only proxies with string keys; sequences become
    tuples; scalars pass through. Anything else -- a callable, a live handle, an
    arbitrary object -- is refused, because carrying it would both defeat the
    isolation this gives (later mutation leaking back into a record) and retain
    a thing the adapter has no business holding. Bytes are decoded as text so a
    record stays comparable and serialisable.

    The isolation matters: a caller may mutate its input dict after adaptation,
    and the record must not change under it.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(k): _freeze(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
        )
    if isinstance(value, Sequence):
        return tuple(_freeze(v) for v in value)
    raise AdapterError(
        f"value of type {type(value).__name__!r} is not plain data; the adapter "
        "translates data, and refuses to retain live objects or callables"
    )


def _plain(value: object) -> object:
    """Undo ``_freeze`` into JSON-native containers for canonical serialisation."""
    if isinstance(value, MappingProxyType):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    return value


def _content_text(value: object) -> str:
    """Copy a content value to text without interpreting it.

    A string is taken as-is. Anything structured is rendered as canonical JSON
    (sorted keys, stable separators) so the same input always yields the same
    text -- a faithful transcription, not a reading of meaning.
    """
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"))


def _first_identity(kind: RecordKind, frozen: Mapping[str, object]) -> str:
    """The first identity key holding a non-empty scalar. An id is a name, not a record."""
    for key in _IDENTITY_KEYS[kind]:
        raw = frozen.get(key)
        if isinstance(raw, (str, int, float)) and not isinstance(raw, bool):
            text = str(raw).strip()
            if text:
                return text
    raise AdapterError(
        f"{kind} payload has no usable identity; expected one of "
        f"{list(_IDENTITY_KEYS[kind])} with a non-empty scalar value"
    )


def _first_content(kind: RecordKind, frozen: Mapping[str, object]) -> str:
    """The first content key holding non-empty content, copied to text."""
    for key in _CONTENT_KEYS[kind]:
        if key in frozen:
            text = _content_text(frozen[key])
            if text:
                return text
    raise AdapterError(
        f"{kind} payload has no usable content; expected one of "
        f"{list(_CONTENT_KEYS[kind])} with a non-empty value"
    )


def normalize(
    kind: RecordKind | str,
    payload: Mapping[str, object],
    origin_label: str = "external",
) -> NormalizedRecord:
    """Translate one external payload into a neutral record.

    Pure and total-or-raising: the same payload always yields an equal record,
    nothing outside the arguments is read (no clock, no environment, no
    filesystem, no network), and an input that cannot be honestly translated
    raises ``AdapterError`` rather than acquiring an invented default.

    ``origin_label`` is a free-text note of where the caller got the data (for
    example ``"langgraph"``). It is inert metadata -- it is never read from the
    payload's own fields and never means provenance, authority, or trust.
    """
    record_kind = kind if isinstance(kind, RecordKind) else RecordKind(str(kind))
    if not isinstance(payload, Mapping):
        raise AdapterError(
            f"payload must be a mapping of external fields, got {type(payload).__name__!r}"
        )
    if not isinstance(origin_label, str):
        raise AdapterError("origin_label must be a string; it is an inert data label")
    frozen = _freeze(payload)
    assert isinstance(frozen, MappingProxyType)  # payload is a Mapping, so this holds
    return NormalizedRecord(
        record_kind=record_kind,
        identity=_first_identity(record_kind, frozen),
        content=_first_content(record_kind, frozen),
        declarations=frozen,
        origin_label=origin_label.strip() or "external",
    )


def normalize_actor(payload: Mapping[str, object], origin_label: str = "external") -> NormalizedRecord:
    """Translate an external actor/agent description."""
    return normalize(RecordKind.ACTOR, payload, origin_label)


def normalize_task(payload: Mapping[str, object], origin_label: str = "external") -> NormalizedRecord:
    """Translate an external task description."""
    return normalize(RecordKind.TASK, payload, origin_label)


def normalize_claim(payload: Mapping[str, object], origin_label: str = "external") -> NormalizedRecord:
    """Translate an external completion/claim description. It stays a claim."""
    return normalize(RecordKind.CLAIM, payload, origin_label)


def normalize_event(payload: Mapping[str, object], origin_label: str = "external") -> NormalizedRecord:
    """Translate an external event description."""
    return normalize(RecordKind.EVENT, payload, origin_label)


def normalize_tool_output(payload: Mapping[str, object], origin_label: str = "external") -> NormalizedRecord:
    """Translate an external tool result. A tool's own 'success' is not evidence."""
    return normalize(RecordKind.TOOL_OUTPUT, payload, origin_label)


def normalize_all(
    items: Sequence[tuple[RecordKind | str, Mapping[str, object]]],
    origin_label: str = "external",
) -> tuple[NormalizedRecord, ...]:
    """Translate a batch of ``(kind, payload)`` pairs, preserving order.

    Deterministic and order-preserving. A single un-translatable item raises,
    rather than the batch silently dropping it and returning a shorter, quietly
    lossy result.
    """
    return tuple(normalize(kind, payload, origin_label) for kind, payload in items)
