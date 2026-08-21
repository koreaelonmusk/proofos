"""Typed cross-agent envelopes with runtime-assigned identity.

An agent must not be able to become the collector by saying it is the
collector. Identity here is a property of the object you were handed, not a
field you fill in: a component holds a ``MessageSender`` bound to its own agent
id at construction, and the bus stamps that id onto everything it sends. A
``sender_agent_id`` appearing in a payload is data, and is treated as data.

Messages carry no authority of their own. Receiving a VERIFY_RESULT does not
let you write one; that still requires the capability. The envelope exists so
the conversation is typed, correlated, and auditable -- not so it can be used
as a permission.

The bus also refuses messages it did not issue, replays, and envelopes
belonging to another execution or task.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .failures import AgentIdentityInvalid, AuthorityFailure, MessageRejected
from .registry import AgentRegistry

DEFAULT_MAX_AGE_SECONDS = 300.0


class MessageType(StrEnum):
    PLAN = "PLAN"
    ACTION_REQUEST = "ACTION_REQUEST"
    ACTION_RESULT = "ACTION_RESULT"
    CLAIM = "CLAIM"
    COLLECTION_REQUEST = "COLLECTION_REQUEST"
    EVIDENCE_RESULT = "EVIDENCE_RESULT"
    VERIFY_REQUEST = "VERIFY_REQUEST"
    VERIFY_RESULT = "VERIFY_RESULT"
    RECOVERY_REQUEST = "RECOVERY_REQUEST"


def new_message_id() -> str:
    return f"msg_{uuid.uuid4().hex}"


@dataclass(frozen=True)
class AgentMessage:
    message_id: str
    execution_id: str
    task_id: str
    sender_agent_id: str
    recipient_agent_id: str
    message_type: MessageType
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    correlation_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "sender_agent_id": self.sender_agent_id,
            "recipient_agent_id": self.recipient_agent_id,
            "message_type": str(self.message_type),
            "payload": self.payload,
            "created_at": self.created_at,
            "correlation_id": self.correlation_id,
        }


class MessageSender:
    """A send handle bound to one agent identity.

    The bound id is assigned at construction by the runtime. Nothing a caller
    passes can change it, which is the whole point.
    """

    __slots__ = ("_bus", "agent_id")

    def __init__(self, bus: "MessageBus", agent_id: str) -> None:
        self._bus = bus
        self.agent_id = agent_id

    def send(
        self,
        recipient_agent_id: str,
        message_type: MessageType,
        correlation_id: str = "",
        **payload: Any,
    ) -> AgentMessage:
        return self._bus._issue(
            sender_agent_id=self.agent_id,
            recipient_agent_id=recipient_agent_id,
            message_type=message_type,
            correlation_id=correlation_id,
            payload=payload,
        )


class MessageBus:
    """Issues and validates envelopes for one execution."""

    def __init__(
        self,
        registry: AgentRegistry,
        execution_id: str,
        task_id: str,
        max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    ) -> None:
        self._registry = registry
        self.execution_id = execution_id
        self.task_id = task_id
        self._max_age = max_age_seconds
        self._issued: dict[str, str] = {}
        self._delivered: set[str] = set()
        self._log: list[AgentMessage] = []

    def sender_for(self, agent_id: str) -> MessageSender:
        """Hand out a send handle. Unknown agents get nothing."""
        self._registry.get(agent_id)
        return MessageSender(self, agent_id)

    def _issue(
        self,
        sender_agent_id: str,
        recipient_agent_id: str,
        message_type: MessageType,
        correlation_id: str,
        payload: dict[str, Any],
    ) -> AgentMessage:
        self._registry.get(sender_agent_id)
        self._registry.get(recipient_agent_id)

        # Anything in the payload that looks like an identity claim is dropped:
        # the sender is who the runtime says it is.
        clean = {
            key: value
            for key, value in payload.items()
            if key not in {"sender_agent_id", "execution_id", "task_id"}
        }

        message = AgentMessage(
            message_id=new_message_id(),
            execution_id=self.execution_id,
            task_id=self.task_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            message_type=message_type,
            payload=clean,
            created_at=time.time(),
            correlation_id=correlation_id or new_message_id(),
        )
        self._issued[message.message_id] = sender_agent_id
        self._log.append(message)
        return message

    def accept(self, message: AgentMessage, recipient_agent_id: str) -> AgentMessage:
        """Validate an envelope before a recipient acts on it.

        Refuses anything this bus did not issue, anything already delivered,
        anything from another execution or task, and anything stale.
        """
        if not isinstance(message, AgentMessage):
            raise MessageRejected(
                AuthorityFailure.POLICY_REJECTED, "not an AgentMessage"
            )

        true_sender = self._issued.get(message.message_id)
        if true_sender is None:
            raise MessageRejected(
                AuthorityFailure.AGENT_IDENTITY_INVALID,
                f"message {message.message_id} was not issued by this runtime",
            )
        if true_sender != message.sender_agent_id:
            raise MessageRejected(
                AuthorityFailure.AGENT_IDENTITY_INVALID,
                f"message {message.message_id} claims sender "
                f"{message.sender_agent_id!r} but was issued by {true_sender!r}",
            )

        if message.execution_id != self.execution_id:
            raise MessageRejected(
                AuthorityFailure.MESSAGE_MISROUTED,
                f"message belongs to execution {message.execution_id!r}",
            )
        if message.task_id != self.task_id:
            raise MessageRejected(
                AuthorityFailure.MESSAGE_MISROUTED,
                f"message belongs to task {message.task_id!r}",
            )
        if message.recipient_agent_id != recipient_agent_id:
            raise MessageRejected(
                AuthorityFailure.MESSAGE_MISROUTED,
                f"message is addressed to {message.recipient_agent_id!r}, "
                f"not {recipient_agent_id!r}",
            )

        if message.message_id in self._delivered:
            raise MessageRejected(
                AuthorityFailure.MESSAGE_REPLAYED,
                f"message {message.message_id} was already delivered",
            )

        age = time.time() - message.created_at
        if age > self._max_age:
            raise MessageRejected(
                AuthorityFailure.POLICY_REJECTED,
                f"message is {age:.0f}s old, older than {self._max_age:.0f}s",
            )

        self._delivered.add(message.message_id)
        return message

    def history(self) -> tuple[AgentMessage, ...]:
        return tuple(self._log)


def require_identity(registry: AgentRegistry, agent_id: str) -> str:
    """Resolve an agent id or refuse. Never invents an identity."""
    try:
        registry.get(agent_id)
    except AgentIdentityInvalid:
        raise
    return agent_id
