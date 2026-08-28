"""Authority and orchestration failure classes.

Verification failures live in ``verifier.FailureClass`` and describe why a claim
could not be believed. These describe why an *actor* was not allowed to do
something, or why an execution could not proceed safely.

Every one of these is terminal-safe. None of them may ever map to success.
"""

from __future__ import annotations

from enum import StrEnum


class AuthorityFailure(StrEnum):
    CAPABILITY_DENIED = "CAPABILITY_DENIED"
    AGENT_IDENTITY_INVALID = "AGENT_IDENTITY_INVALID"
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"
    MESSAGE_REPLAYED = "MESSAGE_REPLAYED"
    MESSAGE_MISROUTED = "MESSAGE_MISROUTED"
    POLICY_REJECTED = "POLICY_REJECTED"
    MODEL_NONCOMPLIANCE = "MODEL_NONCOMPLIANCE"
    MODEL_FAILURE = "MODEL_FAILURE"
    COLLECTOR_UNAVAILABLE = "COLLECTOR_UNAVAILABLE"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    NONE = "NONE"


class CapabilityDenied(PermissionError):
    """Raised when a component attempts something its capability forbids.

    This is a hard failure, never a downgrade: a denied attempt must not
    silently proceed with reduced effect.
    """

    def __init__(self, agent_id: str, attempted: str, reason: str = "") -> None:
        detail = f"agent {agent_id!r} may not {attempted}"
        if reason:
            detail = f"{detail}: {reason}"
        super().__init__(detail)
        self.agent_id = agent_id
        self.attempted = attempted
        self.reason = reason


class AgentIdentityInvalid(PermissionError):
    """Raised when an agent id is unknown, or does not match the runtime holder."""


class ToolNotAllowed(PermissionError):
    """Raised when a role is configured with a tool outside its remit."""


class MessageRejected(ValueError):
    """Raised when an envelope is replayed, misrouted, or otherwise untrustworthy."""

    def __init__(self, failure: AuthorityFailure, detail: str) -> None:
        super().__init__(f"{failure}: {detail}")
        self.failure = failure
