"""Agent turns, behind a narrow abstraction.

The orchestration owns the state machine. A turn runner owns one bounded
conversation with whatever is playing a role -- deterministic Python or a live
Gemini agent -- and hands back a record of what happened.

The distinction that matters is in ``decision_from``. A verifier turn produces
prose *and* a tool result. Only the tool result is authority. A model that says
"VERIFIED" while its tool returned ABSTAIN has narrated, not decided, and the
runtime reads past it. That is not defensive coding for its own sake: an LLM
confidently summarizing its own success is precisely the failure mode ProofOS
exists to catch, and it would be absurd to let it back in through the component
that reports the verdict.

Nothing here can produce evidence. A turn runner runs agents and records what
they did; writing OBSERVED evidence needs a signed attestation, which needs a
key that lives in another process.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

VERIFY_TOOL = "verify_task_completion"
ACTION_TOOL = "perform_action"


@dataclass(frozen=True)
class ToolInvocation:
    """One tool call an agent made, and what came back."""

    name: str
    args: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None

    def summary(self) -> dict[str, Any]:
        """Safe for journaling: names and arguments, never key material."""
        return {
            "tool": self.name,
            "args": {k: v for k, v in self.args.items() if k in {"task_id", "claim"}},
            "status": (self.result or {}).get("status"),
        }


@dataclass(frozen=True)
class AgentTurn:
    """What one agent actually did during one bounded turn."""

    role: str
    agent_id: str
    model: str
    attempt: int = 0
    session_id: str = ""
    tool_calls: tuple[ToolInvocation, ...] = ()
    final_text: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    error: str = ""

    @property
    def failed(self) -> bool:
        return bool(self.error)

    def calls_to(self, name: str) -> tuple[ToolInvocation, ...]:
        return tuple(c for c in self.tool_calls if c.name == name)

    def summary(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "agent_id": self.agent_id,
            "model": self.model,
            "attempt": self.attempt,
            "tool_calls": [c.summary() for c in self.tool_calls],
            "final_text": self.final_text[:500],
            "duration_ms": int((self.completed_at - self.started_at) * 1000),
            "error": self.error,
        }


@dataclass(frozen=True)
class VerdictExtraction:
    """The deterministic decision a verifier turn produced, if any."""

    decision: dict[str, Any] | None
    noncompliance: str = ""

    @property
    def usable(self) -> bool:
        return self.decision is not None and not self.noncompliance


def decision_from(turn: AgentTurn, expected_task_id: str) -> VerdictExtraction:
    """Read the verdict out of a verifier turn. Prose is never consulted.

    Refuses rather than guesses when the turn is ambiguous: no tool call, a tool
    call for a different task, or a call with no result are all
    MODEL_NONCOMPLIANCE. A verifier that did not demonstrably ask the
    deterministic verifier about *this* task has not produced a verdict, however
    confidently it wrote one.
    """
    if turn.failed:
        return VerdictExtraction(None, f"verifier turn failed: {turn.error}")

    calls = turn.calls_to(VERIFY_TOOL)
    if not calls:
        return VerdictExtraction(
            None, "verifier did not call the verification tool"
        )

    for call in calls:
        supplied = call.args.get("task_id")
        if supplied != expected_task_id:
            # The runtime chose the task. A model substituting its own is
            # answering a question nobody asked.
            return VerdictExtraction(
                None,
                f"verifier called the tool for task {supplied!r}, "
                f"not {expected_task_id!r}",
            )

    decided = [c for c in calls if isinstance(c.result, dict) and c.result.get("status")]
    if not decided:
        return VerdictExtraction(None, "verification tool returned no decision")

    # A model may call the tool more than once; the last completed result stands.
    return VerdictExtraction(decided[-1].result)


class AgentTurnRunner(Protocol):
    """One bounded turn per role, for one execution."""

    async def plan(self, task_id: str, goal: str) -> AgentTurn: ...

    async def execute(self, task_id: str, instruction: str) -> AgentTurn: ...

    async def verify(self, task_id: str, claim: str, attempt: int) -> AgentTurn: ...

    def describe(self) -> dict[str, Any]: ...

    async def aclose(self) -> None: ...


class DeterministicTurnRunner:
    """Scripted turns that call the same deterministic components.

    Not a mock of Gemini and not presented as one: it exercises the
    orchestration contract without any model, which is what lets the state
    machine be tested exhaustively and cheaply. Runs marked with this runtime
    are never described as live.
    """

    RUNTIME = "deterministic"

    def __init__(self, fleet, verify_tool, model: str = "none") -> None:
        self._fleet = fleet
        self._verify_tool = verify_tool
        self._model = model

    def describe(self) -> dict[str, Any]:
        return {
            "agent_runtime": self.RUNTIME,
            "model": self._model,
            "live_model_enabled": False,
        }

    async def plan(self, task_id: str, goal: str) -> AgentTurn:
        started = time.time()
        self._fleet.planner.plan(task_id, goal, ())
        return AgentTurn(
            role="planner",
            agent_id=self._fleet.planner._ctx.agent_id,
            model=self._model,
            final_text=f"plan: {goal}",
            started_at=started,
            completed_at=time.time(),
        )

    async def execute(self, task_id: str, instruction: str) -> AgentTurn:
        started = time.time()
        result = self._fleet.executor.execute(task_id, lambda: "patch applied")
        return AgentTurn(
            role="executor",
            agent_id=self._fleet.executor._ctx.agent_id,
            model=self._model,
            tool_calls=(
                ToolInvocation(ACTION_TOOL, {"instruction": instruction}, {"result": result}),
            ),
            final_text=result,
            started_at=started,
            completed_at=time.time(),
        )

    async def verify(self, task_id: str, claim: str, attempt: int) -> AgentTurn:
        started = time.time()
        args = {"task_id": task_id, "claim": claim}
        result = self._verify_tool(**args)
        return AgentTurn(
            role="verifier",
            agent_id=self._fleet.verifier._ctx.agent_id,
            model=self._model,
            attempt=attempt,
            tool_calls=(ToolInvocation(VERIFY_TOOL, args, result),),
            final_text=result["status"],
            started_at=started,
            completed_at=time.time(),
        )

    async def aclose(self) -> None:
        return None
