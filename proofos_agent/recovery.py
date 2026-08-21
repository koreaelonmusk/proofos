"""Bounded recovery loop around the verification decision.

An ABSTAIN names the evidence kinds that were not satisfied. Recovery attempts to
collect exactly those, then re-verifies. The loop is bounded: it terminates on
VERIFIED, on exhausted retries, or when no collector exists for what is missing.
It never converts a failure into a success.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable, Mapping

MAX_ATTEMPTS = 2


@dataclass
class Turn:
    """What the agent actually did on one attempt."""

    attempt: int
    tool_calls: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    final_text: str = ""

    @property
    def decision(self) -> dict | None:
        """The verifier's decision, or None if the tool was never called."""
        return self.tool_results[-1] if self.tool_results else None


TurnRunner = Callable[[int], Awaitable[Turn]]


async def run_verification_loop(
    run_turn: TurnRunner,
    collectors: Mapping[str, Callable[[], None]],
    max_attempts: int = MAX_ATTEMPTS,
) -> dict:
    transcript: list[dict] = []
    final_status = "ABSTAIN"
    terminal_reason = "No attempt was made."

    for attempt in range(1, max_attempts + 1):
        turn = await run_turn(attempt)
        decision = turn.decision

        transcript.append(
            {
                "attempt": attempt,
                "tool_calls": turn.tool_calls,
                "verifier_decision": decision,
                "agent_final_text": turn.final_text.strip(),
            }
        )

        if decision is None:
            # The agent tried to answer without calling the verifier. Fail closed.
            terminal_reason = "Model did not call the verification tool."
            break

        if decision.get("status") == "VERIFIED":
            final_status = "VERIFIED"
            terminal_reason = decision.get("reason", "")
            break

        missing = list(decision.get("missing") or [])
        if attempt == max_attempts:
            terminal_reason = f"RETRY_EXHAUSTED after {max_attempts} attempts."
            break

        uncollectable = [kind for kind in missing if kind not in collectors]
        if uncollectable:
            terminal_reason = f"No collector available for evidence: {uncollectable}."
            break

        for kind in missing:
            collectors[kind]()

    return {
        "attempts": transcript,
        "final_status": final_status,
        "terminal_reason": terminal_reason,
    }
