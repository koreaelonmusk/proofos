"""Bounded recovery loop around the verification decision.

An ABSTAIN names the evidence kinds that were not satisfied. Recovery attempts to
collect exactly those, then re-verifies. The loop is bounded: it terminates on
VERIFIED, on exhausted retries, or when no collector exists for what is missing.
It never converts a failure into a success.

Every step is appended to the execution journal, so the final decision can be
reconstructed afterwards without trusting the agent's account of it.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping

from proofos.journal import EventType, Journal, Severity

MAX_ATTEMPTS = 2

ORCHESTRATOR = "orchestrator"
VERIFIER = "verifier"
COLLECTOR = "collector"
EXECUTOR = "executor"


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


def _collector_detail(result: Any) -> dict[str, Any]:
    """Describe a collector's result without assuming its concrete type."""
    if result is None:
        return {"outcome": "NONE"}
    outcome = getattr(result, "outcome", None)
    return {
        "outcome": str(outcome) if outcome is not None else "UNKNOWN",
        "recorded": bool(getattr(result, "observed_response", False)),
        "satisfies_requirement": bool(getattr(result, "healthy", False)),
        "detail": str(getattr(result, "detail", "")),
    }


async def run_verification_loop(
    run_turn: TurnRunner,
    collectors: Mapping[str, Callable[[], Any]],
    max_attempts: int = MAX_ATTEMPTS,
    journal: Journal | None = None,
) -> dict:
    transcript: list[dict] = []
    final_status = "ABSTAIN"
    terminal_reason = "No attempt was made."
    failure_class = "RETRY_EXHAUSTED"

    def note(event: EventType, agent: str, status: str, severity=Severity.INFO, **detail):
        if journal is not None:
            journal.record(event, agent, status, severity, **detail)

    note(
        EventType.EXECUTION_START,
        ORCHESTRATOR,
        "STARTED",
        max_attempts=max_attempts,
        collectors=sorted(collectors),
    )

    for attempt in range(1, max_attempts + 1):
        turn = await run_turn(attempt)
        decision = turn.decision

        note(
            EventType.AGENT_TURN,
            EXECUTOR,
            "CLAIMED_SUCCESS" if turn.final_text else "RESPONDED",
            attempt=attempt,
            tool_call_count=len(turn.tool_calls),
        )
        for call in turn.tool_calls:
            note(
                EventType.TOOL_CALL,
                EXECUTOR,
                "INVOKED",
                attempt=attempt,
                tool=call.get("name"),
                args=call.get("args"),
            )

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
            failure_class = "MODEL_NONCOMPLIANCE"
            note(
                EventType.VERIFIER_DECISION,
                VERIFIER,
                "ABSTAIN",
                Severity.WARNING,
                attempt=attempt,
                failure=failure_class,
                reason=terminal_reason,
            )
            break

        note(
            EventType.VERIFIER_DECISION,
            VERIFIER,
            decision.get("status", "UNKNOWN"),
            Severity.INFO
            if decision.get("status") == "VERIFIED"
            else Severity.WARNING,
            attempt=attempt,
            failure=decision.get("failure"),
            missing=decision.get("missing"),
            reason=decision.get("reason"),
        )

        if decision.get("status") == "VERIFIED":
            final_status = "VERIFIED"
            terminal_reason = decision.get("reason", "")
            failure_class = "NONE"
            break

        missing = list(decision.get("missing") or [])
        if attempt == max_attempts:
            terminal_reason = f"RETRY_EXHAUSTED after {max_attempts} attempts."
            failure_class = "RETRY_EXHAUSTED"
            break

        uncollectable = [kind for kind in missing if kind not in collectors]
        if uncollectable:
            terminal_reason = f"No collector available for evidence: {uncollectable}."
            failure_class = "COLLECTOR_UNAVAILABLE"
            break

        note(
            EventType.RECOVERY_START,
            ORCHESTRATOR,
            "COLLECTING",
            attempt=attempt,
            missing=missing,
        )
        for kind in missing:
            # Collectors may be async so that blocking I/O can be offloaded off
            # the event loop. A collector that blocks the loop would stall the
            # whole worker, including any endpoint it is trying to observe.
            result = collectors[kind]()
            if inspect.isawaitable(result):
                result = await result
            detail = _collector_detail(result)
            collected = detail.get("recorded")
            note(
                EventType.EVIDENCE_COLLECTED
                if collected
                else EventType.EVIDENCE_REJECTED,
                COLLECTOR,
                detail.get("outcome", "UNKNOWN"),
                Severity.INFO if collected else Severity.WARNING,
                attempt=attempt,
                kind=kind,
                **detail,
            )

    note(
        EventType.EXECUTION_COMPLETE,
        ORCHESTRATOR,
        final_status,
        Severity.INFO if final_status == "VERIFIED" else Severity.WARNING,
        failure=failure_class,
        reason=terminal_reason,
        attempts=len(transcript),
    )

    outcome = {
        "attempts": transcript,
        "final_status": final_status,
        "terminal_reason": terminal_reason,
        "failure_class": failure_class,
    }
    if journal is not None:
        outcome["execution_id"] = journal.execution_id
        outcome["trace_id"] = journal.trace_id
    return outcome
