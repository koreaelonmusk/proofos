"""Multi-agent execution with bounded recovery.

The orchestrator routes and budgets. It cannot observe, cannot verify, and
cannot open a task with no requirements. When every downstream role fails it
terminates safely, which for this product means ABSTAIN with a named cause --
never a shrug that reads as success.
"""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Iterable

from proofos.failures import (
    AuthorityFailure,
    CapabilityDenied,
    MessageRejected,
)
from proofos.journal import EventType, Journal, JournalUnavailableError, Severity
from proofos.verifier import Requirement

from .fleet import Fleet

MAX_ATTEMPTS = 2

ProbeRunner = Callable[[Callable[[], Any]], Awaitable[Any] | Any]


async def _run(runner: ProbeRunner | None, fn: Callable[[], Any]) -> Any:
    """Call ``fn``, optionally through a runner that moves it off the event loop."""
    if runner is None:
        return fn()
    result = runner(fn)
    if inspect.isawaitable(result):
        return await result
    return result


async def run_multi_agent_execution(
    fleet: Fleet,
    journal: Journal,
    task_id: str,
    goal: str,
    claim_text: str,
    required_kinds: Iterable[Requirement],
    seed_evidence: Callable[[], None] | None = None,
    collect_runtime: Callable[[], Any] | None = None,
    action: Callable[[], str] | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    probe_runner: ProbeRunner | None = None,
) -> dict[str, Any]:
    orchestrator = fleet.orchestrator_context
    audit_failures: list[str] = []

    def note(event: EventType, status: str, severity=Severity.INFO, **payload):
        try:
            orchestrator.audit.record(event, status, severity, **payload)
        except JournalUnavailableError as exc:
            audit_failures.append(f"{event}: {exc}")

    note(
        EventType.EXECUTION_START,
        "STARTED",
        max_attempts=max_attempts,
        agents=[r.agent_id for r in fleet.registry.records()],
    )

    final_status = "ABSTAIN"
    failure_class = AuthorityFailure.RETRY_EXHAUSTED.value
    terminal_reason = "No attempt was made."
    decisions: list[dict[str, Any]] = []

    try:
        plan = fleet.planner.plan(task_id, goal, required_kinds)
        orchestrator.tasks.open_task(task_id, plan.required_kinds)

        if seed_evidence is not None:
            seed_evidence()

        if action is not None:
            fleet.executor.execute(task_id, action)
        fleet.executor.claim_success(task_id, claim_text)

        for attempt in range(1, max_attempts + 1):
            decision = fleet.verifier.verify(task_id, claim_text)
            decisions.append(
                {
                    "attempt": attempt,
                    "status": decision.status,
                    "failure": decision.failure,
                    "missing": list(decision.missing),
                    "reason": decision.reason,
                }
            )

            if decision.status == "VERIFIED":
                final_status = "VERIFIED"
                failure_class = AuthorityFailure.NONE.value
                terminal_reason = decision.reason
                break

            if attempt == max_attempts:
                failure_class = AuthorityFailure.RETRY_EXHAUSTED.value
                terminal_reason = f"RETRY_EXHAUSTED after {max_attempts} attempts."
                break

            if "runtime" not in decision.missing or collect_runtime is None:
                failure_class = AuthorityFailure.COLLECTOR_UNAVAILABLE.value
                terminal_reason = (
                    f"No collector available for evidence: {list(decision.missing)}."
                )
                break

            note(
                EventType.RECOVERY_START,
                "REQUESTED",
                attempt=attempt,
                missing=list(decision.missing),
            )
            await _run(probe_runner, collect_runtime)

    except CapabilityDenied as exc:
        failure_class = AuthorityFailure.CAPABILITY_DENIED.value
        terminal_reason = str(exc)
        note(
            EventType.EXECUTION_COMPLETE,
            "ABSTAIN",
            Severity.ERROR,
            failure=failure_class,
            reason=terminal_reason,
        )
        final_status = "ABSTAIN"
    except MessageRejected as exc:
        failure_class = exc.failure.value
        terminal_reason = str(exc)
        final_status = "ABSTAIN"

    if audit_failures:
        # Losing the audit trail never creates evidence, so it can only
        # downgrade the outcome.
        final_status = "ABSTAIN"
        failure_class = AuthorityFailure.AUDIT_UNAVAILABLE.value
        terminal_reason = (
            "Verification could not be durably recorded, so completion is not "
            f"claimed. {audit_failures[0]}"
        )

    note(
        EventType.EXECUTION_COMPLETE,
        final_status,
        Severity.INFO if final_status == "VERIFIED" else Severity.WARNING,
        failure=failure_class,
        reason=terminal_reason,
        attempts=len(decisions),
    )

    return {
        "execution_id": journal.execution_id,
        "trace_id": journal.trace_id,
        "task_id": task_id,
        "claim": claim_text,
        "final_status": final_status,
        "failure_class": failure_class,
        "terminal_reason": terminal_reason,
        "decisions": decisions,
        "audit_intact": not audit_failures,
        "agents": _describe_agents(fleet),
    }


def _describe_agents(fleet: Fleet) -> list[dict[str, Any]]:
    return [
        {
            "agent_id": record.agent_id,
            "role": str(record.role),
            "capabilities": sorted(record.capabilities),
            "runtime": str(record.runtime),
        }
        for record in fleet.registry.records()
    ]


async def run_agent_execution(
    fleet: Fleet,
    journal: Journal,
    turn_runner,
    task_id: str,
    goal: str,
    claim_text: str,
    required_kinds: Iterable[Requirement],
    seed_evidence: Callable[[], None] | None = None,
    collect_runtime: Callable[[], Any] | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    probe_runner: ProbeRunner | None = None,
) -> dict[str, Any]:
    """Run the execution with agents playing the roles.

    The runtime owns every transition: it fixes the requirements before anyone
    speaks, decides when to collect, and decides when to stop. An agent gets one
    bounded turn at a time and no say in what happens next.

    Verdicts come from the verification tool's result. Model prose is recorded
    for the demo and never read for meaning -- a verifier that writes
    "VERIFIED" over an ABSTAIN has narrated, not decided.
    """
    from .turn_runner import decision_from

    orchestrator = fleet.orchestrator_context
    audit_failures: list[str] = []
    turns: list[dict[str, Any]] = []

    def note(event: EventType, status: str, severity=Severity.INFO, **payload):
        try:
            orchestrator.audit.record(event, status, severity, **payload)
        except JournalUnavailableError as exc:
            audit_failures.append(f"{event}: {exc}")

    def record_turn(turn) -> None:
        turns.append(turn.summary())
        note(
            EventType.AGENT_TURN_STARTED,
            turn.role.upper(),
            agent_id=turn.agent_id,
            model=turn.model,
            attempt=turn.attempt,
        )
        for call in turn.tool_calls:
            note(
                EventType.AGENT_TOOL_CALLED,
                "INVOKED",
                agent_id=turn.agent_id,
                tool=call.name,
                attempt=turn.attempt,
            )
            note(
                EventType.AGENT_TOOL_RESULT,
                (call.result or {}).get("status", "NO_RESULT"),
                Severity.INFO if call.result else Severity.WARNING,
                agent_id=turn.agent_id,
                tool=call.name,
                attempt=turn.attempt,
            )
        note(
            EventType.AGENT_TURN_COMPLETED,
            "FAILED" if turn.failed else "COMPLETED",
            Severity.WARNING if turn.failed else Severity.INFO,
            agent_id=turn.agent_id,
            attempt=turn.attempt,
            error=turn.error,
        )

    runtime_facts = turn_runner.describe()
    note(
        EventType.EXECUTION_START,
        "STARTED",
        max_attempts=max_attempts,
        agents=[r.agent_id for r in fleet.registry.records()],
        **runtime_facts,
    )

    final_status = "ABSTAIN"
    failure_class = AuthorityFailure.RETRY_EXHAUSTED.value
    terminal_reason = "No attempt was made."
    decisions: list[dict[str, Any]] = []

    try:
        # Requirements are fixed here, before any agent speaks. A planner may
        # describe what would prove the goal; it cannot narrow what must.
        orchestrator.tasks.open_task(task_id, tuple(required_kinds))

        record_turn(await turn_runner.plan(task_id, goal))

        if seed_evidence is not None:
            seed_evidence()

        record_turn(await turn_runner.execute(task_id, goal))

        # The claim is the runtime's, phrased by the runtime. Whatever the
        # executor wrote is recorded as a self-report and judged as one.
        fleet.executor.claim_success(task_id, claim_text)

        for attempt in range(1, max_attempts + 1):
            turn = await turn_runner.verify(task_id, claim_text, attempt)
            record_turn(turn)

            extraction = decision_from(turn, task_id)
            if not extraction.usable:
                final_status = "ABSTAIN"
                failure_class = AuthorityFailure.MODEL_NONCOMPLIANCE.value
                terminal_reason = extraction.noncompliance
                note(
                    EventType.MODEL_NONCOMPLIANCE,
                    "ABSTAIN",
                    Severity.WARNING,
                    attempt=attempt,
                    reason=terminal_reason,
                )
                break

            decision = extraction.decision
            decisions.append(
                {
                    "attempt": attempt,
                    "status": decision.get("status"),
                    "failure": decision.get("failure"),
                    "missing": list(decision.get("missing") or []),
                    "reason": decision.get("reason"),
                    # Kept so a reviewer can read prose and verdict side by side.
                    "model_text": turn.final_text[:200],
                }
            )
            note(
                EventType.VERIFIER_DECISION,
                decision.get("status", "UNKNOWN"),
                Severity.INFO
                if decision.get("status") == "VERIFIED"
                else Severity.WARNING,
                attempt=attempt,
                failure=decision.get("failure"),
                missing=decision.get("missing"),
            )

            if decision.get("status") == "VERIFIED":
                final_status = "VERIFIED"
                failure_class = AuthorityFailure.NONE.value
                terminal_reason = decision.get("reason", "")
                break

            missing = list(decision.get("missing") or [])
            if attempt == max_attempts:
                failure_class = AuthorityFailure.RETRY_EXHAUSTED.value
                terminal_reason = f"RETRY_EXHAUSTED after {max_attempts} attempts."
                break

            if "runtime" not in missing or collect_runtime is None:
                failure_class = AuthorityFailure.COLLECTOR_UNAVAILABLE.value
                terminal_reason = f"No collector available for evidence: {missing}."
                break

            # Collection is the runtime's move. No agent holds a tool that
            # reaches the collector.
            note(
                EventType.RECOVERY_START, "REQUESTED", attempt=attempt, missing=missing
            )
            await _run(probe_runner, collect_runtime)

    except CapabilityDenied as exc:
        final_status = "ABSTAIN"
        failure_class = AuthorityFailure.CAPABILITY_DENIED.value
        terminal_reason = str(exc)
    except MessageRejected as exc:
        final_status = "ABSTAIN"
        failure_class = exc.failure.value
        terminal_reason = str(exc)

    if audit_failures:
        final_status = "ABSTAIN"
        failure_class = AuthorityFailure.AUDIT_UNAVAILABLE.value
        terminal_reason = (
            "Verification could not be durably recorded, so completion is not "
            f"claimed. {audit_failures[0]}"
        )

    note(
        EventType.EXECUTION_COMPLETE,
        final_status,
        Severity.INFO if final_status == "VERIFIED" else Severity.WARNING,
        failure=failure_class,
        reason=terminal_reason,
        attempts=len(decisions),
    )

    return {
        "execution_id": journal.execution_id,
        "trace_id": journal.trace_id,
        "task_id": task_id,
        "claim": claim_text,
        "final_status": final_status,
        "failure_class": failure_class,
        "terminal_reason": terminal_reason,
        "decisions": decisions,
        "agent_turns": turns,
        "audit_intact": not audit_failures,
        **runtime_facts,
        "agents": _describe_agents(fleet),
    }
