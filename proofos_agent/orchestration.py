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
        "agents": [
            {
                "agent_id": record.agent_id,
                "role": str(record.role),
                "capabilities": sorted(record.capabilities),
                "runtime": str(record.runtime),
            }
            for record in fleet.registry.records()
        ],
    }
