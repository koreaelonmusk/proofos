"""The P0 scenario, run by the separated fleet.

Same story as before -- a worker claims a production bug is fixed, only its own
word backs the runtime claim, ProofOS refuses, a real probe runs, ProofOS
accepts -- but now no single component could have shortcut it.

The executor writes its self-report through a capability that stamps EXECUTOR
and nothing else. The collector writes the observation. The verifier reads and
judges. None of them holds the others' authority.
"""

from __future__ import annotations

from typing import Any, Callable

from proofos.journal import Journal, JournalSink
from proofos.ledger import EvidenceLedger
from proofos.registry import AgentRegistry, default_registry

from . import scenario
from .fleet import Fleet, build_fleet
from .orchestration import MAX_ATTEMPTS, ProbeRunner, run_multi_agent_execution

GOAL = "Fix production bug BUG-4417 and confirm the service is healthy."
CI_SUMMARY = "ci-run 32469217999: 159 passed, 0 failed, 0 skipped"


def build_scenario_fleet(
    sink: JournalSink,
    registry: AgentRegistry | None = None,
    task_id: str = scenario.TASK_ID,
) -> tuple[Fleet, Journal, EvidenceLedger]:
    ledger = EvidenceLedger()
    journal = Journal(sink, task_id=task_id)
    fleet = build_fleet(ledger, journal, registry or default_registry(), task_id)
    return fleet, journal, ledger


async def run_scenario(
    sink: JournalSink,
    health_url: str,
    timeout: float | None = None,
    registry: AgentRegistry | None = None,
    task_id: str = scenario.TASK_ID,
    claim_text: str = scenario.WORKER_CLAIM,
    max_attempts: int = MAX_ATTEMPTS,
    probe_runner: ProbeRunner | None = None,
    action: Callable[[], str] | None = None,
) -> tuple[dict[str, Any], Journal, EvidenceLedger]:
    """Run the full separated-fleet scenario and return its outcome."""
    fleet, journal, ledger = build_scenario_fleet(sink, registry, task_id)
    probe_timeout = scenario.health_timeout() if timeout is None else timeout

    def seed_ci_evidence() -> None:
        # Test evidence is an observation too, written by the collector scoped
        # to that kind. The HTTP collector cannot write it, and vice versa.
        fleet.ci_collector.record_ci_result(task_id, CI_SUMMARY)

    def collect_runtime() -> Any:
        return fleet.collector.collect_runtime(task_id, health_url, probe_timeout)

    outcome = await run_multi_agent_execution(
        fleet=fleet,
        journal=journal,
        task_id=task_id,
        goal=GOAL,
        claim_text=claim_text,
        required_kinds=scenario.REQUIRED_KINDS,
        seed_evidence=seed_ci_evidence,
        collect_runtime=collect_runtime,
        action=action or (lambda: "patch applied"),
        max_attempts=max_attempts,
        probe_runner=probe_runner,
    )
    return outcome, journal, ledger
