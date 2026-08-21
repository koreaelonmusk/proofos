"""The P0 scenario with observation authority in a separate process.

Same story, one structural change: the runtime process can no longer produce
runtime evidence at all. It can ask the collector process to look, and it can
check the signature on what comes back. It cannot author an observation,
because it does not have the key.
"""

from __future__ import annotations

from typing import Any, Callable

from proofos.collector_registry import CollectorRegistry, registry_for
from proofos.ingestion import AttestationIngestor, NonceLedger
from proofos.journal import Journal, JournalSink
from proofos.ledger import EvidenceLedger
from proofos.profiles import RUNTIME_HEALTH_PROFILE
from proofos.registry import COLLECTOR_ID, AgentRegistry, default_registry

from . import scenario
from .collector_client import CollectorClient
from .fleet import AttestedCollector, AttestedCollectorContext, Fleet, build_fleet
from .verification_tool import build_verification_tool
from .fleet_scenario import CI_SUMMARY, GOAL
from .orchestration import (
    MAX_ATTEMPTS,
    ProbeRunner,
    run_agent_execution,
    run_multi_agent_execution,
)


def build_attested_fleet(
    sink: JournalSink,
    collector_public_key_b64: str,
    client: CollectorClient,
    registry: AgentRegistry | None = None,
    task_id: str = scenario.TASK_ID,
    collector_id: str = COLLECTOR_ID,
    profile_id: str = RUNTIME_HEALTH_PROFILE,
) -> tuple[Fleet, AttestedCollector, Journal, EvidenceLedger, CollectorRegistry]:
    ledger = EvidenceLedger()
    journal = Journal(sink, task_id=task_id)

    fleet = build_fleet(
        ledger,
        journal,
        registry or default_registry(),
        task_id,
        # The in-process collector keeps no runtime authority here: runtime
        # observations must now come from the other process.
        collector_kinds=(),
        ingestor_collectors=((collector_id, ("runtime",)),),
    )

    collectors = registry_for(
        collector_id,
        collector_public_key_b64,
        allowed_kinds=("runtime",),
        allowed_profiles=(profile_id,),
    )
    ingestor = AttestationIngestor(
        capabilities=fleet.ingestor_capabilities,
        collectors=collectors,
        nonces=NonceLedger(),
    )

    attested = AttestedCollector(
        AttestedCollectorContext(
            agent_id=collector_id,
            client=client,
            ingestor=ingestor,
            profile_id=profile_id,
            audit=fleet.collector._ctx.audit,
            sender=fleet.collector._ctx.sender,
        )
    )
    return fleet, attested, journal, ledger, collectors


async def run_attested_scenario(
    sink: JournalSink,
    collector_public_key_b64: str,
    client: CollectorClient,
    registry: AgentRegistry | None = None,
    task_id: str = scenario.TASK_ID,
    claim_text: str = scenario.WORKER_CLAIM,
    max_attempts: int = MAX_ATTEMPTS,
    probe_runner: ProbeRunner | None = None,
    action: Callable[[], str] | None = None,
    collector_id: str = COLLECTOR_ID,
    profile_id: str = RUNTIME_HEALTH_PROFILE,
) -> tuple[dict[str, Any], Journal, EvidenceLedger]:
    fleet, attested, journal, ledger, _ = build_attested_fleet(
        sink,
        collector_public_key_b64,
        client,
        registry,
        task_id,
        collector_id=collector_id,
        profile_id=profile_id,
    )

    def seed_ci_evidence() -> None:
        fleet.ci_collector.record_ci_result(task_id, CI_SUMMARY)

    def collect_runtime() -> Any:
        return attested.collect_runtime(
            execution_id=journal.execution_id,
            task_id=task_id,
            kind="runtime",
            max_age_seconds=scenario.RUNTIME_MAX_AGE_SECONDS,
        )

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


def build_turn_runner(
    agent_runtime: str,
    fleet: Fleet,
    ledger: EvidenceLedger,
    task_id: str,
    registry: AgentRegistry | None = None,
):
    """Build the turn runner for the requested runtime.

    There is deliberately no fallback. If live mode is asked for and no
    credential path exists, this raises: quietly running the deterministic
    runtime instead would produce a demo that looks live and is not, which is
    the same class of lie ProofOS exists to refuse.
    """
    from .turn_runner import DeterministicTurnRunner

    verify_tool = build_verification_tool(ledger)

    if agent_runtime == "gemini":
        from .gemini_runner import GeminiAdkTurnRunner, preflight

        credential_mode = preflight()
        return GeminiAdkTurnRunner(
            fleet=fleet,
            ledger=ledger,
            task_id=task_id,
            registry=registry,
            credential_mode=credential_mode,
        )

    return DeterministicTurnRunner(fleet, verify_tool)


async def run_attested_agent_scenario(
    sink: JournalSink,
    collector_public_key_b64: str,
    client: CollectorClient,
    agent_runtime: str = "deterministic",
    registry: AgentRegistry | None = None,
    task_id: str = scenario.TASK_ID,
    claim_text: str = scenario.WORKER_CLAIM,
    max_attempts: int = MAX_ATTEMPTS,
    probe_runner: ProbeRunner | None = None,
    collector_id: str = COLLECTOR_ID,
    profile_id: str = RUNTIME_HEALTH_PROFILE,
) -> tuple[dict[str, Any], Journal, EvidenceLedger]:
    """The full path: agents play the roles, evidence stays attested."""
    registry = registry or default_registry()
    fleet, attested, journal, ledger, _ = build_attested_fleet(
        sink,
        collector_public_key_b64,
        client,
        registry,
        task_id,
        collector_id=collector_id,
        profile_id=profile_id,
    )

    turn_runner = build_turn_runner(agent_runtime, fleet, ledger, task_id, registry)

    def seed_ci_evidence() -> None:
        fleet.ci_collector.record_ci_result(task_id, CI_SUMMARY)

    def collect_runtime() -> Any:
        return attested.collect_runtime(
            execution_id=journal.execution_id,
            task_id=task_id,
            kind="runtime",
            max_age_seconds=scenario.RUNTIME_MAX_AGE_SECONDS,
        )

    try:
        outcome = await run_agent_execution(
            fleet=fleet,
            journal=journal,
            turn_runner=turn_runner,
            task_id=task_id,
            goal=GOAL,
            claim_text=claim_text,
            required_kinds=scenario.REQUIRED_KINDS,
            seed_evidence=seed_ci_evidence,
            collect_runtime=collect_runtime,
            max_attempts=max_attempts,
            probe_runner=probe_runner,
        )
    finally:
        await turn_runner.aclose()

    return outcome, journal, ledger
