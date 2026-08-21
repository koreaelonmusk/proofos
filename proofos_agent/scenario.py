"""The P0 demo scenario: a worker claims a production bug is fixed.

Test evidence is independently collected. Runtime evidence is not present at the
start -- the worker only *asserts* the service is healthy -- so ProofOS must
refuse the claim until a real probe observes the service.
"""

from __future__ import annotations

import os
import time

from proofos.ledger import EvidenceLedger
from proofos.probe import DEFAULT_TIMEOUT_SECONDS, ProbeResult, probe_health
from proofos.verifier import Evidence, EvidenceSource, Requirement

TASK_ID = "BUG-4417"
WORKER_CLAIM = "Production bug BUG-4417 is fixed and the service is healthy."

# A recorded CI run speaks for as long as the commit it describes, so it carries
# no freshness horizon. A health probe speaks only for the moment it ran.
RUNTIME_MAX_AGE_SECONDS = 300.0
REQUIRED_KINDS = (
    Requirement("tests"),
    Requirement("runtime", max_age_seconds=RUNTIME_MAX_AGE_SECONDS),
)

DEFAULT_HEALTH_URL = "http://127.0.0.1:8081/healthz"
CI_COLLECTOR = "github-actions"


def health_url() -> str:
    return os.environ.get("PROOFOS_HEALTH_URL", DEFAULT_HEALTH_URL)


def health_timeout() -> float:
    raw = os.environ.get("PROOFOS_HEALTH_TIMEOUT")
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        return float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def seed_incomplete_evidence(ledger: EvidenceLedger, now: float | None = None) -> None:
    """Open the task with test evidence only; runtime is unobserved."""
    stamp = time.time() if now is None else now
    ledger.open_task(TASK_ID, REQUIRED_KINDS)
    ledger.record(
        TASK_ID,
        Evidence(
            kind="tests",
            value="ci-run 32461296659: 44 passed, 0 failed, 0 skipped",
            source=EvidenceSource.OBSERVED,
            collected_at=stamp,
            collector=CI_COLLECTOR,
        ),
    )
    # The worker also asserts the service is healthy. That is a self-report and
    # must not satisfy the runtime requirement.
    ledger.record(
        TASK_ID,
        Evidence(
            kind="runtime",
            value="worker states: I verified the service myself, it is healthy",
            source=EvidenceSource.EXECUTOR,
            collected_at=stamp,
            collector="executor-agent",
        ),
    )


def collect_runtime_evidence(
    ledger: EvidenceLedger,
    url: str | None = None,
    timeout: float | None = None,
) -> ProbeResult:
    """Probe the service and record whatever the network actually returned.

    Evidence is recorded only when a real HTTP response arrived. If nothing came
    back -- timeout, refused redirect, or connection failure -- nothing is
    observed, so nothing is recorded and the runtime requirement stays
    unsatisfied.

    The recorded value is the probe's own account of the response. It is never a
    canned string, and it is marked valid only when the service genuinely
    reported itself healthy.
    """
    result = probe_health(
        url if url is not None else health_url(),
        timeout if timeout is not None else health_timeout(),
    )

    if result.observed_response:
        ledger.record(
            TASK_ID,
            Evidence(
                kind="runtime",
                value=f"probe {result.outcome.value}: {result.detail}",
                source=EvidenceSource.OBSERVED,
                valid=result.healthy,
                collected_at=time.time(),
                collector=result.collector,
            ),
        )

    return result


# Recovery collectors, keyed by the evidence kind they can independently obtain.
COLLECTORS = {"runtime": collect_runtime_evidence}
