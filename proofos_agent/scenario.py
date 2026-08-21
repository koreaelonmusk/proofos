"""The P0 demo scenario: a worker claims a production bug is fixed.

Test evidence is independently collected. Runtime evidence is deliberately
absent, so ProofOS must refuse the claim until recovery collects it.
"""

from __future__ import annotations

from proofos.ledger import EvidenceLedger
from proofos.verifier import Evidence, EvidenceSource

TASK_ID = "BUG-4417"
REQUIRED_KINDS = ("tests", "runtime")
WORKER_CLAIM = "Production bug BUG-4417 is fixed and the service is healthy."


def seed_incomplete_evidence(ledger: EvidenceLedger) -> None:
    """Open the task with test evidence only; runtime evidence is missing."""
    ledger.open_task(TASK_ID, REQUIRED_KINDS)
    ledger.record(
        TASK_ID,
        Evidence(
            kind="tests",
            value="ci-run 32458985990: 553 passed, 0 failed, 0 skipped",
            source=EvidenceSource.OBSERVED,
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
        ),
    )


def collect_runtime_evidence(ledger: EvidenceLedger) -> None:
    """Recovery step: independently observe the runtime and record the result."""
    ledger.record(
        TASK_ID,
        Evidence(
            kind="runtime",
            value="probe GET /healthz -> 200; error-rate 0.00% over 300s window",
            source=EvidenceSource.OBSERVED,
        ),
    )


# Recovery collectors, keyed by the evidence kind they can independently obtain.
COLLECTORS = {"runtime": collect_runtime_evidence}
