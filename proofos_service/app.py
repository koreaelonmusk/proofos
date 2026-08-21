"""ProofOS HTTP service.

Exposes the verification runtime over HTTP so it can run on Cloud Run.

Three endpoints, each with a reason to exist:

* ``GET /healthz``  -- the service's own health, in the exact shape the ProofOS
  probe requires. A deployed ProofOS can therefore be the target of a real
  probe, which is what makes cloud evidence collection genuine rather than
  simulated.
* ``POST /executions`` -- run a bounded verify/recover execution for a task and
  return the decision.
* ``GET /executions/{execution_id}`` -- replay the audit trail for a decision.

The trust boundary is unchanged and is the reason the request body is so small:
a caller may state a claim, and nothing else. It cannot declare what counts as
proof, assert that proof exists, or name its own verdict.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from proofos.journal import JournalUnavailableError, summarize
from proofos.journal_backend import build_journal_backend
from proofos.registry import default_registry
from proofos_agent import scenario
from proofos_agent.fleet_scenario import run_scenario
from proofos_agent.orchestration import MAX_ATTEMPTS

SERVICE_NAME = "proofos"

app = FastAPI(
    title="ProofOS",
    description="Evidence-first verification runtime.",
    version="0.1.0",
)

# One journal backend per process. In-memory by default; set
# PROOFOS_JOURNAL_BACKEND=firestore to persist. Every execution also streams its
# events to stdout, where Cloud Logging picks them up.
JOURNAL = build_journal_backend()

# Validated and sealed at import. A misconfigured authority model stops the
# process here rather than serving requests with a broken separation.
REGISTRY = default_registry()


class ExecutionRequest(BaseModel):
    """What a caller is allowed to say.

    Only a claim. Evidence requirements and evidence itself belong to the
    runtime; accepting either from the caller would hand the trust boundary to
    whoever sends the request.
    """

    claim: str = Field(
        default=scenario.WORKER_CLAIM,
        max_length=2000,
        description="The completion claim to be checked. An assertion, not evidence.",
    )
    max_attempts: int = Field(default=MAX_ATTEMPTS, ge=1, le=5)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Health in the shape the ProofOS probe requires."""
    return {"status": "ok", "service": SERVICE_NAME}


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "invariant": "no claim of completion without independent evidence",
        "endpoints": ["/healthz", "/executions", "/executions/{execution_id}"],
        "journal_backend": JOURNAL.backend,
    }


def _health_target() -> str:
    """The endpoint the runtime probe should observe.

    Defaults to this service's own health endpoint so a Cloud Run deployment
    collects evidence over a real network hop rather than from a fixture.
    """
    configured = os.environ.get("PROOFOS_HEALTH_URL")
    if configured:
        return configured
    port = os.environ.get("PORT", "8080")
    return f"http://127.0.0.1:{port}/healthz"


@app.post("/executions")
async def create_execution(request: ExecutionRequest) -> dict[str, Any]:
    """Run one bounded verify/recover execution across the separated fleet."""
    probes: list[dict[str, Any]] = []
    health_url = _health_target()

    def record_probe(result) -> None:
        probes.append(
            {
                "url": result.url,
                "outcome": result.outcome.value,
                "status_code": result.status_code,
                "detail": result.detail,
                "satisfies_requirement": result.healthy,
            }
        )

    async def probe_runner(fn):
        # The probe blocks on a socket. Run it in a worker thread so the event
        # loop stays free -- otherwise the service cannot answer the very
        # health request it is trying to observe.
        result = await run_in_threadpool(fn)
        record_probe(result)
        return result

    outcome, journal, ledger = await run_scenario(
        sink=JOURNAL.append_sink,
        health_url=health_url,
        registry=REGISTRY,
        claim_text=request.claim,
        max_attempts=request.max_attempts,
        probe_runner=probe_runner,
    )

    return {
        "health_endpoint": health_url,
        "journal_backend": JOURNAL.backend,
        "probes": probes,
        "evidence": [
            {
                "kind": item.kind,
                "source": str(item.source),
                "collector": item.collector,
                "satisfies_requirement": item.valid,
            }
            for item in ledger.evidence(scenario.TASK_ID)
        ],
        **outcome,
    }


@app.get("/executions/{execution_id}")
def read_execution(execution_id: str) -> dict[str, Any]:
    """Replay the audit trail for one execution."""
    try:
        events = JOURNAL.durable_sink.list_execution(execution_id)
    except JournalUnavailableError as exc:
        # An unreadable journal is reported, never silently thinned into a
        # shorter history that would understate what happened.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    if not events:
        raise HTTPException(status_code=404, detail="unknown execution_id")

    chain_ok, problems = JOURNAL.durable_sink.verify_chain(execution_id)
    return {
        "summary": summarize(events),
        "chain_ok": chain_ok,
        "chain_problems": list(problems),
        "events": [event.to_dict() for event in events],
    }
