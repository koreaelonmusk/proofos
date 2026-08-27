"""ProofOS HTTP service.

Exposes the verification runtime over HTTP so it can run on Cloud Run.

Four endpoints, each with a reason to exist:

* ``GET /healthz``  -- the service's own health, in the exact shape the ProofOS
  probe requires, so a deployed ProofOS can be the target of a real probe.
* ``GET /config`` -- how this instance obtains runtime evidence, so the
  separation is inspectable from outside the process.
* ``POST /executions`` -- run a bounded verify/recover execution.
* ``GET /executions/{execution_id}`` -- replay the audit trail for a decision.

In the default (remote) mode this process cannot produce runtime evidence at
all. It can ask a separate collector to look, and it can check the signature on
what comes back. It holds no signing key, so it cannot author an observation,
and there is no path by which a failed collection becomes locally-produced
evidence instead.

The trust boundary is why the request body is so small: a caller may state a
claim, and nothing else. It cannot declare what counts as proof, assert that
proof exists, name a collection target, or name its own verdict.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from proofos.journal import JournalUnavailableError, summarize
from proofos.journal_backend import build_journal_backend
from proofos.registry import default_registry
from proofos_agent import scenario
from proofos_agent.attested_scenario import run_attested_agent_scenario
from proofos_agent.collector_client import build_collector_client
from proofos_agent.fleet_scenario import run_scenario
from proofos_agent.orchestration import MAX_ATTEMPTS

from .config import AgentRuntime, CollectorMode, RuntimeConfig, build_runtime_config

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

# Misconfiguration stops startup rather than degrading quietly at request time.
CONFIG: RuntimeConfig = build_runtime_config()


class ExecutionRequest(BaseModel):
    """What a caller is allowed to say.

    ``extra="forbid"`` is load-bearing: a request carrying ``source``,
    ``collector_id``, ``request_nonce``, ``status_code``, ``url``, or
    ``evidence`` is refused rather than having those fields quietly ignored.
    Silently ignored input is where smuggling hides.
    """

    model_config = ConfigDict(extra="forbid")

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


@app.get("/health")
def health() -> dict[str, Any]:
    """Health in the probe's contract shape, on a path Cloud Run leaves alone.

    ``/healthz`` is intercepted by Google's front end and never reaches the
    container, so an external observer -- including the collector -- cannot use
    it. This path is the one a cross-service probe actually reaches.
    """
    return {"status": "ok", "service": SERVICE_NAME}


@app.get("/config")
def config() -> dict[str, Any]:
    """How this instance obtains runtime evidence. Carries no key material."""
    return {
        "service": SERVICE_NAME,
        "journal_backend": JOURNAL.backend,
        **CONFIG.describe(),
    }


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "invariant": "no claim of completion without independent evidence",
        "endpoints": [
            "/healthz",
            "/config",
            "/executions",
            "/executions/{execution_id}",
        ],
        "collector_mode": str(CONFIG.mode),
    }


def _evidence_view(outcome: dict[str, Any], ledger) -> tuple[list[dict], int | None]:
    """Render each evidence item as the verifier actually treated it.

    The three flags come from the verifier that produced the verdict, keyed by
    evidence id. This layer decides nothing. An earlier version reported
    ``satisfies_requirement = item.valid``, which is integrity, not acceptance
    -- so a self-report the verifier had just refused was displayed as
    satisfying, in the one direction that flatters the system.

    Acceptance belongs to an attempt, not to the evidence. The flags here
    describe the last attempt; ``attempts`` carries the rest.
    """
    decisions = outcome.get("decisions") or []
    final = decisions[-1] if decisions else None
    attempt = final.get("attempt") if final else None
    assessed = {a["evidence_id"]: a for a in (final or {}).get("evidence", [])}

    view = []
    for item in ledger.evidence(scenario.TASK_ID):
        assessment = assessed.get(item.content_hash)
        if assessment is None:
            # Recorded after the last verification, so no verifier has ruled on
            # it. Reported as not accepted, never as accepted by default.
            view.append(
                {
                    "kind": item.kind,
                    "source": str(item.source),
                    "collector": item.collector,
                    "integrity_valid": item.intact and item.valid,
                    "accepted_by_verifier": False,
                    "satisfies_requirement": False,
                    "rejection_reason": "No verification attempt has assessed this item.",
                }
            )
            continue
        view.append(
            {
                "kind": item.kind,
                "source": str(item.source),
                "collector": item.collector,
                "integrity_valid": assessment["integrity_valid"],
                "accepted_by_verifier": assessment["accepted_by_verifier"],
                "satisfies_requirement": assessment["satisfies_requirement"],
                "rejection_reason": assessment["rejection_reason"],
            }
        )
    return view, attempt


def _response(outcome: dict[str, Any], ledger) -> dict[str, Any]:
    evidence, attempt = _evidence_view(outcome, ledger)
    return {
        "journal_backend": JOURNAL.backend,
        **CONFIG.describe(),
        "evidence": evidence,
        "evidence_as_of_attempt": attempt,
        "attempts": [
            {
                "attempt": d.get("attempt"),
                "decision": d.get("status"),
                "failure": d.get("failure"),
                "missing": d.get("missing"),
                "evidence": d.get("evidence", []),
            }
            for d in (outcome.get("decisions") or [])
        ],
        **outcome,
    }


async def _offload(fn):
    # A collector call blocks on a socket. Run it in a worker thread so the
    # event loop stays free -- otherwise this service cannot answer the very
    # health request the collector is probing.
    return await run_in_threadpool(fn)


async def _run_remote_execution(request: ExecutionRequest) -> dict[str, Any]:
    """Obtain runtime evidence from the separate collector, or abstain."""
    client = build_collector_client(
        CONFIG.collector_url, CONFIG.client_timeout, CONFIG.auth
    )

    outcome, _journal, ledger = await run_attested_agent_scenario(
        sink=JOURNAL.append_sink,
        collector_public_key_b64=CONFIG.public_key_b64,
        client=client,
        registry=REGISTRY,
        claim_text=request.claim,
        max_attempts=request.max_attempts,
        probe_runner=_offload,
        agent_runtime=str(CONFIG.agent_runtime),
        collector_id=CONFIG.collector_id,
        profile_id=CONFIG.profile_id,
    )
    return _response(outcome, ledger)


async def _run_inprocess_execution(request: ExecutionRequest) -> dict[str, Any]:
    """Deterministic in-process collection. Explicitly not a deployment mode."""
    outcome, _journal, ledger = await run_scenario(
        sink=JOURNAL.append_sink,
        health_url=scenario.health_url(),
        registry=REGISTRY,
        claim_text=request.claim,
        max_attempts=request.max_attempts,
        probe_runner=_offload,
    )
    return _response(outcome, ledger)


@app.post("/executions")
async def create_execution(request: ExecutionRequest) -> dict[str, Any]:
    """Run one bounded verify/recover execution across the separated fleet."""
    if CONFIG.mode is CollectorMode.REMOTE:
        return await _run_remote_execution(request)
    return await _run_inprocess_execution(request)


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
