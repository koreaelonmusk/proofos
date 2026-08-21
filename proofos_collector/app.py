"""The collector service.

Runs as its own process and holds the only Ed25519 private key in the system.
That is the entire point: an orchestrator with a shared secret could fabricate
collector evidence, so it is given a public key and nothing else.

The request body is deliberately tiny. A caller names an execution, a task, an
evidence kind, a profile, and the nonce it was challenged with. It does not name
a URL, a scheme, a host, a timestamp, a collector id, an outcome, or a source --
those are the collector's to determine, and accepting any of them from the
caller would hand back the authority the process boundary just established.

The public key is never served from this API. Fetching a verification key over
the same channel you are trying to verify is trust-on-first-use, and would let
whoever controls this endpoint substitute their own key. It is written to a file
at startup for the local harness, and is configuration in production.
"""

from __future__ import annotations

import base64
import os
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from proofos.attestation import AttestationSigner, Outcome
from proofos.probe import probe_health
from proofos.profiles import (
    ProfileRegistry,
    ProfileScopeViolation,
    UnknownProfile,
    default_profiles,
    describe,
)

SERVICE_NAME = "proofos-collector"

COLLECTOR_ID_ENV = "PROOFOS_COLLECTOR_ID"
TARGET_ENV = "PROOFOS_COLLECTOR_TARGET"
PRIVATE_KEY_ENV = "PROOFOS_COLLECTOR_PRIVATE_KEY"
PUBLIC_KEY_FILE_ENV = "PROOFOS_COLLECTOR_PUBKEY_FILE"
TIMEOUT_ENV = "PROOFOS_COLLECTOR_TIMEOUT"

DEFAULT_COLLECTOR_ID = "collector-http-v1"
DEFAULT_TARGET = "http://127.0.0.1:8081/healthz"


class CollectRequest(BaseModel):
    """Everything a caller is allowed to say.

    ``extra="forbid"`` is load-bearing: a request carrying ``source``,
    ``collector_id``, ``observed_at``, ``url``, ``valid``, or ``signature`` is
    rejected outright rather than having those fields quietly ignored. Silently
    ignored input is where smuggling hides.
    """

    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(min_length=1, max_length=200)
    task_id: str = Field(min_length=1, max_length=200)
    evidence_kind: str = Field(min_length=1, max_length=100)
    profile_id: str = Field(min_length=1, max_length=200)
    request_nonce: str = Field(min_length=1, max_length=200)


def _load_signer() -> AttestationSigner:
    """Load or generate the signing key. The private key never leaves here."""
    collector_id = os.environ.get(COLLECTOR_ID_ENV, DEFAULT_COLLECTOR_ID)
    encoded = os.environ.get(PRIVATE_KEY_ENV)
    if encoded:
        key = Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(encoded, validate=True)
        )
        return AttestationSigner(key, collector_id)
    return AttestationSigner.generate(collector_id)


def _publish_public_key(signer: AttestationSigner) -> None:
    """Write the public key where the harness can read it.

    Only the public half is written, and only if a path was configured.
    """
    path = os.environ.get(PUBLIC_KEY_FILE_ENV)
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(signer.public_key_b64())


def _load_profiles(collector_id: str) -> ProfileRegistry:
    timeout = float(os.environ.get(TIMEOUT_ENV, "5"))
    target = os.environ.get(TARGET_ENV, DEFAULT_TARGET)
    return default_profiles(target, collector_id, timeout)


SIGNER = _load_signer()
PROFILES = _load_profiles(SIGNER.collector_id)
_publish_public_key(SIGNER)

app = FastAPI(
    title="ProofOS Collector",
    description="Performs approved observations and signs what it saw.",
    version="0.1.0",
)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "service": SERVICE_NAME}


@app.get("/v1/profiles")
def list_profiles() -> dict[str, Any]:
    """What may be collected. Targets are not disclosed."""
    return {
        "collector_id": SIGNER.collector_id,
        "profiles": describe({p.profile_id: p for p in PROFILES.profiles()}),
    }


@app.post("/v1/collect")
async def collect(request: CollectRequest) -> dict[str, Any]:
    """Perform an approved observation and return a signed attestation."""
    try:
        profile = PROFILES.resolve(
            request.profile_id, request.evidence_kind, SIGNER.collector_id
        )
    except UnknownProfile as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ProfileScopeViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # The probe blocks on a socket; keep it off the event loop so this service
    # can still answer while a collection is in flight.
    result = await run_in_threadpool(
        probe_health,
        profile.target,
        profile.timeout,
        profile.max_response_bytes,
        profile.expected_status_field,
        profile.expected_status_value,
    )

    attestation = SIGNER.sign(
        execution_id=request.execution_id,
        task_id=request.task_id,
        kind=profile.allowed_kind,
        profile_id=profile.profile_id,
        request_nonce=request.request_nonce,
        observed_at=time.time(),
        outcome=Outcome(result.outcome.value),
        status_code=result.status_code,
        response_digest_value=result.body_digest,
        # The detail names the profile, not the target. A caller that cannot be
        # told the URL should not learn it from the reply.
        detail=f"{result.outcome.value} via {profile.profile_id}",
    )

    return {"attestation": attestation.to_dict()}
