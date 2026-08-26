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

import os
import time
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from proofos.attestation import AttestationSigner, Outcome
from proofos.keys import FileSigningKeyProvider, write_public_key
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
# A path, never the key itself. Key material in an environment variable ends up
# in process listings, crash dumps, and container inspect output.
PRIVATE_KEY_FILE_ENV = "PROOFOS_COLLECTOR_PRIVATE_KEY_FILE"
# Bootstrapping a key must be asked for. A mounted secret that fails to
# appear would otherwise be answered by minting a fresh identity, which
# silently invalidates every attestation issued under the real one.
CREATE_KEY_ENV = "PROOFOS_COLLECTOR_CREATE_KEY"
PUBLIC_KEY_FILE_ENV = "PROOFOS_COLLECTOR_PUBKEY_FILE"
TIMEOUT_ENV = "PROOFOS_COLLECTOR_TIMEOUT"
# Whether the observation target refuses anonymous requests. When set, the
# collector presents its own Cloud Run service identity.
TARGET_REQUIRES_AUTH_ENV = "PROOFOS_COLLECTOR_TARGET_REQUIRES_AUTH"

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
    """Load the signing key. It is read here and never leaves this process.

    With a key file configured the identity survives a restart, which a service
    artifact needs: an ephemeral key would silently invalidate every
    attestation issued before the last deploy. Without one the key is
    ephemeral, which is fine for a throwaway test and wrong for anything else.
    """
    collector_id = os.environ.get(COLLECTOR_ID_ENV, DEFAULT_COLLECTOR_ID)
    key_file = os.environ.get(PRIVATE_KEY_FILE_ENV)
    if key_file:
        # Default: a configured path must already hold a key. On Cloud Run the
        # key arrives as a mounted secret, and a missing mount is a deployment
        # fault to surface, not one to paper over with a new identity.
        create = os.environ.get(CREATE_KEY_ENV, "").strip().lower() in {"1", "true", "yes"}
        provider = FileSigningKeyProvider(key_file, create_if_missing=create)
        return AttestationSigner(provider.load_private_key(), collector_id)
    return AttestationSigner.generate(collector_id)


def _publish_public_key(signer: AttestationSigner) -> None:
    """Write the public half so a separately configured API can be given it.

    A deployment convenience for handing configuration across, not a trust
    bootstrap. There is deliberately no endpoint that serves this.
    """
    path = os.environ.get(PUBLIC_KEY_FILE_ENV)
    if not path:
        return
    write_public_key(path, signer.public_key())


def _load_profiles(collector_id: str) -> ProfileRegistry:
    timeout = float(os.environ.get(TIMEOUT_ENV, "5"))
    target = os.environ.get(TARGET_ENV, DEFAULT_TARGET)
    requires_auth = os.environ.get(TARGET_REQUIRES_AUTH_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    return default_profiles(target, collector_id, timeout, requires_auth)


def _identity_token_for(target: str) -> str:
    """A Google-signed ID token for the target, from this service's identity.

    The collector authenticates as itself. It never receives, stores, or reuses
    the caller's credential -- an observer borrowing the credential of the party
    it observes would defeat the separation this service exists to provide.

    A failure here raises rather than falling back to an anonymous request: a
    silent downgrade would turn a permission problem into an UNHEALTHY reading
    and point the investigation at the wrong service.
    """
    import google.auth.transport.requests
    import google.oauth2.id_token

    parts = urlsplit(target)
    audience = f"{parts.scheme}://{parts.netloc}"
    return google.oauth2.id_token.fetch_id_token(
        google.auth.transport.requests.Request(), audience
    )


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

    token = None
    if profile.requires_auth:
        try:
            token = await run_in_threadpool(_identity_token_for, profile.target)
        except Exception as exc:  # noqa: BLE001 - surfaced, never downgraded
            raise HTTPException(
                status_code=503,
                detail=(
                    "collector could not obtain its own identity token: "
                    f"{type(exc).__name__}"
                ),
            ) from exc

    # The probe blocks on a socket; keep it off the event loop so this service
    # can still answer while a collection is in flight.
    result = await run_in_threadpool(
        probe_health,
        profile.target,
        profile.timeout,
        profile.max_response_bytes,
        profile.expected_status_field,
        profile.expected_status_value,
        token,
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
