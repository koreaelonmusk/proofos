"""Authenticated ProofOS collector E2E harness, gated by sealed launch evidence.

This harness is intentionally *not* wired to impersonate the API service account
from GitHub Actions. Run it only in a controlled runtime that already carries the
ProofOS API service identity. The collector independently validates that Google
identity.

The launch verdict is checked before public-key loading, token acquisition, or
network I/O. HOLD means exactly that: the authenticated path is not touched.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Callable

from proofos.capabilities import ObservationCapability
from proofos.collector_registry import registry_for
from proofos.ingestion import AttestationIngestor, NonceLedger, RejectionReason
from proofos.keys import verification_provider_from_env
from proofos.ledger import EvidenceLedger
from proofos.verifier import Requirement
from proofos_agent.collector_client import GoogleIdTokenCollectorClient
from verify_live_launch_verdict import VerdictVerificationError, verify_verdict

SCHEMA_VERSION = 1
KIND = "proofos-authenticated-collector-e2e"
READY = "READY_FOR_AUTHENTICATED_E2E"


class AuthenticatedE2EError(RuntimeError):
    pass


def _canonical_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthenticatedE2EError(
            f"could not read required evidence artifact: {type(exc).__name__}"
        ) from exc


def authorize_from_bundle(
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    try:
        verified = verify_verdict(
            health,
            trust,
            manifest,
            verdict,
            expected_git_sha=expected_git_sha,
        )
    except VerdictVerificationError as exc:
        raise AuthenticatedE2EError(f"launch verdict invalid: {exc}") from exc

    if verified["status"] != READY:
        raise AuthenticatedE2EError(
            "authenticated E2E is not authorized by the sealed launch verdict"
        )
    return verified


def _build_ingestor(
    public_key_b64: str,
    *,
    collector_id: str,
    profile_id: str,
    task_id: str,
) -> tuple[AttestationIngestor, EvidenceLedger]:
    ledger = EvidenceLedger()
    capability = ObservationCapability(ledger, collector_id, ("runtime",))
    ledger.open_task(task_id, (Requirement("runtime"),))
    ledger.seal()
    collectors = registry_for(
        collector_id,
        public_key_b64,
        allowed_kinds=("runtime",),
        allowed_profiles=(profile_id,),
    )
    ingestor = AttestationIngestor(
        capabilities={collector_id: capability},
        collectors=collectors,
        nonces=NonceLedger(),
    )
    return ingestor, ledger


def execute_core(
    *,
    client,
    public_key_b64: str,
    collector_id: str,
    profile_id: str,
    max_age_seconds: float,
    execution_id: str,
    task_id: str,
) -> dict[str, Any]:
    ingestor, ledger = _build_ingestor(
        public_key_b64,
        collector_id=collector_id,
        profile_id=profile_id,
        task_id=task_id,
    )
    nonce = ingestor.issue_nonce(execution_id, task_id, "runtime")
    raw = client.collect(
        execution_id=execution_id,
        task_id=task_id,
        evidence_kind="runtime",
        profile_id=profile_id,
        request_nonce=nonce,
    )
    if not isinstance(raw, dict):
        raise AuthenticatedE2EError("collector returned a non-object attestation")

    # Prove profile binding without consuming the real nonce.
    profile_rejection = ingestor.ingest(
        raw,
        execution_id=execution_id,
        task_id=task_id,
        expected_kind="runtime",
        expected_profile=f"{profile_id}-wrong",
        expected_nonce=nonce,
        max_age_seconds=max_age_seconds,
    )
    if profile_rejection.accepted or profile_rejection.reason is not RejectionReason.PROFILE_MISMATCH:
        raise AuthenticatedE2EError("profile binding rejection was not proven")

    # Prove nonce binding using another runtime-issued challenge.
    wrong_nonce = ingestor.issue_nonce(execution_id, task_id, "runtime")
    nonce_rejection = ingestor.ingest(
        raw,
        execution_id=execution_id,
        task_id=task_id,
        expected_kind="runtime",
        expected_profile=profile_id,
        expected_nonce=wrong_nonce,
        max_age_seconds=max_age_seconds,
    )
    if nonce_rejection.accepted or nonce_rejection.reason is not RejectionReason.NONCE_BINDING:
        raise AuthenticatedE2EError("nonce binding rejection was not proven")

    # Prove a signed field cannot be modified while retaining authority.
    tampered = copy.deepcopy(raw)
    tampered["status_code"] = 599 if raw.get("status_code") != 599 else 598
    tamper_rejection = ingestor.ingest(
        tampered,
        execution_id=execution_id,
        task_id=task_id,
        expected_kind="runtime",
        expected_profile=profile_id,
        expected_nonce=nonce,
        max_age_seconds=max_age_seconds,
    )
    if tamper_rejection.accepted or tamper_rejection.reason is not RejectionReason.SIGNATURE_INVALID:
        raise AuthenticatedE2EError("signed-field tamper rejection was not proven")

    accepted = ingestor.ingest(
        raw,
        execution_id=execution_id,
        task_id=task_id,
        expected_kind="runtime",
        expected_profile=profile_id,
        expected_nonce=nonce,
        max_age_seconds=max_age_seconds,
    )
    if not accepted.accepted or accepted.evidence is None:
        raise AuthenticatedE2EError(
            f"valid signed attestation was rejected: {accepted.reason}"
        )

    recorded = ledger.evidence(task_id)
    if len(recorded) != 1 or recorded[0].content_hash != accepted.evidence.content_hash:
        raise AuthenticatedE2EError("accepted attestation was not recorded exactly once")

    attestation_hash = hashlib.sha256(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "collector_id": collector_id,
        "profile_id": profile_id,
        "attestation_outcome": str(accepted.outcome),
        "signature_and_scope_verified": True,
        "profile_mismatch_rejected": True,
        "nonce_binding_rejected": True,
        "signed_field_tamper_rejected": True,
        "observed_evidence_recorded_once": True,
        "attestation_sha256": attestation_hash,
        "evidence_content_hash": accepted.evidence.content_hash,
        "nonce_sha256": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
    }


def run_authenticated_e2e(
    *,
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    collector_url: str,
    expected_git_sha: str,
    collector_id: str,
    profile_id: str,
    max_age_seconds: float,
    client_factory: Callable[[str], Any] | None = None,
    public_key_loader: Callable[[], str] | None = None,
) -> dict[str, Any]:
    verified_verdict = authorize_from_bundle(
        health,
        trust,
        manifest,
        verdict,
        expected_git_sha=expected_git_sha,
    )

    # Everything below this point is privileged. Nothing above it obtains a
    # token, opens a network connection, or loads trust material.
    loader = public_key_loader or (
        lambda: verification_provider_from_env().load_public_key_b64()
    )
    public_key_b64 = loader()
    factory = client_factory or (lambda url: GoogleIdTokenCollectorClient(url))
    client = factory(collector_url)

    execution_id = f"e2e_{secrets.token_hex(12)}"
    task_id = f"e2e_task_{secrets.token_hex(8)}"
    checks = execute_core(
        client=client,
        public_key_b64=public_key_b64,
        collector_id=collector_id,
        profile_id=profile_id,
        max_age_seconds=max_age_seconds,
        execution_id=execution_id,
        task_id=task_id,
    )

    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "observed_at": time.time(),
        "status": "AUTHENTICATED_E2E_PROVEN",
        "launch_verdict_sha256": verdict["verdict_sha256"],
        "manifest_sha256": verified_verdict["manifest_sha256"],
        "workflow_source_git_sha": verified_verdict["workflow_source_git_sha"],
        "github_deployment_id": verified_verdict["github_deployment_id"],
        "github_deployment_status_id": verified_verdict[
            "github_deployment_status_id"
        ],
        "deployment_environment": verified_verdict["deployment_environment"],
        "target_origin": verified_verdict["target_origin"],
        "transport": "google-oidc-ambient-service-identity",
        **checks,
        "claim_boundary": [
            "proves one authenticated collector call returned a signed attestation accepted by the existing ingestion kernel",
            "proves profile mismatch, nonce mismatch, and signed-field tampering are rejected locally by the same ingestion kernel",
            "does not prove restart durability, journal durability, or production release approval",
            "records no bearer token, private key, raw nonce, or raw attestation",
        ],
    }
    return {**body, "evidence_sha256": _canonical_hash(body)}


def _self_test() -> None:
    from proofos.attestation import AttestationSigner, Outcome
    from verify_live_evidence_pair import _health_sample, _trust_sample, build_manifest, verify_pair
    from build_live_launch_verdict import derive_verdict

    class FakeClient:
        def __init__(self, signer):
            self.signer = signer
            self.calls = 0

        def collect(self, execution_id, task_id, evidence_kind, profile_id, request_nonce):
            self.calls += 1
            return self.signer.sign(
                execution_id=execution_id,
                task_id=task_id,
                kind=evidence_kind,
                profile_id=profile_id,
                request_nonce=request_nonce,
                observed_at=time.time(),
                outcome=Outcome.HEALTHY,
                status_code=200,
                response_digest_value="digest",
                detail="healthy",
            ).to_dict()

    # HOLD must stop before any privileged loader or client factory runs.
    sha = "0123456789abcdef0123456789abcdef01234567"
    origin = "https://proofos-preview.vercel.app"
    hold_h = _health_sample(origin, sha)
    hold_t = _trust_sample(origin, sha)
    hold_m = build_manifest(verify_pair(hold_h, hold_t, expected_git_sha=sha))
    hold_v = derive_verdict(hold_h, hold_t, hold_m, expected_git_sha=sha)
    touched = []
    try:
        run_authenticated_e2e(
            health=hold_h,
            trust=hold_t,
            manifest=hold_m,
            verdict=hold_v,
            collector_url=origin,
            expected_git_sha=sha,
            collector_id="collector-http-v1",
            profile_id="runtime-health-v1",
            max_age_seconds=120,
            client_factory=lambda _url: touched.append("client"),
            public_key_loader=lambda: touched.append("key"),
        )
    except AuthenticatedE2EError:
        pass
    else:
        raise AssertionError("HOLD verdict authorized E2E")
    assert touched == []

    # Unit-test the privileged core with a real Ed25519 signer and no network.
    signer = AttestationSigner.generate("collector-http-v1")
    client = FakeClient(signer)
    checks = execute_core(
        client=client,
        public_key_b64=signer.public_key_b64(),
        collector_id="collector-http-v1",
        profile_id="runtime-health-v1",
        max_age_seconds=120,
        execution_id="e2e_test",
        task_id="e2e_task",
    )
    assert client.calls == 1
    assert checks["signature_and_scope_verified"]
    assert checks["profile_mismatch_rejected"]
    assert checks["nonce_binding_rejected"]
    assert checks["signed_field_tamper_rejected"]
    print("authenticated E2E gate self-test OK")


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("health", "trust", "manifest", "verdict"):
        p.add_argument(name, nargs="?", type=Path)
    p.add_argument("--collector-url", default="")
    p.add_argument("--expected-git-sha", default="")
    p.add_argument("--collector-id", default="collector-http-v1")
    p.add_argument("--profile-id", default="runtime-health-v1")
    p.add_argument("--max-age-seconds", type=float, default=120.0)
    p.add_argument("--output", type=Path)
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()

    if a.self_test:
        _self_test()
        return 0

    if any(getattr(a, name) is None for name in ("health", "trust", "manifest", "verdict")):
        p.error("four launch evidence artifacts are required")
    if not a.collector_url or a.output is None:
        p.error("--collector-url and --output are required")

    try:
        evidence = run_authenticated_e2e(
            health=_load_json(a.health),
            trust=_load_json(a.trust),
            manifest=_load_json(a.manifest),
            verdict=_load_json(a.verdict),
            collector_url=a.collector_url,
            expected_git_sha=a.expected_git_sha,
            collector_id=a.collector_id,
            profile_id=a.profile_id,
            max_age_seconds=a.max_age_seconds,
        )
    except AuthenticatedE2EError as exc:
        print(f"authenticated E2E HOLD/FAIL: {exc}", file=sys.stderr)
        return 2

    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
