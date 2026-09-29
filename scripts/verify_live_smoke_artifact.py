"""Verify persisted Vercel live-smoke evidence without trusting its producer.

The verifier consumes only the artifact bytes. It recomputes the self-hash and
checks outcome-specific invariants so a stored smoke record cannot silently
change meaning after it was produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 2
KIND = "vercel-live-smoke-observation"
OUTCOMES = {"OBSERVED_HEALTH", "BLOCKED_BY_DEPLOYMENT_PROTECTION"}
ALLOWED_RUNTIME_KEYS = {
    "platform",
    "environment",
    "deployment_id",
    "region",
    "git_sha",
    "url",
}


class ArtifactVerificationError(RuntimeError):
    pass


def _git_sha(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ArtifactVerificationError(f"{field} must be a string")
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ArtifactVerificationError(f"{field} must be a full 40-character git SHA")
    return value


def _vercel_origin(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ArtifactVerificationError(f"{field} must be a string")
    parts = urlsplit(value.strip())
    if (
        parts.scheme != "https"
        or not parts.hostname
        or not parts.hostname.lower().endswith(".vercel.app")
        or parts.username is not None
        or parts.password is not None
        or parts.port not in {None, 443}
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ArtifactVerificationError(f"{field} must be an exact https://*.vercel.app origin")
    return f"https://{parts.hostname.lower()}"


def _canonical_hash_without_digest(evidence: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _positive_int(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ArtifactVerificationError(f"{field} must be a positive integer")
    return value


def _environment(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ArtifactVerificationError(f"{field} must be a string")
    value = value.strip().lower()
    if value not in {"production", "preview", "development"}:
        raise ArtifactVerificationError(f"{field} is unsupported")
    return value


def _deployment_event(evidence: dict[str, Any]) -> dict[str, Any]:
    event = evidence.get("deployment_event")
    if not isinstance(event, dict):
        raise ArtifactVerificationError("deployment_event is missing")
    expected_keys = {
        "github_deployment_id",
        "github_deployment_status_id",
        "environment",
        "environment_url",
        "source_git_sha",
    }
    if set(event) != expected_keys:
        raise ArtifactVerificationError("deployment_event fields do not match schema")
    return {
        "github_deployment_id": _positive_int(
            event["github_deployment_id"], field="deployment_event.github_deployment_id"
        ),
        "github_deployment_status_id": _positive_int(
            event["github_deployment_status_id"],
            field="deployment_event.github_deployment_status_id",
        ),
        "environment": _environment(
            event["environment"], field="deployment_event.environment"
        ),
        "environment_url": _vercel_origin(
            event["environment_url"], field="deployment_event.environment_url"
        ),
        "source_git_sha": _git_sha(
            event["source_git_sha"], field="deployment_event.source_git_sha"
        ),
    }


def verify_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise ArtifactVerificationError("artifact must be a JSON object")

    if evidence.get("schema_version") != SCHEMA_VERSION:
        raise ArtifactVerificationError("unsupported schema version")
    if evidence.get("kind") != KIND:
        raise ArtifactVerificationError("unexpected evidence kind")
    if evidence.get("observer") != "github-actions-http":
        raise ArtifactVerificationError("unexpected observer")

    digest = evidence.get("evidence_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ArtifactVerificationError("evidence SHA-256 is missing or malformed")
    expected_digest = _canonical_hash_without_digest(evidence)
    if digest.lower() != expected_digest:
        raise ArtifactVerificationError("evidence SHA-256 mismatch")

    origin = _vercel_origin(evidence.get("target_origin"), field="target_origin")
    deployment_event = _deployment_event(evidence)
    if deployment_event["environment_url"] != origin:
        raise ArtifactVerificationError(
            "target origin does not match deployment event environment URL"
        )
    if evidence.get("health_url") != f"{origin}/healthz":
        raise ArtifactVerificationError("health URL is not bound to target origin")

    if not isinstance(evidence.get("bypass_attempted"), bool):
        raise ArtifactVerificationError("bypass_attempted must be boolean")

    boundary = evidence.get("claim_boundary")
    if not isinstance(boundary, list) or not boundary or not all(
        isinstance(item, str) and item.strip() for item in boundary
    ):
        raise ArtifactVerificationError("claim boundary must be a non-empty list of statements")

    outcome = evidence.get("outcome")
    if outcome not in OUTCOMES:
        raise ArtifactVerificationError("unsupported smoke outcome")

    workflow_sha = evidence.get("workflow_source_git_sha")
    if workflow_sha is not None:
        workflow_sha = _git_sha(workflow_sha, field="workflow_source_git_sha")
    if workflow_sha != deployment_event["source_git_sha"]:
        raise ArtifactVerificationError(
            "workflow source SHA does not match deployment event source SHA"
        )

    if outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        if evidence.get("http_status") not in {401, 403}:
            raise ArtifactVerificationError("protection-blocked evidence must record HTTP 401 or 403")
        if "observation" in evidence:
            raise ArtifactVerificationError("protection-blocked evidence must not claim an application observation")
        if not any("does not prove the collector is healthy or unhealthy" in item for item in boundary):
            raise ArtifactVerificationError("protection-blocked claim boundary is incomplete")
        return {
            "valid": True,
            "outcome": outcome,
            "target_origin": origin,
            "workflow_source_git_sha": workflow_sha,
            "deployment_event": deployment_event,
            "evidence_sha256": digest.lower(),
        }

    if evidence.get("http_status") != 200:
        raise ArtifactVerificationError("observed-health evidence must record HTTP 200")
    observation = evidence.get("observation")
    if not isinstance(observation, dict):
        raise ArtifactVerificationError("observed-health evidence is missing observation")
    if observation.get("status") != "ok":
        raise ArtifactVerificationError("observed health status is not ok")
    if observation.get("service") != "proofos-collector":
        raise ArtifactVerificationError("observed service identity is unexpected")

    runtime = observation.get("runtime")
    if not isinstance(runtime, dict):
        raise ArtifactVerificationError("observed runtime provenance is missing")
    if set(runtime) - ALLOWED_RUNTIME_KEYS:
        raise ArtifactVerificationError("runtime provenance contains non-allowlisted fields")
    if runtime.get("platform") != "vercel":
        raise ArtifactVerificationError("observed runtime platform is not vercel")

    deployment_id = runtime.get("deployment_id")
    if not isinstance(deployment_id, str) or not deployment_id.startswith("dpl_"):
        raise ArtifactVerificationError("deployment id is missing or malformed")

    environment = runtime.get("environment")
    if environment not in {"production", "preview", "development"}:
        raise ArtifactVerificationError("runtime environment is missing or invalid")
    if environment != deployment_event["environment"]:
        raise ArtifactVerificationError(
            "runtime environment does not match deployment event environment"
        )

    runtime_sha = _git_sha(runtime.get("git_sha"), field="runtime.git_sha")
    if workflow_sha is None:
        raise ArtifactVerificationError("observed-health evidence requires workflow source SHA")
    if runtime_sha != workflow_sha:
        raise ArtifactVerificationError("runtime git SHA does not match workflow source SHA")

    if "url" in runtime:
        runtime_url = _vercel_origin(runtime["url"], field="runtime.url")
        if runtime_url != deployment_event["environment_url"]:
            raise ArtifactVerificationError(
                "runtime URL does not match deployment event environment URL"
            )

    if not any("does not prove IAM policy" in item for item in boundary):
        raise ArtifactVerificationError("observed-health claim boundary is incomplete")

    return {
        "valid": True,
        "outcome": outcome,
        "target_origin": origin,
        "deployment_id": deployment_id,
        "workflow_source_git_sha": workflow_sha,
        "runtime_git_sha": runtime_sha,
        "deployment_event": deployment_event,
        "evidence_sha256": digest.lower(),
    }


def _signed(sample: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(sample, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**sample, "evidence_sha256": digest}


def _self_test() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    blocked = _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": "https://proofos-preview.vercel.app",
            "health_url": "https://proofos-preview.vercel.app/healthz",
            "http_status": 401,
            "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
            "bypass_attempted": False,
            "workflow_source_git_sha": sha,
            "deployment_event": {
                "github_deployment_id": 123,
                "github_deployment_status_id": 456,
                "environment": "preview",
                "environment_url": "https://proofos-preview.vercel.app",
                "source_git_sha": sha,
            },
            "claim_boundary": [
                "proves the deployment edge rejected the workflow request before application health was observed",
                "does not prove the collector is healthy or unhealthy",
                "does not expose or record the automation bypass secret",
            ],
        }
    )
    assert verify_evidence(blocked)["valid"]

    observed = _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": "https://proofos-preview.vercel.app",
            "health_url": "https://proofos-preview.vercel.app/healthz",
            "http_status": 200,
            "outcome": "OBSERVED_HEALTH",
            "bypass_attempted": True,
            "workflow_source_git_sha": sha,
            "deployment_event": {
                "github_deployment_id": 123,
                "github_deployment_status_id": 456,
                "environment": "preview",
                "environment_url": "https://proofos-preview.vercel.app",
                "source_git_sha": sha,
            },
            "observation": {
                "status": "ok",
                "service": "proofos-collector",
                "runtime": {
                    "platform": "vercel",
                    "environment": "preview",
                    "deployment_id": "dpl_test",
                    "region": "icn1",
                    "git_sha": sha,
                    "url": "https://proofos-preview.vercel.app",
                },
            },
            "claim_boundary": [
                "proves the HTTPS health endpoint answered the expected public contract",
                "records only allowlisted runtime provenance exposed by the collector",
                "does not prove IAM policy, readiness, signing-key durability, or an end-to-end VERIFIED execution",
            ],
        }
    )
    assert verify_evidence(observed)["runtime_git_sha"] == sha

    tampered = json.loads(json.dumps(observed))
    tampered["observation"]["runtime"]["git_sha"] = "f" * 40
    try:
        verify_evidence(tampered)
    except ArtifactVerificationError:
        pass
    else:
        raise AssertionError("tampered evidence was accepted")

    print("live smoke artifact verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if args.artifact is None:
        parser.error("artifact path is required unless --self-test is used")

    try:
        raw = args.artifact.read_text(encoding="utf-8")
        evidence = json.loads(raw)
        result = verify_evidence(evidence)
    except (OSError, json.JSONDecodeError, ArtifactVerificationError) as exc:
        print(f"live smoke artifact INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
