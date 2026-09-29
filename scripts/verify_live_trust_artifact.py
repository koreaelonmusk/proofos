"""Verify persisted Vercel trust-surface evidence independently.

The producer performs network I/O. This verifier does not. It consumes only the
persisted JSON bytes, recomputes the self-hash, and checks that each top-level
outcome is exactly supported by its readiness and anonymous-collection facts.
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
KIND = "vercel-live-trust-surface-observation"
TOP_LEVEL_KEYS = {
    "schema_version",
    "kind",
    "observed_at",
    "observer",
    "target_origin",
    "workflow_source_git_sha",
    "deployment_event",
    "bypass_attempted",
    "outcome",
    "readiness",
    "anonymous_collect",
    "claim_boundary",
    "evidence_sha256",
}
OUTCOMES = {
    "READY_AND_ANONYMOUS_DENIED",
    "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED",
    "READINESS_BLOCKED_AND_ANONYMOUS_DENIED",
    "BLOCKED_BY_DEPLOYMENT_PROTECTION",
}


class TrustArtifactVerificationError(RuntimeError):
    pass


def _origin(value: Any) -> str:
    if not isinstance(value, str):
        raise TrustArtifactVerificationError("target_origin must be a string")
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
        raise TrustArtifactVerificationError(
            "target_origin must be an exact https://*.vercel.app origin"
        )
    return f"https://{parts.hostname.lower()}"


def _git_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise TrustArtifactVerificationError("workflow_source_git_sha must be a string")
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise TrustArtifactVerificationError(
            "workflow_source_git_sha must be a full 40-character git SHA"
        )
    return value


def _positive_int(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise TrustArtifactVerificationError(f"{field} must be a positive integer")
    return value


def _environment(value: Any) -> str:
    if not isinstance(value, str):
        raise TrustArtifactVerificationError("deployment environment must be a string")
    value = value.strip().lower()
    if value not in {"production", "preview", "development"}:
        raise TrustArtifactVerificationError("deployment environment is unsupported")
    return value


def _deployment_event(evidence: dict[str, Any]) -> dict[str, Any]:
    event = evidence.get("deployment_event")
    if not isinstance(event, dict):
        raise TrustArtifactVerificationError("deployment_event is missing")
    expected_keys = {
        "github_deployment_id",
        "github_deployment_status_id",
        "environment",
        "environment_url",
        "source_git_sha",
    }
    if set(event) != expected_keys:
        raise TrustArtifactVerificationError("deployment_event fields do not match schema")
    return {
        "github_deployment_id": _positive_int(
            event["github_deployment_id"], field="deployment_event.github_deployment_id"
        ),
        "github_deployment_status_id": _positive_int(
            event["github_deployment_status_id"],
            field="deployment_event.github_deployment_status_id",
        ),
        "environment": _environment(event["environment"]),
        "environment_url": _origin(event["environment_url"]),
        "source_git_sha": _git_sha(event["source_git_sha"]),
    }


def _hash_without_digest(evidence: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in evidence.items() if key != "evidence_sha256"
    }
    canonical = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _readiness(value: Any) -> str:
    if not isinstance(value, dict):
        raise TrustArtifactVerificationError("readiness must be an object")
    outcome = value.get("outcome")
    status = value.get("http_status")

    if outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        if status not in {401, 403} or "observation" in value:
            raise TrustArtifactVerificationError("invalid protection-blocked readiness")
        return outcome

    observation = value.get("observation")
    if not isinstance(observation, dict) or set(observation) != {
        "status",
        "service",
        "issues",
    }:
        raise TrustArtifactVerificationError("invalid readiness observation schema")
    if observation.get("service") != "proofos-collector":
        raise TrustArtifactVerificationError("unexpected readiness service")

    issues = observation.get("issues")
    if not isinstance(issues, list) or any(
        not isinstance(item, str) or not item or len(item) > 120 for item in issues
    ):
        raise TrustArtifactVerificationError("invalid readiness issue list")

    if outcome == "READY":
        if status != 200 or observation.get("status") != "ready" or issues:
            raise TrustArtifactVerificationError("inconsistent READY evidence")
        return outcome

    if outcome == "CONFIG_NOT_READY":
        if status != 503 or observation.get("status") != "not_ready":
            raise TrustArtifactVerificationError("inconsistent CONFIG_NOT_READY evidence")
        return outcome

    raise TrustArtifactVerificationError("unsupported readiness outcome")


def _anonymous_collect(value: Any) -> str:
    if not isinstance(value, dict):
        raise TrustArtifactVerificationError("anonymous_collect must be an object")
    outcome = value.get("outcome")
    status = value.get("http_status")

    if outcome == "ANONYMOUS_COLLECTION_DENIED":
        if status != 401 or set(value) != {"outcome", "http_status"}:
            raise TrustArtifactVerificationError(
                "application-level anonymous denial must be exactly HTTP 401"
            )
        return outcome

    if outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        if status not in {401, 403} or set(value) != {"outcome", "http_status"}:
            raise TrustArtifactVerificationError("invalid protection-blocked collection")
        return outcome

    raise TrustArtifactVerificationError("unsupported anonymous collection outcome")


def verify_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise TrustArtifactVerificationError("artifact must be a JSON object")
    if set(evidence) != TOP_LEVEL_KEYS:
        raise TrustArtifactVerificationError("artifact top-level schema drifted")
    if evidence.get("schema_version") != SCHEMA_VERSION:
        raise TrustArtifactVerificationError("unsupported schema version")
    if evidence.get("kind") != KIND:
        raise TrustArtifactVerificationError("unexpected evidence kind")
    if evidence.get("observer") != "github-actions-http":
        raise TrustArtifactVerificationError("unexpected observer")
    if not isinstance(evidence.get("observed_at"), str) or not evidence["observed_at"].strip():
        raise TrustArtifactVerificationError("observed_at is missing")
    if not isinstance(evidence.get("bypass_attempted"), bool):
        raise TrustArtifactVerificationError("bypass_attempted must be boolean")

    digest = evidence.get("evidence_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise TrustArtifactVerificationError("evidence SHA-256 is malformed")
    if digest.lower() != _hash_without_digest(evidence):
        raise TrustArtifactVerificationError("evidence SHA-256 mismatch")

    origin = _origin(evidence.get("target_origin"))
    workflow_sha = _git_sha(evidence.get("workflow_source_git_sha"))
    deployment_event = _deployment_event(evidence)
    if deployment_event["environment_url"] != origin:
        raise TrustArtifactVerificationError(
            "target origin does not match deployment event environment URL"
        )
    if deployment_event["source_git_sha"] != workflow_sha:
        raise TrustArtifactVerificationError(
            "workflow source SHA does not match deployment event source SHA"
        )

    boundary = evidence.get("claim_boundary")
    if not isinstance(boundary, list) or not boundary or not all(
        isinstance(item, str) and item.strip() for item in boundary
    ):
        raise TrustArtifactVerificationError("claim boundary is invalid")
    if not any(
        "does not prove an authenticated end-to-end collection succeeds" in item
        for item in boundary
    ):
        raise TrustArtifactVerificationError("claim boundary overstates trust evidence")

    readiness = _readiness(evidence.get("readiness"))
    anonymous = _anonymous_collect(evidence.get("anonymous_collect"))
    outcome = evidence.get("outcome")
    if outcome not in OUTCOMES:
        raise TrustArtifactVerificationError("unsupported top-level outcome")

    expected_pair = {
        "READY_AND_ANONYMOUS_DENIED": ("READY", "ANONYMOUS_COLLECTION_DENIED"),
        "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED": (
            "CONFIG_NOT_READY",
            "ANONYMOUS_COLLECTION_DENIED",
        ),
        "READINESS_BLOCKED_AND_ANONYMOUS_DENIED": (
            "BLOCKED_BY_DEPLOYMENT_PROTECTION",
            "ANONYMOUS_COLLECTION_DENIED",
        ),
        "BLOCKED_BY_DEPLOYMENT_PROTECTION": (
            "BLOCKED_BY_DEPLOYMENT_PROTECTION",
            "BLOCKED_BY_DEPLOYMENT_PROTECTION",
        ),
    }[outcome]

    if (readiness, anonymous) != expected_pair:
        raise TrustArtifactVerificationError(
            "top-level outcome is not supported by observed trust facts"
        )

    return {
        "valid": True,
        "outcome": outcome,
        "target_origin": origin,
        "workflow_source_git_sha": workflow_sha,
        "deployment_event": deployment_event,
        "evidence_sha256": digest.lower(),
    }


def _signed(sample: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(sample, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**sample, "evidence_sha256": digest}


def _sample(outcome: str, readiness: dict[str, Any], anonymous: dict[str, Any]) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": "https://proofos-preview.vercel.app",
            "workflow_source_git_sha": "0123456789abcdef0123456789abcdef01234567",
            "deployment_event": {
                "github_deployment_id": 123,
                "github_deployment_status_id": 456,
                "environment": "preview",
                "environment_url": "https://proofos-preview.vercel.app",
                "source_git_sha": "0123456789abcdef0123456789abcdef01234567",
            },
            "bypass_attempted": True,
            "outcome": outcome,
            "readiness": readiness,
            "anonymous_collect": anonymous,
            "claim_boundary": [
                "records whether the live collector configuration is ready or explicitly not ready",
                "proves anonymous collection is denied only when the application response is reached",
                "does not prove an authenticated end-to-end collection succeeds",
                "does not expose signing keys, bearer tokens, WIF tokens, target URLs, or bypass secrets",
            ],
        }
    )


def _self_test() -> None:
    ready = {
        "outcome": "READY",
        "http_status": 200,
        "observation": {
            "status": "ready",
            "service": "proofos-collector",
            "issues": [],
        },
    }
    denied = {"outcome": "ANONYMOUS_COLLECTION_DENIED", "http_status": 401}
    valid = _sample("READY_AND_ANONYMOUS_DENIED", ready, denied)
    assert verify_evidence(valid)["valid"]

    not_ready = {
        "outcome": "CONFIG_NOT_READY",
        "http_status": 503,
        "observation": {
            "status": "not_ready",
            "service": "proofos-collector",
            "issues": ["signing_key_not_configured"],
        },
    }
    assert verify_evidence(
        _sample("CONFIG_NOT_READY_AND_ANONYMOUS_DENIED", not_ready, denied)
    )["valid"]

    blocked = {
        "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
        "http_status": 403,
    }
    assert verify_evidence(
        _sample("READINESS_BLOCKED_AND_ANONYMOUS_DENIED", blocked, denied)
    )["valid"]
    assert verify_evidence(
        _sample("BLOCKED_BY_DEPLOYMENT_PROTECTION", blocked, blocked)
    )["valid"]

    tampered = json.loads(json.dumps(valid))
    tampered["anonymous_collect"]["http_status"] = 200
    try:
        verify_evidence(tampered)
    except TrustArtifactVerificationError:
        pass
    else:
        raise AssertionError("tampered trust evidence was accepted")

    mismatched = _sample("READY_AND_ANONYMOUS_DENIED", not_ready, denied)
    try:
        verify_evidence(mismatched)
    except TrustArtifactVerificationError:
        pass
    else:
        raise AssertionError("unsupported outcome/fact pairing was accepted")

    print("live trust artifact verifier self-test OK")


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
        evidence = json.loads(args.artifact.read_text(encoding="utf-8"))
        result = verify_evidence(evidence)
    except (
        OSError,
        json.JSONDecodeError,
        TrustArtifactVerificationError,
    ) as exc:
        print(f"live trust artifact INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
