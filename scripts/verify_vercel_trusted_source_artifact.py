"""Independently verify persisted Vercel Trusted Source probe evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
KIND = "vercel-trusted-source-observation"
OUTCOMES = {
    "TRUSTED_SOURCE_REJECTED",
    "TRUSTED_SOURCE_ACCEPTED_READY",
    "TRUSTED_SOURCE_ACCEPTED_NOT_READY",
}


class TrustedSourceArtifactError(RuntimeError):
    pass


def _origin(value: Any) -> str:
    if not isinstance(value, str):
        raise TrustedSourceArtifactError("target origin must be a string")
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
        raise TrustedSourceArtifactError(
            "target origin must be an exact https://*.vercel.app origin"
        )
    return f"https://{parts.hostname.lower()}"


def _git_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise TrustedSourceArtifactError("source git SHA must be a string")
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise TrustedSourceArtifactError(
            "source git SHA must be a full 40-character SHA"
        )
    return value


def _positive_int(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise TrustedSourceArtifactError(f"{field} must be a positive integer")
    return value


def _deployment_event(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "github_deployment_id",
        "github_deployment_status_id",
        "environment",
        "environment_url",
        "source_git_sha",
    }:
        raise TrustedSourceArtifactError("deployment_event schema drifted")
    if value.get("environment") != "production":
        raise TrustedSourceArtifactError("trusted-source evidence must be production")
    return {
        "github_deployment_id": _positive_int(
            value["github_deployment_id"], field="github_deployment_id"
        ),
        "github_deployment_status_id": _positive_int(
            value["github_deployment_status_id"], field="github_deployment_status_id"
        ),
        "environment": "production",
        "environment_url": _origin(value["environment_url"]),
        "source_git_sha": _git_sha(value["source_git_sha"]),
    }


def _hash_without_digest(value: dict[str, Any]) -> str:
    unsigned = {
        key: item for key, item in value.items() if key != "evidence_sha256"
    }
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _health(value: Any, *, origin: str, sha: str) -> None:
    if not isinstance(value, dict) or set(value) != {"status", "service", "runtime"}:
        raise TrustedSourceArtifactError("health schema drifted")
    if value.get("status") != "ok" or value.get("service") != "proofos-collector":
        raise TrustedSourceArtifactError("health identity is invalid")
    runtime = value.get("runtime")
    if not isinstance(runtime, dict):
        raise TrustedSourceArtifactError("runtime provenance is missing")
    allowed = {"platform", "environment", "deployment_id", "region", "git_sha", "url"}
    if set(runtime) - allowed:
        raise TrustedSourceArtifactError("runtime provenance contains extra fields")
    if runtime.get("platform") != "vercel":
        raise TrustedSourceArtifactError("runtime platform is not vercel")
    if runtime.get("environment") != "production":
        raise TrustedSourceArtifactError("runtime environment is not production")
    if _git_sha(runtime.get("git_sha")) != sha:
        raise TrustedSourceArtifactError("runtime Git SHA does not match source")
    if "url" in runtime and _origin(runtime["url"]) != origin:
        raise TrustedSourceArtifactError("runtime URL does not match origin")


def _readiness(value: Any, *, expected: str) -> None:
    if not isinstance(value, dict) or set(value) != {"status", "service", "issues"}:
        raise TrustedSourceArtifactError("readiness schema drifted")
    if value.get("service") != "proofos-collector":
        raise TrustedSourceArtifactError("readiness service is invalid")
    if value.get("status") != expected:
        raise TrustedSourceArtifactError("readiness status does not match outcome")
    issues = value.get("issues")
    if not isinstance(issues, list) or any(
        not isinstance(item, str) or not item or len(item) > 120 for item in issues
    ):
        raise TrustedSourceArtifactError("readiness issue list is invalid")
    if expected == "ready" and issues:
        raise TrustedSourceArtifactError("ready evidence cannot carry issues")


def verify_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrustedSourceArtifactError("artifact must be an object")

    common = {
        "schema_version",
        "kind",
        "observed_at",
        "observer",
        "target_origin",
        "workflow_source_git_sha",
        "deployment_event",
        "outcome",
        "claim_boundary",
        "evidence_sha256",
    }
    outcome = value.get("outcome")
    if outcome not in OUTCOMES:
        raise TrustedSourceArtifactError("unsupported trusted-source outcome")

    expected_keys = set(common)
    if outcome == "TRUSTED_SOURCE_REJECTED":
        expected_keys.add("http_status")
    else:
        expected_keys.update({"health", "readiness"})

    if set(value) != expected_keys:
        raise TrustedSourceArtifactError("artifact top-level schema drifted")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != KIND:
        raise TrustedSourceArtifactError("artifact type is invalid")
    if value.get("observer") != "github-actions-oidc":
        raise TrustedSourceArtifactError("observer is invalid")
    if not isinstance(value.get("observed_at"), str) or not value["observed_at"].strip():
        raise TrustedSourceArtifactError("observed_at is missing")

    digest = value.get("evidence_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in "0123456789abcdefABCDEF" for ch in digest)
    ):
        raise TrustedSourceArtifactError("evidence digest is malformed")
    if digest.lower() != _hash_without_digest(value):
        raise TrustedSourceArtifactError("evidence digest mismatch")

    origin = _origin(value.get("target_origin"))
    sha = _git_sha(value.get("workflow_source_git_sha"))
    event = _deployment_event(value.get("deployment_event"))
    if event["environment_url"] != origin or event["source_git_sha"] != sha:
        raise TrustedSourceArtifactError("deployment binding mismatch")

    boundary = value.get("claim_boundary")
    if not isinstance(boundary, list) or not boundary or not all(
        isinstance(item, str) and item.strip() for item in boundary
    ):
        raise TrustedSourceArtifactError("claim boundary is invalid")
    if not any("does not reveal or persist the OIDC token" in item for item in boundary):
        raise TrustedSourceArtifactError("OIDC secrecy boundary is missing")

    if outcome == "TRUSTED_SOURCE_REJECTED":
        if value.get("http_status") not in {401, 403}:
            raise TrustedSourceArtifactError("rejected outcome requires HTTP 401/403")
    else:
        _health(value.get("health"), origin=origin, sha=sha)
        expected_ready = (
            "ready"
            if outcome == "TRUSTED_SOURCE_ACCEPTED_READY"
            else "not_ready"
        )
        _readiness(value.get("readiness"), expected=expected_ready)

    return {
        "valid": True,
        "outcome": outcome,
        "target_origin": origin,
        "workflow_source_git_sha": sha,
        "evidence_sha256": digest.lower(),
    }


def _signed(value: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**value, "evidence_sha256": digest}


def _base(outcome: str) -> dict[str, Any]:
    sha = "0123456789abcdef0123456789abcdef01234567"
    origin = "https://proofos-production.vercel.app"
    return {
        "schema_version": 1,
        "kind": KIND,
        "observed_at": "2026-09-30T00:00:00+00:00",
        "observer": "github-actions-oidc",
        "target_origin": origin,
        "workflow_source_git_sha": sha,
        "deployment_event": {
            "github_deployment_id": 123,
            "github_deployment_status_id": 456,
            "environment": "production",
            "environment_url": origin,
            "source_git_sha": sha,
        },
        "outcome": outcome,
    }


def _self_test() -> None:
    rejected = _base("TRUSTED_SOURCE_REJECTED")
    rejected.update(
        {
            "http_status": 401,
            "claim_boundary": [
                "proves the Vercel edge did not accept this GitHub Actions OIDC request",
                "does not reveal or persist the OIDC token",
                "does not prove application health or readiness",
            ],
        }
    )
    assert verify_evidence(_signed(rejected))["valid"]

    accepted = _base("TRUSTED_SOURCE_ACCEPTED_NOT_READY")
    accepted.update(
        {
            "health": {
                "status": "ok",
                "service": "proofos-collector",
                "runtime": {
                    "platform": "vercel",
                    "environment": "production",
                    "deployment_id": "dpl_test",
                    "git_sha": accepted["workflow_source_git_sha"],
                    "url": accepted["target_origin"],
                },
            },
            "readiness": {
                "status": "not_ready",
                "service": "proofos-collector",
                "issues": ["signing_key_not_configured"],
            },
            "claim_boundary": [
                "proves Vercel Trusted Sources accepted the GitHub Actions OIDC request",
                "records only the public health/readiness contract after edge authentication",
                "does not prove authenticated collector invocation or signed evidence collection",
                "does not reveal or persist the OIDC token",
            ],
        }
    )
    assert verify_evidence(_signed(accepted))["valid"]

    tampered = _signed(accepted)
    tampered["readiness"]["status"] = "ready"
    try:
        verify_evidence(tampered)
    except TrustedSourceArtifactError:
        pass
    else:
        raise AssertionError("tampered trusted-source evidence was accepted")

    print("Vercel trusted-source artifact verifier self-test OK")


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
        value = json.loads(args.artifact.read_text(encoding="utf-8"))
        result = verify_evidence(value)
    except (OSError, json.JSONDecodeError, TrustedSourceArtifactError) as exc:
        print(f"trusted-source artifact INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
