"""Cross-check independently verified Vercel health and trust artifacts.

Each artifact already has its own producer and independent verifier. This gate
prevents split-brain evidence where individually valid records accidentally refer
to different deployments, origins, or source revisions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_smoke_artifact import (
    ArtifactVerificationError,
    verify_evidence as verify_health_evidence,
)
from verify_live_trust_artifact import (
    TrustArtifactVerificationError,
    verify_evidence as verify_trust_evidence,
)


class EvidencePairError(RuntimeError):
    pass


def _full_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise EvidencePairError("expected git SHA must be a full 40-character SHA")
    return value


def verify_pair(
    health_evidence: Any,
    trust_evidence: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    try:
        health = verify_health_evidence(health_evidence)
    except ArtifactVerificationError as exc:
        raise EvidencePairError(f"health evidence invalid: {exc}") from exc

    try:
        trust = verify_trust_evidence(trust_evidence)
    except TrustArtifactVerificationError as exc:
        raise EvidencePairError(f"trust evidence invalid: {exc}") from exc

    if health["target_origin"] != trust["target_origin"]:
        raise EvidencePairError("health and trust evidence target different origins")

    if health["workflow_source_git_sha"] != trust["workflow_source_git_sha"]:
        raise EvidencePairError(
            "health and trust evidence bind to different workflow source SHAs"
        )

    if health.get("deployment_event") != trust.get("deployment_event"):
        raise EvidencePairError(
            "health and trust evidence bind to different deployment events"
        )

    source_sha = health["workflow_source_git_sha"]
    if source_sha is None:
        raise EvidencePairError("paired evidence requires a workflow source SHA")

    if expected_git_sha and source_sha != _full_sha(expected_git_sha):
        raise EvidencePairError("paired evidence does not match the expected git SHA")

    pair_material = {
        "health_evidence_sha256": health["evidence_sha256"],
        "trust_evidence_sha256": trust["evidence_sha256"],
        "target_origin": health["target_origin"],
        "workflow_source_git_sha": source_sha,
        "github_deployment_id": health["deployment_event"]["github_deployment_id"],
        "github_deployment_status_id": health["deployment_event"]["github_deployment_status_id"],
        "deployment_environment": health["deployment_event"]["environment"],
    }
    pair_digest = hashlib.sha256(
        json.dumps(pair_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return {
        "valid": True,
        **pair_material,
        "pair_sha256": pair_digest,
        "health_outcome": health["outcome"],
        "trust_outcome": trust["outcome"],
    }


def _signed(sample: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(
        json.dumps(sample, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**sample, "evidence_sha256": digest}


def _health_sample(origin: str, sha: str) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 2,
            "kind": "vercel-live-smoke-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "health_url": f"{origin}/healthz",
            "http_status": 401,
            "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
            "bypass_attempted": False,
            "workflow_source_git_sha": sha,
            "deployment_event": {
                "github_deployment_id": 123,
                "github_deployment_status_id": 456,
                "environment": "preview",
                "environment_url": origin,
                "source_git_sha": sha,
            },
            "claim_boundary": [
                "proves the deployment edge rejected the workflow request before application health was observed",
                "does not prove the collector is healthy or unhealthy",
                "does not expose or record the automation bypass secret",
            ],
        }
    )


def _trust_sample(origin: str, sha: str) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 2,
            "kind": "vercel-live-trust-surface-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "workflow_source_git_sha": sha,
            "deployment_event": {
                "github_deployment_id": 123,
                "github_deployment_status_id": 456,
                "environment": "preview",
                "environment_url": origin,
                "source_git_sha": sha,
            },
            "bypass_attempted": False,
            "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
            "readiness": {
                "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
                "http_status": 401,
            },
            "anonymous_collect": {
                "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
                "http_status": 401,
            },
            "claim_boundary": [
                "records whether the live collector configuration is ready or explicitly not ready",
                "proves anonymous collection is denied only when the application response is reached",
                "does not prove an authenticated end-to-end collection succeeds",
                "does not expose signing keys, bearer tokens, WIF tokens, target URLs, or bypass secrets",
            ],
        }
    )


def _self_test() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    origin = "https://proofos-preview.vercel.app"

    paired = verify_pair(
        _health_sample(origin, sha),
        _trust_sample(origin, sha),
        expected_git_sha=sha,
    )
    assert paired["valid"]
    assert len(paired["pair_sha256"]) == 64

    cases = (
        (
            _health_sample(origin, sha),
            _trust_sample("https://other-preview.vercel.app", sha),
        ),
        (
            _health_sample(origin, sha),
            _trust_sample(origin, "f" * 40),
        ),
    )
    for health, trust in cases:
        try:
            verify_pair(health, trust)
        except EvidencePairError:
            continue
        raise AssertionError("split-brain evidence pair was accepted")

    tampered = _health_sample(origin, sha)
    tampered["http_status"] = 200
    try:
        verify_pair(tampered, _trust_sample(origin, sha))
    except EvidencePairError:
        pass
    else:
        raise AssertionError("invalid constituent evidence was accepted")

    print("live evidence pair verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health_artifact", nargs="?", type=Path)
    parser.add_argument("trust_artifact", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if args.health_artifact is None or args.trust_artifact is None:
        parser.error(
            "health and trust artifact paths are required unless --self-test is used"
        )

    try:
        health = json.loads(args.health_artifact.read_text(encoding="utf-8"))
        trust = json.loads(args.trust_artifact.read_text(encoding="utf-8"))
        result = verify_pair(
            health,
            trust,
            expected_git_sha=args.expected_git_sha,
        )
    except (
        OSError,
        json.JSONDecodeError,
        EvidencePairError,
    ) as exc:
        print(f"live evidence pair INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
