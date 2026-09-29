"""Derive a conservative launch verdict from verified live Vercel evidence.

This is not a deployment controller. It cannot make an unobserved property true.
Its job is to turn the independently verified health/trust pair into a stable
machine-readable next-gate decision without overstating what the evidence proves.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_evidence_pair import EvidencePairError, verify_pair

SCHEMA_VERSION = 1
KIND = "proofos-live-launch-verdict"
HOLD = "HOLD"
READY_FOR_AUTHENTICATED_E2E = "READY_FOR_AUTHENTICATED_E2E"


class LaunchVerdictError(RuntimeError):
    pass


def _canonical_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def derive_verdict(
    health_evidence: Any,
    trust_evidence: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    try:
        pair = verify_pair(
            health_evidence,
            trust_evidence,
            expected_git_sha=expected_git_sha,
        )
    except EvidencePairError as exc:
        raise LaunchVerdictError(f"evidence pair invalid: {exc}") from exc

    if not isinstance(trust_evidence, dict):
        raise LaunchVerdictError("trust evidence must be an object")

    trust_outcome = pair["trust_outcome"]
    bypass_attempted = trust_evidence.get("bypass_attempted")
    if not isinstance(bypass_attempted, bool):
        raise LaunchVerdictError("trust evidence bypass_attempted is invalid")

    status = HOLD
    reasons: list[str]
    next_required_evidence: list[str]
    readiness_issues: list[str] = []

    if trust_outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        reasons = ["deployment_protection_blocked_application_observation"]
        if bypass_attempted:
            reasons.append("automation_bypass_attempted_but_edge_still_blocked")
            next_required_evidence = [
                "repair_vercel_automation_bypass",
                "rerun_live_trust_observation",
            ]
        else:
            reasons.append("automation_bypass_not_configured_for_workflow")
            next_required_evidence = [
                "configure_vercel_automation_bypass",
                "rerun_live_trust_observation",
            ]
    elif trust_outcome == "READINESS_BLOCKED_AND_ANONYMOUS_DENIED":
        reasons = [
            "application_caller_auth_observed",
            "readiness_not_observed_through_deployment_edge",
        ]
        next_required_evidence = [
            "observe_application_readiness",
            "rerun_live_trust_observation",
        ]
    elif trust_outcome == "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED":
        readiness = trust_evidence.get("readiness")
        observation = readiness.get("observation") if isinstance(readiness, dict) else None
        issues = observation.get("issues") if isinstance(observation, dict) else None
        if not isinstance(issues, list) or any(not isinstance(item, str) for item in issues):
            raise LaunchVerdictError("not-ready trust evidence has invalid issue list")
        readiness_issues = sorted(issues)
        reasons = ["collector_configuration_not_ready"]
        reasons.extend(f"readiness:{issue}" for issue in readiness_issues)
        next_required_evidence = [
            "resolve_collector_readiness_issues",
            "rerun_live_trust_observation",
        ]
    elif trust_outcome == "READY_AND_ANONYMOUS_DENIED":
        status = READY_FOR_AUTHENTICATED_E2E
        reasons = [
            "collector_readiness_observed",
            "anonymous_collection_denial_observed",
            "authenticated_end_to_end_collection_not_yet_proven",
        ]
        next_required_evidence = [
            "authenticated_collection_with_fresh_nonce",
            "signed_attestation_verification",
            "tamper_nonce_and_profile_rejection",
        ]
    else:
        raise LaunchVerdictError(f"unsupported trust outcome: {trust_outcome}")

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "target_origin": pair["target_origin"],
        "workflow_source_git_sha": pair["workflow_source_git_sha"],
        "pair_sha256": pair["pair_sha256"],
        "health_evidence_sha256": pair["health_evidence_sha256"],
        "trust_evidence_sha256": pair["trust_evidence_sha256"],
        "health_outcome": pair["health_outcome"],
        "trust_outcome": trust_outcome,
        "bypass_attempted": bypass_attempted,
        "readiness_issues": readiness_issues,
        "reasons": reasons,
        "next_required_evidence": next_required_evidence,
        "claim_boundary": [
            "this verdict is derived only from independently verified live evidence",
            "HOLD does not mean the service is unhealthy; it means the next launch property is not proven",
            "READY_FOR_AUTHENTICATED_E2E is not production GO and does not prove a successful authenticated collection",
        ],
    }
    return {**unsigned, "verdict_sha256": _canonical_hash(unsigned)}


def _signed(value: dict[str, Any]) -> dict[str, Any]:
    digest = _canonical_hash(value)
    return {**value, "evidence_sha256": digest}


def _health_blocked(origin: str, sha: str) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 1,
            "kind": "vercel-live-smoke-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "health_url": f"{origin}/healthz",
            "http_status": 401,
            "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
            "bypass_attempted": False,
            "workflow_source_git_sha": sha,
            "claim_boundary": [
                "proves the deployment edge rejected the workflow request before application health was observed",
                "does not prove the collector is healthy or unhealthy",
                "does not expose or record the automation bypass secret",
            ],
        }
    )


def _trust_blocked(origin: str, sha: str, bypass_attempted: bool) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 1,
            "kind": "vercel-live-trust-surface-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "workflow_source_git_sha": sha,
            "bypass_attempted": bypass_attempted,
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
    origin = "https://proofos-preview.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"

    verdict = derive_verdict(
        _health_blocked(origin, sha),
        _trust_blocked(origin, sha, False),
        expected_git_sha=sha,
    )
    assert verdict["status"] == HOLD
    assert "automation_bypass_not_configured_for_workflow" in verdict["reasons"]
    assert len(verdict["verdict_sha256"]) == 64

    verdict = derive_verdict(
        _health_blocked(origin, sha),
        _trust_blocked(origin, sha, True),
        expected_git_sha=sha,
    )
    assert "automation_bypass_attempted_but_edge_still_blocked" in verdict["reasons"]

    print("live launch verdict self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health_artifact", nargs="?", type=Path)
    parser.add_argument("trust_artifact", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if args.health_artifact is None or args.trust_artifact is None or args.output is None:
        parser.error(
            "health artifact, trust artifact, and --output are required unless --self-test is used"
        )

    try:
        health = json.loads(args.health_artifact.read_text(encoding="utf-8"))
        trust = json.loads(args.trust_artifact.read_text(encoding="utf-8"))
        verdict = derive_verdict(
            health,
            trust,
            expected_git_sha=args.expected_git_sha,
        )
    except (
        OSError,
        json.JSONDecodeError,
        LaunchVerdictError,
    ) as exc:
        print(f"live launch verdict FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(verdict, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
