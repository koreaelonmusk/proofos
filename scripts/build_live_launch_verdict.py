"""Derive a conservative launch verdict from a sealed live evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_evidence_manifest import ManifestVerificationError, verify_manifest

SCHEMA_VERSION = 2
KIND = "proofos-live-launch-verdict"
HOLD = "HOLD"
READY_FOR_AUTHENTICATED_E2E = "READY_FOR_AUTHENTICATED_E2E"


class LaunchVerdictError(RuntimeError):
    pass


def _hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def derive_verdict(
    health: Any,
    trust: Any,
    manifest: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    try:
        sealed = verify_manifest(
            health,
            trust,
            manifest,
            expected_git_sha=expected_git_sha,
        )
    except ManifestVerificationError as exc:
        raise LaunchVerdictError(f"sealed evidence invalid: {exc}") from exc

    if not isinstance(trust, dict):
        raise LaunchVerdictError("trust evidence must be an object")

    trust_outcome = manifest.get("trust_outcome")
    health_outcome = manifest.get("health_outcome")
    bypass_attempted = trust.get("bypass_attempted")
    if not isinstance(bypass_attempted, bool):
        raise LaunchVerdictError("trust evidence bypass_attempted is invalid")

    status = HOLD
    issues: list[str] = []
    reasons: list[str]
    next_required: list[str]

    if trust_outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        reasons = ["deployment_protection_blocked_application_observation"]
        if bypass_attempted:
            reasons.append("automation_bypass_attempted_but_edge_still_blocked")
            next_required = ["repair_vercel_automation_bypass", "rerun_live_trust_observation"]
        else:
            reasons.append("automation_bypass_not_configured_for_workflow")
            next_required = ["configure_vercel_automation_bypass", "rerun_live_trust_observation"]
    elif trust_outcome == "READINESS_BLOCKED_AND_ANONYMOUS_DENIED":
        reasons = ["application_caller_auth_observed", "readiness_not_observed_through_deployment_edge"]
        next_required = ["observe_application_readiness", "rerun_live_trust_observation"]
    elif trust_outcome == "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED":
        readiness = trust.get("readiness")
        observation = readiness.get("observation") if isinstance(readiness, dict) else None
        raw = observation.get("issues") if isinstance(observation, dict) else None
        if not isinstance(raw, list) or not raw or any(not isinstance(x, str) for x in raw):
            raise LaunchVerdictError("not-ready evidence must contain readiness issues")
        issues = sorted(raw)
        reasons = ["collector_configuration_not_ready", *[f"readiness:{x}" for x in issues]]
        next_required = ["resolve_collector_readiness_issues", "rerun_live_trust_observation"]
    elif trust_outcome == "READY_AND_ANONYMOUS_DENIED":
        status = READY_FOR_AUTHENTICATED_E2E
        reasons = [
            "collector_readiness_observed",
            "anonymous_collection_denial_observed",
            "authenticated_end_to_end_collection_not_yet_proven",
        ]
        next_required = [
            "authenticated_collection_with_fresh_nonce",
            "signed_attestation_verification",
            "tamper_nonce_and_profile_rejection",
        ]
    else:
        raise LaunchVerdictError(f"unsupported trust outcome: {trust_outcome}")

    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "target_origin": sealed["target_origin"],
        "workflow_source_git_sha": sealed["workflow_source_git_sha"],
        "github_deployment_id": sealed["github_deployment_id"],
        "github_deployment_status_id": sealed["github_deployment_status_id"],
        "deployment_environment": sealed["deployment_environment"],
        "manifest_sha256": sealed["manifest_sha256"],
        "pair_sha256": sealed["pair_sha256"],
        "health_evidence_sha256": sealed["health_evidence_sha256"],
        "trust_evidence_sha256": sealed["trust_evidence_sha256"],
        "health_outcome": health_outcome,
        "trust_outcome": trust_outcome,
        "bypass_attempted": bypass_attempted,
        "readiness_issues": issues,
        "reasons": reasons,
        "next_required_evidence": next_required,
        "claim_boundary": [
            "derived only from an independently verified sealed deployment evidence bundle",
            "HOLD means the next launch property is unproven, not that the service is unhealthy",
            "READY_FOR_AUTHENTICATED_E2E is not production GO and does not prove authenticated collection",
        ],
    }
    return {**body, "verdict_sha256": _hash(body)}


def _self_test() -> None:
    from verify_live_evidence_pair import _health_sample, _trust_sample, build_manifest, verify_pair

    sha = "0123456789abcdef0123456789abcdef01234567"
    origin = "https://proofos-preview.vercel.app"
    health = _health_sample(origin, sha)
    trust = _trust_sample(origin, sha)
    manifest = build_manifest(verify_pair(health, trust, expected_git_sha=sha))
    verdict = derive_verdict(health, trust, manifest, expected_git_sha=sha)
    assert verdict["status"] == HOLD
    assert verdict["manifest_sha256"] == manifest["manifest_sha256"]
    print("live launch verdict builder self-test OK")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("health", nargs="?", type=Path)
    p.add_argument("trust", nargs="?", type=Path)
    p.add_argument("manifest", nargs="?", type=Path)
    p.add_argument("--expected-git-sha", default="")
    p.add_argument("--output", type=Path)
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        _self_test(); return 0
    if None in (a.health, a.trust, a.manifest, a.output):
        p.error("health, trust, manifest, and --output are required unless --self-test is used")
    try:
        verdict = derive_verdict(
            json.loads(a.health.read_text()),
            json.loads(a.trust.read_text()),
            json.loads(a.manifest.read_text()),
            expected_git_sha=a.expected_git_sha,
        )
    except (OSError, json.JSONDecodeError, LaunchVerdictError) as exc:
        print(f"live launch verdict FAILED: {exc}", file=sys.stderr); return 1
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n")
    print(json.dumps(verdict, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
