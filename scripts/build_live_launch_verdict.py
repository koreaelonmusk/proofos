"""Derive a conservative machine launch verdict from a verified live evidence bundle.

This module is not a deployment controller and cannot turn missing evidence into
authority. It consumes the independently verifiable health/trust/manifest bundle
and emits only the next evidence gate that is justified by what was observed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_evidence_manifest import (
    ManifestVerificationError,
    verify_manifest,
)
from verify_live_evidence_pair import build_manifest, verify_pair

SCHEMA_VERSION = 2
KIND = "proofos-live-launch-verdict"
HOLD = "HOLD"
READY_FOR_AUTHENTICATED_E2E = "READY_FOR_AUTHENTICATED_E2E"


class LaunchVerdictError(RuntimeError):
    pass


def _canonical_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _derive_semantics(
    *,
    health_outcome: str,
    trust_outcome: str,
    bypass_attempted: bool,
    readiness_issues: list[str],
) -> tuple[str, list[str], list[str]]:
    if trust_outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        reasons = ["deployment_protection_blocked_application_observation"]
        if bypass_attempted:
            reasons.append("automation_bypass_attempted_but_edge_still_blocked")
            next_required = [
                "repair_vercel_automation_bypass",
                "rerun_live_evidence_observation",
            ]
        else:
            reasons.append("automation_bypass_not_configured_for_workflow")
            next_required = [
                "configure_vercel_automation_bypass",
                "rerun_live_evidence_observation",
            ]
        return HOLD, reasons, next_required

    if trust_outcome == "READINESS_BLOCKED_AND_ANONYMOUS_DENIED":
        return (
            HOLD,
            [
                "application_caller_auth_observed",
                "readiness_not_observed_through_deployment_edge",
            ],
            [
                "observe_application_readiness",
                "rerun_live_evidence_observation",
            ],
        )

    if trust_outcome == "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED":
        if not readiness_issues:
            raise LaunchVerdictError(
                "configuration-not-ready evidence must carry readiness issues"
            )
        reasons = ["collector_configuration_not_ready"]
        reasons.extend(f"readiness:{issue}" for issue in readiness_issues)
        return (
            HOLD,
            reasons,
            [
                "resolve_collector_readiness_issues",
                "rerun_live_evidence_observation",
            ],
        )

    if trust_outcome == "READY_AND_ANONYMOUS_DENIED":
        if health_outcome != "OBSERVED_HEALTH":
            return (
                HOLD,
                [
                    "collector_readiness_observed",
                    "anonymous_collection_denial_observed",
                    "application_health_not_observed",
                ],
                [
                    "observe_application_health",
                    "rerun_live_evidence_observation",
                ],
            )
        return (
            READY_FOR_AUTHENTICATED_E2E,
            [
                "application_health_observed",
                "collector_readiness_observed",
                "anonymous_collection_denial_observed",
                "authenticated_end_to_end_collection_not_yet_proven",
            ],
            [
                "authenticated_collection_with_fresh_nonce",
                "signed_attestation_verification",
                "tamper_nonce_and_profile_rejection",
            ],
        )

    raise LaunchVerdictError(f"unsupported trust outcome: {trust_outcome}")


def derive_verdict(
    health_evidence: Any,
    trust_evidence: Any,
    manifest: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    try:
        verified = verify_manifest(
            health_evidence,
            trust_evidence,
            manifest,
            expected_git_sha=expected_git_sha,
        )
    except ManifestVerificationError as exc:
        raise LaunchVerdictError(f"evidence manifest invalid: {exc}") from exc

    if not isinstance(manifest, dict):
        raise LaunchVerdictError("manifest must be an object")
    if not isinstance(trust_evidence, dict):
        raise LaunchVerdictError("trust evidence must be an object")

    health_outcome = manifest.get("health_outcome")
    trust_outcome = manifest.get("trust_outcome")
    if not isinstance(health_outcome, str) or not isinstance(trust_outcome, str):
        raise LaunchVerdictError("manifest outcomes are missing")

    bypass_attempted = trust_evidence.get("bypass_attempted")
    if not isinstance(bypass_attempted, bool):
        raise LaunchVerdictError("trust evidence bypass_attempted is invalid")

    readiness_issues: list[str] = []
    if trust_outcome == "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED":
        readiness = trust_evidence.get("readiness")
        observation = readiness.get("observation") if isinstance(readiness, dict) else None
        issues = observation.get("issues") if isinstance(observation, dict) else None
        if not isinstance(issues, list) or any(
            not isinstance(item, str) or not item for item in issues
        ):
            raise LaunchVerdictError("not-ready trust evidence has invalid issue list")
        readiness_issues = sorted(issues)

    status, reasons, next_required_evidence = _derive_semantics(
        health_outcome=health_outcome,
        trust_outcome=trust_outcome,
        bypass_attempted=bypass_attempted,
        readiness_issues=readiness_issues,
    )

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "target_origin": verified["target_origin"],
        "workflow_source_git_sha": verified["workflow_source_git_sha"],
        "github_deployment_id": verified["github_deployment_id"],
        "github_deployment_status_id": verified["github_deployment_status_id"],
        "deployment_environment": verified["deployment_environment"],
        "manifest_sha256": verified["manifest_sha256"],
        "pair_sha256": verified["pair_sha256"],
        "health_evidence_sha256": verified["health_evidence_sha256"],
        "trust_evidence_sha256": verified["trust_evidence_sha256"],
        "health_outcome": health_outcome,
        "trust_outcome": trust_outcome,
        "bypass_attempted": bypass_attempted,
        "readiness_issues": readiness_issues,
        "reasons": reasons,
        "next_required_evidence": next_required_evidence,
        "claim_boundary": [
            "this verdict is derived only from an independently verified deployment evidence bundle",
            "HOLD does not mean the service is unhealthy; it means the next launch property is not proven",
            "READY_FOR_AUTHENTICATED_E2E is not production GO and authorizes only the next authenticated evidence step",
        ],
    }
    return {**unsigned, "verdict_sha256": _canonical_hash(unsigned)}


def _signed(value: dict[str, Any]) -> dict[str, Any]:
    return {**value, "evidence_sha256": _canonical_hash(value)}


def _event(origin: str, sha: str) -> dict[str, Any]:
    return {
        "github_deployment_id": 123,
        "github_deployment_status_id": 456,
        "environment": "preview",
        "environment_url": origin,
        "source_git_sha": sha,
    }


def _blocked_health(origin: str, sha: str) -> dict[str, Any]:
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
            "deployment_event": _event(origin, sha),
            "claim_boundary": [
                "proves the deployment edge rejected the workflow request before application health was observed",
                "does not prove the collector is healthy or unhealthy",
                "does not expose or record the automation bypass secret",
            ],
        }
    )


def _blocked_trust(origin: str, sha: str, *, bypass_attempted: bool) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 2,
            "kind": "vercel-live-trust-surface-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "workflow_source_git_sha": sha,
            "deployment_event": _event(origin, sha),
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


def _observed_health(origin: str, sha: str) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 2,
            "kind": "vercel-live-smoke-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "health_url": f"{origin}/healthz",
            "http_status": 200,
            "outcome": "OBSERVED_HEALTH",
            "bypass_attempted": True,
            "workflow_source_git_sha": sha,
            "deployment_event": _event(origin, sha),
            "observation": {
                "status": "ok",
                "service": "proofos-collector",
                "runtime": {
                    "platform": "vercel",
                    "environment": "preview",
                    "deployment_id": "dpl_test",
                    "region": "icn1",
                    "git_sha": sha,
                    "url": origin,
                },
            },
            "claim_boundary": [
                "proves the HTTPS health endpoint answered the expected public contract",
                "records only allowlisted runtime provenance exposed by the collector",
                "does not prove IAM policy, readiness, signing-key durability, or an end-to-end VERIFIED execution",
            ],
        }
    )


def _ready_trust(origin: str, sha: str) -> dict[str, Any]:
    return _signed(
        {
            "schema_version": 2,
            "kind": "vercel-live-trust-surface-observation",
            "observed_at": "2026-09-30T00:00:00+00:00",
            "observer": "github-actions-http",
            "target_origin": origin,
            "workflow_source_git_sha": sha,
            "deployment_event": _event(origin, sha),
            "bypass_attempted": True,
            "outcome": "READY_AND_ANONYMOUS_DENIED",
            "readiness": {
                "outcome": "READY",
                "http_status": 200,
                "observation": {
                    "status": "ready",
                    "service": "proofos-collector",
                    "issues": [],
                },
            },
            "anonymous_collect": {
                "outcome": "ANONYMOUS_COLLECTION_DENIED",
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


def _manifest(health: dict[str, Any], trust: dict[str, Any], sha: str) -> dict[str, Any]:
    return build_manifest(verify_pair(health, trust, expected_git_sha=sha))


def _self_test() -> None:
    origin = "https://proofos-preview.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"

    health = _blocked_health(origin, sha)
    trust = _blocked_trust(origin, sha, bypass_attempted=False)
    verdict = derive_verdict(
        health,
        trust,
        _manifest(health, trust, sha),
        expected_git_sha=sha,
    )
    assert verdict["status"] == HOLD
    assert "automation_bypass_not_configured_for_workflow" in verdict["reasons"]
    assert len(verdict["manifest_sha256"]) == 64

    health = _observed_health(origin, sha)
    trust = _ready_trust(origin, sha)
    verdict = derive_verdict(
        health,
        trust,
        _manifest(health, trust, sha),
        expected_git_sha=sha,
    )
    assert verdict["status"] == READY_FOR_AUTHENTICATED_E2E
    assert verdict["next_required_evidence"][0] == "authenticated_collection_with_fresh_nonce"

    # Readiness alone cannot advance the gate if health was not directly observed.
    health = _blocked_health(origin, sha)
    trust = _ready_trust(origin, sha)
    verdict = derive_verdict(
        health,
        trust,
        _manifest(health, trust, sha),
        expected_git_sha=sha,
    )
    assert verdict["status"] == HOLD
    assert "application_health_not_observed" in verdict["reasons"]

    print("live launch verdict v2 self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health_artifact", nargs="?", type=Path)
    parser.add_argument("trust_artifact", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if (
        args.health_artifact is None
        or args.trust_artifact is None
        or args.manifest is None
        or args.output is None
    ):
        parser.error(
            "health artifact, trust artifact, manifest, and --output are required unless --self-test is used"
        )

    try:
        health = json.loads(args.health_artifact.read_text(encoding="utf-8"))
        trust = json.loads(args.trust_artifact.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        verdict = derive_verdict(
            health,
            trust,
            manifest,
            expected_git_sha=args.expected_git_sha,
        )
    except (OSError, json.JSONDecodeError, LaunchVerdictError) as exc:
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
