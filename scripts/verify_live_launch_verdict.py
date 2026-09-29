"""Independently verify a persisted ProofOS live launch verdict."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
KIND = "proofos-live-launch-verdict"
STATUSES = {"HOLD", "READY_FOR_AUTHENTICATED_E2E"}
TOP_LEVEL_KEYS = {
    "schema_version",
    "kind",
    "status",
    "target_origin",
    "workflow_source_git_sha",
    "pair_sha256",
    "health_evidence_sha256",
    "trust_evidence_sha256",
    "health_outcome",
    "trust_outcome",
    "bypass_attempted",
    "readiness_issues",
    "reasons",
    "next_required_evidence",
    "claim_boundary",
    "verdict_sha256",
}


class VerdictVerificationError(RuntimeError):
    pass


def _hash_without_digest(verdict: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in verdict.items() if key != "verdict_sha256"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise VerdictVerificationError(f"{field} must be a SHA-256 hex digest")
    value = value.lower()
    if any(ch not in "0123456789abcdef" for ch in value):
        raise VerdictVerificationError(f"{field} must be a SHA-256 hex digest")
    return value


def _git_sha(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 40:
        raise VerdictVerificationError("workflow_source_git_sha must be a full git SHA")
    value = value.lower()
    if any(ch not in "0123456789abcdef" for ch in value):
        raise VerdictVerificationError("workflow_source_git_sha must be a full git SHA")
    return value


def _origin(value: Any) -> str:
    if not isinstance(value, str):
        raise VerdictVerificationError("target_origin must be a string")
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
        raise VerdictVerificationError("target_origin must be an exact Vercel origin")
    return f"https://{parts.hostname.lower()}"


def verify_verdict(verdict: Any) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        raise VerdictVerificationError("verdict must be a JSON object")
    if set(verdict) != TOP_LEVEL_KEYS:
        raise VerdictVerificationError("verdict schema drifted")
    if verdict.get("schema_version") != SCHEMA_VERSION or verdict.get("kind") != KIND:
        raise VerdictVerificationError("unsupported verdict schema")

    digest = _sha256(verdict.get("verdict_sha256"), "verdict_sha256")
    if digest != _hash_without_digest(verdict):
        raise VerdictVerificationError("verdict SHA-256 mismatch")

    status = verdict.get("status")
    if status not in STATUSES:
        raise VerdictVerificationError("unsupported launch verdict status")

    origin = _origin(verdict.get("target_origin"))
    git_sha = _git_sha(verdict.get("workflow_source_git_sha"))
    pair_sha = _sha256(verdict.get("pair_sha256"), "pair_sha256")
    health_sha = _sha256(verdict.get("health_evidence_sha256"), "health_evidence_sha256")
    trust_sha = _sha256(verdict.get("trust_evidence_sha256"), "trust_evidence_sha256")

    if not isinstance(verdict.get("bypass_attempted"), bool):
        raise VerdictVerificationError("bypass_attempted must be boolean")

    for field in ("readiness_issues", "reasons", "next_required_evidence", "claim_boundary"):
        value = verdict.get(field)
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            raise VerdictVerificationError(f"{field} must contain non-empty strings")

    trust_outcome = verdict.get("trust_outcome")
    reasons = verdict["reasons"]
    next_required = verdict["next_required_evidence"]
    readiness_issues = verdict["readiness_issues"]
    bypass_attempted = verdict["bypass_attempted"]

    expected_status: str
    expected_reasons: list[str]
    expected_next: list[str]

    if trust_outcome == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        expected_status = "HOLD"
        expected_reasons = ["deployment_protection_blocked_application_observation"]
        if bypass_attempted:
            expected_reasons.append("automation_bypass_attempted_but_edge_still_blocked")
            expected_next = [
                "repair_vercel_automation_bypass",
                "rerun_live_trust_observation",
            ]
        else:
            expected_reasons.append("automation_bypass_not_configured_for_workflow")
            expected_next = [
                "configure_vercel_automation_bypass",
                "rerun_live_trust_observation",
            ]
        if readiness_issues:
            raise VerdictVerificationError(
                "edge-blocked verdict cannot claim application readiness issues"
            )
    elif trust_outcome == "READINESS_BLOCKED_AND_ANONYMOUS_DENIED":
        expected_status = "HOLD"
        expected_reasons = [
            "application_caller_auth_observed",
            "readiness_not_observed_through_deployment_edge",
        ]
        expected_next = [
            "observe_application_readiness",
            "rerun_live_trust_observation",
        ]
        if readiness_issues:
            raise VerdictVerificationError(
                "readiness-blocked verdict cannot claim unobserved readiness issues"
            )
    elif trust_outcome == "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED":
        expected_status = "HOLD"
        if not readiness_issues:
            raise VerdictVerificationError(
                "configuration-not-ready verdict must carry readiness issues"
            )
        expected_reasons = ["collector_configuration_not_ready"]
        expected_reasons.extend(f"readiness:{issue}" for issue in readiness_issues)
        expected_next = [
            "resolve_collector_readiness_issues",
            "rerun_live_trust_observation",
        ]
    elif trust_outcome == "READY_AND_ANONYMOUS_DENIED":
        expected_status = "READY_FOR_AUTHENTICATED_E2E"
        if readiness_issues:
            raise VerdictVerificationError("ready verdict cannot carry readiness issues")
        expected_reasons = [
            "collector_readiness_observed",
            "anonymous_collection_denial_observed",
            "authenticated_end_to_end_collection_not_yet_proven",
        ]
        expected_next = [
            "authenticated_collection_with_fresh_nonce",
            "signed_attestation_verification",
            "tamper_nonce_and_profile_rejection",
        ]
    else:
        raise VerdictVerificationError("unsupported trust outcome")

    if status != expected_status:
        raise VerdictVerificationError(
            "verdict status does not match independently derived trust state"
        )
    if reasons != expected_reasons:
        raise VerdictVerificationError(
            "verdict reasons do not match independently derived trust state"
        )
    if next_required != expected_next:
        raise VerdictVerificationError(
            "next required evidence does not match independently derived trust state"
        )

    if not any("not production GO" in item for item in verdict["claim_boundary"]):
        raise VerdictVerificationError("claim boundary does not prevent production overclaim")

    return {
        "valid": True,
        "status": status,
        "target_origin": origin,
        "workflow_source_git_sha": git_sha,
        "pair_sha256": pair_sha,
        "health_evidence_sha256": health_sha,
        "trust_evidence_sha256": trust_sha,
        "verdict_sha256": digest,
        "reasons": reasons,
    }


def _self_test() -> None:
    unsigned = {
        "schema_version": 1,
        "kind": KIND,
        "status": "HOLD",
        "target_origin": "https://proofos-preview.vercel.app",
        "workflow_source_git_sha": "0123456789abcdef0123456789abcdef01234567",
        "pair_sha256": "a" * 64,
        "health_evidence_sha256": "b" * 64,
        "trust_evidence_sha256": "c" * 64,
        "health_outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
        "trust_outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
        "bypass_attempted": False,
        "readiness_issues": [],
        "reasons": [
            "deployment_protection_blocked_application_observation",
            "automation_bypass_not_configured_for_workflow",
        ],
        "next_required_evidence": [
            "configure_vercel_automation_bypass",
            "rerun_live_trust_observation",
        ],
        "claim_boundary": [
            "this verdict is derived only from independently verified live evidence",
            "HOLD does not mean the service is unhealthy; it means the next launch property is not proven",
            "READY_FOR_AUTHENTICATED_E2E is not production GO and does not prove a successful authenticated collection",
        ],
    }
    verdict = {
        **unsigned,
        "verdict_sha256": hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    assert verify_verdict(verdict)["valid"]

    tampered = json.loads(json.dumps(verdict))
    tampered["status"] = "READY_FOR_AUTHENTICATED_E2E"
    try:
        verify_verdict(tampered)
    except VerdictVerificationError:
        pass
    else:
        raise AssertionError("tampered launch verdict was accepted")

    semantic_forgery = json.loads(json.dumps(unsigned))
    semantic_forgery["reasons"] = ["looks_green_but_is_not_proven"]
    semantic_forgery["verdict_sha256"] = hashlib.sha256(
        json.dumps(
            semantic_forgery,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    # Recompute over the unsigned body correctly so this test proves the
    # verifier rejects bad semantics even when the attacker can re-hash JSON.
    semantic_unsigned = {
        key: value
        for key, value in semantic_forgery.items()
        if key != "verdict_sha256"
    }
    semantic_forgery["verdict_sha256"] = hashlib.sha256(
        json.dumps(
            semantic_unsigned,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    try:
        verify_verdict(semantic_forgery)
    except VerdictVerificationError:
        pass
    else:
        raise AssertionError("re-hashed semantic forgery was accepted")

    ready_unsigned = {
        **unsigned,
        "status": "READY_FOR_AUTHENTICATED_E2E",
        "health_outcome": "OBSERVED_HEALTH",
        "trust_outcome": "READY_AND_ANONYMOUS_DENIED",
        "bypass_attempted": True,
        "readiness_issues": [],
        "reasons": [
            "collector_readiness_observed",
            "anonymous_collection_denial_observed",
            "authenticated_end_to_end_collection_not_yet_proven",
        ],
        "next_required_evidence": [
            "authenticated_collection_with_fresh_nonce",
            "signed_attestation_verification",
            "tamper_nonce_and_profile_rejection",
        ],
    }
    ready_verdict = {
        **ready_unsigned,
        "verdict_sha256": hashlib.sha256(
            json.dumps(
                ready_unsigned,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    }
    assert verify_verdict(ready_verdict)["status"] == "READY_FOR_AUTHENTICATED_E2E"

    print("live launch verdict verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("verdict", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if args.verdict is None:
        parser.error("verdict path is required unless --self-test is used")

    try:
        value = json.loads(args.verdict.read_text(encoding="utf-8"))
        result = verify_verdict(value)
    except (OSError, json.JSONDecodeError, VerdictVerificationError) as exc:
        print(f"live launch verdict INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
