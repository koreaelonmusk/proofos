"""Independently verify a persisted ProofOS live launch verdict v2.

The verifier does not trust the verdict producer. It reloads the constituent
health, trust, and manifest artifacts, independently re-derives the expected
verdict, and requires byte-level semantic equality apart from JSON formatting.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_live_launch_verdict import (
    KIND,
    SCHEMA_VERSION,
    LaunchVerdictError,
    derive_verdict,
)

EXPECTED_KEYS = {
    "schema_version",
    "kind",
    "status",
    "target_origin",
    "workflow_source_git_sha",
    "github_deployment_id",
    "github_deployment_status_id",
    "deployment_environment",
    "manifest_sha256",
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


def _digest_without_verdict_hash(verdict: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in verdict.items() if key != "verdict_sha256"
    }
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_verdict(
    health_evidence: Any,
    trust_evidence: Any,
    manifest: Any,
    verdict: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        raise VerdictVerificationError("verdict must be a JSON object")
    if set(verdict) != EXPECTED_KEYS:
        raise VerdictVerificationError("verdict schema drifted")
    if verdict.get("schema_version") != SCHEMA_VERSION:
        raise VerdictVerificationError("unsupported verdict schema version")
    if verdict.get("kind") != KIND:
        raise VerdictVerificationError("unexpected verdict kind")

    digest = verdict.get("verdict_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest.lower())
    ):
        raise VerdictVerificationError("verdict SHA-256 is malformed")
    if digest.lower() != _digest_without_verdict_hash(verdict):
        raise VerdictVerificationError("verdict SHA-256 mismatch")

    try:
        expected = derive_verdict(
            health_evidence,
            trust_evidence,
            manifest,
            expected_git_sha=expected_git_sha,
        )
    except LaunchVerdictError as exc:
        raise VerdictVerificationError(
            f"constituent evidence bundle is invalid: {exc}"
        ) from exc

    if verdict != expected:
        raise VerdictVerificationError(
            "persisted verdict does not exactly match independently re-derived verdict"
        )

    return {
        "valid": True,
        "status": verdict["status"],
        "verdict_sha256": digest.lower(),
        "manifest_sha256": verdict["manifest_sha256"],
        "pair_sha256": verdict["pair_sha256"],
        "health_evidence_sha256": verdict["health_evidence_sha256"],
        "trust_evidence_sha256": verdict["trust_evidence_sha256"],
        "github_deployment_id": verdict["github_deployment_id"],
        "github_deployment_status_id": verdict["github_deployment_status_id"],
        "deployment_environment": verdict["deployment_environment"],
        "workflow_source_git_sha": verdict["workflow_source_git_sha"],
        "target_origin": verdict["target_origin"],
        "reasons": verdict["reasons"],
        "next_required_evidence": verdict["next_required_evidence"],
    }


def _self_test() -> None:
    from build_live_launch_verdict import (
        _blocked_health,
        _blocked_trust,
        _manifest,
        _observed_health,
        _ready_trust,
    )

    origin = "https://proofos-preview.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"

    health = _blocked_health(origin, sha)
    trust = _blocked_trust(origin, sha, bypass_attempted=False)
    manifest = _manifest(health, trust, sha)
    verdict = derive_verdict(
        health,
        trust,
        manifest,
        expected_git_sha=sha,
    )
    assert verify_verdict(
        health,
        trust,
        manifest,
        verdict,
        expected_git_sha=sha,
    )["status"] == "HOLD"

    health = _observed_health(origin, sha)
    trust = _ready_trust(origin, sha)
    manifest = _manifest(health, trust, sha)
    verdict = derive_verdict(
        health,
        trust,
        manifest,
        expected_git_sha=sha,
    )
    assert verify_verdict(
        health,
        trust,
        manifest,
        verdict,
        expected_git_sha=sha,
    )["status"] == "READY_FOR_AUTHENTICATED_E2E"

    tampered = json.loads(json.dumps(verdict))
    tampered["reasons"] = ["looks_green_but_is_not_proven"]
    unsigned = {
        key: value for key, value in tampered.items() if key != "verdict_sha256"
    }
    tampered["verdict_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        verify_verdict(
            health,
            trust,
            manifest,
            tampered,
            expected_git_sha=sha,
        )
    except VerdictVerificationError:
        pass
    else:
        raise AssertionError("re-hashed semantic forgery was accepted")

    print("live launch verdict v2 verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health_artifact", nargs="?", type=Path)
    parser.add_argument("trust_artifact", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("verdict", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if (
        args.health_artifact is None
        or args.trust_artifact is None
        or args.manifest is None
        or args.verdict is None
    ):
        parser.error(
            "health artifact, trust artifact, manifest, and verdict are required unless --self-test is used"
        )

    try:
        health = json.loads(args.health_artifact.read_text(encoding="utf-8"))
        trust = json.loads(args.trust_artifact.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        verdict = json.loads(args.verdict.read_text(encoding="utf-8"))
        result = verify_verdict(
            health,
            trust,
            manifest,
            verdict,
            expected_git_sha=args.expected_git_sha,
        )
    except (
        OSError,
        json.JSONDecodeError,
        VerdictVerificationError,
    ) as exc:
        print(f"live launch verdict INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
