"""Build Trusted Promotion from an admitted workflow-run Trusted Source path."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_trusted_promotion_proof import BLOCKED, _ALLOWED_REASON_SETS
from verify_live_launch_verdict import VerdictVerificationError, verify_verdict
from verify_vercel_provider_admission import (
    ProviderAdmissionVerificationError,
    verify_admission,
)

SCHEMA_VERSION = 1
KIND = "proofos-followup-trusted-promotion-proof"
STATUS = "AUTHORIZED_FOR_AUTHENTICATED_E2E"
ADMITTED = "ADMITTED_FOR_TRUSTED_PROMOTION"


class FollowupTrustedPromotionError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def derive_followup_promotion(
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    original_trusted_source: Any,
    followup_trusted_source: Any,
    diagnosis: Any,
    admission: Any,
    *,
    expected_git_sha: str,
    source_run_id: int,
    followup_run_id: int,
) -> dict[str, Any]:
    try:
        launch = verify_verdict(
            health,
            trust,
            manifest,
            verdict,
            expected_git_sha=expected_git_sha,
        )
    except VerdictVerificationError as exc:
        raise FollowupTrustedPromotionError(
            f"public launch evidence invalid: {exc}"
        ) from exc

    try:
        admitted = verify_admission(
            original_trusted_source,
            followup_trusted_source,
            diagnosis,
            admission,
            expected_source_run_id=source_run_id,
            expected_followup_run_id=followup_run_id,
        )
    except ProviderAdmissionVerificationError as exc:
        raise FollowupTrustedPromotionError(
            f"provider admission invalid: {exc}"
        ) from exc

    if launch["status"] != "HOLD":
        raise FollowupTrustedPromotionError(
            "follow-up promotion is only defined for public HOLD"
        )
    if verdict.get("health_outcome") != BLOCKED or verdict.get("trust_outcome") != BLOCKED:
        raise FollowupTrustedPromotionError(
            "public HOLD must be caused by deployment protection blocking both observations"
        )
    if verdict.get("readiness_issues") != []:
        raise FollowupTrustedPromotionError(
            "public HOLD carries unrelated readiness issues"
        )
    reasons = verdict.get("reasons")
    if not isinstance(reasons, list) or frozenset(reasons) not in _ALLOWED_REASON_SETS:
        raise FollowupTrustedPromotionError(
            "public HOLD contains reasons outside the deployment-protection boundary"
        )

    if launch["deployment_environment"] != "production":
        raise FollowupTrustedPromotionError("follow-up promotion is production-only")
    if admitted["status"] != ADMITTED:
        raise FollowupTrustedPromotionError(
            "provider admission did not admit follow-up evidence for promotion"
        )
    if not isinstance(admission, dict):
        raise FollowupTrustedPromotionError("provider admission must be an object")

    if admission.get("target_origin") != launch["target_origin"]:
        raise FollowupTrustedPromotionError(
            "provider admission targets a different origin"
        )
    if admission.get("workflow_source_git_sha") != launch["workflow_source_git_sha"]:
        raise FollowupTrustedPromotionError(
            "provider admission binds to a different Git SHA"
        )
    if admission.get("github_deployment_id") != launch["github_deployment_id"]:
        raise FollowupTrustedPromotionError(
            "provider admission binds to a different deployment"
        )
    if (
        admission.get("github_deployment_status_id")
        != launch["github_deployment_status_id"]
    ):
        raise FollowupTrustedPromotionError(
            "provider admission binds to a different deployment status"
        )

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": STATUS,
        "target_origin": launch["target_origin"],
        "workflow_source_git_sha": launch["workflow_source_git_sha"],
        "github_deployment_id": launch["github_deployment_id"],
        "github_deployment_status_id": launch["github_deployment_status_id"],
        "deployment_environment": launch["deployment_environment"],
        "source_run_id": source_run_id,
        "followup_run_id": followup_run_id,
        "manifest_sha256": launch["manifest_sha256"],
        "verdict_sha256": launch["verdict_sha256"],
        "provider_admission_sha256": admitted["admission_sha256"],
        "followup_evidence_sha256": admitted["followup_evidence_sha256"],
        "public_status": launch["status"],
        "public_reasons": reasons,
        "authorization_scope": "authenticated_e2e_evidence_only",
        "next_required_evidence": [
            "fresh_dual_identity_authenticated_collection",
            "signed_attestation_verification",
            "tamper_nonce_and_profile_rejection",
        ],
        "claim_boundary": [
            "does not rewrite or upgrade the public observer launch verdict",
            "requires an independently verified Provider Admission Contract",
            "binds source and follow-up workflow runs into the promotion proof",
            "authorizes only the next authenticated E2E evidence step",
            "does not prove authenticated collection or production GO",
        ],
    }
    return {**unsigned, "promotion_sha256": _digest(unsigned)}


def _self_test() -> None:
    from build_live_launch_verdict import (
        _blocked_health,
        _blocked_trust,
        _manifest,
        derive_verdict,
    )
    from build_vercel_provider_admission import _self_test as admission_self_test

    admission_self_test()

    # Full positive fixture is exercised by the provider-admission self-test and
    # workflow integration; keep this self-test focused on public-HOLD semantics.
    origin = "https://proofos-production.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"
    health = _blocked_health(origin, sha)
    trust = _blocked_trust(origin, sha, bypass_attempted=False)
    for evidence in (health, trust):
        evidence["deployment_event"]["environment"] = "production"
        evidence["evidence_sha256"] = _digest(
            {k: v for k, v in evidence.items() if k != "evidence_sha256"}
        )
    verdict = derive_verdict(
        health,
        trust,
        _manifest(health, trust, sha),
        expected_git_sha=sha,
    )
    assert verdict["status"] == "HOLD"
    print("follow-up trusted promotion public-HOLD self-test OK")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in (
        "health",
        "trust",
        "manifest",
        "verdict",
        "original_trusted_source",
        "followup_trusted_source",
        "diagnosis",
        "admission",
    ):
        parser.add_argument(name, nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    inputs = [
        args.health,
        args.trust,
        args.manifest,
        args.verdict,
        args.original_trusted_source,
        args.followup_trusted_source,
        args.diagnosis,
        args.admission,
        args.output,
    ]
    if any(item is None for item in inputs):
        parser.error("eight evidence inputs and --output are required")

    try:
        proof = derive_followup_promotion(
            _load(args.health),
            _load(args.trust),
            _load(args.manifest),
            _load(args.verdict),
            _load(args.original_trusted_source),
            _load(args.followup_trusted_source),
            _load(args.diagnosis),
            _load(args.admission),
            expected_git_sha=args.expected_git_sha,
            source_run_id=args.source_run_id,
            followup_run_id=args.followup_run_id,
        )
    except (OSError, json.JSONDecodeError, FollowupTrustedPromotionError) as exc:
        print(f"follow-up trusted promotion FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(proof, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
