"""Independently verify a persisted follow-up Trusted Promotion Proof."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_followup_trusted_promotion import (
    KIND,
    SCHEMA_VERSION,
    STATUS,
    FollowupTrustedPromotionError,
    derive_followup_promotion,
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
    "source_run_id",
    "followup_run_id",
    "manifest_sha256",
    "verdict_sha256",
    "provider_admission_sha256",
    "followup_evidence_sha256",
    "public_status",
    "public_reasons",
    "authorization_scope",
    "next_required_evidence",
    "claim_boundary",
    "promotion_sha256",
}


class FollowupTrustedPromotionVerificationError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in value.items() if k != "promotion_sha256"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_followup_promotion(
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    original_trusted_source: Any,
    followup_trusted_source: Any,
    diagnosis: Any,
    admission: Any,
    promotion: Any,
    *,
    expected_git_sha: str,
    expected_source_run_id: int,
    expected_followup_run_id: int,
) -> dict[str, Any]:
    if not isinstance(promotion, dict) or set(promotion) != EXPECTED_KEYS:
        raise FollowupTrustedPromotionVerificationError(
            "follow-up promotion schema drifted"
        )
    if promotion.get("schema_version") != SCHEMA_VERSION:
        raise FollowupTrustedPromotionVerificationError(
            "unsupported follow-up promotion schema"
        )
    if promotion.get("kind") != KIND or promotion.get("status") != STATUS:
        raise FollowupTrustedPromotionVerificationError(
            "follow-up promotion identity is invalid"
        )
    if promotion.get("source_run_id") != expected_source_run_id:
        raise FollowupTrustedPromotionVerificationError(
            "follow-up promotion binds a different source run"
        )
    if promotion.get("followup_run_id") != expected_followup_run_id:
        raise FollowupTrustedPromotionVerificationError(
            "follow-up promotion binds a different follow-up run"
        )
    if promotion.get("promotion_sha256") != _digest(promotion):
        raise FollowupTrustedPromotionVerificationError(
            "follow-up promotion SHA-256 mismatch"
        )

    try:
        expected = derive_followup_promotion(
            health,
            trust,
            manifest,
            verdict,
            original_trusted_source,
            followup_trusted_source,
            diagnosis,
            admission,
            expected_git_sha=expected_git_sha,
            source_run_id=expected_source_run_id,
            followup_run_id=expected_followup_run_id,
        )
    except FollowupTrustedPromotionError as exc:
        raise FollowupTrustedPromotionVerificationError(
            f"follow-up promotion constituents invalid: {exc}"
        ) from exc

    if promotion != expected:
        raise FollowupTrustedPromotionVerificationError(
            "persisted follow-up promotion differs from independent re-derivation"
        )

    return {
        "valid": True,
        "status": promotion["status"],
        "target_origin": promotion["target_origin"],
        "workflow_source_git_sha": promotion["workflow_source_git_sha"],
        "source_run_id": promotion["source_run_id"],
        "followup_run_id": promotion["followup_run_id"],
        "promotion_sha256": promotion["promotion_sha256"],
        "provider_admission_sha256": promotion["provider_admission_sha256"],
    }


def _self_test() -> None:
    from build_followup_trusted_promotion import _fixture

    (
        health,
        trust,
        manifest,
        verdict,
        original,
        followup,
        diagnosis,
        admission,
        sha,
        source_run_id,
        followup_run_id,
    ) = _fixture()
    promotion = derive_followup_promotion(
        health,
        trust,
        manifest,
        verdict,
        original,
        followup,
        diagnosis,
        admission,
        expected_git_sha=sha,
        source_run_id=source_run_id,
        followup_run_id=followup_run_id,
    )
    result = verify_followup_promotion(
        health,
        trust,
        manifest,
        verdict,
        original,
        followup,
        diagnosis,
        admission,
        promotion,
        expected_git_sha=sha,
        expected_source_run_id=source_run_id,
        expected_followup_run_id=followup_run_id,
    )
    assert result["valid"] is True
    assert result["status"] == STATUS
    assert result["provider_admission_sha256"] == admission["admission_sha256"]
    print("follow-up trusted promotion verifier self-test OK")


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
        "promotion",
    ):
        parser.add_argument(name, nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
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
        args.promotion,
    ]
    if any(item is None for item in inputs):
        parser.error("nine evidence files are required")

    try:
        result = verify_followup_promotion(
            *[_load(item) for item in inputs],
            expected_git_sha=args.expected_git_sha,
            expected_source_run_id=args.source_run_id,
            expected_followup_run_id=args.followup_run_id,
        )
    except (
        OSError,
        json.JSONDecodeError,
        FollowupTrustedPromotionVerificationError,
    ) as exc:
        print(f"follow-up trusted promotion INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
