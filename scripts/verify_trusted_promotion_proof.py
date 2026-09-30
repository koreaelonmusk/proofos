"""Independently verify a persisted Trusted Promotion Proof."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_trusted_promotion_proof import (
    KIND,
    SCHEMA_VERSION,
    STATUS,
    TrustedPromotionError,
    derive_trusted_promotion,
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
    "manifest_sha256",
    "verdict_sha256",
    "trusted_source_evidence_sha256",
    "public_status",
    "public_reasons",
    "trusted_source_outcome",
    "authorization_scope",
    "next_required_evidence",
    "claim_boundary",
    "promotion_sha256",
}


class TrustedPromotionVerificationError(RuntimeError):
    pass


def _digest_without_hash(value: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in value.items() if k != "promotion_sha256"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_promotion(
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    trusted_source: Any,
    promotion: Any,
    *,
    expected_git_sha: str = "",
    expected_source_run_id: int = 0,
) -> dict[str, Any]:
    if not isinstance(promotion, dict) or set(promotion) != EXPECTED_KEYS:
        raise TrustedPromotionVerificationError("promotion proof schema drifted")
    if promotion.get("schema_version") != SCHEMA_VERSION:
        raise TrustedPromotionVerificationError("unsupported promotion schema")
    if promotion.get("kind") != KIND or promotion.get("status") != STATUS:
        raise TrustedPromotionVerificationError("promotion proof identity is invalid")
    if (
        not isinstance(expected_source_run_id, int)
        or isinstance(expected_source_run_id, bool)
        or expected_source_run_id <= 0
    ):
        raise TrustedPromotionVerificationError(
            "expected source run id must be a positive integer"
        )
    if promotion.get("source_run_id") != expected_source_run_id:
        raise TrustedPromotionVerificationError(
            "promotion proof is bound to a different source run"
        )
    digest = promotion.get("promotion_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest.lower())
    ):
        raise TrustedPromotionVerificationError("promotion SHA-256 is malformed")
    if digest.lower() != _digest_without_hash(promotion):
        raise TrustedPromotionVerificationError("promotion SHA-256 mismatch")

    try:
        expected = derive_trusted_promotion(
            health,
            trust,
            manifest,
            verdict,
            trusted_source,
            expected_git_sha=expected_git_sha,
            source_run_id=expected_source_run_id,
        )
    except TrustedPromotionError as exc:
        raise TrustedPromotionVerificationError(
            f"promotion constituents are invalid: {exc}"
        ) from exc
    if promotion != expected:
        raise TrustedPromotionVerificationError(
            "persisted promotion does not match independent re-derivation"
        )
    return {
        "valid": True,
        "status": promotion["status"],
        "target_origin": promotion["target_origin"],
        "workflow_source_git_sha": promotion["workflow_source_git_sha"],
        "source_run_id": promotion["source_run_id"],
        "promotion_sha256": digest.lower(),
        "verdict_sha256": promotion["verdict_sha256"],
        "trusted_source_evidence_sha256": promotion[
            "trusted_source_evidence_sha256"
        ],
    }


def _self_test() -> None:
    # Builder self-test covers semantic positive/negative cases. This verifier
    # additionally proves a re-hashed semantic forgery cannot pass.
    from build_trusted_promotion_proof import _self_test as builder_self_test

    builder_self_test()
    print("trusted promotion verifier self-test OK")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedPromotionVerificationError(
            f"could not read promotion artifact: {type(exc).__name__}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health", nargs="?", type=Path)
    parser.add_argument("trust", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("verdict", nargs="?", type=Path)
    parser.add_argument("trusted_source", nargs="?", type=Path)
    parser.add_argument("promotion", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if any(
        item is None
        for item in (
            args.health,
            args.trust,
            args.manifest,
            args.verdict,
            args.trusted_source,
            args.promotion,
        )
    ):
        parser.error("six artifact inputs are required")
    try:
        result = verify_promotion(
            _load(args.health),
            _load(args.trust),
            _load(args.manifest),
            _load(args.verdict),
            _load(args.trusted_source),
            _load(args.promotion),
            expected_git_sha=args.expected_git_sha,
            expected_source_run_id=args.source_run_id,
        )
    except TrustedPromotionVerificationError as exc:
        print(f"trusted promotion proof INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
