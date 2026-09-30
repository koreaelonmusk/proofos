"""Independently verify a persisted ProofOS trust-pipeline receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_trust_pipeline_receipt import (
    KIND, SCHEMA_VERSION, TrustPipelineReceiptError, build_receipt,
)

EXPECTED_KEYS = {
    "schema_version", "kind", "status", "trigger_mode", "source_run_id",
    "followup_run_id", "e2e_run_id", "target_origin", "workflow_source_git_sha",
    "github_deployment_id", "github_deployment_status_id", "authorization_status",
    "authorized", "authorization_basis", "manifest_sha256", "verdict_sha256",
    "trusted_promotion_sha256", "provider_diagnosis_status",
    "provider_diagnosis_sha256", "authorization_result_sha256",
    "claim_boundary", "receipt_sha256",
}


class TrustPipelineReceiptVerificationError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    unsigned = {k: v for k, v in value.items() if k != "receipt_sha256"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_receipt(authorization: Any, receipt: Any, provider_diagnosis: Any | None = None) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != EXPECTED_KEYS:
        raise TrustPipelineReceiptVerificationError("receipt schema drifted")
    if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("kind") != KIND:
        raise TrustPipelineReceiptVerificationError("receipt identity is invalid")
    if receipt.get("receipt_sha256") != _digest(receipt):
        raise TrustPipelineReceiptVerificationError("receipt SHA-256 mismatch")
    try:
        expected = build_receipt(
            authorization,
            source_run_id=receipt["source_run_id"],
            followup_run_id=receipt["followup_run_id"],
            e2e_run_id=receipt["e2e_run_id"],
            provider_diagnosis=provider_diagnosis,
        )
    except TrustPipelineReceiptError as exc:
        raise TrustPipelineReceiptVerificationError(f"receipt constituents invalid: {exc}") from exc
    if receipt != expected:
        raise TrustPipelineReceiptVerificationError("persisted receipt differs from re-derivation")
    return {
        "valid": True, "status": receipt["status"],
        "trigger_mode": receipt["trigger_mode"],
        "receipt_sha256": receipt["receipt_sha256"],
    }


def _self_test() -> None:
    auth = {
        "authorized": False, "status": "HOLD", "authorization_basis": "none",
        "trusted_promotion_sha256": None, "source_run_id": 10,
        "target_origin": "https://proofos.example.vercel.app",
        "workflow_source_git_sha": "a" * 40, "github_deployment_id": 1,
        "github_deployment_status_id": 2, "deployment_environment": "production",
        "manifest_sha256": "b" * 64, "verdict_sha256": "c" * 64,
    }
    diagnosis = {
        "source_run_id": 10, "followup_run_id": 20,
        "workflow_source_git_sha": "a" * 40,
        "target_origin": "https://proofos.example.vercel.app",
        "status": "PROVIDER_CONFIGURATION_REQUIRED",
        "diagnosis_sha256": "d" * 64,
    }
    receipt = build_receipt(
        auth,
        source_run_id=10,
        followup_run_id=20,
        e2e_run_id=30,
        provider_diagnosis=diagnosis,
    )
    result = verify_receipt(auth, receipt, diagnosis)
    assert result["valid"] is True
    assert result["status"] == "HOLD_PROVIDER_CONFIGURATION_REQUIRED"
    print("trust pipeline receipt verifier self-test OK")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("authorization", nargs="?", type=Path)
    parser.add_argument("receipt", nargs="?", type=Path)
    parser.add_argument("--provider-diagnosis", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        _self_test()
        return 0
    if args.authorization is None or args.receipt is None:
        parser.error("authorization and receipt are required")
    try:
        result = verify_receipt(
            _load(args.authorization), _load(args.receipt),
            _load(args.provider_diagnosis) if args.provider_diagnosis else None,
        )
    except (OSError, json.JSONDecodeError, TrustPipelineReceiptVerificationError) as exc:
        print(f"trust pipeline receipt INVALID: {exc}", file=sys.stderr); return 1
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
