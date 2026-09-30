"""Build a run-bound receipt for one ProofOS trust-pipeline authorization decision."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

SCHEMA_VERSION = 1
KIND = "proofos-trust-pipeline-receipt"


class TrustPipelineReceiptError(RuntimeError):
    pass


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def build_receipt(
    authorization: Any,
    *,
    source_run_id: int,
    followup_run_id: int | None,
    e2e_run_id: int,
    provider_diagnosis: Any | None = None,
) -> dict[str, Any]:
    if not isinstance(authorization, dict):
        raise TrustPipelineReceiptError("authorization result must be an object")
    for name, value in (("source_run_id", source_run_id), ("e2e_run_id", e2e_run_id)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise TrustPipelineReceiptError(f"{name} must be a positive integer")

    automatic = followup_run_id is not None
    if automatic:
        if not isinstance(followup_run_id, int) or isinstance(followup_run_id, bool) or followup_run_id <= 0:
            raise TrustPipelineReceiptError("followup_run_id must be a positive integer")
        if not isinstance(provider_diagnosis, dict):
            raise TrustPipelineReceiptError("automatic receipt requires provider diagnosis")
        if provider_diagnosis.get("source_run_id") != source_run_id:
            raise TrustPipelineReceiptError("provider diagnosis binds a different source run")
        if provider_diagnosis.get("followup_run_id") != followup_run_id:
            raise TrustPipelineReceiptError("provider diagnosis binds a different follow-up run")
        if provider_diagnosis.get("workflow_source_git_sha") != authorization.get("workflow_source_git_sha"):
            raise TrustPipelineReceiptError("provider diagnosis binds a different Git SHA")
        if provider_diagnosis.get("target_origin") != authorization.get("target_origin"):
            raise TrustPipelineReceiptError("provider diagnosis targets a different origin")

    if authorization.get("source_run_id") not in {None, source_run_id}:
        raise TrustPipelineReceiptError("authorization binds a different source run")
    if not isinstance(authorization.get("authorized"), bool):
        raise TrustPipelineReceiptError("authorization result is missing boolean authorized")

    diagnosis_status = provider_diagnosis.get("status") if automatic else None
    diagnosis_hash = provider_diagnosis.get("diagnosis_sha256") if automatic else None
    if authorization["authorized"]:
        status = "AUTHORIZED_FOR_PRIVILEGED_E2E"
    elif diagnosis_status == "PROVIDER_CONFIGURATION_REQUIRED":
        status = "HOLD_PROVIDER_CONFIGURATION_REQUIRED"
    else:
        status = "HOLD"

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "trigger_mode": "automatic_sequential" if automatic else "manual_recovery",
        "source_run_id": source_run_id,
        "followup_run_id": followup_run_id,
        "e2e_run_id": e2e_run_id,
        "target_origin": authorization.get("target_origin"),
        "workflow_source_git_sha": authorization.get("workflow_source_git_sha"),
        "github_deployment_id": authorization.get("github_deployment_id"),
        "github_deployment_status_id": authorization.get("github_deployment_status_id"),
        "authorization_status": authorization.get("status"),
        "authorized": authorization["authorized"],
        "authorization_basis": authorization.get("authorization_basis"),
        "manifest_sha256": authorization.get("manifest_sha256"),
        "verdict_sha256": authorization.get("verdict_sha256"),
        "trusted_promotion_sha256": authorization.get("trusted_promotion_sha256"),
        "provider_diagnosis_status": diagnosis_status,
        "provider_diagnosis_sha256": diagnosis_hash,
        "authorization_result_sha256": _canonical_hash(authorization),
        "claim_boundary": [
            "records one authorization decision and its run provenance",
            "does not itself authorize privileged execution",
            "automatic receipts require a run-bound provider diagnosis",
            "does not contain OIDC tokens, bearer tokens, or signing keys",
        ],
    }
    return {**unsigned, "receipt_sha256": _canonical_hash(unsigned)}


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
        auth, source_run_id=10, followup_run_id=20, e2e_run_id=30,
        provider_diagnosis=diagnosis,
    )
    assert receipt["status"] == "HOLD_PROVIDER_CONFIGURATION_REQUIRED"
    assert len(receipt["receipt_sha256"]) == 64
    print("trust pipeline receipt self-test OK")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustPipelineReceiptError(f"could not read receipt input: {type(exc).__name__}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("authorization", nargs="?", type=Path)
    parser.add_argument("--provider-diagnosis", type=Path)
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--e2e-run-id", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        _self_test(); return 0
    if args.authorization is None or args.output is None:
        parser.error("authorization and --output are required")
    try:
        receipt = build_receipt(
            _load(args.authorization),
            source_run_id=args.source_run_id,
            followup_run_id=(args.followup_run_id if args.followup_run_id > 0 else None),
            e2e_run_id=args.e2e_run_id,
            provider_diagnosis=(
                _load(args.provider_diagnosis) if args.provider_diagnosis else None
            ),
        )
    except TrustPipelineReceiptError as exc:
        print(f"trust pipeline receipt FAILED: {exc}", file=sys.stderr); return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
