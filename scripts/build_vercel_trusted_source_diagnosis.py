"""Derive a bounded diagnosis from original and follow-up Vercel Trusted Source evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_vercel_trusted_source_artifact import (
    TrustedSourceArtifactError,
    verify_evidence,
)

SCHEMA_VERSION = 2
KIND = "proofos-vercel-trusted-source-capability-diagnosis"
REJECTED = "TRUSTED_SOURCE_REJECTED"


class TrustedSourceDiagnosisError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _event(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrustedSourceDiagnosisError("deployment event is missing")
    required = {
        "github_deployment_id",
        "github_deployment_status_id",
        "environment",
        "environment_url",
        "source_git_sha",
    }
    if set(value) != required:
        raise TrustedSourceDiagnosisError("deployment event schema drifted")
    return value


def derive_diagnosis(
    original: Any,
    followup: Any,
    *,
    source_run_id: int,
    followup_run_id: int,
) -> dict[str, Any]:
    try:
        first = verify_evidence(original)
        second = verify_evidence(followup)
    except TrustedSourceArtifactError as exc:
        raise TrustedSourceDiagnosisError(f"trusted-source evidence invalid: {exc}") from exc

    if not isinstance(original, dict) or not isinstance(followup, dict):
        raise TrustedSourceDiagnosisError("diagnosis inputs must be objects")
    for name, value in (
        ("source_run_id", source_run_id),
        ("followup_run_id", followup_run_id),
    ):
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value <= 0
        ):
            raise TrustedSourceDiagnosisError(f"{name} must be a positive integer")
    if source_run_id == followup_run_id:
        raise TrustedSourceDiagnosisError(
            "source and follow-up run IDs must identify different workflow runs"
        )

    if first["target_origin"] != second["target_origin"]:
        raise TrustedSourceDiagnosisError("trusted-source observations target different origins")
    if first["workflow_source_git_sha"] != second["workflow_source_git_sha"]:
        raise TrustedSourceDiagnosisError("trusted-source observations bind different Git SHAs")

    original_event = _event(original.get("deployment_event"))
    followup_event = _event(followup.get("deployment_event"))
    if original_event != followup_event:
        raise TrustedSourceDiagnosisError("trusted-source observations bind different deployment events")

    original_claims = original.get("oidc_claims")
    followup_claims = followup.get("oidc_claims")
    if not isinstance(original_claims, dict) or not isinstance(followup_claims, dict):
        raise TrustedSourceDiagnosisError("OIDC diagnostic claims are missing")

    original_event_name = original_claims.get("event_name")
    followup_event_name = followup_claims.get("event_name")
    if original_event_name != "deployment_status":
        raise TrustedSourceDiagnosisError("original evidence is not deployment_status OIDC")
    if followup_event_name != "workflow_run":
        raise TrustedSourceDiagnosisError("follow-up evidence is not workflow_run OIDC")

    original_ref = first.get("oidc_ref")
    followup_ref = second.get("oidc_ref")
    if followup_ref != "refs/heads/main":
        raise TrustedSourceDiagnosisError("follow-up OIDC is not main-ref bound")

    if first["outcome"] == REJECTED and second["outcome"] == REJECTED:
        status = "PROVIDER_CONFIGURATION_REQUIRED"
        finding = "EVENT_CONTEXT_NOT_ROOT_CAUSE"
        next_required = [
            "inspect_vercel_trusted_sources_project_configuration",
            "confirm_github_repository_trust_registration",
            "rerun_followup_probe_after_provider_configuration_change",
        ]
    elif first["outcome"] == REJECTED and second["outcome"] != REJECTED:
        status = "FOLLOWUP_TRUST_PATH_ACCEPTED"
        finding = "EVENT_CONTEXT_CHANGED_TRUST_RESULT"
        next_required = [
            "bind_followup_evidence_into_trusted_promotion",
            "rerun_authenticated_e2e",
        ]
    else:
        status = "NO_PROVIDER_BLOCKER_PROVEN"
        finding = "NO_REJECTION_COMPARISON_AVAILABLE"
        next_required = ["continue_existing_trust_evidence_path"]

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "finding": finding,
        "target_origin": first["target_origin"],
        "workflow_source_git_sha": first["workflow_source_git_sha"],
        "github_deployment_id": original_event["github_deployment_id"],
        "github_deployment_status_id": original_event["github_deployment_status_id"],
        "source_run_id": source_run_id,
        "followup_run_id": followup_run_id,
        "original_outcome": first["outcome"],
        "followup_outcome": second["outcome"],
        "original_event_name": original_event_name,
        "followup_event_name": followup_event_name,
        "original_oidc_ref": original_ref,
        "followup_oidc_ref": followup_ref,
        "original_evidence_sha256": first["evidence_sha256"],
        "followup_evidence_sha256": second["evidence_sha256"],
        "next_required_evidence": next_required,
        "claim_boundary": [
            "compares only independently verified Trusted Source evidence for one deployment event",
            "does not modify Vercel project settings or GitHub OIDC policy",
            "does not authorize authenticated E2E or production rollout",
            "does not persist raw OIDC tokens or provider response bodies",
        ],
    }
    return {**unsigned, "diagnosis_sha256": _digest(unsigned)}


def _self_test() -> None:
    from verify_vercel_trusted_source_artifact import _base, _signed

    original = _base(REJECTED)
    original["oidc_claims"]["event_name"] = "deployment_status"
    original["oidc_claims"].pop("ref", None)
    original.update({
        "http_status": 401,
        "claim_boundary": [
            "proves the Vercel edge did not accept this GitHub Actions OIDC request",
            "does not reveal or persist the OIDC token",
            "does not prove application health or readiness",
        ],
    })
    original = _signed(original)

    followup = json.loads(json.dumps(original))
    followup.pop("evidence_sha256", None)
    followup["oidc_claims"]["event_name"] = "workflow_run"
    followup["oidc_claims"]["ref"] = "refs/heads/main"
    followup["oidc_claims"]["sub"] = (
        "repo:koreaelonmusk@44775845/proofos@1341515802:ref:refs/heads/main"
    )
    followup = _signed(followup)

    result = derive_diagnosis(
        original,
        followup,
        source_run_id=123,
        followup_run_id=456,
    )
    assert result["status"] == "PROVIDER_CONFIGURATION_REQUIRED"
    assert result["finding"] == "EVENT_CONTEXT_NOT_ROOT_CAUSE"
    assert len(result["diagnosis_sha256"]) == 64
    print("trusted-source capability diagnosis self-test OK")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedSourceDiagnosisError(
            f"could not read trusted-source evidence: {type(exc).__name__}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", nargs="?", type=Path)
    parser.add_argument("followup", nargs="?", type=Path)
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if args.original is None or args.followup is None or args.output is None:
        parser.error("original, followup, and --output are required")

    try:
        diagnosis = derive_diagnosis(
            _load(args.original),
            _load(args.followup),
            source_run_id=args.source_run_id,
            followup_run_id=args.followup_run_id,
        )
    except TrustedSourceDiagnosisError as exc:
        print(f"trusted-source capability diagnosis FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(diagnosis, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(diagnosis, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
