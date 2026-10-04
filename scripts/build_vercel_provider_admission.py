"""Build a provider admission contract from independently verified Trusted Source evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_vercel_trusted_source_artifact import (
    TrustedSourceArtifactError,
    verify_evidence as verify_trusted_source,
)
from verify_vercel_trusted_source_diagnosis import (
    TrustedSourceDiagnosisVerificationError,
    verify_diagnosis,
)

SCHEMA_VERSION = 1
KIND = "proofos-vercel-provider-admission"
ADMITTED = "ADMITTED_FOR_TRUSTED_PROMOTION"
HOLD_PROVIDER = "HOLD_PROVIDER_CONFIGURATION_REQUIRED"
HOLD_NOT_READY = "HOLD_TRUSTED_SOURCE_NOT_READY"
READY = "TRUSTED_SOURCE_ACCEPTED_READY_AND_ANONYMOUS_DENIED"
NOT_READY = "TRUSTED_SOURCE_ACCEPTED_NOT_READY_AND_ANONYMOUS_DENIED"
REJECTED = "TRUSTED_SOURCE_REJECTED"


class ProviderAdmissionError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def derive_admission(
    original: Any,
    followup: Any,
    diagnosis: Any,
    *,
    source_run_id: int,
    followup_run_id: int,
) -> dict[str, Any]:
    try:
        first = verify_trusted_source(original)
        second = verify_trusted_source(followup)
        verified_diagnosis = verify_diagnosis(
            original,
            followup,
            diagnosis,
            expected_source_run_id=source_run_id,
            expected_followup_run_id=followup_run_id,
        )
    except (TrustedSourceArtifactError, TrustedSourceDiagnosisVerificationError) as exc:
        raise ProviderAdmissionError(f"provider evidence invalid: {exc}") from exc

    if not isinstance(followup, dict):
        raise ProviderAdmissionError("follow-up evidence must be an object")

    claims = followup.get("oidc_claims")
    if not isinstance(claims, dict):
        raise ProviderAdmissionError("follow-up OIDC claims are missing")
    if claims.get("event_name") != "workflow_run":
        raise ProviderAdmissionError("follow-up identity must come from workflow_run")
    if claims.get("ref") != "refs/heads/main":
        raise ProviderAdmissionError("follow-up identity must be main-ref bound")
    expected_workflow = (
        "koreaelonmusk/proofos/.github/workflows/"
        "vercel-trusted-source-followup.yml@refs/heads/main"
    )
    if claims.get("workflow_ref") != expected_workflow:
        raise ProviderAdmissionError("follow-up identity is bound to the wrong workflow")
    if claims.get("workflow_sha") != second["workflow_source_git_sha"]:
        raise ProviderAdmissionError("follow-up workflow SHA does not match deployed Git SHA")

    outcome = second["outcome"]
    diagnosis_status = verified_diagnosis["status"]
    if outcome == READY:
        if diagnosis_status != "FOLLOWUP_TRUST_PATH_ACCEPTED":
            raise ProviderAdmissionError(
                "ready follow-up evidence is inconsistent with provider diagnosis"
            )
        status = ADMITTED
        next_required = ["build_trusted_promotion_from_admitted_followup"]
    elif outcome == NOT_READY:
        status = HOLD_NOT_READY
        next_required = ["configure_collector_readiness", "rerun_trusted_source_followup"]
    elif outcome == REJECTED:
        if diagnosis_status != "PROVIDER_CONFIGURATION_REQUIRED":
            raise ProviderAdmissionError(
                "rejected follow-up evidence is inconsistent with provider diagnosis"
            )
        status = HOLD_PROVIDER
        next_required = [
            "configure_vercel_trusted_sources_oidc_provider",
            "rerun_trusted_source_followup",
        ]
    else:
        raise ProviderAdmissionError("unsupported Trusted Source outcome")

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "source_run_id": source_run_id,
        "followup_run_id": followup_run_id,
        "target_origin": second["target_origin"],
        "workflow_source_git_sha": second["workflow_source_git_sha"],
        "github_deployment_id": diagnosis["github_deployment_id"],
        "github_deployment_status_id": diagnosis["github_deployment_status_id"],
        "original_evidence_sha256": first["evidence_sha256"],
        "followup_evidence_sha256": second["evidence_sha256"],
        "diagnosis_sha256": verified_diagnosis["diagnosis_sha256"],
        "trusted_source_outcome": outcome,
        "trusted_source_plane": "workflow_run_followup",
        "authorization_scope": "trusted_promotion_input_only",
        "next_required_evidence": next_required,
        "claim_boundary": [
            "does not authorize privileged E2E or production rollout",
            "admits only independently verified follow-up Trusted Source evidence",
            "binds source and follow-up workflow run IDs into one decision",
            "requires the main follow-up workflow identity and deployed Git SHA",
            "contains no OIDC token, bearer token, signing key, or provider response body",
        ],
    }
    return {**unsigned, "admission_sha256": _digest(unsigned)}


def _self_test() -> None:
    from verify_vercel_trusted_source_artifact import _base, _signed
    from build_vercel_trusted_source_diagnosis import derive_diagnosis

    original = _base(REJECTED)
    original["oidc_claims"]["event_name"] = "deployment_status"
    original["oidc_claims"].pop("ref", None)
    original.update(
        {
            "http_status": 401,
            "claim_boundary": [
                "proves the Vercel edge did not accept this GitHub Actions OIDC request",
                "does not reveal or persist the OIDC token",
                "does not prove application health or readiness",
            ],
        }
    )
    original = _signed(original)

    followup = _base(READY)
    followup["workflow_source_git_sha"] = original["workflow_source_git_sha"]
    followup["target_origin"] = original["target_origin"]
    followup["deployment_event"] = json.loads(json.dumps(original["deployment_event"]))
    followup["oidc_claims"]["event_name"] = "workflow_run"
    followup["oidc_claims"]["ref"] = "refs/heads/main"
    followup["oidc_claims"]["workflow_ref"] = (
        "koreaelonmusk/proofos/.github/workflows/"
        "vercel-trusted-source-followup.yml@refs/heads/main"
    )
    followup["oidc_claims"]["workflow_sha"] = followup["workflow_source_git_sha"]
    followup["oidc_claims"]["sub"] = (
        "repo:koreaelonmusk@44775845/proofos@1341515802:ref:refs/heads/main"
    )
    followup.update(
        {
            "health": {
                "status": "ok",
                "service": "proofos-collector",
                "runtime": {
                    "platform": "vercel",
                    "environment": "production",
                    "deployment_id": "dpl_test",
                    "git_sha": followup["workflow_source_git_sha"],
                    "url": followup["target_origin"],
                },
            },
            "readiness": {
                "status": "ready",
                "service": "proofos-collector",
                "issues": [],
            },
            "anonymous_collect": {
                "outcome": "ANONYMOUS_COLLECTION_DENIED",
                "http_status": 401,
            },
            "claim_boundary": [
                "proves Vercel Trusted Sources accepted the GitHub Actions OIDC request",
                "records only the public health/readiness contract after edge authentication",
                "proves the reached application denied anonymous collection before probe or signing authority",
                "does not prove authenticated collector invocation or signed evidence collection",
                "does not reveal or persist the OIDC token",
            ],
        }
    )
    followup = _signed(followup)

    diagnosis = derive_diagnosis(
        original, followup, source_run_id=10, followup_run_id=20
    )
    admission = derive_admission(
        original, followup, diagnosis, source_run_id=10, followup_run_id=20
    )
    assert admission["status"] == ADMITTED
    assert len(admission["admission_sha256"]) == 64
    print("provider admission contract self-test OK")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderAdmissionError(
            f"could not read provider admission input: {type(exc).__name__}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", nargs="?", type=Path)
    parser.add_argument("followup", nargs="?", type=Path)
    parser.add_argument("diagnosis", nargs="?", type=Path)
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if any(
        value is None
        for value in (args.original, args.followup, args.diagnosis, args.output)
    ):
        parser.error("original, followup, diagnosis, and --output are required")

    try:
        result = derive_admission(
            _load(args.original),
            _load(args.followup),
            _load(args.diagnosis),
            source_run_id=args.source_run_id,
            followup_run_id=args.followup_run_id,
        )
    except ProviderAdmissionError as exc:
        print(f"provider admission FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
