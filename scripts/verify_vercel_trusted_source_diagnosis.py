"""Independently verify a persisted Vercel Trusted Source capability diagnosis."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import typing

from build_vercel_trusted_source_diagnosis import (
    KIND,
    SCHEMA_VERSION,
    TrustedSourceDiagnosisError,
    derive_diagnosis,
)

EXPECTED_KEYS = {
    "schema_version", "kind", "status", "finding", "target_origin",
    "workflow_source_git_sha", "github_deployment_id",
    "github_deployment_status_id", "source_run_id", "followup_run_id",
    "original_outcome", "followup_outcome",
    "original_event_name", "followup_event_name", "original_oidc_ref",
    "followup_oidc_ref", "original_evidence_sha256",
    "followup_evidence_sha256", "next_required_evidence", "claim_boundary",
    "diagnosis_sha256",
}


class TrustedSourceDiagnosisVerificationError(RuntimeError):
    pass


def _digest(value: dict[str, typing.Any]) -> str:
    unsigned = {k: v for k, v in value.items() if k != "diagnosis_sha256"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_diagnosis(
    original: typing.Any,
    followup: typing.Any,
    diagnosis: typing.Any,
    *,
    expected_source_run_id: int,
    expected_followup_run_id: int,
) -> dict[str, typing.Any]:
    if not isinstance(diagnosis, dict) or set(diagnosis) != EXPECTED_KEYS:
        raise TrustedSourceDiagnosisVerificationError("diagnosis schema drifted")
    if diagnosis.get("schema_version") != SCHEMA_VERSION or diagnosis.get("kind") != KIND:
        raise TrustedSourceDiagnosisVerificationError("diagnosis identity is invalid")
    if diagnosis.get("source_run_id") != expected_source_run_id:
        raise TrustedSourceDiagnosisVerificationError(
            "diagnosis is bound to a different source run"
        )
    if diagnosis.get("followup_run_id") != expected_followup_run_id:
        raise TrustedSourceDiagnosisVerificationError(
            "diagnosis is bound to a different follow-up run"
        )
    digest = diagnosis.get("diagnosis_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise TrustedSourceDiagnosisVerificationError("diagnosis SHA-256 is malformed")
    if digest.lower() != _digest(diagnosis):
        raise TrustedSourceDiagnosisVerificationError("diagnosis SHA-256 mismatch")
    try:
        expected = derive_diagnosis(
            original,
            followup,
            source_run_id=expected_source_run_id,
            followup_run_id=expected_followup_run_id,
        )
    except TrustedSourceDiagnosisError as exc:
        raise TrustedSourceDiagnosisVerificationError(
            f"diagnosis constituents invalid: {exc}"
        ) from exc
    if diagnosis != expected:
        raise TrustedSourceDiagnosisVerificationError(
            "persisted diagnosis does not match independent re-derivation"
        )
    return {
        "valid": True,
        "status": diagnosis["status"],
        "finding": diagnosis["finding"],
        "source_run_id": diagnosis["source_run_id"],
        "followup_run_id": diagnosis["followup_run_id"],
        "diagnosis_sha256": digest.lower(),
    }


def _load(path: Path) -> typing.Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("followup", type=Path)
    parser.add_argument("diagnosis", type=Path)
    parser.add_argument("--source-run-id", type=int, required=True)
    parser.add_argument("--followup-run-id", type=int, required=True)
    args = parser.parse_args()
    try:
        result = verify_diagnosis(
            _load(args.original),
            _load(args.followup),
            _load(args.diagnosis),
            expected_source_run_id=args.source_run_id,
            expected_followup_run_id=args.followup_run_id,
        )
    except (OSError, json.JSONDecodeError, TrustedSourceDiagnosisVerificationError) as exc:
        print(f"trusted-source diagnosis INVALID: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
