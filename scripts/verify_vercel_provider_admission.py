"""Independently verify a persisted Vercel Provider Admission Contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_vercel_provider_admission import (
    KIND,
    SCHEMA_VERSION,
    ProviderAdmissionError,
    derive_admission,
)

EXPECTED_KEYS = {
    "schema_version",
    "kind",
    "status",
    "source_run_id",
    "followup_run_id",
    "target_origin",
    "workflow_source_git_sha",
    "github_deployment_id",
    "github_deployment_status_id",
    "original_evidence_sha256",
    "followup_evidence_sha256",
    "diagnosis_sha256",
    "trusted_source_outcome",
    "trusted_source_plane",
    "authorization_scope",
    "next_required_evidence",
    "claim_boundary",
    "admission_sha256",
}


class ProviderAdmissionVerificationError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "admission_sha256"}
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_admission(
    original: Any,
    followup: Any,
    diagnosis: Any,
    admission: Any,
    *,
    expected_source_run_id: int,
    expected_followup_run_id: int,
) -> dict[str, Any]:
    if not isinstance(admission, dict) or set(admission) != EXPECTED_KEYS:
        raise ProviderAdmissionVerificationError("admission schema drifted")
    if admission.get("schema_version") != SCHEMA_VERSION or admission.get("kind") != KIND:
        raise ProviderAdmissionVerificationError("admission identity is invalid")
    if admission.get("source_run_id") != expected_source_run_id:
        raise ProviderAdmissionVerificationError("admission binds a different source run")
    if admission.get("followup_run_id") != expected_followup_run_id:
        raise ProviderAdmissionVerificationError("admission binds a different follow-up run")
    if admission.get("admission_sha256") != _digest(admission):
        raise ProviderAdmissionVerificationError("admission SHA-256 mismatch")

    try:
        expected = derive_admission(
            original,
            followup,
            diagnosis,
            source_run_id=expected_source_run_id,
            followup_run_id=expected_followup_run_id,
        )
    except ProviderAdmissionError as exc:
        raise ProviderAdmissionVerificationError(
            f"admission constituents invalid: {exc}"
        ) from exc
    if admission != expected:
        raise ProviderAdmissionVerificationError(
            "persisted admission differs from independent re-derivation"
        )

    return {
        "valid": True,
        "status": admission["status"],
        "source_run_id": admission["source_run_id"],
        "followup_run_id": admission["followup_run_id"],
        "admission_sha256": admission["admission_sha256"],
        "followup_evidence_sha256": admission["followup_evidence_sha256"],
    }


def _self_test() -> None:
    from build_vercel_provider_admission import _self_test as builder_self_test

    builder_self_test()
    print("provider admission verifier self-test OK")


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", nargs="?", type=Path)
    parser.add_argument("followup", nargs="?", type=Path)
    parser.add_argument("diagnosis", nargs="?", type=Path)
    parser.add_argument("admission", nargs="?", type=Path)
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if any(
        value is None
        for value in (args.original, args.followup, args.diagnosis, args.admission)
    ):
        parser.error("four evidence files are required")

    try:
        result = verify_admission(
            _load(args.original),
            _load(args.followup),
            _load(args.diagnosis),
            _load(args.admission),
            expected_source_run_id=args.source_run_id,
            expected_followup_run_id=args.followup_run_id,
        )
    except (
        OSError,
        json.JSONDecodeError,
        ProviderAdmissionVerificationError,
    ) as exc:
        print(f"provider admission INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
