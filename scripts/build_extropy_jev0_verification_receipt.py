"""Build a deterministic receipt for verified Extropy jev0 execution provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_extropy_jev0_provenance import (
    ExtropyJev0ProvenanceError,
    verify_execution_report,
)

SCHEMA_VERSION = 1
KIND = "proofos-extropy-jev0-verification-receipt"
VERIFIER_PATH = Path(__file__).with_name("verify_extropy_jev0_provenance.py")


class ExtropyJev0ReceiptError(RuntimeError):
    pass


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _loaded_verifier_bytes() -> bytes:
    loaded_path = Path(verify_execution_report.__code__.co_filename).resolve()
    expected_path = VERIFIER_PATH.resolve()
    if loaded_path != expected_path:
        raise ExtropyJev0ReceiptError(
            "loaded provenance verifier does not match canonical verifier path"
        )
    try:
        return expected_path.read_bytes()
    except OSError as exc:
        raise ExtropyJev0ReceiptError(
            f"could not read loaded provenance verifier: {type(exc).__name__}"
        ) from exc


def build_receipt(
    execution_report: Any,
    *,
    executable_bytes: bytes,
    policy_bytes: bytes,
    capabilities: Any,
) -> dict[str, Any]:
    try:
        verification = verify_execution_report(
            execution_report,
            executable_bytes=executable_bytes,
            policy_bytes=policy_bytes,
            capabilities=capabilities,
        )
    except ExtropyJev0ProvenanceError as exc:
        raise ExtropyJev0ReceiptError(
            f"execution provenance is not independently verified: {exc}"
        ) from exc

    verifier_bytes = _loaded_verifier_bytes()
    records = verification["verified_records"]
    capability_ids = [record["capabilityId"] for record in records]
    executable_sha256 = _sha256_bytes(executable_bytes)
    policy_sha256 = _sha256_bytes(policy_bytes)
    capabilities_sha256 = _canonical_hash(capabilities)

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "execution_report_sha256": _canonical_hash(execution_report),
        "verifier_sha256": _sha256_bytes(verifier_bytes),
        "verification_result_sha256": _canonical_hash(verification),
        "executable_sha256": executable_sha256,
        "policy_sha256": policy_sha256,
        "capabilities_sha256": capabilities_sha256,
        "verified_record_count": len(records),
        "verified_capability_ids": capability_ids,
        "claim_boundary": [
            "records one independent re-verification of Extropy jev0 execution provenance",
            "binds the exact execution report, jev0 executable, policy, capabilities, and verifier implementation",
            "does not grant Extropy execution authority",
            "does not prove the supervised command achieved its requested postcondition",
        ],
    }
    return {**unsigned, "receipt_sha256": _canonical_hash(unsigned)}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExtropyJev0ReceiptError(
            f"could not read JSON constituent: {type(exc).__name__}"
        ) from exc


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ExtropyJev0ReceiptError(
            f"could not read binary constituent: {type(exc).__name__}"
        ) from exc


def _fixture() -> tuple[dict[str, Any], bytes, bytes, dict[str, Any]]:
    executable = b"jev0-binary"
    policy = b'{"schema_version":1}\n'
    capabilities = {
        "schema_version": 1,
        "runtime_ready": True,
        "process_backend": "posix",
    }
    provenance = {
        "schema": "extropy-jev0-execution-provenance/v1",
        "executableSha256": _sha256_bytes(executable),
        "policySha256": _sha256_bytes(policy),
        "capabilitiesSha256": _canonical_hash(capabilities),
    }
    report = {
        "schema": "extropy-capability-execution-report/v1",
        "kind": "capability.execution.report",
        "workId": "work-1",
        "runId": "run-1",
        "mode": "armed",
        "executedCount": 1,
        "blockedCount": 0,
        "records": [
            {
                "capabilityId": "tool/mcp/extropy-local/run_npm_script",
                "executor": "tool-broker",
                "workCapabilities": ["EXECUTE"],
                "status": "EXECUTED",
                "reason": "executed",
                "executed": True,
                "verified": False,
                "jev0Execution": provenance,
            }
        ],
    }
    return report, executable, policy, capabilities


def _self_test() -> None:
    report, executable, policy, capabilities = _fixture()
    first = build_receipt(
        report,
        executable_bytes=executable,
        policy_bytes=policy,
        capabilities=capabilities,
    )
    second = build_receipt(
        report,
        executable_bytes=executable,
        policy_bytes=policy,
        capabilities=capabilities,
    )
    assert first == second
    assert first["verified_record_count"] == 1
    assert len(first["receipt_sha256"]) == 64
    print("Extropy jev0 verification receipt builder self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("execution_report", nargs="?", type=Path)
    parser.add_argument("--jev0-executable", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--capabilities", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if (
        args.execution_report is None
        or args.jev0_executable is None
        or args.policy is None
        or args.capabilities is None
        or args.output is None
    ):
        parser.error(
            "execution_report, --jev0-executable, --policy, --capabilities, "
            "and --output are required"
        )

    try:
        receipt = build_receipt(
            _load_json(args.execution_report),
            executable_bytes=_read_bytes(args.jev0_executable),
            policy_bytes=_read_bytes(args.policy),
            capabilities=_load_json(args.capabilities),
        )
    except ExtropyJev0ReceiptError as exc:
        print(f"Extropy jev0 verification receipt FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
