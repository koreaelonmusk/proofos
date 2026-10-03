"""Independently verify Extropy's jev0 execution provenance against constituents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

PROVENANCE_SCHEMA = "extropy-jev0-execution-provenance/v1"
EXPECTED_PROVENANCE_KEYS = {
    "schema",
    "executableSha256",
    "policySha256",
    "capabilitiesSha256",
}


class ExtropyJev0ProvenanceError(RuntimeError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _validate_provenance(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != EXPECTED_PROVENANCE_KEYS:
        raise ExtropyJev0ProvenanceError("jev0 execution provenance schema drifted")
    if value.get("schema") != PROVENANCE_SCHEMA:
        raise ExtropyJev0ProvenanceError("unsupported jev0 execution provenance schema")
    for key in ("executableSha256", "policySha256", "capabilitiesSha256"):
        if not _is_sha256(value.get(key)):
            raise ExtropyJev0ProvenanceError(f"{key} must be a lowercase SHA-256")
    return value


def _records(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ExtropyJev0ProvenanceError("execution report payload must be an object")
    records = payload.get("records")
    if not isinstance(records, list):
        raise ExtropyJev0ProvenanceError("execution report records must be an array")
    result: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ExtropyJev0ProvenanceError("execution report record must be an object")
        if "jev0Execution" in record:
            result.append(record)
    if not result:
        raise ExtropyJev0ProvenanceError("execution report contains no jev0 provenance")
    return result


def verify_execution_report(
    payload: Any,
    *,
    executable_bytes: bytes,
    policy_bytes: bytes,
    capabilities: Any,
) -> dict[str, Any]:
    if not isinstance(capabilities, dict):
        raise ExtropyJev0ProvenanceError("capabilities constituent must be a JSON object")
    if capabilities.get("schema_version") != 1:
        raise ExtropyJev0ProvenanceError("unsupported jev0 capabilities schema")

    expected_executable = _sha256_bytes(executable_bytes)
    expected_policy = _sha256_bytes(policy_bytes)
    expected_capabilities = _canonical_json_sha256(capabilities)

    verified: list[dict[str, Any]] = []
    for record in _records(payload):
        provenance = _validate_provenance(record["jev0Execution"])
        if record.get("executed") is not True:
            raise ExtropyJev0ProvenanceError(
                "jev0 provenance is attached to a non-executed capability"
            )
        if provenance["executableSha256"] != expected_executable:
            raise ExtropyJev0ProvenanceError("jev0 executable SHA-256 mismatch")
        if provenance["policySha256"] != expected_policy:
            raise ExtropyJev0ProvenanceError("jev0 policy SHA-256 mismatch")
        if provenance["capabilitiesSha256"] != expected_capabilities:
            raise ExtropyJev0ProvenanceError("jev0 capabilities SHA-256 mismatch")

        verified.append(
            {
                "capabilityId": record.get("capabilityId"),
                "status": record.get("status"),
                "executableSha256": expected_executable,
                "policySha256": expected_policy,
                "capabilitiesSha256": expected_capabilities,
            }
        )

    return {
        "valid": True,
        "kind": "proofos-extropy-jev0-provenance-verification",
        "schema_version": 1,
        "verified_records": verified,
        "claim_boundary": [
            "independently re-hashes supplied jev0 execution constituents",
            "does not prove that Extropy was authorized to execute",
            "does not prove the supervised command achieved its requested outcome",
            "does not treat executor self-report as sufficient without constituents",
        ],
    }


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExtropyJev0ProvenanceError(
            f"could not read JSON constituent: {type(exc).__name__}"
        ) from exc


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ExtropyJev0ProvenanceError(
            f"could not read binary constituent: {type(exc).__name__}"
        ) from exc


def _self_test() -> None:
    executable = b"#!/usr/bin/env python3\nprint('jev0')\n"
    policy = b'{"schema_version":1,"max_files":4,"max_lines":200}\n'
    capabilities = {
        "schema_version": 1,
        "runtime_ready": True,
        "process_backend": "posix",
    }
    provenance = {
        "schema": PROVENANCE_SCHEMA,
        "executableSha256": _sha256_bytes(executable),
        "policySha256": _sha256_bytes(policy),
        "capabilitiesSha256": _canonical_json_sha256(capabilities),
    }
    payload = {
        "runId": "run-1",
        "records": [
            {
                "capabilityId": "tool/mcp/extropy-local/run_npm_script",
                "status": "EXECUTED",
                "executed": True,
                "verified": False,
                "jev0Execution": provenance,
            }
        ],
    }

    result = verify_execution_report(
        payload,
        executable_bytes=executable,
        policy_bytes=policy,
        capabilities=capabilities,
    )
    assert result["valid"] is True
    assert len(result["verified_records"]) == 1

    tampered = json.loads(json.dumps(payload))
    tampered["records"][0]["jev0Execution"]["policySha256"] = "0" * 64
    try:
        verify_execution_report(
            tampered,
            executable_bytes=executable,
            policy_bytes=policy,
            capabilities=capabilities,
        )
    except ExtropyJev0ProvenanceError:
        pass
    else:
        raise AssertionError("tampered provenance unexpectedly verified")

    print("Extropy jev0 provenance verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("execution_report", nargs="?", type=Path)
    parser.add_argument("--jev0-executable", type=Path)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--capabilities", type=Path)
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
    ):
        parser.error(
            "execution_report, --jev0-executable, --policy, and --capabilities are required"
        )

    try:
        result = verify_execution_report(
            _load_json(args.execution_report),
            executable_bytes=_read_bytes(args.jev0_executable),
            policy_bytes=_read_bytes(args.policy),
            capabilities=_load_json(args.capabilities),
        )
    except ExtropyJev0ProvenanceError as exc:
        print(f"Extropy jev0 provenance INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
