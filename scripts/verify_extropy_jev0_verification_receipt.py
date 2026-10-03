"""Independently re-derive a ProofOS Extropy-jev0 verification receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from build_extropy_jev0_verification_receipt import (
    KIND,
    SCHEMA_VERSION,
    VERIFIER_PATH,
    ExtropyJev0ReceiptError,
    build_receipt,
)

EXPECTED_KEYS = {
    "schema_version",
    "kind",
    "execution_report_sha256",
    "verifier_sha256",
    "verification_result_sha256",
    "executable_sha256",
    "policy_sha256",
    "capabilities_sha256",
    "verified_record_count",
    "verified_capability_ids",
    "claim_boundary",
    "receipt_sha256",
}


class ExtropyJev0ReceiptVerificationError(RuntimeError):
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


def _digest(receipt: dict[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_sha256"
    }
    return _canonical_hash(unsigned)


def verify_receipt(
    receipt: Any,
    execution_report: Any,
    *,
    executable_bytes: bytes,
    policy_bytes: bytes,
    capabilities: Any,
) -> dict[str, Any]:
    if not isinstance(receipt, dict) or set(receipt) != EXPECTED_KEYS:
        raise ExtropyJev0ReceiptVerificationError("verification receipt schema drifted")
    if (
        type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt.get("kind") != KIND
    ):
        raise ExtropyJev0ReceiptVerificationError("verification receipt identity is invalid")
    if receipt.get("receipt_sha256") != _digest(receipt):
        raise ExtropyJev0ReceiptVerificationError("verification receipt SHA-256 mismatch")

    try:
        expected = build_receipt(
            execution_report,
            executable_bytes=executable_bytes,
            policy_bytes=policy_bytes,
            capabilities=capabilities,
        )
    except ExtropyJev0ReceiptError as exc:
        raise ExtropyJev0ReceiptVerificationError(
            f"receipt constituents are invalid: {exc}"
        ) from exc

    if receipt != expected:
        raise ExtropyJev0ReceiptVerificationError(
            "persisted verification receipt differs from re-derivation"
        )

    return {
        "valid": True,
        "kind": receipt["kind"],
        "receipt_sha256": receipt["receipt_sha256"],
        "execution_report_sha256": receipt["execution_report_sha256"],
        "verifier_sha256": receipt["verifier_sha256"],
        "verified_record_count": receipt["verified_record_count"],
    }


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExtropyJev0ReceiptVerificationError(
            f"could not read JSON input: {type(exc).__name__}"
        ) from exc


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ExtropyJev0ReceiptVerificationError(
            f"could not read binary input: {type(exc).__name__}"
        ) from exc


def _self_test() -> None:
    from build_extropy_jev0_verification_receipt import _fixture

    report, executable, policy, capabilities = _fixture()
    receipt = build_receipt(
        report,
        executable_bytes=executable,
        policy_bytes=policy,
        capabilities=capabilities,
    )
    result = verify_receipt(
        receipt,
        report,
        executable_bytes=executable,
        policy_bytes=policy,
        capabilities=capabilities,
    )
    assert result["valid"] is True

    tampered = dict(receipt)
    tampered["verified_record_count"] = 2
    try:
        verify_receipt(
            tampered,
            report,
            executable_bytes=executable,
            policy_bytes=policy,
            capabilities=capabilities,
        )
    except ExtropyJev0ReceiptVerificationError:
        pass
    else:
        raise AssertionError("tampered verification receipt unexpectedly verified")

    print("Extropy jev0 verification receipt verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", nargs="?", type=Path)
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
        args.receipt is None
        or args.execution_report is None
        or args.jev0_executable is None
        or args.policy is None
        or args.capabilities is None
    ):
        parser.error(
            "receipt, execution_report, --jev0-executable, --policy, "
            "and --capabilities are required"
        )

    try:
        result = verify_receipt(
            _load_json(args.receipt),
            _load_json(args.execution_report),
            executable_bytes=_read_bytes(args.jev0_executable),
            policy_bytes=_read_bytes(args.policy),
            capabilities=_load_json(args.capabilities),
        )
    except ExtropyJev0ReceiptVerificationError as exc:
        print(f"Extropy jev0 verification receipt INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
