"""Create a signed receipt from an independently recomputed transparency audit.

This command intentionally requires an existing Ed25519 private key file. It
never generates or rotates auditor identity implicitly.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
for entry in (str(ROOT), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from audit_transparency import evaluate_artifacts  # noqa: E402
from proofos.transparency_audit_receipt import (  # noqa: E402
    TransparencyAuditReceiptSigner,
)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(
            f"could not read auditor private key {path}: {type(exc).__name__}"
        ) from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError) as exc:
        raise ValueError("auditor private key is not readable PKCS#8 PEM") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(
            f"auditor private key is {type(key).__name__}, not Ed25519"
        )
    return key


def _write_create_only(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite existing receipt {path}") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a signed ProofOS transparency audit receipt"
    )
    parser.add_argument("gossip", type=Path)
    parser.add_argument("--gossip-public-key", required=True)
    parser.add_argument("--gossip-publisher-id", required=True)
    parser.add_argument("--expected-policy-digest", required=True)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--certificate-public-key")
    parser.add_argument("--certificate-signer-id")
    parser.add_argument("--auditor-private-key", type=Path, required=True)
    parser.add_argument("--auditor-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        result, bundle, certificate = evaluate_artifacts(
            gossip_path=args.gossip,
            gossip_public_key=args.gossip_public_key,
            gossip_publisher_id=args.gossip_publisher_id,
            expected_policy_digest=args.expected_policy_digest,
            certificate_path=args.certificate,
            certificate_public_key=args.certificate_public_key,
            certificate_signer_id=args.certificate_signer_id,
        )
        signer = TransparencyAuditReceiptSigner(
            _load_private_key(args.auditor_private_key),
            args.auditor_id,
        )
        receipt = signer.sign(result, bundle, certificate)
        _write_create_only(args.output, receipt.to_dict())
    except Exception as exc:  # noqa: BLE001
        print(
            json.dumps(
                {"valid": False, "error": type(exc).__name__, "detail": str(exc)},
                sort_keys=True,
            )
        )
        return 2

    print(
        json.dumps(
            {
                "valid": True,
                "output": str(args.output),
                "auditor_id": receipt.auditor_id,
                "auditor_public_key": signer.public_key_b64(),
                "transparency_state": receipt.transparency_state,
                "audit_result_digest": receipt.audit_result_digest,
                "claim_boundary": [
                    "signs one independently recomputed transparency audit result",
                    "does not create or rotate auditor identity",
                    "does not decide task completion or grant execution authority",
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
