"""Public verification of a signed ProofOS transparency audit receipt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
for entry in (str(ROOT), str(SCRIPTS)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from audit_transparency import _read_json, evaluate_artifacts  # noqa: E402
from proofos.transparency_audit_receipt import (  # noqa: E402
    TransparencyAuditReceipt,
    TransparencyAuditReceiptVerifier,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a signed ProofOS transparency audit receipt"
    )
    parser.add_argument("receipt", type=Path)
    parser.add_argument("gossip", type=Path)
    parser.add_argument("--gossip-public-key", required=True)
    parser.add_argument("--gossip-publisher-id", required=True)
    parser.add_argument("--expected-policy-digest", required=True)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--certificate-public-key")
    parser.add_argument("--certificate-signer-id")
    parser.add_argument("--auditor-public-key", required=True)
    parser.add_argument("--auditor-id", required=True)
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
        receipt = TransparencyAuditReceipt.from_dict(_read_json(args.receipt))
        verifier = TransparencyAuditReceiptVerifier.from_b64(
            args.auditor_public_key,
            args.auditor_id,
        )
        verifier.verify(receipt, result, bundle, certificate)
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
                "auditor_id": receipt.auditor_id,
                "transparency_state": receipt.transparency_state,
                "audit_result_digest": receipt.audit_result_digest,
                "checkpoint_digest": receipt.checkpoint_digest,
                "claim_boundary": [
                    "verifies receipt signature and source-artifact binding",
                    "recomputes transparency from pinned public inputs",
                    "requires no private key or network access",
                    "does not decide task completion or grant execution authority",
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
