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
from proofos.auditor_key_recovery import (  # noqa: E402
    RecoveryPolicy,
    parse_auditor_key_history,
    verify_auditor_key_history,
)
from proofos.recovery_policy_rotation import (  # noqa: E402
    RECOVERY_POLICY_TRANSITION_GENESIS,
    parse_recovery_policy_history,
    verify_recovery_policy_chain,
)
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
    parser.add_argument("--auditor-initial-public-key", required=True)
    parser.add_argument(
        "--auditor-key-history",
        "--auditor-key-transitions",
        dest="auditor_key_history",
        type=Path,
        required=True,
    )
    parser.add_argument("--expected-auditor-generation", type=int, required=True)
    parser.add_argument(
        "--expected-auditor-history-digest",
        "--expected-auditor-transition-digest",
        dest="expected_auditor_history_digest",
        required=True,
    )
    parser.add_argument(
        "--auditor-recovery-initial-policy",
        "--auditor-recovery-policy",
        dest="auditor_recovery_initial_policy",
        type=Path,
    )
    parser.add_argument("--auditor-recovery-policy-history", type=Path)
    parser.add_argument(
        "--expected-auditor-recovery-policy-generation", type=int
    )
    parser.add_argument(
        "--expected-auditor-recovery-policy-history-digest",
        "--expected-auditor-recovery-policy-digest",
        dest="expected_auditor_recovery_policy_history_digest",
    )
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
        history = parse_auditor_key_history(
            _read_json(args.auditor_key_history)
        )
        recovery_policy = None
        recovery_policy_generation = None
        recovery_policy_history_digest = None
        recovery_policy_args = (
            args.auditor_recovery_initial_policy,
            args.auditor_recovery_policy_history,
            args.expected_auditor_recovery_policy_generation,
            args.expected_auditor_recovery_policy_history_digest,
        )
        if any(value is not None for value in recovery_policy_args):
            if args.auditor_recovery_initial_policy is None:
                raise ValueError("initial recovery policy is required")
            if args.auditor_recovery_policy_history is None:
                raise ValueError("recovery policy history is required")
            if args.expected_auditor_recovery_policy_generation is None:
                raise ValueError("expected recovery policy generation is required")
            if args.expected_auditor_recovery_policy_history_digest is None:
                raise ValueError("expected recovery policy history digest is required")

            initial_recovery_policy = RecoveryPolicy.from_dict(
                _read_json(args.auditor_recovery_initial_policy)
            )
            recovery_policy_history = parse_recovery_policy_history(
                _read_json(args.auditor_recovery_policy_history)
            )
            recovery_policy = verify_recovery_policy_chain(
                initial_policy=initial_recovery_policy,
                transitions=recovery_policy_history,
                expected_generation=args.expected_auditor_recovery_policy_generation,
                expected_head_digest=(
                    args.expected_auditor_recovery_policy_history_digest
                ),
            )
            recovery_policy_generation = (
                args.expected_auditor_recovery_policy_generation
            )
            recovery_policy_history_digest = (
                args.expected_auditor_recovery_policy_history_digest
            )
        trusted_auditor_key = verify_auditor_key_history(
            auditor_id=args.auditor_id,
            initial_public_key=args.auditor_initial_public_key,
            entries=history,
            expected_generation=args.expected_auditor_generation,
            expected_head_digest=args.expected_auditor_history_digest,
            recovery_policy=recovery_policy,
            expected_recovery_policy_digest=(
                recovery_policy.digest() if recovery_policy is not None else None
            ),
        )
        verifier = TransparencyAuditReceiptVerifier.from_b64(
            trusted_auditor_key,
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
                "auditor_key_generation": args.expected_auditor_generation,
                "auditor_history_digest": args.expected_auditor_history_digest,
                "auditor_recovery_policy_digest": (
                    recovery_policy.digest() if recovery_policy is not None else None
                ),
                "auditor_recovery_policy_generation": recovery_policy_generation,
                "auditor_recovery_policy_history_digest": (
                    recovery_policy_history_digest
                ),
                "transparency_state": receipt.transparency_state,
                "audit_result_digest": receipt.audit_result_digest,
                "checkpoint_digest": receipt.checkpoint_digest,
                "claim_boundary": [
                    "verifies receipt signature and source-artifact binding",
                    "recomputes transparency from pinned public inputs",
                    "derives the active auditor key from a pinned initial key and verified key history",
                    "derives recovery authority from a pinned initial policy and verified policy history",
                    "requires old-policy and new-policy threshold approval for recovery-policy rotation",
                    "requires pinned N-of-M recovery authority for emergency recovery entries",
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
