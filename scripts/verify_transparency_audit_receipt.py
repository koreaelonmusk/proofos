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
from proofos.governance_witness import (  # noqa: E402
    parse_governance_history,
    verify_governance_history,
)
from proofos.governance_witness_policy_rotation import (  # noqa: E402
    GOVERNANCE_WITNESS_POLICY_GENESIS,
    parse_governance_witness_policy,
    parse_governance_witness_policy_history,
    policy_for_governance_generation,
    verify_governance_witness_policy_chain,
)
from proofos.recovery_authority_revocation import (  # noqa: E402
    REVOCATION_GENESIS,
    parse_revocation_registry,
    verify_revocation_registry,
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
    parser.add_argument("--expected-auditor-recovery-policy-history-digest")
    parser.add_argument("--expected-auditor-recovery-policy-digest")
    parser.add_argument("--auditor-recovery-revocations", type=Path)
    parser.add_argument("--expected-auditor-revocation-generation", type=int)
    parser.add_argument("--expected-auditor-revocation-head-digest")
    parser.add_argument("--governance-witness-bundle", type=Path, required=True)
    parser.add_argument("--expected-governance-witness-policy-digest", required=True)
    parser.add_argument("--governance-witness-policy-initial", type=Path)
    parser.add_argument("--governance-witness-policy-history", type=Path)
    parser.add_argument("--expected-governance-witness-policy-generation", type=int)
    parser.add_argument("--expected-governance-witness-policy-history-digest")
    parser.add_argument("--expected-governance-generation", type=int, required=True)
    parser.add_argument("--expected-governance-head-digest", required=True)
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
        governance_history = parse_governance_history(
            _read_json(args.governance_witness_bundle)
        )

        governance_policy_schedule = None
        governance_policy_args = (
            args.governance_witness_policy_initial,
            args.governance_witness_policy_history,
            args.expected_governance_witness_policy_generation,
            args.expected_governance_witness_policy_history_digest,
        )
        if any(value is not None for value in governance_policy_args):
            if args.governance_witness_policy_initial is None:
                raise ValueError("initial governance witness policy is required")
            if args.governance_witness_policy_history is None:
                raise ValueError("governance witness policy history is required")
            if args.expected_governance_witness_policy_generation is None:
                raise ValueError(
                    "expected governance witness policy generation is required"
                )
            if args.expected_governance_witness_policy_history_digest is None:
                raise ValueError(
                    "expected governance witness policy history digest is required"
                )

            initial_governance_policy = parse_governance_witness_policy(
                _read_json(args.governance_witness_policy_initial)
            )
            governance_policy_transitions = (
                parse_governance_witness_policy_history(
                    _read_json(args.governance_witness_policy_history)
                )
            )
            verify_governance_witness_policy_chain(
                initial_policy=initial_governance_policy,
                transitions=governance_policy_transitions,
                expected_generation=(
                    args.expected_governance_witness_policy_generation
                ),
                expected_head_digest=(
                    args.expected_governance_witness_policy_history_digest
                ),
            )
            active_governance_policy = policy_for_governance_generation(
                initial_governance_policy,
                governance_policy_transitions,
                args.expected_governance_generation,
            )
            if (
                active_governance_policy.digest()
                != args.expected_governance_witness_policy_digest
            ):
                raise ValueError(
                    "active governance witness policy digest does not match external pin"
                )

            governance_policy_schedule = tuple(
                policy_for_governance_generation(
                    initial_governance_policy,
                    governance_policy_transitions,
                    generation,
                ).digest()
                for generation in range(1, len(governance_history) + 1)
            )

        governance_quorum = verify_governance_history(
            governance_history,
            expected_policy_digest=(
                None
                if governance_policy_schedule is not None
                else args.expected_governance_witness_policy_digest
            ),
            expected_policy_digests=governance_policy_schedule,
            expected_governance_generation=args.expected_governance_generation,
            expected_governance_head_digest=args.expected_governance_head_digest,
        )
        governance = governance_history[-1].snapshot
        if governance.auditor_history_generation != args.expected_auditor_generation:
            raise ValueError("auditor generation disagrees with governance snapshot")
        if governance.auditor_history_digest != args.expected_auditor_history_digest:
            raise ValueError("auditor history digest disagrees with governance snapshot")
        history = parse_auditor_key_history(
            _read_json(args.auditor_key_history)
        )
        recovery_policy = None
        recovery_policy_generation = None
        recovery_policy_history_digest = None

        continuity_requested = any(
            value is not None
            for value in (
                args.auditor_recovery_policy_history,
                args.expected_auditor_recovery_policy_generation,
                args.expected_auditor_recovery_policy_history_digest,
            )
        )
        static_policy_requested = any(
            value is not None
            for value in (
                args.auditor_recovery_initial_policy,
                args.expected_auditor_recovery_policy_digest,
            )
        )

        if continuity_requested:
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
            if (
                args.expected_auditor_recovery_policy_digest is not None
                and recovery_policy.digest()
                != args.expected_auditor_recovery_policy_digest
            ):
                raise ValueError(
                    "active recovery policy digest does not match external pin"
                )
        elif static_policy_requested:
            if args.auditor_recovery_initial_policy is None:
                raise ValueError("recovery policy is required")
            if args.expected_auditor_recovery_policy_digest is None:
                raise ValueError("expected recovery-policy digest is required")
            recovery_policy = RecoveryPolicy.from_dict(
                _read_json(args.auditor_recovery_initial_policy)
            )
            if recovery_policy.digest() != args.expected_auditor_recovery_policy_digest:
                raise ValueError(
                    "recovery policy digest does not match external pin"
                )
            recovery_policy_generation = 0
            recovery_policy_history_digest = RECOVERY_POLICY_TRANSITION_GENESIS

        revoked_authorities = None
        revocation_generation = None
        revocation_head_digest = None
        revocation_args = (
            args.auditor_recovery_revocations,
            args.expected_auditor_revocation_generation,
            args.expected_auditor_revocation_head_digest,
        )
        if any(value is not None for value in revocation_args):
            if recovery_policy is None:
                raise ValueError(
                    "recovery authority revocations require an active recovery policy"
                )
            if args.auditor_recovery_revocations is None:
                raise ValueError("recovery authority revocation registry is required")
            if args.expected_auditor_revocation_generation is None:
                raise ValueError("expected revocation generation is required")
            if args.expected_auditor_revocation_head_digest is None:
                raise ValueError("expected revocation head digest is required")
            revocations = parse_revocation_registry(
                _read_json(args.auditor_recovery_revocations)
            )
            revoked_authorities = verify_revocation_registry(
                policy=recovery_policy,
                revocations=revocations,
                expected_generation=args.expected_auditor_revocation_generation,
                expected_head_digest=args.expected_auditor_revocation_head_digest,
            )
            revocation_generation = args.expected_auditor_revocation_generation
            revocation_head_digest = args.expected_auditor_revocation_head_digest

        if recovery_policy is not None:
            if governance.recovery_policy_generation != recovery_policy_generation:
                raise ValueError(
                    "recovery policy generation disagrees with governance snapshot"
                )
            if governance.recovery_policy_digest != recovery_policy.digest():
                raise ValueError(
                    "recovery policy digest disagrees with governance snapshot"
                )
            if (
                governance.recovery_policy_history_digest
                != recovery_policy_history_digest
            ):
                raise ValueError(
                    "recovery policy history digest disagrees with governance snapshot"
                )
        else:
            if governance.recovery_policy_generation != 0:
                raise ValueError(
                    "governance snapshot requires recovery policy configuration"
                )
            if governance.recovery_policy_digest != "0" * 64:
                raise ValueError(
                    "governance snapshot commits a generation-zero recovery "
                    "policy, so the recovery policy artifact is required"
                )
            if (
                governance.recovery_policy_history_digest
                != RECOVERY_POLICY_TRANSITION_GENESIS
            ):
                raise ValueError(
                    "governance snapshot has non-genesis recovery policy history "
                    "without recovery policy configuration"
                )
        if revocation_generation is not None:
            if governance.revocation_generation != revocation_generation:
                raise ValueError(
                    "revocation generation disagrees with governance snapshot"
                )
            if governance.revocation_head_digest != revocation_head_digest:
                raise ValueError(
                    "revocation head digest disagrees with governance snapshot"
                )
        elif governance.revocation_generation != 0:
            raise ValueError(
                "governance snapshot requires revocation registry configuration"
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
            revoked_authorities=revoked_authorities,
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
                "governance_generation": governance.governance_generation,
                "governance_head_digest": governance.snapshot_digest(),
                "governance_counted_witnesses": list(
                    governance_quorum.counted_witnesses
                ),
                "governance_witness_policy_generation": (
                    args.expected_governance_witness_policy_generation
                    if args.expected_governance_witness_policy_generation is not None
                    else 0
                ),
                "governance_witness_policy_history_digest": (
                    args.expected_governance_witness_policy_history_digest
                    if args.expected_governance_witness_policy_history_digest is not None
                    else GOVERNANCE_WITNESS_POLICY_GENESIS
                ),
                "auditor_key_generation": args.expected_auditor_generation,
                "auditor_history_digest": args.expected_auditor_history_digest,
                "auditor_recovery_policy_digest": (
                    recovery_policy.digest() if recovery_policy is not None else None
                ),
                "auditor_recovery_policy_generation": recovery_policy_generation,
                "auditor_recovery_policy_history_digest": (
                    recovery_policy_history_digest
                ),
                "auditor_recovery_revocation_generation": revocation_generation,
                "auditor_recovery_revocation_head_digest": revocation_head_digest,
                "transparency_state": receipt.transparency_state,
                "audit_result_digest": receipt.audit_result_digest,
                "checkpoint_digest": receipt.checkpoint_digest,
                "claim_boundary": [
                    "requires N-of-M witnesses to attest every governance snapshot in the pinned history",
                    "derives governance witness policy from a two-quorum continuity chain when rotated",
                    "requires append-only governance snapshot continuity through the externally pinned head",
                    "verifies receipt signature and source-artifact binding",
                    "recomputes transparency from pinned public inputs",
                    "derives the active auditor key from a pinned initial key and verified key history",
                    "derives recovery authority from a pinned initial policy and verified policy history",
                    "requires old-policy and new-policy threshold approval for recovery-policy rotation",
                    "requires pinned N-of-M recovery authority for emergency recovery entries",
                    "rejects recovery approvals from authorities revoked for that auditor generation",
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
