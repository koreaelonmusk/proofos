"""Offline public audit for ProofOS witness transparency artifacts.

This command verifies transport provenance, independently recomputes witness
quorum, and binds any quorum certificate to that recomputed result. It does not
contact ProofOS services and does not decide whether the underlying task is
complete.

Exit codes:
  0 transparency ACCEPTED
  3 transparency HOLD
  4 transparency REJECTED
  2 malformed/forged/unverifiable input
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from proofos.quorum_certificate import (
    QuorumCertificate,
    QuorumCertificateVerifier,
)
from proofos.transparency_gate import (
    TransparencyState,
    evaluate_transparency,
)
from proofos.witness_gossip import WitnessGossipBundle, WitnessGossipVerifier


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"could not read JSON artifact {path}: {type(exc).__name__}"
        ) from exc


def audit(
    *,
    gossip_path: Path,
    gossip_public_key: str,
    gossip_publisher_id: str,
    expected_policy_digest: str,
    certificate_path: Path | None = None,
    certificate_public_key: str | None = None,
    certificate_signer_id: str | None = None,
) -> dict[str, Any]:
    bundle = WitnessGossipBundle.from_dict(_read_json(gossip_path))
    gossip_verifier = WitnessGossipVerifier.from_b64(
        gossip_public_key,
        gossip_publisher_id,
    )

    certificate = None
    certificate_verifier = None
    if certificate_path is not None:
        if not certificate_public_key or not certificate_signer_id:
            raise ValueError(
                "certificate public key and signer id are required with certificate"
            )
        certificate = QuorumCertificate.from_dict(_read_json(certificate_path))
        certificate_verifier = QuorumCertificateVerifier.from_b64(
            certificate_public_key,
            certificate_signer_id,
        )
    elif certificate_public_key or certificate_signer_id:
        raise ValueError(
            "certificate key/signer configuration requires --certificate"
        )

    result = evaluate_transparency(
        bundle,
        gossip_verifier=gossip_verifier,
        expected_policy_digest=expected_policy_digest,
        certificate=certificate,
        certificate_verifier=certificate_verifier,
    )
    return {
        "valid": True,
        "transparency_state": str(result.state),
        "accepted": result.accepted,
        "policy_digest": result.policy_digest,
        "operation_id": result.operation_id,
        "execution_id": result.execution_id,
        "checkpoint_version": result.checkpoint_version,
        "checkpoint_digest": result.checkpoint_digest,
        "counted_witnesses": list(result.counted_witnesses),
        "required": result.required,
        "gossip_publisher_id": result.gossip_publisher_id,
        "certificate_signer_id": result.certificate_signer_id,
        "claim_boundary": [
            "verifies witness transparency evidence only",
            "does not decide ProofOS task completion",
            "does not grant execution, evidence, or capability authority",
            "does not require network access or private keys",
        ],
    }


def _exit_code(state: str) -> int:
    if state == str(TransparencyState.ACCEPTED):
        return 0
    if state in {
        str(TransparencyState.HOLD_INSUFFICIENT),
        str(TransparencyState.HOLD_CERTIFICATE_REQUIRED),
    }:
        return 3
    if state == str(TransparencyState.REJECTED_SPLIT_VIEW):
        return 4
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Offline ProofOS witness transparency audit"
    )
    parser.add_argument("gossip", type=Path)
    parser.add_argument("--gossip-public-key", required=True)
    parser.add_argument("--gossip-publisher-id", required=True)
    parser.add_argument("--expected-policy-digest", required=True)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--certificate-public-key")
    parser.add_argument("--certificate-signer-id")
    args = parser.parse_args()

    try:
        report = audit(
            gossip_path=args.gossip,
            gossip_public_key=args.gossip_public_key,
            gossip_publisher_id=args.gossip_publisher_id,
            expected_policy_digest=args.expected_policy_digest,
            certificate_path=args.certificate,
            certificate_public_key=args.certificate_public_key,
            certificate_signer_id=args.certificate_signer_id,
        )
    except Exception as exc:  # noqa: BLE001 - CLI must fail closed on any verifier error
        print(
            json.dumps(
                {
                    "valid": False,
                    "error": type(exc).__name__,
                    "detail": str(exc),
                },
                sort_keys=True,
            )
        )
        return 2

    print(json.dumps(report, sort_keys=True))
    return _exit_code(report["transparency_state"])


if __name__ == "__main__":
    raise SystemExit(main())
