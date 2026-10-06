"""Transparency acceptance gate over gossip and quorum certificates.

This gate decides whether independent witness transparency evidence is complete
enough to accept as a transport/audit statement. It never decides whether the
underlying task is complete and carries no evidence, capability, or execution
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .quorum_certificate import (
    QuorumCertificate,
    QuorumCertificateVerifier,
)
from .witness_gossip import WitnessGossipBundle, WitnessGossipVerifier
from .witness_quorum import WitnessQuorumState


class TransparencyState(StrEnum):
    ACCEPTED = "ACCEPTED"
    HOLD_INSUFFICIENT = "HOLD_INSUFFICIENT"
    HOLD_CERTIFICATE_REQUIRED = "HOLD_CERTIFICATE_REQUIRED"
    REJECTED_SPLIT_VIEW = "REJECTED_SPLIT_VIEW"


class TransparencyGateError(ValueError):
    pass


@dataclass(frozen=True)
class TransparencyResult:
    state: TransparencyState
    policy_digest: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    counted_witnesses: tuple[str, ...]
    required: int
    gossip_publisher_id: str
    certificate_signer_id: str | None = None

    @property
    def accepted(self) -> bool:
        return self.state is TransparencyState.ACCEPTED


def evaluate_transparency(
    bundle: WitnessGossipBundle,
    *,
    gossip_verifier: WitnessGossipVerifier,
    expected_policy_digest: str,
    certificate: QuorumCertificate | None = None,
    certificate_verifier: QuorumCertificateVerifier | None = None,
) -> TransparencyResult:
    """Independently recompute gossip, then bind any quorum certificate to it."""
    quorum = gossip_verifier.verify(
        bundle,
        expected_policy_digest=expected_policy_digest,
    )

    base = dict(
        policy_digest=quorum.policy_digest,
        operation_id=quorum.operation_id,
        execution_id=quorum.execution_id,
        checkpoint_version=quorum.checkpoint_version,
        checkpoint_digest=quorum.checkpoint_digest,
        counted_witnesses=quorum.counted_witnesses,
        required=quorum.required,
        gossip_publisher_id=bundle.publisher_id,
    )

    if quorum.state is WitnessQuorumState.SPLIT_VIEW:
        if certificate is not None or certificate_verifier is not None:
            raise TransparencyGateError(
                "split-view transparency evidence cannot carry a quorum certificate"
            )
        return TransparencyResult(
            state=TransparencyState.REJECTED_SPLIT_VIEW,
            certificate_signer_id=None,
            **base,
        )

    if quorum.state is WitnessQuorumState.INSUFFICIENT:
        if certificate is not None or certificate_verifier is not None:
            raise TransparencyGateError(
                "insufficient witness evidence cannot carry a quorum certificate"
            )
        return TransparencyResult(
            state=TransparencyState.HOLD_INSUFFICIENT,
            certificate_signer_id=None,
            **base,
        )

    if certificate is None or certificate_verifier is None:
        return TransparencyResult(
            state=TransparencyState.HOLD_CERTIFICATE_REQUIRED,
            certificate_signer_id=None,
            **base,
        )

    certificate_verifier.verify(certificate, quorum)
    return TransparencyResult(
        state=TransparencyState.ACCEPTED,
        certificate_signer_id=certificate.signer_id,
        **base,
    )


__all__ = [
    "TransparencyGateError",
    "TransparencyResult",
    "TransparencyState",
    "evaluate_transparency",
]
