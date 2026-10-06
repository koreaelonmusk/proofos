"""Pinned N-of-M quorum over independently signed witness receipts.

Quorum is transparency evidence, never a ProofOS completion verdict. It answers
only whether enough distinct configured witnesses accepted the same checkpoint
commitment.

The quorum policy is content-addressed and callers must supply the externally
pinned expected digest. A runtime actor therefore cannot silently downgrade
2-of-3 into 1-of-1 and still produce an accepted quorum result.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Mapping

from .integrity import content_hash
from .witness import WitnessRecord
from .witness_receipt import WitnessReceipt, WitnessReceiptVerifier


class WitnessQuorumError(ValueError):
    """Base class for quorum refusal."""


class WitnessQuorumPolicyError(WitnessQuorumError):
    pass


class WitnessQuorumScopeError(WitnessQuorumError):
    pass


class WitnessQuorumState(StrEnum):
    QUORUM = "QUORUM"
    INSUFFICIENT = "INSUFFICIENT"
    SPLIT_VIEW = "SPLIT_VIEW"


@dataclass(frozen=True)
class WitnessQuorumPolicy:
    policy_id: str
    witness_ids: tuple[str, ...]
    threshold: int

    def __post_init__(self) -> None:
        if not self.policy_id.strip():
            raise WitnessQuorumPolicyError("policy_id must not be empty")
        if not self.witness_ids:
            raise WitnessQuorumPolicyError("quorum policy must name witnesses")
        if any(not witness_id.strip() for witness_id in self.witness_ids):
            raise WitnessQuorumPolicyError("witness ids must not be empty")
        if len(set(self.witness_ids)) != len(self.witness_ids):
            raise WitnessQuorumPolicyError("quorum policy contains duplicate witnesses")
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise WitnessQuorumPolicyError("threshold must be an integer")
        if self.threshold < 1 or self.threshold > len(self.witness_ids):
            raise WitnessQuorumPolicyError(
                "threshold must be between 1 and the configured witness count"
            )

    def digest(self) -> str:
        return content_hash(
            {
                "policy_id": self.policy_id,
                "witness_ids": sorted(self.witness_ids),
                "threshold": self.threshold,
            }
        )


@dataclass(frozen=True)
class WitnessVote:
    receipt: WitnessReceipt
    record: WitnessRecord

    @property
    def scope(self) -> tuple[str, str, int]:
        return (
            self.record.operation_id,
            self.record.execution_id,
            self.record.checkpoint_version,
        )

    @property
    def commitment(self) -> tuple[str, str, int, str, str, int, str]:
        return (
            self.record.operation_id,
            self.record.execution_id,
            self.record.checkpoint_version,
            self.record.checkpoint_digest,
            self.record.signer_id,
            self.record.last_journal_sequence,
            self.record.last_journal_hash,
        )

    @property
    def commitment_hash(self) -> str:
        return content_hash(
            {
                "operation_id": self.record.operation_id,
                "execution_id": self.record.execution_id,
                "checkpoint_version": self.record.checkpoint_version,
                "checkpoint_digest": self.record.checkpoint_digest,
                "signer_id": self.record.signer_id,
                "last_journal_sequence": self.record.last_journal_sequence,
                "last_journal_hash": self.record.last_journal_hash,
            }
        )


@dataclass(frozen=True)
class WitnessQuorumResult:
    state: WitnessQuorumState
    policy_digest: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    counted_witnesses: tuple[str, ...]
    required: int
    conflicting_commitment_hashes: tuple[str, ...] = ()

    @property
    def count(self) -> int:
        return len(self.counted_witnesses)

    @property
    def quorum_met(self) -> bool:
        return self.state is WitnessQuorumState.QUORUM


def evaluate_witness_quorum(
    votes: Iterable[WitnessVote],
    *,
    verifiers: Mapping[str, WitnessReceiptVerifier],
    policy: WitnessQuorumPolicy,
    expected_policy_digest: str,
) -> WitnessQuorumResult:
    """Verify signed votes against one externally pinned threshold policy."""
    policy_digest = policy.digest()
    if expected_policy_digest != policy_digest:
        raise WitnessQuorumPolicyError(
            "quorum policy digest does not match externally pinned policy"
        )

    allowed = set(policy.witness_ids)
    verified: list[WitnessVote] = []
    for vote in votes:
        witness_id = vote.receipt.witness_id
        if witness_id not in allowed:
            raise WitnessQuorumPolicyError(
                f"witness {witness_id!r} is not allowed by quorum policy"
            )
        verifier = verifiers.get(witness_id)
        if verifier is None:
            raise WitnessQuorumPolicyError(
                f"no verifier configured for witness {witness_id!r}"
            )
        verifier.verify(vote.receipt, vote.record)
        verified.append(vote)

    if not verified:
        return WitnessQuorumResult(
            state=WitnessQuorumState.INSUFFICIENT,
            policy_digest=policy_digest,
            operation_id="",
            execution_id="",
            checkpoint_version=0,
            checkpoint_digest="",
            counted_witnesses=(),
            required=policy.threshold,
        )

    scope = verified[0].scope
    for vote in verified[1:]:
        if vote.scope != scope:
            raise WitnessQuorumScopeError(
                "quorum inputs span different operation/execution/checkpoint scopes"
            )

    by_witness: dict[str, WitnessVote] = {}
    duplicate_conflict = False
    conflicting_hashes: set[str] = set()

    for vote in verified:
        witness_id = vote.receipt.witness_id
        prior = by_witness.get(witness_id)
        if prior is None:
            by_witness[witness_id] = vote
            continue
        if prior.commitment != vote.commitment:
            duplicate_conflict = True
            conflicting_hashes.add(prior.commitment_hash)
            conflicting_hashes.add(vote.commitment_hash)

    commitments = {vote.commitment for vote in by_witness.values()}
    if len(commitments) > 1:
        conflicting_hashes.update(
            vote.commitment_hash for vote in by_witness.values()
        )

    operation_id, execution_id, checkpoint_version = scope
    counted = tuple(sorted(by_witness))

    if duplicate_conflict or len(commitments) > 1:
        return WitnessQuorumResult(
            state=WitnessQuorumState.SPLIT_VIEW,
            policy_digest=policy_digest,
            operation_id=operation_id,
            execution_id=execution_id,
            checkpoint_version=checkpoint_version,
            checkpoint_digest="",
            counted_witnesses=counted,
            required=policy.threshold,
            conflicting_commitment_hashes=tuple(sorted(conflicting_hashes)),
        )

    checkpoint_digest = next(iter(by_witness.values())).record.checkpoint_digest
    state = (
        WitnessQuorumState.QUORUM
        if len(by_witness) >= policy.threshold
        else WitnessQuorumState.INSUFFICIENT
    )
    return WitnessQuorumResult(
        state=state,
        policy_digest=policy_digest,
        operation_id=operation_id,
        execution_id=execution_id,
        checkpoint_version=checkpoint_version,
        checkpoint_digest=checkpoint_digest,
        counted_witnesses=counted,
        required=policy.threshold,
    )


__all__ = [
    "WitnessQuorumError",
    "WitnessQuorumPolicy",
    "WitnessQuorumPolicyError",
    "WitnessQuorumResult",
    "WitnessQuorumScopeError",
    "WitnessQuorumState",
    "WitnessVote",
    "evaluate_witness_quorum",
]
