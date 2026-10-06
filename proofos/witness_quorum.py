"""N-of-M quorum evaluation for independently signed witness receipts.

Quorum is a transparency property, not a completion verdict. It answers only:
"Did enough distinct, registered witnesses independently sign the same exact
checkpoint commitment?"

Rules:
- only registered witness identities count;
- one witness counts at most once, regardless of how many receipts it submits;
- every counted receipt must verify against its witness record;
- all counted receipts must bind to the same operation, execution, checkpoint
  version, and checkpoint digest;
- conflicting receipts from one witness or across witnesses fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .witness import WitnessRecord
from .witness_receipt import WitnessReceipt, WitnessReceiptVerifier


class WitnessQuorumError(ValueError):
    """Base class for quorum refusal."""


class InvalidQuorumPolicy(WitnessQuorumError):
    pass


class UnknownWitnessError(WitnessQuorumError):
    pass


class WitnessReceiptConflictError(WitnessQuorumError):
    pass


class WitnessQuorumNotMet(WitnessQuorumError):
    pass


@dataclass(frozen=True)
class WitnessVote:
    receipt: WitnessReceipt
    record: WitnessRecord


@dataclass(frozen=True)
class WitnessQuorumResult:
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    required: int
    registered: int
    counted_witnesses: tuple[str, ...]
    quorum_met: bool

    @property
    def count(self) -> int:
        return len(self.counted_witnesses)


def evaluate_witness_quorum(
    votes: Iterable[WitnessVote],
    verifiers: Mapping[str, WitnessReceiptVerifier],
    required: int,
) -> WitnessQuorumResult:
    """Verify and count distinct witness receipts for one checkpoint.

    Raises on malformed policy, unknown identities, invalid signatures/bindings,
    or conflicting checkpoint commitments. A syntactically valid but
    insufficient set returns quorum_met=False so callers may distinguish
    degraded availability from cryptographic corruption.
    """
    registered = len(verifiers)
    if isinstance(required, bool) or not isinstance(required, int):
        raise InvalidQuorumPolicy("required quorum must be an integer")
    if required < 1:
        raise InvalidQuorumPolicy("required quorum must be >= 1")
    if required > registered:
        raise InvalidQuorumPolicy(
            f"required quorum {required} exceeds registered witnesses {registered}"
        )

    by_witness: dict[str, WitnessVote] = {}
    target: tuple[str, str, int, str] | None = None

    for vote in votes:
        receipt = vote.receipt
        record = vote.record
        verifier = verifiers.get(receipt.witness_id)
        if verifier is None:
            raise UnknownWitnessError(
                f"witness {receipt.witness_id!r} is not registered"
            )

        verifier.verify(receipt, record)

        identity = (
            receipt.operation_id,
            receipt.execution_id,
            receipt.checkpoint_version,
            receipt.checkpoint_digest,
        )
        if target is None:
            target = identity
        elif identity != target:
            raise WitnessReceiptConflictError(
                "witness receipts do not bind to the same checkpoint commitment"
            )

        prior = by_witness.get(receipt.witness_id)
        if prior is None:
            by_witness[receipt.witness_id] = vote
            continue

        prior_receipt = prior.receipt
        prior_identity = (
            prior_receipt.operation_id,
            prior_receipt.execution_id,
            prior_receipt.checkpoint_version,
            prior_receipt.checkpoint_digest,
        )
        if identity != prior_identity:
            raise WitnessReceiptConflictError(
                f"witness {receipt.witness_id!r} submitted conflicting checkpoint receipts"
            )

        # Multiple independently valid receipts from the same witness for the
        # same checkpoint are availability duplicates, never extra votes.

    if target is None:
        return WitnessQuorumResult(
            operation_id="",
            execution_id="",
            checkpoint_version=0,
            checkpoint_digest="",
            required=required,
            registered=registered,
            counted_witnesses=(),
            quorum_met=False,
        )

    operation_id, execution_id, checkpoint_version, checkpoint_digest = target
    counted = tuple(sorted(by_witness))
    return WitnessQuorumResult(
        operation_id=operation_id,
        execution_id=execution_id,
        checkpoint_version=checkpoint_version,
        checkpoint_digest=checkpoint_digest,
        required=required,
        registered=registered,
        counted_witnesses=counted,
        quorum_met=len(counted) >= required,
    )


def require_witness_quorum(
    votes: Iterable[WitnessVote],
    verifiers: Mapping[str, WitnessReceiptVerifier],
    required: int,
) -> WitnessQuorumResult:
    """Return a verified quorum result or raise when the threshold is unmet."""
    result = evaluate_witness_quorum(votes, verifiers, required)
    if not result.quorum_met:
        raise WitnessQuorumNotMet(
            f"witness quorum not met: {result.count}/{result.required}"
        )
    return result


__all__ = [
    "InvalidQuorumPolicy",
    "UnknownWitnessError",
    "WitnessQuorumError",
    "WitnessQuorumNotMet",
    "WitnessQuorumResult",
    "WitnessReceiptConflictError",
    "WitnessVote",
    "evaluate_witness_quorum",
    "require_witness_quorum",
]
