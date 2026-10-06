"""Independent append-only witness ledger for signed checkpoints.

A witness does not decide whether work is complete. It verifies a signed
checkpoint, then records that commitment outside the primary continuity store.
Its job is narrower and more mechanical: detect rollback, skipped history,
equivocation, signer drift, and witness-ledger tampering.

The reference implementation is in-memory so the contract can be tested without
cloud credentials. Durable transport/storage can implement the same protocol.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Protocol

from .checkpoint_attestation import (
    CheckpointVerifier,
    SignedCheckpoint,
)
from .continuity import OperationCheckpoint
from .integrity import content_hash

WITNESS_RECORD_VERSION = "proofos.witness.v1"
WITNESS_GENESIS = "0" * 64


class WitnessError(RuntimeError):
    """Base class for witness refusal."""


class WitnessRollbackError(WitnessError):
    pass


class WitnessGapError(WitnessError):
    pass


class WitnessEquivocationError(WitnessError):
    pass


class WitnessSignerDriftError(WitnessError):
    pass


class WitnessIntegrityError(WitnessError):
    pass


@dataclass(frozen=True)
class WitnessRecord:
    version: str
    witness_id: str
    signer_id: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    last_journal_sequence: int
    last_journal_hash: str
    checkpoint_signature: str
    observed_at: float
    previous_record_hash: str
    record_hash: str = field(default="", compare=False)

    def unsigned_fields(self) -> dict:
        return {
            "version": self.version,
            "witness_id": self.witness_id,
            "signer_id": self.signer_id,
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "checkpoint_version": self.checkpoint_version,
            "checkpoint_digest": self.checkpoint_digest,
            "last_journal_sequence": self.last_journal_sequence,
            "last_journal_hash": self.last_journal_hash,
            "checkpoint_signature": self.checkpoint_signature,
            "observed_at": self.observed_at,
            "previous_record_hash": self.previous_record_hash,
        }

    def compute_hash(self) -> str:
        return content_hash(self.unsigned_fields())

    @property
    def intact(self) -> bool:
        return self.record_hash == self.compute_hash()

    def to_dict(self) -> dict:
        return {**self.unsigned_fields(), "record_hash": self.record_hash}


class WitnessLedger(Protocol):
    def observe(
        self,
        envelope: SignedCheckpoint,
        checkpoint: OperationCheckpoint,
        verifier: CheckpointVerifier,
        observed_at: float | None = None,
    ) -> WitnessRecord: ...

    def history(self, operation_id: str) -> tuple[WitnessRecord, ...]: ...

    def verify(self, operation_id: str) -> tuple[bool, tuple[str, ...]]: ...


@dataclass
class InMemoryWitnessLedger:
    """Reference witness enforcing complete monotonic checkpoint history."""

    witness_id: str
    _records: dict[str, list[WitnessRecord]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.witness_id.strip():
            raise ValueError("witness_id must not be empty")

    def observe(
        self,
        envelope: SignedCheckpoint,
        checkpoint: OperationCheckpoint,
        verifier: CheckpointVerifier,
        observed_at: float | None = None,
    ) -> WitnessRecord:
        verifier.verify(envelope, checkpoint)

        stamp = time.time() if observed_at is None else float(observed_at)
        if not math.isfinite(stamp):
            raise WitnessIntegrityError("witness observed_at must be finite")
        if stamp < envelope.issued_at:
            raise WitnessIntegrityError(
                "witness observation cannot predate signed checkpoint issuance"
            )

        history = self._records.setdefault(envelope.operation_id, [])
        if history:
            latest = history[-1]
            if not latest.intact:
                raise WitnessIntegrityError("existing witness tail failed integrity")
            if envelope.signer_id != latest.signer_id:
                raise WitnessSignerDriftError(
                    f"{envelope.operation_id}: signer changed from "
                    f"{latest.signer_id!r} to {envelope.signer_id!r}"
                )
            if envelope.execution_id != latest.execution_id:
                raise WitnessEquivocationError(
                    f"{envelope.operation_id}: execution_id changed across checkpoints"
                )
            if envelope.checkpoint_version < latest.checkpoint_version:
                raise WitnessRollbackError(
                    f"{envelope.operation_id}: checkpoint rollback "
                    f"{envelope.checkpoint_version} < {latest.checkpoint_version}"
                )
            if envelope.checkpoint_version == latest.checkpoint_version:
                if (
                    envelope.checkpoint_digest == latest.checkpoint_digest
                    and envelope.signature == latest.checkpoint_signature
                ):
                    return latest
                raise WitnessEquivocationError(
                    f"{envelope.operation_id}: conflicting checkpoint at version "
                    f"{envelope.checkpoint_version}"
                )
            expected = latest.checkpoint_version + 1
            if envelope.checkpoint_version != expected:
                raise WitnessGapError(
                    f"{envelope.operation_id}: expected checkpoint version "
                    f"{expected}, got {envelope.checkpoint_version}"
                )
            previous_hash = latest.record_hash
        else:
            if envelope.checkpoint_version != 1:
                raise WitnessGapError(
                    f"{envelope.operation_id}: first witnessed checkpoint must be "
                    f"version 1, got {envelope.checkpoint_version}"
                )
            previous_hash = WITNESS_GENESIS

        record = WitnessRecord(
            version=WITNESS_RECORD_VERSION,
            witness_id=self.witness_id,
            signer_id=envelope.signer_id,
            operation_id=envelope.operation_id,
            execution_id=envelope.execution_id,
            checkpoint_version=envelope.checkpoint_version,
            checkpoint_digest=envelope.checkpoint_digest,
            last_journal_sequence=envelope.last_journal_sequence,
            last_journal_hash=envelope.last_journal_hash,
            checkpoint_signature=envelope.signature,
            observed_at=stamp,
            previous_record_hash=previous_hash,
        )
        record = WitnessRecord(**{**record.unsigned_fields(), "record_hash": record.compute_hash()})
        history.append(record)
        return record

    def history(self, operation_id: str) -> tuple[WitnessRecord, ...]:
        return tuple(self._records.get(operation_id, ()))

    def verify(self, operation_id: str) -> tuple[bool, tuple[str, ...]]:
        records = self.history(operation_id)
        problems: list[str] = []
        previous = WITNESS_GENESIS

        for index, record in enumerate(records):
            if not record.intact:
                problems.append(
                    f"witness record {index} does not match its content hash"
                )
            if record.previous_record_hash != previous:
                problems.append(
                    f"witness record {index} does not follow its predecessor"
                )
            if record.checkpoint_version != index + 1:
                problems.append(
                    f"witness checkpoint version {record.checkpoint_version} "
                    f"does not match position {index + 1}"
                )
            if index:
                prior = records[index - 1]
                if record.signer_id != prior.signer_id:
                    problems.append(f"witness signer drift at record {index}")
                if record.execution_id != prior.execution_id:
                    problems.append(f"witness execution drift at record {index}")
            previous = record.record_hash

        return (not problems), tuple(problems)


__all__ = [
    "InMemoryWitnessLedger",
    "WITNESS_GENESIS",
    "WITNESS_RECORD_VERSION",
    "WitnessEquivocationError",
    "WitnessError",
    "WitnessGapError",
    "WitnessIntegrityError",
    "WitnessLedger",
    "WitnessRecord",
    "WitnessRollbackError",
    "WitnessSignerDriftError",
]
