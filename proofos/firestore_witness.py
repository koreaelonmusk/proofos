"""Durable Firestore-backed witness ledger.

The in-memory witness proves the transition rules. This adapter adds durable,
transactional storage for those rules without changing their authority.

Important trust boundary: durable storage is not automatically an independent
witness. A deployment may claim operational independence only when the injected
Firestore client is owned and governed outside the primary ProofOS continuity
store's administrative boundary. This module cannot prove that deployment fact.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from .checkpoint_attestation import CheckpointVerifier, SignedCheckpoint
from .continuity import OperationCheckpoint
from .witness import (
    WITNESS_GENESIS,
    WITNESS_RECORD_VERSION,
    WitnessEquivocationError,
    WitnessError,
    WitnessGapError,
    WitnessIntegrityError,
    WitnessRecord,
    WitnessRollbackError,
    WitnessSignerDriftError,
)

WITNESS_OPERATIONS_COLLECTION = "witness_operations"
WITNESS_RECORDS_COLLECTION = "records"
WITNESS_SEQUENCE_ID_WIDTH = 12


class WitnessUnavailableError(WitnessError):
    """The durable witness store could not be read or written safely."""


def _sequence_id(version: int) -> str:
    return str(version).zfill(WITNESS_SEQUENCE_ID_WIDTH)


def _default_transactional() -> Callable:
    from google.cloud import firestore  # imported lazily: optional at import time

    return firestore.transactional


def _already_exists_error() -> type[Exception]:
    try:
        from google.api_core import exceptions

        return exceptions.AlreadyExists
    except ImportError:  # pragma: no cover - only when the client is absent
        return FileExistsError


def _record_from_dict(data: Any) -> WitnessRecord:
    if not isinstance(data, dict):
        raise WitnessIntegrityError("stored witness record is not an object")
    try:
        record = WitnessRecord(
            version=str(data["version"]),
            witness_id=str(data["witness_id"]),
            signer_id=str(data["signer_id"]),
            operation_id=str(data["operation_id"]),
            execution_id=str(data["execution_id"]),
            checkpoint_version=int(data["checkpoint_version"]),
            checkpoint_digest=str(data["checkpoint_digest"]),
            last_journal_sequence=int(data["last_journal_sequence"]),
            last_journal_hash=str(data["last_journal_hash"]),
            checkpoint_signature=str(data["checkpoint_signature"]),
            observed_at=float(data["observed_at"]),
            previous_record_hash=str(data["previous_record_hash"]),
            record_hash=str(data["record_hash"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise WitnessIntegrityError(
            f"malformed stored witness record: {type(exc).__name__}: {exc}"
        ) from exc
    if record.version != WITNESS_RECORD_VERSION:
        raise WitnessIntegrityError(
            f"unsupported witness record version {record.version!r}"
        )
    if not record.intact:
        raise WitnessIntegrityError("stored witness record failed content integrity")
    return record


def _head_payload(record: WitnessRecord) -> dict[str, Any]:
    return {
        "operation_id": record.operation_id,
        "witness_id": record.witness_id,
        "signer_id": record.signer_id,
        "execution_id": record.execution_id,
        "latest_checkpoint_version": record.checkpoint_version,
        "head_record_hash": record.record_hash,
    }


class FirestoreWitnessLedger:
    """Append-only witness ledger with transactional compare-and-set semantics."""

    def __init__(
        self,
        client: Any,
        witness_id: str,
        transactional: Callable | None = None,
        root_collection: str = WITNESS_OPERATIONS_COLLECTION,
    ) -> None:
        if not witness_id.strip():
            raise ValueError("witness_id must not be empty")
        self._client = client
        self.witness_id = witness_id
        self._transactional = transactional or _default_transactional()
        self._root = root_collection
        self._already_exists = _already_exists_error()

    def _operation_ref(self, operation_id: str):
        return self._client.collection(self._root).document(operation_id)

    def _records_ref(self, operation_id: str):
        return self._operation_ref(operation_id).collection(WITNESS_RECORDS_COLLECTION)

    def _validate_latest(
        self,
        operation_id: str,
        head: dict[str, Any],
        latest: WitnessRecord,
    ) -> None:
        try:
            head_operation = str(head["operation_id"])
            head_witness = str(head["witness_id"])
            head_signer = str(head["signer_id"])
            head_execution = str(head["execution_id"])
            head_version = int(head["latest_checkpoint_version"])
            head_hash = str(head["head_record_hash"])
        except (KeyError, TypeError, ValueError) as exc:
            raise WitnessIntegrityError(
                f"malformed witness head for {operation_id}: {exc}"
            ) from exc

        if head_operation != operation_id:
            raise WitnessIntegrityError(
                f"witness head operation mismatch: {head_operation!r} != {operation_id!r}"
            )
        if head_witness != self.witness_id or latest.witness_id != self.witness_id:
            raise WitnessIntegrityError(
                f"{operation_id}: durable witness id does not match configured witness"
            )
        if latest.operation_id != operation_id:
            raise WitnessIntegrityError(
                f"{operation_id}: stored witness record belongs to another operation"
            )
        if latest.checkpoint_version != head_version:
            raise WitnessIntegrityError(
                f"{operation_id}: witness head version does not match latest record"
            )
        if latest.record_hash != head_hash:
            raise WitnessIntegrityError(
                f"{operation_id}: witness head hash does not match latest record"
            )
        if latest.signer_id != head_signer:
            raise WitnessIntegrityError(
                f"{operation_id}: witness head signer does not match latest record"
            )
        if latest.execution_id != head_execution:
            raise WitnessIntegrityError(
                f"{operation_id}: witness head execution does not match latest record"
            )

    def _transition(
        self,
        envelope: SignedCheckpoint,
        latest: WitnessRecord | None,
    ) -> tuple[str, WitnessRecord | None]:
        if latest is None:
            if envelope.checkpoint_version != 1:
                raise WitnessGapError(
                    f"{envelope.operation_id}: first witnessed checkpoint must be "
                    f"version 1, got {envelope.checkpoint_version}"
                )
            return WITNESS_GENESIS, None

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
                return latest.record_hash, latest
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
        return latest.record_hash, None

    def observe(
        self,
        envelope: SignedCheckpoint,
        checkpoint: OperationCheckpoint,
        verifier: CheckpointVerifier,
        observed_at: float | None = None,
    ) -> WitnessRecord:
        verifier.verify(envelope, checkpoint)

        stamp = time.time() if observed_at is None else float(observed_at)
        if stamp < envelope.issued_at:
            raise WitnessIntegrityError(
                "witness observation cannot predate signed checkpoint issuance"
            )

        operation_ref = self._operation_ref(envelope.operation_id)
        records_ref = self._records_ref(envelope.operation_id)

        def operation(transaction):
            head_snapshot = operation_ref.get(transaction=transaction)
            latest: WitnessRecord | None = None
            head_exists = getattr(head_snapshot, "exists", False)
            if head_exists:
                head = head_snapshot.to_dict() or {}
                try:
                    latest_version = int(head["latest_checkpoint_version"])
                except (KeyError, TypeError, ValueError) as exc:
                    raise WitnessIntegrityError(
                        f"malformed witness head for {envelope.operation_id}: {exc}"
                    ) from exc
                latest_snapshot = records_ref.document(
                    _sequence_id(latest_version)
                ).get(transaction=transaction)
                if not getattr(latest_snapshot, "exists", False):
                    raise WitnessIntegrityError(
                        f"{envelope.operation_id}: witness head points to a missing record"
                    )
                latest = _record_from_dict(latest_snapshot.to_dict())
                self._validate_latest(envelope.operation_id, head, latest)

            previous_hash, replay = self._transition(envelope, latest)
            if replay is not None:
                return replay

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
            record = WitnessRecord(
                **{**record.unsigned_fields(), "record_hash": record.compute_hash()}
            )
            transaction.create(
                records_ref.document(_sequence_id(record.checkpoint_version)),
                record.to_dict(),
            )
            if head_exists:
                transaction.set(operation_ref, _head_payload(record))
            else:
                transaction.create(operation_ref, _head_payload(record))
            return record

        try:
            transaction = self._client.transaction()
            return self._transactional(operation)(transaction)
        except self._already_exists:
            # A competing writer may have committed the same checkpoint between
            # our read and commit. Re-read canonical state and classify it as an
            # exact replay or equivocation instead of hiding the race.
            return self._resolve_commit_race(envelope)
        except WitnessError:
            raise
        except Exception as exc:  # noqa: BLE001 - durable audit loss must fail closed
            raise WitnessUnavailableError(
                f"firestore witness append failed for {envelope.operation_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def _resolve_commit_race(self, envelope: SignedCheckpoint) -> WitnessRecord:
        try:
            head_snapshot = self._operation_ref(envelope.operation_id).get()
            if not getattr(head_snapshot, "exists", False):
                raise WitnessUnavailableError(
                    f"{envelope.operation_id}: concurrent witness write lost its head"
                )
            head = head_snapshot.to_dict() or {}
            version = int(head["latest_checkpoint_version"])
            snapshot = self._records_ref(envelope.operation_id).document(
                _sequence_id(version)
            ).get()
            if not getattr(snapshot, "exists", False):
                raise WitnessUnavailableError(
                    f"{envelope.operation_id}: concurrent witness write lost its record"
                )
            latest = _record_from_dict(snapshot.to_dict())
            self._validate_latest(envelope.operation_id, head, latest)
            _, replay = self._transition(envelope, latest)
            if replay is not None:
                return replay
            raise WitnessUnavailableError(
                f"{envelope.operation_id}: concurrent witness state advanced unexpectedly"
            )
        except WitnessError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WitnessUnavailableError(
                f"failed to resolve witness write race for {envelope.operation_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def history(self, operation_id: str) -> tuple[WitnessRecord, ...]:
        try:
            records = [
                _record_from_dict(snapshot.to_dict())
                for snapshot in self._records_ref(operation_id).stream()
            ]
        except WitnessError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WitnessUnavailableError(
                f"firestore witness read failed for {operation_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        records.sort(key=lambda record: record.checkpoint_version)
        for record in records:
            if record.operation_id != operation_id:
                raise WitnessIntegrityError(
                    f"{operation_id}: stored witness history contains another operation"
                )
            if record.witness_id != self.witness_id:
                raise WitnessIntegrityError(
                    f"{operation_id}: stored witness history changed witness identity"
                )
        return tuple(records)

    def verify(self, operation_id: str) -> tuple[bool, tuple[str, ...]]:
        problems: list[str] = []
        try:
            records = self.history(operation_id)
            head_snapshot = self._operation_ref(operation_id).get()
        except WitnessIntegrityError as exc:
            return False, (str(exc),)
        except WitnessUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WitnessUnavailableError(
                f"firestore witness verification failed for {operation_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

        previous = WITNESS_GENESIS
        for index, record in enumerate(records):
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

        head_exists = getattr(head_snapshot, "exists", False)
        if not records:
            if head_exists:
                problems.append("witness head exists without witness records")
            return (not problems), tuple(problems)
        if not head_exists:
            problems.append("witness records exist without a durable head")
            return False, tuple(problems)

        try:
            self._validate_latest(
                operation_id, head_snapshot.to_dict() or {}, records[-1]
            )
        except WitnessIntegrityError as exc:
            problems.append(str(exc))
        return (not problems), tuple(problems)


__all__ = [
    "FirestoreWitnessLedger",
    "WITNESS_OPERATIONS_COLLECTION",
    "WITNESS_RECORDS_COLLECTION",
    "WitnessUnavailableError",
]
