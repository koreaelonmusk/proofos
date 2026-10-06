"""Durable create-only filesystem backend for witness checkpoints.

This backend is intended for a storage boundary independent from the primary
continuity/journal database: a separate volume, host, replicated filesystem, or
object-store mount. Operation IDs never become path components; they are hashed
into fixed-width namespaces to prevent traversal.

Each checkpoint version is one immutable JSON file created with O_EXCL. The
backend fsyncs the file and, where supported, the containing directory before
reporting success. Reads re-validate the witness record chain rather than
trusting filenames or prior process memory.
"""

from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Any

from .checkpoint_attestation import CheckpointVerifier, SignedCheckpoint
from .continuity import OperationCheckpoint
from .integrity import content_hash
from .witness import (
    WITNESS_GENESIS,
    WITNESS_RECORD_VERSION,
    WitnessEquivocationError,
    WitnessGapError,
    WitnessIntegrityError,
    WitnessRecord,
    WitnessRollbackError,
    WitnessSignerDriftError,
)

_RECORD_FIELDS = frozenset(WitnessRecord.__dataclass_fields__)
_RECORD_NAME = re.compile(r"^[0-9]{12}\.json$")


class FileWitnessLedger:
    """Append-only witness ledger backed by create-only version files."""

    def __init__(self, root: str | os.PathLike, witness_id: str) -> None:
        if not witness_id.strip():
            raise ValueError("witness_id must not be empty")
        self.root = Path(root)
        self.witness_id = witness_id
        self.root.mkdir(parents=True, exist_ok=True)

    def _operation_dir(self, operation_id: str) -> Path:
        namespace = content_hash({"operation_id": operation_id})
        return self.root / namespace

    def _record_path(self, operation_id: str, version: int) -> Path:
        return self._operation_dir(operation_id) / f"{version:012d}.json"

    def history(self, operation_id: str) -> tuple[WitnessRecord, ...]:
        directory = self._operation_dir(operation_id)
        if not directory.exists():
            return ()
        if directory.is_symlink() or not directory.is_dir():
            raise WitnessIntegrityError(
                f"witness namespace for {operation_id} is not a real directory"
            )

        entries = list(directory.iterdir())
        for path in entries:
            if path.is_symlink():
                raise WitnessIntegrityError(
                    f"witness storage contains a symlink: {path.name}"
                )
            if not path.is_file() or not _RECORD_NAME.fullmatch(path.name):
                raise WitnessIntegrityError(
                    f"unexpected witness storage entry: {path.name}"
                )

        records: list[WitnessRecord] = []
        for path in sorted(entries, key=lambda p: p.name):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise WitnessIntegrityError(
                    f"unreadable witness record {path.name}: {type(exc).__name__}"
                ) from exc
            record = _record_from_dict(raw)
            filename_version = int(path.stem)
            if record.checkpoint_version != filename_version:
                raise WitnessIntegrityError(
                    f"witness filename version {filename_version} does not match "
                    f"record version {record.checkpoint_version}"
                )
            if record.operation_id != operation_id:
                raise WitnessIntegrityError(
                    f"witness record {path.name} belongs to a different operation"
                )
            if record.witness_id != self.witness_id:
                raise WitnessIntegrityError(
                    f"witness record {path.name} belongs to {record.witness_id!r}, "
                    f"not {self.witness_id!r}"
                )
            records.append(record)

        ok, problems = _verify_records(records)
        if not ok:
            raise WitnessIntegrityError("; ".join(problems))
        return tuple(records)

    def observe(
        self,
        envelope: SignedCheckpoint,
        checkpoint: OperationCheckpoint,
        verifier: CheckpointVerifier,
        observed_at: float | None = None,
    ) -> WitnessRecord:
        verifier.verify(envelope, checkpoint)
        stamp = __import__("time").time() if observed_at is None else float(observed_at)
        if not math.isfinite(stamp):
            raise WitnessIntegrityError("witness observed_at must be finite")
        if stamp < envelope.issued_at:
            raise WitnessIntegrityError(
                "witness observation cannot predate signed checkpoint issuance"
            )

        history = self.history(envelope.operation_id)
        previous_hash = self._validate_next(envelope, history)

        if history and envelope.checkpoint_version == history[-1].checkpoint_version:
            return history[-1]

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
        self._create(record)

        # Read-after-write is part of the contract. Success means the durable
        # representation can be reconstructed and still verifies.
        stored = self.history(record.operation_id)
        if not stored or stored[-1] != record:
            raise WitnessIntegrityError("witness write did not round-trip exactly")
        return record

    def _validate_next(
        self,
        envelope: SignedCheckpoint,
        history: tuple[WitnessRecord, ...],
    ) -> str:
        if not history:
            if envelope.checkpoint_version != 1:
                raise WitnessGapError(
                    f"{envelope.operation_id}: first witnessed checkpoint must be "
                    f"version 1, got {envelope.checkpoint_version}"
                )
            return WITNESS_GENESIS

        latest = history[-1]
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
                return latest.previous_record_hash
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
        return latest.record_hash

    def _create(self, record: WitnessRecord) -> None:
        directory = self._operation_dir(record.operation_id)
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink():
            raise WitnessIntegrityError("witness operation namespace is a symlink")

        path = self._record_path(record.operation_id, record.checkpoint_version)
        payload = (
            json.dumps(
                record.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            # Concurrent same-version writer won. Re-read and accept only exact
            # content; anything else is equivocation.
            current = self.history(record.operation_id)
            existing = next(
                (
                    item
                    for item in current
                    if item.checkpoint_version == record.checkpoint_version
                ),
                None,
            )
            if existing == record:
                return
            raise WitnessEquivocationError(
                f"{record.operation_id}: durable witness version "
                f"{record.checkpoint_version} already differs"
            )
        except OSError as exc:
            raise WitnessIntegrityError(
                f"could not create witness record: {type(exc).__name__}: {exc}"
            ) from exc

        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(directory)
        except Exception:
            # A failed durability barrier must not be reported as success. The
            # create-only file remains as evidence of the interrupted attempt.
            raise

    def verify(self, operation_id: str) -> tuple[bool, tuple[str, ...]]:
        try:
            records = self.history(operation_id)
        except WitnessIntegrityError as exc:
            return False, (str(exc),)
        return _verify_records(records)


def _record_from_dict(raw: Any) -> WitnessRecord:
    if not isinstance(raw, dict):
        raise WitnessIntegrityError("witness record must be a JSON object")
    keys = set(raw)
    missing = _RECORD_FIELDS - keys
    unexpected = keys - _RECORD_FIELDS
    if missing:
        raise WitnessIntegrityError(f"witness record missing fields: {sorted(missing)}")
    if unexpected:
        raise WitnessIntegrityError(
            f"witness record has unexpected fields: {sorted(unexpected)}"
        )
    try:
        record = WitnessRecord(
            version=str(raw["version"]),
            witness_id=str(raw["witness_id"]),
            signer_id=str(raw["signer_id"]),
            operation_id=str(raw["operation_id"]),
            execution_id=str(raw["execution_id"]),
            checkpoint_version=int(raw["checkpoint_version"]),
            checkpoint_digest=str(raw["checkpoint_digest"]),
            last_journal_sequence=int(raw["last_journal_sequence"]),
            last_journal_hash=str(raw["last_journal_hash"]),
            checkpoint_signature=str(raw["checkpoint_signature"]),
            observed_at=float(raw["observed_at"]),
            previous_record_hash=str(raw["previous_record_hash"]),
            record_hash=str(raw["record_hash"]),
        )
    except (TypeError, ValueError) as exc:
        raise WitnessIntegrityError(f"malformed witness record: {exc}") from exc

    if record.version != WITNESS_RECORD_VERSION:
        raise WitnessIntegrityError(
            f"unsupported witness record version {record.version!r}"
        )
    if not math.isfinite(record.observed_at):
        raise WitnessIntegrityError("witness observed_at must be finite")
    return record


def _verify_records(
    records: tuple[WitnessRecord, ...] | list[WitnessRecord],
) -> tuple[bool, tuple[str, ...]]:
    problems: list[str] = []
    previous = WITNESS_GENESIS
    for index, record in enumerate(records):
        if not record.intact:
            problems.append(f"witness record {index} does not match its content hash")
        if record.previous_record_hash != previous:
            problems.append(f"witness record {index} does not follow its predecessor")
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


def _fsync_directory(path: Path) -> None:
    if not hasattr(os, "O_DIRECTORY"):
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = ["FileWitnessLedger"]
