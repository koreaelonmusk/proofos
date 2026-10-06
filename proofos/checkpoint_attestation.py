"""Cryptographically signed continuity checkpoints.

A continuity checkpoint remains a bookmark, never a verdict. This module adds a
portable Ed25519 envelope that commits to the checkpoint's canonical content and
its journal position without granting any verification authority.

The private signing key belongs to the checkpoint publisher. Independent
witnesses are expected to hold only the public key and persist verified
envelopes outside the primary continuity store.
"""

from __future__ import annotations

import base64
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .continuity import OperationCheckpoint
from .integrity import canonical_payload, content_hash
from .keys import encode_public_key

CHECKPOINT_SIGNATURE_VERSION = "proofos.checkpoint.v1"

SIGNED_CHECKPOINT_FIELDS: tuple[str, ...] = (
    "version",
    "signer_id",
    "operation_id",
    "execution_id",
    "checkpoint_version",
    "last_journal_sequence",
    "last_journal_hash",
    "checkpoint_digest",
    "issued_at",
)
CHECKPOINT_ENVELOPE_FIELDS: tuple[str, ...] = SIGNED_CHECKPOINT_FIELDS + ("signature",)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CheckpointAttestationError(ValueError):
    """Base class for malformed, forged, or mis-bound checkpoint envelopes."""


class MalformedCheckpointAttestation(CheckpointAttestationError):
    pass


class CheckpointSignatureInvalid(CheckpointAttestationError):
    pass


class CheckpointBindingError(CheckpointAttestationError):
    pass


def digest_checkpoint(checkpoint: OperationCheckpoint) -> str:
    """Digest the exact canonical checkpoint representation."""
    return content_hash(checkpoint.as_dict())


@dataclass(frozen=True)
class SignedCheckpoint:
    """Portable signed commitment to one exact continuity checkpoint."""

    version: str
    signer_id: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    last_journal_sequence: int
    last_journal_hash: str
    checkpoint_digest: str
    issued_at: float
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "signer_id": self.signer_id,
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "checkpoint_version": self.checkpoint_version,
            "last_journal_sequence": self.last_journal_sequence,
            "last_journal_hash": self.last_journal_hash,
            "checkpoint_digest": self.checkpoint_digest,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "SignedCheckpoint":
        if not isinstance(data, Mapping):
            raise MalformedCheckpointAttestation(
                f"expected an object, got {type(data).__name__}"
            )

        keys = set(data)
        expected = set(CHECKPOINT_ENVELOPE_FIELDS)
        unexpected = keys - expected
        missing = expected - keys
        if unexpected:
            raise MalformedCheckpointAttestation(
                f"unexpected fields: {sorted(unexpected)}"
            )
        if missing:
            raise MalformedCheckpointAttestation(f"missing fields: {sorted(missing)}")

        version = _nonempty_str(data["version"], "version")
        signer_id = _nonempty_str(data["signer_id"], "signer_id")
        operation_id = _nonempty_str(data["operation_id"], "operation_id")
        execution_id = _nonempty_str(data["execution_id"], "execution_id")
        checkpoint_version = _int(data["checkpoint_version"], "checkpoint_version")
        last_journal_sequence = _int(
            data["last_journal_sequence"], "last_journal_sequence"
        )
        last_journal_hash = _str(data["last_journal_hash"], "last_journal_hash")
        checkpoint_digest = _str(data["checkpoint_digest"], "checkpoint_digest")
        issued_at = _float(data["issued_at"], "issued_at")
        signature = _nonempty_str(data["signature"], "signature")

        if checkpoint_version < 1:
            raise MalformedCheckpointAttestation("checkpoint_version must be >= 1")
        if last_journal_sequence < -1:
            raise MalformedCheckpointAttestation(
                "last_journal_sequence must be >= -1"
            )
        if last_journal_sequence == -1:
            if last_journal_hash:
                raise MalformedCheckpointAttestation(
                    "empty journal checkpoint must have an empty last_journal_hash"
                )
        elif not _SHA256_RE.fullmatch(last_journal_hash):
            raise MalformedCheckpointAttestation(
                "last_journal_hash must be a lowercase SHA-256 hex digest"
            )
        if not _SHA256_RE.fullmatch(checkpoint_digest):
            raise MalformedCheckpointAttestation(
                "checkpoint_digest must be a lowercase SHA-256 hex digest"
            )

        return cls(
            version=version,
            signer_id=signer_id,
            operation_id=operation_id,
            execution_id=execution_id,
            checkpoint_version=checkpoint_version,
            last_journal_sequence=last_journal_sequence,
            last_journal_hash=last_journal_hash,
            checkpoint_digest=checkpoint_digest,
            issued_at=issued_at,
            signature=signature,
        )


class CheckpointSigner:
    """Private-key holder for checkpoint commitments."""

    __slots__ = ("_key", "signer_id")

    def __init__(self, private_key: Ed25519PrivateKey, signer_id: str) -> None:
        if not signer_id.strip():
            raise ValueError("signer_id must not be empty")
        self._key = private_key
        self.signer_id = signer_id

    @classmethod
    def generate(cls, signer_id: str) -> "CheckpointSigner":
        return cls(Ed25519PrivateKey.generate(), signer_id)

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def public_key_b64(self) -> str:
        return encode_public_key(self.public_key())

    def sign(
        self,
        checkpoint: OperationCheckpoint,
        issued_at: float | None = None,
    ) -> SignedCheckpoint:
        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")
        if stamp < checkpoint.updated_at:
            raise ValueError("checkpoint cannot be signed before its updated_at")

        unsigned = SignedCheckpoint(
            version=CHECKPOINT_SIGNATURE_VERSION,
            signer_id=self.signer_id,
            operation_id=checkpoint.operation_id,
            execution_id=checkpoint.execution_id,
            checkpoint_version=checkpoint.checkpoint_version,
            last_journal_sequence=checkpoint.last_journal_sequence,
            last_journal_hash=checkpoint.last_journal_hash,
            checkpoint_digest=digest_checkpoint(checkpoint),
            issued_at=stamp,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return SignedCheckpoint(
            **{
                **unsigned.signed_fields(),
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class CheckpointVerifier:
    """Public-key-only verifier for checkpoint commitments."""

    __slots__ = ("_public_key",)

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_b64(cls, encoded: str) -> "CheckpointVerifier":
        try:
            raw = base64.b64decode(encoded, validate=True)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise CheckpointSignatureInvalid(
                f"public key is not valid Ed25519 base64: {exc}"
            ) from exc
        return cls(key)

    def verify(
        self,
        envelope: SignedCheckpoint,
        checkpoint: OperationCheckpoint,
    ) -> None:
        if envelope.version != CHECKPOINT_SIGNATURE_VERSION:
            raise CheckpointBindingError(
                f"unsupported checkpoint signature version {envelope.version!r}"
            )

        try:
            signature = base64.b64decode(envelope.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise CheckpointSignatureInvalid(
                f"signature is not valid base64: {exc}"
            ) from exc
        if len(signature) != 64:
            raise CheckpointSignatureInvalid(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )

        try:
            self._public_key.verify(signature, envelope.signing_bytes())
        except InvalidSignature as exc:
            raise CheckpointSignatureInvalid(
                "signature does not match the checkpoint commitment"
            ) from exc

        expected = {
            "operation_id": checkpoint.operation_id,
            "execution_id": checkpoint.execution_id,
            "checkpoint_version": checkpoint.checkpoint_version,
            "last_journal_sequence": checkpoint.last_journal_sequence,
            "last_journal_hash": checkpoint.last_journal_hash,
            "checkpoint_digest": digest_checkpoint(checkpoint),
        }
        actual = envelope.signed_fields()
        for field, value in expected.items():
            if actual[field] != value:
                raise CheckpointBindingError(
                    f"signed checkpoint {field} does not match checkpoint"
                )
        if envelope.issued_at < checkpoint.updated_at:
            raise CheckpointBindingError(
                "signed checkpoint predates checkpoint updated_at"
            )


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedCheckpointAttestation(f"{field} must be a string")
    return value


def _nonempty_str(value: Any, field: str) -> str:
    value = _str(value, field)
    if not value.strip():
        raise MalformedCheckpointAttestation(f"{field} must not be empty")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedCheckpointAttestation(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedCheckpointAttestation(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedCheckpointAttestation(f"{field} must be finite")
    return result


__all__ = [
    "CHECKPOINT_SIGNATURE_VERSION",
    "CheckpointAttestationError",
    "CheckpointBindingError",
    "CheckpointSignatureInvalid",
    "CheckpointSigner",
    "CheckpointVerifier",
    "MalformedCheckpointAttestation",
    "SignedCheckpoint",
    "digest_checkpoint",
]
