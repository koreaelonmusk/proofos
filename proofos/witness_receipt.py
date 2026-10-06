"""Cryptographically signed receipts for independent witness observations.

A witness receipt proves that a named witness accepted one exact WitnessRecord.
It does not promote a checkpoint into a verdict and carries no verification
authority. Quorum logic can later combine multiple independently verified
receipts without trusting the primary continuity store.
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

from .integrity import canonical_payload
from .keys import encode_public_key
from .witness import WitnessRecord

WITNESS_RECEIPT_VERSION = "proofos.witness-receipt.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SIGNED_RECEIPT_FIELDS: tuple[str, ...] = (
    "version",
    "witness_id",
    "operation_id",
    "execution_id",
    "checkpoint_version",
    "checkpoint_digest",
    "witness_record_hash",
    "issued_at",
)
RECEIPT_FIELDS: tuple[str, ...] = SIGNED_RECEIPT_FIELDS + ("signature",)


class WitnessReceiptError(ValueError):
    pass


class MalformedWitnessReceipt(WitnessReceiptError):
    pass


class WitnessReceiptSignatureInvalid(WitnessReceiptError):
    pass


class WitnessReceiptBindingError(WitnessReceiptError):
    pass


@dataclass(frozen=True)
class WitnessReceipt:
    version: str
    witness_id: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    witness_record_hash: str
    issued_at: float
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "witness_id": self.witness_id,
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "checkpoint_version": self.checkpoint_version,
            "checkpoint_digest": self.checkpoint_digest,
            "witness_record_hash": self.witness_record_hash,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "WitnessReceipt":
        if not isinstance(data, Mapping):
            raise MalformedWitnessReceipt(
                f"expected an object, got {type(data).__name__}"
            )
        keys = set(data)
        expected = set(RECEIPT_FIELDS)
        unexpected = keys - expected
        missing = expected - keys
        if unexpected:
            raise MalformedWitnessReceipt(f"unexpected fields: {sorted(unexpected)}")
        if missing:
            raise MalformedWitnessReceipt(f"missing fields: {sorted(missing)}")

        version = _nonempty_str(data["version"], "version")
        witness_id = _nonempty_str(data["witness_id"], "witness_id")
        operation_id = _nonempty_str(data["operation_id"], "operation_id")
        execution_id = _nonempty_str(data["execution_id"], "execution_id")
        checkpoint_version = _int(data["checkpoint_version"], "checkpoint_version")
        checkpoint_digest = _digest(data["checkpoint_digest"], "checkpoint_digest")
        witness_record_hash = _digest(
            data["witness_record_hash"], "witness_record_hash"
        )
        issued_at = _float(data["issued_at"], "issued_at")
        signature = _nonempty_str(data["signature"], "signature")

        if checkpoint_version < 1:
            raise MalformedWitnessReceipt("checkpoint_version must be >= 1")

        return cls(
            version=version,
            witness_id=witness_id,
            operation_id=operation_id,
            execution_id=execution_id,
            checkpoint_version=checkpoint_version,
            checkpoint_digest=checkpoint_digest,
            witness_record_hash=witness_record_hash,
            issued_at=issued_at,
            signature=signature,
        )


class WitnessReceiptSigner:
    """Private-key holder belonging to one independent witness."""

    __slots__ = ("_key", "witness_id")

    def __init__(self, private_key: Ed25519PrivateKey, witness_id: str) -> None:
        if not witness_id.strip():
            raise ValueError("witness_id must not be empty")
        self._key = private_key
        self.witness_id = witness_id

    @classmethod
    def generate(cls, witness_id: str) -> "WitnessReceiptSigner":
        return cls(Ed25519PrivateKey.generate(), witness_id)

    def public_key_b64(self) -> str:
        return encode_public_key(self._key.public_key())

    def sign(
        self,
        record: WitnessRecord,
        issued_at: float | None = None,
    ) -> WitnessReceipt:
        if record.witness_id != self.witness_id:
            raise WitnessReceiptBindingError(
                f"signer {self.witness_id!r} cannot sign record for "
                f"{record.witness_id!r}"
            )
        if not record.intact:
            raise WitnessReceiptBindingError("cannot sign a tampered witness record")
        if not math.isfinite(record.observed_at):
            raise WitnessReceiptBindingError(
                "witness observation time must be finite"
            )

        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")
        if stamp < record.observed_at:
            raise ValueError("receipt cannot predate witness observation")

        unsigned = WitnessReceipt(
            version=WITNESS_RECEIPT_VERSION,
            witness_id=record.witness_id,
            operation_id=record.operation_id,
            execution_id=record.execution_id,
            checkpoint_version=record.checkpoint_version,
            checkpoint_digest=record.checkpoint_digest,
            witness_record_hash=record.record_hash,
            issued_at=stamp,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return WitnessReceipt(
            **{
                **unsigned.signed_fields(),
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class WitnessReceiptVerifier:
    """Public-key-only verification for one witness identity."""

    __slots__ = ("_key", "witness_id")

    def __init__(self, public_key: Ed25519PublicKey, witness_id: str) -> None:
        if not witness_id.strip():
            raise ValueError("witness_id must not be empty")
        self._key = public_key
        self.witness_id = witness_id

    @classmethod
    def from_b64(
        cls,
        encoded: str,
        witness_id: str,
    ) -> "WitnessReceiptVerifier":
        try:
            raw = base64.b64decode(encoded, validate=True)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise WitnessReceiptSignatureInvalid(
                f"public key is not valid Ed25519 base64: {exc}"
            ) from exc
        return cls(key, witness_id)

    def verify(self, receipt: WitnessReceipt, record: WitnessRecord) -> None:
        if receipt.version != WITNESS_RECEIPT_VERSION:
            raise WitnessReceiptBindingError(
                f"unsupported witness receipt version {receipt.version!r}"
            )
        if receipt.witness_id != self.witness_id:
            raise WitnessReceiptBindingError(
                f"receipt belongs to {receipt.witness_id!r}, not "
                f"{self.witness_id!r}"
            )
        if not record.intact:
            raise WitnessReceiptBindingError("witness record failed integrity")
        if not math.isfinite(record.observed_at):
            raise WitnessReceiptBindingError(
                "witness observation time must be finite"
            )

        try:
            signature = base64.b64decode(receipt.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise WitnessReceiptSignatureInvalid(
                f"signature is not valid base64: {exc}"
            ) from exc
        if len(signature) != 64:
            raise WitnessReceiptSignatureInvalid(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )

        try:
            self._key.verify(signature, receipt.signing_bytes())
        except InvalidSignature as exc:
            raise WitnessReceiptSignatureInvalid(
                "signature does not match witness receipt"
            ) from exc

        expected = {
            "witness_id": record.witness_id,
            "operation_id": record.operation_id,
            "execution_id": record.execution_id,
            "checkpoint_version": record.checkpoint_version,
            "checkpoint_digest": record.checkpoint_digest,
            "witness_record_hash": record.record_hash,
        }
        actual = receipt.signed_fields()
        for field, value in expected.items():
            if actual[field] != value:
                raise WitnessReceiptBindingError(
                    f"receipt {field} does not match witness record"
                )
        if receipt.issued_at < record.observed_at:
            raise WitnessReceiptBindingError(
                "receipt predates witness observation"
            )


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedWitnessReceipt(f"{field} must be a string")
    return value


def _nonempty_str(value: Any, field: str) -> str:
    value = _str(value, field)
    if not value.strip():
        raise MalformedWitnessReceipt(f"{field} must not be empty")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedWitnessReceipt(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedWitnessReceipt(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedWitnessReceipt(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    value = _str(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise MalformedWitnessReceipt(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "MalformedWitnessReceipt",
    "WitnessReceipt",
    "WitnessReceiptBindingError",
    "WitnessReceiptError",
    "WitnessReceiptSignatureInvalid",
    "WitnessReceiptSigner",
    "WitnessReceiptVerifier",
]
