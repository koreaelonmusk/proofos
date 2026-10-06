"""Signed transport certificate for a recomputed witness quorum.

The certificate is not authority. It may only be created from an already
verified QUORUM result, and verification must bind it back to that independently
recomputed result. The signer therefore protects transport integrity without
being able to manufacture quorum.
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

from .integrity import canonical_payload, content_hash
from .keys import encode_public_key
from .witness_quorum import WitnessQuorumResult, WitnessQuorumState

QUORUM_CERTIFICATE_VERSION = "proofos.quorum-certificate.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SIGNED_FIELDS: tuple[str, ...] = (
    "version",
    "signer_id",
    "policy_digest",
    "operation_id",
    "execution_id",
    "checkpoint_version",
    "checkpoint_digest",
    "counted_witnesses",
    "required",
    "quorum_result_digest",
    "issued_at",
)
ENVELOPE_FIELDS: tuple[str, ...] = SIGNED_FIELDS + ("signature",)


class QuorumCertificateError(ValueError):
    pass


class MalformedQuorumCertificate(QuorumCertificateError):
    pass


class QuorumCertificateSignatureInvalid(QuorumCertificateError):
    pass


class QuorumCertificateBindingError(QuorumCertificateError):
    pass


def digest_quorum_result(result: WitnessQuorumResult) -> str:
    return content_hash(
        {
            "state": str(result.state),
            "policy_digest": result.policy_digest,
            "operation_id": result.operation_id,
            "execution_id": result.execution_id,
            "checkpoint_version": result.checkpoint_version,
            "checkpoint_digest": result.checkpoint_digest,
            "counted_witnesses": list(result.counted_witnesses),
            "required": result.required,
            "conflicting_commitment_hashes": list(
                result.conflicting_commitment_hashes
            ),
        }
    )


@dataclass(frozen=True)
class QuorumCertificate:
    version: str
    signer_id: str
    policy_digest: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    counted_witnesses: tuple[str, ...]
    required: int
    quorum_result_digest: str
    issued_at: float
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "signer_id": self.signer_id,
            "policy_digest": self.policy_digest,
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "checkpoint_version": self.checkpoint_version,
            "checkpoint_digest": self.checkpoint_digest,
            "counted_witnesses": list(self.counted_witnesses),
            "required": self.required,
            "quorum_result_digest": self.quorum_result_digest,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "QuorumCertificate":
        if not isinstance(data, Mapping):
            raise MalformedQuorumCertificate(
                f"expected an object, got {type(data).__name__}"
            )
        keys = set(data)
        expected = set(ENVELOPE_FIELDS)
        unexpected = keys - expected
        missing = expected - keys
        if unexpected:
            raise MalformedQuorumCertificate(
                f"unexpected fields: {sorted(unexpected)}"
            )
        if missing:
            raise MalformedQuorumCertificate(f"missing fields: {sorted(missing)}")

        counted_raw = data["counted_witnesses"]
        if not isinstance(counted_raw, list) or not all(
            isinstance(item, str) and item.strip() for item in counted_raw
        ):
            raise MalformedQuorumCertificate(
                "counted_witnesses must be a list of non-empty strings"
            )
        counted = tuple(counted_raw)
        if tuple(sorted(set(counted))) != counted:
            raise MalformedQuorumCertificate(
                "counted_witnesses must be unique and sorted"
            )

        certificate = cls(
            version=_nonempty_str(data["version"], "version"),
            signer_id=_nonempty_str(data["signer_id"], "signer_id"),
            policy_digest=_digest(data["policy_digest"], "policy_digest"),
            operation_id=_nonempty_str(data["operation_id"], "operation_id"),
            execution_id=_nonempty_str(data["execution_id"], "execution_id"),
            checkpoint_version=_int(data["checkpoint_version"], "checkpoint_version"),
            checkpoint_digest=_digest(
                data["checkpoint_digest"], "checkpoint_digest"
            ),
            counted_witnesses=counted,
            required=_int(data["required"], "required"),
            quorum_result_digest=_digest(
                data["quorum_result_digest"], "quorum_result_digest"
            ),
            issued_at=_float(data["issued_at"], "issued_at"),
            signature=_nonempty_str(data["signature"], "signature"),
        )
        if certificate.version != QUORUM_CERTIFICATE_VERSION:
            raise MalformedQuorumCertificate(
                f"unsupported quorum certificate version {certificate.version!r}"
            )
        if certificate.checkpoint_version < 1:
            raise MalformedQuorumCertificate("checkpoint_version must be >= 1")
        if certificate.required < 1:
            raise MalformedQuorumCertificate("required must be >= 1")
        if len(certificate.counted_witnesses) < certificate.required:
            raise MalformedQuorumCertificate(
                "certificate does not contain enough counted witnesses"
            )
        return certificate


class QuorumCertificateSigner:
    __slots__ = ("_key", "signer_id")

    def __init__(self, private_key: Ed25519PrivateKey, signer_id: str) -> None:
        if not signer_id.strip():
            raise ValueError("signer_id must not be empty")
        self._key = private_key
        self.signer_id = signer_id

    @classmethod
    def generate(cls, signer_id: str) -> "QuorumCertificateSigner":
        return cls(Ed25519PrivateKey.generate(), signer_id)

    def public_key_b64(self) -> str:
        return encode_public_key(self._key.public_key())

    def sign(
        self,
        result: WitnessQuorumResult,
        issued_at: float | None = None,
    ) -> QuorumCertificate:
        if result.state is not WitnessQuorumState.QUORUM or not result.quorum_met:
            raise QuorumCertificateBindingError(
                "only an independently recomputed QUORUM result may be certified"
            )
        if len(result.counted_witnesses) < result.required:
            raise QuorumCertificateBindingError(
                "quorum result has fewer counted witnesses than required"
            )

        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")

        unsigned = QuorumCertificate(
            version=QUORUM_CERTIFICATE_VERSION,
            signer_id=self.signer_id,
            policy_digest=result.policy_digest,
            operation_id=result.operation_id,
            execution_id=result.execution_id,
            checkpoint_version=result.checkpoint_version,
            checkpoint_digest=result.checkpoint_digest,
            counted_witnesses=tuple(result.counted_witnesses),
            required=result.required,
            quorum_result_digest=digest_quorum_result(result),
            issued_at=stamp,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return QuorumCertificate(
            **{
                **unsigned.signed_fields(),
                "counted_witnesses": unsigned.counted_witnesses,
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class QuorumCertificateVerifier:
    __slots__ = ("_key", "signer_id")

    def __init__(self, public_key: Ed25519PublicKey, signer_id: str) -> None:
        if not signer_id.strip():
            raise ValueError("signer_id must not be empty")
        self._key = public_key
        self.signer_id = signer_id

    @classmethod
    def from_b64(
        cls,
        encoded: str,
        signer_id: str,
    ) -> "QuorumCertificateVerifier":
        try:
            raw = base64.b64decode(encoded, validate=True)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise QuorumCertificateSignatureInvalid(
                f"public key is not valid Ed25519 base64: {exc}"
            ) from exc
        return cls(key, signer_id)

    def verify(
        self,
        certificate: QuorumCertificate,
        result: WitnessQuorumResult,
    ) -> None:
        if certificate.version != QUORUM_CERTIFICATE_VERSION:
            raise QuorumCertificateBindingError(
                f"unsupported quorum certificate version {certificate.version!r}"
            )
        if certificate.signer_id != self.signer_id:
            raise QuorumCertificateBindingError(
                f"certificate belongs to {certificate.signer_id!r}, not "
                f"{self.signer_id!r}"
            )
        if result.state is not WitnessQuorumState.QUORUM or not result.quorum_met:
            raise QuorumCertificateBindingError(
                "certificate cannot bind to a non-quorum result"
            )

        try:
            signature = base64.b64decode(certificate.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise QuorumCertificateSignatureInvalid(
                f"signature is not valid base64: {exc}"
            ) from exc
        if len(signature) != 64:
            raise QuorumCertificateSignatureInvalid(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )
        try:
            self._key.verify(signature, certificate.signing_bytes())
        except InvalidSignature as exc:
            raise QuorumCertificateSignatureInvalid(
                "signature does not match quorum certificate"
            ) from exc

        expected = {
            "policy_digest": result.policy_digest,
            "operation_id": result.operation_id,
            "execution_id": result.execution_id,
            "checkpoint_version": result.checkpoint_version,
            "checkpoint_digest": result.checkpoint_digest,
            "counted_witnesses": tuple(result.counted_witnesses),
            "required": result.required,
            "quorum_result_digest": digest_quorum_result(result),
        }
        actual = {
            "policy_digest": certificate.policy_digest,
            "operation_id": certificate.operation_id,
            "execution_id": certificate.execution_id,
            "checkpoint_version": certificate.checkpoint_version,
            "checkpoint_digest": certificate.checkpoint_digest,
            "counted_witnesses": certificate.counted_witnesses,
            "required": certificate.required,
            "quorum_result_digest": certificate.quorum_result_digest,
        }
        for field, value in expected.items():
            if actual[field] != value:
                raise QuorumCertificateBindingError(
                    f"certificate {field} does not match recomputed quorum"
                )


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedQuorumCertificate(f"{field} must be a string")
    return value


def _nonempty_str(value: Any, field: str) -> str:
    value = _str(value, field)
    if not value.strip():
        raise MalformedQuorumCertificate(f"{field} must not be empty")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedQuorumCertificate(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedQuorumCertificate(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedQuorumCertificate(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    value = _str(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise MalformedQuorumCertificate(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "MalformedQuorumCertificate",
    "QUORUM_CERTIFICATE_VERSION",
    "QuorumCertificate",
    "QuorumCertificateBindingError",
    "QuorumCertificateError",
    "QuorumCertificateSignatureInvalid",
    "QuorumCertificateSigner",
    "QuorumCertificateVerifier",
    "digest_quorum_result",
]
