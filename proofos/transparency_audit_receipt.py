"""Signed receipt for an independently recomputed transparency audit.

The receipt is a portable statement of what an auditor recomputed from pinned
public inputs. It is not a task-completion verdict and does not grant execution,
evidence, or capability authority.

Verification is deliberately two-layered:
1. verify the auditor signature over the receipt;
2. bind every receipt claim back to the independently recomputed
   TransparencyResult and source artifact digests.
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
from .quorum_certificate import QuorumCertificate
from .transparency_gate import TransparencyResult
from .witness_gossip import WitnessGossipBundle

TRANSPARENCY_AUDIT_RECEIPT_VERSION = "proofos.transparency-audit-receipt.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SIGNED_FIELDS: tuple[str, ...] = (
    "version",
    "auditor_id",
    "transparency_state",
    "policy_digest",
    "operation_id",
    "execution_id",
    "checkpoint_version",
    "checkpoint_digest",
    "counted_witnesses",
    "required",
    "gossip_publisher_id",
    "certificate_signer_id",
    "gossip_bundle_digest",
    "certificate_digest",
    "audit_result_digest",
    "issued_at",
)
ENVELOPE_FIELDS: tuple[str, ...] = SIGNED_FIELDS + ("signature",)


class TransparencyAuditReceiptError(ValueError):
    pass


class MalformedTransparencyAuditReceipt(TransparencyAuditReceiptError):
    pass


class TransparencyAuditReceiptSignatureInvalid(TransparencyAuditReceiptError):
    pass


class TransparencyAuditReceiptBindingError(TransparencyAuditReceiptError):
    pass


def digest_gossip_bundle(bundle: WitnessGossipBundle) -> str:
    return content_hash(bundle.to_dict())


def digest_quorum_certificate(certificate: QuorumCertificate | None) -> str | None:
    return None if certificate is None else content_hash(certificate.to_dict())


def digest_transparency_result(result: TransparencyResult) -> str:
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
            "gossip_publisher_id": result.gossip_publisher_id,
            "certificate_signer_id": result.certificate_signer_id,
        }
    )


@dataclass(frozen=True)
class TransparencyAuditReceipt:
    version: str
    auditor_id: str
    transparency_state: str
    policy_digest: str
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    counted_witnesses: tuple[str, ...]
    required: int
    gossip_publisher_id: str
    certificate_signer_id: str | None
    gossip_bundle_digest: str
    certificate_digest: str | None
    audit_result_digest: str
    issued_at: float
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "auditor_id": self.auditor_id,
            "transparency_state": self.transparency_state,
            "policy_digest": self.policy_digest,
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "checkpoint_version": self.checkpoint_version,
            "checkpoint_digest": self.checkpoint_digest,
            "counted_witnesses": list(self.counted_witnesses),
            "required": self.required,
            "gossip_publisher_id": self.gossip_publisher_id,
            "certificate_signer_id": self.certificate_signer_id,
            "gossip_bundle_digest": self.gossip_bundle_digest,
            "certificate_digest": self.certificate_digest,
            "audit_result_digest": self.audit_result_digest,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "TransparencyAuditReceipt":
        if not isinstance(data, Mapping):
            raise MalformedTransparencyAuditReceipt(
                f"expected an object, got {type(data).__name__}"
            )
        keys = set(data)
        expected = set(ENVELOPE_FIELDS)
        unexpected = keys - expected
        missing = expected - keys
        if unexpected:
            raise MalformedTransparencyAuditReceipt(
                f"unexpected fields: {sorted(unexpected)}"
            )
        if missing:
            raise MalformedTransparencyAuditReceipt(
                f"missing fields: {sorted(missing)}"
            )

        counted_raw = data["counted_witnesses"]
        if not isinstance(counted_raw, list) or not all(
            isinstance(item, str) and item.strip() for item in counted_raw
        ):
            raise MalformedTransparencyAuditReceipt(
                "counted_witnesses must be a list of non-empty strings"
            )
        counted = tuple(counted_raw)
        if counted != tuple(sorted(set(counted))):
            raise MalformedTransparencyAuditReceipt(
                "counted_witnesses must be unique and sorted"
            )

        certificate_signer_id = data["certificate_signer_id"]
        if certificate_signer_id is not None:
            certificate_signer_id = _nonempty_str(
                certificate_signer_id, "certificate_signer_id"
            )

        certificate_digest = data["certificate_digest"]
        if certificate_digest is not None:
            certificate_digest = _digest(certificate_digest, "certificate_digest")

        receipt = cls(
            version=_nonempty_str(data["version"], "version"),
            auditor_id=_nonempty_str(data["auditor_id"], "auditor_id"),
            transparency_state=_nonempty_str(
                data["transparency_state"], "transparency_state"
            ),
            policy_digest=_digest(data["policy_digest"], "policy_digest"),
            operation_id=_nonempty_str(data["operation_id"], "operation_id"),
            execution_id=_nonempty_str(data["execution_id"], "execution_id"),
            checkpoint_version=_int(data["checkpoint_version"], "checkpoint_version"),
            checkpoint_digest=_digest(
                data["checkpoint_digest"], "checkpoint_digest"
            ),
            counted_witnesses=counted,
            required=_int(data["required"], "required"),
            gossip_publisher_id=_nonempty_str(
                data["gossip_publisher_id"], "gossip_publisher_id"
            ),
            certificate_signer_id=certificate_signer_id,
            gossip_bundle_digest=_digest(
                data["gossip_bundle_digest"], "gossip_bundle_digest"
            ),
            certificate_digest=certificate_digest,
            audit_result_digest=_digest(
                data["audit_result_digest"], "audit_result_digest"
            ),
            issued_at=_float(data["issued_at"], "issued_at"),
            signature=_nonempty_str(data["signature"], "signature"),
        )
        if receipt.version != TRANSPARENCY_AUDIT_RECEIPT_VERSION:
            raise MalformedTransparencyAuditReceipt(
                f"unsupported audit receipt version {receipt.version!r}"
            )
        if receipt.checkpoint_version < 1:
            raise MalformedTransparencyAuditReceipt(
                "checkpoint_version must be >= 1"
            )
        if receipt.required < 1:
            raise MalformedTransparencyAuditReceipt("required must be >= 1")
        if (
            receipt.transparency_state == "ACCEPTED"
            and len(receipt.counted_witnesses) < receipt.required
        ):
            raise MalformedTransparencyAuditReceipt(
                "accepted audit receipt has fewer counted witnesses than required"
            )
        return receipt


class TransparencyAuditReceiptSigner:
    __slots__ = ("_key", "auditor_id")

    def __init__(self, private_key: Ed25519PrivateKey, auditor_id: str) -> None:
        if not auditor_id.strip():
            raise ValueError("auditor_id must not be empty")
        self._key = private_key
        self.auditor_id = auditor_id

    @classmethod
    def generate(cls, auditor_id: str) -> "TransparencyAuditReceiptSigner":
        return cls(Ed25519PrivateKey.generate(), auditor_id)

    def public_key_b64(self) -> str:
        return encode_public_key(self._key.public_key())

    def sign(
        self,
        result: TransparencyResult,
        bundle: WitnessGossipBundle,
        certificate: QuorumCertificate | None,
        issued_at: float | None = None,
    ) -> TransparencyAuditReceipt:
        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")

        unsigned = TransparencyAuditReceipt(
            version=TRANSPARENCY_AUDIT_RECEIPT_VERSION,
            auditor_id=self.auditor_id,
            transparency_state=str(result.state),
            policy_digest=result.policy_digest,
            operation_id=result.operation_id,
            execution_id=result.execution_id,
            checkpoint_version=result.checkpoint_version,
            checkpoint_digest=result.checkpoint_digest,
            counted_witnesses=tuple(result.counted_witnesses),
            required=result.required,
            gossip_publisher_id=result.gossip_publisher_id,
            certificate_signer_id=result.certificate_signer_id,
            gossip_bundle_digest=digest_gossip_bundle(bundle),
            certificate_digest=digest_quorum_certificate(certificate),
            audit_result_digest=digest_transparency_result(result),
            issued_at=stamp,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return TransparencyAuditReceipt(
            **{
                **unsigned.signed_fields(),
                "counted_witnesses": unsigned.counted_witnesses,
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class TransparencyAuditReceiptVerifier:
    __slots__ = ("_key", "auditor_id")

    def __init__(self, public_key: Ed25519PublicKey, auditor_id: str) -> None:
        if not auditor_id.strip():
            raise ValueError("auditor_id must not be empty")
        self._key = public_key
        self.auditor_id = auditor_id

    @classmethod
    def from_b64(
        cls,
        encoded: str,
        auditor_id: str,
    ) -> "TransparencyAuditReceiptVerifier":
        try:
            raw = base64.b64decode(encoded, validate=True)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise TransparencyAuditReceiptSignatureInvalid(
                f"public key is not valid Ed25519 base64: {exc}"
            ) from exc
        return cls(key, auditor_id)

    def verify(
        self,
        receipt: TransparencyAuditReceipt,
        result: TransparencyResult,
        bundle: WitnessGossipBundle,
        certificate: QuorumCertificate | None,
    ) -> None:
        if receipt.version != TRANSPARENCY_AUDIT_RECEIPT_VERSION:
            raise TransparencyAuditReceiptBindingError(
                f"unsupported audit receipt version {receipt.version!r}"
            )
        if receipt.auditor_id != self.auditor_id:
            raise TransparencyAuditReceiptBindingError(
                f"receipt belongs to {receipt.auditor_id!r}, not "
                f"{self.auditor_id!r}"
            )

        try:
            signature = base64.b64decode(receipt.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise TransparencyAuditReceiptSignatureInvalid(
                f"signature is not valid base64: {exc}"
            ) from exc
        if len(signature) != 64:
            raise TransparencyAuditReceiptSignatureInvalid(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )
        try:
            self._key.verify(signature, receipt.signing_bytes())
        except InvalidSignature as exc:
            raise TransparencyAuditReceiptSignatureInvalid(
                "signature does not match transparency audit receipt"
            ) from exc

        expected = {
            "transparency_state": str(result.state),
            "policy_digest": result.policy_digest,
            "operation_id": result.operation_id,
            "execution_id": result.execution_id,
            "checkpoint_version": result.checkpoint_version,
            "checkpoint_digest": result.checkpoint_digest,
            "counted_witnesses": tuple(result.counted_witnesses),
            "required": result.required,
            "gossip_publisher_id": result.gossip_publisher_id,
            "certificate_signer_id": result.certificate_signer_id,
            "gossip_bundle_digest": digest_gossip_bundle(bundle),
            "certificate_digest": digest_quorum_certificate(certificate),
            "audit_result_digest": digest_transparency_result(result),
        }
        actual = {
            "transparency_state": receipt.transparency_state,
            "policy_digest": receipt.policy_digest,
            "operation_id": receipt.operation_id,
            "execution_id": receipt.execution_id,
            "checkpoint_version": receipt.checkpoint_version,
            "checkpoint_digest": receipt.checkpoint_digest,
            "counted_witnesses": receipt.counted_witnesses,
            "required": receipt.required,
            "gossip_publisher_id": receipt.gossip_publisher_id,
            "certificate_signer_id": receipt.certificate_signer_id,
            "gossip_bundle_digest": receipt.gossip_bundle_digest,
            "certificate_digest": receipt.certificate_digest,
            "audit_result_digest": receipt.audit_result_digest,
        }
        for field, value in expected.items():
            if actual[field] != value:
                raise TransparencyAuditReceiptBindingError(
                    f"audit receipt {field} does not match recomputed audit"
                )


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedTransparencyAuditReceipt(f"{field} must be a string")
    return value


def _nonempty_str(value: Any, field: str) -> str:
    value = _str(value, field)
    if not value.strip():
        raise MalformedTransparencyAuditReceipt(f"{field} must not be empty")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedTransparencyAuditReceipt(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedTransparencyAuditReceipt(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedTransparencyAuditReceipt(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    value = _str(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise MalformedTransparencyAuditReceipt(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "MalformedTransparencyAuditReceipt",
    "TRANSPARENCY_AUDIT_RECEIPT_VERSION",
    "TransparencyAuditReceipt",
    "TransparencyAuditReceiptBindingError",
    "TransparencyAuditReceiptError",
    "TransparencyAuditReceiptSignatureInvalid",
    "TransparencyAuditReceiptSigner",
    "TransparencyAuditReceiptVerifier",
    "digest_gossip_bundle",
    "digest_quorum_certificate",
    "digest_transparency_result",
]
