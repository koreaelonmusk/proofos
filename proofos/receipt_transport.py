"""Short-lived authenticated transport for ProofOS jev0 verification receipts.

The content-addressed receipt proves what was independently re-derived. This
module adds a separate statement about *who transported that receipt*.

The transport envelope deliberately does not carry a public key, receipt body,
authority bit, or verdict. A receiver must be configured with the trusted
ProofOS public key out of band and must supply the expected one-time nonce.

Trust layers remain separate:

receipt integrity != transport identity != Extropy authority != terminal truth
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .integrity import canonical_payload, content_hash

TRANSPORT_VERSION = "proofos.extropy.jev0.receipt-transport.v1"
TRANSPORT_AUDIENCE = "extropy-proofos-jev0-receipt"
TRANSPORT_ISSUER = "proofos-truth-plane"
MAX_TRANSPORT_LIFETIME_MS = 5 * 60 * 1000
MAX_CLOCK_SKEW_MS = 30 * 1000
MAX_SAFE_INTEGER = (1 << 53) - 1

RECEIPT_KIND = "proofos-extropy-jev0-verification-receipt"
RECEIPT_SCHEMA_VERSION = 1
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")

RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "execution_report_sha256",
        "verifier_sha256",
        "verification_result_sha256",
        "executable_sha256",
        "policy_sha256",
        "capabilities_sha256",
        "verified_record_count",
        "verified_capability_ids",
        "claim_boundary",
        "receipt_sha256",
    }
)

SIGNED_FIELDS = (
    "version",
    "audience",
    "issuer",
    "key_id",
    "receipt_sha256",
    "execution_report_sha256",
    "verifier_sha256",
    "request_nonce",
    "issued_at_unix_ms",
    "expires_at_unix_ms",
)
ENVELOPE_FIELDS = frozenset((*SIGNED_FIELDS, "signature"))


class ReceiptTransportError(ValueError):
    pass


class ReceiptTransportMalformed(ReceiptTransportError):
    pass


class ReceiptTransportSignatureInvalid(ReceiptTransportError):
    pass


class ReceiptTransportBindingInvalid(ReceiptTransportError):
    pass


def _strict_string(value: Any, field: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ReceiptTransportMalformed(f"{field} must be a bounded non-empty string")
    return value


def _strict_ms(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_SAFE_INTEGER
    ):
        raise ReceiptTransportMalformed(f"{field} must be a non-negative safe integer")
    return value


def _receipt_identity(receipt: Any) -> tuple[str, str, str]:
    if not isinstance(receipt, Mapping) or set(receipt) != RECEIPT_FIELDS:
        raise ReceiptTransportMalformed("receipt schema drifted")
    if (
        receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION
        or receipt.get("kind") != RECEIPT_KIND
    ):
        raise ReceiptTransportMalformed("receipt identity is invalid")

    for field in (
        "receipt_sha256",
        "execution_report_sha256",
        "verifier_sha256",
        "verification_result_sha256",
        "executable_sha256",
        "policy_sha256",
        "capabilities_sha256",
    ):
        value = receipt.get(field)
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            raise ReceiptTransportMalformed(f"{field} must be lowercase SHA-256")

    unsigned = dict(receipt)
    supplied = unsigned.pop("receipt_sha256")
    if supplied != content_hash(unsigned):
        raise ReceiptTransportMalformed("receipt content digest mismatch")

    return (
        supplied,
        str(receipt["execution_report_sha256"]),
        str(receipt["verifier_sha256"]),
    )


@dataclass(frozen=True)
class SignedReceiptTransportEnvelope:
    version: str
    audience: str
    issuer: str
    key_id: str
    receipt_sha256: str
    execution_report_sha256: str
    verifier_sha256: str
    request_nonce: str
    issued_at_unix_ms: int
    expires_at_unix_ms: int
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in SIGNED_FIELDS}

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: Any) -> "SignedReceiptTransportEnvelope":
        if not isinstance(value, Mapping) or set(value) != ENVELOPE_FIELDS:
            raise ReceiptTransportMalformed("transport envelope schema drifted")

        version = _strict_string(value["version"], "version")
        audience = _strict_string(value["audience"], "audience")
        issuer = _strict_string(value["issuer"], "issuer")
        key_id = _strict_string(value["key_id"], "key_id", max_length=128)
        receipt_sha256 = _strict_string(
            value["receipt_sha256"], "receipt_sha256", max_length=64
        )
        execution_report_sha256 = _strict_string(
            value["execution_report_sha256"],
            "execution_report_sha256",
            max_length=64,
        )
        verifier_sha256 = _strict_string(
            value["verifier_sha256"], "verifier_sha256", max_length=64
        )
        request_nonce = _strict_string(
            value["request_nonce"], "request_nonce", max_length=128
        )
        issued_at = _strict_ms(value["issued_at_unix_ms"], "issued_at_unix_ms")
        expires_at = _strict_ms(value["expires_at_unix_ms"], "expires_at_unix_ms")
        signature = _strict_string(value["signature"], "signature", max_length=128)

        if version != TRANSPORT_VERSION:
            raise ReceiptTransportMalformed("transport version is unsupported")
        if audience != TRANSPORT_AUDIENCE:
            raise ReceiptTransportMalformed("transport audience is invalid")
        if issuer != TRANSPORT_ISSUER:
            raise ReceiptTransportMalformed("transport issuer is invalid")
        if not KEY_ID.fullmatch(key_id):
            raise ReceiptTransportMalformed("transport key_id is invalid")
        if not HEX64.fullmatch(receipt_sha256):
            raise ReceiptTransportMalformed("receipt_sha256 must be lowercase SHA-256")
        if not HEX64.fullmatch(execution_report_sha256):
            raise ReceiptTransportMalformed(
                "execution_report_sha256 must be lowercase SHA-256"
            )
        if not HEX64.fullmatch(verifier_sha256):
            raise ReceiptTransportMalformed("verifier_sha256 must be lowercase SHA-256")
        if not NONCE.fullmatch(request_nonce):
            raise ReceiptTransportMalformed("request_nonce is invalid")
        if expires_at <= issued_at:
            raise ReceiptTransportMalformed("transport expiry must follow issuance")
        if expires_at - issued_at > MAX_TRANSPORT_LIFETIME_MS:
            raise ReceiptTransportMalformed("transport lifetime exceeds maximum")

        try:
            decoded = base64.b64decode(signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise ReceiptTransportMalformed("transport signature is not valid base64") from exc
        if len(decoded) != 64:
            raise ReceiptTransportMalformed("transport signature must be 64 bytes")

        return cls(
            version=version,
            audience=audience,
            issuer=issuer,
            key_id=key_id,
            receipt_sha256=receipt_sha256,
            execution_report_sha256=execution_report_sha256,
            verifier_sha256=verifier_sha256,
            request_nonce=request_nonce,
            issued_at_unix_ms=issued_at,
            expires_at_unix_ms=expires_at,
            signature=signature,
        )


class ReceiptTransportSigner:
    """Truth-plane signer. The private key never appears in the envelope."""

    __slots__ = ("_key", "key_id")

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        if not KEY_ID.fullmatch(key_id):
            raise ReceiptTransportMalformed("transport key_id is invalid")
        self._key = private_key
        self.key_id = key_id

    @classmethod
    def generate(cls, key_id: str) -> "ReceiptTransportSigner":
        return cls(Ed25519PrivateKey.generate(), key_id)

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes()).decode("ascii")

    def sign(
        self,
        receipt: Mapping[str, Any],
        *,
        request_nonce: str,
        issued_at_unix_ms: int,
        lifetime_ms: int = 120_000,
    ) -> SignedReceiptTransportEnvelope:
        receipt_sha256, report_sha256, verifier_sha256 = _receipt_identity(receipt)
        if not NONCE.fullmatch(request_nonce):
            raise ReceiptTransportMalformed("request_nonce is invalid")
        issued_at = _strict_ms(issued_at_unix_ms, "issued_at_unix_ms")
        if (
            isinstance(lifetime_ms, bool)
            or not isinstance(lifetime_ms, int)
            or lifetime_ms <= 0
            or lifetime_ms > MAX_TRANSPORT_LIFETIME_MS
        ):
            raise ReceiptTransportMalformed("transport lifetime is invalid")
        expires_at = issued_at + lifetime_ms
        if expires_at > MAX_SAFE_INTEGER:
            raise ReceiptTransportMalformed("transport expiry exceeds safe integer")

        unsigned = SignedReceiptTransportEnvelope(
            version=TRANSPORT_VERSION,
            audience=TRANSPORT_AUDIENCE,
            issuer=TRANSPORT_ISSUER,
            key_id=self.key_id,
            receipt_sha256=receipt_sha256,
            execution_report_sha256=report_sha256,
            verifier_sha256=verifier_sha256,
            request_nonce=request_nonce,
            issued_at_unix_ms=issued_at,
            expires_at_unix_ms=expires_at,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return SignedReceiptTransportEnvelope(
            **{
                **unsigned.signed_fields(),
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class ReceiptTransportVerifier:
    """Receiver-side verifier configured with one trusted ProofOS public key."""

    __slots__ = ("_public_key", "key_id")

    def __init__(self, public_key: Ed25519PublicKey, key_id: str) -> None:
        if not KEY_ID.fullmatch(key_id):
            raise ReceiptTransportMalformed("trusted key_id is invalid")
        self._public_key = public_key
        self.key_id = key_id

    @classmethod
    def from_b64(cls, public_key_b64: str, key_id: str) -> "ReceiptTransportVerifier":
        try:
            raw = base64.b64decode(public_key_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise ReceiptTransportMalformed("trusted public key is not valid base64") from exc
        if len(raw) != 32:
            raise ReceiptTransportMalformed("trusted Ed25519 public key must be 32 bytes")
        return cls(Ed25519PublicKey.from_public_bytes(raw), key_id)

    def verify(
        self,
        envelope_value: Any,
        receipt: Mapping[str, Any],
        *,
        expected_nonce: str,
        now_unix_ms: int,
    ) -> SignedReceiptTransportEnvelope:
        envelope = SignedReceiptTransportEnvelope.from_dict(envelope_value)
        if envelope.key_id != self.key_id:
            raise ReceiptTransportBindingInvalid("transport key_id is not trusted")

        receipt_sha256, report_sha256, verifier_sha256 = _receipt_identity(receipt)
        if envelope.receipt_sha256 != receipt_sha256:
            raise ReceiptTransportBindingInvalid("transport receipt digest mismatch")
        if envelope.execution_report_sha256 != report_sha256:
            raise ReceiptTransportBindingInvalid("transport report digest mismatch")
        if envelope.verifier_sha256 != verifier_sha256:
            raise ReceiptTransportBindingInvalid("transport verifier digest mismatch")
        if envelope.request_nonce != expected_nonce:
            raise ReceiptTransportBindingInvalid("transport nonce mismatch")

        now = _strict_ms(now_unix_ms, "now_unix_ms")
        if now + MAX_CLOCK_SKEW_MS < envelope.issued_at_unix_ms:
            raise ReceiptTransportBindingInvalid("transport envelope is future-dated")
        if now > envelope.expires_at_unix_ms:
            raise ReceiptTransportBindingInvalid("transport envelope is expired")

        try:
            signature = base64.b64decode(envelope.signature, validate=True)
            self._public_key.verify(signature, envelope.signing_bytes())
        except (ValueError, InvalidSignature) as exc:
            raise ReceiptTransportSignatureInvalid(
                "transport signature does not match signed fields"
            ) from exc

        return envelope
