"""Signed observation attestations.

An in-process grant stops a component writing evidence it was never given
authority for. It cannot stop code running in the same interpreter, because
that code can reach the grant. The fix is to move the authority to a process
that holds a private key nobody else has.

An attestation is a collector's signed statement of what it observed. The
orchestrator can carry one from the collector to the ledger; it cannot author
one, and it cannot change a byte of one without the signature failing.

Two rules shape this module:

* **``source`` is never transmitted.** An attestation says what was observed,
  not how much to trust it. Whether an observation becomes OBSERVED evidence is
  decided by the receiving runtime after verification, and nothing on the wire
  can assert it.
* **Signatures cover re-canonicalized fields, not received bytes.** The payload
  is parsed under a strict schema and serialized again deterministically before
  verification, so reordered keys, whitespace, or smuggled extra fields cannot
  change what was signed and what is checked.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .integrity import canonical_payload, content_hash

ATTESTATION_VERSION = "proofos.observation.v1"

#: Exactly the fields that are signed. Not a subset, not a superset -- an
#: attestation carrying an unexpected field is refused rather than ignored,
#: because "ignored" is where smuggling lives.
SIGNED_FIELDS: tuple[str, ...] = (
    "version",
    "execution_id",
    "task_id",
    "kind",
    "collector_id",
    "profile_id",
    "request_nonce",
    "observed_at",
    "outcome",
    "status_code",
    "response_digest",
)

ENVELOPE_FIELDS: tuple[str, ...] = SIGNED_FIELDS + ("detail", "signature")


class AttestationError(ValueError):
    """Raised when an attestation is malformed, unsigned, or forged."""


class MalformedAttestation(AttestationError):
    pass


class SignatureInvalid(AttestationError):
    pass


class Outcome(StrEnum):
    """What the collector saw. Deliberately not a verdict.

    A collector reports HEALTHY or UNHEALTHY_STATUS with equal authority. Both
    are authentic observations; only one helps a claim. Discarding the negative
    one would throw away the most useful audit evidence there is.
    """

    HEALTHY = "HEALTHY"
    UNHEALTHY_STATUS = "UNHEALTHY_STATUS"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    REDIRECTED = "REDIRECTED"
    TIMEOUT = "TIMEOUT"
    UNREACHABLE = "UNREACHABLE"

    @property
    def satisfies(self) -> bool:
        """Only a healthy observation can support a completion claim."""
        return self is Outcome.HEALTHY

    @property
    def observed_response(self) -> bool:
        """True when bytes actually came back from the network."""
        return self in {
            Outcome.HEALTHY,
            Outcome.UNHEALTHY_STATUS,
            Outcome.MALFORMED_RESPONSE,
        }


@dataclass(frozen=True)
class ObservationAttestation:
    """A collector's signed statement about one observation."""

    version: str
    execution_id: str
    task_id: str
    kind: str
    collector_id: str
    profile_id: str
    request_nonce: str
    observed_at: float
    outcome: Outcome
    status_code: int | None
    response_digest: str
    detail: str
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "kind": self.kind,
            "collector_id": self.collector_id,
            "profile_id": self.profile_id,
            "request_nonce": self.request_nonce,
            "observed_at": self.observed_at,
            "outcome": str(self.outcome),
            "status_code": self.status_code,
            "response_digest": self.response_digest,
        }

    def signing_bytes(self) -> bytes:
        """Deterministic bytes over the signed fields, rebuilt from parsed data."""
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        payload = self.signed_fields()
        payload["detail"] = self.detail
        payload["signature"] = self.signature
        return payload

    @classmethod
    def from_dict(cls, data: Any) -> "ObservationAttestation":
        """Parse under a strict schema.

        Unknown or missing fields are refused rather than dropped: a field the
        parser silently ignores is a field an attacker can hide meaning in, and
        a field it silently defaults is one the signature never covered.
        """
        if not isinstance(data, Mapping):
            raise MalformedAttestation(
                f"expected an object, got {type(data).__name__}"
            )

        keys = set(data.keys())
        expected = set(ENVELOPE_FIELDS)
        unexpected = keys - expected
        missing = expected - keys
        if unexpected:
            raise MalformedAttestation(f"unexpected fields: {sorted(unexpected)}")
        if missing:
            raise MalformedAttestation(f"missing fields: {sorted(missing)}")

        try:
            status = data["status_code"]
            return cls(
                version=_as_str(data["version"], "version"),
                execution_id=_as_str(data["execution_id"], "execution_id"),
                task_id=_as_str(data["task_id"], "task_id"),
                kind=_as_str(data["kind"], "kind"),
                collector_id=_as_str(data["collector_id"], "collector_id"),
                profile_id=_as_str(data["profile_id"], "profile_id"),
                request_nonce=_as_str(data["request_nonce"], "request_nonce"),
                observed_at=_as_float(data["observed_at"], "observed_at"),
                outcome=Outcome(data["outcome"]),
                status_code=None if status is None else _as_int(status, "status_code"),
                response_digest=_as_str(data["response_digest"], "response_digest"),
                detail=_as_str(data["detail"], "detail"),
                signature=_as_str(data["signature"], "signature"),
            )
        except MalformedAttestation:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise MalformedAttestation(f"malformed attestation: {exc}") from exc


def _as_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedAttestation(f"{field} must be a string")
    return value


def _as_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedAttestation(f"{field} must be a number")
    return float(value)


def _as_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedAttestation(f"{field} must be an integer")
    return value


def response_digest(body: bytes) -> str:
    """Digest of exactly the bytes the collector received."""
    return content_hash({"body": base64.b64encode(body).decode("ascii")})


class AttestationSigner:
    """Holds the private key. Lives only inside a collector process.

    Nothing in this class exports the private key, and no other component is
    constructed with one. That asymmetry is the whole point: an orchestrator
    with a shared secret could fabricate collector evidence, so it is given a
    public key and nothing else.
    """

    __slots__ = ("_key", "collector_id")

    def __init__(self, private_key: Ed25519PrivateKey, collector_id: str) -> None:
        self._key = private_key
        self.collector_id = collector_id

    @classmethod
    def generate(cls, collector_id: str) -> "AttestationSigner":
        return cls(Ed25519PrivateKey.generate(), collector_id)

    def public_key(self) -> Ed25519PublicKey:
        """The public half. There is deliberately no private-key accessor."""
        return self._key.public_key()

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes()).decode("ascii")

    def sign(
        self,
        execution_id: str,
        task_id: str,
        kind: str,
        profile_id: str,
        request_nonce: str,
        observed_at: float,
        outcome: Outcome,
        status_code: int | None,
        response_digest_value: str,
        detail: str,
    ) -> ObservationAttestation:
        unsigned = ObservationAttestation(
            version=ATTESTATION_VERSION,
            execution_id=execution_id,
            task_id=task_id,
            kind=kind,
            collector_id=self.collector_id,
            profile_id=profile_id,
            request_nonce=request_nonce,
            observed_at=observed_at,
            outcome=outcome,
            status_code=status_code,
            response_digest=response_digest_value,
            detail=detail,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return ObservationAttestation(
            **{
                **{f: getattr(unsigned, f) for f in ENVELOPE_FIELDS if f != "signature"},
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class AttestationVerifier:
    """Holds only public keys. Cannot produce a signature."""

    __slots__ = ("_public_key",)

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key

    @classmethod
    def from_bytes(cls, raw: bytes) -> "AttestationVerifier":
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    @classmethod
    def from_b64(cls, encoded: str) -> "AttestationVerifier":
        return cls.from_bytes(base64.b64decode(encoded, validate=True))

    def verify(self, attestation: ObservationAttestation) -> None:
        """Raise SignatureInvalid unless the signature covers these exact fields."""
        try:
            signature = base64.b64decode(attestation.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise SignatureInvalid(f"signature is not valid base64: {exc}") from exc

        if len(signature) != 64:
            raise SignatureInvalid(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )

        try:
            self._public_key.verify(signature, attestation.signing_bytes())
        except InvalidSignature as exc:
            raise SignatureInvalid(
                "signature does not match the attested fields"
            ) from exc
