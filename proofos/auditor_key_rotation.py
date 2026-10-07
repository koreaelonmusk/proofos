"""Cryptographic continuity for auditor signing-key rotation.

A signed transparency audit receipt is only as durable as the trust anchor used
to verify its auditor signature. Replacing that key without a proof of succession
would create a silent trust reset.

This module defines a dual-signed transition:
- the previous auditor key authorizes the successor;
- the successor key proves possession;
- generation numbers must advance exactly by one;
- every transition commits to the previous transition digest.

The transition changes only which public key represents one auditor identity.
It carries no task-completion verdict, evidence, capability, or execution
authority.
"""

from __future__ import annotations

import base64
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .integrity import canonical_payload, content_hash
from .keys import encode_public_key

AUDITOR_KEY_TRANSITION_VERSION = "proofos.auditor-key-transition.v1"
KEY_TRANSITION_GENESIS = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SIGNED_FIELDS: tuple[str, ...] = (
    "version",
    "auditor_id",
    "generation",
    "previous_public_key",
    "next_public_key",
    "previous_transition_digest",
    "issued_at",
)
ENVELOPE_FIELDS: tuple[str, ...] = SIGNED_FIELDS + (
    "previous_key_signature",
    "next_key_signature",
)


class AuditorKeyTransitionError(ValueError):
    pass


class MalformedAuditorKeyTransition(AuditorKeyTransitionError):
    pass


class AuditorKeyTransitionSignatureInvalid(AuditorKeyTransitionError):
    pass


class AuditorKeyContinuityError(AuditorKeyTransitionError):
    pass


@dataclass(frozen=True)
class AuditorKeyTransition:
    """One dual-signed auditor-key succession statement."""

    version: str
    auditor_id: str
    generation: int
    previous_public_key: str
    next_public_key: str
    previous_transition_digest: str
    issued_at: float
    previous_key_signature: str
    next_key_signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "auditor_id": self.auditor_id,
            "generation": self.generation,
            "previous_public_key": self.previous_public_key,
            "next_public_key": self.next_public_key,
            "previous_transition_digest": self.previous_transition_digest,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def transition_digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signed_fields(),
            "previous_key_signature": self.previous_key_signature,
            "next_key_signature": self.next_key_signature,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AuditorKeyTransition":
        if not isinstance(data, Mapping):
            raise MalformedAuditorKeyTransition(
                f"expected an object, got {type(data).__name__}"
            )

        keys = set(data)
        expected = set(ENVELOPE_FIELDS)
        unexpected = keys - expected
        missing = expected - keys
        if unexpected:
            raise MalformedAuditorKeyTransition(
                f"unexpected fields: {sorted(unexpected)}"
            )
        if missing:
            raise MalformedAuditorKeyTransition(
                f"missing fields: {sorted(missing)}"
            )

        transition = cls(
            version=_nonempty_str(data["version"], "version"),
            auditor_id=_nonempty_str(data["auditor_id"], "auditor_id"),
            generation=_int(data["generation"], "generation"),
            previous_public_key=_public_key(
                data["previous_public_key"], "previous_public_key"
            ),
            next_public_key=_public_key(data["next_public_key"], "next_public_key"),
            previous_transition_digest=_digest(
                data["previous_transition_digest"], "previous_transition_digest"
            ),
            issued_at=_float(data["issued_at"], "issued_at"),
            previous_key_signature=_signature(
                data["previous_key_signature"], "previous_key_signature"
            ),
            next_key_signature=_signature(
                data["next_key_signature"], "next_key_signature"
            ),
        )

        if transition.version != AUDITOR_KEY_TRANSITION_VERSION:
            raise MalformedAuditorKeyTransition(
                f"unsupported auditor key transition version {transition.version!r}"
            )
        if transition.generation < 1:
            raise MalformedAuditorKeyTransition("generation must be >= 1")
        if transition.previous_public_key == transition.next_public_key:
            raise MalformedAuditorKeyTransition(
                "rotation must change the auditor public key"
            )
        return transition


class AuditorKeyTransitionSigner:
    """Construct a transition only when both old and new private keys are held."""

    @staticmethod
    def sign(
        *,
        auditor_id: str,
        generation: int,
        previous_private_key: Ed25519PrivateKey,
        next_private_key: Ed25519PrivateKey,
        previous_transition_digest: str = KEY_TRANSITION_GENESIS,
        issued_at: float | None = None,
    ) -> AuditorKeyTransition:
        if not auditor_id.strip():
            raise ValueError("auditor_id must not be empty")
        if generation < 1:
            raise ValueError("generation must be >= 1")
        if not _SHA256_RE.fullmatch(previous_transition_digest):
            raise ValueError(
                "previous_transition_digest must be a lowercase SHA-256 hex digest"
            )

        previous_public_key = encode_public_key(previous_private_key.public_key())
        next_public_key = encode_public_key(next_private_key.public_key())
        if previous_public_key == next_public_key:
            raise ValueError("rotation must change the auditor public key")

        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")

        unsigned = AuditorKeyTransition(
            version=AUDITOR_KEY_TRANSITION_VERSION,
            auditor_id=auditor_id,
            generation=generation,
            previous_public_key=previous_public_key,
            next_public_key=next_public_key,
            previous_transition_digest=previous_transition_digest,
            issued_at=stamp,
            previous_key_signature="",
            next_key_signature="",
        )
        payload = unsigned.signing_bytes()
        return AuditorKeyTransition(
            **{
                **unsigned.signed_fields(),
                "previous_key_signature": base64.b64encode(
                    previous_private_key.sign(payload)
                ).decode("ascii"),
                "next_key_signature": base64.b64encode(
                    next_private_key.sign(payload)
                ).decode("ascii"),
            }
        )


def verify_transition(transition: AuditorKeyTransition) -> None:
    """Verify schema-version semantics and both possession signatures."""
    if transition.version != AUDITOR_KEY_TRANSITION_VERSION:
        raise AuditorKeyContinuityError(
            f"unsupported auditor key transition version {transition.version!r}"
        )
    if transition.generation < 1:
        raise AuditorKeyContinuityError("generation must be >= 1")
    if transition.previous_public_key == transition.next_public_key:
        raise AuditorKeyContinuityError("rotation did not change public key")
    if not math.isfinite(transition.issued_at):
        raise AuditorKeyContinuityError("issued_at must be finite")
    if not _SHA256_RE.fullmatch(transition.previous_transition_digest):
        raise AuditorKeyContinuityError(
            "previous_transition_digest is not a SHA-256 digest"
        )

    previous = _decode_public_key(transition.previous_public_key)
    successor = _decode_public_key(transition.next_public_key)
    payload = transition.signing_bytes()

    _verify_signature(
        previous,
        transition.previous_key_signature,
        payload,
        "previous auditor key",
    )
    _verify_signature(
        successor,
        transition.next_key_signature,
        payload,
        "next auditor key",
    )


def verify_transition_chain(
    *,
    auditor_id: str,
    initial_public_key: str,
    transitions: Iterable[AuditorKeyTransition],
) -> str:
    """Verify complete key continuity and return the final trusted public key."""
    current_key = _public_key(initial_public_key, "initial_public_key")
    previous_digest = KEY_TRANSITION_GENESIS
    expected_generation = 1

    for transition in transitions:
        verify_transition(transition)

        if transition.auditor_id != auditor_id:
            raise AuditorKeyContinuityError(
                f"transition belongs to {transition.auditor_id!r}, not {auditor_id!r}"
            )
        if transition.generation != expected_generation:
            raise AuditorKeyContinuityError(
                f"expected auditor key generation {expected_generation}, "
                f"got {transition.generation}"
            )
        if transition.previous_public_key != current_key:
            raise AuditorKeyContinuityError(
                f"generation {transition.generation} does not build on "
                "the currently trusted auditor key"
            )
        if transition.previous_transition_digest != previous_digest:
            raise AuditorKeyContinuityError(
                f"generation {transition.generation} does not follow "
                "the previous transition digest"
            )

        current_key = transition.next_public_key
        previous_digest = transition.transition_digest()
        expected_generation += 1

    return current_key


def _decode_public_key(encoded: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(encoded, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise AuditorKeyTransitionSignatureInvalid(
            f"public key is not valid Ed25519 base64: {exc}"
        ) from exc


def _verify_signature(
    key: Ed25519PublicKey,
    encoded_signature: str,
    payload: bytes,
    label: str,
) -> None:
    try:
        signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise AuditorKeyTransitionSignatureInvalid(
            f"{label} signature is not valid base64: {exc}"
        ) from exc
    if len(signature) != 64:
        raise AuditorKeyTransitionSignatureInvalid(
            f"{label} Ed25519 signature is {len(signature)} bytes, expected 64"
        )
    try:
        key.verify(signature, payload)
    except InvalidSignature as exc:
        raise AuditorKeyTransitionSignatureInvalid(
            f"{label} signature does not match transition"
        ) from exc


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedAuditorKeyTransition(f"{field} must be a string")
    return value


def _nonempty_str(value: Any, field: str) -> str:
    value = _str(value, field)
    if not value.strip():
        raise MalformedAuditorKeyTransition(f"{field} must not be empty")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedAuditorKeyTransition(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedAuditorKeyTransition(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedAuditorKeyTransition(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    value = _str(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise MalformedAuditorKeyTransition(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


def _public_key(value: Any, field: str) -> str:
    value = _nonempty_str(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise MalformedAuditorKeyTransition(
            f"{field} must be a raw Ed25519 public key encoded as base64"
        ) from exc
    if len(raw) != 32:
        raise MalformedAuditorKeyTransition(
            f"{field} decoded to {len(raw)} bytes, expected 32"
        )
    return value


def _signature(value: Any, field: str) -> str:
    value = _nonempty_str(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise MalformedAuditorKeyTransition(
            f"{field} must be valid base64"
        ) from exc
    if len(raw) != 64:
        raise MalformedAuditorKeyTransition(
            f"{field} decoded to {len(raw)} bytes, expected 64"
        )
    return value


__all__ = [
    "AUDITOR_KEY_TRANSITION_VERSION",
    "KEY_TRANSITION_GENESIS",
    "AuditorKeyContinuityError",
    "AuditorKeyTransition",
    "AuditorKeyTransitionError",
    "AuditorKeyTransitionSignatureInvalid",
    "AuditorKeyTransitionSigner",
    "MalformedAuditorKeyTransition",
    "verify_transition",
    "verify_transition_chain",
]
