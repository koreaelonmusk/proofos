"""Threshold-signed revocation registry for recovery authorities.

Recovery-policy continuity proves who is allowed to authorize emergency key
recovery. A separate revocation registry answers the time-sensitive question:
when did one of those authorities stop being trusted?

Each revocation:
- is signed by the configured recovery-policy threshold excluding the target;
- binds the policy digest, target authority/key, incident id, effective auditor
  generation, and previous revocation digest;
- is append-only and externally head-pinned;
- does not rewrite historical recoveries before its effective generation.
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

from .auditor_key_recovery import RecoveryApproval, RecoveryPolicy, RecoveryPolicyError
from .integrity import canonical_payload, content_hash
from .keys import encode_public_key

RECOVERY_AUTHORITY_REVOCATION_VERSION = "proofos.recovery-authority-revocation.v1"
REVOCATION_GENESIS = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class RecoveryAuthorityRevocationError(ValueError):
    pass


class MalformedRecoveryAuthorityRevocation(RecoveryAuthorityRevocationError):
    pass


class RecoveryAuthorityRevocationSignatureInvalid(RecoveryAuthorityRevocationError):
    pass


class RecoveryAuthorityRevocationContinuityError(RecoveryAuthorityRevocationError):
    pass


@dataclass(frozen=True)
class RecoveryAuthorityRevocation:
    version: str
    revocation_generation: int
    policy_digest: str
    authority_id: str
    authority_public_key: str
    effective_from_auditor_generation: int
    incident_id: str
    previous_revocation_digest: str
    issued_at: float
    approvals: tuple[RecoveryApproval, ...]

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "revocation_generation": self.revocation_generation,
            "policy_digest": self.policy_digest,
            "authority_id": self.authority_id,
            "authority_public_key": self.authority_public_key,
            "effective_from_auditor_generation": (
                self.effective_from_auditor_generation
            ),
            "incident_id": self.incident_id,
            "previous_revocation_digest": self.previous_revocation_digest,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def revocation_digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signed_fields(),
            "approvals": [item.to_dict() for item in self.approvals],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "RecoveryAuthorityRevocation":
        if not isinstance(data, Mapping):
            raise MalformedRecoveryAuthorityRevocation(
                "recovery authority revocation must be an object"
            )
        expected = {
            "version",
            "revocation_generation",
            "policy_digest",
            "authority_id",
            "authority_public_key",
            "effective_from_auditor_generation",
            "incident_id",
            "previous_revocation_digest",
            "issued_at",
            "approvals",
        }
        if set(data) != expected:
            raise MalformedRecoveryAuthorityRevocation(
                "recovery authority revocation fields are not exact"
            )
        raw_approvals = data["approvals"]
        if not isinstance(raw_approvals, list):
            raise MalformedRecoveryAuthorityRevocation(
                "revocation approvals must be a list"
            )
        approvals = tuple(RecoveryApproval.from_dict(item) for item in raw_approvals)
        ids = tuple(item.authority_id for item in approvals)
        if ids != tuple(sorted(set(ids))):
            raise MalformedRecoveryAuthorityRevocation(
                "revocation approvals must be unique and sorted"
            )
        item = cls(
            version=_nonempty_str(data["version"], "version"),
            revocation_generation=_int(
                data["revocation_generation"], "revocation_generation"
            ),
            policy_digest=_digest(data["policy_digest"], "policy_digest"),
            authority_id=_nonempty_str(data["authority_id"], "authority_id"),
            authority_public_key=_canonical_public_key(
                data["authority_public_key"], "authority_public_key"
            ),
            effective_from_auditor_generation=_int(
                data["effective_from_auditor_generation"],
                "effective_from_auditor_generation",
            ),
            incident_id=_nonempty_str(data["incident_id"], "incident_id"),
            previous_revocation_digest=_digest(
                data["previous_revocation_digest"], "previous_revocation_digest"
            ),
            issued_at=_float(data["issued_at"], "issued_at"),
            approvals=approvals,
        )
        if item.version != RECOVERY_AUTHORITY_REVOCATION_VERSION:
            raise MalformedRecoveryAuthorityRevocation(
                f"unsupported revocation version {item.version!r}"
            )
        if item.revocation_generation < 1:
            raise MalformedRecoveryAuthorityRevocation(
                "revocation_generation must be >= 1"
            )
        if item.effective_from_auditor_generation < 1:
            raise MalformedRecoveryAuthorityRevocation(
                "effective_from_auditor_generation must be >= 1"
            )
        return item


class RecoveryAuthorityRevocationSigner:
    @staticmethod
    def sign(
        *,
        revocation_generation: int,
        policy: RecoveryPolicy,
        authority_id: str,
        effective_from_auditor_generation: int,
        incident_id: str,
        authority_private_keys: Mapping[str, Ed25519PrivateKey],
        previous_revocation_digest: str = REVOCATION_GENESIS,
        issued_at: float | None = None,
    ) -> RecoveryAuthorityRevocation:
        if isinstance(revocation_generation, bool) or not isinstance(
            revocation_generation, int
        ):
            raise ValueError("revocation_generation must be an integer")
        if revocation_generation < 1:
            raise ValueError("revocation_generation must be >= 1")
        if isinstance(effective_from_auditor_generation, bool) or not isinstance(
            effective_from_auditor_generation, int
        ):
            raise ValueError(
                "effective_from_auditor_generation must be an integer"
            )
        if effective_from_auditor_generation < 1:
            raise ValueError(
                "effective_from_auditor_generation must be >= 1"
            )
        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")
        if not _SHA256_RE.fullmatch(previous_revocation_digest):
            raise ValueError("previous_revocation_digest must be a SHA-256 digest")

        authority_public_key = policy.public_key_for(authority_id)
        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")

        unsigned = RecoveryAuthorityRevocation(
            version=RECOVERY_AUTHORITY_REVOCATION_VERSION,
            revocation_generation=revocation_generation,
            policy_digest=policy.digest(),
            authority_id=authority_id,
            authority_public_key=authority_public_key,
            effective_from_auditor_generation=effective_from_auditor_generation,
            incident_id=incident_id,
            previous_revocation_digest=previous_revocation_digest,
            issued_at=stamp,
            approvals=(),
        )
        payload = unsigned.signing_bytes()

        approvals: list[RecoveryApproval] = []
        for signer_id in sorted(authority_private_keys):
            if signer_id == authority_id:
                raise RecoveryPolicyError(
                    "revoked authority cannot approve its own revocation"
                )
            if signer_id not in policy.authority_ids:
                raise RecoveryPolicyError(
                    f"authority {signer_id!r} is not allowed by recovery policy"
                )
            key = authority_private_keys[signer_id]
            if encode_public_key(key.public_key()) != policy.public_key_for(signer_id):
                raise RecoveryPolicyError(
                    f"private key for {signer_id!r} does not match recovery policy"
                )
            approvals.append(
                RecoveryApproval(
                    authority_id=signer_id,
                    signature=base64.b64encode(key.sign(payload)).decode("ascii"),
                )
            )

        if len(approvals) < policy.threshold:
            raise RecoveryPolicyError(
                f"authority revocation requires {policy.threshold} non-target "
                f"approvals, got {len(approvals)}"
            )

        return RecoveryAuthorityRevocation(
            **{
                **unsigned.signed_fields(),
                "approvals": tuple(approvals),
            }
        )


def verify_revocation(
    revocation: RecoveryAuthorityRevocation,
    *,
    policy: RecoveryPolicy,
    expected_policy_digest: str,
) -> None:
    if revocation.version != RECOVERY_AUTHORITY_REVOCATION_VERSION:
        raise RecoveryAuthorityRevocationContinuityError(
            f"unsupported revocation version {revocation.version!r}"
        )
    if revocation.policy_digest != policy.digest():
        raise RecoveryPolicyError("revocation does not bind the supplied policy")
    if expected_policy_digest != policy.digest():
        raise RecoveryPolicyError("revocation policy digest does not match external pin")
    if policy.public_key_for(revocation.authority_id) != revocation.authority_public_key:
        raise RecoveryAuthorityRevocationContinuityError(
            "revocation authority key does not match recovery policy"
        )
    if revocation.effective_from_auditor_generation < 1:
        raise RecoveryAuthorityRevocationContinuityError(
            "effective_from_auditor_generation must be >= 1"
        )
    if not math.isfinite(revocation.issued_at):
        raise RecoveryAuthorityRevocationContinuityError("issued_at must be finite")

    ids = tuple(item.authority_id for item in revocation.approvals)
    if ids != tuple(sorted(set(ids))):
        raise RecoveryPolicyError("revocation approvals must be unique and sorted")
    if revocation.authority_id in ids:
        raise RecoveryPolicyError("revoked authority cannot approve its own revocation")
    if len(revocation.approvals) < policy.threshold:
        raise RecoveryPolicyError(
            f"authority revocation requires {policy.threshold} approvals, "
            f"got {len(revocation.approvals)}"
        )

    payload = revocation.signing_bytes()
    for approval in revocation.approvals:
        key = _decode_public_key(policy.public_key_for(approval.authority_id))
        _verify_signature(
            key,
            approval.signature,
            payload,
            f"recovery authority {approval.authority_id}",
        )


def verify_revocation_registry(
    *,
    policy: RecoveryPolicy,
    revocations: tuple[RecoveryAuthorityRevocation, ...],
    expected_generation: int,
    expected_head_digest: str,
) -> dict[str, int]:
    if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
        raise RecoveryAuthorityRevocationContinuityError(
            "expected_generation must be an integer"
        )
    if expected_generation < 0:
        raise RecoveryAuthorityRevocationContinuityError(
            "expected_generation must be >= 0"
        )
    if not _SHA256_RE.fullmatch(expected_head_digest):
        raise RecoveryAuthorityRevocationContinuityError(
            "expected_head_digest is not a SHA-256 digest"
        )

    previous_digest = REVOCATION_GENESIS
    next_generation = 1
    effective: dict[str, int] = {}

    for item in revocations:
        verify_revocation(
            item,
            policy=policy,
            expected_policy_digest=policy.digest(),
        )
        if item.revocation_generation != next_generation:
            raise RecoveryAuthorityRevocationContinuityError(
                f"expected revocation generation {next_generation}, "
                f"got {item.revocation_generation}"
            )
        if item.previous_revocation_digest != previous_digest:
            raise RecoveryAuthorityRevocationContinuityError(
                "revocation does not follow the current revocation registry head"
            )
        if item.authority_id in effective:
            raise RecoveryAuthorityRevocationContinuityError(
                f"authority {item.authority_id!r} is already revoked"
            )
        effective[item.authority_id] = item.effective_from_auditor_generation
        previous_digest = item.revocation_digest()
        next_generation += 1

    if len(revocations) != expected_generation:
        raise RecoveryAuthorityRevocationContinuityError(
            f"revocation registry rollback or truncation: expected generation "
            f"{expected_generation}, verified {len(revocations)}"
        )
    if previous_digest != expected_head_digest:
        raise RecoveryAuthorityRevocationContinuityError(
            "revocation registry head digest does not match external pin"
        )
    return effective


def parse_revocation_registry(
    data: Any,
) -> tuple[RecoveryAuthorityRevocation, ...]:
    if not isinstance(data, list):
        raise MalformedRecoveryAuthorityRevocation(
            "recovery authority revocation registry must be a JSON array"
        )
    return tuple(RecoveryAuthorityRevocation.from_dict(item) for item in data)


def revoked_for_auditor_generation(
    effective_generations: Mapping[str, int],
    auditor_generation: int,
) -> frozenset[str]:
    return frozenset(
        authority_id
        for authority_id, effective_from in effective_generations.items()
        if effective_from <= auditor_generation
    )


def _canonical_public_key(value: Any, field: str) -> str:
    value = _nonempty_str(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise MalformedRecoveryAuthorityRevocation(
            f"{field} must be a raw Ed25519 public key encoded as base64"
        ) from exc
    if len(raw) != 32:
        raise MalformedRecoveryAuthorityRevocation(
            f"{field} decoded to {len(raw)} bytes, expected 32"
        )
    if base64.b64encode(raw).decode("ascii") != value:
        raise MalformedRecoveryAuthorityRevocation(
            f"{field} must use canonical base64"
        )
    return value


def _decode_public_key(encoded: str) -> Ed25519PublicKey:
    raw = base64.b64decode(encoded, validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_signature(
    key: Ed25519PublicKey,
    encoded: str,
    payload: bytes,
    label: str,
) -> None:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise RecoveryAuthorityRevocationSignatureInvalid(
            f"{label} signature is not valid base64"
        ) from exc
    if len(raw) != 64:
        raise RecoveryAuthorityRevocationSignatureInvalid(
            f"{label} signature has invalid length"
        )
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise RecoveryAuthorityRevocationSignatureInvalid(
            f"{label} signature is not canonical base64"
        )
    try:
        key.verify(raw, payload)
    except InvalidSignature as exc:
        raise RecoveryAuthorityRevocationSignatureInvalid(
            f"{label} signature does not match revocation"
        ) from exc


def _nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedRecoveryAuthorityRevocation(
            f"{field} must be a non-empty string"
        )
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedRecoveryAuthorityRevocation(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedRecoveryAuthorityRevocation(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedRecoveryAuthorityRevocation(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise MalformedRecoveryAuthorityRevocation(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "RECOVERY_AUTHORITY_REVOCATION_VERSION",
    "REVOCATION_GENESIS",
    "MalformedRecoveryAuthorityRevocation",
    "RecoveryAuthorityRevocation",
    "RecoveryAuthorityRevocationContinuityError",
    "RecoveryAuthorityRevocationError",
    "RecoveryAuthorityRevocationSignatureInvalid",
    "RecoveryAuthorityRevocationSigner",
    "parse_revocation_registry",
    "revoked_for_auditor_generation",
    "verify_revocation",
    "verify_revocation_registry",
]
