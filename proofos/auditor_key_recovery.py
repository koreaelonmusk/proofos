"""Emergency recovery for a compromised auditor signing key.

Normal rotation requires the current auditor key to authorize its successor.
That rule is unsafe after compromise because the attacker also controls that key.

Emergency recovery therefore uses a separately pinned N-of-M recovery policy.
The compromised key does not sign the recovery. Instead:
- threshold recovery authorities sign one canonical recovery statement;
- the replacement auditor key proves possession;
- the statement binds the current key, generation, prior history digest,
  incident id, and externally pinned recovery-policy digest.

The recovery statement carries no task-completion, evidence, capability, or
execution authority.
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

from .auditor_key_rotation import (
    AuditorKeyContinuityError,
    AuditorKeyTransition,
    KEY_TRANSITION_GENESIS,
    verify_transition,
)
from .integrity import canonical_payload, content_hash
from .keys import encode_public_key

AUDITOR_KEY_RECOVERY_VERSION = "proofos.auditor-key-recovery.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditorKeyRecoveryError(ValueError):
    pass


class RecoveryPolicyError(AuditorKeyRecoveryError):
    pass


class MalformedAuditorKeyRecovery(AuditorKeyRecoveryError):
    pass


class AuditorKeyRecoverySignatureInvalid(AuditorKeyRecoveryError):
    pass


class AuditorKeyRecoveryContinuityError(AuditorKeyRecoveryError):
    pass


@dataclass(frozen=True)
class RecoveryPolicy:
    policy_id: str
    authorities: tuple[tuple[str, str], ...]
    threshold: int

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise RecoveryPolicyError("policy_id must not be empty")
        if not self.authorities:
            raise RecoveryPolicyError("recovery policy must name authorities")
        ids: list[str] = []
        keys: list[str] = []
        for entry in self.authorities:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise RecoveryPolicyError(
                    "each recovery authority entry must be (authority_id, public_key_b64)"
                )
            authority_id, public_key = entry
            if not isinstance(authority_id, str) or not authority_id.strip():
                raise RecoveryPolicyError("recovery authority ids must not be empty")
            public_key = _canonical_public_key(public_key, "recovery authority key")
            ids.append(authority_id)
            keys.append(public_key)
        if len(ids) != len(set(ids)):
            raise RecoveryPolicyError("recovery policy contains duplicate authorities")
        if len(keys) != len(set(keys)):
            raise RecoveryPolicyError(
                "recovery authorities must use distinct Ed25519 keys"
            )
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, int):
            raise RecoveryPolicyError("threshold must be an integer")
        if self.threshold < 1 or self.threshold > len(self.authorities):
            raise RecoveryPolicyError(
                "threshold must be between 1 and the configured authority count"
            )

    @property
    def authority_ids(self) -> tuple[str, ...]:
        return tuple(authority_id for authority_id, _ in self.authorities)

    def public_key_for(self, authority_id: str) -> str:
        for configured_id, public_key in self.authorities:
            if configured_id == authority_id:
                return public_key
        raise RecoveryPolicyError(
            f"authority {authority_id!r} is not allowed by recovery policy"
        )

    def digest(self) -> str:
        return content_hash(
            {
                "policy_id": self.policy_id,
                "authorities": sorted(self.authorities),
                "threshold": self.threshold,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "authorities": [
                {"authority_id": authority_id, "public_key": public_key}
                for authority_id, public_key in self.authorities
            ],
            "threshold": self.threshold,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "RecoveryPolicy":
        if not isinstance(data, Mapping):
            raise RecoveryPolicyError("recovery policy must be an object")
        expected = {"policy_id", "authorities", "threshold"}
        if set(data) != expected:
            raise RecoveryPolicyError("recovery policy fields are not exact")
        raw = data["authorities"]
        if not isinstance(raw, list):
            raise RecoveryPolicyError("authorities must be a list")
        authorities: list[tuple[str, str]] = []
        for item in raw:
            if not isinstance(item, Mapping) or set(item) != {
                "authority_id",
                "public_key",
            }:
                raise RecoveryPolicyError("malformed recovery authority entry")
            authorities.append(
                (
                    _nonempty_str(item["authority_id"], "authority_id"),
                    _canonical_public_key(item["public_key"], "public_key"),
                )
            )
        return cls(
            policy_id=_nonempty_str(data["policy_id"], "policy_id"),
            authorities=tuple(authorities),
            threshold=_int(data["threshold"], "threshold"),
        )


@dataclass(frozen=True)
class RecoveryApproval:
    authority_id: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {"authority_id": self.authority_id, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "RecoveryApproval":
        if not isinstance(data, Mapping) or set(data) != {"authority_id", "signature"}:
            raise MalformedAuditorKeyRecovery("malformed recovery approval")
        return cls(
            authority_id=_nonempty_str(data["authority_id"], "authority_id"),
            signature=_canonical_signature(data["signature"], "signature"),
        )


@dataclass(frozen=True)
class AuditorKeyRecovery:
    version: str
    auditor_id: str
    generation: int
    compromised_public_key: str
    replacement_public_key: str
    previous_history_digest: str
    recovery_policy_digest: str
    incident_id: str
    issued_at: float
    approvals: tuple[RecoveryApproval, ...]
    replacement_key_signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "auditor_id": self.auditor_id,
            "generation": self.generation,
            "compromised_public_key": self.compromised_public_key,
            "replacement_public_key": self.replacement_public_key,
            "previous_history_digest": self.previous_history_digest,
            "recovery_policy_digest": self.recovery_policy_digest,
            "incident_id": self.incident_id,
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def recovery_digest(self) -> str:
        return content_hash(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.signed_fields(),
            "approvals": [approval.to_dict() for approval in self.approvals],
            "replacement_key_signature": self.replacement_key_signature,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "AuditorKeyRecovery":
        if not isinstance(data, Mapping):
            raise MalformedAuditorKeyRecovery("recovery must be an object")
        expected = {
            "version",
            "auditor_id",
            "generation",
            "compromised_public_key",
            "replacement_public_key",
            "previous_history_digest",
            "recovery_policy_digest",
            "incident_id",
            "issued_at",
            "approvals",
            "replacement_key_signature",
        }
        if set(data) != expected:
            raise MalformedAuditorKeyRecovery("recovery fields are not exact")
        raw_approvals = data["approvals"]
        if not isinstance(raw_approvals, list):
            raise MalformedAuditorKeyRecovery("approvals must be a list")
        approvals = tuple(RecoveryApproval.from_dict(item) for item in raw_approvals)
        ids = tuple(approval.authority_id for approval in approvals)
        if ids != tuple(sorted(set(ids))):
            raise MalformedAuditorKeyRecovery(
                "recovery approvals must be unique and sorted by authority id"
            )
        recovery = cls(
            version=_nonempty_str(data["version"], "version"),
            auditor_id=_nonempty_str(data["auditor_id"], "auditor_id"),
            generation=_int(data["generation"], "generation"),
            compromised_public_key=_canonical_public_key(
                data["compromised_public_key"], "compromised_public_key"
            ),
            replacement_public_key=_canonical_public_key(
                data["replacement_public_key"], "replacement_public_key"
            ),
            previous_history_digest=_digest(
                data["previous_history_digest"], "previous_history_digest"
            ),
            recovery_policy_digest=_digest(
                data["recovery_policy_digest"], "recovery_policy_digest"
            ),
            incident_id=_nonempty_str(data["incident_id"], "incident_id"),
            issued_at=_float(data["issued_at"], "issued_at"),
            approvals=approvals,
            replacement_key_signature=_canonical_signature(
                data["replacement_key_signature"], "replacement_key_signature"
            ),
        )
        if recovery.version != AUDITOR_KEY_RECOVERY_VERSION:
            raise MalformedAuditorKeyRecovery(
                f"unsupported auditor key recovery version {recovery.version!r}"
            )
        if recovery.generation < 1:
            raise MalformedAuditorKeyRecovery("generation must be >= 1")
        if recovery.compromised_public_key == recovery.replacement_public_key:
            raise MalformedAuditorKeyRecovery(
                "recovery must replace the compromised key"
            )
        return recovery


class AuditorKeyRecoverySigner:
    @staticmethod
    def sign(
        *,
        auditor_id: str,
        generation: int,
        compromised_public_key: str,
        replacement_private_key: Ed25519PrivateKey,
        previous_history_digest: str,
        incident_id: str,
        policy: RecoveryPolicy,
        authority_private_keys: Mapping[str, Ed25519PrivateKey],
        issued_at: float | None = None,
    ) -> AuditorKeyRecovery:
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ValueError("generation must be an integer")
        if generation < 1:
            raise ValueError("generation must be >= 1")
        if not auditor_id.strip() or not incident_id.strip():
            raise ValueError("auditor_id and incident_id must not be empty")
        compromised_public_key = _canonical_public_key(
            compromised_public_key, "compromised_public_key"
        )
        if not _SHA256_RE.fullmatch(previous_history_digest):
            raise ValueError("previous_history_digest must be a SHA-256 digest")

        replacement_public_key = encode_public_key(
            replacement_private_key.public_key()
        )
        if replacement_public_key == compromised_public_key:
            raise ValueError("recovery must replace the compromised key")

        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")

        unsigned = AuditorKeyRecovery(
            version=AUDITOR_KEY_RECOVERY_VERSION,
            auditor_id=auditor_id,
            generation=generation,
            compromised_public_key=compromised_public_key,
            replacement_public_key=replacement_public_key,
            previous_history_digest=previous_history_digest,
            recovery_policy_digest=policy.digest(),
            incident_id=incident_id,
            issued_at=stamp,
            approvals=(),
            replacement_key_signature="",
        )
        payload = unsigned.signing_bytes()
        approvals: list[RecoveryApproval] = []
        for authority_id in sorted(authority_private_keys):
            if authority_id not in policy.authority_ids:
                raise RecoveryPolicyError(
                    f"authority {authority_id!r} is not allowed by recovery policy"
                )
            private_key = authority_private_keys[authority_id]
            if encode_public_key(private_key.public_key()) != policy.public_key_for(
                authority_id
            ):
                raise RecoveryPolicyError(
                    f"private key for {authority_id!r} does not match recovery policy"
                )
            approvals.append(
                RecoveryApproval(
                    authority_id=authority_id,
                    signature=base64.b64encode(private_key.sign(payload)).decode("ascii"),
                )
            )
        if len(approvals) < policy.threshold:
            raise RecoveryPolicyError(
                f"recovery requires {policy.threshold} approvals, got {len(approvals)}"
            )

        return AuditorKeyRecovery(
            **{
                **unsigned.signed_fields(),
                "approvals": tuple(approvals),
                "replacement_key_signature": base64.b64encode(
                    replacement_private_key.sign(payload)
                ).decode("ascii"),
            }
        )


def verify_recovery(
    recovery: AuditorKeyRecovery,
    *,
    policy: RecoveryPolicy,
    expected_policy_digest: str,
    revoked_authorities: Mapping[str, int] | None = None,
) -> None:
    if recovery.version != AUDITOR_KEY_RECOVERY_VERSION:
        raise AuditorKeyRecoveryContinuityError(
            f"unsupported auditor key recovery version {recovery.version!r}"
        )
    if recovery.recovery_policy_digest != policy.digest():
        raise RecoveryPolicyError("recovery does not bind the supplied policy")
    if expected_policy_digest != policy.digest():
        raise RecoveryPolicyError(
            "recovery policy digest does not match external pin"
        )
    if recovery.compromised_public_key == recovery.replacement_public_key:
        raise AuditorKeyRecoveryContinuityError(
            "recovery did not replace the compromised key"
        )

    if len(recovery.approvals) < policy.threshold:
        raise RecoveryPolicyError(
            f"recovery requires {policy.threshold} approvals, "
            f"got {len(recovery.approvals)}"
        )

    payload = recovery.signing_bytes()
    allowed = set(policy.authority_ids)
    revoked_authorities = revoked_authorities or {}
    seen: set[str] = set()
    for approval in recovery.approvals:
        if approval.authority_id in seen:
            raise RecoveryPolicyError("duplicate recovery authority approval")
        seen.add(approval.authority_id)
        if approval.authority_id not in allowed:
            raise RecoveryPolicyError(
                f"authority {approval.authority_id!r} is not allowed"
            )
        effective_from = revoked_authorities.get(approval.authority_id)
        if (
            effective_from is not None
            and effective_from <= recovery.generation
        ):
            raise RecoveryPolicyError(
                f"authority {approval.authority_id!r} is revoked for "
                f"auditor generation {recovery.generation}"
            )
        key = _decode_public_key(policy.public_key_for(approval.authority_id))
        _verify_signature(
            key,
            approval.signature,
            payload,
            f"recovery authority {approval.authority_id}",
        )

    replacement = _decode_public_key(recovery.replacement_public_key)
    _verify_signature(
        replacement,
        recovery.replacement_key_signature,
        payload,
        "replacement auditor key",
    )


AuditorKeyHistoryEntry = AuditorKeyTransition | AuditorKeyRecovery


def parse_auditor_key_history(data: Any) -> tuple[AuditorKeyHistoryEntry, ...]:
    if not isinstance(data, list):
        raise AuditorKeyRecoveryContinuityError(
            "auditor key history must be a JSON array"
        )
    entries: list[AuditorKeyHistoryEntry] = []
    for item in data:
        if not isinstance(item, Mapping):
            raise AuditorKeyRecoveryContinuityError(
                "auditor key history entries must be objects"
            )
        version = item.get("version")
        if version == AUDITOR_KEY_RECOVERY_VERSION:
            entries.append(AuditorKeyRecovery.from_dict(item))
        else:
            entries.append(AuditorKeyTransition.from_dict(item))
    return tuple(entries)


def verify_auditor_key_history(
    *,
    auditor_id: str,
    initial_public_key: str,
    entries: Iterable[AuditorKeyHistoryEntry],
    expected_generation: int,
    expected_head_digest: str,
    recovery_policy: RecoveryPolicy | None = None,
    expected_recovery_policy_digest: str | None = None,
    revoked_authorities: Mapping[str, int] | None = None,
) -> str:
    if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
        raise AuditorKeyRecoveryContinuityError(
            "expected_generation must be an integer"
        )
    if expected_generation < 0:
        raise AuditorKeyRecoveryContinuityError("expected_generation must be >= 0")
    if not _SHA256_RE.fullmatch(expected_head_digest):
        raise AuditorKeyRecoveryContinuityError(
            "expected_head_digest is not a SHA-256 digest"
        )

    current_key = _canonical_public_key(initial_public_key, "initial_public_key")
    previous_digest = KEY_TRANSITION_GENESIS
    next_generation = 1
    verified_count = 0

    for entry in entries:
        if isinstance(entry, AuditorKeyRecovery):
            if recovery_policy is None or expected_recovery_policy_digest is None:
                raise RecoveryPolicyError(
                    "auditor key history contains emergency recovery but no "
                    "externally pinned recovery policy was supplied"
                )
            verify_recovery(
                entry,
                policy=recovery_policy,
                expected_policy_digest=expected_recovery_policy_digest,
                revoked_authorities=revoked_authorities,
            )
            if entry.auditor_id != auditor_id:
                raise AuditorKeyRecoveryContinuityError(
                    f"recovery belongs to {entry.auditor_id!r}, not {auditor_id!r}"
                )
            if entry.generation != next_generation:
                raise AuditorKeyRecoveryContinuityError(
                    f"expected auditor key generation {next_generation}, "
                    f"got {entry.generation}"
                )
            if entry.compromised_public_key != current_key:
                raise AuditorKeyRecoveryContinuityError(
                    "recovery does not revoke the currently trusted auditor key"
                )
            if entry.previous_history_digest != previous_digest:
                raise AuditorKeyRecoveryContinuityError(
                    "recovery does not follow the current auditor history head"
                )
            current_key = entry.replacement_public_key
            previous_digest = entry.recovery_digest()
        else:
            verify_transition(entry)
            if entry.auditor_id != auditor_id:
                raise AuditorKeyRecoveryContinuityError(
                    f"transition belongs to {entry.auditor_id!r}, not {auditor_id!r}"
                )
            if entry.generation != next_generation:
                raise AuditorKeyRecoveryContinuityError(
                    f"expected auditor key generation {next_generation}, "
                    f"got {entry.generation}"
                )
            if entry.previous_public_key != current_key:
                raise AuditorKeyRecoveryContinuityError(
                    "normal rotation does not build on the currently trusted key"
                )
            if entry.previous_transition_digest != previous_digest:
                raise AuditorKeyRecoveryContinuityError(
                    "normal rotation does not follow the current auditor history head"
                )
            current_key = entry.next_public_key
            previous_digest = entry.transition_digest()

        verified_count += 1
        next_generation += 1

    if verified_count != expected_generation:
        raise AuditorKeyRecoveryContinuityError(
            f"auditor key history rollback or truncation: expected generation "
            f"{expected_generation}, verified {verified_count}"
        )
    if previous_digest != expected_head_digest:
        raise AuditorKeyRecoveryContinuityError(
            "auditor key history head digest does not match external pin"
        )
    return current_key


def _canonical_public_key(value: Any, field: str) -> str:
    value = _nonempty_str(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise MalformedAuditorKeyRecovery(
            f"{field} must be a raw Ed25519 public key encoded as base64"
        ) from exc
    if len(raw) != 32:
        raise MalformedAuditorKeyRecovery(
            f"{field} decoded to {len(raw)} bytes, expected 32"
        )
    if base64.b64encode(raw).decode("ascii") != value:
        raise MalformedAuditorKeyRecovery(f"{field} must use canonical base64")
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
    encoded = _canonical_signature(encoded, f"{label} signature")
    raw = base64.b64decode(encoded, validate=True)
    try:
        key.verify(raw, payload)
    except InvalidSignature as exc:
        raise AuditorKeyRecoverySignatureInvalid(
            f"{label} signature does not match recovery statement"
        ) from exc


def _canonical_signature(value: Any, field: str) -> str:
    value = _nonempty_str(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise MalformedAuditorKeyRecovery(f"{field} must be valid base64") from exc
    if len(raw) != 64:
        raise MalformedAuditorKeyRecovery(
            f"{field} decoded to {len(raw)} bytes, expected 64"
        )
    if base64.b64encode(raw).decode("ascii") != value:
        raise MalformedAuditorKeyRecovery(f"{field} must use canonical base64")
    return value


def _str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedAuditorKeyRecovery(f"{field} must be a string")
    return value


def _nonempty_str(value: Any, field: str) -> str:
    value = _str(value, field)
    if not value.strip():
        raise MalformedAuditorKeyRecovery(f"{field} must not be empty")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedAuditorKeyRecovery(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedAuditorKeyRecovery(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedAuditorKeyRecovery(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    value = _str(value, field)
    if not _SHA256_RE.fullmatch(value):
        raise MalformedAuditorKeyRecovery(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "AUDITOR_KEY_RECOVERY_VERSION",
    "AuditorKeyHistoryEntry",
    "AuditorKeyRecovery",
    "AuditorKeyRecoveryContinuityError",
    "AuditorKeyRecoveryError",
    "AuditorKeyRecoverySignatureInvalid",
    "AuditorKeyRecoverySigner",
    "MalformedAuditorKeyRecovery",
    "RecoveryApproval",
    "RecoveryPolicy",
    "RecoveryPolicyError",
    "parse_auditor_key_history",
    "verify_auditor_key_history",
    "verify_recovery",
]
