"""Continuity proofs for recovery-authority policy rotation.

Emergency auditor recovery is only trustworthy while the recovery policy itself
has a stable trust root. This module prevents a silent policy reset by requiring
a two-quorum handoff for every policy change:

- the previous policy threshold authorizes the successor policy;
- the successor policy threshold proves control of the new recovery authority set;
- policy generations advance exactly by one;
- every handoff commits to the previous handoff digest;
- verifiers pin the expected final generation and handoff digest.

The handoff changes recovery authority only. It carries no task-completion,
evidence, capability, or execution authority.
"""

from __future__ import annotations

import base64
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .auditor_key_recovery import RecoveryApproval, RecoveryPolicy, RecoveryPolicyError
from .integrity import canonical_payload, content_hash

RECOVERY_POLICY_TRANSITION_VERSION = "proofos.recovery-policy-transition.v1"
RECOVERY_POLICY_TRANSITION_GENESIS = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class RecoveryPolicyContinuityError(ValueError):
    pass


class MalformedRecoveryPolicyTransition(RecoveryPolicyContinuityError):
    pass


class RecoveryPolicyTransitionSignatureInvalid(RecoveryPolicyContinuityError):
    pass


@dataclass(frozen=True)
class RecoveryPolicyTransition:
    version: str
    generation: int
    previous_policy: dict[str, Any]
    next_policy: dict[str, Any]
    previous_transition_digest: str
    issued_at: float
    previous_approvals: tuple[RecoveryApproval, ...]
    next_approvals: tuple[RecoveryApproval, ...]

    def previous(self) -> RecoveryPolicy:
        return RecoveryPolicy.from_dict(self.previous_policy)

    def successor(self) -> RecoveryPolicy:
        return RecoveryPolicy.from_dict(self.next_policy)

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generation": self.generation,
            "previous_policy": self.previous_policy,
            "next_policy": self.next_policy,
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
            "previous_approvals": [item.to_dict() for item in self.previous_approvals],
            "next_approvals": [item.to_dict() for item in self.next_approvals],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "RecoveryPolicyTransition":
        if not isinstance(data, Mapping):
            raise MalformedRecoveryPolicyTransition("transition must be an object")
        expected = {
            "version",
            "generation",
            "previous_policy",
            "next_policy",
            "previous_transition_digest",
            "issued_at",
            "previous_approvals",
            "next_approvals",
        }
        if set(data) != expected:
            raise MalformedRecoveryPolicyTransition(
                "recovery policy transition fields are not exact"
            )
        previous_approvals = _parse_approvals(data["previous_approvals"], "previous")
        next_approvals = _parse_approvals(data["next_approvals"], "next")
        transition = cls(
            version=_nonempty_str(data["version"], "version"),
            generation=_int(data["generation"], "generation"),
            previous_policy=_policy_dict(data["previous_policy"], "previous_policy"),
            next_policy=_policy_dict(data["next_policy"], "next_policy"),
            previous_transition_digest=_digest(
                data["previous_transition_digest"], "previous_transition_digest"
            ),
            issued_at=_float(data["issued_at"], "issued_at"),
            previous_approvals=previous_approvals,
            next_approvals=next_approvals,
        )
        if transition.version != RECOVERY_POLICY_TRANSITION_VERSION:
            raise MalformedRecoveryPolicyTransition(
                f"unsupported recovery policy transition version {transition.version!r}"
            )
        if transition.generation < 1:
            raise MalformedRecoveryPolicyTransition("generation must be >= 1")
        if transition.previous().digest() == transition.successor().digest():
            raise MalformedRecoveryPolicyTransition("policy transition made no change")
        return transition


class RecoveryPolicyTransitionSigner:
    @staticmethod
    def sign(
        *,
        generation: int,
        previous_policy: RecoveryPolicy,
        next_policy: RecoveryPolicy,
        previous_authority_private_keys: Mapping[str, Ed25519PrivateKey],
        next_authority_private_keys: Mapping[str, Ed25519PrivateKey],
        previous_transition_digest: str = RECOVERY_POLICY_TRANSITION_GENESIS,
        issued_at: float | None = None,
    ) -> RecoveryPolicyTransition:
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ValueError("generation must be an integer")
        if generation < 1:
            raise ValueError("generation must be >= 1")
        if not _SHA256_RE.fullmatch(previous_transition_digest):
            raise ValueError("previous_transition_digest must be a SHA-256 digest")
        if previous_policy.digest() == next_policy.digest():
            raise ValueError("policy transition must change the policy")

        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")

        unsigned = RecoveryPolicyTransition(
            version=RECOVERY_POLICY_TRANSITION_VERSION,
            generation=generation,
            previous_policy=previous_policy.to_dict(),
            next_policy=next_policy.to_dict(),
            previous_transition_digest=previous_transition_digest,
            issued_at=stamp,
            previous_approvals=(),
            next_approvals=(),
        )
        payload = unsigned.signing_bytes()
        previous_approvals = _sign_policy_threshold(
            previous_policy, previous_authority_private_keys, payload
        )
        next_approvals = _sign_policy_threshold(
            next_policy, next_authority_private_keys, payload
        )
        return RecoveryPolicyTransition(
            **{
                **unsigned.signed_fields(),
                "previous_approvals": previous_approvals,
                "next_approvals": next_approvals,
            }
        )


def verify_policy_transition(transition: RecoveryPolicyTransition) -> None:
    if transition.version != RECOVERY_POLICY_TRANSITION_VERSION:
        raise RecoveryPolicyContinuityError(
            f"unsupported recovery policy transition version {transition.version!r}"
        )
    if isinstance(transition.generation, bool) or transition.generation < 1:
        raise RecoveryPolicyContinuityError("generation must be a positive integer")
    if not math.isfinite(transition.issued_at):
        raise RecoveryPolicyContinuityError("issued_at must be finite")
    if not _SHA256_RE.fullmatch(transition.previous_transition_digest):
        raise RecoveryPolicyContinuityError(
            "previous_transition_digest is not a SHA-256 digest"
        )

    previous_policy = transition.previous()
    next_policy = transition.successor()
    if previous_policy.digest() == next_policy.digest():
        raise RecoveryPolicyContinuityError("policy transition made no change")
    payload = transition.signing_bytes()
    _verify_threshold(previous_policy, transition.previous_approvals, payload, "previous")
    _verify_threshold(next_policy, transition.next_approvals, payload, "next")


def verify_recovery_policy_chain(
    *,
    initial_policy: RecoveryPolicy,
    transitions: tuple[RecoveryPolicyTransition, ...],
    expected_generation: int,
    expected_head_digest: str,
) -> RecoveryPolicy:
    if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
        raise RecoveryPolicyContinuityError("expected_generation must be an integer")
    if expected_generation < 0:
        raise RecoveryPolicyContinuityError("expected_generation must be >= 0")
    if not _SHA256_RE.fullmatch(expected_head_digest):
        raise RecoveryPolicyContinuityError(
            "expected_head_digest is not a SHA-256 digest"
        )

    current = initial_policy
    previous_digest = RECOVERY_POLICY_TRANSITION_GENESIS
    next_generation = 1
    verified_count = 0

    for transition in transitions:
        verify_policy_transition(transition)
        if transition.generation != next_generation:
            raise RecoveryPolicyContinuityError(
                f"expected recovery policy generation {next_generation}, "
                f"got {transition.generation}"
            )
        if transition.previous().digest() != current.digest():
            raise RecoveryPolicyContinuityError(
                "policy transition does not build on the currently trusted policy"
            )
        if transition.previous_transition_digest != previous_digest:
            raise RecoveryPolicyContinuityError(
                "policy transition does not follow the current policy history head"
            )
        current = transition.successor()
        previous_digest = transition.transition_digest()
        next_generation += 1
        verified_count += 1

    if verified_count != expected_generation:
        raise RecoveryPolicyContinuityError(
            f"recovery policy rollback or truncation: expected generation "
            f"{expected_generation}, verified {verified_count}"
        )
    if previous_digest != expected_head_digest:
        raise RecoveryPolicyContinuityError(
            "recovery policy history head digest does not match external pin"
        )
    return current


def parse_recovery_policy_history(data: Any) -> tuple[RecoveryPolicyTransition, ...]:
    if not isinstance(data, list):
        raise MalformedRecoveryPolicyTransition(
            "recovery policy transition history must be a JSON array"
        )
    return tuple(RecoveryPolicyTransition.from_dict(item) for item in data)


def _sign_policy_threshold(
    policy: RecoveryPolicy,
    private_keys: Mapping[str, Ed25519PrivateKey],
    payload: bytes,
) -> tuple[RecoveryApproval, ...]:
    approvals: list[RecoveryApproval] = []
    for authority_id in sorted(private_keys):
        if authority_id not in policy.authority_ids:
            raise RecoveryPolicyError(
                f"authority {authority_id!r} is not allowed by recovery policy"
            )
        key = private_keys[authority_id]
        from .keys import encode_public_key

        if encode_public_key(key.public_key()) != policy.public_key_for(authority_id):
            raise RecoveryPolicyError(
                f"private key for {authority_id!r} does not match recovery policy"
            )
        approvals.append(
            RecoveryApproval(
                authority_id=authority_id,
                signature=base64.b64encode(key.sign(payload)).decode("ascii"),
            )
        )
    if len(approvals) < policy.threshold:
        raise RecoveryPolicyError(
            f"policy transition requires {policy.threshold} approvals, "
            f"got {len(approvals)}"
        )
    return tuple(approvals)


def _verify_threshold(
    policy: RecoveryPolicy,
    approvals: tuple[RecoveryApproval, ...],
    payload: bytes,
    label: str,
) -> None:
    ids = tuple(item.authority_id for item in approvals)
    if ids != tuple(sorted(set(ids))):
        raise RecoveryPolicyContinuityError(
            f"{label} policy approvals must be unique and sorted"
        )
    if len(approvals) < policy.threshold:
        raise RecoveryPolicyContinuityError(
            f"{label} policy threshold requires {policy.threshold} approvals, "
            f"got {len(approvals)}"
        )
    for approval in approvals:
        try:
            public_key = policy.public_key_for(approval.authority_id)
            raw_key = base64.b64decode(public_key, validate=True)
            raw_signature = base64.b64decode(approval.signature, validate=True)
            if base64.b64encode(raw_signature).decode("ascii") != approval.signature:
                raise RecoveryPolicyTransitionSignatureInvalid(
                    f"{label} approval signature is not canonical base64"
                )
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_signature, payload)
        except InvalidSignature as exc:
            raise RecoveryPolicyTransitionSignatureInvalid(
                f"{label} approval from {approval.authority_id!r} is invalid"
            ) from exc


def _parse_approvals(value: Any, label: str) -> tuple[RecoveryApproval, ...]:
    if not isinstance(value, list):
        raise MalformedRecoveryPolicyTransition(f"{label}_approvals must be a list")
    approvals = tuple(RecoveryApproval.from_dict(item) for item in value)
    ids = tuple(item.authority_id for item in approvals)
    if ids != tuple(sorted(set(ids))):
        raise MalformedRecoveryPolicyTransition(
            f"{label}_approvals must be unique and sorted"
        )
    return approvals


def _policy_dict(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MalformedRecoveryPolicyTransition(f"{field} must be an object")
    policy = RecoveryPolicy.from_dict(value)
    return policy.to_dict()


def _nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedRecoveryPolicyTransition(f"{field} must be a non-empty string")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedRecoveryPolicyTransition(f"{field} must be an integer")
    return value


def _float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedRecoveryPolicyTransition(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedRecoveryPolicyTransition(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise MalformedRecoveryPolicyTransition(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "RECOVERY_POLICY_TRANSITION_GENESIS",
    "RECOVERY_POLICY_TRANSITION_VERSION",
    "MalformedRecoveryPolicyTransition",
    "RecoveryPolicyContinuityError",
    "RecoveryPolicyTransition",
    "RecoveryPolicyTransitionSignatureInvalid",
    "RecoveryPolicyTransitionSigner",
    "parse_recovery_policy_history",
    "verify_policy_transition",
    "verify_recovery_policy_chain",
]
