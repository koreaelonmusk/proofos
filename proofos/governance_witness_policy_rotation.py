"""Continuity proof for governance witness policy rotation.

A governance snapshot is only as independent as the witness policy used to
attest it. Silently replacing that policy would reset the trust root.

Every policy transition therefore requires:
- threshold authorization from the previous governance witness policy;
- threshold possession proof from the next governance witness policy;
- exact +1 policy generation;
- linkage to the previous policy-transition digest.

The transition changes who may attest governance snapshots. It does not grant
task-completion, evidence, recovery, capability, or execution authority.
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
from .witness_quorum import WitnessQuorumPolicy, WitnessQuorumPolicyError

GOVERNANCE_WITNESS_POLICY_TRANSITION_VERSION = (
    "proofos.governance-witness-policy-transition.v1"
)
GOVERNANCE_WITNESS_POLICY_GENESIS = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class GovernanceWitnessPolicyContinuityError(ValueError):
    pass


class MalformedGovernanceWitnessPolicyTransition(
    GovernanceWitnessPolicyContinuityError
):
    pass


class GovernanceWitnessPolicySignatureInvalid(
    GovernanceWitnessPolicyContinuityError
):
    pass


@dataclass(frozen=True)
class GovernancePolicyApproval:
    witness_id: str
    signature: str

    def to_dict(self) -> dict[str, str]:
        return {"witness_id": self.witness_id, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "GovernancePolicyApproval":
        if not isinstance(data, Mapping) or set(data) != {"witness_id", "signature"}:
            raise MalformedGovernanceWitnessPolicyTransition(
                "malformed governance policy approval"
            )
        return cls(
            witness_id=_nonempty(data["witness_id"], "witness_id"),
            signature=_canonical_signature(data["signature"], "signature"),
        )


@dataclass(frozen=True)
class GovernanceWitnessPolicyTransition:
    version: str
    generation: int
    previous_policy: dict[str, Any]
    next_policy: dict[str, Any]
    previous_transition_digest: str
    issued_at: int | float
    previous_approvals: tuple[GovernancePolicyApproval, ...]
    next_approvals: tuple[GovernancePolicyApproval, ...]

    def previous(self) -> WitnessQuorumPolicy:
        return _policy_from_dict(self.previous_policy)

    def successor(self) -> WitnessQuorumPolicy:
        return _policy_from_dict(self.next_policy)

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
            "previous_approvals": [x.to_dict() for x in self.previous_approvals],
            "next_approvals": [x.to_dict() for x in self.next_approvals],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "GovernanceWitnessPolicyTransition":
        if not isinstance(data, Mapping):
            raise MalformedGovernanceWitnessPolicyTransition(
                "governance witness policy transition must be an object"
            )
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
            raise MalformedGovernanceWitnessPolicyTransition(
                "governance witness policy transition fields are not exact"
            )
        item = cls(
            version=_nonempty(data["version"], "version"),
            generation=_integer(data["generation"], "generation"),
            previous_policy=_policy_dict(data["previous_policy"], "previous_policy"),
            next_policy=_policy_dict(data["next_policy"], "next_policy"),
            previous_transition_digest=_digest(
                data["previous_transition_digest"], "previous_transition_digest"
            ),
            issued_at=_finite_number(data["issued_at"], "issued_at"),
            previous_approvals=_approvals(
                data["previous_approvals"], "previous_approvals"
            ),
            next_approvals=_approvals(data["next_approvals"], "next_approvals"),
        )
        if item.version != GOVERNANCE_WITNESS_POLICY_TRANSITION_VERSION:
            raise MalformedGovernanceWitnessPolicyTransition(
                f"unsupported governance witness policy transition version "
                f"{item.version!r}"
            )
        if item.generation < 1:
            raise MalformedGovernanceWitnessPolicyTransition(
                "generation must be >= 1"
            )
        if item.previous().digest() == item.successor().digest():
            raise MalformedGovernanceWitnessPolicyTransition(
                "governance witness policy transition made no change"
            )
        return item


class GovernanceWitnessPolicyTransitionSigner:
    @staticmethod
    def sign(
        *,
        generation: int,
        previous_policy: WitnessQuorumPolicy,
        next_policy: WitnessQuorumPolicy,
        previous_private_keys: Mapping[str, Ed25519PrivateKey],
        next_private_keys: Mapping[str, Ed25519PrivateKey],
        previous_transition_digest: str = GOVERNANCE_WITNESS_POLICY_GENESIS,
        issued_at: int | float | None = None,
    ) -> GovernanceWitnessPolicyTransition:
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ValueError("generation must be an integer")
        if generation < 1:
            raise ValueError("generation must be >= 1")
        if not _SHA256_RE.fullmatch(previous_transition_digest):
            raise ValueError("previous_transition_digest must be a SHA-256 digest")
        if previous_policy.digest() == next_policy.digest():
            raise ValueError("policy transition must change the policy")

        stamp: int | float = time.time() if issued_at is None else issued_at
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
            raise ValueError("issued_at must be numeric")
        if not math.isfinite(float(stamp)):
            raise ValueError("issued_at must be finite")

        unsigned = GovernanceWitnessPolicyTransition(
            version=GOVERNANCE_WITNESS_POLICY_TRANSITION_VERSION,
            generation=generation,
            previous_policy=_policy_to_dict(previous_policy),
            next_policy=_policy_to_dict(next_policy),
            previous_transition_digest=previous_transition_digest,
            issued_at=stamp,
            previous_approvals=(),
            next_approvals=(),
        )
        payload = unsigned.signing_bytes()
        return GovernanceWitnessPolicyTransition(
            **{
                **unsigned.signed_fields(),
                "previous_approvals": _sign_threshold(
                    previous_policy, previous_private_keys, payload
                ),
                "next_approvals": _sign_threshold(
                    next_policy, next_private_keys, payload
                ),
            }
        )


def verify_policy_transition(
    transition: GovernanceWitnessPolicyTransition,
) -> None:
    if transition.version != GOVERNANCE_WITNESS_POLICY_TRANSITION_VERSION:
        raise GovernanceWitnessPolicyContinuityError(
            f"unsupported governance witness policy transition version "
            f"{transition.version!r}"
        )
    if isinstance(transition.generation, bool) or transition.generation < 1:
        raise GovernanceWitnessPolicyContinuityError(
            "generation must be a positive integer"
        )
    if not math.isfinite(float(transition.issued_at)):
        raise GovernanceWitnessPolicyContinuityError("issued_at must be finite")
    if not _SHA256_RE.fullmatch(transition.previous_transition_digest):
        raise GovernanceWitnessPolicyContinuityError(
            "previous_transition_digest is not a SHA-256 digest"
        )

    previous_policy = transition.previous()
    next_policy = transition.successor()
    if previous_policy.digest() == next_policy.digest():
        raise GovernanceWitnessPolicyContinuityError(
            "governance witness policy transition made no change"
        )
    payload = transition.signing_bytes()
    _verify_threshold(
        previous_policy, transition.previous_approvals, payload, "previous"
    )
    _verify_threshold(next_policy, transition.next_approvals, payload, "next")


def verify_governance_witness_policy_chain(
    *,
    initial_policy: WitnessQuorumPolicy,
    transitions: tuple[GovernanceWitnessPolicyTransition, ...],
    expected_generation: int,
    expected_head_digest: str,
) -> tuple[WitnessQuorumPolicy, tuple[WitnessQuorumPolicy, ...]]:
    if isinstance(expected_generation, bool) or not isinstance(expected_generation, int):
        raise GovernanceWitnessPolicyContinuityError(
            "expected_generation must be an integer"
        )
    if expected_generation < 0:
        raise GovernanceWitnessPolicyContinuityError(
            "expected_generation must be >= 0"
        )
    if not _SHA256_RE.fullmatch(expected_head_digest):
        raise GovernanceWitnessPolicyContinuityError(
            "expected_head_digest is not a SHA-256 digest"
        )

    current = initial_policy
    history: list[WitnessQuorumPolicy] = [initial_policy]
    previous_digest = GOVERNANCE_WITNESS_POLICY_GENESIS

    for expected, transition in enumerate(transitions, start=1):
        verify_policy_transition(transition)
        if transition.generation != expected:
            raise GovernanceWitnessPolicyContinuityError(
                f"expected governance witness policy generation {expected}, "
                f"got {transition.generation}"
            )
        if transition.previous().digest() != current.digest():
            raise GovernanceWitnessPolicyContinuityError(
                "governance witness policy transition does not build on "
                "the currently trusted policy"
            )
        if transition.previous_transition_digest != previous_digest:
            raise GovernanceWitnessPolicyContinuityError(
                "governance witness policy transition does not follow "
                "the current policy history head"
            )
        current = transition.successor()
        history.append(current)
        previous_digest = transition.transition_digest()

    if len(transitions) != expected_generation:
        raise GovernanceWitnessPolicyContinuityError(
            f"governance witness policy rollback or truncation: expected generation "
            f"{expected_generation}, verified {len(transitions)}"
        )
    if previous_digest != expected_head_digest:
        raise GovernanceWitnessPolicyContinuityError(
            "governance witness policy history head digest does not match external pin"
        )
    return current, tuple(history)


def parse_governance_witness_policy_history(
    data: Any,
) -> tuple[GovernanceWitnessPolicyTransition, ...]:
    if not isinstance(data, list):
        raise MalformedGovernanceWitnessPolicyTransition(
            "governance witness policy history must be a JSON array"
        )
    return tuple(GovernanceWitnessPolicyTransition.from_dict(item) for item in data)


def policy_for_governance_generation(
    policies: tuple[WitnessQuorumPolicy, ...],
    governance_generation: int,
) -> WitnessQuorumPolicy:
    if isinstance(governance_generation, bool) or not isinstance(
        governance_generation, int
    ):
        raise GovernanceWitnessPolicyContinuityError(
            "governance_generation must be an integer"
        )
    if governance_generation < 1 or governance_generation > len(policies):
        raise GovernanceWitnessPolicyContinuityError(
            f"no governance witness policy available for governance generation "
            f"{governance_generation}"
        )
    return policies[governance_generation - 1]


def _sign_threshold(
    policy: WitnessQuorumPolicy,
    private_keys: Mapping[str, Ed25519PrivateKey],
    payload: bytes,
) -> tuple[GovernancePolicyApproval, ...]:
    approvals: list[GovernancePolicyApproval] = []
    for witness_id in sorted(private_keys):
        if witness_id not in policy.witness_ids:
            raise WitnessQuorumPolicyError(
                f"witness {witness_id!r} is not allowed by governance policy"
            )
        key = private_keys[witness_id]
        if encode_public_key(key.public_key()) != policy.public_key_for(witness_id):
            raise WitnessQuorumPolicyError(
                f"private key for {witness_id!r} does not match governance policy"
            )
        approvals.append(
            GovernancePolicyApproval(
                witness_id=witness_id,
                signature=base64.b64encode(key.sign(payload)).decode("ascii"),
            )
        )
    if len(approvals) < policy.threshold:
        raise WitnessQuorumPolicyError(
            f"governance witness policy transition requires {policy.threshold} "
            f"approvals, got {len(approvals)}"
        )
    return tuple(approvals)


def _verify_threshold(
    policy: WitnessQuorumPolicy,
    approvals: tuple[GovernancePolicyApproval, ...],
    payload: bytes,
    label: str,
) -> None:
    ids = tuple(item.witness_id for item in approvals)
    if ids != tuple(sorted(set(ids))):
        raise GovernanceWitnessPolicyContinuityError(
            f"{label} approvals must be unique and sorted"
        )
    if len(approvals) < policy.threshold:
        raise GovernanceWitnessPolicyContinuityError(
            f"{label} policy requires {policy.threshold} approvals, "
            f"got {len(approvals)}"
        )
    for approval in approvals:
        key = _decode_public_key(policy.public_key_for(approval.witness_id))
        raw = base64.b64decode(approval.signature, validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != approval.signature:
            raise GovernanceWitnessPolicySignatureInvalid(
                f"{label} approval signature is not canonical Ed25519 base64"
            )
        try:
            key.verify(raw, payload)
        except InvalidSignature as exc:
            raise GovernanceWitnessPolicySignatureInvalid(
                f"{label} approval from {approval.witness_id!r} is invalid"
            ) from exc


def _policy_to_dict(policy: WitnessQuorumPolicy) -> dict[str, Any]:
    return {
        "policy_id": policy.policy_id,
        "witnesses": [
            {"witness_id": wid, "public_key_b64": key}
            for wid, key in policy.witnesses
        ],
        "threshold": policy.threshold,
    }


def _policy_from_dict(data: Any) -> WitnessQuorumPolicy:
    if not isinstance(data, Mapping):
        raise MalformedGovernanceWitnessPolicyTransition(
            "governance witness policy must be an object"
        )
    if set(data) != {"policy_id", "witnesses", "threshold"}:
        raise MalformedGovernanceWitnessPolicyTransition(
            "governance witness policy fields are not exact"
        )
    raw = data["witnesses"]
    if not isinstance(raw, list):
        raise MalformedGovernanceWitnessPolicyTransition(
            "governance witness policy witnesses must be a list"
        )
    witnesses: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {
            "witness_id",
            "public_key_b64",
        }:
            raise MalformedGovernanceWitnessPolicyTransition(
                "malformed governance witness entry"
            )
        witnesses.append(
            (
                _nonempty(item["witness_id"], "witness_id"),
                _canonical_public_key(item["public_key_b64"], "public_key_b64"),
            )
        )
    try:
        return WitnessQuorumPolicy(
            _nonempty(data["policy_id"], "policy_id"),
            tuple(witnesses),
            _integer(data["threshold"], "threshold"),
        )
    except WitnessQuorumPolicyError as exc:
        raise MalformedGovernanceWitnessPolicyTransition(str(exc)) from exc


def _policy_dict(value: Any, field: str) -> dict[str, Any]:
    try:
        return _policy_to_dict(_policy_from_dict(value))
    except MalformedGovernanceWitnessPolicyTransition as exc:
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field}: {exc}"
        ) from exc


def _decode_public_key(encoded: str) -> Ed25519PublicKey:
    raw = base64.b64decode(encoded, validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def _canonical_public_key(value: Any, field: str) -> str:
    value = _nonempty(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be Ed25519 public-key base64"
        ) from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must use canonical Ed25519 base64"
        )
    return value


def _canonical_signature(value: Any, field: str) -> str:
    value = _nonempty(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be valid base64"
        ) from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be canonical 64-byte Ed25519 base64"
        )
    return value


def _approvals(value: Any, field: str) -> tuple[GovernancePolicyApproval, ...]:
    if not isinstance(value, list):
        raise MalformedGovernanceWitnessPolicyTransition(f"{field} must be a list")
    approvals = tuple(GovernancePolicyApproval.from_dict(x) for x in value)
    ids = tuple(x.witness_id for x in approvals)
    if ids != tuple(sorted(set(ids))):
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be unique and sorted"
        )
    return approvals


def _nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be a non-empty string"
        )
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be an integer"
        )
    return value


def _finite_number(value: Any, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be numeric"
        )
    if not math.isfinite(float(value)):
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be finite"
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise MalformedGovernanceWitnessPolicyTransition(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "GOVERNANCE_WITNESS_POLICY_GENESIS",
    "GOVERNANCE_WITNESS_POLICY_TRANSITION_VERSION",
    "GovernancePolicyApproval",
    "GovernanceWitnessPolicyContinuityError",
    "GovernanceWitnessPolicySignatureInvalid",
    "GovernanceWitnessPolicyTransition",
    "GovernanceWitnessPolicyTransitionSigner",
    "MalformedGovernanceWitnessPolicyTransition",
    "parse_governance_witness_policy_history",
    "policy_for_governance_generation",
    "verify_governance_witness_policy_chain",
    "verify_policy_transition",
]
