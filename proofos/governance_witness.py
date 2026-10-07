"""Cross-witness governance snapshots for ProofOS trust-root publication.

The public audit path has several independently verified trust histories:
auditor keys, recovery policy, and recovery-authority revocations. A verifier
should not accept arbitrary final head pins for those histories without an
independent statement about which heads are current.

This module lets the existing witness quorum attest one exact governance
snapshot. It does not authorize recovery, rotate keys, or decide task
completion. It only proves that enough pinned witness identities observed the
same set of governance heads.
"""

from __future__ import annotations

import base64
import math
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .integrity import canonical_payload, content_hash
from .keys import encode_public_key
from .witness_quorum import WitnessQuorumPolicy

GOVERNANCE_SNAPSHOT_VERSION = "proofos.governance-snapshot.v1"
GOVERNANCE_ATTESTATION_VERSION = "proofos.governance-attestation.v1"
GOVERNANCE_GENESIS = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class GovernanceError(ValueError):
    pass


class MalformedGovernanceSnapshot(GovernanceError):
    pass


class GovernanceAttestationSignatureInvalid(GovernanceError):
    pass


class GovernanceBindingError(GovernanceError):
    pass


class GovernanceQuorumState(StrEnum):
    QUORUM = "QUORUM"
    INSUFFICIENT = "INSUFFICIENT"
    SPLIT_VIEW = "SPLIT_VIEW"


@dataclass(frozen=True)
class GovernanceSnapshot:
    version: str
    governance_generation: int
    previous_snapshot_digest: str
    auditor_history_generation: int
    auditor_history_digest: str
    recovery_policy_generation: int
    recovery_policy_digest: str
    recovery_policy_history_digest: str
    revocation_generation: int
    revocation_head_digest: str
    issued_at: float

    def fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "governance_generation": self.governance_generation,
            "previous_snapshot_digest": self.previous_snapshot_digest,
            "auditor_history_generation": self.auditor_history_generation,
            "auditor_history_digest": self.auditor_history_digest,
            "recovery_policy_generation": self.recovery_policy_generation,
            "recovery_policy_digest": self.recovery_policy_digest,
            "recovery_policy_history_digest": self.recovery_policy_history_digest,
            "revocation_generation": self.revocation_generation,
            "revocation_head_digest": self.revocation_head_digest,
            "issued_at": self.issued_at,
        }

    def snapshot_digest(self) -> str:
        return content_hash(self.fields())

    def to_dict(self) -> dict[str, Any]:
        return self.fields()

    @classmethod
    def from_dict(cls, data: Any) -> "GovernanceSnapshot":
        if not isinstance(data, Mapping):
            raise MalformedGovernanceSnapshot("governance snapshot must be an object")
        expected = {
            "version",
            "governance_generation",
            "previous_snapshot_digest",
            "auditor_history_generation",
            "auditor_history_digest",
            "recovery_policy_generation",
            "recovery_policy_digest",
            "recovery_policy_history_digest",
            "revocation_generation",
            "revocation_head_digest",
            "issued_at",
        }
        if set(data) != expected:
            raise MalformedGovernanceSnapshot(
                "governance snapshot fields are not exact"
            )

        snapshot = cls(
            version=_nonempty(data["version"], "version"),
            governance_generation=_int(
                data["governance_generation"], "governance_generation"
            ),
            previous_snapshot_digest=_digest(
                data["previous_snapshot_digest"], "previous_snapshot_digest"
            ),
            auditor_history_generation=_nonnegative_int(
                data["auditor_history_generation"], "auditor_history_generation"
            ),
            auditor_history_digest=_digest(
                data["auditor_history_digest"], "auditor_history_digest"
            ),
            recovery_policy_generation=_nonnegative_int(
                data["recovery_policy_generation"], "recovery_policy_generation"
            ),
            recovery_policy_digest=_digest(
                data["recovery_policy_digest"], "recovery_policy_digest"
            ),
            recovery_policy_history_digest=_digest(
                data["recovery_policy_history_digest"],
                "recovery_policy_history_digest",
            ),
            revocation_generation=_nonnegative_int(
                data["revocation_generation"], "revocation_generation"
            ),
            revocation_head_digest=_digest(
                data["revocation_head_digest"], "revocation_head_digest"
            ),
            issued_at=_finite_float(data["issued_at"], "issued_at"),
        )
        if snapshot.version != GOVERNANCE_SNAPSHOT_VERSION:
            raise MalformedGovernanceSnapshot(
                f"unsupported governance snapshot version {snapshot.version!r}"
            )
        if snapshot.governance_generation < 1:
            raise MalformedGovernanceSnapshot(
                "governance_generation must be >= 1"
            )
        return snapshot


@dataclass(frozen=True)
class GovernanceAttestation:
    version: str
    witness_id: str
    snapshot_digest: str
    observed_at: float
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "witness_id": self.witness_id,
            "snapshot_digest": self.snapshot_digest,
            "observed_at": self.observed_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "GovernanceAttestation":
        if not isinstance(data, Mapping):
            raise MalformedGovernanceSnapshot("governance attestation must be an object")
        expected = {
            "version",
            "witness_id",
            "snapshot_digest",
            "observed_at",
            "signature",
        }
        if set(data) != expected:
            raise MalformedGovernanceSnapshot(
                "governance attestation fields are not exact"
            )
        item = cls(
            version=_nonempty(data["version"], "version"),
            witness_id=_nonempty(data["witness_id"], "witness_id"),
            snapshot_digest=_digest(data["snapshot_digest"], "snapshot_digest"),
            observed_at=_finite_float(data["observed_at"], "observed_at"),
            signature=_canonical_signature(data["signature"], "signature"),
        )
        if item.version != GOVERNANCE_ATTESTATION_VERSION:
            raise MalformedGovernanceSnapshot(
                f"unsupported governance attestation version {item.version!r}"
            )
        return item


@dataclass(frozen=True)
class GovernanceQuorumResult:
    state: GovernanceQuorumState
    policy_digest: str
    snapshot_digest: str
    counted_witnesses: tuple[str, ...]
    required: int
    conflicting_snapshot_digests: tuple[str, ...] = ()

    @property
    def quorum_met(self) -> bool:
        return self.state is GovernanceQuorumState.QUORUM


@dataclass(frozen=True)
class GovernanceWitnessBundle:
    version: str
    snapshot: GovernanceSnapshot
    policy: WitnessQuorumPolicy
    attestations: tuple[GovernanceAttestation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "snapshot": self.snapshot.to_dict(),
            "policy": {
                "policy_id": self.policy.policy_id,
                "witnesses": [
                    {"witness_id": wid, "public_key_b64": key}
                    for wid, key in self.policy.witnesses
                ],
                "threshold": self.policy.threshold,
            },
            "attestations": [item.to_dict() for item in self.attestations],
        }

    @classmethod
    def from_dict(cls, data: Any) -> "GovernanceWitnessBundle":
        if not isinstance(data, Mapping):
            raise MalformedGovernanceSnapshot("governance bundle must be an object")
        expected = {"version", "snapshot", "policy", "attestations"}
        if set(data) != expected:
            raise MalformedGovernanceSnapshot(
                "governance bundle fields are not exact"
            )
        version = _nonempty(data["version"], "version")
        if version != GOVERNANCE_SNAPSHOT_VERSION:
            raise MalformedGovernanceSnapshot(
                f"unsupported governance bundle version {version!r}"
            )
        policy = _policy_from_dict(data["policy"])
        raw_attestations = data["attestations"]
        if not isinstance(raw_attestations, list):
            raise MalformedGovernanceSnapshot("attestations must be a list")
        return cls(
            version=version,
            snapshot=GovernanceSnapshot.from_dict(data["snapshot"]),
            policy=policy,
            attestations=tuple(
                GovernanceAttestation.from_dict(item)
                for item in raw_attestations
            ),
        )


class GovernanceAttestationSigner:
    __slots__ = ("_key", "witness_id")

    def __init__(self, private_key: Ed25519PrivateKey, witness_id: str) -> None:
        if not witness_id.strip():
            raise ValueError("witness_id must not be empty")
        self._key = private_key
        self.witness_id = witness_id

    @classmethod
    def generate(cls, witness_id: str) -> "GovernanceAttestationSigner":
        return cls(Ed25519PrivateKey.generate(), witness_id)

    def public_key_b64(self) -> str:
        return encode_public_key(self._key.public_key())

    def sign(
        self,
        snapshot: GovernanceSnapshot,
        observed_at: float | None = None,
    ) -> GovernanceAttestation:
        stamp = time.time() if observed_at is None else float(observed_at)
        if not math.isfinite(stamp):
            raise ValueError("observed_at must be finite")
        if stamp < snapshot.issued_at:
            raise ValueError("witness observation cannot predate governance snapshot")
        unsigned = GovernanceAttestation(
            version=GOVERNANCE_ATTESTATION_VERSION,
            witness_id=self.witness_id,
            snapshot_digest=snapshot.snapshot_digest(),
            observed_at=stamp,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return GovernanceAttestation(
            **{
                **unsigned.signed_fields(),
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


def verify_governance_bundle(
    bundle: GovernanceWitnessBundle,
    *,
    expected_policy_digest: str,
    expected_governance_generation: int,
    expected_governance_head_digest: str,
) -> GovernanceQuorumResult:
    if bundle.version != GOVERNANCE_SNAPSHOT_VERSION:
        raise GovernanceBindingError(
            f"unsupported governance bundle version {bundle.version!r}"
        )
    if bundle.snapshot.version != GOVERNANCE_SNAPSHOT_VERSION:
        raise GovernanceBindingError(
            f"unsupported governance snapshot version {bundle.snapshot.version!r}"
        )
    for attestation in bundle.attestations:
        if attestation.version != GOVERNANCE_ATTESTATION_VERSION:
            raise GovernanceBindingError(
                f"unsupported governance attestation version {attestation.version!r}"
            )
        if attestation.observed_at < bundle.snapshot.issued_at:
            raise GovernanceBindingError(
                "governance attestation predates the governance snapshot"
            )

    policy_digest = bundle.policy.digest()
    if policy_digest != expected_policy_digest:
        raise GovernanceBindingError(
            "governance witness policy digest does not match external pin"
        )
    if isinstance(expected_governance_generation, bool) or not isinstance(
        expected_governance_generation, int
    ):
        raise GovernanceBindingError(
            "expected_governance_generation must be an integer"
        )
    if bundle.snapshot.governance_generation != expected_governance_generation:
        raise GovernanceBindingError(
            "governance snapshot generation does not match external pin"
        )
    if bundle.snapshot.snapshot_digest() != expected_governance_head_digest:
        raise GovernanceBindingError(
            "governance snapshot digest does not match external pin"
        )

    allowed = set(bundle.policy.witness_ids)
    by_witness: dict[str, GovernanceAttestation] = {}
    conflicting: set[str] = set()

    for attestation in bundle.attestations:
        if attestation.witness_id not in allowed:
            raise GovernanceBindingError(
                f"witness {attestation.witness_id!r} is not allowed"
            )
        expected_key = bundle.policy.public_key_for(attestation.witness_id)
        key = _decode_public_key(expected_key)
        _verify_attestation_signature(key, attestation)

        prior = by_witness.get(attestation.witness_id)
        if prior is None:
            by_witness[attestation.witness_id] = attestation
            continue
        if prior.snapshot_digest != attestation.snapshot_digest:
            conflicting.add(prior.snapshot_digest)
            conflicting.add(attestation.snapshot_digest)

    snapshot_digests = {
        item.snapshot_digest for item in by_witness.values()
    }
    if len(snapshot_digests) > 1:
        conflicting.update(snapshot_digests)

    counted = tuple(sorted(by_witness))
    if conflicting:
        return GovernanceQuorumResult(
            state=GovernanceQuorumState.SPLIT_VIEW,
            policy_digest=policy_digest,
            snapshot_digest="",
            counted_witnesses=counted,
            required=bundle.policy.threshold,
            conflicting_snapshot_digests=tuple(sorted(conflicting)),
        )

    snapshot_digest = bundle.snapshot.snapshot_digest()
    for attestation in by_witness.values():
        if attestation.snapshot_digest != snapshot_digest:
            raise GovernanceBindingError(
                "governance attestation does not bind the supplied snapshot"
            )

    state = (
        GovernanceQuorumState.QUORUM
        if len(by_witness) >= bundle.policy.threshold
        else GovernanceQuorumState.INSUFFICIENT
    )
    return GovernanceQuorumResult(
        state=state,
        policy_digest=policy_digest,
        snapshot_digest=snapshot_digest,
        counted_witnesses=counted,
        required=bundle.policy.threshold,
    )


def _verify_attestation_signature(
    key: Ed25519PublicKey,
    attestation: GovernanceAttestation,
) -> None:
    try:
        raw = base64.b64decode(attestation.signature, validate=True)
    except (ValueError, TypeError) as exc:
        raise GovernanceAttestationSignatureInvalid(
            "governance attestation signature is not valid base64"
        ) from exc
    if len(raw) != 64:
        raise GovernanceAttestationSignatureInvalid(
            "governance attestation signature has invalid length"
        )
    if base64.b64encode(raw).decode("ascii") != attestation.signature:
        raise GovernanceAttestationSignatureInvalid(
            "governance attestation signature is not canonical base64"
        )
    try:
        key.verify(raw, attestation.signing_bytes())
    except InvalidSignature as exc:
        raise GovernanceAttestationSignatureInvalid(
            "governance attestation signature does not verify"
        ) from exc


def _policy_from_dict(data: Any) -> WitnessQuorumPolicy:
    if not isinstance(data, Mapping):
        raise MalformedGovernanceSnapshot("governance witness policy must be an object")
    expected = {"policy_id", "witnesses", "threshold"}
    if set(data) != expected:
        raise MalformedGovernanceSnapshot(
            "governance witness policy fields are not exact"
        )
    raw = data["witnesses"]
    if not isinstance(raw, list):
        raise MalformedGovernanceSnapshot(
            "governance witness policy witnesses must be a list"
        )
    witnesses: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {
            "witness_id",
            "public_key_b64",
        }:
            raise MalformedGovernanceSnapshot(
                "malformed governance witness policy entry"
            )
        witness_id = _nonempty(item["witness_id"], "witness_id")
        public_key = _canonical_public_key(
            item["public_key_b64"], "public_key_b64"
        )
        witnesses.append((witness_id, public_key))
    return WitnessQuorumPolicy(
        _nonempty(data["policy_id"], "policy_id"),
        tuple(witnesses),
        _int(data["threshold"], "threshold"),
    )


def _decode_public_key(encoded: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(encoded, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise GovernanceBindingError("witness public key is not valid Ed25519") from exc


def _canonical_public_key(value: Any, field: str) -> str:
    value = _nonempty(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise MalformedGovernanceSnapshot(
            f"{field} must be an Ed25519 public key encoded as base64"
        ) from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise MalformedGovernanceSnapshot(
            f"{field} must use canonical Ed25519 base64"
        )
    return value


def _canonical_signature(value: Any, field: str) -> str:
    value = _nonempty(value, field)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise MalformedGovernanceSnapshot(f"{field} must be valid base64") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise MalformedGovernanceSnapshot(
            f"{field} must be canonical 64-byte Ed25519 base64"
        )
    return value


def _nonempty(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MalformedGovernanceSnapshot(f"{field} must be a non-empty string")
    return value


def _int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedGovernanceSnapshot(f"{field} must be an integer")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    result = _int(value, field)
    if result < 0:
        raise MalformedGovernanceSnapshot(f"{field} must be >= 0")
    return result


def _finite_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedGovernanceSnapshot(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedGovernanceSnapshot(f"{field} must be finite")
    return result


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise MalformedGovernanceSnapshot(
            f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


__all__ = [
    "GOVERNANCE_ATTESTATION_VERSION",
    "GOVERNANCE_GENESIS",
    "GOVERNANCE_SNAPSHOT_VERSION",
    "GovernanceAttestation",
    "GovernanceAttestationSignatureInvalid",
    "GovernanceAttestationSigner",
    "GovernanceBindingError",
    "GovernanceError",
    "GovernanceQuorumResult",
    "GovernanceQuorumState",
    "GovernanceSnapshot",
    "GovernanceWitnessBundle",
    "MalformedGovernanceSnapshot",
    "verify_governance_bundle",
]
