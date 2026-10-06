"""Proof-carrying signed gossip bundles for witness quorum results.

A gossip bundle can cross process or administrative boundaries without asking
the receiver to trust the sender's quorum claim. The outer Ed25519 signature
protects transport provenance, while the receiver independently re-verifies:

1. the externally pinned witness policy;
2. every witness receipt signature;
3. every witness-record content hash;
4. the N-of-M quorum or split-view result.

The gossip publisher therefore cannot manufacture quorum by signing a lie.
"""

from __future__ import annotations

import base64
import math
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .integrity import canonical_payload
from .keys import encode_public_key
from .witness import WITNESS_RECORD_VERSION, WitnessRecord
from .witness_quorum import (
    WitnessQuorumPolicy,
    WitnessQuorumResult,
    WitnessQuorumState,
    WitnessVote,
    evaluate_witness_quorum,
)
from .witness_receipt import WitnessReceipt, WitnessReceiptVerifier

WITNESS_GOSSIP_VERSION = "proofos.witness-gossip.v1"


class WitnessGossipError(ValueError):
    """Base class for gossip bundle refusal."""


class MalformedWitnessGossip(WitnessGossipError):
    pass


class WitnessGossipSignatureInvalid(WitnessGossipError):
    pass


class WitnessGossipBindingError(WitnessGossipError):
    pass


@dataclass(frozen=True)
class WitnessGossipBundle:
    version: str
    publisher_id: str
    policy: WitnessQuorumPolicy
    operation_id: str
    execution_id: str
    checkpoint_version: int
    checkpoint_digest: str
    quorum_state: str
    required: int
    counted_witnesses: tuple[str, ...]
    conflicting_commitment_hashes: tuple[str, ...]
    votes: tuple[WitnessVote, ...]
    issued_at: float
    signature: str

    def signed_fields(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "publisher_id": self.publisher_id,
            "policy": {
                "policy_id": self.policy.policy_id,
                "witnesses": [
                    {
                        "witness_id": witness_id,
                        "public_key_b64": public_key_b64,
                    }
                    for witness_id, public_key_b64 in self.policy.witnesses
                ],
                "threshold": self.policy.threshold,
            },
            "operation_id": self.operation_id,
            "execution_id": self.execution_id,
            "checkpoint_version": self.checkpoint_version,
            "checkpoint_digest": self.checkpoint_digest,
            "quorum_state": self.quorum_state,
            "required": self.required,
            "counted_witnesses": list(self.counted_witnesses),
            "conflicting_commitment_hashes": list(
                self.conflicting_commitment_hashes
            ),
            "votes": [
                {
                    "receipt": vote.receipt.to_dict(),
                    "record": vote.record.to_dict(),
                }
                for vote in self.votes
            ],
            "issued_at": self.issued_at,
        }

    def signing_bytes(self) -> bytes:
        return canonical_payload(self.signed_fields())

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_fields(), "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> "WitnessGossipBundle":
        if not isinstance(data, Mapping):
            raise MalformedWitnessGossip(
                f"expected an object, got {type(data).__name__}"
            )
        expected = {
            "version",
            "publisher_id",
            "policy",
            "operation_id",
            "execution_id",
            "checkpoint_version",
            "checkpoint_digest",
            "quorum_state",
            "required",
            "counted_witnesses",
            "conflicting_commitment_hashes",
            "votes",
            "issued_at",
            "signature",
        }
        keys = set(data)
        if keys - expected:
            raise MalformedWitnessGossip(
                f"unexpected fields: {sorted(keys - expected)}"
            )
        if expected - keys:
            raise MalformedWitnessGossip(
                f"missing fields: {sorted(expected - keys)}"
            )

        policy = _policy_from_dict(data["policy"])
        votes = _votes_from_list(data["votes"])
        issued_at = _finite_float(data["issued_at"], "issued_at")
        checkpoint_version = _integer(
            data["checkpoint_version"], "checkpoint_version"
        )
        required = _integer(data["required"], "required")
        if checkpoint_version < 0:
            raise MalformedWitnessGossip("checkpoint_version must be >= 0")
        if required < 1:
            raise MalformedWitnessGossip("required must be >= 1")

        counted = _string_tuple(data["counted_witnesses"], "counted_witnesses")
        conflicts = _string_tuple(
            data["conflicting_commitment_hashes"],
            "conflicting_commitment_hashes",
        )

        return cls(
            version=_nonempty(data["version"], "version"),
            publisher_id=_nonempty(data["publisher_id"], "publisher_id"),
            policy=policy,
            operation_id=_string(data["operation_id"], "operation_id"),
            execution_id=_string(data["execution_id"], "execution_id"),
            checkpoint_version=checkpoint_version,
            checkpoint_digest=_string(
                data["checkpoint_digest"], "checkpoint_digest"
            ),
            quorum_state=_nonempty(data["quorum_state"], "quorum_state"),
            required=required,
            counted_witnesses=counted,
            conflicting_commitment_hashes=conflicts,
            votes=votes,
            issued_at=issued_at,
            signature=_nonempty(data["signature"], "signature"),
        )


class WitnessGossipSigner:
    """Outer transport signer. It is deliberately not a quorum authority."""

    __slots__ = ("_key", "publisher_id")

    def __init__(self, private_key: Ed25519PrivateKey, publisher_id: str) -> None:
        if not publisher_id.strip():
            raise ValueError("publisher_id must not be empty")
        self._key = private_key
        self.publisher_id = publisher_id

    @classmethod
    def generate(cls, publisher_id: str) -> "WitnessGossipSigner":
        return cls(Ed25519PrivateKey.generate(), publisher_id)

    def public_key_b64(self) -> str:
        return encode_public_key(self._key.public_key())

    def sign(
        self,
        *,
        policy: WitnessQuorumPolicy,
        result: WitnessQuorumResult,
        votes: tuple[WitnessVote, ...],
        issued_at: float | None = None,
    ) -> WitnessGossipBundle:
        stamp = time.time() if issued_at is None else float(issued_at)
        if not math.isfinite(stamp):
            raise ValueError("issued_at must be finite")
        unsigned = WitnessGossipBundle(
            version=WITNESS_GOSSIP_VERSION,
            publisher_id=self.publisher_id,
            policy=policy,
            operation_id=result.operation_id,
            execution_id=result.execution_id,
            checkpoint_version=result.checkpoint_version,
            checkpoint_digest=result.checkpoint_digest,
            quorum_state=str(result.state),
            required=result.required,
            counted_witnesses=result.counted_witnesses,
            conflicting_commitment_hashes=result.conflicting_commitment_hashes,
            votes=votes,
            issued_at=stamp,
            signature="",
        )
        signature = self._key.sign(unsigned.signing_bytes())
        return WitnessGossipBundle(
            **{
                **unsigned.__dict__,
                "signature": base64.b64encode(signature).decode("ascii"),
            }
        )


class WitnessGossipVerifier:
    """Verify outer provenance, then independently recompute inner quorum."""

    __slots__ = ("_key", "publisher_id")

    def __init__(self, public_key: Ed25519PublicKey, publisher_id: str) -> None:
        if not publisher_id.strip():
            raise ValueError("publisher_id must not be empty")
        self._key = public_key
        self.publisher_id = publisher_id

    @classmethod
    def from_b64(
        cls, encoded: str, publisher_id: str
    ) -> "WitnessGossipVerifier":
        try:
            raw = base64.b64decode(encoded, validate=True)
            key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise WitnessGossipSignatureInvalid(
                f"public key is not valid Ed25519 base64: {exc}"
            ) from exc
        return cls(key, publisher_id)

    def verify(
        self,
        bundle: WitnessGossipBundle,
        *,
        expected_policy_digest: str,
    ) -> WitnessQuorumResult:
        if bundle.version != WITNESS_GOSSIP_VERSION:
            raise WitnessGossipBindingError(
                f"unsupported gossip version {bundle.version!r}"
            )
        if bundle.publisher_id != self.publisher_id:
            raise WitnessGossipBindingError(
                f"bundle belongs to {bundle.publisher_id!r}, not "
                f"{self.publisher_id!r}"
            )
        if not math.isfinite(bundle.issued_at):
            raise WitnessGossipBindingError("gossip issued_at must be finite")

        try:
            signature = base64.b64decode(bundle.signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise WitnessGossipSignatureInvalid(
                f"signature is not valid base64: {exc}"
            ) from exc
        if len(signature) != 64:
            raise WitnessGossipSignatureInvalid(
                f"Ed25519 signatures are 64 bytes, got {len(signature)}"
            )
        try:
            self._key.verify(signature, bundle.signing_bytes())
        except InvalidSignature as exc:
            raise WitnessGossipSignatureInvalid(
                "signature does not match gossip bundle"
            ) from exc

        verifiers = {
            witness_id: WitnessReceiptVerifier.from_b64(
                public_key_b64, witness_id
            )
            for witness_id, public_key_b64 in bundle.policy.witnesses
        }
        recomputed = evaluate_witness_quorum(
            bundle.votes,
            verifiers=verifiers,
            policy=bundle.policy,
            expected_policy_digest=expected_policy_digest,
        )
        expected = _result_projection(recomputed)
        actual = {
            "operation_id": bundle.operation_id,
            "execution_id": bundle.execution_id,
            "checkpoint_version": bundle.checkpoint_version,
            "checkpoint_digest": bundle.checkpoint_digest,
            "quorum_state": bundle.quorum_state,
            "required": bundle.required,
            "counted_witnesses": bundle.counted_witnesses,
            "conflicting_commitment_hashes": bundle.conflicting_commitment_hashes,
        }
        if actual != expected:
            raise WitnessGossipBindingError(
                "gossip quorum claim does not match independently recomputed result"
            )
        return recomputed


def _result_projection(result: WitnessQuorumResult) -> dict[str, Any]:
    return {
        "operation_id": result.operation_id,
        "execution_id": result.execution_id,
        "checkpoint_version": result.checkpoint_version,
        "checkpoint_digest": result.checkpoint_digest,
        "quorum_state": str(result.state),
        "required": result.required,
        "counted_witnesses": result.counted_witnesses,
        "conflicting_commitment_hashes": result.conflicting_commitment_hashes,
    }


def _policy_from_dict(data: Any) -> WitnessQuorumPolicy:
    if not isinstance(data, Mapping):
        raise MalformedWitnessGossip("policy must be an object")
    expected = {"policy_id", "witnesses", "threshold"}
    keys = set(data)
    if keys != expected:
        raise MalformedWitnessGossip(
            f"policy fields mismatch: {sorted(keys ^ expected)}"
        )
    raw_witnesses = data["witnesses"]
    if not isinstance(raw_witnesses, list):
        raise MalformedWitnessGossip("policy witnesses must be a list")
    witnesses: list[tuple[str, str]] = []
    for item in raw_witnesses:
        if not isinstance(item, Mapping) or set(item) != {
            "witness_id",
            "public_key_b64",
        }:
            raise MalformedWitnessGossip("malformed policy witness entry")
        witnesses.append(
            (
                _nonempty(item["witness_id"], "witness_id"),
                _nonempty(item["public_key_b64"], "public_key_b64"),
            )
        )
    try:
        return WitnessQuorumPolicy(
            _nonempty(data["policy_id"], "policy_id"),
            tuple(witnesses),
            _integer(data["threshold"], "threshold"),
        )
    except ValueError as exc:
        raise MalformedWitnessGossip(str(exc)) from exc


def _votes_from_list(data: Any) -> tuple[WitnessVote, ...]:
    if not isinstance(data, list):
        raise MalformedWitnessGossip("votes must be a list")
    votes: list[WitnessVote] = []
    for item in data:
        if not isinstance(item, Mapping) or set(item) != {"receipt", "record"}:
            raise MalformedWitnessGossip("malformed gossip vote")
        try:
            receipt = WitnessReceipt.from_dict(item["receipt"])
            record = _record_from_dict(item["record"])
        except ValueError as exc:
            raise MalformedWitnessGossip(str(exc)) from exc
        votes.append(WitnessVote(receipt, record))
    return tuple(votes)


def _record_from_dict(data: Any) -> WitnessRecord:
    if not isinstance(data, Mapping):
        raise MalformedWitnessGossip("witness record must be an object")
    expected = {
        "version",
        "witness_id",
        "signer_id",
        "operation_id",
        "execution_id",
        "checkpoint_version",
        "checkpoint_digest",
        "last_journal_sequence",
        "last_journal_hash",
        "checkpoint_signature",
        "observed_at",
        "previous_record_hash",
        "record_hash",
    }
    if set(data) != expected:
        raise MalformedWitnessGossip(
            f"witness record fields mismatch: {sorted(set(data) ^ expected)}"
        )
    record = WitnessRecord(
        version=_nonempty(data["version"], "record.version"),
        witness_id=_nonempty(data["witness_id"], "record.witness_id"),
        signer_id=_nonempty(data["signer_id"], "record.signer_id"),
        operation_id=_nonempty(data["operation_id"], "record.operation_id"),
        execution_id=_nonempty(data["execution_id"], "record.execution_id"),
        checkpoint_version=_integer(
            data["checkpoint_version"], "record.checkpoint_version"
        ),
        checkpoint_digest=_nonempty(
            data["checkpoint_digest"], "record.checkpoint_digest"
        ),
        last_journal_sequence=_integer(
            data["last_journal_sequence"], "record.last_journal_sequence"
        ),
        last_journal_hash=_string(
            data["last_journal_hash"], "record.last_journal_hash"
        ),
        checkpoint_signature=_nonempty(
            data["checkpoint_signature"], "record.checkpoint_signature"
        ),
        observed_at=_finite_float(
            data["observed_at"], "record.observed_at"
        ),
        previous_record_hash=_nonempty(
            data["previous_record_hash"], "record.previous_record_hash"
        ),
        record_hash=_nonempty(data["record_hash"], "record.record_hash"),
    )
    if record.version != WITNESS_RECORD_VERSION:
        raise MalformedWitnessGossip(
            f"unsupported witness record version {record.version!r}"
        )
    if record.checkpoint_version < 1:
        raise MalformedWitnessGossip("record checkpoint_version must be >= 1")
    if not record.intact:
        raise MalformedWitnessGossip("witness record failed content integrity")
    return record


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise MalformedWitnessGossip(f"{field} must be a string")
    return value


def _nonempty(value: Any, field: str) -> str:
    value = _string(value, field)
    if not value.strip():
        raise MalformedWitnessGossip(f"{field} must not be empty")
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedWitnessGossip(f"{field} must be an integer")
    return value


def _finite_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedWitnessGossip(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result):
        raise MalformedWitnessGossip(f"{field} must be finite")
    return result


def _string_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise MalformedWitnessGossip(f"{field} must be a list")
    return tuple(_string(item, field) for item in value)


__all__ = [
    "MalformedWitnessGossip",
    "WITNESS_GOSSIP_VERSION",
    "WitnessGossipBindingError",
    "WitnessGossipBundle",
    "WitnessGossipError",
    "WitnessGossipSignatureInvalid",
    "WitnessGossipSigner",
    "WitnessGossipVerifier",
]
