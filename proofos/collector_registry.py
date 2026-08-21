"""Collector identity: public keys, scopes, and what each may attest to.

A ``collector_id`` inside a signed payload is a claim, not an identity. It
becomes an identity only when the signature verifies against the key this
registry holds for that id. Checking the field without checking the key would
let anyone relabel an attestation and keep the signature that no longer matches.

The registry is sealed after startup. Which keys are trusted must not change
while executions are running.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from .attestation import AttestationVerifier


class CollectorIdentityError(ValueError):
    """Raised when a collector is unknown, unscoped, or its key does not match."""


class UnknownCollector(CollectorIdentityError):
    pass


class CollectorScopeViolation(CollectorIdentityError):
    pass


@dataclass(frozen=True)
class CollectorRecord:
    collector_id: str
    public_key_b64: str
    allowed_kinds: frozenset[str]
    allowed_profiles: frozenset[str]
    version: str = "v1"
    active: bool = True
    _verifier: AttestationVerifier = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        try:
            raw = base64.b64decode(self.public_key_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise CollectorIdentityError(
                f"{self.collector_id}: public key is not valid base64"
            ) from exc
        if len(raw) != 32:
            raise CollectorIdentityError(
                f"{self.collector_id}: Ed25519 public keys are 32 bytes, "
                f"got {len(raw)}"
            )
        object.__setattr__(self, "_verifier", AttestationVerifier.from_bytes(raw))

    @property
    def verifier(self) -> AttestationVerifier:
        return self._verifier


class CollectorRegistry:
    """Which collectors exist, their keys, and what each may attest to."""

    def __init__(self) -> None:
        self._records: dict[str, CollectorRecord] = {}
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    def register(self, record: CollectorRecord) -> CollectorRecord:
        if self._sealed:
            raise CollectorIdentityError(
                f"cannot register {record.collector_id!r}: the collector registry "
                "is sealed. Trusted keys must not change mid-execution."
            )
        if record.collector_id in self._records:
            raise CollectorIdentityError(
                f"duplicate collector {record.collector_id!r}"
            )
        self._records[record.collector_id] = record
        return record

    def seal(self) -> "CollectorRegistry":
        self._sealed = True
        return self

    def get(self, collector_id: str) -> CollectorRecord:
        record = self._records.get(collector_id)
        if record is None:
            raise UnknownCollector(f"unknown collector {collector_id!r}")
        if not record.active:
            raise UnknownCollector(f"collector {collector_id!r} is not active")
        return record

    def require_scope(self, collector_id: str, kind: str, profile_id: str) -> CollectorRecord:
        """Confirm this collector may attest to this kind via this profile."""
        record = self.get(collector_id)
        if kind not in record.allowed_kinds:
            raise CollectorScopeViolation(
                f"collector {collector_id!r} may not attest to {kind!r} evidence; "
                f"scoped to {sorted(record.allowed_kinds)}"
            )
        if profile_id not in record.allowed_profiles:
            raise CollectorScopeViolation(
                f"collector {collector_id!r} may not use profile {profile_id!r}; "
                f"scoped to {sorted(record.allowed_profiles)}"
            )
        return record

    def records(self) -> tuple[CollectorRecord, ...]:
        return tuple(self._records.values())

    def ids(self) -> tuple[str, ...]:
        return tuple(self._records)


def registry_for(
    collector_id: str,
    public_key_b64: str,
    allowed_kinds: tuple[str, ...],
    allowed_profiles: tuple[str, ...],
) -> CollectorRegistry:
    """A sealed registry trusting exactly one collector key."""
    registry = CollectorRegistry()
    registry.register(
        CollectorRecord(
            collector_id=collector_id,
            public_key_b64=public_key_b64,
            allowed_kinds=frozenset(allowed_kinds),
            allowed_profiles=frozenset(allowed_profiles),
        )
    )
    return registry.seal()
