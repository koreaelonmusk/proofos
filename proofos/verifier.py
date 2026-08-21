from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable

from .integrity import content_hash


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    ABSTAIN = "ABSTAIN"


class EvidenceSource(StrEnum):
    """Provenance of an evidence item.

    Only OBSERVED evidence originates outside the agent under scrutiny and can
    therefore satisfy a verification requirement.
    """

    OBSERVED = "OBSERVED"
    EXECUTOR = "EXECUTOR"
    MODEL = "MODEL"


TRUSTED_SOURCES: frozenset[EvidenceSource] = frozenset({EvidenceSource.OBSERVED})


class FailureClass(StrEnum):
    NONE = "NONE"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"
    EVIDENCE_UNTRUSTED = "EVIDENCE_UNTRUSTED"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_TAMPERED = "EVIDENCE_TAMPERED"
    MALFORMED_INPUT = "MALFORMED_INPUT"
    VERIFIER_FAILURE = "VERIFIER_FAILURE"


@dataclass(frozen=True)
class Evidence:
    """A single observation offered in support of a completion claim.

    ``source`` is mandatory: an evidence item with no declared provenance cannot
    be trusted, so the contract refuses to let callers omit it.

    ``collected_at`` gives the observation a position in time. Without it an
    observation can be replayed forever, so a requirement that declares a
    freshness horizon will not accept undated evidence.
    """

    kind: str
    value: str
    source: EvidenceSource
    valid: bool = True
    collected_at: float | None = None
    collector: str = "unspecified"
    content_hash: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if not self.content_hash:
            object.__setattr__(self, "content_hash", self.compute_hash())

    def compute_hash(self) -> str:
        return content_hash(
            {
                "kind": self.kind,
                "value": self.value,
                "source": str(self.source),
                "valid": self.valid,
                "collected_at": self.collected_at,
                "collector": self.collector,
            }
        )

    @property
    def intact(self) -> bool:
        """False if the record's content no longer matches its own digest."""
        return self.content_hash == self.compute_hash()


@dataclass(frozen=True)
class Requirement:
    """One thing that must be proven before a claim can be accepted.

    ``max_age_seconds`` is the horizon over which an observation stays
    meaningful. A health probe speaks only for the moment it ran; a recorded
    test run speaks for as long as the commit it describes. Declaring the
    horizon per requirement keeps that difference explicit instead of assuming
    one global answer.
    """

    kind: str
    max_age_seconds: float | None = None


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reason: str
    missing: tuple[str, ...] = ()
    failure: FailureClass = FailureClass.NONE


def _abstain(
    reason: str,
    failure: FailureClass,
    missing: tuple[str, ...] = (),
) -> VerificationResult:
    return VerificationResult(
        status=VerificationStatus.ABSTAIN,
        reason=reason,
        missing=missing,
        failure=failure,
    )


def _as_requirement(item: object) -> Requirement | None:
    if isinstance(item, Requirement):
        return item if item.kind.strip() else None
    if isinstance(item, str):
        return Requirement(item.strip()) if item.strip() else None
    return None


def verify_completion(
    claim: str,
    evidence: Iterable[Evidence],
    required_kinds: Iterable[Requirement | str],
    now: float | None = None,
) -> VerificationResult:
    """Fail closed unless every declared requirement is met by trusted evidence.

    A requirement is satisfied only when the most recent trusted observation of
    that kind is valid, intact, non-empty, and within the requirement's freshness
    horizon.

    Any unexpected error is reported as ABSTAIN/VERIFIER_FAILURE: a verifier that
    crashes must never be read as success.
    """
    try:
        return _verify(claim, evidence, required_kinds, now)
    except Exception as exc:  # noqa: BLE001 - verifier failure must fail closed
        return _abstain(
            f"Verifier failed with an unexpected error: {type(exc).__name__}.",
            FailureClass.VERIFIER_FAILURE,
        )


def _verify(
    claim: str,
    evidence: Iterable[Evidence],
    required_kinds: Iterable[Requirement | str],
    now: float | None,
) -> VerificationResult:
    if not isinstance(claim, str) or not claim.strip():
        return _abstain(
            "Completion claim is empty or malformed.",
            FailureClass.MALFORMED_INPUT,
        )

    requirements: list[Requirement] = []
    seen: set[str] = set()
    for raw in required_kinds:
        requirement = _as_requirement(raw)
        if requirement is None or requirement.kind in seen:
            continue
        seen.add(requirement.kind)
        requirements.append(requirement)

    if not requirements:
        return _abstain(
            "No verification requirements were declared.",
            FailureClass.EVIDENCE_MISSING,
        )

    items = tuple(evidence)
    if any(not isinstance(item, Evidence) for item in items):
        return _abstain(
            "Evidence set contains a malformed item.",
            FailureClass.MALFORMED_INPUT,
            tuple(r.kind for r in requirements),
        )

    if any(not item.intact for item in items):
        return _abstain(
            "An evidence record no longer matches its own content hash.",
            FailureClass.EVIDENCE_TAMPERED,
            tuple(r.kind for r in requirements),
        )

    reference_time = time.time() if now is None else now
    unsatisfied: list[str] = []
    failures: list[FailureClass] = []

    for requirement in requirements:
        failure = _evaluate(requirement, items, reference_time)
        if failure is not None:
            unsatisfied.append(requirement.kind)
            failures.append(failure)

    if unsatisfied:
        distinct = set(failures)
        failure = failures[0] if len(distinct) == 1 else FailureClass.EVIDENCE_MISSING
        return _abstain(
            "Required evidence is missing, stale, invalid, or self-reported.",
            failure,
            tuple(unsatisfied),
        )

    return VerificationResult(
        status=VerificationStatus.VERIFIED,
        reason=(
            "All required evidence is present, valid, fresh, and "
            "independently sourced."
        ),
    )


def _timestamp(item: Evidence) -> float:
    """Undated evidence sorts oldest so it can never supersede a real reading."""
    return item.collected_at if item.collected_at is not None else float("-inf")


def _evaluate(
    requirement: Requirement,
    items: tuple[Evidence, ...],
    now: float,
) -> FailureClass | None:
    """Return the failure class for a requirement, or None if it is satisfied."""
    matching = [item for item in items if item.kind.strip() == requirement.kind]
    if not matching:
        return FailureClass.EVIDENCE_MISSING

    trusted = [item for item in matching if item.source in TRUSTED_SOURCES]
    if not trusted:
        return FailureClass.EVIDENCE_UNTRUSTED

    if requirement.max_age_seconds is not None:
        horizon = now - requirement.max_age_seconds
        fresh = [
            item
            for item in trusted
            if item.collected_at is not None and item.collected_at >= horizon
        ]
        if not fresh:
            # Undated evidence is treated as stale: an observation that cannot
            # be placed in time cannot be shown to still hold.
            return FailureClass.EVIDENCE_STALE
        trusted = fresh

    # The most recent observation governs. An older failed probe does not veto a
    # service since observed healthy, and a newer failed probe does veto an
    # earlier success.
    latest = max(_timestamp(item) for item in trusted)
    governing = [item for item in trusted if _timestamp(item) == latest]

    # Observations that are equally recent and disagree are unresolvable.
    if any(not item.valid or not item.value.strip() for item in governing):
        return FailureClass.EVIDENCE_INVALID

    return None
