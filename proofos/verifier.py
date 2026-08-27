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
class EvidenceAssessment:
    """Why one evidence item did or did not count, for this decision.

    A reporting projection, not a second opinion. Every field here is produced
    by the same pass that produced the verdict, so a presentation layer can
    render what the verifier did without re-deriving trust rules of its own --
    which is how a rejected self-report came to be displayed as satisfying.

    The three flags are deliberately distinct:

    ``integrity_valid``
        The record is internally sound: it matches its own digest, is not
        marked invalid, and carries a value. True for an honest self-report.
    ``accepted_by_verifier``
        The record survived the trust policy for a requirement of its kind --
        trusted provenance, within the freshness horizon, integrity intact.
    ``satisfies_requirement``
        The record was actually among those that settled a requirement. A
        trusted-but-superseded observation is accepted and does not satisfy.

    Acceptance is a fact about one decision, not a property of the evidence.
    The same item can be rejected at attempt 1 and irrelevant at attempt 2.
    """

    evidence_id: str
    kind: str
    source: str
    collector: str
    integrity_valid: bool
    accepted_by_verifier: bool
    satisfies_requirement: bool
    rejection_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "source": self.source,
            "collector": self.collector,
            "integrity_valid": self.integrity_valid,
            "accepted_by_verifier": self.accepted_by_verifier,
            "satisfies_requirement": self.satisfies_requirement,
            "rejection_reason": self.rejection_reason,
        }


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reason: str
    missing: tuple[str, ...] = ()
    failure: FailureClass = FailureClass.NONE
    assessments: tuple[EvidenceAssessment, ...] = ()

    @property
    def accepted_evidence_ids(self) -> tuple[str, ...]:
        return tuple(a.evidence_id for a in self.assessments if a.accepted_by_verifier)

    @property
    def rejected_evidence_ids(self) -> tuple[str, ...]:
        return tuple(
            a.evidence_id for a in self.assessments if not a.accepted_by_verifier
        )


def _abstain(
    reason: str,
    failure: FailureClass,
    missing: tuple[str, ...] = (),
    assessments: tuple[EvidenceAssessment, ...] = (),
) -> VerificationResult:
    return VerificationResult(
        status=VerificationStatus.ABSTAIN,
        reason=reason,
        missing=missing,
        failure=failure,
        assessments=assessments,
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
        # Nothing is accepted once the set is tampered, and the projection says
        # so item by item rather than leaving a caller to infer it.
        return _abstain(
            "An evidence record no longer matches its own content hash.",
            FailureClass.EVIDENCE_TAMPERED,
            tuple(r.kind for r in requirements),
            _assess(items, {}),
        )

    reference_time = time.time() if now is None else now
    unsatisfied: list[str] = []
    failures: list[FailureClass] = []
    outcomes: dict[str, _RequirementOutcome] = {}

    for requirement in requirements:
        outcome = _evaluate(requirement, items, reference_time)
        outcomes[requirement.kind] = outcome
        if outcome.failure is not None:
            unsatisfied.append(requirement.kind)
            failures.append(outcome.failure)

    assessments = _assess(items, outcomes)

    if unsatisfied:
        distinct = set(failures)
        failure = failures[0] if len(distinct) == 1 else FailureClass.EVIDENCE_MISSING
        return _abstain(
            "Required evidence is missing, stale, invalid, or self-reported.",
            failure,
            tuple(unsatisfied),
            assessments,
        )

    return VerificationResult(
        status=VerificationStatus.VERIFIED,
        reason=(
            "All required evidence is present, valid, fresh, and "
            "independently sourced."
        ),
        assessments=assessments,
    )


def _timestamp(item: Evidence) -> float:
    """Undated evidence sorts oldest so it can never supersede a real reading."""
    return item.collected_at if item.collected_at is not None else float("-inf")


@dataclass(frozen=True)
class _RequirementOutcome:
    """The verdict for one requirement, plus the items that produced it."""

    failure: FailureClass | None
    accepted: tuple[Evidence, ...] = ()
    governing: tuple[Evidence, ...] = ()


def _evaluate(
    requirement: Requirement,
    items: tuple[Evidence, ...],
    now: float,
) -> _RequirementOutcome:
    """Decide one requirement and report which evidence decided it.

    The decision path is unchanged; the sets it walks are now returned instead
    of discarded, so reporting can describe the same selection rather than
    guess at it.
    """
    matching = [item for item in items if item.kind.strip() == requirement.kind]
    if not matching:
        return _RequirementOutcome(FailureClass.EVIDENCE_MISSING)

    trusted = [item for item in matching if item.source in TRUSTED_SOURCES]
    if not trusted:
        return _RequirementOutcome(FailureClass.EVIDENCE_UNTRUSTED)

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
            return _RequirementOutcome(FailureClass.EVIDENCE_STALE)
        trusted = fresh

    # The most recent observation governs. An older failed probe does not veto a
    # service since observed healthy, and a newer failed probe does veto an
    # earlier success.
    latest = max(_timestamp(item) for item in trusted)
    governing = [item for item in trusted if _timestamp(item) == latest]

    # Observations that are equally recent and disagree are unresolvable.
    if any(not item.valid or not item.value.strip() for item in governing):
        return _RequirementOutcome(
            FailureClass.EVIDENCE_INVALID, tuple(trusted), tuple(governing)
        )

    return _RequirementOutcome(None, tuple(trusted), tuple(governing))


def _integrity_valid(item: Evidence) -> bool:
    """Internally sound: matches its digest, not marked invalid, carries a value."""
    return item.intact and item.valid and bool(item.value.strip())


def _assess(
    items: tuple[Evidence, ...],
    outcomes: dict[str, _RequirementOutcome],
) -> tuple[EvidenceAssessment, ...]:
    """Project the decision onto each evidence item.

    Nothing here re-decides anything: acceptance is membership in a set the
    verifier already built, and the reason is read off the same failure class.
    """
    accepted_ids: dict[int, str] = {}
    governing_ids: dict[int, str] = {}
    for kind, outcome in outcomes.items():
        for item in outcome.accepted:
            accepted_ids[id(item)] = kind
        if outcome.failure is None:
            for item in outcome.governing:
                governing_ids[id(item)] = kind

    assessments = []
    for item in items:
        kind = item.kind.strip()
        outcome = outcomes.get(kind)
        # Acceptance presupposes integrity. An item can reach the trusted pool
        # on provenance alone -- the kernel only tests validity on the items
        # that govern -- but reporting an unsound record as accepted would
        # overstate what the verifier did.
        accepted = id(item) in accepted_ids and _integrity_valid(item)
        satisfies = id(item) in governing_ids
        assessments.append(
            EvidenceAssessment(
                evidence_id=item.content_hash,
                kind=item.kind,
                source=str(item.source),
                collector=item.collector,
                integrity_valid=_integrity_valid(item),
                accepted_by_verifier=accepted,
                satisfies_requirement=satisfies,
                rejection_reason=_rejection_reason(item, outcome, accepted, satisfies),
            )
        )
    return tuple(assessments)


def _rejection_reason(
    item: Evidence,
    outcome: _RequirementOutcome | None,
    accepted: bool,
    satisfies: bool,
) -> str:
    if satisfies:
        return ""
    if outcome is None:
        return "No requirement of this kind was declared for this task."
    if not item.intact:
        return "The record no longer matches its own content hash."
    if item.source not in TRUSTED_SOURCES:
        return (
            f"Provenance is {item.source}; only {'/'.join(sorted(TRUSTED_SOURCES))} "
            "evidence originates outside the agent under scrutiny."
        )
    if not item.valid or not item.value.strip():
        return "Marked invalid or empty, so it cannot settle the requirement."
    if not accepted:
        if outcome.failure is FailureClass.EVIDENCE_STALE:
            return "Outside the freshness horizon declared by the requirement."
        return f"Not accepted for this requirement: {outcome.failure}."
    return "Superseded by a more recent observation of the same kind."
