from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


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
    MALFORMED_INPUT = "MALFORMED_INPUT"
    VERIFIER_FAILURE = "VERIFIER_FAILURE"


@dataclass(frozen=True)
class Evidence:
    """A single observation offered in support of a completion claim.

    ``source`` is mandatory: an evidence item with no declared provenance cannot
    be trusted, so the contract refuses to let callers omit it.
    """

    kind: str
    value: str
    source: EvidenceSource
    valid: bool = True


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


def verify_completion(
    claim: str,
    evidence: Iterable[Evidence],
    required_kinds: Iterable[str],
) -> VerificationResult:
    """Fail closed unless every declared requirement is met by trusted evidence.

    A requirement is satisfied only when at least one evidence item of that kind
    is valid, non-empty, and carries a trusted provenance, *and* no evidence item
    of that kind is invalid. Conflicting evidence is treated as unverifiable
    rather than resolved in favour of the claim.

    Any unexpected error is reported as ABSTAIN/VERIFIER_FAILURE: a verifier that
    crashes must never be read as success.
    """
    try:
        return _verify(claim, evidence, required_kinds)
    except Exception as exc:  # noqa: BLE001 - verifier failure must fail closed
        return _abstain(
            f"Verifier failed with an unexpected error: {type(exc).__name__}.",
            FailureClass.VERIFIER_FAILURE,
        )


def _verify(
    claim: str,
    evidence: Iterable[Evidence],
    required_kinds: Iterable[str],
) -> VerificationResult:
    if not isinstance(claim, str) or not claim.strip():
        return _abstain(
            "Completion claim is empty or malformed.",
            FailureClass.MALFORMED_INPUT,
        )

    required = tuple(
        dict.fromkeys(
            kind.strip()
            for kind in required_kinds
            if isinstance(kind, str) and kind.strip()
        )
    )
    if not required:
        return _abstain(
            "No verification requirements were declared.",
            FailureClass.EVIDENCE_MISSING,
        )

    items = tuple(evidence)
    if any(not isinstance(item, Evidence) for item in items):
        return _abstain(
            "Evidence set contains a malformed item.",
            FailureClass.MALFORMED_INPUT,
            required,
        )

    unsatisfied: list[str] = []
    failures: set[FailureClass] = set()

    for kind in required:
        matching = [item for item in items if item.kind.strip() == kind]
        if not matching:
            unsatisfied.append(kind)
            failures.add(FailureClass.EVIDENCE_MISSING)
            continue

        # Conflicting or tampered evidence never resolves in favour of the claim.
        if any(not item.valid or not item.value.strip() for item in matching):
            unsatisfied.append(kind)
            failures.add(FailureClass.EVIDENCE_INVALID)
            continue

        if not any(item.source in TRUSTED_SOURCES for item in matching):
            unsatisfied.append(kind)
            failures.add(FailureClass.EVIDENCE_UNTRUSTED)
            continue

    if unsatisfied:
        # Report the most specific failure when exactly one class is implicated.
        failure = failures.pop() if len(failures) == 1 else FailureClass.EVIDENCE_MISSING
        return _abstain(
            "Required evidence is missing, invalid, or self-reported.",
            failure,
            tuple(unsatisfied),
        )

    return VerificationResult(
        status=VerificationStatus.VERIFIED,
        reason="All required evidence is present, valid, and independently sourced.",
    )
