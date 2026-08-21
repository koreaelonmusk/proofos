from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    ABSTAIN = "ABSTAIN"


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    valid: bool = True


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    reason: str
    missing: tuple[str, ...] = ()


def verify_completion(
    claim: str,
    evidence: Iterable[Evidence],
    required_kinds: Iterable[str],
) -> VerificationResult:
    """Fail closed unless all declared evidence requirements are satisfied."""
    claim = claim.strip()
    if not claim:
        return VerificationResult(
            status=VerificationStatus.ABSTAIN,
            reason="Completion claim is empty.",
        )

    required = tuple(
        dict.fromkeys(kind.strip() for kind in required_kinds if kind.strip())
    )
    if not required:
        return VerificationResult(
            status=VerificationStatus.ABSTAIN,
            reason="No verification requirements were declared.",
        )

    valid_kinds = {
        item.kind.strip()
        for item in evidence
        if item.kind.strip() and item.value.strip() and item.valid
    }

    missing = tuple(kind for kind in required if kind not in valid_kinds)
    if missing:
        return VerificationResult(
            status=VerificationStatus.ABSTAIN,
            reason="Required evidence is missing or invalid.",
            missing=missing,
        )

    return VerificationResult(
        status=VerificationStatus.VERIFIED,
        reason="All required evidence is present and valid.",
    )
