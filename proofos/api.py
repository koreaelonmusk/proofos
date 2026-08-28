"""The public Python surface.

Small on purpose. A developer integrating ProofOS needs to express one thing --
"here is a claim, here is what would prove it, here is what I have" -- and read
one answer. Everything else in this package is machinery for doing that safely,
and machinery is not an API.

``ProofOS`` is a façade. It adds no rules: the verdict comes from the same
``verify_completion`` kernel that the ADK runtime, the HTTP service and the CLI
all call. That is the point. A second entry point that decided things slightly
differently would be a second definition of truth, which is exactly what this
project exists to prevent.

    from proofos import ProofOS, Requirement, Evidence, EvidenceSource

    result = ProofOS().verify(
        claim="Deployment complete.",
        requirements=[Requirement("runtime_health", max_age_seconds=300)],
        evidence=[
            Evidence("runtime_health", "deploy-agent says it is up",
                     EvidenceSource.EXECUTOR, collector="deploy-agent"),
        ],
    )

    result.status      # ABSTAIN
    result.reason      # EVIDENCE_UNTRUSTED
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .verifier import (
    Evidence,
    EvidenceAssessment,
    FailureClass,
    Requirement,
    VerificationResult,
    VerificationStatus,
    verify_completion,
)


@dataclass(frozen=True)
class Decision:
    """What ProofOS concluded, and enough to explain it to a person.

    Wraps ``VerificationResult`` rather than replacing it: ``raw`` is always
    the kernel's own output, so nothing here can drift from what was decided.
    """

    status: VerificationStatus
    reason: FailureClass
    explanation: str
    missing: tuple[str, ...]
    evidence: tuple[EvidenceAssessment, ...]
    raw: VerificationResult

    @property
    def verified(self) -> bool:
        return self.status is VerificationStatus.VERIFIED

    @property
    def accepted(self) -> tuple[EvidenceAssessment, ...]:
        return tuple(a for a in self.evidence if a.accepted_by_verifier)

    @property
    def rejected(self) -> tuple[EvidenceAssessment, ...]:
        return tuple(a for a in self.evidence if not a.accepted_by_verifier)

    def as_dict(self) -> dict:
        return {
            "status": str(self.status),
            "reason": str(self.reason),
            "explanation": self.explanation,
            "missing": list(self.missing),
            "evidence": [a.as_dict() for a in self.evidence],
        }

    def __str__(self) -> str:
        return f"{self.status} ({self.reason})"


class ProofOS:
    """Ask whether a claim is supported by evidence that did not come from the
    thing making the claim.

    Holds no state between calls and grants no authority. Constructing one does
    not let you certify anything; it only lets you ask.
    """

    def verify(
        self,
        claim: str,
        requirements: Iterable[Requirement | str],
        evidence: Iterable[Evidence] = (),
        now: float | None = None,
    ) -> Decision:
        """Return a decision. Never raises on bad input -- it abstains.

        ``now`` is injectable so callers can reason about freshness
        deterministically. That is how a three-week-old observation can be
        shown to have expired without waiting three weeks.
        """
        result = verify_completion(
            claim=claim,
            evidence=tuple(evidence),
            required_kinds=tuple(requirements),
            now=now,
        )
        return Decision(
            status=result.status,
            reason=result.failure,
            explanation=result.reason,
            missing=result.missing,
            evidence=result.assessments,
            raw=result,
        )


__all__ = ["Decision", "ProofOS"]
