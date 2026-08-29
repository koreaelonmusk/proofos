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

from .ledger import EvidenceLedger
from .verifier import (
    TRUSTED_SOURCES,
    Evidence,
    EvidenceAssessment,
    FailureClass,
    Requirement,
    VerificationResult,
    VerificationStatus,
    verify_completion,
)


class ProvenanceNotDeclarable(ValueError):
    """A caller labelled evidence with a provenance it is not able to grant.

    ``verify_completion`` is a decision function over evidence whose provenance
    has already been established. In the deployed runtime that establishment
    happens at the ingestion boundary, which holds the only observation
    capability and hands the kernel evidence that arrived through a signature it
    verified.

    This façade takes evidence from its caller, which makes it the one entry
    point where a provenance could be typed in rather than earned. Somebody
    writing ``source=EvidenceSource.OBSERVED`` and reading back VERIFIED would
    have proven nothing, and would have used the front door to do it.
    """



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
        """Return a decision. Abstains on insufficient evidence; raises on a
        caller trying to declare its own provenance.

        Those are different failures and are reported differently on purpose.
        Evidence that does not satisfy a requirement is an answer -- ABSTAIN,
        with the reason. Evidence labelled OBSERVED by the party asking for the
        verdict is not an answer, it is a category error, and returning ABSTAIN
        for it would file the caller's mistake alongside "the evidence was not
        good enough" and let them keep believing they had submitted an
        observation.

        ``now`` is injectable so callers can reason about freshness
        deterministically. That is how a three-week-old observation can be
        shown to have expired without waiting three weeks.
        """
        supplied = tuple(evidence)
        self._refuse_declared_provenance(supplied)
        return self._decide(claim, supplied, tuple(requirements), now)


    def verify_recorded(
        self,
        ledger: "EvidenceLedger",
        task_id: str,
        claim: str,
        now: float | None = None,
    ) -> Decision:
        """Judge what a ledger recorded for one task.

        This is the entry point that can return VERIFIED, and the reason is
        structural rather than a policy decision made here. OBSERVED evidence
        only reaches a ledger through a grant that ledger issued, to a collector
        writing under its own identity, for a kind that grant covers. By the
        time it is read back, the provenance has been earned; ``verify`` cannot
        say the same about a list it was handed, which is why it refuses one.

        The requirements come from the ledger too. A caller who could pass
        different requirements than the task was opened with could ask an
        easier question than the one being answered.
        """
        return self._decide(
            claim=claim,
            evidence=tuple(ledger.evidence(task_id)),
            requirements=tuple(ledger.requirements(task_id)),
            now=now,
        )

    def _decide(self, claim: str, evidence: tuple[Evidence, ...],
                requirements: tuple[Requirement | str, ...],
                now: float | None) -> Decision:
        result = verify_completion(
            claim=claim, evidence=evidence, required_kinds=requirements, now=now,
        )
        return Decision(
            status=result.status,
            reason=result.failure,
            explanation=result.reason,
            missing=result.missing,
            evidence=result.assessments,
            raw=result,
        )

    @staticmethod
    def _refuse_declared_provenance(evidence: tuple[Evidence, ...]) -> None:
        """Refuse any provenance the kernel treats as independent.

        Derived from the kernel's own ``TRUSTED_SOURCES`` rather than naming
        OBSERVED here. If a later build decides some other provenance is
        independent, this refusal follows it; a hardcoded check would quietly
        stop covering the thing it was written for.
        """
        declared = [item for item in evidence if item.source in TRUSTED_SOURCES]
        if not declared:
            return
        names = sorted({str(item.source) for item in declared})
        kinds = sorted({item.kind for item in declared})
        raise ProvenanceNotDeclarable(
            f"evidence for {kinds} arrived labelled {names}, and this entry "
            "point cannot accept that. Independent provenance is established "
            "where an observation is made, not where a verdict is requested.\n"
            "  To supply an observation: hold an ObservationCapability, call "
            "record_observation on it, and verify from the EvidenceLedger that "
            "recorded it.\n"
            "  To ask what a self-report is worth: pass it as EXECUTOR and read "
            "the refusal."
        )


__all__ = ["Decision", "ProofOS", "ProvenanceNotDeclarable"]
