"""The verification tool, bound to a specific evidence ledger.

The tool is built as a closure over a ledger rather than reading a module
global, so each execution can own its evidence. A shared global would let one
request observe another request's evidence, which is a correctness bug and a
cross-tenant leak in anything multi-user.

The signature is the trust boundary and is deliberately minimal: a caller may
name a task and state a claim. It cannot declare what counts as proof, assert
that proof exists, or supply its own verdict. Whatever the model writes into
``claim`` is an assertion under scrutiny, never an input to the decision.
"""

from __future__ import annotations

from typing import Callable

from proofos.ledger import EvidenceLedger, EvidenceTamperedError, UnknownTaskError
from proofos.verifier import (
    FailureClass,
    VerificationResult,
    VerificationStatus,
    verify_completion,
)


def build_verification_tool(ledger: EvidenceLedger) -> Callable[[str, str], dict]:
    """Return a verification tool that reads only from ``ledger``.

    Each full ``VerificationResult`` is kept on the returned function as
    ``.results``, in call order. That list is a runtime-owned side channel for
    reporting: it lets the service explain which evidence the verifier accepted
    without the presentation layer re-deriving trust rules. It deliberately
    does not travel back to the model -- the dict below is unchanged, so
    nothing about reporting alters what the verifier is asked or answers.
    """
    results: list[VerificationResult] = []

    def verify_task_completion(task_id: str, claim: str) -> dict:
        """Verify a completion claim for a task against independently collected evidence.

        Args:
            task_id: Identifier of the task being verified.
            claim: The completion claim being made about that task.

        Returns:
            A verification decision. The caller cannot influence which evidence
            exists; evidence is read from the runtime-owned ledger.
        """
        try:
            required = ledger.requirements(task_id)
            evidence = ledger.evidence(task_id)
        except UnknownTaskError:
            return {
                "status": VerificationStatus.ABSTAIN.value,
                "reason": f"No verification task is registered for task_id={task_id!r}.",
                "missing": [],
                "failure": FailureClass.MALFORMED_INPUT.value,
            }
        except EvidenceTamperedError:
            return {
                "status": VerificationStatus.ABSTAIN.value,
                "reason": "Stored evidence failed its integrity check.",
                "missing": [],
                "failure": FailureClass.EVIDENCE_TAMPERED.value,
            }

        result = verify_completion(
            claim=claim,
            evidence=evidence,
            required_kinds=required,
        )

        results.append(result)
        return {
            "status": result.status.value,
            "reason": result.reason,
            "missing": list(result.missing),
            "failure": result.failure.value,
        }

    verify_task_completion.results = results  # type: ignore[attr-defined]
    return verify_task_completion
