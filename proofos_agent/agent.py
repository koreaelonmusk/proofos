from __future__ import annotations

from google.adk.agents import Agent

from proofos.ledger import EvidenceLedger, UnknownTaskError
from proofos.verifier import FailureClass, VerificationStatus, verify_completion

MODEL = "gemini-3.5-flash"

# The ledger is owned by the runtime. Collectors write to it out of band; the
# model can only reference a task id.
LEDGER = EvidenceLedger()


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
        required = LEDGER.requirements(task_id)
        evidence = LEDGER.evidence(task_id)
    except UnknownTaskError:
        return {
            "status": VerificationStatus.ABSTAIN.value,
            "reason": f"No verification task is registered for task_id={task_id!r}.",
            "missing": [],
            "failure": FailureClass.MALFORMED_INPUT.value,
        }

    result = verify_completion(
        claim=claim,
        evidence=evidence,
        required_kinds=required,
    )

    return {
        "status": result.status.value,
        "reason": result.reason,
        "missing": list(result.missing),
        "failure": result.failure.value,
    }


root_agent = Agent(
    name="proofos_verifier",
    model=MODEL,
    description="Evidence-first autonomous completion verifier.",
    instruction=(
        "You are ProofOS. Treat every completion claim as untrusted until "
        "independent evidence proves it.\n"
        "Before reporting any outcome you MUST call verify_task_completion with "
        "the task_id and the claim exactly as given to you.\n"
        "You do not decide what evidence exists. The tool reads evidence from a "
        "ledger you cannot write to. Never assert that evidence is present.\n"
        "Your own reasoning, confidence, or the worker's assurances are NOT "
        "evidence and must never be treated as such.\n"
        "If the tool returns ABSTAIN, you must NOT claim completion. State "
        "ABSTAIN and list exactly which evidence kinds are missing.\n"
        "If the tool returns VERIFIED, report verified completion and summarize "
        "the evidence the tool relied on.\n"
        "Begin your final answer with the tool's status verbatim: "
        "'VERIFIED' or 'ABSTAIN'."
    ),
    tools=[verify_task_completion],
)
