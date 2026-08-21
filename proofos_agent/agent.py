from google.adk.agents import Agent

from proofos.verifier import Evidence, verify_completion


def verify_task_completion(
    claim: str,
    evidence_summary: str,
    has_test_evidence: bool,
    has_runtime_evidence: bool,
) -> dict:
    """Verify a completion claim against independent test/runtime evidence."""
    evidence = (
        Evidence(
            kind="tests",
            value=evidence_summary if has_test_evidence else "",
            valid=has_test_evidence,
        ),
        Evidence(
            kind="runtime",
            value=evidence_summary if has_runtime_evidence else "",
            valid=has_runtime_evidence,
        ),
    )

    result = verify_completion(
        claim=claim,
        evidence=evidence,
        required_kinds=("tests", "runtime"),
    )

    return {
        "status": result.status.value,
        "reason": result.reason,
        "missing": list(result.missing),
    }


root_agent = Agent(
    name="proofos_verifier",
    model="gemini-3.5-flash",
    description="Evidence-first autonomous completion verifier.",
    instruction=(
        "You are ProofOS. Treat every completion claim as untrusted until "
        "independent evidence proves it. Before reporting success, call "
        "verify_task_completion. If the tool returns ABSTAIN, do not claim "
        "completion and explicitly report the missing evidence. If it returns "
        "VERIFIED, report verified completion and summarize the evidence."
    ),
    tools=[verify_task_completion],
)
