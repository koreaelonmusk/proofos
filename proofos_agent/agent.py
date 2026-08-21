from __future__ import annotations

from google.adk.agents import Agent

from proofos.ledger import EvidenceLedger
from proofos_agent.verification_tool import build_verification_tool

MODEL = "gemini-3.5-flash"

# The ledger is owned by the runtime. Collectors write to it out of band; the
# model can only reference a task id.
LEDGER = EvidenceLedger()

verify_task_completion = build_verification_tool(LEDGER)

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
