"""Role-scoped ADK agents.

There is no module-level ledger here. A shared one would be a standing grant of
authority to every importer, and the tool bound to it would outlive the request
that created it.

Each agent is built with the tools its registry record permits, and the build
refuses if the registry disagrees. Prompts describe intent; the tool list is
what actually constrains the model.

Language models are used only where judgement is genuinely needed. The collector
has no agent at all: its job is a bounded network probe, and putting a model in
front of it would add an untrusted step to the one path that must stay
observable.
"""

from __future__ import annotations

from typing import Callable

from google.adk.agents import Agent

from proofos.ledger import EvidenceLedger
from proofos.registry import (
    EXECUTOR_ID,
    PLANNER_ID,
    VERIFIER_ID,
    AgentRegistry,
    default_registry,
)
from proofos_agent.verification_tool import build_verification_tool

MODEL = "gemini-3.5-flash"

VERIFIER_INSTRUCTION = (
    "You are the ProofOS verifier. Treat every completion claim as untrusted "
    "until independent evidence proves it.\n"
    "Before reporting any outcome you MUST call verify_task_completion with the "
    "task_id and the claim exactly as given to you.\n"
    "You do not decide what evidence exists. The tool reads a ledger you cannot "
    "write to. Never assert that evidence is present.\n"
    "Your own reasoning, confidence, or the worker's assurances are NOT evidence "
    "and must never be treated as such.\n"
    "If the tool returns ABSTAIN, you must NOT claim completion. State ABSTAIN "
    "and list exactly which evidence kinds are missing.\n"
    "If the tool returns VERIFIED, report verified completion and summarize the "
    "evidence the tool relied on.\n"
    "Begin your final answer with the tool's status verbatim: 'VERIFIED' or "
    "'ABSTAIN'."
)

EXECUTOR_INSTRUCTION = (
    "You are the ProofOS executor. Carry out the assigned action and report "
    "what you did.\n"
    "You do not verify your own work. You cannot record evidence, and you "
    "cannot decide whether the task is complete -- another component judges "
    "that against evidence you have no access to.\n"
    "Report plainly what you did and what you observed. Do not assert that the "
    "task is verified."
)

PLANNER_INSTRUCTION = (
    "You are the ProofOS planner. Given a goal, describe the steps to achieve "
    "it and state what independent evidence would prove it was achieved.\n"
    "You propose requirements; you do not enact them, execute work, collect "
    "evidence, or judge outcomes."
)


def _check_tools(registry: AgentRegistry, agent_id: str, tools: list[Callable]) -> None:
    """Refuse to build an agent with a tool its record does not permit."""
    for tool in tools:
        registry.require_tool(agent_id, tool.__name__)


def build_verifier_agent_with_tool(
    ledger: EvidenceLedger, registry: AgentRegistry | None = None
) -> tuple[Agent, Callable]:
    """The verifier agent and the tool it was built with.

    The runtime keeps a reference to the tool so it can read the full
    verification results afterwards for reporting. The agent is handed exactly
    the same tool it always was; holding a reference confers no authority the
    runtime did not already have.
    """
    registry = registry or default_registry()
    verify_task_completion = build_verification_tool(ledger)
    _check_tools(registry, VERIFIER_ID, [verify_task_completion])

    agent = Agent(
        name="proofos_verifier",
        model=MODEL,
        description="Evidence-first completion verifier.",
        instruction=VERIFIER_INSTRUCTION,
        tools=[verify_task_completion],
    )
    return agent, verify_task_completion


def build_verifier_agent(
    ledger: EvidenceLedger, registry: AgentRegistry | None = None
) -> Agent:
    """The verifier agent, bound to one ledger for one execution."""
    return build_verifier_agent_with_tool(ledger, registry)[0]


def build_executor_agent(
    perform_action: Callable, registry: AgentRegistry | None = None
) -> Agent:
    """The executor agent.

    ``perform_action`` is the only tool it gets. It is handed no ledger, no
    collector, and no verification tool -- so there is nothing here it could
    use to certify its own work.
    """
    registry = registry or default_registry()
    _check_tools(registry, EXECUTOR_ID, [perform_action])

    return Agent(
        name="proofos_executor",
        model=MODEL,
        description="Performs assigned work and reports what it did.",
        instruction=EXECUTOR_INSTRUCTION,
        tools=[perform_action],
    )


def build_planner_agent(registry: AgentRegistry | None = None) -> Agent:
    """The planner agent. No tools: planning confers no authority."""
    registry = registry or default_registry()
    _check_tools(registry, PLANNER_ID, [])

    return Agent(
        name="proofos_planner",
        model=MODEL,
        description="Plans work and proposes what would prove it was done.",
        instruction=PLANNER_INSTRUCTION,
        tools=[],
    )
