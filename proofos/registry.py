"""Agent registry and authority validation.

The registry is not decorative metadata. It is checked at startup, and an
illegal capability or tool assignment stops the process rather than being
quietly downgraded. A system that boots with a misconfigured executor is worse
than one that refuses to boot, because the misconfiguration is invisible.

Two layers of checking, deliberately overlapping:

* a per-role allowlist -- a role may hold nothing outside its remit, so a new
  capability added later is denied by default rather than inherited by
  everyone;
* named invariants -- the specific combinations that would let an actor certify
  its own work, spelled out so the reason each is forbidden is legible.

The registry can be sealed. Once an execution begins, its authority model must
not change underneath it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable, Mapping

from .capabilities import Capability
from .failures import AgentIdentityInvalid, ToolNotAllowed


class Role(StrEnum):
    ORCHESTRATOR = "orchestrator"
    PLANNER = "planner"
    EXECUTOR = "executor"
    COLLECTOR = "collector"
    VERIFIER = "verifier"


class Runtime(StrEnum):
    DETERMINISTIC = "deterministic"
    ADK_GEMINI = "adk-gemini"


#: What each role may hold. Anything outside its set is refused at startup.
ROLE_CAPABILITIES: Mapping[Role, frozenset[str]] = {
    Role.ORCHESTRATOR: frozenset(
        {Capability.ORCHESTRATE, Capability.REQUEST_RECOVERY, Capability.APPEND_AUDIT}
    ),
    Role.PLANNER: frozenset({Capability.PLAN, Capability.APPEND_AUDIT}),
    Role.EXECUTOR: frozenset(
        {Capability.EXECUTE, Capability.CLAIM, Capability.APPEND_AUDIT}
    ),
    Role.COLLECTOR: frozenset(
        {
            Capability.OBSERVE,
            Capability.WRITE_OBSERVED_EVIDENCE,
            Capability.APPEND_AUDIT,
        }
    ),
    Role.VERIFIER: frozenset(
        {Capability.READ_EVIDENCE, Capability.VERIFY, Capability.APPEND_AUDIT}
    ),
}

#: What each role may be handed as a tool. The verification tool in particular
#: belongs to exactly one role.
ROLE_TOOLS: Mapping[Role, frozenset[str]] = {
    Role.ORCHESTRATOR: frozenset(),
    Role.PLANNER: frozenset(),
    Role.EXECUTOR: frozenset({"perform_action"}),
    Role.COLLECTOR: frozenset({"probe_http"}),
    Role.VERIFIER: frozenset({"verify_task_completion"}),
}


@dataclass(frozen=True)
class Invariant:
    """One forbidden capability combination, with the reason it is forbidden."""

    role: Role
    forbidden: frozenset[str]
    because: str

    def check(self, record: "AgentRecord") -> str | None:
        if record.role is not self.role:
            return None
        overlap = record.capabilities & self.forbidden
        if not overlap:
            return None
        return (
            f"{record.agent_id} ({self.role}) may not hold "
            f"{sorted(overlap)}: {self.because}"
        )


#: The combinations that would let an actor certify its own work.
INVARIANTS: tuple[Invariant, ...] = (
    Invariant(
        Role.EXECUTOR,
        frozenset({Capability.WRITE_OBSERVED_EVIDENCE, Capability.OBSERVE}),
        "the actor being judged must not produce the evidence used to judge it",
    ),
    Invariant(
        Role.EXECUTOR,
        frozenset({Capability.VERIFY, Capability.READ_EVIDENCE}),
        "an executor that can reach the verdict can certify its own work",
    ),
    Invariant(
        Role.COLLECTOR,
        frozenset({Capability.VERIFY}),
        "deciding whether its own observation completes the task is not the "
        "collector's judgement to make",
    ),
    Invariant(
        Role.COLLECTOR,
        frozenset({Capability.EXECUTE, Capability.CLAIM}),
        "a collector that performed the work would be observing itself",
    ),
    Invariant(
        Role.VERIFIER,
        frozenset({Capability.EXECUTE, Capability.CLAIM}),
        "a verifier that can act would be judging its own action",
    ),
    Invariant(
        Role.VERIFIER,
        frozenset({Capability.WRITE_OBSERVED_EVIDENCE, Capability.OBSERVE}),
        "a verifier that can collect evidence can invent the evidence it needs",
    ),
    Invariant(
        Role.PLANNER,
        frozenset(
            {
                Capability.WRITE_OBSERVED_EVIDENCE,
                Capability.OBSERVE,
                Capability.CLAIM,
                Capability.VERIFY,
            }
        ),
        "planning confers no authority over evidence or verdicts",
    ),
    Invariant(
        Role.ORCHESTRATOR,
        frozenset({Capability.WRITE_OBSERVED_EVIDENCE, Capability.OBSERVE}),
        "an orchestrator that can forge observations can force any outcome",
    ),
    Invariant(
        Role.ORCHESTRATOR,
        frozenset({Capability.VERIFY}),
        "routing must not include reaching the verdict it routes toward",
    ),
)


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    role: Role
    capabilities: frozenset[str]
    tools: tuple[str, ...] = ()
    runtime: Runtime = Runtime.DETERMINISTIC
    version: str = "v1"


class AuthorityViolation(RuntimeError):
    """Raised at startup when the configured authority model is unsafe."""

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems = tuple(problems)
        joined = "\n  - ".join(self.problems)
        super().__init__(f"illegal authority configuration:\n  - {joined}")


class AgentRegistry:
    """Who exists, what they may hold, and what they may be handed."""

    def __init__(self) -> None:
        self._records: dict[str, AgentRecord] = {}
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    def register(self, record: AgentRecord) -> AgentRecord:
        if self._sealed:
            raise AuthorityViolation(
                [
                    f"cannot register {record.agent_id}: the registry is sealed. "
                    "An execution's authority model must not change underneath it."
                ]
            )
        if record.agent_id in self._records:
            raise AuthorityViolation(
                [f"duplicate agent_id {record.agent_id!r}"]
            )
        self._records[record.agent_id] = record
        return record

    def seal(self) -> "AgentRegistry":
        """Validate, then freeze. Registration after this point is refused."""
        self.validate()
        self._sealed = True
        return self

    def get(self, agent_id: str) -> AgentRecord:
        try:
            return self._records[agent_id]
        except KeyError:
            raise AgentIdentityInvalid(f"unknown agent_id {agent_id!r}") from None

    def records(self) -> tuple[AgentRecord, ...]:
        return tuple(self._records.values())

    def by_role(self, role: Role) -> tuple[AgentRecord, ...]:
        return tuple(r for r in self._records.values() if r.role is role)

    def has_capability(self, agent_id: str, capability: str) -> bool:
        return capability in self.get(agent_id).capabilities

    def validate(self) -> None:
        """Raise AuthorityViolation if any configured authority is illegal."""
        problems: list[str] = []

        for record in self._records.values():
            problems.extend(self._validate_record(record))

        if problems:
            raise AuthorityViolation(problems)

    def _validate_record(self, record: AgentRecord) -> list[str]:
        problems: list[str] = []

        unknown = record.capabilities - Capability.ALL
        if unknown:
            problems.append(
                f"{record.agent_id} declares unknown capabilities {sorted(unknown)}"
            )

        permitted = ROLE_CAPABILITIES.get(record.role, frozenset())
        outside = record.capabilities - permitted - unknown
        if outside:
            problems.append(
                f"{record.agent_id} ({record.role}) holds {sorted(outside)}, "
                f"outside the {record.role} remit {sorted(permitted)}"
            )

        for invariant in INVARIANTS:
            problem = invariant.check(record)
            if problem:
                problems.append(problem)

        allowed_tools = ROLE_TOOLS.get(record.role, frozenset())
        stray = set(record.tools) - allowed_tools
        if stray:
            problems.append(
                f"{record.agent_id} ({record.role}) is configured with tools "
                f"{sorted(stray)}, permitted: {sorted(allowed_tools)}"
            )

        return problems

    def require_tool(self, agent_id: str, tool_name: str) -> None:
        """Raise ToolNotAllowed unless this agent is configured with the tool."""
        record = self.get(agent_id)
        if tool_name not in record.tools:
            raise ToolNotAllowed(
                f"agent {agent_id!r} ({record.role}) may not use tool "
                f"{tool_name!r}; configured tools: {sorted(record.tools)}"
            )


# -- the default ProofOS fleet -------------------------------------------------

ORCHESTRATOR_ID = "orchestrator-v1"
PLANNER_ID = "planner-v1"
EXECUTOR_ID = "executor-v1"
COLLECTOR_ID = "collector-http-v1"
COLLECTOR_CI_ID = "collector-ci-v1"
VERIFIER_ID = "verifier-v1"


def default_registry() -> AgentRegistry:
    """The fleet, sealed and validated.

    Note what the executor does *not* hold: no OBSERVE, no
    WRITE_OBSERVED_EVIDENCE, no READ_EVIDENCE, no VERIFY.
    """
    registry = AgentRegistry()
    registry.register(
        AgentRecord(
            agent_id=ORCHESTRATOR_ID,
            role=Role.ORCHESTRATOR,
            capabilities=frozenset(
                {
                    Capability.ORCHESTRATE,
                    Capability.REQUEST_RECOVERY,
                    Capability.APPEND_AUDIT,
                }
            ),
        )
    )
    registry.register(
        AgentRecord(
            agent_id=PLANNER_ID,
            role=Role.PLANNER,
            capabilities=frozenset({Capability.PLAN, Capability.APPEND_AUDIT}),
            runtime=Runtime.ADK_GEMINI,
        )
    )
    registry.register(
        AgentRecord(
            agent_id=EXECUTOR_ID,
            role=Role.EXECUTOR,
            capabilities=frozenset(
                {Capability.EXECUTE, Capability.CLAIM, Capability.APPEND_AUDIT}
            ),
            tools=("perform_action",),
            runtime=Runtime.ADK_GEMINI,
        )
    )
    registry.register(
        AgentRecord(
            agent_id=COLLECTOR_ID,
            role=Role.COLLECTOR,
            capabilities=frozenset(
                {
                    Capability.OBSERVE,
                    Capability.WRITE_OBSERVED_EVIDENCE,
                    Capability.APPEND_AUDIT,
                }
            ),
            tools=("probe_http",),
            # A network probe has no cognition to add. Making it an LLM would
            # add an untrusted step to the one path that must stay observable.
            runtime=Runtime.DETERMINISTIC,
        )
    )
    registry.register(
        AgentRecord(
            agent_id=COLLECTOR_CI_ID,
            role=Role.COLLECTOR,
            capabilities=frozenset(
                {
                    Capability.OBSERVE,
                    Capability.WRITE_OBSERVED_EVIDENCE,
                    Capability.APPEND_AUDIT,
                }
            ),
            tools=(),
            runtime=Runtime.DETERMINISTIC,
        )
    )
    registry.register(
        AgentRecord(
            agent_id=VERIFIER_ID,
            role=Role.VERIFIER,
            capabilities=frozenset(
                {Capability.READ_EVIDENCE, Capability.VERIFY, Capability.APPEND_AUDIT}
            ),
            tools=("verify_task_completion",),
            runtime=Runtime.ADK_GEMINI,
        )
    )
    return registry.seal()
