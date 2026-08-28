"""A discovery view over the sealed authority registry.

Two things are deliberately kept apart.

``AgentRegistry`` is the security authority: what a component may hold, and
which tools it may be handed. It is sealed at startup and nothing here can
widen it.

``AgentCatalog`` is how a person finds an agent -- who owns it, what it is for,
what data it touches, whether it is still in service. That is organisational
metadata, and organisational metadata must never become permission. So a card
is *validated against* its registry record rather than being a second source of
truth: a card that claims a capability the record does not grant is refused at
construction, not at use.

The distinction matters more than it might look. A catalog is the kind of thing
that gets edited by whoever is on call, and the moment an edit there can grant a
tool, the registry has stopped being the authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable, Iterator

from .registry import AgentRecord, AgentRegistry, Role, Runtime


class Lifecycle(StrEnum):
    """Whether an agent may be assigned to new work."""

    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class SecurityClass(StrEnum):
    """How much damage this agent could do if it misbehaved."""

    OBSERVER = "OBSERVER"
    ACTOR = "ACTOR"
    ADJUDICATOR = "ADJUDICATOR"
    COORDINATOR = "COORDINATOR"


class CatalogError(ValueError):
    """Raised when a card disagrees with the authority it claims to describe."""


@dataclass(frozen=True)
class AgentCard:
    """How an agent is discovered. Never how it is authorised."""

    agent_id: str
    version: str
    role: Role
    owner: str
    purpose: str
    capabilities: frozenset[str]
    tools: tuple[str, ...]
    tool_scope: str
    data_scope: str
    runtime: Runtime
    security_class: SecurityClass
    lifecycle: Lifecycle = Lifecycle.ACTIVE

    @property
    def identity(self) -> tuple[str, str]:
        return (self.agent_id, self.version)

    @property
    def assignable(self) -> bool:
        """Only ACTIVE agents may be picked for new work.

        DEPRECATED agents stay assignable to operations that already pinned
        them -- retiring an agent must not strand an incident that is mid
        flight -- but they are not offered for anything new.
        """
        return self.lifecycle is Lifecycle.ACTIVE

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "version": self.version,
            "role": str(self.role),
            "owner": self.owner,
            "purpose": self.purpose,
            "capabilities": sorted(self.capabilities),
            "tools": list(self.tools),
            "tool_scope": self.tool_scope,
            "data_scope": self.data_scope,
            "runtime": str(self.runtime),
            "security_class": str(self.security_class),
            "lifecycle": str(self.lifecycle),
        }


def _validate(card: AgentCard, record: AgentRecord) -> None:
    """Refuse a card that describes an authority the registry did not grant."""
    if card.version != record.version:
        raise CatalogError(
            f"{card.agent_id}: card version {card.version!r} does not match "
            f"registered version {record.version!r}"
        )
    if card.role is not record.role:
        raise CatalogError(
            f"{card.agent_id}: card role {card.role} does not match "
            f"registered role {record.role}"
        )
    extra_caps = set(card.capabilities) - set(record.capabilities)
    if extra_caps:
        raise CatalogError(
            f"{card.agent_id}: card claims capabilities the registry does not "
            f"grant: {sorted(extra_caps)}"
        )
    extra_tools = set(card.tools) - set(record.tools)
    if extra_tools:
        raise CatalogError(
            f"{card.agent_id}: card claims tools the registry does not permit: "
            f"{sorted(extra_tools)}"
        )


@dataclass(frozen=True)
class AgentCatalog:
    """Versioned, filterable discovery over a sealed registry."""

    registry: AgentRegistry
    _cards: dict[tuple[str, str], AgentCard] = field(default_factory=dict)

    @classmethod
    def build(
        cls, registry: AgentRegistry, cards: Iterable[AgentCard]
    ) -> "AgentCatalog":
        known = {record.agent_id: record for record in registry.records()}
        index: dict[tuple[str, str], AgentCard] = {}

        for card in cards:
            record = known.get(card.agent_id)
            if record is None:
                raise CatalogError(
                    f"{card.agent_id!r} is not a registered agent; the catalog "
                    "cannot describe an authority that does not exist"
                )
            _validate(card, record)
            if card.identity in index:
                raise CatalogError(
                    f"duplicate catalog entry for {card.agent_id} {card.version}"
                )
            index[card.identity] = card

        return cls(registry=registry, _cards=index)

    # -- discovery ----------------------------------------------------------

    def __iter__(self) -> Iterator[AgentCard]:
        return iter(sorted(self._cards.values(), key=lambda c: c.identity))

    def __len__(self) -> int:
        return len(self._cards)

    def get(self, agent_id: str, version: str) -> AgentCard | None:
        return self._cards.get((agent_id, version))

    def require(self, agent_id: str, version: str) -> AgentCard:
        """Resolve an exact pinned identity, or refuse.

        Never falls back to another version. A silent upgrade is how a
        long-running operation ends up run by an agent nobody assigned to it.
        """
        card = self.get(agent_id, version)
        if card is None:
            raise CatalogError(
                f"no catalog entry for {agent_id} {version}; ProofOS will not "
                "substitute a different version"
            )
        return card

    def find(
        self,
        *,
        role: Role | None = None,
        capability: str | None = None,
        lifecycle: Lifecycle | None = None,
        data_scope: str | None = None,
        tool_scope: str | None = None,
        assignable_only: bool = False,
    ) -> tuple[AgentCard, ...]:
        results = []
        for card in self:
            if role is not None and card.role is not role:
                continue
            if capability is not None and capability not in card.capabilities:
                continue
            if lifecycle is not None and card.lifecycle is not lifecycle:
                continue
            if data_scope is not None and card.data_scope != data_scope:
                continue
            if tool_scope is not None and card.tool_scope != tool_scope:
                continue
            if assignable_only and not card.assignable:
                continue
            results.append(card)
        return tuple(results)

    def as_dict(self) -> dict:
        return {"agents": [card.as_dict() for card in self]}


#: The fleet as deployed. Owners and purposes are descriptive; the capabilities
#: and tools on every card are checked against the sealed registry at build
#: time, so this block cannot quietly hand anyone a new permission.
def default_catalog(registry: AgentRegistry | None = None) -> AgentCatalog:
    from .registry import default_registry

    registry = registry or default_registry()
    known = {record.agent_id: record for record in registry.records()}

    described = {
        "orchestrator-v1": (
            "platform-reliability",
            "Routes work, budgets attempts, and owns every state transition.",
            "none",
            "execution-control-plane",
            SecurityClass.COORDINATOR,
        ),
        "planner-v1": (
            "platform-reliability",
            "Proposes steps and what would prove them. Enacts nothing.",
            "none",
            "task-description",
            SecurityClass.OBSERVER,
        ),
        "executor-v1": (
            "operations-remediation",
            "Carries out the assigned remediation and reports what it did.",
            "perform_action",
            "target-system",
            SecurityClass.ACTOR,
        ),
        "collector-http-v1": (
            "platform-observability",
            "Probes a protected endpoint under its own identity and signs what it saw.",
            "probe_http",
            "runtime-health",
            SecurityClass.OBSERVER,
        ),
        "collector-ci-v1": (
            "platform-observability",
            "Reports recorded test results as independent evidence.",
            "none",
            "build-results",
            SecurityClass.OBSERVER,
        ),
        "verifier-v1": (
            "governance",
            "Judges claims against evidence. Cannot act and cannot observe.",
            "verify_task_completion",
            "evidence-ledger",
            SecurityClass.ADJUDICATOR,
        ),
    }

    cards = []
    for agent_id, (owner, purpose, tool_scope, data_scope, klass) in described.items():
        record = known[agent_id]
        cards.append(
            AgentCard(
                agent_id=record.agent_id,
                version=record.version,
                role=record.role,
                owner=owner,
                purpose=purpose,
                capabilities=frozenset(record.capabilities),
                tools=tuple(record.tools),
                tool_scope=tool_scope,
                data_scope=data_scope,
                runtime=record.runtime,
                security_class=klass,
            )
        )
    return AgentCatalog.build(registry, cards)


__all__ = [
    "AgentCard",
    "AgentCatalog",
    "CatalogError",
    "Lifecycle",
    "SecurityClass",
    "default_catalog",
]
