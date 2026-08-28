"""Resuming an operation that outlived the process which started it.

This is a railway switch, not a judge. It decides which track an operation may
take next; it never decides whether the operation succeeded. Everything it
returns still has to go through the same verification kernel as a fresh run.

The property worth stating first, because it is the one that would hurt if it
were wrong: **a restart must not repeat the work.** An operation that has
already applied a remediation and is only waiting for someone independent to
confirm it must resume into collection, never back into execution. Getting this
wrong is how an agent orders two laptops, or applies the same production change
twice.

The proof that the action already ran is not taken from the checkpoint. It is
read out of the hash-chained journal, where ``ACTION_EXECUTED`` was written at
the moment it happened and cannot be edited afterwards without breaking the
chain. The checkpoint says where to look; the journal says what occurred.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .agent_catalog import AgentCatalog, CatalogError
from .continuity import (
    MAY_EXECUTE,
    TERMINAL,
    ContinuityError,
    ContinuityFailure,
    ContinuityStore,
    OperationCheckpoint,
    Phase,
    chain_is_intact,
    journal_head,
    policy_digest,
)
from .journal import ExecutionEvent

#: The journal status written when the executor actually did work. Tool calls
#: the runtime declined to run never produce one, which is what makes counting
#: them meaningful.
ACTION_EXECUTED = "ACTION_EXECUTED"


class NextStep(str):
    """What the runtime is permitted to do next. Deliberately a closed set."""


EXECUTE = NextStep("EXECUTE")
COLLECT = NextStep("COLLECT")
VERIFY = NextStep("VERIFY")
NOTHING = NextStep("NOTHING")


@dataclass(frozen=True)
class ResumePlan:
    """The outcome of a resume attempt. Carries no verdict, by construction."""

    checkpoint: OperationCheckpoint
    next_step: NextStep
    action_executions: int
    agent_versions: dict[str, str]
    journal_events: tuple[ExecutionEvent, ...]

    @property
    def may_execute(self) -> bool:
        return self.next_step == EXECUTE

    def as_dict(self) -> dict:
        return {
            "operation_id": self.checkpoint.operation_id,
            "execution_id": self.checkpoint.execution_id,
            "phase": str(self.checkpoint.phase),
            "next_step": str(self.next_step),
            "action_executions": self.action_executions,
            "agent_versions": dict(self.agent_versions),
            "journal_events": len(self.journal_events),
        }


def count_actions(events: Iterable[ExecutionEvent]) -> int:
    """How many times the action actually ran, according to the journal."""
    return sum(1 for event in events if event.status == ACTION_EXECUTED)


def _next_step(phase: Phase) -> NextStep:
    if phase in TERMINAL:
        return NOTHING
    if phase in MAY_EXECUTE:
        return EXECUTE
    if phase is Phase.VERIFYING:
        return VERIFY
    # ACTION_COMPLETE and AWAITING_INDEPENDENT_EVIDENCE both mean the work is
    # done and the only thing missing is someone else's word for it.
    return COLLECT


class OperationResumer:
    """Loads an operation and reports the one step it is allowed to take.

    It holds no ledger, no collector, no signing key and no verification
    capability. There is nothing here that could reach a verdict even if it
    tried.
    """

    def __init__(
        self,
        store: ContinuityStore,
        catalog: AgentCatalog,
        journal_reader,
    ) -> None:
        self._store = store
        self._catalog = catalog
        #: Anything with ``list_execution(execution_id)``. The durable journal
        #: sink already satisfies this.
        self._journal = journal_reader

    def resume(self, operation_id: str) -> ResumePlan:
        checkpoint = self._store.get(operation_id)
        if checkpoint is None:
            raise ContinuityError(
                ContinuityFailure.UNKNOWN_OPERATION,
                f"no operation {operation_id!r}; ProofOS will not invent one",
            )

        self._check_policy(checkpoint)
        events = self._load_journal(checkpoint)
        self._check_binding(checkpoint, events)
        versions = self._resolve_agents(checkpoint)

        executions = count_actions(events)
        step = _next_step(checkpoint.phase)

        # Belt and braces: if the journal says the action ran, no phase may
        # send us back to execution, whatever the checkpoint claims.
        if executions > 0 and step == EXECUTE:
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"{operation_id}: checkpoint phase {checkpoint.phase} would "
                f"re-execute, but the journal records {executions} completed "
                "action(s)",
            )

        return ResumePlan(
            checkpoint=checkpoint,
            next_step=step,
            action_executions=executions,
            agent_versions=versions,
            journal_events=events,
        )

    # -- checks -------------------------------------------------------------

    def _check_policy(self, checkpoint: OperationCheckpoint) -> None:
        expected = policy_digest(
            checkpoint.requirements, checkpoint.assigned_agent_versions
        )
        if expected != checkpoint.policy_digest:
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"{checkpoint.operation_id}: requirements or agent assignment "
                "do not match the recorded policy digest",
            )

    def _load_journal(
        self, checkpoint: OperationCheckpoint
    ) -> tuple[ExecutionEvent, ...]:
        try:
            events = tuple(self._journal.list_execution(checkpoint.execution_id))
        except Exception as exc:  # noqa: BLE001 - an unreadable journal is not an empty one
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"journal unreadable for {checkpoint.execution_id}: "
                f"{type(exc).__name__}",
            ) from exc

        intact, problems = chain_is_intact(events)
        if not intact:
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"{checkpoint.execution_id}: audit chain is broken: "
                f"{'; '.join(problems)}",
            )
        return events

    def _check_binding(
        self, checkpoint: OperationCheckpoint, events: tuple[ExecutionEvent, ...]
    ) -> None:
        """The checkpoint must name a point the journal actually contains."""
        head_sequence, head_hash = journal_head(events)

        if checkpoint.last_journal_sequence > head_sequence:
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"{checkpoint.operation_id}: checkpoint is at sequence "
                f"{checkpoint.last_journal_sequence} but the journal ends at "
                f"{head_sequence}; the trail has been truncated or replaced",
            )

        recorded = {event.sequence: event.content_hash for event in events}
        expected = recorded.get(checkpoint.last_journal_sequence)
        if checkpoint.last_journal_sequence >= 0 and expected is None:
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"{checkpoint.operation_id}: journal has no event at sequence "
                f"{checkpoint.last_journal_sequence}",
            )
        if expected is not None and expected != checkpoint.last_journal_hash:
            raise ContinuityError(
                ContinuityFailure.CONTINUITY_INTEGRITY_ERROR,
                f"{checkpoint.operation_id}: event "
                f"{checkpoint.last_journal_sequence} does not match the hash "
                "recorded when the checkpoint was written",
            )
        # head_hash is read above so a future check can compare it; the
        # sequence and per-event hash together already pin the position.
        del head_hash

    def _resolve_agents(self, checkpoint: OperationCheckpoint) -> dict[str, str]:
        """Every pinned version must still exist, at exactly that version.

        A retired agent is an explicit failure. Resolving to whatever is
        current would mean an operation quietly finishing under an agent nobody
        assigned to it, weeks after the assignment was made.
        """
        resolved: dict[str, str] = {}
        for agent_id, version in sorted(checkpoint.assigned_agent_versions.items()):
            try:
                card = self._catalog.require(agent_id, version)
            except CatalogError as exc:
                raise ContinuityError(
                    ContinuityFailure.AGENT_VERSION_UNAVAILABLE, str(exc)
                ) from exc
            if card.version != version:
                raise ContinuityError(
                    ContinuityFailure.AGENT_VERSION_MISMATCH,
                    f"{agent_id}: pinned {version}, catalog offered "
                    f"{card.version}",
                )
            resolved[agent_id] = card.version
        return resolved


__all__ = [
    "ACTION_EXECUTED",
    "COLLECT",
    "EXECUTE",
    "NOTHING",
    "NextStep",
    "OperationResumer",
    "ResumePlan",
    "VERIFY",
    "count_actions",
]
