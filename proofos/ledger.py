from __future__ import annotations

from dataclasses import dataclass, field

from .failures import CapabilityDenied
from .verifier import Evidence, EvidenceSource, Requirement


class UnknownTaskError(KeyError):
    """Raised when a caller references a task the runtime never opened."""


class EvidenceTamperedError(ValueError):
    """Raised when a stored record no longer matches its own content hash."""


class ObservationGrant:
    """Proof that its holder was authorised to write OBSERVED evidence.

    A grant cannot be constructed usefully by hand: it carries a reference to
    the private marker object of the ledger that issued it, and the ledger
    checks that marker by identity. Grants are issued during wiring and the
    ledger is then sealed, so reaching the ledger later does not let anyone mint
    themselves a new one.
    """

    __slots__ = ("_issuer", "collector_id", "kinds")

    def __init__(self, issuer: object, collector_id: str, kinds: frozenset[str]):
        self._issuer = issuer
        self.collector_id = collector_id
        self.kinds = kinds


@dataclass
class _TaskRecord:
    required_kinds: tuple[Requirement, ...]
    evidence: list[Evidence] = field(default_factory=list)


class EvidenceLedger:
    """Runtime-owned store of verification requirements and collected evidence.

    This is the trust boundary. Requirements and evidence are written only by
    the runtime and its collectors -- never by the model under scrutiny. The
    agent can reference a task by id, but it cannot declare what counts as
    proof, nor assert that proof exists.

    Writing OBSERVED evidence additionally requires a grant. Reaching this
    object is therefore not enough to forge an observation: you need a grant,
    grants are issued only during wiring, and after ``seal()`` no more can be
    minted.

    The limit of this is worth stating plainly. Code running inside the same
    interpreter can still reach a grant by introspection if it holds a
    reference to something that holds one. What this prevents is a component
    writing evidence it was never given authority for -- by accident, by
    refactor, or by an agent whose only reach is its declared tools. Genuine
    isolation against arbitrary in-process code requires process separation.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, _TaskRecord] = {}
        self._marker = object()
        self._sealed = False

    # -- authority ---------------------------------------------------------

    def grant_observation(
        self, collector_id: str, kinds: tuple[str, ...]
    ) -> ObservationGrant:
        """Issue the authority to write OBSERVED evidence of certain kinds."""
        if self._sealed:
            raise CapabilityDenied(
                collector_id,
                "obtain a new observation grant",
                "the ledger is sealed; authority is fixed at wiring time",
            )
        return ObservationGrant(self._marker, collector_id, frozenset(kinds))

    def seal(self) -> "EvidenceLedger":
        """Freeze the set of collectors. No further grants may be issued."""
        self._sealed = True
        return self

    @property
    def sealed(self) -> bool:
        return self._sealed

    # -- writing -----------------------------------------------------------

    def record(
        self,
        task_id: str,
        evidence: Evidence,
        grant: ObservationGrant | None = None,
    ) -> None:
        """Attach one collected observation or self-report to a task.

        OBSERVED evidence requires a matching grant. Anything else -- an
        executor's self-report, a model's assertion -- needs none, because it
        can never satisfy a requirement anyway.
        """
        if evidence.source is EvidenceSource.OBSERVED:
            self._check_grant(evidence, grant)
        self._require(task_id).evidence.append(evidence)

    def _check_grant(
        self, evidence: Evidence, grant: ObservationGrant | None
    ) -> None:
        who = evidence.collector or "unknown"
        if grant is None:
            raise CapabilityDenied(
                who,
                f"write OBSERVED {evidence.kind!r} evidence",
                "no observation grant supplied",
            )
        if getattr(grant, "_issuer", None) is not self._marker:
            raise CapabilityDenied(
                who,
                f"write OBSERVED {evidence.kind!r} evidence",
                "observation grant was not issued by this ledger",
            )
        if evidence.kind not in grant.kinds:
            raise CapabilityDenied(
                grant.collector_id,
                f"write OBSERVED {evidence.kind!r} evidence",
                f"grant covers {sorted(grant.kinds)}",
            )
        if evidence.collector != grant.collector_id:
            raise CapabilityDenied(
                grant.collector_id,
                f"write evidence attributed to {evidence.collector!r}",
                "a collector may only write under its own identity",
            )

    def open_task(self, task_id: str, required_kinds: tuple[Requirement, ...]) -> None:
        self._tasks[task_id] = _TaskRecord(required_kinds=tuple(required_kinds))

    # -- reading -----------------------------------------------------------

    def requirements(self, task_id: str) -> tuple[Requirement, ...]:
        return self._require(task_id).required_kinds

    def evidence(self, task_id: str) -> tuple[Evidence, ...]:
        """Return the task's evidence, refusing records that were mutated.

        In process this cannot fire, because Evidence is frozen. It exists so
        the same contract holds once records come back from a durable store.
        """
        items = tuple(self._require(task_id).evidence)
        for item in items:
            if not item.intact:
                raise EvidenceTamperedError(
                    f"evidence record for task {task_id!r} kind {item.kind!r} "
                    "does not match its content hash"
                )
        return items

    def knows(self, task_id: str) -> bool:
        return task_id in self._tasks

    def reset(self) -> None:
        self._tasks.clear()

    def _require(self, task_id: str) -> _TaskRecord:
        try:
            return self._tasks[task_id]
        except KeyError:
            raise UnknownTaskError(task_id) from None
