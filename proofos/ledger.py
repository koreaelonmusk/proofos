from __future__ import annotations

from dataclasses import dataclass, field

from .verifier import Evidence


class UnknownTaskError(KeyError):
    """Raised when a caller references a task the runtime never opened."""


@dataclass
class _TaskRecord:
    required_kinds: tuple[str, ...]
    evidence: list[Evidence] = field(default_factory=list)


class EvidenceLedger:
    """Runtime-owned store of verification requirements and collected evidence.

    This is the trust boundary. Requirements and evidence are written only by the
    runtime and its collectors -- never by the model under scrutiny. The agent can
    reference a task by id, but it cannot declare what counts as proof, nor assert
    that proof exists.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, _TaskRecord] = {}

    def open_task(self, task_id: str, required_kinds: tuple[str, ...]) -> None:
        self._tasks[task_id] = _TaskRecord(required_kinds=tuple(required_kinds))

    def record(self, task_id: str, evidence: Evidence) -> None:
        """Attach one collected observation to a task."""
        self._require(task_id).evidence.append(evidence)

    def requirements(self, task_id: str) -> tuple[str, ...]:
        return self._require(task_id).required_kinds

    def evidence(self, task_id: str) -> tuple[Evidence, ...]:
        return tuple(self._require(task_id).evidence)

    def knows(self, task_id: str) -> bool:
        return task_id in self._tasks

    def reset(self) -> None:
        self._tasks.clear()

    def _require(self, task_id: str) -> _TaskRecord:
        try:
            return self._tasks[task_id]
        except KeyError:
            raise UnknownTaskError(task_id) from None
