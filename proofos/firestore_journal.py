"""Firestore-backed journal sink.

Layout:

    executions/{execution_id}                    -- chain head: next_sequence, head_hash
    executions/{execution_id}/events/{seq}       -- one document per event
    executions/{execution_id}/event_ids/{id}     -- idempotency index

Three rules shape this adapter:

1. **Storage is not an authority.** Firestore records what the runtime decided.
   Nothing read back from Firestore can create trusted evidence, change a
   verdict, or satisfy a requirement. The verifier never reads this module.

2. **Ordering is never inferred.** Documents carry an explicit ``sequence`` and
   are sorted by that field, not by document id, query order, or write time.

3. **Appends are atomic and non-destructive.** A new event is written with
   ``create``, which fails if that sequence already exists, inside a
   transaction that also advances the chain head. Two concurrent writers cannot
   quietly share a sequence, and no write path overwrites an existing event --
   history is append-only, so a failed execution can never be edited into a
   successful one.

Anything that goes wrong raises ``JournalUnavailableError``. Losing the audit
trail is a failure to be surfaced, never a silent success.
"""

from __future__ import annotations

from typing import Any, Callable

from .journal import (
    GENESIS_HASH,
    EventDraft,
    ExecutionEvent,
    JournalUnavailableError,
    finalize,
    verify_events,
)

EXECUTIONS_COLLECTION = "executions"
EVENTS_COLLECTION = "events"
EVENT_IDS_COLLECTION = "event_ids"

# Sequence numbers become document ids, zero padded so any lexicographic
# listing agrees with numeric order. The sequence field remains the authority.
SEQUENCE_ID_WIDTH = 12
MAX_APPEND_ATTEMPTS = 5


def _sequence_id(sequence: int) -> str:
    return str(sequence).zfill(SEQUENCE_ID_WIDTH)


def _default_transactional() -> Callable:
    from google.cloud import firestore  # imported lazily so the package stays optional

    return firestore.transactional


def _already_exists_error() -> type[Exception]:
    try:
        from google.api_core import exceptions

        return exceptions.AlreadyExists
    except ImportError:  # pragma: no cover - only when the client is absent
        return FileExistsError


class FirestoreJournalSink:
    """Durable journal sink backed by Firestore.

    ``client`` is injected rather than constructed here so the adapter's
    contract can be tested deterministically without credentials, and so the
    caller owns the connection's lifetime.
    """

    def __init__(
        self,
        client: Any,
        transactional: Callable | None = None,
        root_collection: str = EXECUTIONS_COLLECTION,
    ) -> None:
        self._client = client
        self._transactional = transactional or _default_transactional()
        self._root = root_collection
        self._already_exists = _already_exists_error()

    # -- references -------------------------------------------------------

    def _execution_ref(self, execution_id: str):
        return self._client.collection(self._root).document(execution_id)

    def _events_ref(self, execution_id: str):
        return self._execution_ref(execution_id).collection(EVENTS_COLLECTION)

    def _event_ids_ref(self, execution_id: str):
        return self._execution_ref(execution_id).collection(EVENT_IDS_COLLECTION)

    # -- writing ----------------------------------------------------------

    def append(self, draft: EventDraft) -> ExecutionEvent:
        """Append one event atomically, or raise JournalUnavailableError."""
        last_error: Exception | None = None

        for _ in range(MAX_APPEND_ATTEMPTS):
            try:
                return self._append_once(draft)
            except self._already_exists as exc:
                # Another writer took this sequence. Re-read the head and retry.
                last_error = exc
            except JournalUnavailableError:
                raise
            except Exception as exc:  # noqa: BLE001 - surfaced as audit loss below
                raise JournalUnavailableError(
                    f"firestore append failed for {draft.execution_id}: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc

        raise JournalUnavailableError(
            f"firestore append for {draft.execution_id} lost {MAX_APPEND_ATTEMPTS} "
            f"sequence races: {last_error}"
        )

    def _append_once(self, draft: EventDraft) -> ExecutionEvent:
        execution_ref = self._execution_ref(draft.execution_id)
        events_ref = self._events_ref(draft.execution_id)
        event_ids_ref = self._event_ids_ref(draft.execution_id)

        def operation(transaction):
            # Firestore requires every read to precede every write.
            id_ref = event_ids_ref.document(draft.event_id)
            id_snapshot = id_ref.get(transaction=transaction)
            head_snapshot = execution_ref.get(transaction=transaction)

            if getattr(id_snapshot, "exists", False):
                # Idempotent retry: this event was already recorded. Return the
                # stored copy rather than appending a second one.
                recorded = id_snapshot.to_dict() or {}
                stored = events_ref.document(
                    _sequence_id(int(recorded["sequence"]))
                ).get(transaction=transaction)
                if not getattr(stored, "exists", False):
                    raise JournalUnavailableError(
                        f"idempotency index for {draft.event_id} points at a "
                        "missing event: the write was only partly applied"
                    )
                return _from_record(stored.to_dict())

            head = head_snapshot.to_dict() if getattr(head_snapshot, "exists", False) else None
            head = head or {}
            sequence = int(head.get("next_sequence", 0))
            previous_hash = str(head.get("head_hash", GENESIS_HASH))

            event = finalize(draft, sequence, previous_hash)

            # create() fails if the document exists, so a concurrent writer that
            # already claimed this sequence cannot be overwritten.
            transaction.create(
                events_ref.document(_sequence_id(sequence)), event.to_dict()
            )
            transaction.create(
                id_ref, {"event_id": draft.event_id, "sequence": sequence}
            )
            transaction.set(
                execution_ref,
                {
                    "execution_id": draft.execution_id,
                    "task_id": draft.task_id,
                    "next_sequence": sequence + 1,
                    "head_hash": event.content_hash,
                },
                merge=True,
            )
            return event

        transaction = self._client.transaction()
        return self._transactional(operation)(transaction)

    def store(self, event: ExecutionEvent) -> None:
        """Write an already-chained event verbatim, without re-sequencing it."""
        try:
            self._events_ref(event.execution_id).document(
                _sequence_id(event.sequence)
            ).create(event.to_dict())
            self._event_ids_ref(event.execution_id).document(event.event_id).create(
                {"event_id": event.event_id, "sequence": event.sequence}
            )
        except self._already_exists:
            # Replaying the same finalized event is a no-op, not an error.
            return
        except Exception as exc:  # noqa: BLE001
            raise JournalUnavailableError(
                f"firestore store failed for {event.execution_id}: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    # -- reading ----------------------------------------------------------

    def list_execution(self, execution_id: str) -> tuple[ExecutionEvent, ...]:
        """Return the execution's events ordered by their explicit sequence.

        Raises JournalUnavailableError if any stored record is unreadable. A
        journal that cannot be parsed cannot be trusted, and returning a
        partial history would understate what happened.
        """
        try:
            snapshots = list(self._events_ref(execution_id).stream())
        except Exception as exc:  # noqa: BLE001
            raise JournalUnavailableError(
                f"firestore read failed for {execution_id}: {type(exc).__name__}: {exc}"
            ) from exc

        events = [_from_record(snapshot.to_dict()) for snapshot in snapshots]
        # Sort by the stored sequence field, never by document order.
        return tuple(sorted(events, key=lambda e: e.sequence))

    def verify_chain(self, execution_id: str) -> tuple[bool, tuple[str, ...]]:
        """Check the persisted chain. Never raises; reports problems instead."""
        try:
            events = self.list_execution(execution_id)
        except JournalUnavailableError as exc:
            return False, (str(exc),)
        return verify_events(events)


def _from_record(record: Any) -> ExecutionEvent:
    if not isinstance(record, dict):
        raise JournalUnavailableError(
            f"malformed journal record: expected a mapping, got {type(record).__name__}"
        )
    try:
        return ExecutionEvent.from_dict(record)
    except ValueError as exc:
        raise JournalUnavailableError(str(exc)) from exc
