"""Journal backend selection.

Chooses where the audit trail is durably written. In-memory is the default so
local runs and tests need no credentials; Firestore is opt-in via environment.

The durable sink is always the *primary*: it assigns sequence numbers and owns
the atomic append, because that is where concurrent writers actually contend.
Stdout is a replica that receives the already-finalized event, which is why the
logs and the store can never disagree about ordering.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .journal import (
    FanoutJournalSink,
    InMemoryJournalSink,
    JournalSink,
    StreamJournalSink,
)

BACKEND_ENV = "PROOFOS_JOURNAL_BACKEND"
PROJECT_ENV = "PROOFOS_FIRESTORE_PROJECT"
DATABASE_ENV = "PROOFOS_FIRESTORE_DATABASE"


@dataclass(frozen=True)
class JournalBackend:
    """The sink to append through, and the durable sink to query."""

    append_sink: JournalSink
    durable_sink: JournalSink
    backend: str
    detail: str


def build_journal_backend(
    client: Any | None = None,
    stream_replica: bool = True,
) -> JournalBackend:
    """Build the configured backend.

    Set ``PROOFOS_JOURNAL_BACKEND=firestore`` to persist to Firestore. Anything
    else -- including unset -- keeps the in-memory sink, so nothing about the
    default path requires cloud credentials.
    """
    requested = os.environ.get(BACKEND_ENV, "memory").strip().lower()

    if requested == "firestore":
        durable, detail = _build_firestore_sink(client)
    else:
        durable, detail = InMemoryJournalSink(), "in-memory (not durable)"

    append: JournalSink = durable
    if stream_replica:
        append = FanoutJournalSink(durable, StreamJournalSink())

    return JournalBackend(
        append_sink=append,
        durable_sink=durable,
        backend=requested if requested == "firestore" else "memory",
        detail=detail,
    )


def _build_firestore_sink(client: Any | None) -> tuple[JournalSink, str]:
    from .firestore_journal import FirestoreJournalSink

    if client is not None:
        return FirestoreJournalSink(client), "firestore (injected client)"

    from google.cloud import firestore

    project = os.environ.get(PROJECT_ENV) or os.environ.get("GOOGLE_CLOUD_PROJECT")
    database = os.environ.get(DATABASE_ENV)
    kwargs: dict[str, Any] = {}
    if project:
        kwargs["project"] = project
    if database:
        kwargs["database"] = database

    return (
        FirestoreJournalSink(firestore.Client(**kwargs)),
        f"firestore (project={project or 'default'})",
    )
