"""ProofOS: evidence-first verification for autonomous agents.

An agent claim is not proof. The public surface is deliberately small --
``ProofOS`` to ask, ``Requirement`` to say what would prove it, ``Evidence``
to supply what you have, and a ``Decision`` to read back.
"""

from .api import Decision, ProofOS
from .integrity import content_hash
from .journal import (
    EventType,
    ExecutionEvent,
    InMemoryJournalSink,
    Journal,
    JournalUnavailableError,
)
from .ledger import EvidenceLedger, EvidenceTamperedError, UnknownTaskError
from .probe import ProbeOutcome, ProbeResult, probe_health
from .verifier import (
    Evidence,
    EvidenceSource,
    FailureClass,
    Requirement,
    VerificationResult,
    VerificationStatus,
    verify_completion,
)

__all__ = [
    "Evidence",
    "EvidenceLedger",
    "EvidenceSource",
    "EvidenceTamperedError",
    "EventType",
    "ExecutionEvent",
    "FailureClass",
    "InMemoryJournalSink",
    "Journal",
    "JournalUnavailableError",
    "ProbeOutcome",
    "ProbeResult",
    "Requirement",
    "UnknownTaskError",
    "VerificationResult",
    "VerificationStatus",
    "content_hash",
    "probe_health",
    "verify_completion",
]

__all__ = [
    "Decision",
    "ProofOS",
    "Requirement",
    "Evidence",
    "EvidenceSource",
    "VerificationResult",
    "VerificationStatus",
    "FailureClass",
    "verify_completion",
    "EvidenceLedger",
    "Journal",
    "EventType",
    "probe_health",
    "content_hash",
]
