"""ProofOS: evidence-first verification for autonomous agents.

An agent claim is not proof. The public surface is deliberately small --
``ProofOS`` to ask, ``Requirement`` to say what would prove it, ``Evidence``
to supply what you have, and a ``Decision`` to read back.
"""

from .api import Decision, ProofOS
from .integrity import content_hash
from .journal import (
    EventDraft,
    EventType,
    ExecutionEvent,
    InMemoryJournalSink,
    Journal,
    JournalSink,
    JournalUnavailableError,
    Severity,
)
from .ledger import (
    EvidenceLedger,
    EvidenceTamperedError,
    ObservationGrant,
    UnknownTaskError,
)
from .probe import ProbeOutcome, ProbeResult, probe_health
from .verifier import (
    Evidence,
    EvidenceAssessment,
    EvidenceSource,
    FailureClass,
    Requirement,
    VerificationResult,
    VerificationStatus,
    verify_completion,
)

#: The public surface. Two rules decide what belongs here, and a test enforces
#: both: a name is exported if a caller needs it, and any type reachable from an
#: exported signature must itself be exported. The second rule is not pedantry --
#: ``Decision.accepted`` returned ``EvidenceAssessment`` objects that no caller
#: could import by name, which is an API that cannot be typed against.
#:
#: Everything else in this package is internal. Import it and you are writing
#: against something that may move.
__all__ = [
    # Ask a question, read the answer.
    "ProofOS",
    "Decision",
    # Say what would prove it, and supply what you have.
    "Requirement",
    "Evidence",
    "EvidenceSource",
    # What the kernel returns.
    "VerificationResult",
    "VerificationStatus",
    "FailureClass",
    "EvidenceAssessment",
    "verify_completion",
    # Recording and observing.
    "EvidenceLedger",
    "Journal",
    "JournalSink",
    "InMemoryJournalSink",
    "EventType",
    "EventDraft",
    "ExecutionEvent",
    "Severity",
    "ObservationGrant",
    "probe_health",
    "ProbeResult",
    "ProbeOutcome",
    "content_hash",
    # Failures a caller is expected to catch by name, rather than by string.
    "EvidenceTamperedError",
    "UnknownTaskError",
    "JournalUnavailableError",
]
