"""The ingestion boundary.

This is the only place an observation becomes OBSERVED evidence, and it is the
only in-process holder of an observation grant. Everything upstream -- the
orchestrator, the transport, the agents -- can carry an attestation but cannot
turn one into trusted evidence.

``source`` never arrives on the wire. A collector states what it saw; this
module decides, after eleven checks, whether that statement earns the OBSERVED
label. Failure at any stage writes nothing.

Rejections are recorded with a short reason code rather than an exception trace,
so the journal explains what happened without carrying key material, tokens, or
attacker-controlled text into storage.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from enum import StrEnum

from .attestation import (
    ATTESTATION_VERSION,
    AttestationError,
    ObservationAttestation,
    Outcome,
)
from .capabilities import ObservationCapability
from .collector_registry import CollectorIdentityError, CollectorRegistry
from .verifier import Evidence

#: How far in the future an observed_at may sit before we call it nonsense.
#: Clocks drift; they do not run minutes ahead.
CLOCK_SKEW_TOLERANCE_SECONDS = 60.0


class RejectionReason(StrEnum):
    MALFORMED = "MALFORMED_ATTESTATION"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNKNOWN_COLLECTOR = "UNKNOWN_COLLECTOR"
    COLLECTOR_SCOPE = "COLLECTOR_SCOPE_VIOLATION"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    EXECUTION_MISMATCH = "EXECUTION_MISMATCH"
    TASK_MISMATCH = "TASK_MISMATCH"
    KIND_MISMATCH = "KIND_MISMATCH"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    NONCE_UNKNOWN = "NONCE_UNKNOWN"
    NONCE_REUSED = "NONCE_REUSED"
    NONCE_BINDING = "NONCE_BINDING_MISMATCH"
    STALE = "ATTESTATION_STALE"
    FUTURE_DATED = "ATTESTATION_FUTURE_DATED"


class AttestationRejected(ValueError):
    def __init__(self, reason: RejectionReason, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else str(reason))
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class NonceRecord:
    nonce: str
    execution_id: str
    task_id: str
    kind: str
    issued_at: float
    consumed_by: str = ""


class NonceLedger:
    """Runtime-issued, single-use challenges bound to one execution and task.

    A signature proves who observed. It does not prove *when* or *for which
    request*. The nonce is what stops a genuine, correctly signed attestation
    being replayed into a different execution, a different task, or a second
    time into the same one.
    """

    def __init__(self) -> None:
        self._records: dict[str, NonceRecord] = {}

    def issue(self, execution_id: str, task_id: str, kind: str) -> str:
        nonce = f"nonce_{secrets.token_hex(16)}"
        self._records[nonce] = NonceRecord(
            nonce=nonce,
            execution_id=execution_id,
            task_id=task_id,
            kind=kind,
            issued_at=time.time(),
        )
        return nonce

    def consume(
        self,
        nonce: str,
        execution_id: str,
        task_id: str,
        kind: str,
        signature: str,
    ) -> bool:
        """Spend a nonce. Returns True if this is a replay of the same attestation.

        Presenting the identical attestation twice is a retry, and is answered
        idempotently. Presenting a *different* attestation against a spent nonce
        is an attack, and is refused.
        """
        record = self._records.get(nonce)
        if record is None:
            raise AttestationRejected(
                RejectionReason.NONCE_UNKNOWN, "nonce was not issued by this runtime"
            )
        if (record.execution_id, record.task_id, record.kind) != (
            execution_id,
            task_id,
            kind,
        ):
            raise AttestationRejected(
                RejectionReason.NONCE_BINDING,
                "nonce was issued for a different execution, task, or kind",
            )
        if record.consumed_by:
            if record.consumed_by == signature:
                return True
            raise AttestationRejected(
                RejectionReason.NONCE_REUSED,
                "nonce was already spent by a different attestation",
            )
        self._records[nonce] = NonceRecord(
            nonce=record.nonce,
            execution_id=record.execution_id,
            task_id=record.task_id,
            kind=record.kind,
            issued_at=record.issued_at,
            consumed_by=signature,
        )
        return False


@dataclass(frozen=True)
class IngestionResult:
    accepted: bool
    outcome: Outcome | None = None
    evidence: Evidence | None = None
    reason: RejectionReason | None = None
    detail: str = ""
    duplicate: bool = False

    @property
    def satisfies_requirement(self) -> bool:
        return bool(self.accepted and self.outcome is not None and self.outcome.satisfies)


class AttestationIngestor:
    """Turns a signed attestation into trusted evidence, or into nothing.

    Holds the only observation grant in the process. It writes evidence solely
    on behalf of a collector whose signature it has just verified, so nothing
    upstream needs -- or is given -- the authority to write OBSERVED evidence.
    """

    __slots__ = ("_capabilities", "_collectors", "_nonces")

    def __init__(
        self,
        capabilities: dict[str, ObservationCapability],
        collectors: CollectorRegistry,
        nonces: NonceLedger,
    ) -> None:
        self._capabilities = capabilities
        self._collectors = collectors
        self._nonces = nonces

    def issue_nonce(self, execution_id: str, task_id: str, kind: str) -> str:
        return self._nonces.issue(execution_id, task_id, kind)

    def ingest(
        self,
        raw: object,
        execution_id: str,
        task_id: str,
        expected_kind: str,
        expected_profile: str,
        expected_nonce: str,
        max_age_seconds: float | None,
        now: float | None = None,
    ) -> IngestionResult:
        """Validate an attestation and, only if every check passes, record it."""
        try:
            return self._ingest(
                raw,
                execution_id,
                task_id,
                expected_kind,
                expected_profile,
                expected_nonce,
                max_age_seconds,
                time.time() if now is None else now,
            )
        except AttestationRejected as exc:
            return IngestionResult(
                accepted=False, reason=exc.reason, detail=exc.detail
            )

    def _ingest(
        self,
        raw: object,
        execution_id: str,
        task_id: str,
        expected_kind: str,
        expected_profile: str,
        expected_nonce: str,
        max_age_seconds: float | None,
        now: float,
    ) -> IngestionResult:
        # 1. parse under a strict schema
        try:
            attestation = ObservationAttestation.from_dict(raw)
        except AttestationError as exc:
            raise AttestationRejected(RejectionReason.MALFORMED, str(exc)) from exc

        # 2. version
        if attestation.version != ATTESTATION_VERSION:
            raise AttestationRejected(
                RejectionReason.UNSUPPORTED_VERSION, attestation.version
            )

        # 3-4. collector is known, active, and scoped to this kind and profile
        try:
            record = self._collectors.require_scope(
                attestation.collector_id, attestation.kind, attestation.profile_id
            )
        except CollectorIdentityError as exc:
            reason = (
                RejectionReason.UNKNOWN_COLLECTOR
                if "unknown" in str(exc) or "not active" in str(exc)
                else RejectionReason.COLLECTOR_SCOPE
            )
            raise AttestationRejected(reason, str(exc)) from exc

        # 5. signature, against the key registered for that id -- so relabelling
        #    an attestation invalidates it rather than transferring it
        try:
            record.verifier.verify(attestation)
        except AttestationError as exc:
            raise AttestationRejected(
                RejectionReason.SIGNATURE_INVALID, str(exc)
            ) from exc

        # 6-9. the signed fields must match what this runtime actually asked for
        if attestation.execution_id != execution_id:
            raise AttestationRejected(RejectionReason.EXECUTION_MISMATCH)
        if attestation.task_id != task_id:
            raise AttestationRejected(RejectionReason.TASK_MISMATCH)
        if attestation.kind != expected_kind:
            raise AttestationRejected(RejectionReason.KIND_MISMATCH)
        if attestation.profile_id != expected_profile:
            raise AttestationRejected(RejectionReason.PROFILE_MISMATCH)
        if attestation.request_nonce != expected_nonce:
            raise AttestationRejected(
                RejectionReason.NONCE_BINDING, "attestation answers a different request"
            )

        # 10. freshness. A signature proves authorship, never recency.
        if attestation.observed_at > now + CLOCK_SKEW_TOLERANCE_SECONDS:
            raise AttestationRejected(RejectionReason.FUTURE_DATED)
        if (
            max_age_seconds is not None
            and attestation.observed_at < now - max_age_seconds
        ):
            raise AttestationRejected(
                RejectionReason.STALE,
                f"observed {now - attestation.observed_at:.0f}s ago",
            )

        # 11. spend the nonce, last, so a rejected attestation does not burn it
        duplicate = self._nonces.consume(
            attestation.request_nonce,
            execution_id,
            task_id,
            attestation.kind,
            attestation.signature,
        )

        if duplicate:
            # The identical attestation, presented again. Already recorded; a
            # retry must not append a second copy of the same observation.
            return IngestionResult(
                accepted=True, outcome=attestation.outcome, duplicate=True
            )

        # 12. only now does an observation become OBSERVED evidence
        capability = self._capabilities.get(attestation.collector_id)
        if capability is None:
            raise AttestationRejected(
                RejectionReason.UNKNOWN_COLLECTOR,
                "no observation capability for this collector",
            )

        evidence = capability.record_observation(
            task_id,
            kind=attestation.kind,
            value=(
                f"attested {attestation.outcome.value} via {attestation.profile_id}: "
                f"{attestation.detail}"
            ),
            satisfies=attestation.outcome.satisfies,
            collected_at=attestation.observed_at,
        )

        return IngestionResult(
            accepted=True,
            outcome=attestation.outcome,
            evidence=evidence,
            duplicate=duplicate,
        )
