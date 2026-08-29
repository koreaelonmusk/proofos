"""Replay can reproduce a decision. It cannot reproduce an observation.

Given a proof bundle, this recomputes the verdict the way the original run
computed it -- same requirements, same evidence records, same instant -- and
reports whether it agrees with what the bundle says happened. Nothing here
decides what VERIFIED means. It rebuilds a ledger and asks the ordinary
authoritative path, because a replay that carried its own copy of the trust
rules would eventually answer a slightly different question than production
does, and nobody would notice until it mattered.

## The hard part, stated plainly

An in-process observation grant is authority held by an object. Authority held
by an object does not survive being written to a file, and no arrangement of
bytes can carry it. So a bundle arriving with ``source: OBSERVED`` on every
record is, on its own, a document making an assertion -- exactly the shape this
whole system exists to refuse.

The resolution is that **the replaying process names who it trusts, and the
bundle never can.** ``trusted_collectors`` is an argument supplied by whoever is
running the replay, from their own knowledge of which collectors were real. It
defaults to nothing, so a bundle replayed with no argument reaches ABSTAIN
however many times it says OBSERVED. This is the same law the collector registry
keeps -- a ``collector_id`` in a payload is a claim, and becomes an identity only
when something outside the payload vouches for the key.

And that argument can only ever *preserve* provenance, never create it:

* recorded OBSERVED + collector named by the caller  ->  OBSERVED
* recorded OBSERVED + collector not named           ->  EXECUTOR (demoted)
* recorded anything else                            ->  unchanged

There is no branch that raises a record above what the bundle recorded. Naming
a collector that only ever self-reported buys nothing, because the promotion
path does not exist. That is the structural half of "replayed evidence is not a
new observation": the other half is that this module performs no I/O, so there
is no new observation available to it in the first place.

## When the evidence is signed

A record may carry the attestation envelope its collector signed. Then the
question stops being "does the caller vouch for this name" and becomes "does
this signature verify against a key the *replaying environment* holds" -- which
is a better question, and still not a question about truth. Four states stay
apart: signed, signed by a key someone vouches for, authorized for this kind,
and satisfies the requirement. Only the last one is a verdict, and it is reached
somewhere else.

The trust root arrives as an argument -- a ``CollectorRegistry``, the same type
production uses. Nothing in a bundle can add to it, because verification never
reads a key out of the envelope: it reads the ``collector_id``, asks the
registry for that collector's key, and checks the signature against that. An
attacker's perfectly valid signature over a perfectly formed envelope naming
``trusted-collector`` fails, because the registry's key for that name is not the
attacker's.

And the two paths do not rescue each other. A record carrying an attestation
must have that attestation verify; naming its collector in
``trusted_collectors`` does nothing for it. Otherwise the weaker path would
quietly become the way around the stronger one.

## What replay is entitled to say

    "Given these records, ProofOS reaches VERIFIED for time T."

Not:

    "The world still satisfies this."

Historical replay is reproducibility. Re-evaluating at a later time is a
different question with a different name -- ``re_evaluate_at`` -- and it answers
it honestly: old evidence falls outside its freshness horizon and the verdict
becomes ABSTAIN. That is the correct answer, and the reason freshness horizons
are worth declaring at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable

from .api import Decision, ProofOS
from .bundle import EvidenceRecord, ProofBundle
from .capabilities import ObservationCapability
from .ledger import EvidenceLedger
from .portable_attestation import (
    AttestationUnavailable,
    PortableAttestationRejected,
    bind_to_record,
    verify_portable,
)
from .verifier import Evidence, EvidenceSource, Requirement

#: The provenance a bundle may claim and a caller may confirm. Derived from the
#: kernel's own notion of independence rather than naming OBSERVED here, so a
#: later build that changes what counts as trusted changes this too.
from .verifier import TRUSTED_SOURCES


class ReplayError(ValueError):
    """A bundle this build will not replay authoritatively, and why."""


class ReplayMode(StrEnum):
    """Which question was asked. Two questions, two names, on purpose."""

    #: Reproduce the historical decision at the bundle's own verification time.
    HISTORICAL = "historical"
    #: Ask what the same sealed records are worth at some later instant. Not a
    #: new observation -- the same evidence, judged against a newer clock.
    RE_EVALUATED = "re_evaluated"


@dataclass(frozen=True)
class ReplayResult:
    """What an independent process computed, and what the bundle claimed.

    ``recomputed`` is the answer. ``recorded_verdict`` is what the bundle says
    the original run concluded, carried so the two can be compared. If they
    disagree, ``matches_recorded`` is False and that is the finding -- not an
    error to be smoothed over, and not a reason to prefer the recorded one.
    """

    bundle_id: str
    mode: ReplayMode
    evaluated_at: float
    recomputed: Decision
    recorded_verdict: str
    recorded_reason: str
    #: Records whose recorded OBSERVED provenance the caller vouched for.
    reinstated: tuple[str, ...] = ()
    #: Records the original run recorded as independent whose provenance this
    #: replay would not confirm. Carried as a self-report: kept, worth nothing.
    demoted: tuple[str, ...] = ()
    #: Why each carried attestation was refused, so a reviewer can tell an
    #: absent trust anchor from a forged signature.
    rejected: tuple[tuple[str, str], ...] = ()

    @property
    def status(self) -> str:
        return str(self.recomputed.status)

    @property
    def reason(self) -> str:
        return str(self.recomputed.reason)

    @property
    def matches_recorded(self) -> bool:
        """Whether the independent answer agrees with the recorded one.

        False when nothing was recorded, too. A bundle that never said what it
        concluded has not been shown to agree with anything.
        """
        return bool(self.recorded_verdict) and self.recorded_verdict == self.status

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "mode": str(self.mode),
            "evaluated_at": self.evaluated_at,
            "recomputed_verdict": self.status,
            "recomputed_reason": self.reason,
            "recorded_verdict": self.recorded_verdict or "(none)",
            "recorded_reason": self.recorded_reason or "(none)",
            "matches_recorded": self.matches_recorded,
            "reinstated": list(self.reinstated),
            "demoted": list(self.demoted),
            "rejected": [list(item) for item in self.rejected],
        }


def replay_historical(
    bundle: ProofBundle,
    *,
    trust_anchor: Any = None,
    trusted_collectors: Iterable[str] = (),
    expected_digest: str = "",
) -> ReplayResult:
    """Recompute the decision at the bundle's own verification time.

    This is reproducibility: the same records judged against the same clock
    should give the same answer on any machine, and if it does not, something
    changed that a version number should have covered.
    """
    # `None` rather than bundle.verification_time: the argument is read
    # after the type check, so a caller passing something that is not a
    # bundle meets the refusal rather than an AttributeError.
    return _replay(bundle, None, ReplayMode.HISTORICAL, trust_anchor,
                   trusted_collectors, expected_digest)


def re_evaluate_at(
    bundle: ProofBundle,
    now: float,
    *,
    trust_anchor: Any = None,
    trusted_collectors: Iterable[str] = (),
    expected_digest: str = "",
) -> ReplayResult:
    """Ask what the same sealed records are worth at a later instant.

    Deliberately a different function with a different name, because it answers
    a different question. No evidence is collected -- there is nothing here that
    could collect any -- so a requirement with a freshness horizon will find its
    observation outside it and abstain. An old proof going quiet is the horizon
    doing its job.
    """
    return _replay(bundle, now, ReplayMode.RE_EVALUATED, trust_anchor,
                   trusted_collectors, expected_digest)


def _replay(
    bundle: ProofBundle,
    now: float | None,
    mode: ReplayMode,
    trust_anchor: Any,
    trusted_collectors: Iterable[str],
    expected_digest: str,
) -> ReplayResult:
    if not isinstance(bundle, ProofBundle):
        raise ReplayError("replay takes a ProofBundle. Load the file with "
                          "proofos.bundle.load_bundle first, so the schema is "
                          "checked before anything reads it")

    # Integrity first, and it raises. Nothing downstream gets to see a bundle
    # whose bytes disagree with its digest, including the parts of it that look
    # harmless.
    now = bundle.verification_time if now is None else now
    bundle.require_intact()
    if expected_digest and expected_digest != bundle.digest:
        raise ReplayError(
            f"bundle digest {bundle.digest} is not the expected "
            f"{expected_digest}. The file is internally consistent and is not "
            "the one you asked for")

    trusted = frozenset(str(name) for name in trusted_collectors if str(name))

    reinstated: list[str] = []
    demoted: list[str] = []
    rejected: list[tuple[str, str]] = []
    for record in bundle.evidence:
        _require_record_intact(record)
        if not _was_trusted(record):
            continue
        if record.attestation:
            # Carrying a signature means the signature answers the question.
            # Being named in trusted_collectors does not rescue a record whose
            # attestation failed -- otherwise the weaker path would be the way
            # around the stronger one.
            refusal = _attestation_refusal(record, bundle, trust_anchor, now)
            if refusal:
                rejected.append((record.content_hash, refusal))
                demoted.append(record.content_hash)
            else:
                reinstated.append(record.content_hash)
        elif record.collector in trusted:
            reinstated.append(record.content_hash)
        else:
            demoted.append(record.content_hash)

    confirmed = frozenset(reinstated)
    ledger = EvidenceLedger()
    ledger.open_task(bundle.task_id, tuple(
        Requirement(kind=r.kind, max_age_seconds=r.max_age_seconds)
        for r in bundle.requirements))

    # Capabilities are minted by this process from its own ledger, for the
    # collectors this replay confirmed. The bundle contributes a list of
    # records; it never contributes authority. Recording through the capability
    # rather than assembling an Evidence by hand is why this module contains no
    # code that names an independent provenance at all.
    capabilities = {
        collector: ObservationCapability(ledger, collector, tuple(sorted(kinds)))
        for collector, kinds in grant_plan(bundle, trusted,
                                           attested=confirmed).items()
    }
    ledger.seal()

    for record in bundle.evidence:
        if record.content_hash in confirmed:
            capabilities[record.collector].record_observation(
                bundle.task_id, kind=record.kind, value=record.value,
                satisfies=record.valid, collected_at=record.collected_at)
        else:
            ledger.record(bundle.task_id, Evidence(
                kind=record.kind, value=record.value,
                source=_untrusted_source(record), valid=record.valid,
                collected_at=record.collected_at, collector=record.collector))

    decision = ProofOS().verify_recorded(ledger, bundle.task_id, bundle.claim,
                                         now=now)
    return ReplayResult(
        bundle_id=bundle.bundle_id,
        mode=mode,
        evaluated_at=now,
        recomputed=decision,
        recorded_verdict=bundle.recorded_verdict,
        recorded_reason=bundle.recorded_reason,
        reinstated=tuple(reinstated),
        demoted=tuple(demoted),
        rejected=tuple(rejected),
    )


def _attestation_refusal(record: EvidenceRecord, bundle: ProofBundle,
                         trust_anchor: Any, now: float) -> str:
    """Empty when the carried attestation verifies and belongs to this record.

    Every failure is a refusal, including "the signature machinery is not
    installed". An unchecked signature is not a weaker yes.
    """
    try:
        observation = verify_portable(record.attestation, registry=trust_anchor,
                                      now=now)
        bind_to_record(observation, record, task_id=bundle.task_id,
                       execution_id=bundle.execution_id)
    except PortableAttestationRejected as exc:
        return exc.reason
    except AttestationUnavailable:
        return "SIGNATURE_MACHINERY_UNAVAILABLE"
    return ""


def grant_plan(bundle: ProofBundle, trusted: Iterable[str], *,
               attested: Iterable[str] = ()) -> dict[str, frozenset[str]]:
    """Exactly which collectors this replay will vouch for, and for which kinds.

    A separate, testable function rather than a loop inside the replay, because
    this is the one place where a file turns back into authority and it should
    be possible to look at it on its own.

    Both sides bound it. A collector the caller did not name gets no entry, so
    the bundle cannot widen it; a kind that collector did not observe is not
    covered, so naming a collector does not hand it the whole task. Minting more
    than this would be latent over-authority even while the provenance rules
    happen to make it unreachable -- and the provenance rules are exactly the
    kind of thing a later edit changes.
    """
    allowed = frozenset(str(name) for name in trusted if str(name))
    confirmed = frozenset(attested)
    plan: dict[str, set[str]] = {}
    for record in bundle.evidence:
        if not _was_trusted(record):
            continue
        # A record carrying a signature is admitted by that signature or not at
        # all. A name in `trusted` speaks only for records that carry none.
        vouched = (record.content_hash in confirmed if record.attestation
                   else record.collector in allowed)
        if vouched:
            plan.setdefault(record.collector, set()).add(record.kind)
    return {collector: frozenset(kinds) for collector, kinds in plan.items()}


def _was_trusted(record: EvidenceRecord) -> bool:
    """Whether the original run recorded this as independent provenance."""
    return record.source in {str(s) for s in TRUSTED_SOURCES}


def _untrusted_source(record: EvidenceRecord) -> EvidenceSource:
    """The provenance for a record this replay did not confirm.

    Every path out of here is untrusted, and the last line says so rather than
    assuming it: a later edit that made this function capable of returning an
    independent provenance would be the whole failure, and it would look like a
    one-line change.
    """
    source = EvidenceSource.EXECUTOR if _was_trusted(record) else _declared(record)
    if source in TRUSTED_SOURCES:
        raise ReplayError(
            "an unconfirmed record reached an independent provenance. This is "
            "the one thing replay must not be able to do")
    return source


def _declared(record: EvidenceRecord) -> EvidenceSource:
    try:
        return EvidenceSource(record.source)
    except ValueError:
        raise ReplayError(
            f"evidence record declares an unknown provenance "
            f"{record.source!r}") from None


def _require_record_intact(record: EvidenceRecord) -> None:
    if not record.intact:
        raise ReplayError(
            f"evidence record for {record.kind!r} does not match its own "
            "digest. The bundle is internally consistent, so this record was "
            "already broken when it was sealed")


def render_replay(result: ReplayResult) -> str:
    """The result, for a person, including the sentence that has to be there."""
    facts = result.as_dict()
    width = max(len(k) for k in facts)
    lines = [f"replay of {facts['bundle_id']} ({facts['mode']})", ""]
    lines += [f"  {key:<{width}}  {facts[key]}" for key in facts]
    lines += [
        "",
        "  This is a recomputation of a recorded decision, not a new",
        "  observation. It says what ProofOS concludes from these records at",
        "  this instant. It does not say the world still satisfies the claim.",
    ]
    return "\n".join(lines)


#: Tier 2. Imported from ``proofos.replay`` by whoever is checking a proof on
#: another machine; the root API is for someone verifying a claim.
__all__ = [
    "ReplayError",
    "grant_plan",
    "ReplayMode",
    "ReplayResult",
    "replay_historical",
    "re_evaluate_at",
    "render_replay",
]
