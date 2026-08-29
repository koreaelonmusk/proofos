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
from .ledger import EvidenceLedger
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
    #: Records recorded as OBSERVED whose collector the caller did not vouch
    #: for. Carried as EXECUTOR: kept, and worth nothing.
    demoted: tuple[str, ...] = ()

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
        }


def replay_historical(
    bundle: ProofBundle,
    *,
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
    return _replay(bundle, None, ReplayMode.HISTORICAL,
                   trusted_collectors, expected_digest)


def re_evaluate_at(
    bundle: ProofBundle,
    now: float,
    *,
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
    return _replay(bundle, now, ReplayMode.RE_EVALUATED, trusted_collectors,
                   expected_digest)


def _replay(
    bundle: ProofBundle,
    now: float | None,
    mode: ReplayMode,
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
    ledger = EvidenceLedger()
    ledger.open_task(bundle.task_id, tuple(
        Requirement(kind=r.kind, max_age_seconds=r.max_age_seconds)
        for r in bundle.requirements))

    reinstated: list[str] = []
    demoted: list[str] = []
    plan: list[tuple[EvidenceRecord, EvidenceSource]] = []
    for record in bundle.evidence:
        _require_record_intact(record)
        source = _source_for(record, trusted)
        if _was_trusted(record):
            (reinstated if source in TRUSTED_SOURCES else demoted).append(
                record.content_hash)
        plan.append((record, source))

    # Grants are minted by this process from its own ledger. The bundle
    # contributes a list of records; it never contributes authority.
    grants: dict[str, Any] = {
        collector: ledger.grant_observation(collector, tuple(sorted(kinds)))
        for collector, kinds in grant_plan(bundle, trusted).items()
    }
    ledger.seal()

    for record, source in plan:
        ledger.record(
            bundle.task_id,
            Evidence(
                kind=record.kind,
                value=record.value,
                source=source,
                valid=record.valid,
                collected_at=record.collected_at,
                collector=record.collector,
            ),
            grants.get(record.collector) if source in TRUSTED_SOURCES else None,
        )

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
    )


def grant_plan(bundle: ProofBundle,
               trusted: Iterable[str]) -> dict[str, frozenset[str]]:
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
    plan: dict[str, set[str]] = {}
    for record in bundle.evidence:
        if _was_trusted(record) and record.collector in allowed:
            plan.setdefault(record.collector, set()).add(record.kind)
    return {collector: frozenset(kinds) for collector, kinds in plan.items()}


def _was_trusted(record: EvidenceRecord) -> bool:
    """Whether the original run recorded this as independent provenance."""
    return record.source in {str(s) for s in TRUSTED_SOURCES}


def _source_for(record: EvidenceRecord, trusted: frozenset[str]) -> EvidenceSource:
    """Decide one record's provenance for this replay.

    The only outcomes are: keep what was recorded, or fall back to EXECUTOR.
    There is no argument, no flag and no branch that returns a provenance
    stronger than the one in the record -- which is why naming a collector that
    only ever self-reported changes nothing.
    """
    if _was_trusted(record):
        if record.collector and record.collector in trusted:
            return EvidenceSource(record.source)
        return EvidenceSource.EXECUTOR
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
