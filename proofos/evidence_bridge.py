"""Encode a neutral submission as evidence, and fix its provenance structurally.

This is the one wall between two jobs that look alike and are not. An adapter
translates what a foreign system *said* into ProofOS vocabulary; it decides
nothing and holds no verifier type. This module takes that neutral submission
and encodes it as ``Evidence`` for the kernel to read. Encoding is where a
provenance is written down -- so it is deliberately the *only* place a neutral
submission becomes evidence, and the provenance it writes is fixed by the code,
never chosen by the caller or the payload.

What the fixed provenance is, and why:

    Everything in an ``AdapterEnvelope`` came from the component whose claim is
    under scrutiny -- the actor's own words, and the results of tools that same
    actor ran. None of it is independent of that actor. So every record this
    bridge emits is ``EvidenceSource.EXECUTOR``. There is no branch that reaches
    ``OBSERVED``: independence is a property of *who observed* something, and by
    construction nobody independent is present in a submission. A caller that
    passes ``{"source": "OBSERVED", "verified": true}`` still gets EXECUTOR
    evidence, because those words were written by the thing being examined.

    OBSERVED evidence exists, and it verifies -- but it is minted by an
    authorised collector on the trusted path (``EvidenceLedger`` + a grant),
    never here. This module cannot import that path and does not try.

What this module deliberately cannot do, enforced by test, not by convention:

    * It never produces ``EvidenceSource.OBSERVED`` -- the constant is not named
      in the file.
    * It takes no ``source`` / ``trusted`` / ``observed`` argument. Provenance is
      not an input.
    * It has no ``verify``, ``trust``, ``grant``, ``accept`` or ``certify``, and
      never calls ``verify_completion``. Encoding evidence is not deciding
      whether it satisfies a requirement -- that is the verifier's job, over
      evidence whose provenance was established somewhere it can reach.
"""

from __future__ import annotations

import json

from .adapters import MAX_TEXT, AdapterEnvelope
from .verifier import Evidence, EvidenceSource

__all__ = ["evidence_from_envelope"]


def evidence_from_envelope(envelope: AdapterEnvelope, kind: str) -> tuple[Evidence, ...]:
    """Encode one neutral submission as EXECUTOR evidence records.

    The claim becomes one record; each tool result becomes another. Every record
    is ``EvidenceSource.EXECUTOR`` and is attributed to the actor that produced
    the submission -- a tool the executor ran is not independent of the executor,
    and the ``collector`` field says so rather than naming the tool as a third
    party. Pure: no I/O, no clock, no network; the same envelope always yields
    the same records.
    """
    records = [Evidence(
        kind=kind,
        value=envelope.claim.text[:MAX_TEXT],
        source=EvidenceSource.EXECUTOR,
        collected_at=envelope.claim.at,
        collector=envelope.claim.actor.actor_id,
    )]
    for result in envelope.tool_results:
        records.append(Evidence(
            kind=kind,
            value=f"{result.tool}: {json.dumps(dict(result.payload), sort_keys=True)[:MAX_TEXT]}",
            source=EvidenceSource.EXECUTOR,
            collected_at=result.at,
            collector=envelope.claim.actor.actor_id,
        ))
    return tuple(records)
