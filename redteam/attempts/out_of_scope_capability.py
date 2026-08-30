"""What does NOT count: minting your own observation grant.

Kept in the corpus deliberately. It is the first thing a challenger tries, it
succeeds completely, and it proves nothing about ProofOS — arbitrary code in
the same interpreter is documented non-defense #1.

This attempt DOES reach VERIFIED. That is the point: the arena must classify it
OUT_OF_SCOPE rather than BYPASS_CONFIRMED. If it is ever reported as a break,
the scope detection has failed and every other green result from this arena is
worthless.
"""
from proofos import EvidenceLedger
from proofos.capabilities import ObservationCapability

TITLE = "build a fresh ledger, mint a capability, write the evidence you want"
AUTHOR = "project"


def run(kit):
    # Nothing stops this, and nothing is supposed to. On the arena's own sealed
    # ledger the seal refuses it; so the attempt sidesteps that by building an
    # unsealed one, which is exactly the in-process move that is out of scope.
    ledger = EvidenceLedger()
    ledger.open_task(kit.task_id, (kit.requirement,))
    cap = ObservationCapability(ledger, "proofos-collector", (kit.kind,))
    ledger.seal()
    cap.record_observation(kit.task_id, kind=kit.kind,
                           value="GET /health -> 200", satisfies=True,
                           collected_at=kit.now - 5)
    return kit.verify_recorded(ledger)
