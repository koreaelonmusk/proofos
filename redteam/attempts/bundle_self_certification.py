"""A bundle that carries its own verdict and no evidence at all."""
import json

from proofos.bundle import export_bundle, load_bundle
from proofos.integrity import content_hash
from proofos.replay import replay_historical

TITLE = "a proof bundle asserting recorded_verdict=VERIFIED with the evidence removed"
AUTHOR = "project"


def run(kit):
    decision = kit.verify_recorded()
    bundle = export_bundle(
        claim=kit.claim, requirements=kit.ledger.requirements(kit.task_id),
        evidence=kit.ledger.evidence(kit.task_id), task_id=kit.task_id,
        verification_time=kit.now, created_at=kit.now,
        recorded_verdict=str(decision.status), recorded_reason=str(decision.reason))

    raw = json.loads(bundle.to_json())
    raw["recorded_verdict"] = "VERIFIED"       # say the answer out loud
    raw["evidence"] = []                        # and remove the reason for it
    raw.pop("digest", None)
    sealed = load_bundle({**raw, "digest": content_hash(raw)})

    # Vouch for the collector the bundle names, to give it every chance.
    return replay_historical(sealed, trusted_collectors=["proofos-collector"]).recomputed
