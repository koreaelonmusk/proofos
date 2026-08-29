"""The same observation, two routes, two different answers.

Everything else about plugins is checked structurally: the manifest has no word
for authority, the return type has no field for provenance, the conformance
suite fails a plugin that reports an outage as healthy. Those are good tests and
none of them answers the question a sceptic actually asks --

    if I install a plugin and it tells you the service is fine, does that count?

So this file takes one observation, holds its content fixed, and runs it down
both routes. Down the plugin route it is a statement someone made. Down the
ingestion route the same bytes are signed by a collector whose key a sealed
registry holds, checked at a boundary that owns the only observation
capability, and written to a ledger under that collector's own identity.

Identical content. Different provenance. One ABSTAIN and one VERIFIED, and the
difference is not what was seen but who is in a position to say so.
"""

from __future__ import annotations

import time
import unittest

from proofos import (
    Evidence,
    EvidenceLedger,
    EvidenceSource,
    ProofOS,
    Requirement,
)
from proofos.api import ProvenanceNotDeclarable
from proofos.attestation import AttestationSigner, Outcome, response_digest
from proofos.capabilities import ObservationCapability
from proofos.collector_registry import registry_for
from proofos.conformance import Observation, ObservationOutcome, ObservationRequest
from proofos.ingestion import AttestationIngestor, NonceLedger
from proofos.plugins import PLUGIN_SCHEMA, parse_manifest

COLLECTOR = "http-health-collector"
PROFILE = "runtime-health-v1"
TASK = "DEPLOY-9"
EXECUTION = "exec_boundary"
KIND = "runtime_health"
BODY = b'{"status":"ok"}'

MANIFEST = parse_manifest({
    "schema_version": PLUGIN_SCHEMA,
    "plugin_id": "http-health",
    "version": "1.0.0",
    "kind": "collector",
    "entrypoint": "tests:Health",
    "description": "Reports what an HTTP health endpoint said.",
    "minimum_proofos_version": "0.1.0",
    "permissions": ["network", "submit_observation"],
    "network_scope": ["status.example.com"],
    "evidence_kinds": [KIND],
    "source_commit": "0" * 40,
})


class Health:
    """A plugin that genuinely saw a healthy service. Not an adversary."""

    manifest = MANIFEST

    def __init__(self, at: float) -> None:
        self._at = at

    def observe(self, request: ObservationRequest) -> Observation:
        return Observation(
            kind=request.kind,
            outcome=ObservationOutcome.HEALTHY,
            observed_at=self._at,
            detail="HTTP 200, status field 'ok'",
            status_code=200,
            response_digest=response_digest(BODY),
        )


class TheSameObservationDownTwoRoutesTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_700_000_000.0
        self.requirements = (Requirement(KIND, max_age_seconds=300),)
        self.observation = Health(self.now).observe(
            ObservationRequest(kind=KIND, target="https://status.example.com/health")
        )

    # -- route one: the plugin said so ------------------------------------------

    def test_a_plugin_cannot_label_its_own_output(self):
        # Before anything else: there is no field to put it in. The rest of this
        # route exists because an integrator might try to add one on the way out.
        self.assertFalse(hasattr(self.observation, "source"))
        self.assertNotIn("source", Observation.__dataclass_fields__)

    def test_the_honest_mapping_of_a_plugin_observation_abstains(self):
        # An integrator turning an Observation into Evidence has one truthful
        # option: it came from a component this process ran, so it is a report,
        # not an independent observation.
        evidence = Evidence(
            kind=self.observation.kind,
            value=self.observation.detail,
            source=EvidenceSource.EXECUTOR,
            collected_at=self.observation.observed_at,
            collector=MANIFEST.plugin_id,
        )
        decision = ProofOS().verify("Deployment complete.", self.requirements,
                                    [evidence], now=self.now)
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")

    def test_the_dishonest_mapping_is_refused_rather_than_evaluated(self):
        # The integrator who reaches for OBSERVED because the plugin "really did
        # observe it". True, and beside the point: what makes an observation
        # independent is who is able to vouch for it, not how it was obtained.
        evidence = Evidence(
            kind=self.observation.kind,
            value=self.observation.detail,
            source=EvidenceSource.OBSERVED,
            collected_at=self.observation.observed_at,
            collector=MANIFEST.plugin_id,
        )
        with self.assertRaises(ProvenanceNotDeclarable):
            ProofOS().verify("Deployment complete.", self.requirements,
                             [evidence], now=self.now)

    def test_installing_the_plugin_changes_nothing_about_trust(self):
        # The sentence the whole contract rests on, as an assertion. The plugin
        # is present, conformant, permitted and pinned, and the verdict for its
        # output is the same as it would be for any other self-report.
        self.assertTrue(MANIFEST.is_pinned)
        self.assertIn(KIND, MANIFEST.evidence_kinds)
        evidence = Evidence(kind=KIND, value=self.observation.detail,
                            source=EvidenceSource.EXECUTOR,
                            collected_at=self.now, collector=MANIFEST.plugin_id)
        decision = ProofOS().verify("Deployment complete.", self.requirements,
                                    [evidence], now=self.now)
        self.assertFalse(decision.verified)

    # -- route two: a collector vouched for it ----------------------------------

    def ingest_the_same_observation(self):
        """Sign and ingest exactly what the plugin saw."""
        signer = AttestationSigner.generate(COLLECTOR)
        ledger = EvidenceLedger()
        ledger.open_task(TASK, self.requirements)
        capability = ObservationCapability(ledger, COLLECTOR, (KIND,))
        ledger.seal()
        collectors = registry_for(COLLECTOR, signer.public_key_b64(),
                                  (KIND,), (PROFILE,))
        nonces = NonceLedger()
        ingestor = AttestationIngestor({COLLECTOR: capability}, collectors, nonces)
        nonce = ingestor.issue_nonce(EXECUTION, TASK, KIND)
        attestation = signer.sign(
            execution_id=EXECUTION,
            task_id=TASK,
            kind=KIND,
            profile_id=PROFILE,
            request_nonce=nonce,
            observed_at=self.observation.observed_at,
            outcome=Outcome.HEALTHY,
            status_code=self.observation.status_code,
            response_digest_value=self.observation.response_digest,
            detail=self.observation.detail,
        )
        result = ingestor.ingest(
            attestation.to_dict(),
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind=KIND,
            expected_profile=PROFILE,
            expected_nonce=nonce,
            max_age_seconds=300.0,
            now=self.now,
        )
        return ledger, result

    def test_the_authorized_route_verifies(self):
        ledger, result = self.ingest_the_same_observation()
        self.assertTrue(result.accepted, result.detail)
        decision = ProofOS().verify_recorded(ledger, TASK, "Deployment complete.",
                                             now=self.now)
        self.assertTrue(decision.verified)
        self.assertEqual([a.source for a in decision.accepted], ["OBSERVED"])

    def test_the_content_is_identical_down_both_routes(self):
        # The point of the whole file. If the two routes disagreed about what
        # was seen, the different verdicts would prove nothing -- they would
        # just be answers to different questions.
        _, result = self.ingest_the_same_observation()
        self.assertEqual(result.evidence.kind, self.observation.kind)
        self.assertIn(self.observation.detail, result.evidence.value)
        self.assertEqual(self.observation.status_code, 200)
        self.assertEqual(self.observation.response_digest, response_digest(BODY))

    def test_only_the_provenance_differs(self):
        _, result = self.ingest_the_same_observation()
        plugin_side = Evidence(kind=KIND, value=self.observation.detail,
                               source=EvidenceSource.EXECUTOR,
                               collected_at=self.observation.observed_at,
                               collector=MANIFEST.plugin_id)
        self.assertIs(result.evidence.source, EvidenceSource.OBSERVED)
        self.assertIs(plugin_side.source, EvidenceSource.EXECUTOR)
        self.assertEqual(result.evidence.kind, plugin_side.kind)
        self.assertEqual(result.evidence.collected_at, plugin_side.collected_at)

    # -- the boundary itself ----------------------------------------------------

    def test_the_plugins_identity_cannot_stand_in_for_the_collectors(self):
        # A plugin ships a collector; that does not make it one. The identity
        # that counts is the one whose key the sealed registry holds, and the
        # ledger refuses a write attributed to anyone else.
        from proofos.capabilities import CapabilityDenied

        ledger = EvidenceLedger()
        ledger.open_task(TASK, self.requirements)
        capability = ObservationCapability(ledger, COLLECTOR, (KIND,))
        ledger.seal()
        forged = Evidence(kind=KIND, value="probe HEALTHY",
                          source=EvidenceSource.OBSERVED, collected_at=self.now,
                          collector=MANIFEST.plugin_id)
        with self.assertRaises(CapabilityDenied):
            ledger.record(TASK, forged, capability._grant)

    def test_an_unsigned_replay_of_the_same_facts_is_rejected(self):
        # Same content again, this time without a signature the registry can
        # check. Content is not what earns provenance.
        signer = AttestationSigner.generate(COLLECTOR)
        ledger = EvidenceLedger()
        ledger.open_task(TASK, self.requirements)
        capability = ObservationCapability(ledger, COLLECTOR, (KIND,))
        ledger.seal()
        collectors = registry_for(COLLECTOR, signer.public_key_b64(),
                                  (KIND,), (PROFILE,))
        ingestor = AttestationIngestor({COLLECTOR: capability}, collectors,
                                       NonceLedger())
        nonce = ingestor.issue_nonce(EXECUTION, TASK, KIND)
        stranger = AttestationSigner.generate(COLLECTOR)
        attestation = stranger.sign(
            execution_id=EXECUTION, task_id=TASK, kind=KIND, profile_id=PROFILE,
            request_nonce=nonce, observed_at=self.observation.observed_at,
            outcome=Outcome.HEALTHY, status_code=200,
            response_digest_value=self.observation.response_digest,
            detail=self.observation.detail,
        )
        result = ingestor.ingest(
            attestation.to_dict(), execution_id=EXECUTION, task_id=TASK,
            expected_kind=KIND, expected_profile=PROFILE, expected_nonce=nonce,
            max_age_seconds=300.0, now=self.now,
        )
        self.assertFalse(result.accepted)
        decision = ProofOS().verify_recorded(ledger, TASK, "Deployment complete.",
                                             now=self.now)
        self.assertFalse(decision.verified)


if __name__ == "__main__":
    unittest.main()
