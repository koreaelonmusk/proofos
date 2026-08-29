"""A bundle may carry a signature. It may not carry permission to believe it.

These tests are about the carrying: the envelope survives the trip byte for
byte, the bundle digest covers it, the evidence record's own digest does not,
and nothing that must not travel travels.

The load-bearing one is the last class. ``portable_attestation.observed_value``
reconstructs the text a live ingestion would have recorded, and a reconstruction
that drifts from the real thing would fail open in the worst possible way -- so
it is pinned against the output of an actual ``AttestationIngestor``, not
against a string somebody typed here.
"""

from __future__ import annotations

import json
import unittest

from proofos import EvidenceLedger, ProofOS, Requirement
from proofos.attestation import AttestationSigner, Outcome, response_digest
from proofos.bundle import (
    BundleError,
    BundleIntegrityError,
    MAX_VALUE,
    SensitiveContentError,
    export_bundle,
    load_bundle,
)
from proofos.capabilities import ObservationCapability
from proofos.collector_registry import registry_for
from proofos.ingestion import AttestationIngestor, NonceLedger
from proofos.portable_attestation import observed_value

NOW = 1_700_000_000.0
KIND = "runtime_health"
PROFILE = "cloud-run-health"
CLAIM = "Deployment complete."
COLLECTOR = "proofos-collector"
TASK = "DEPLOY-9"
EXECUTION = "exec_1"
HORIZON = 900.0

#: A PEM header is the shape of the thing that must never travel.
PRIVATE_KEY_PEM = ("-----BEGIN PRIVATE KEY-----\n"
                   "MC4CAQAwBQYDK2VwBCIEIExampleExampleExample\n"
                   "-----END PRIVATE KEY-----")


class Observatory:
    """The real thing: a signer, a registry, and the authoritative ingestor."""

    def __init__(self, collector: str = COLLECTOR, kinds=(KIND,),
                 profiles=(PROFILE,)):
        self.signer = AttestationSigner.generate(collector)
        self.registry = registry_for(collector, self.signer.public_key_b64(),
                                     kinds, profiles)
        self.ledger = EvidenceLedger()
        self.ledger.open_task(TASK, (Requirement(KIND, max_age_seconds=HORIZON),))
        self.capability = ObservationCapability(self.ledger, collector, kinds)
        self.nonces = NonceLedger()
        self.ledger.seal()
        self.ingestor = AttestationIngestor({collector: self.capability},
                                            self.registry, self.nonces)

    def sign(self, *, kind=KIND, detail="anon 403 -> authed 200",
             outcome=Outcome.HEALTHY, observed_at=NOW - 10, nonce=None,
             task_id=TASK, execution_id=EXECUTION):
        nonce = nonce or self.ingestor.issue_nonce(execution_id, task_id, kind)
        return self.signer.sign(
            execution_id=execution_id, task_id=task_id, kind=kind,
            profile_id=PROFILE, request_nonce=nonce, observed_at=observed_at,
            outcome=outcome, status_code=200,
            response_digest_value=response_digest(b"ok"), detail=detail)

    def ingest(self, attestation, *, now=NOW):
        """Through the authoritative path, exactly as production does."""
        result = self.ingestor.ingest(
            attestation.to_dict(), attestation.execution_id, attestation.task_id,
            attestation.kind, PROFILE, attestation.request_nonce, HORIZON, now=now)
        assert result.accepted, result.reason
        return result.evidence

    def observed(self, **kwargs):
        attestation = self.sign(**kwargs)
        return attestation, self.ingest(attestation)


def bundle_from(obs: Observatory, evidence, attestation, **overrides):
    decision = ProofOS().verify_recorded(obs.ledger, TASK, CLAIM, now=NOW)
    kwargs = dict(claim=CLAIM, requirements=obs.ledger.requirements(TASK),
                  evidence=(evidence,), task_id=TASK, execution_id=EXECUTION,
                  verification_time=NOW, created_at=NOW + 1,
                  actor_id="deploy-agent", policy_id="strict-v1",
                  recorded_verdict=str(decision.status),
                  recorded_reason=str(decision.reason),
                  attestations={evidence.content_hash: attestation.to_dict()})
    kwargs.update(overrides)
    return export_bundle(**kwargs)


class TheEnvelopeSurvivesTheTripTests(unittest.TestCase):
    def setUp(self):
        self.obs = Observatory()
        self.attestation, self.evidence = self.obs.observed()
        self.bundle = bundle_from(self.obs, self.evidence, self.attestation)

    def test_the_envelope_round_trips_field_for_field(self):
        carried = load_bundle(self.bundle.to_json()).evidence[0].attestation
        self.assertEqual(carried, self.attestation.to_dict())

    def test_the_signature_travels_with_it(self):
        carried = load_bundle(self.bundle.to_json()).evidence[0].attestation
        self.assertEqual(carried["signature"], self.attestation.signature)
        self.assertEqual(carried["collector_id"], COLLECTOR)

    def test_a_record_without_one_carries_an_empty_envelope(self):
        plain = export_bundle(claim=CLAIM,
                              requirements=self.obs.ledger.requirements(TASK),
                              evidence=(self.evidence,), task_id=TASK,
                              verification_time=NOW, created_at=NOW + 1)
        self.assertEqual(load_bundle(plain.to_json()).evidence[0].attestation, {})


class ThreeLayersNoneSubstitutingTests(unittest.TestCase):
    """§11. Bundle digest, attestation signature, trust anchor, verdict.

    Each answers a different question, and the tests here are about the first
    two not being confused for each other.
    """

    def setUp(self):
        self.obs = Observatory()
        self.attestation, self.evidence = self.obs.observed()
        self.bundle = bundle_from(self.obs, self.evidence, self.attestation)

    def test_the_bundle_digest_covers_the_envelope(self):
        raw = json.loads(self.bundle.to_json())
        raw["evidence"][0]["attestation"]["signature"] = "AAAA"
        with self.assertRaises(BundleIntegrityError):
            load_bundle(raw).require_intact()

    def test_the_record_digest_does_not_cover_the_envelope(self):
        # It must not: the record digest has to agree with the kernel's own
        # digest over the same Evidence, and the kernel has never heard of an
        # attestation. Adding it here would make every attested record look
        # tampered to the verifier.
        record = load_bundle(self.bundle.to_json()).evidence[0]
        self.assertTrue(record.intact)
        self.assertEqual(record.content_hash, self.evidence.content_hash)

    def test_an_envelope_must_be_flat(self):
        # Nesting is somewhere to hide a field the signature never covered.
        raw = json.loads(self.bundle.to_json())
        raw["evidence"][0]["attestation"]["extra"] = {"trusted": True}
        with self.assertRaises(BundleError) as caught:
            load_bundle(raw)
        self.assertIn("flat", str(caught.exception))

    def test_an_oversized_envelope_is_refused(self):
        raw = json.loads(self.bundle.to_json())
        raw["evidence"][0]["attestation"] = {f"f{i}": i for i in range(64)}
        with self.assertRaises(BundleError):
            load_bundle(raw)
        raw["evidence"][0]["attestation"] = {"detail": "x" * (MAX_VALUE + 1)}
        with self.assertRaises(BundleError):
            load_bundle(raw)

    def test_the_serializer_does_not_know_the_attestation_schema(self):
        # Deliberate. A signed payload parsed in two places is a signed payload
        # that will one day be parsed two ways, so bundle.py carries the
        # envelope opaquely and the strict parse happens against the signature.
        import ast
        import pathlib

        # Read from the syntax tree with docstrings removed and identifiers
        # matched exactly: `MAX_ENVELOPE_FIELDS` is not `ENVELOPE_FIELDS`, and a
        # substring check that cannot tell them apart is a check that will one
        # day be silenced rather than fixed.
        tree = ast.parse((pathlib.Path(__file__).resolve().parent.parent
                          / "proofos" / "bundle.py").read_text(encoding="utf-8"))
        docstrings = {ast.get_docstring(n, clean=False) for n in ast.walk(tree)
                      if isinstance(n, (ast.Module, ast.ClassDef,
                                        ast.FunctionDef))}
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names.add(getattr(node, "module", "") or "")
                names.update(a.name for a in node.names)
        literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                    and isinstance(n.value, str)} - docstrings

        # `attestation` itself is the record's field name and belongs here.
        # What must not appear is knowledge of what is *inside* one.
        for forbidden in ("SIGNED_FIELDS", "ENVELOPE_FIELDS",
                          "ObservationAttestation", "AttestationVerifier",
                          "AttestationSigner", "cryptography"):
            self.assertNotIn(forbidden, names, f"bundle.py knows {forbidden}")
        for forbidden in ("collector_id", "request_nonce", "response_digest",
                          "observed_at", "status_code"):
            self.assertNotIn(forbidden, literals,
                             f"bundle.py names the attestation field "
                             f"{forbidden}")


class NoPrivateKeyEscapesTests(unittest.TestCase):
    """§24. The hard one."""

    def setUp(self):
        self.obs = Observatory()

    def test_a_private_key_in_the_envelope_is_refused(self):
        attestation, evidence = self.obs.observed()
        raw = attestation.to_dict()
        raw["detail"] = PRIVATE_KEY_PEM
        with self.assertRaises(SensitiveContentError):
            bundle_from(self.obs, evidence, attestation,
                        attestations={evidence.content_hash: raw})

    def test_a_private_key_in_an_evidence_value_is_refused(self):
        attestation, _ = self.obs.observed(detail=PRIVATE_KEY_PEM)
        # The value is derived from the detail, so this is the same leak
        # arriving through the evidence rather than the envelope.
        ledger = EvidenceLedger()
        ledger.open_task(TASK, (Requirement(KIND, max_age_seconds=HORIZON),))
        capability = ObservationCapability(ledger, COLLECTOR, (KIND,))
        ledger.seal()
        evidence = capability.record_observation(
            TASK, kind=KIND, value=observed_value(attestation), satisfies=True,
            collected_at=NOW - 10)
        with self.assertRaises(SensitiveContentError):
            export_bundle(claim=CLAIM, requirements=ledger.requirements(TASK),
                          evidence=(evidence,), task_id=TASK,
                          verification_time=NOW, created_at=NOW + 1)

    def test_the_signer_never_exposes_its_private_half(self):
        # Not a bundle property -- a property of the thing a bundle could reach.
        signer = self.obs.signer
        for forbidden in ("private_key", "private_bytes", "export_key",
                          "secret", "_key_bytes"):
            self.assertFalse(hasattr(signer, forbidden))
        self.assertNotIn(signer.public_key_b64(), PRIVATE_KEY_PEM)


class TheReconstructionMatchesTheRealIngestionTests(unittest.TestCase):
    """The anti-drift pin.

    ``observed_value`` mirrors a line inside trusted-core ingestion. Mirrors
    drift. So rather than asserting it against a string written here, assert it
    against what an actual ``AttestationIngestor`` actually recorded -- if the
    kernel changes that construction, this fails, which is the point.
    """

    def test_it_reproduces_what_the_ingestor_recorded(self):
        obs = Observatory()
        attestation, evidence = obs.observed(detail="anon 403 -> authed 200")
        self.assertEqual(observed_value(attestation), evidence.value)

    def test_it_reproduces_it_for_an_unhealthy_observation_too(self):
        # A collector reports UNHEALTHY_STATUS with equal authority, and the
        # text it produces is a different branch of the same construction.
        obs = Observatory()
        attestation, evidence = obs.observed(outcome=Outcome.UNHEALTHY_STATUS,
                                             detail="503 from the service")
        self.assertEqual(observed_value(attestation), evidence.value)
        self.assertFalse(evidence.valid)

    def test_the_detail_is_the_part_the_signature_does_not_cover(self):
        # Stated as a test because it is a real limit of the existing contract:
        # `detail` is in the envelope and not in SIGNED_FIELDS, so it has
        # bundle-level integrity and not signature-level integrity.
        from proofos.attestation import ENVELOPE_FIELDS, SIGNED_FIELDS

        self.assertIn("detail", ENVELOPE_FIELDS)
        self.assertNotIn("detail", SIGNED_FIELDS)
        obs = Observatory()
        attestation = obs.sign(detail="original")
        edited = attestation.to_dict() | {"detail": "edited"}
        from proofos.attestation import ObservationAttestation

        # The signature still verifies, because it never covered this field.
        obs.registry.get(COLLECTOR).verifier.verify(
            ObservationAttestation.from_dict(edited))
        # And the reconstruction changes, which is what the binding check in
        # replay compares against the recorded value.
        self.assertNotEqual(observed_value(ObservationAttestation.from_dict(edited)),
                            observed_value(attestation))


if __name__ == "__main__":
    unittest.main()
