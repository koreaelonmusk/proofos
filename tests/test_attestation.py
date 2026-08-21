"""Attestation attacks.

Every test is an attempt to get the ingestion boundary to accept something it
should not: a forged signature, a field changed after signing, a genuine
attestation replayed somewhere it does not belong, or a caller trying to assert
trust rather than earn it.

These run in-process with a real Ed25519 keypair. Process separation itself is
proved in test_process_separation.py.
"""

import base64
import json
import time
import unittest
from dataclasses import replace

from proofos.attestation import (
    ATTESTATION_VERSION,
    AttestationSigner,
    AttestationVerifier,
    MalformedAttestation,
    ObservationAttestation,
    Outcome,
    SignatureInvalid,
    response_digest,
)
from proofos.capabilities import ObservationCapability
from proofos.collector_registry import (
    CollectorRecord,
    CollectorRegistry,
    CollectorScopeViolation,
    UnknownCollector,
    registry_for,
)
from proofos.ingestion import (
    AttestationIngestor,
    NonceLedger,
    RejectionReason,
)
from proofos.ledger import EvidenceLedger
from proofos.verifier import EvidenceSource, Requirement

COLLECTOR = "collector-http-v1"
PROFILE = "runtime-health-v1"
TASK = "BUG-4417"
EXECUTION = "exec_attest"


class AttestationTestCase(unittest.TestCase):
    def setUp(self):
        self.signer = AttestationSigner.generate(COLLECTOR)
        self.ledger = EvidenceLedger()
        self.ledger.open_task(TASK, (Requirement("runtime", max_age_seconds=300),))
        self.capability = ObservationCapability(self.ledger, COLLECTOR, ("runtime",))
        self.ledger.seal()
        self.collectors = registry_for(
            COLLECTOR, self.signer.public_key_b64(), ("runtime",), (PROFILE,)
        )
        self.nonces = NonceLedger()
        self.ingestor = AttestationIngestor(
            {COLLECTOR: self.capability}, self.collectors, self.nonces
        )

    def sign(self, nonce, **overrides):
        fields = dict(
            execution_id=EXECUTION,
            task_id=TASK,
            kind="runtime",
            profile_id=PROFILE,
            request_nonce=nonce,
            observed_at=time.time(),
            outcome=Outcome.HEALTHY,
            status_code=200,
            response_digest_value=response_digest(b'{"status":"ok"}'),
            detail="HEALTHY via runtime-health-v1",
        )
        fields.update(overrides)
        return self.signer.sign(**fields)

    def nonce(self, execution_id=EXECUTION, task_id=TASK, kind="runtime"):
        return self.ingestor.issue_nonce(execution_id, task_id, kind)

    def ingest(self, attestation, nonce, **overrides):
        args = dict(
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind="runtime",
            expected_profile=PROFILE,
            expected_nonce=nonce,
            max_age_seconds=300.0,
        )
        args.update(overrides)
        payload = (
            attestation.to_dict()
            if isinstance(attestation, ObservationAttestation)
            else attestation
        )
        return self.ingestor.ingest(payload, **args)


class HappyPathTests(AttestationTestCase):
    def test_a_valid_attestation_becomes_observed_evidence(self):
        nonce = self.nonce()
        result = self.ingest(self.sign(nonce), nonce)

        self.assertTrue(result.accepted)
        self.assertTrue(result.satisfies_requirement)
        self.assertIs(result.evidence.source, EvidenceSource.OBSERVED)
        self.assertEqual(result.evidence.collector, COLLECTOR)

    def test_source_is_derived_not_transmitted(self):
        # "source" is not a field on the wire at all. Trust is decided here,
        # after verification, and cannot be asserted by the sender.
        payload = self.sign(self.nonce()).to_dict()
        self.assertNotIn("source", payload)
        self.assertNotIn("valid", payload)


class SignatureAttackTests(AttestationTestCase):
    def assert_rejected(self, result, reason):
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, reason)
        self.assertEqual(self.ledger.evidence(TASK), ())

    def test_forged_signature_is_rejected(self):
        nonce = self.nonce()
        forged = replace(
            self.sign(nonce),
            signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
        )
        self.assert_rejected(self.ingest(forged, nonce), RejectionReason.SIGNATURE_INVALID)

    def test_signature_from_a_different_key_is_rejected(self):
        nonce = self.nonce()
        impostor = AttestationSigner.generate(COLLECTOR)
        attestation = impostor.sign(
            execution_id=EXECUTION,
            task_id=TASK,
            kind="runtime",
            profile_id=PROFILE,
            request_nonce=nonce,
            observed_at=time.time(),
            outcome=Outcome.HEALTHY,
            status_code=200,
            response_digest_value="d",
            detail="d",
        )
        self.assert_rejected(
            self.ingest(attestation, nonce), RejectionReason.SIGNATURE_INVALID
        )

    def test_truncated_signature_is_rejected(self):
        nonce = self.nonce()
        original = self.sign(nonce)
        raw = base64.b64decode(original.signature)
        short = replace(
            original, signature=base64.b64encode(raw[:32]).decode("ascii")
        )
        self.assert_rejected(self.ingest(short, nonce), RejectionReason.SIGNATURE_INVALID)

    def test_non_base64_signature_is_rejected(self):
        nonce = self.nonce()
        bad = replace(self.sign(nonce), signature="not base64 !!!")
        self.assert_rejected(self.ingest(bad, nonce), RejectionReason.SIGNATURE_INVALID)

    def test_empty_signature_is_rejected(self):
        nonce = self.nonce()
        self.assert_rejected(
            self.ingest(replace(self.sign(nonce), signature=""), nonce),
            RejectionReason.SIGNATURE_INVALID,
        )


class TamperAfterSigningTests(AttestationTestCase):
    """Every signed field must be covered. Changing any one must break it."""

    def tamper(self, nonce, **changes):
        payload = self.sign(nonce).to_dict()
        payload.update(changes)
        return payload

    def assert_tamper_rejected(self, nonce, expected=RejectionReason.SIGNATURE_INVALID, **changes):
        result = self.ingest(self.tamper(nonce, **changes), nonce)
        self.assertFalse(result.accepted, msg=f"accepted tampered {list(changes)}")
        self.assertIs(result.reason, expected)
        self.assertEqual(self.ledger.evidence(TASK), ())

    def test_status_code_change_breaks_the_signature(self):
        self.assert_tamper_rejected(self.nonce(), status_code=200 if False else 500)

    def test_outcome_change_breaks_the_signature(self):
        # The most valuable tamper: turning an unhealthy reading into a healthy
        # one. It must not survive.
        nonce = self.nonce()
        unhealthy = self.sign(
            nonce, outcome=Outcome.UNHEALTHY_STATUS, status_code=503
        ).to_dict()
        unhealthy["outcome"] = "HEALTHY"
        result = self.ingest(unhealthy, nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.SIGNATURE_INVALID)

    def test_execution_id_change_breaks_the_signature(self):
        nonce = self.nonce()
        self.assert_tamper_rejected(nonce, execution_id="exec_other")

    def test_task_id_change_breaks_the_signature(self):
        self.assert_tamper_rejected(self.nonce(), task_id="OTHER-TASK")

    def test_kind_change_is_caught_by_scope_before_the_signature(self):
        # Two layers cover this. The collector's scope is checked before the
        # signature, so a retargeted kind is refused as a scope violation
        # rather than a bad signature. Both refuse; the earlier one wins.
        self.assert_tamper_rejected(
            self.nonce(), expected=RejectionReason.COLLECTOR_SCOPE, kind="tests"
        )

    def test_kind_change_also_breaks_the_signature_on_its_own(self):
        # With scope widened so the first layer passes, the signature still
        # catches it -- the layers are independent, not one dressed as two.
        nonce = self.nonce()
        collectors = registry_for(
            COLLECTOR, self.signer.public_key_b64(), ("runtime", "tests"), (PROFILE,)
        )
        ingestor = AttestationIngestor(
            {COLLECTOR: self.capability}, collectors, self.nonces
        )
        payload = self.sign(nonce).to_dict()
        payload["kind"] = "tests"
        result = ingestor.ingest(
            payload,
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind="tests",
            expected_profile=PROFILE,
            expected_nonce=nonce,
            max_age_seconds=300.0,
        )
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.SIGNATURE_INVALID)

    def test_profile_change_is_caught_by_scope_before_the_signature(self):
        self.assert_tamper_rejected(
            self.nonce(),
            expected=RejectionReason.COLLECTOR_SCOPE,
            profile_id="other-profile-v1",
        )

    def test_profile_change_also_breaks_the_signature_on_its_own(self):
        nonce = self.nonce()
        collectors = registry_for(
            COLLECTOR,
            self.signer.public_key_b64(),
            ("runtime",),
            (PROFILE, "other-profile-v1"),
        )
        ingestor = AttestationIngestor(
            {COLLECTOR: self.capability}, collectors, self.nonces
        )
        payload = self.sign(nonce).to_dict()
        payload["profile_id"] = "other-profile-v1"
        result = ingestor.ingest(
            payload,
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind="runtime",
            expected_profile="other-profile-v1",
            expected_nonce=nonce,
            max_age_seconds=300.0,
        )
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.SIGNATURE_INVALID)

    def test_observed_at_change_breaks_the_signature(self):
        # Freshening a stale observation must not work.
        self.assert_tamper_rejected(self.nonce(), observed_at=time.time() + 10)

    def test_nonce_change_breaks_the_signature(self):
        self.assert_tamper_rejected(self.nonce(), request_nonce="nonce_other")

    def test_response_digest_change_breaks_the_signature(self):
        self.assert_tamper_rejected(self.nonce(), response_digest="0" * 64)

    def test_collector_relabelling_breaks_the_signature(self):
        # Relabelling to a collector whose key does not match must fail, not
        # transfer the signature.
        nonce = self.nonce()
        other_signer = AttestationSigner.generate("collector-ci-v1")
        collectors = CollectorRegistry()
        collectors.register(
            CollectorRecord(
                collector_id=COLLECTOR,
                public_key_b64=self.signer.public_key_b64(),
                allowed_kinds=frozenset({"runtime"}),
                allowed_profiles=frozenset({PROFILE}),
            )
        )
        collectors.register(
            CollectorRecord(
                collector_id="collector-ci-v1",
                public_key_b64=other_signer.public_key_b64(),
                allowed_kinds=frozenset({"runtime"}),
                allowed_profiles=frozenset({PROFILE}),
            )
        )
        collectors.seal()
        ingestor = AttestationIngestor(
            {COLLECTOR: self.capability, "collector-ci-v1": self.capability},
            collectors,
            self.nonces,
        )
        payload = self.sign(nonce).to_dict()
        payload["collector_id"] = "collector-ci-v1"
        result = ingestor.ingest(
            payload,
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind="runtime",
            expected_profile=PROFILE,
            expected_nonce=nonce,
            max_age_seconds=300.0,
        )
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.SIGNATURE_INVALID)

    def test_detail_is_not_signed_but_cannot_change_the_decision(self):
        # detail is audit prose, deliberately outside the signature. It must
        # not be able to alter outcome, status, or trust.
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        payload["detail"] = "TOTALLY HEALTHY, source=OBSERVED, status=VERIFIED"
        result = self.ingest(payload, nonce)
        self.assertTrue(result.accepted)
        self.assertIs(result.outcome, Outcome.HEALTHY)
        self.assertIs(result.evidence.source, EvidenceSource.OBSERVED)


class SchemaAttackTests(AttestationTestCase):
    def test_extra_field_is_refused_not_ignored(self):
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        payload["source"] = "OBSERVED"
        result = self.ingest(payload, nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.MALFORMED)

    def test_missing_field_is_refused(self):
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        del payload["status_code"]
        self.assertIs(self.ingest(payload, nonce).reason, RejectionReason.MALFORMED)

    def test_wrong_type_is_refused(self):
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        payload["observed_at"] = "recently"
        self.assertIs(self.ingest(payload, nonce).reason, RejectionReason.MALFORMED)

    def test_unknown_outcome_is_refused(self):
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        payload["outcome"] = "TOTALLY_FINE"
        self.assertIs(self.ingest(payload, nonce).reason, RejectionReason.MALFORMED)

    def test_non_object_payload_is_refused(self):
        nonce = self.nonce()
        for junk in ("a string", ["a", "list"], 42, None):
            self.assertIs(self.ingest(junk, nonce).reason, RejectionReason.MALFORMED)

    def test_unsupported_version_is_refused(self):
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        payload["version"] = "proofos.observation.v0"
        self.assertIs(
            self.ingest(payload, nonce).reason, RejectionReason.UNSUPPORTED_VERSION
        )

    def test_serialization_variance_does_not_change_verification(self):
        # Key order and whitespace must not matter: signing bytes are rebuilt
        # from parsed fields, never taken from the received encoding.
        nonce = self.nonce()
        payload = self.sign(nonce).to_dict()
        reordered = json.loads(
            json.dumps(dict(reversed(list(payload.items()))), indent=4)
        )
        self.assertTrue(self.ingest(reordered, nonce).accepted)


class ReplayTests(AttestationTestCase):
    def test_the_same_attestation_twice_is_idempotent_not_doubled(self):
        nonce = self.nonce()
        attestation = self.sign(nonce)
        first = self.ingest(attestation, nonce)
        second = self.ingest(attestation, nonce)

        self.assertTrue(first.accepted)
        self.assertTrue(second.accepted)
        self.assertTrue(second.duplicate)
        # One observation, not two.
        self.assertEqual(len(self.ledger.evidence(TASK)), 1)

    def test_a_different_attestation_cannot_reuse_a_spent_nonce(self):
        nonce = self.nonce()
        self.ingest(self.sign(nonce), nonce)
        second = self.ingest(self.sign(nonce, status_code=201), nonce)
        self.assertFalse(second.accepted)
        self.assertIs(second.reason, RejectionReason.NONCE_REUSED)

    def test_an_unissued_nonce_is_refused(self):
        attestation = self.sign("nonce_never_issued")
        result = self.ingest(attestation, "nonce_never_issued")
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.NONCE_UNKNOWN)

    def test_cross_execution_replay_is_refused(self):
        # A genuine attestation for another execution, correctly signed.
        other_nonce = self.nonce(execution_id="exec_other")
        stolen = self.sign(other_nonce, execution_id="exec_other")
        result = self.ingest(stolen, other_nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.EXECUTION_MISMATCH)

    def test_cross_task_replay_is_refused(self):
        other_nonce = self.nonce(task_id="OTHER-TASK")
        stolen = self.sign(other_nonce, task_id="OTHER-TASK")
        result = self.ingest(stolen, other_nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.TASK_MISMATCH)

    def test_a_nonce_from_another_task_cannot_be_spent_here(self):
        foreign = self.nonce(task_id="OTHER-TASK")
        attestation = self.sign(foreign)
        result = self.ingest(attestation, foreign)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.NONCE_BINDING)

    def test_an_attestation_answering_a_different_challenge_is_refused(self):
        issued = self.nonce()
        other = self.nonce()
        attestation = self.sign(other)
        result = self.ingest(attestation, issued)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.NONCE_BINDING)

    def test_a_rejected_attestation_does_not_burn_the_nonce(self):
        nonce = self.nonce()
        bad = replace(self.sign(nonce), signature=base64.b64encode(b"\x00" * 64).decode())
        self.assertFalse(self.ingest(bad, nonce).accepted)
        # The honest attestation can still be presented afterwards.
        self.assertTrue(self.ingest(self.sign(nonce), nonce).accepted)


class FreshnessTests(AttestationTestCase):
    def test_a_perfectly_signed_stale_attestation_is_refused(self):
        nonce = self.nonce()
        stale = self.sign(nonce, observed_at=time.time() - 10_000)
        result = self.ingest(stale, nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.STALE)

    def test_a_future_dated_attestation_is_refused(self):
        nonce = self.nonce()
        future = self.sign(nonce, observed_at=time.time() + 3600)
        result = self.ingest(future, nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.FUTURE_DATED)

    def test_small_clock_skew_is_tolerated(self):
        nonce = self.nonce()
        skewed = self.sign(nonce, observed_at=time.time() + 5)
        self.assertTrue(self.ingest(skewed, nonce).accepted)


class NegativeObservationTests(AttestationTestCase):
    """An authentic failure is evidence, and must be kept."""

    def test_an_unhealthy_observation_is_accepted_but_does_not_satisfy(self):
        nonce = self.nonce()
        unhealthy = self.sign(nonce, outcome=Outcome.UNHEALTHY_STATUS, status_code=503)
        result = self.ingest(unhealthy, nonce)

        self.assertTrue(result.accepted)
        self.assertFalse(result.satisfies_requirement)
        # Recorded, not discarded: a signed 503 is the most useful audit
        # evidence there is.
        recorded = self.ledger.evidence(TASK)
        self.assertEqual(len(recorded), 1)
        self.assertIs(recorded[0].source, EvidenceSource.OBSERVED)
        self.assertFalse(recorded[0].valid)

    def test_a_timeout_observation_is_authentic_and_unsatisfying(self):
        nonce = self.nonce()
        result = self.ingest(
            self.sign(nonce, outcome=Outcome.TIMEOUT, status_code=None), nonce
        )
        self.assertTrue(result.accepted)
        self.assertFalse(result.satisfies_requirement)

    def test_a_redirected_observation_does_not_satisfy(self):
        nonce = self.nonce()
        result = self.ingest(
            self.sign(nonce, outcome=Outcome.REDIRECTED, status_code=302), nonce
        )
        self.assertTrue(result.accepted)
        self.assertFalse(result.satisfies_requirement)


class CollectorIdentityTests(AttestationTestCase):
    def test_unknown_collector_is_refused(self):
        nonce = self.nonce()
        stranger = AttestationSigner.generate("collector-rogue-v1")
        attestation = stranger.sign(
            execution_id=EXECUTION,
            task_id=TASK,
            kind="runtime",
            profile_id=PROFILE,
            request_nonce=nonce,
            observed_at=time.time(),
            outcome=Outcome.HEALTHY,
            status_code=200,
            response_digest_value="d",
            detail="d",
        )
        result = self.ingest(attestation, nonce)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.UNKNOWN_COLLECTOR)

    def test_a_collector_outside_its_kind_scope_is_refused(self):
        collectors = registry_for(
            COLLECTOR, self.signer.public_key_b64(), ("tests",), (PROFILE,)
        )
        ingestor = AttestationIngestor(
            {COLLECTOR: self.capability}, collectors, self.nonces
        )
        nonce = ingestor.issue_nonce(EXECUTION, TASK, "runtime")
        result = ingestor.ingest(
            self.sign(nonce).to_dict(),
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind="runtime",
            expected_profile=PROFILE,
            expected_nonce=nonce,
            max_age_seconds=300.0,
        )
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.COLLECTOR_SCOPE)

    def test_a_collector_outside_its_profile_scope_is_refused(self):
        collectors = registry_for(
            COLLECTOR, self.signer.public_key_b64(), ("runtime",), ("other-v1",)
        )
        ingestor = AttestationIngestor(
            {COLLECTOR: self.capability}, collectors, self.nonces
        )
        nonce = ingestor.issue_nonce(EXECUTION, TASK, "runtime")
        result = ingestor.ingest(
            self.sign(nonce).to_dict(),
            execution_id=EXECUTION,
            task_id=TASK,
            expected_kind="runtime",
            expected_profile=PROFILE,
            expected_nonce=nonce,
            max_age_seconds=300.0,
        )
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.COLLECTOR_SCOPE)

    def test_an_inactive_collector_is_refused(self):
        collectors = CollectorRegistry()
        collectors.register(
            CollectorRecord(
                collector_id=COLLECTOR,
                public_key_b64=self.signer.public_key_b64(),
                allowed_kinds=frozenset({"runtime"}),
                allowed_profiles=frozenset({PROFILE}),
                active=False,
            )
        )
        collectors.seal()
        with self.assertRaises(UnknownCollector):
            collectors.get(COLLECTOR)

    def test_the_collector_registry_seals(self):
        with self.assertRaises(Exception):
            self.collectors.register(
                CollectorRecord(
                    collector_id="late-v1",
                    public_key_b64=self.signer.public_key_b64(),
                    allowed_kinds=frozenset({"runtime"}),
                    allowed_profiles=frozenset({PROFILE}),
                )
            )

    def test_a_malformed_public_key_is_refused_at_registration(self):
        for bad in ("not base64", base64.b64encode(b"short").decode()):
            with self.assertRaises(Exception):
                CollectorRecord(
                    collector_id="bad-v1",
                    public_key_b64=bad,
                    allowed_kinds=frozenset({"runtime"}),
                    allowed_profiles=frozenset({PROFILE}),
                )


class KeySeparationTests(unittest.TestCase):
    def test_a_verifier_cannot_sign(self):
        signer = AttestationSigner.generate(COLLECTOR)
        verifier = AttestationVerifier.from_b64(signer.public_key_b64())
        self.assertFalse(hasattr(verifier, "sign"))
        public = [n for n in dir(verifier) if not n.startswith("_")]
        self.assertEqual(public, ["from_b64", "from_bytes", "verify"])

    def test_the_signer_never_exports_the_private_key(self):
        signer = AttestationSigner.generate(COLLECTOR)
        public = {n for n in dir(signer) if not n.startswith("_")}
        self.assertEqual(
            public, {"collector_id", "generate", "public_key_b64", "public_key_bytes", "sign"}
        )

    def test_two_collectors_have_different_keys(self):
        a = AttestationSigner.generate(COLLECTOR)
        b = AttestationSigner.generate(COLLECTOR)
        self.assertNotEqual(a.public_key_b64(), b.public_key_b64())


if __name__ == "__main__":
    unittest.main()
