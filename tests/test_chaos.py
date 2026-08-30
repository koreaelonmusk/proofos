"""Break the assumptions on purpose, and check what breaks with them.

The rest of the suite asks whether ProofOS answers correctly when its inputs are
hostile. This asks something narrower and nastier: whether it fails *safely* when
its own machinery is corrupted, truncated, raced, or run against a clock that
lies. The difference matters because every one of these is a state a real system
reaches without anybody attacking it.

The invariant under test is one sentence: no combination of broken assumptions
produces VERIFIED. Wrong answers, crashes and refusals are all acceptable
outcomes; a certificate is not.
"""

from __future__ import annotations

import concurrent.futures
import json
import math
import unittest

from proofos import (
    Evidence,
    EvidenceLedger,
    EvidenceSource,
    ProofOS,
    Requirement,
    UnknownTaskError,
)
from proofos.attestation import (
    AttestationSigner,
    AttestationVerifier,
    ObservationAttestation,
    Outcome,
    SignatureInvalid,
    response_digest,
)
from proofos.bundle import BundleError, BundleIntegrityError, export_bundle, load_bundle
from proofos.capabilities import ObservationCapability
from proofos.collector_registry import (
    CollectorIdentityError,
    CollectorRecord,
    CollectorRegistry,
    registry_for,
)
from proofos.failures import CapabilityDenied
from proofos.ingestion import AttestationIngestor, NonceLedger, RejectionReason
from proofos.integrity import content_hash
from proofos.portable_attestation import PortableAttestationRejected, verify_portable
from proofos.replay import ReplayError, re_evaluate_at, replay_historical

NOW = 1_700_000_000.0
KIND = "runtime_health"
PROFILE = "cloud-run-health"
CLAIM = "Deployment complete."
COLLECTOR = "proofos-collector"
TASK = "DEPLOY-9"
EXECUTION = "exec_1"
HORIZON = 900.0


class Rig:
    """A working, honest setup — so every test below breaks exactly one thing."""

    def __init__(self, collector: str = COLLECTOR, kinds=(KIND,)):
        self.signer = AttestationSigner.generate(collector)
        self.registry = registry_for(collector, self.signer.public_key_b64(),
                                     kinds, (PROFILE,))
        self.ledger = EvidenceLedger()
        self.ledger.open_task(TASK, (Requirement(KIND, max_age_seconds=HORIZON),))
        self.capability = ObservationCapability(self.ledger, collector, kinds)
        self.nonces = NonceLedger()
        self.ledger.seal()
        self.ingestor = AttestationIngestor({collector: self.capability},
                                            self.registry, self.nonces)

    def sign(self, *, signer=None, kind=KIND, observed_at=NOW - 10,
             outcome=Outcome.HEALTHY, task_id=TASK, execution_id=EXECUTION,
             nonce=None, detail="anon 403 -> authed 200"):
        nonce = nonce or self.ingestor.issue_nonce(execution_id, task_id, kind)
        return (signer or self.signer).sign(
            execution_id=execution_id, task_id=task_id, kind=kind,
            profile_id=PROFILE, request_nonce=nonce, observed_at=observed_at,
            outcome=outcome, status_code=200,
            response_digest_value=response_digest(b"ok"), detail=detail)

    def ingest(self, attestation, *, now=NOW):
        return self.ingestor.ingest(
            attestation.to_dict(), attestation.execution_id, attestation.task_id,
            attestation.kind, PROFILE, attestation.request_nonce, HORIZON, now=now)

    def observed(self):
        attestation = self.sign()
        result = self.ingest(attestation)
        assert result.accepted, result.reason
        return attestation, result.evidence

    def bundle(self, attestation, attested_record, **overrides):
        """`attested_record` is the record the attestation belongs to.

        Named distinctly from the exported set so a test can override
        ``evidence=`` without colliding with it.
        """
        decision = ProofOS().verify_recorded(self.ledger, TASK, CLAIM, now=NOW)
        kwargs = dict(
            claim=CLAIM, requirements=self.ledger.requirements(TASK),
            evidence=(attested_record,), task_id=TASK, execution_id=EXECUTION,
            verification_time=NOW, created_at=NOW + 1,
            recorded_verdict=str(decision.status),
            recorded_reason=str(decision.reason),
            attestations={attested_record.content_hash: attestation.to_dict()})
        kwargs.update(overrides)
        return load_bundle(export_bundle(**kwargs).to_json())


def reseal(bundle, mutate) -> dict:
    """Edit a serialized bundle and recompute its digest, as a forger would."""
    raw = json.loads(bundle.to_json())
    mutate(raw)
    raw.pop("digest")
    return {**raw, "digest": content_hash(raw)}


class TrustAnchorCorruptionTests(unittest.TestCase):
    """1. The trust root is an input. Corrupt inputs must not certify."""

    def setUp(self):
        self.rig = Rig()
        self.attestation, self.evidence = self.rig.observed()
        self.proof = self.rig.bundle(self.attestation, self.evidence)

    def test_a_key_that_is_not_base64_is_refused_at_registration(self):
        with self.assertRaises(CollectorIdentityError):
            CollectorRecord(collector_id=COLLECTOR, public_key_b64="not base64!!",
                            allowed_kinds=frozenset({KIND}),
                            allowed_profiles=frozenset({PROFILE}))

    def test_a_key_of_the_wrong_length_is_refused_at_registration(self):
        # Truncation is the realistic corruption: a config file cut short, a
        # secret manager returning a partial value.
        import base64

        short = base64.b64encode(b"\x01" * 31).decode("ascii")
        with self.assertRaises(CollectorIdentityError) as caught:
            CollectorRecord(collector_id=COLLECTOR, public_key_b64=short,
                            allowed_kinds=frozenset({KIND}),
                            allowed_profiles=frozenset({PROFILE}))
        self.assertIn("32 bytes", str(caught.exception))

    def test_an_empty_registry_certifies_nothing(self):
        empty = CollectorRegistry().seal()
        result = replay_historical(self.proof, trust_anchor=empty)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["UNKNOWN_COLLECTOR"])

    def test_a_registry_holding_a_valid_but_wrong_key_certifies_nothing(self):
        stranger = AttestationSigner.generate(COLLECTOR)
        wrong = registry_for(COLLECTOR, stranger.public_key_b64(), (KIND,),
                             (PROFILE,))
        result = replay_historical(self.proof, trust_anchor=wrong)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["SIGNATURE_INVALID"])

    def test_a_registry_cannot_be_widened_after_sealing(self):
        with self.assertRaises(CollectorIdentityError):
            self.rig.registry.register(CollectorRecord(
                collector_id="late-arrival",
                public_key_b64=self.rig.signer.public_key_b64(),
                allowed_kinds=frozenset({KIND}),
                allowed_profiles=frozenset({PROFILE})))

    def test_a_non_registry_object_passed_as_a_trust_anchor_does_not_certify(self):
        # Somebody passes a dict, a namespace, or stray configuration. Before
        # this test that reached registry.require_scope and raised
        # AttributeError out of replay -- fail-closed, but as a crash rather
        # than a refusal, and a caller could not tell a bad anchor from a bug.
        for impostor in ({"proofos-collector": "trusted"}, object(), 0, "registry"):
            with self.subTest(anchor=type(impostor).__name__):
                result = replay_historical(self.proof, trust_anchor=impostor)
                self.assertEqual(result.status, "ABSTAIN")
                self.assertEqual([r[1] for r in result.rejected],
                                 ["MALFORMED_TRUST_ANCHOR"])


class CollectorKeyCompromiseTests(unittest.TestCase):
    """2. Assume the key is stolen. What still holds, and what does not."""

    def setUp(self):
        self.rig = Rig()
        self.attacker = AttestationSigner.generate(COLLECTOR)

    def test_the_stolen_key_does_produce_accepted_evidence(self):
        # Stated as a passing test rather than hidden: if an attacker holds the
        # signing key, they are the collector as far as any verifier can tell.
        # This is the boundary of what signatures buy, and the threat model says
        # so out loud.
        compromised = registry_for(COLLECTOR, self.attacker.public_key_b64(),
                                   (KIND,), (PROFILE,))
        forged = self.rig.sign(signer=self.attacker)
        observation = verify_portable(forged.to_dict(), registry=compromised,
                                      now=NOW)
        self.assertEqual(observation.collector_id, COLLECTOR)

    def test_rotating_the_key_invalidates_everything_signed_with_the_old_one(self):
        old = self.rig.sign()
        rotated = AttestationSigner.generate(COLLECTOR)
        registry = registry_for(COLLECTOR, rotated.public_key_b64(), (KIND,),
                                (PROFILE,))
        with self.assertRaises(PortableAttestationRejected) as caught:
            verify_portable(old.to_dict(), registry=registry, now=NOW)
        self.assertEqual(caught.exception.reason, "SIGNATURE_INVALID")

    def test_deactivating_a_collector_stops_it_mid_flight(self):
        registry = CollectorRegistry()
        registry.register(CollectorRecord(
            collector_id=COLLECTOR, public_key_b64=self.rig.signer.public_key_b64(),
            allowed_kinds=frozenset({KIND}), allowed_profiles=frozenset({PROFILE}),
            active=False))
        registry.seal()
        with self.assertRaises(PortableAttestationRejected) as caught:
            verify_portable(self.rig.sign().to_dict(), registry=registry, now=NOW)
        self.assertEqual(caught.exception.reason, "UNKNOWN_COLLECTOR")

    def test_a_stolen_key_still_cannot_widen_its_own_scope(self):
        # The key authenticates. The registry authorizes, and it is not the
        # attacker's to edit.
        compromised = registry_for(COLLECTOR, self.attacker.public_key_b64(),
                                   (KIND,), (PROFILE,))
        overreach = self.rig.sign(signer=self.attacker, kind="task_outcome")
        with self.assertRaises(PortableAttestationRejected) as caught:
            verify_portable(overreach.to_dict(), registry=compromised, now=NOW)
        self.assertEqual(caught.exception.reason, "COLLECTOR_SCOPE_VIOLATION")


class EvidenceTamperingTests(unittest.TestCase):
    """3. Records that changed after they were written."""

    def test_a_mutated_record_fails_the_whole_set_closed(self):
        ledger = EvidenceLedger()
        ledger.open_task(TASK, (Requirement(KIND, max_age_seconds=HORIZON),))
        capability = ObservationCapability(ledger, COLLECTOR, (KIND,))
        ledger.seal()
        good = capability.record_observation(TASK, kind=KIND, value="probe 200",
                                             satisfies=True, collected_at=NOW)
        broken = Evidence(kind=KIND, value="probe 200", source=EvidenceSource.MODEL,
                          collected_at=NOW, collector="agent",
                          content_hash="0" * 64)
        decision = ProofOS().verify(CLAIM,
                                    (Requirement(KIND, max_age_seconds=HORIZON),),
                                    (broken,), now=NOW)
        self.assertEqual(str(decision.reason), "EVIDENCE_TAMPERED")
        self.assertFalse(decision.verified)
        self.assertTrue(good.intact)

    def test_one_bad_record_poisons_a_set_that_would_otherwise_verify(self):
        # Deliberate: a set containing a record that no longer matches its digest
        # is not a set with one bad item, it is a set nobody can vouch for.
        rig = Rig()
        _, evidence = rig.observed()
        broken = Evidence(kind=KIND, value="x", source=EvidenceSource.EXECUTOR,
                          collected_at=NOW, collector="agent",
                          content_hash="0" * 64)
        rig.ledger.record(TASK, broken)
        with self.assertRaises(Exception) as caught:
            rig.ledger.evidence(TASK)
        self.assertIn("content hash", str(caught.exception))
        self.assertTrue(evidence.intact)


class BundleCorruptionTests(unittest.TestCase):
    """4. Truncation, reordering, duplication, absurd sizes."""

    def setUp(self):
        self.rig = Rig()
        self.attestation, self.evidence = self.rig.observed()
        self.proof = self.rig.bundle(self.attestation, self.evidence)
        self.text = self.proof.to_json()

    def test_every_truncation_is_refused_rather_than_partially_read(self):
        for fraction in (0.1, 0.25, 0.5, 0.75, 0.9, 0.99):
            cut = self.text[:int(len(self.text) * fraction)]
            with self.subTest(fraction=fraction):
                with self.assertRaises(BundleError):
                    load_bundle(cut)

    def test_a_byte_flipped_anywhere_is_caught_by_the_digest_or_the_parser(self):
        for position in range(0, len(self.text), max(1, len(self.text) // 40)):
            damaged = (self.text[:position]
                       + ("0" if self.text[position] != "0" else "1")
                       + self.text[position + 1:])
            with self.subTest(position=position):
                try:
                    loaded = load_bundle(damaged)
                except BundleError:
                    continue                       # refused at the parser
                self.assertFalse(loaded.intact,    # or refused at the digest
                                 f"a flipped byte at {position} went unnoticed")

    def test_reordering_the_evidence_changes_the_digest(self):
        rig = Rig()
        attestation, evidence = rig.observed()
        second = rig.capability.record_observation(
            TASK, kind=KIND, value="probe 2 -> 200", satisfies=True,
            collected_at=NOW - 5)
        proof = rig.bundle(attestation, evidence, evidence=(evidence, second))
        shuffled = reseal(proof, lambda raw: raw["evidence"].reverse())
        # Resealed, so integrity passes -- and the digest of the original no
        # longer matches, which is what an out-of-band digest is for.
        self.assertNotEqual(load_bundle(shuffled).digest, proof.digest)

    def test_duplicating_a_record_does_not_multiply_its_weight(self):
        proof = reseal(self.proof,
                       lambda raw: raw["evidence"].append(dict(raw["evidence"][0])))
        result = replay_historical(load_bundle(proof), trust_anchor=self.rig.registry)
        # Two copies of one observation are one observation, seen twice.
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(len(result.reinstated), 2)
        stale = re_evaluate_at(load_bundle(proof), NOW + HORIZON + 1,
                               trust_anchor=self.rig.registry)
        self.assertEqual(stale.reason, "EVIDENCE_STALE")

    def test_an_absurd_record_count_is_refused_before_it_is_parsed(self):
        proof = reseal(self.proof,
                       lambda raw: raw.__setitem__("evidence",
                                                   raw["evidence"] * 5000))
        with self.assertRaises(BundleError) as caught:
            load_bundle(proof)
        self.assertIn("more than", str(caught.exception))

    def test_deeply_nested_json_is_refused(self):
        proof = json.loads(self.text)
        nest = {"a": 1}
        for _ in range(200):
            nest = {"a": nest}
        proof["evidence"][0]["attestation"] = nest
        with self.assertRaises(BundleError):
            load_bundle(proof)


class CapabilityEscalationTests(unittest.TestCase):
    """5. Reaching the ledger is not the same as being allowed to write."""

    def setUp(self):
        self.ledger = EvidenceLedger()
        self.ledger.open_task(TASK, (Requirement(KIND, max_age_seconds=HORIZON),))
        self.grant = self.ledger.grant_observation(COLLECTOR, (KIND,))
        self.ledger.seal()

    def observation(self, **overrides):
        spec = {"kind": KIND, "value": "probe 200",
                "source": EvidenceSource.OBSERVED, "collected_at": NOW,
                "collector": COLLECTOR}
        spec.update(overrides)
        return Evidence(**spec)

    def test_writing_observed_without_a_grant_is_denied(self):
        with self.assertRaises(CapabilityDenied):
            self.ledger.record(TASK, self.observation())

    def test_a_grant_from_another_ledger_is_denied(self):
        other = EvidenceLedger()
        other.open_task(TASK, (Requirement(KIND),))
        foreign = other.grant_observation(COLLECTOR, (KIND,))
        with self.assertRaises(CapabilityDenied) as caught:
            self.ledger.record(TASK, self.observation(), foreign)
        self.assertIn("not issued by this ledger", str(caught.exception))

    def test_a_grant_for_another_kind_is_denied(self):
        with self.assertRaises(CapabilityDenied):
            self.ledger.record(TASK, self.observation(kind="task_outcome"),
                               self.grant)

    def test_a_collector_cannot_write_under_another_identity(self):
        with self.assertRaises(CapabilityDenied) as caught:
            self.ledger.record(TASK, self.observation(collector="someone-else"),
                               self.grant)
        self.assertIn("own identity", str(caught.exception))

    def test_a_forged_grant_object_is_denied(self):
        class Forgery:
            _issuer = object()
            collector_id = COLLECTOR
            kinds = frozenset({KIND})

        with self.assertRaises(CapabilityDenied):
            self.ledger.record(TASK, self.observation(), Forgery())

    def test_no_further_grants_after_sealing(self):
        with self.assertRaises(CapabilityDenied):
            self.ledger.grant_observation("late-collector", (KIND,))

    def test_an_unknown_task_cannot_be_opened_by_writing_to_it(self):
        with self.assertRaises(UnknownTaskError):
            self.ledger.record("NEVER-OPENED", self.observation(), self.grant)


class ClockFailureTests(unittest.TestCase):
    """8. A clock that lies, runs backwards, or returns nonsense."""

    def setUp(self):
        self.rig = Rig()
        self.attestation, self.evidence = self.rig.observed()
        self.proof = self.rig.bundle(self.attestation, self.evidence)

    def test_a_future_dated_observation_is_refused_at_ingestion(self):
        ahead = self.rig.sign(observed_at=NOW + 3600)
        result = self.rig.ingest(ahead)
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, RejectionReason.FUTURE_DATED)

    def test_a_clock_that_runs_backwards_does_not_certify_more(self):
        # Verifying against an earlier instant must not resurrect anything.
        for offset in (0, -HORIZON, -10 * HORIZON, -10 ** 6):
            with self.subTest(offset=offset):
                result = re_evaluate_at(self.proof, NOW + offset,
                                        trust_anchor=self.rig.registry)
                self.assertIn(result.status, {"VERIFIED", "ABSTAIN"})
                if offset < -HORIZON:
                    # The observation is now in the future relative to "now".
                    self.assertEqual(result.status, "ABSTAIN")

    def test_non_finite_times_are_refused_rather_than_compared(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(now=bad):
                result = re_evaluate_at(self.proof, bad,
                                        trust_anchor=self.rig.registry)
                # NaN comparisons are all false, which is exactly how a
                # freshness check quietly stops checking. The answer must not
                # be VERIFIED under any of these.
                self.assertEqual(result.status, "ABSTAIN")

    def test_a_bundle_cannot_carry_a_non_finite_timestamp(self):
        for field in ("created_at", "verification_time"):
            with self.subTest(field=field):
                with self.assertRaises(BundleError):
                    load_bundle(reseal(self.proof,
                                       lambda raw: raw.__setitem__(field, 1e999)))


class ConcurrencyTests(unittest.TestCase):
    """7. Several readers, one ledger, one answer."""

    def test_concurrent_verification_of_one_ledger_agrees(self):
        rig = Rig()
        rig.observed()
        proofos = ProofOS()

        def decide():
            decision = proofos.verify_recorded(rig.ledger, TASK, CLAIM, now=NOW)
            return str(decision.status), str(decision.reason)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            answers = set(pool.map(lambda _: decide(), range(64)))
        self.assertEqual(answers, {("VERIFIED", "NONE")})

    def test_concurrent_replay_of_one_bundle_agrees(self):
        rig = Rig()
        attestation, evidence = rig.observed()
        proof = rig.bundle(attestation, evidence)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            answers = set(pool.map(
                lambda _: replay_historical(proof, trust_anchor=rig.registry).status,
                range(64)))
        self.assertEqual(answers, {"VERIFIED"})

    def test_a_nonce_survives_a_concurrent_stampede_exactly_once(self):
        rig = Rig()
        attestation = rig.sign()
        # Differing in a *signed* field. An earlier version of this test varied
        # `detail`, which the attestation contract does not sign -- so both
        # envelopes carried the identical signature and the nonce ledger was
        # right to call them one attestation. See the test below.
        different = rig.sign(nonce=attestation.request_nonce,
                             outcome=Outcome.UNHEALTHY_STATUS)

        # The same attestation twice is a retry. A different one against a spent
        # nonce is an attack, and exactly one of these may win.
        outcomes = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for future in [pool.submit(rig.ingest, a)
                           for a in (attestation, different, attestation, different)]:
                outcomes.append(future.result())
        accepted = [o for o in outcomes if o.accepted]
        rejected = [o for o in outcomes if not o.accepted]
        self.assertTrue(accepted, "no attestation was accepted at all")
        self.assertTrue(rejected, "a spent nonce accepted a different attestation")
        self.assertTrue(all(o.reason is RejectionReason.NONCE_REUSED
                            for o in rejected))


class TheUnsignedDetailFieldTests(unittest.TestCase):
    """A documented limit of the attestation contract, pinned as behaviour.

    `detail` is in the envelope and not in SIGNED_FIELDS, so two envelopes that
    differ only there carry the same signature. Recorded here rather than left
    to be discovered: the consequences are bounded, and the bound is the point.
    """

    def test_two_envelopes_differing_only_in_detail_share_a_signature(self):
        rig = Rig()
        first = rig.sign()
        second = rig.sign(nonce=first.request_nonce, detail="different prose")
        self.assertEqual(first.signature, second.signature)
        self.assertNotEqual(first.detail, second.detail)

    def test_so_the_second_is_treated_as_a_retry_and_records_nothing(self):
        # The bound: a duplicate does not append a second observation, so an
        # altered `detail` cannot add evidence or change what was recorded.
        rig = Rig()
        first = rig.sign()
        self.assertTrue(rig.ingest(first).accepted)
        before = len(rig.ledger.evidence(TASK))

        second = rig.sign(nonce=first.request_nonce, detail="different prose")
        result = rig.ingest(second)
        self.assertTrue(result.accepted)
        self.assertTrue(result.duplicate)
        self.assertIsNone(result.evidence)
        self.assertEqual(len(rig.ledger.evidence(TASK)), before)

    def test_and_the_outcome_that_decides_anything_is_signed(self):
        # What `detail` cannot do is change the answer: satisfies comes from
        # `outcome`, which is signed, and altering it breaks the signature.
        rig = Rig()
        honest = rig.sign()
        tampered = ObservationAttestation.from_dict(
            honest.to_dict() | {"outcome": str(Outcome.UNHEALTHY_STATUS)})
        with self.assertRaises(SignatureInvalid):
            AttestationVerifier.from_b64(
                rig.signer.public_key_b64()).verify(tampered)


class FailClosedInvariantTests(unittest.TestCase):
    """10. The aggregation: nothing above ever produced a certificate."""

    def test_no_broken_assumption_in_this_module_yields_verified(self):
        # A roll-up rather than a new attack: every corruption this file can
        # construct, run in one place, asserting the one thing that must never
        # happen.
        rig = Rig()
        attestation, evidence = rig.observed()
        proof = rig.bundle(attestation, evidence)
        stranger = AttestationSigner.generate(COLLECTOR)

        hostile = [
            ("no anchor", lambda: replay_historical(proof)),
            ("empty registry",
             lambda: replay_historical(proof, trust_anchor=CollectorRegistry().seal())),
            ("wrong key",
             lambda: replay_historical(proof, trust_anchor=registry_for(
                 COLLECTOR, stranger.public_key_b64(), (KIND,), (PROFILE,)))),
            ("name vouching cannot rescue a signed record",
             lambda: replay_historical(proof, trusted_collectors=[COLLECTOR])),
            ("stale", lambda: re_evaluate_at(proof, NOW + HORIZON + 1,
                                             trust_anchor=rig.registry)),
            ("nan clock", lambda: re_evaluate_at(proof, float("nan"),
                                                 trust_anchor=rig.registry)),
        ]
        for label, attempt in hostile:
            with self.subTest(case=label):
                self.assertEqual(attempt().status, "ABSTAIN",
                                 f"{label} produced a certificate")


if __name__ == "__main__":
    unittest.main()
