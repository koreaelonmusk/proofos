"""Signed is not trusted. Trusted signer is not authorized. Authorized is not satisfied.

The two flagship tests are the shape of the whole phase. In one, a real
collector signs a real observation through the real ingestion path, the bundle
travels, and a process holding the right registry reaches VERIFIED. In the
other, an attacker produces a *cryptographically perfect* signature over a
perfectly formed envelope that names ``proofos-collector`` and asserts
everything it can, and the answer is ABSTAIN -- because the registry's key for
that name is not the attacker's, and the registry comes from the environment.

Everything else here is a way of asking the same question: can anything inside
the file move the trust root?
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from proofos import EvidenceLedger, ProofOS, Requirement
from proofos.attestation import AttestationSigner, ObservationAttestation, Outcome
from proofos.bundle import export_bundle, load_bundle
from proofos.capabilities import ObservationCapability
from proofos.collector_registry import CollectorRecord, CollectorRegistry, registry_for
from proofos.portable_attestation import (
    AttestationUnavailable,
    PortableAttestationRejected,
    available,
    observed_value,
    verify_portable,
)
from proofos.replay import ReplayError, re_evaluate_at, replay_historical

from tests.test_bundle_attestation import (
    CLAIM,
    COLLECTOR,
    EXECUTION,
    HORIZON,
    KIND,
    NOW,
    PROFILE,
    TASK,
    Observatory,
    bundle_from,
)

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "replay.py"
ROOT = pathlib.Path(__file__).resolve().parent.parent


def signed_bundle(obs: Observatory = None, **kwargs):
    obs = obs or Observatory()
    attestation, evidence = obs.observed(**kwargs)
    return obs, attestation, evidence, load_bundle(
        bundle_from(obs, evidence, attestation).to_json())


def resign(bundle, evidence_hash, envelope):
    """Put a different envelope on a record and reseal, as a forger would."""
    from proofos.integrity import content_hash

    raw = json.loads(bundle.to_json())
    for record in raw["evidence"]:
        if record["content_hash"] == evidence_hash:
            record["attestation"] = envelope
    raw.pop("digest")
    return load_bundle({**raw, "digest": content_hash(raw)})


class FlagshipASignedProofReplaysTests(unittest.TestCase):
    """§20. A real signature, verified against a registry from outside."""

    def test_a_signed_observation_replays_to_verified(self):
        obs, _, _, bundle = signed_bundle()
        result = replay_historical(bundle, trust_anchor=obs.registry)
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.reason, "NONE")
        self.assertTrue(result.matches_recorded)
        self.assertEqual(len(result.reinstated), 1)
        self.assertEqual(result.rejected, ())

    def test_the_signature_is_checked_not_assumed(self):
        # The same bundle with one byte of the signature changed. If anything
        # here were trusting the envelope rather than verifying it, this would
        # still pass.
        obs, attestation, evidence, bundle = signed_bundle()
        forged = attestation.to_dict()
        forged["signature"] = ("B" + forged["signature"][1:]
                               if forged["signature"][0] != "B"
                               else "C" + forged["signature"][1:])
        result = replay_historical(resign(bundle, evidence.content_hash, forged),
                                   trust_anchor=obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["SIGNATURE_INVALID"])

    def test_verification_is_deterministic(self):
        obs, _, _, bundle = signed_bundle()
        one = replay_historical(bundle, trust_anchor=obs.registry)
        two = replay_historical(bundle, trust_anchor=obs.registry)
        self.assertEqual(one.as_dict(), two.as_dict())


class FlagshipBTheAttackerSignsPerfectlyTests(unittest.TestCase):
    """§21. Valid cryptography, zero authority."""

    def setUp(self):
        self.obs = Observatory()
        _, self.attestation, self.evidence, self.bundle = signed_bundle(self.obs)
        # An attacker with their own key pair, signing an envelope that names
        # the legitimate collector and asserts everything it can.
        self.attacker = AttestationSigner.generate(COLLECTOR)
        self.forged = self.attacker.sign(
            execution_id=EXECUTION, task_id=TASK, kind=KIND, profile_id=PROFILE,
            request_nonce=self.attestation.request_nonce, observed_at=NOW - 10,
            outcome=Outcome.HEALTHY, status_code=200,
            response_digest_value=self.attestation.response_digest,
            detail="anon 403 -> authed 200")

    def test_the_attacker_signature_is_internally_valid(self):
        # Establishing that the negative below is about authority, not about a
        # malformed forgery. Against the attacker's own key, it verifies.
        from proofos.attestation import AttestationVerifier

        AttestationVerifier.from_b64(
            self.attacker.public_key_b64()).verify(self.forged)

    def test_and_it_still_reaches_abstain(self):
        bundle = resign(self.bundle, self.evidence.content_hash,
                        self.forged.to_dict())
        result = replay_historical(bundle, trust_anchor=self.obs.registry,
                                   trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_UNTRUSTED")
        self.assertEqual([r[1] for r in result.rejected], ["SIGNATURE_INVALID"])
        self.assertEqual(result.reinstated, ())

    def test_the_attackers_own_registry_does_not_travel_with_the_bundle(self):
        # If the bundle could bring its own trust root, this would pass. The
        # registry is an argument, and the attacker cannot reach the argument.
        bundle = resign(self.bundle, self.evidence.content_hash,
                        self.forged.to_dict())
        attacker_registry = registry_for(COLLECTOR,
                                         self.attacker.public_key_b64(),
                                         (KIND,), (PROFILE,))
        theirs = replay_historical(bundle, trust_anchor=attacker_registry)
        ours = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual(theirs.status, "VERIFIED")
        self.assertEqual(ours.status, "ABSTAIN")
        # The difference is the replaying environment's policy. Nothing in the
        # file changed between those two calls.
        self.assertEqual(theirs.bundle_id, ours.bundle_id)

    def test_a_key_carried_in_the_envelope_is_refused_outright(self):
        # The strict parse has no field for one. An envelope offering its own
        # key is malformed rather than persuasive.
        envelope = self.forged.to_dict() | {
            "public_key": self.attacker.public_key_b64(), "trusted": True}
        bundle = resign(self.bundle, self.evidence.content_hash, envelope)
        result = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["MALFORMED_ATTESTATION"])


class TheTrustRootComesFromOutsideTests(unittest.TestCase):
    """§19. Same bytes, three environments, three answers."""

    def setUp(self):
        self.obs, _, _, self.bundle = signed_bundle()

    def test_no_anchor_abstains(self):
        result = replay_historical(self.bundle)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["NO_TRUST_ANCHOR"])

    def test_a_registry_that_does_not_know_this_collector_abstains(self):
        other = registry_for("someone-else", self.obs.signer.public_key_b64(),
                             (KIND,), (PROFILE,))
        result = replay_historical(self.bundle, trust_anchor=other)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["UNKNOWN_COLLECTOR"])

    def test_an_inactive_collector_abstains(self):
        registry = CollectorRegistry()
        registry.register(CollectorRecord(
            collector_id=COLLECTOR, public_key_b64=self.obs.signer.public_key_b64(),
            allowed_kinds=frozenset({KIND}), allowed_profiles=frozenset({PROFILE}),
            active=False))
        registry.seal()
        result = replay_historical(self.bundle, trust_anchor=registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["UNKNOWN_COLLECTOR"])

    def test_the_correct_anchor_verifies(self):
        self.assertEqual(
            replay_historical(self.bundle, trust_anchor=self.obs.registry).status,
            "VERIFIED")

    def test_naming_the_collector_cannot_rescue_a_failed_attestation(self):
        # The rule that keeps the weaker path from becoming the way around the
        # stronger one. A record carrying a signature is admitted by that
        # signature or not at all.
        result = replay_historical(self.bundle, trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(len(result.demoted), 1)
        self.assertEqual(result.reinstated, ())


class ASignatureBindsToOneObservationTests(unittest.TestCase):
    """§9 and §10. Cut and paste."""

    def setUp(self):
        self.obs, self.attestation, self.evidence, self.bundle = signed_bundle()

    def moved(self, **changes):
        """The same signature, on an envelope describing something else."""
        return self.attestation.to_dict() | changes

    def test_a_signature_moved_to_a_different_kind_fails(self):
        bundle = resign(self.bundle, self.evidence.content_hash,
                        self.moved(kind="task_outcome"))
        result = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertIn(result.rejected[0][1],
                      {"SIGNATURE_INVALID", "COLLECTOR_SCOPE_VIOLATION"})

    def test_a_signature_moved_to_a_different_timestamp_fails(self):
        bundle = resign(self.bundle, self.evidence.content_hash,
                        self.moved(observed_at=NOW - 1))
        result = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual([r[1] for r in result.rejected], ["SIGNATURE_INVALID"])

    def test_a_signature_moved_to_a_different_collector_fails(self):
        bundle = resign(self.bundle, self.evidence.content_hash,
                        self.moved(collector_id="other-collector"))
        result = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual([r[1] for r in result.rejected], ["UNKNOWN_COLLECTOR"])

    def test_a_signature_moved_to_a_different_task_fails(self):
        # Genuine collector, genuine signature, genuine observation -- of a
        # different task. It is signed for OTHER-TASK and carried in a bundle
        # for DEPLOY-9, and the signed task_id is what settles it.
        elsewhere = self.obs.sign(task_id="OTHER-TASK")
        bundle = resign(self.bundle, self.evidence.content_hash,
                        elsewhere.to_dict())
        result = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["TASK_MISMATCH"])

    def test_an_edited_value_no_longer_matches_the_attested_observation(self):
        # Found by mutation M5, which dropped the value binding and broke
        # nothing: the old test blanked the record digest, so the record's own
        # integrity check fired first and the binding was never reached.
        #
        # Here the forger is competent. The value is edited, the record digest
        # is recomputed to match, and the bundle is resealed -- so every
        # integrity layer agrees, and the only thing left that can notice is
        # that the text does not match the observation the signature covers.
        edited = self.rebuilt(
            value="attested HEALTHY via cloud-run-health: everything is fine")
        result = replay_historical(edited, trust_anchor=self.obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["BINDING_MISMATCH"])

    def test_an_edited_timestamp_no_longer_matches_either(self):
        edited = self.rebuilt(collected_at=NOW - 1)
        result = replay_historical(edited, trust_anchor=self.obs.registry)
        self.assertEqual([r[1] for r in result.rejected], ["BINDING_MISMATCH"])

    def rebuilt(self, **changes):
        """Edit a record, recompute its digest, reseal the bundle.

        Every integrity layer left agreeing, so only the signature binding can
        object. This is what a forger who has read the code would produce.
        """
        from proofos.integrity import content_hash

        raw = json.loads(self.bundle.to_json())
        record = raw["evidence"][0]
        record.update(changes)
        record["content_hash"] = content_hash({
            "kind": record["kind"], "value": record["value"],
            "source": record["source"], "valid": record["valid"],
            "collected_at": record["collected_at"],
            "collector": record["collector"]})
        raw.pop("digest")
        rebuilt = load_bundle({**raw, "digest": content_hash(raw)})
        self.assertTrue(rebuilt.intact)
        self.assertTrue(rebuilt.evidence[0].intact)
        return rebuilt

    def test_a_signature_for_another_kind_the_collector_may_also_sign(self):
        # Found by mutation M6. The earlier kind test was caught by the
        # registry's scope check before the binding was reached, so dropping the
        # binding changed nothing. This collector is scoped to both kinds, so
        # scope passes, the signature passes, and the only thing standing
        # between a signature for `artifact` and a record of `runtime_health`
        # is that they are not the same observation.
        obs = Observatory(kinds=(KIND, "artifact"))
        attestation, evidence = obs.observed()
        bundle = load_bundle(bundle_from(obs, evidence, attestation).to_json())
        other_kind = obs.sign(kind="artifact")
        moved = resign(bundle, evidence.content_hash, other_kind.to_dict())
        result = replay_historical(moved, trust_anchor=obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected], ["BINDING_MISMATCH"])

    def test_a_future_dated_observation_is_refused(self):
        # The live ingestor refuses one outright, so it cannot be produced
        # through the honest path -- which is itself worth asserting. Replay
        # applies the same rule to one that arrives inside a bundle.
        ahead = self.obs.sign(observed_at=NOW + 3600)
        with self.assertRaises(AssertionError):
            self.obs.ingest(ahead)
        bundle = resign(self.bundle, self.evidence.content_hash, ahead.to_dict())
        result = replay_historical(bundle, trust_anchor=self.obs.registry)
        self.assertEqual([r[1] for r in result.rejected],
                         ["ATTESTATION_FUTURE_DATED"])


class AuthorityDoesNotBypassTheKernelTests(unittest.TestCase):
    """§14, §15, §16, §18."""

    def test_a_valid_signature_does_not_beat_freshness(self):
        obs, _, _, bundle = signed_bundle()
        fresh = replay_historical(bundle, trust_anchor=obs.registry)
        self.assertEqual(fresh.status, "VERIFIED")
        stale = re_evaluate_at(bundle, NOW + HORIZON + 1, trust_anchor=obs.registry)
        self.assertEqual(stale.status, "ABSTAIN")
        self.assertEqual(stale.reason, "EVIDENCE_STALE")
        # The signature still verified. The observation is simply old.
        self.assertEqual(stale.rejected, ())
        self.assertEqual(len(stale.reinstated), 1)

    def test_a_valid_signature_does_not_satisfy_the_wrong_requirement(self):
        obs, _, evidence, _ = signed_bundle()
        attestation = obs.sign()
        bundle = load_bundle(export_bundle(
            claim=CLAIM, requirements=(Requirement("task_outcome",
                                                   max_age_seconds=HORIZON),),
            evidence=(evidence,), task_id=TASK, execution_id=EXECUTION,
            verification_time=NOW, created_at=NOW + 1,
            attestations={evidence.content_hash: attestation.to_dict()},
        ).to_json())
        result = replay_historical(bundle, trust_anchor=obs.registry)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_MISSING")

    def test_a_trusted_collector_does_not_gain_a_kind_it_is_not_scoped_to(self):
        # Registered for runtime_health only; the registry refuses the rest,
        # and neither the bundle asking nor the caller trusting changes that.
        obs = Observatory(kinds=(KIND,))
        scoped = obs.registry.get(COLLECTOR)
        self.assertEqual(scoped.allowed_kinds, frozenset({KIND}))
        with self.assertRaises(PortableAttestationRejected) as caught:
            verify_portable(obs.sign(kind="task_outcome").to_dict(),
                            registry=obs.registry, now=NOW)
        self.assertEqual(caught.exception.reason, "COLLECTOR_SCOPE_VIOLATION")

    def test_the_recorded_verdict_is_still_irrelevant(self):
        obs = Observatory()
        attestation, evidence = obs.observed()
        answers = set()
        for recorded in ("VERIFIED", "ABSTAIN", ""):
            with self.subTest(recorded=recorded):
                bundle = load_bundle(bundle_from(
                    obs, evidence, attestation,
                    recorded_verdict=recorded).to_json())
                # No anchor: signed, and still nothing.
                result = replay_historical(bundle)
                answers.add((result.status, result.reason))
        self.assertEqual(answers, {("ABSTAIN", "EVIDENCE_UNTRUSTED")})


class ReplayNamesNoProvenanceTests(unittest.TestCase):
    """§12 and §13. Signed evidence becomes authoritative one way only."""

    def test_replay_never_writes_an_independent_provenance_by_hand(self):
        # Not a check that the constant is used carefully -- a check that the
        # module's code never names it. Everything that becomes an observation
        # goes through ObservationCapability, which is the authorized primitive.
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        docstrings = {ast.get_docstring(n, clean=False) for n in ast.walk(tree)
                      if isinstance(n, (ast.Module, ast.ClassDef,
                                        ast.FunctionDef))}
        attributes = {n.attr for n in ast.walk(tree)
                      if isinstance(n, ast.Attribute)}
        literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)
                    and isinstance(n.value, str)} - docstrings
        self.assertNotIn("OBSERVED", attributes)
        self.assertNotIn("OBSERVED", literals)

    def test_it_records_observations_through_the_authorized_capability(self):
        imported: set[str] = set()
        for node in ast.walk(ast.parse(MODULE.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                imported.update(a.name for a in node.names)
        self.assertIn("ObservationCapability", imported)
        self.assertIn("verify_portable", imported)

    def test_the_capabilities_it_mints_come_from_the_grant_plan(self):
        # Found by mutation M7, which built the capability set inline from every
        # collector in the file and covered every kind in the file. Nothing
        # broke, because `confirmed` still governs which records use a
        # capability -- so the over-authority was unreachable today and sitting
        # behind a check a later edit could move. Same finding as P11's M7, one
        # layer up.
        #
        # Behaviour cannot distinguish it, so this asserts the structure: the
        # only thing an ObservationCapability is ever built from is grant_plan.
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        constructions = [n for n in ast.walk(tree)
                         if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Name)
                         and n.func.id == "ObservationCapability"]
        self.assertEqual(len(constructions), 1,
                         "an ObservationCapability is minted somewhere new")

        sources = []
        for comp in ast.walk(tree):
            if isinstance(comp, (ast.DictComp, ast.ListComp, ast.SetComp,
                                 ast.GeneratorExp)):
                if any(c is constructions[0] for c in ast.walk(comp)):
                    for generator in comp.generators:
                        sources.append(ast.dump(generator.iter))
        self.assertTrue(sources, "the capability is not built from an iterable")
        self.assertTrue(
            all("grant_plan" in source for source in sources),
            "an ObservationCapability is minted from something other than "
            "grant_plan, so the bounded plan is no longer what bounds it")

    def test_it_implements_no_cryptography_of_its_own(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("cryptography", "Ed25519", "hashlib", "b64decode",
                          "InvalidSignature"):
            self.assertNotIn(forbidden, source)

    def test_without_the_signature_machinery_a_signed_record_is_demoted(self):
        # The zero-dependency install. An unchecked signature is not a weaker
        # yes; the record is demoted and the answer is ABSTAIN.
        obs, _, _, bundle = signed_bundle()
        with mock.patch("proofos.replay.verify_portable",
                        side_effect=AttestationUnavailable("no cryptography")):
            result = replay_historical(bundle, trust_anchor=obs.registry,
                                       trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual([r[1] for r in result.rejected],
                         ["SIGNATURE_MACHINERY_UNAVAILABLE"])

    def test_availability_is_reportable(self):
        self.assertTrue(available())


class CrossProcessSignedTests(unittest.TestCase):
    """§22. A fresh interpreter, with the trust anchor loaded separately."""

    SCRIPT = """
import json, sys
from proofos.bundle import load_bundle
from proofos.collector_registry import registry_for
from proofos.replay import replay_historical

bundle = load_bundle(open(sys.argv[1], encoding="utf-8").read())
collector, key, kind, profile = sys.argv[2:6]
registry = registry_for(collector, key, (kind,), (profile,))
print(json.dumps(replay_historical(bundle, trust_anchor=registry,
                                   expected_digest=bundle.digest).as_dict()))
"""

    def replay_elsewhere(self, bundle, collector, key):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "proof.json"
            path.write_text(bundle.to_json(), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-c", self.SCRIPT, str(path), collector, key,
                 KIND, PROFILE],
                capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_another_process_verifies_the_signature_and_agrees(self):
        # The signer object never leaves this process. Only the public key
        # travels, and it travels beside the bundle rather than inside it.
        obs, _, _, bundle = signed_bundle()
        remote = self.replay_elsewhere(bundle, COLLECTOR,
                                       obs.signer.public_key_b64())
        self.assertEqual(remote["recomputed_verdict"], "VERIFIED")
        self.assertTrue(remote["matches_recorded"])
        self.assertEqual(
            remote, replay_historical(bundle, trust_anchor=obs.registry).as_dict())

    def test_another_process_with_the_wrong_key_abstains(self):
        obs, _, _, bundle = signed_bundle()
        stranger = AttestationSigner.generate(COLLECTOR)
        remote = self.replay_elsewhere(bundle, COLLECTOR,
                                       stranger.public_key_b64())
        self.assertEqual(remote["recomputed_verdict"], "ABSTAIN")
        self.assertEqual([r[1] for r in remote["rejected"]], ["SIGNATURE_INVALID"])

    def test_the_bundle_names_no_key_file_or_machine_path(self):
        obs, _, _, bundle = signed_bundle()
        raw = bundle.to_json()
        for fragment in (str(ROOT), sys.prefix, tempfile.gettempdir()):
            self.assertNotIn(fragment, raw)
        self.assertNotIn(obs.signer.public_key_b64(), raw)


if __name__ == "__main__":
    unittest.main()
