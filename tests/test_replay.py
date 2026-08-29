"""Replay can reproduce a decision. It cannot reproduce an observation.

The two flagship tests sit at opposite ends. One takes a real observation,
written through a real grant, and shows that a different process reaches the
same VERIFIED. The other takes a bundle that says VERIFIED over an evidence set
that never contained an observation, and shows it reaching ABSTAIN -- because a
proof bundle that could certify itself would be a claim wearing a hash.

Everything between those two is about the seam where a file becomes evidence
again, which is the only place in this design where something could go wrong
quietly.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from proofos import Evidence, EvidenceLedger, EvidenceSource, ProofOS, Requirement
from proofos.bundle import (
    BundleIntegrityError,
    export_bundle,
    load_bundle,
)
from proofos.replay import (
    ReplayError,
    ReplayMode,
    grant_plan,
    re_evaluate_at,
    render_replay,
    replay_historical,
)

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "replay.py"
ROOT = pathlib.Path(__file__).resolve().parent.parent
NOW = 1_700_000_000.0
KIND = "service_health"
CLAIM = "Deployment complete."
COLLECTOR = "proofos-collector"
HORIZON = 900.0


def ledger_with(*records, requirement=None):
    """A ledger holding exactly these records, each written the honest way."""
    ledger = EvidenceLedger()
    ledger.open_task("DEPLOY-9", (requirement
                                  or Requirement(KIND, max_age_seconds=HORIZON),))
    observed: dict[str, set[str]] = {}
    for spec in records:
        if spec["source"] is EvidenceSource.OBSERVED:
            observed.setdefault(spec["collector"], set()).add(spec["kind"])
    grants = {collector: ledger.grant_observation(collector, tuple(sorted(kinds)))
              for collector, kinds in observed.items()}
    ledger.seal()
    for spec in records:
        ledger.record("DEPLOY-9", Evidence(**spec),
                      grants.get(spec["collector"])
                      if spec["source"] is EvidenceSource.OBSERVED else None)
    return ledger


def observation(**overrides):
    spec = {"kind": KIND, "value": "GET /health -> 200",
            "source": EvidenceSource.OBSERVED, "collected_at": NOW - 10,
            "collector": COLLECTOR}
    spec.update(overrides)
    return spec


def self_report(**overrides):
    spec = {"kind": KIND, "value": "I checked, the service is up.",
            "source": EvidenceSource.EXECUTOR, "collected_at": NOW - 10,
            "collector": "deploy-agent"}
    spec.update(overrides)
    return spec


def bundle_from(ledger, **overrides):
    decision = ProofOS().verify_recorded(ledger, "DEPLOY-9", CLAIM, now=NOW)
    kwargs = dict(claim=CLAIM, requirements=ledger.requirements("DEPLOY-9"),
                  evidence=ledger.evidence("DEPLOY-9"), task_id="DEPLOY-9",
                  verification_time=NOW, created_at=NOW + 1,
                  actor_id="deploy-agent", policy_id="strict-v1",
                  recorded_verdict=str(decision.status),
                  recorded_reason=str(decision.reason))
    kwargs.update(overrides)
    return export_bundle(**kwargs)


def resealed(bundle, **changes):
    """Edit a bundle and recompute its digest, as a competent forger would.

    Integrity alone would not catch this. What catches it is that replay does
    not read the recorded verdict.
    """
    raw = json.loads(bundle.to_json())
    raw.update(changes)
    raw.pop("digest")
    from proofos.integrity import content_hash

    raw["digest"] = content_hash(raw)
    return load_bundle(raw)


class FlagshipARealProofReplaysTests(unittest.TestCase):
    """§16. A genuine observation, exported, recomputed elsewhere."""

    def test_a_real_observation_replays_to_verified_and_matches(self):
        bundle = bundle_from(ledger_with(observation()))
        self.assertEqual(bundle.recorded_verdict, "VERIFIED")

        result = replay_historical(load_bundle(bundle.to_json()),
                                   trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.reason, "NONE")
        self.assertTrue(result.matches_recorded)
        self.assertEqual(len(result.reinstated), 1)
        self.assertEqual(result.demoted, ())
        self.assertIs(result.mode, ReplayMode.HISTORICAL)

    def test_replay_is_deterministic(self):
        bundle = load_bundle(bundle_from(ledger_with(observation())).to_json())
        one = replay_historical(bundle, trusted_collectors=[COLLECTOR])
        two = replay_historical(bundle, trusted_collectors=[COLLECTOR])
        self.assertEqual(one.as_dict(), two.as_dict())

    def test_the_expected_digest_pins_which_file_was_replayed(self):
        bundle = load_bundle(bundle_from(ledger_with(observation())).to_json())
        replay_historical(bundle, trusted_collectors=[COLLECTOR],
                          expected_digest=bundle.digest)
        with self.assertRaises(ReplayError) as caught:
            replay_historical(bundle, trusted_collectors=[COLLECTOR],
                              expected_digest="0" * 64)
        self.assertIn("is not the one you asked for", str(caught.exception))


class FlagshipBABundleCannotSelfCertifyTests(unittest.TestCase):
    """§17. The whole argument, in one test."""

    def test_a_bundle_asserting_verified_over_self_reports_abstains(self):
        bundle = bundle_from(ledger_with(self_report()),
                             recorded_verdict="VERIFIED", recorded_reason="NONE")
        result = replay_historical(load_bundle(bundle.to_json()),
                                   trusted_collectors=[COLLECTOR, "deploy-agent"])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_UNTRUSTED")
        self.assertFalse(result.matches_recorded)
        self.assertEqual(result.recorded_verdict, "VERIFIED")

    def test_a_bundle_asserting_verified_over_nothing_abstains(self):
        # The minimal malicious bundle: a verdict and an empty evidence list.
        ledger = EvidenceLedger()
        ledger.open_task("DEPLOY-9", (Requirement(KIND, max_age_seconds=HORIZON),))
        ledger.seal()
        bundle = bundle_from(ledger, recorded_verdict="VERIFIED",
                             recorded_reason="NONE")
        result = replay_historical(load_bundle(bundle.to_json()),
                                   trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_MISSING")
        self.assertFalse(result.matches_recorded)

    def test_a_bundle_replayed_with_no_named_collector_abstains(self):
        # The default. A bundle found on the internet, replayed by someone who
        # has not said whose observations they accept, is a document.
        bundle = load_bundle(bundle_from(ledger_with(observation())).to_json())
        result = replay_historical(bundle)
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_UNTRUSTED")
        self.assertEqual(len(result.demoted), 1)
        self.assertEqual(result.reinstated, ())

    def test_the_recorded_verdict_is_never_read_by_the_decision(self):
        # Same records, four different recorded verdicts, one answer.
        answers = set()
        for recorded in ("VERIFIED", "ABSTAIN", "", "TOTALLY_VERIFIED"):
            with self.subTest(recorded=recorded):
                bundle = bundle_from(ledger_with(self_report()),
                                     recorded_verdict=recorded)
                result = replay_historical(load_bundle(bundle.to_json()),
                                           trusted_collectors=[COLLECTOR])
                answers.add((result.status, result.reason))
        self.assertEqual(answers, {("ABSTAIN", "EVIDENCE_UNTRUSTED")})


class NoObservationLaunderingTests(unittest.TestCase):
    """§13. The promotion path does not exist."""

    def test_naming_a_collector_cannot_promote_a_self_report(self):
        # deploy-agent is named as trusted and its record is still EXECUTOR,
        # because trust can only confirm a recorded provenance, never invent one.
        bundle = load_bundle(bundle_from(ledger_with(self_report())).to_json())
        result = replay_historical(bundle,
                                   trusted_collectors=["deploy-agent", COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_UNTRUSTED")
        self.assertEqual(result.reinstated, ())
        self.assertEqual(result.demoted, ())

    def test_no_record_leaves_replay_more_trusted_than_it_arrived(self):
        mixed = ledger_with(observation(), self_report(),
                            observation(value="probe 2 -> 200",
                                        collected_at=NOW - 5,
                                        collector="other-collector"))
        bundle = load_bundle(bundle_from(mixed).to_json())
        recorded = {r.content_hash: r.source for r in bundle.evidence}
        result = replay_historical(bundle, trusted_collectors=[COLLECTOR])
        for digest in result.reinstated:
            self.assertEqual(recorded[digest], "OBSERVED")
        for digest in result.demoted:
            self.assertEqual(recorded[digest], "OBSERVED")
        self.assertEqual(len(result.reinstated) + len(result.demoted),
                         sum(1 for s in recorded.values() if s == "OBSERVED"))

    def test_a_replayed_record_is_not_a_new_observation(self):
        # Replaying the same bundle a hundred times does not accumulate
        # anything: it is one observation, read repeatedly.
        bundle = load_bundle(bundle_from(ledger_with(observation())).to_json())
        answers = {(replay_historical(bundle,
                                      trusted_collectors=[COLLECTOR]).status)
                   for _ in range(5)}
        self.assertEqual(answers, {"VERIFIED"})
        later = re_evaluate_at(bundle, NOW + HORIZON + 1,
                               trusted_collectors=[COLLECTOR])
        self.assertEqual(later.status, "ABSTAIN")

    def test_an_unknown_provenance_is_refused_rather_than_guessed(self):
        bundle = bundle_from(ledger_with(observation()))
        raw = json.loads(bundle.to_json())
        raw["evidence"][0]["source"] = "CERTIFIED"
        with self.assertRaises((ReplayError, BundleIntegrityError)):
            replay_historical(load_bundle(raw), trusted_collectors=[COLLECTOR])

    def test_this_module_collects_nothing(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("urllib", "socket", "requests", "httpx", "subprocess",
                          "open(", "probe_health", "time.time"):
            self.assertNotIn(forbidden, source)


class TheGrantPlanIsBoundedOnBothSidesTests(unittest.TestCase):
    """Found by mutation M7, which minted a grant for every collector in the file.

    Nothing broke, because the provenance rules meant those grants were never
    used -- which is the worst kind of finding: latent over-authority behind a
    check that a later edit could move. The plan is now a function of its own,
    and these tests are about the plan rather than about what today's rules
    happen to do with it.
    """

    def bundle(self):
        return load_bundle(bundle_from(ledger_with(
            observation(),
            observation(kind="artifact", value="sha256:abc",
                        collected_at=NOW - 5),
            observation(value="probe 2 -> 200", collector="other-collector",
                        collected_at=NOW - 5),
            self_report(),
        )).to_json())

    def test_a_collector_the_caller_did_not_name_gets_no_grant(self):
        plan = grant_plan(self.bundle(), [COLLECTOR])
        self.assertEqual(set(plan), {COLLECTOR})
        self.assertNotIn("other-collector", plan)
        self.assertNotIn("deploy-agent", plan)

    def test_naming_nobody_mints_nothing(self):
        self.assertEqual(grant_plan(self.bundle(), []), {})

    def test_a_grant_covers_only_the_kinds_that_collector_observed(self):
        # Naming a collector vouches for what it observed, not for the task.
        plan = grant_plan(self.bundle(), [COLLECTOR])
        self.assertEqual(plan[COLLECTOR], frozenset({KIND, "artifact"}))

    def test_naming_a_self_reporting_collector_mints_nothing_for_it(self):
        plan = grant_plan(self.bundle(), ["deploy-agent"])
        self.assertEqual(plan, {})

    def test_the_bundle_cannot_widen_the_plan(self):
        # Every collector in the file, and the caller named one of them.
        everyone = {r.collector for r in self.bundle().evidence}
        self.assertGreater(len(everyone), 1)
        self.assertEqual(set(grant_plan(self.bundle(), [COLLECTOR])), {COLLECTOR})


class TamperFailsClosedTests(unittest.TestCase):
    """§18 and §19."""

    def test_a_mutated_protected_field_is_never_replayed(self):
        bundle = bundle_from(ledger_with(observation()))
        for path, change in (
            ("evidence source", {"source": "OBSERVED", "collector": "someone"}),
            ("evidence timestamp", {"collected_at": NOW}),
            ("evidence digest", {"content_hash": "0" * 64}),
        ):
            with self.subTest(field=path):
                raw = json.loads(bundle.to_json())
                raw["evidence"][0].update(change)
                with self.assertRaises(BundleIntegrityError):
                    replay_historical(load_bundle(raw),
                                      trusted_collectors=[COLLECTOR])

    def test_a_mutated_requirement_is_never_replayed(self):
        bundle = bundle_from(ledger_with(observation()))
        raw = json.loads(bundle.to_json())
        raw["requirements"][0]["max_age_seconds"] = 10 ** 9
        with self.assertRaises(BundleIntegrityError):
            replay_historical(load_bundle(raw), trusted_collectors=[COLLECTOR])

    def test_flipping_the_recorded_verdict_breaks_integrity(self):
        bundle = bundle_from(ledger_with(self_report()))
        self.assertEqual(bundle.recorded_verdict, "ABSTAIN")
        raw = json.loads(bundle.to_json())
        raw["recorded_verdict"] = "VERIFIED"
        with self.assertRaises(BundleIntegrityError):
            replay_historical(load_bundle(raw), trusted_collectors=[COLLECTOR])

    def test_flipping_it_and_resealing_still_recomputes_abstain(self):
        # The forger who also recomputes the digest. Integrity passes, and it
        # buys nothing, because the recorded verdict is never an input.
        bundle = resealed(bundle_from(ledger_with(self_report())),
                          recorded_verdict="VERIFIED", recorded_reason="NONE")
        self.assertTrue(bundle.intact)
        result = replay_historical(bundle, trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertFalse(result.matches_recorded)

    def test_a_record_broken_before_sealing_is_refused(self):
        # The bundle is internally consistent and one record inside it is not.
        # That record was already broken when the bundle was made.
        bundle = resealed(bundle_from(ledger_with(observation())))
        raw = json.loads(bundle.to_json())
        raw["evidence"][0]["value"] = "GET /health -> 500"
        broken = load_bundle({**raw, "digest": _digest_of(raw)})
        with self.assertRaises(ReplayError) as caught:
            replay_historical(broken, trusted_collectors=[COLLECTOR])
        self.assertIn("does not match its own", str(caught.exception))

    def test_replay_refuses_anything_that_is_not_a_loaded_bundle(self):
        for payload in ({"digest": "x"}, "a string", None):
            with self.subTest(payload=payload):
                with self.assertRaises(ReplayError):
                    replay_historical(payload)


class FreshnessSurvivesSerializationTests(unittest.TestCase):
    """§12 and §20. An old proof going quiet is the horizon working."""

    def setUp(self):
        self.bundle = load_bundle(
            bundle_from(ledger_with(observation())).to_json())

    def test_historical_replay_reproduces_the_moment(self):
        result = replay_historical(self.bundle, trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "VERIFIED")
        self.assertEqual(result.evaluated_at, NOW)

    def test_the_same_sealed_evidence_goes_stale_later(self):
        result = re_evaluate_at(self.bundle, NOW + HORIZON + 1,
                                trusted_collectors=[COLLECTOR])
        self.assertEqual(result.status, "ABSTAIN")
        self.assertEqual(result.reason, "EVIDENCE_STALE")
        self.assertIs(result.mode, ReplayMode.RE_EVALUATED)
        self.assertFalse(result.matches_recorded)

    def test_re_evaluation_is_a_different_function_with_a_different_name(self):
        # Two questions, two names. A single function with a `now` argument
        # would let "is this still true" be asked by accident.
        self.assertNotEqual(replay_historical.__name__, re_evaluate_at.__name__)
        one = replay_historical(self.bundle, trusted_collectors=[COLLECTOR])
        two = re_evaluate_at(self.bundle, NOW, trusted_collectors=[COLLECTOR])
        self.assertEqual(one.status, two.status)
        self.assertNotEqual(str(one.mode), str(two.mode))

    def test_re_evaluation_generates_no_evidence(self):
        before = len(self.bundle.evidence)
        result = re_evaluate_at(self.bundle, NOW + 10,
                                trusted_collectors=[COLLECTOR])
        self.assertEqual(len(self.bundle.evidence), before)
        self.assertEqual(len(result.reinstated), 1)

    def test_the_rendering_says_what_replay_is_not(self):
        text = render_replay(replay_historical(self.bundle,
                                               trusted_collectors=[COLLECTOR]))
        self.assertIn("not a new", text)
        self.assertIn("does not say the world still satisfies", text)


class CrossProcessTests(unittest.TestCase):
    """§21. A different interpreter, started from nothing, reaching the same answer."""

    SCRIPT = """
import json, sys
from proofos.bundle import load_bundle
from proofos.replay import replay_historical
from proofos.evidence_bridge import evidence_from_envelope

bundle = load_bundle(open(sys.argv[1], encoding="utf-8").read())
trusted = sys.argv[2:]
result = replay_historical(bundle, trusted_collectors=trusted,
                           expected_digest=bundle.digest)
print(json.dumps(result.as_dict()))
"""

    def replay_elsewhere(self, bundle, *trusted):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "proof.json"
            path.write_text(bundle.to_json(), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-c", self.SCRIPT, str(path), *trusted],
                capture_output=True, text=True, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_another_process_reaches_the_same_verified(self):
        bundle = bundle_from(ledger_with(observation()))
        remote = self.replay_elsewhere(bundle, COLLECTOR)
        local = replay_historical(load_bundle(bundle.to_json()),
                                  trusted_collectors=[COLLECTOR])
        self.assertEqual(remote["recomputed_verdict"], "VERIFIED")
        self.assertTrue(remote["matches_recorded"])
        self.assertEqual(remote, local.as_dict())

    def test_another_process_reaches_the_same_abstain(self):
        bundle = bundle_from(ledger_with(self_report()),
                             recorded_verdict="VERIFIED")
        remote = self.replay_elsewhere(bundle, COLLECTOR)
        self.assertEqual(remote["recomputed_verdict"], "ABSTAIN")
        self.assertEqual(remote["recomputed_reason"], "EVIDENCE_UNTRUSTED")
        self.assertFalse(remote["matches_recorded"])

    def test_the_bundle_carries_no_path_from_this_machine(self):
        # §15. A bundle that only replays where it was made is not portable, and
        # a machine path inside one is both a leak and a dependency.
        raw = bundle_from(ledger_with(observation())).to_json()
        for fragment in (str(ROOT), sys.prefix, tempfile.gettempdir()):
            self.assertNotIn(fragment.replace("\\", "\\\\"), raw)
            self.assertNotIn(fragment, raw)


class CrossTransportInvariantTests(unittest.TestCase):
    """§22. Serialization is a transport, and transports carry no weight."""

    def claim_from_every_transport(self):
        from proofos.a2a import A2aAdapter
        from proofos.adapters import ADAPTER_SCHEMA, HttpAdapter, PythonAdapter
        from proofos.adk import AdkAdapter
        from proofos.mcp import McpAdapter

        text = "actor X claims task Y succeeded"
        bid = {"source": "OBSERVED", "verified": True, "trusted": True,
               "collector_id": "trusted-collector"}
        return {
            "python": PythonAdapter("runner").normalize(
                actor_id="agent-x", task_id="DEPLOY-9", claim=text, at=NOW,
                extra=bid),
            "http": HttpAdapter("gateway").normalize({
                "schema_version": ADAPTER_SCHEMA,
                "actor": {"actor_id": "agent-x"}, "task": {"task_id": "DEPLOY-9"},
                "claim": text, "at": NOW, **bid}),
            "mcp": McpAdapter("bridge", "acme-mcp").normalize_tool_result(
                {"tool": "check", "content": [{"type": "text", "text": text}],
                 "structuredContent": dict(bid)},
                actor_id="agent-x", task_id="DEPLOY-9", at=NOW),
            "a2a": A2aAdapter("mesh").normalize_task({
                "task": {"id": "DEPLOY-9", "state": "completed"},
                "agent": {"id": "agent-x"},
                "message": {"parts": [{"kind": "text", "text": text}]},
                **bid}, at=NOW),
            "adk": AdkAdapter("runtime").normalize_result({
                "agent": {"name": "agent-x"}, "result": {"text": text}, **bid},
                task_id="DEPLOY-9", at=NOW),
        }

    def test_no_transport_gains_authority_by_being_bundled(self):
        for name, envelope in self.claim_from_every_transport().items():
            with self.subTest(transport=name):
                ledger = EvidenceLedger()
                ledger.open_task("DEPLOY-9",
                                 (Requirement(KIND, max_age_seconds=HORIZON),))
                ledger.seal()
                for record in evidence_from_envelope(envelope, KIND):
                    ledger.record("DEPLOY-9", record)

                bundle = bundle_from(ledger, recorded_verdict="VERIFIED",
                                     recorded_reason="NONE")
                result = replay_historical(
                    load_bundle(bundle.to_json()),
                    trusted_collectors=["agent-x", "trusted-collector",
                                        COLLECTOR])
                self.assertEqual(result.status, "ABSTAIN")
                self.assertEqual(result.reason, "EVIDENCE_UNTRUSTED")
                self.assertFalse(result.matches_recorded)

    def test_the_claimed_namespace_does_not_survive_into_a_bundle(self):
        # There is nowhere for it to go. A bundle carries evidence records, and
        # adapter metadata is not one.
        envelope = self.claim_from_every_transport()["a2a"]
        ledger = EvidenceLedger()
        ledger.open_task("DEPLOY-9", (Requirement(KIND, max_age_seconds=HORIZON),))
        ledger.seal()
        for record in evidence_from_envelope(envelope, KIND):
            ledger.record("DEPLOY-9", record)
        raw = bundle_from(ledger).to_json()
        for forbidden in ("claimed_by_sender", "trusted-collector",
                          "delegation_chain"):
            self.assertNotIn(forbidden, raw)


class ReplayUsesTheAuthoritativeCoreTests(unittest.TestCase):
    """§5. It orchestrates. It does not own a second copy of the rules."""

    def test_it_calls_the_authoritative_path_and_defines_no_second_one(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(a.name for a in node.names)
        self.assertIn("ProofOS", imported)
        self.assertIn("TRUSTED_SOURCES", imported)

        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("verify_recorded", source)
        for forbidden in ("max_age_seconds >", "collected_at >=",
                          "VerificationStatus.VERIFIED", "def _evaluate("):
            self.assertNotIn(forbidden, source,
                             "replay is re-deriving a rule the kernel owns")

    def test_the_trusted_set_is_read_from_the_kernel_not_hardcoded(self):
        # If a later build changes what counts as independent, replay follows it
        # instead of quietly continuing to mean OBSERVED.
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("TRUSTED_SOURCES", source)

    def test_a_bundle_cannot_grant_itself_anything(self):
        # §14. Grants are minted by the replaying process for the collectors the
        # caller named. There is no field a bundle could put one in, and an
        # unknown field is refused rather than ignored.
        bundle = bundle_from(ledger_with(observation()))
        raw = json.loads(bundle.to_json())
        raw["observation_grant"] = {"collector_id": COLLECTOR, "kinds": [KIND]}
        with self.assertRaises(Exception) as caught:
            load_bundle(raw)
        self.assertIn("unexpected", str(caught.exception))


def _digest_of(raw: dict) -> str:
    from proofos.integrity import content_hash

    payload = {k: v for k, v in raw.items() if k != "digest"}
    return content_hash(payload)


if __name__ == "__main__":
    unittest.main()
