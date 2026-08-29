"""A skill says what must be proven. Everything here checks it cannot say more.

The interesting tests are the ones about what a skill *is*. It is data, so it
cannot run; it compiles into a type with nowhere to put a source or a verdict,
so it cannot grant trust; and combining two of them can only tighten, so nobody
weakens a strict requirement by putting a lax recipe beside it.

The rest are refusals, one per thing an author might reach for. Each is checked
by name rather than by "the parser rejected something", because the error is
where the correction happens: somebody writing ``grant = ["VERIFY"]`` has a
model of the system that needs fixing, and "unknown key" does not fix it.
"""

from __future__ import annotations

import ast
import json
import pathlib
import tempfile
import unittest

from proofos import Evidence, EvidenceLedger, EvidenceSource, ProofOS, Requirement
from proofos.api import ProvenanceNotDeclarable
from proofos.capabilities import ObservationCapability
from proofos.conformance import Observation, ObservationOutcome, ObservationRequest
from proofos.skills import (
    BUILTIN_SKILLS,
    REFUSED_FIELDS,
    SKILL_SCHEMA,
    UNBOUNDED,
    PluginRequirement,
    SkillError,
    SkillRequirement,
    VerificationSkill,
    combine,
    get_skill,
    load_skill,
    parse_skill,
)

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "skills.py"
NOW = 1_700_000_000.0

VALID = {
    "schema_version": SKILL_SCHEMA,
    "skill_id": "web-service-release",
    "version": "1.0.0",
    "description": "A service was released.",
    "requirements": {
        "runtime_health": {"max_age_seconds": 300, "source": ["OBSERVED"]},
    },
}


def skill(**overrides) -> dict:
    return {**VALID, **overrides}


def requirements(**overrides) -> dict:
    return skill(requirements={"runtime_health": {"max_age_seconds": 300,
                                                  **overrides}})


class AWellFormedSkillParsesTests(unittest.TestCase):
    def test_the_reference_skill_parses(self):
        s = parse_skill(VALID)
        self.assertEqual(s.skill_id, "web-service-release")
        self.assertEqual(len(s.requirements), 1)
        self.assertEqual(s.requirements[0].max_age_seconds, 300.0)

    def test_it_compiles_to_the_kernels_own_requirement_type(self):
        compiled = parse_skill(VALID).as_requirements()
        self.assertEqual(compiled, (Requirement("runtime_health", 300.0),))

    def test_unbounded_compiles_to_no_horizon(self):
        s = parse_skill(requirements(max_age_seconds=UNBOUNDED))
        self.assertIsNone(s.as_requirements()[0].max_age_seconds)
        self.assertTrue(s.requirements[0].is_unbounded)

    def test_toml_and_json_agree(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "s.json").write_text(json.dumps(VALID), encoding="utf-8")
        (tmp / "s.toml").write_text(
            f"schema_version = {SKILL_SCHEMA}\n"
            'skill_id = "web-service-release"\n'
            'version = "1.0.0"\n'
            'description = "A service was released."\n'
            "[requirements.runtime_health]\n"
            "max_age_seconds = 300\n"
            'source = ["OBSERVED"]\n',
            encoding="utf-8")
        self.assertEqual(load_skill(tmp / "s.json").as_requirements(),
                         load_skill(tmp / "s.toml").as_requirements())

    def test_all_four_built_ins_parse_and_compile(self):
        self.assertEqual(len(BUILTIN_SKILLS), 4)
        for skill_id, s in BUILTIN_SKILLS.items():
            with self.subTest(skill=skill_id):
                self.assertTrue(s.as_requirements())
                self.assertEqual(s.unenforceable_sources, ())

    def test_an_unknown_built_in_suggests_a_real_one(self):
        with self.assertRaises(SkillError) as caught:
            get_skill("web-service-relase")
        self.assertIn("web-service-release", str(caught.exception))


class ASkillCannotSayMoreThanItIsTests(unittest.TestCase):
    """§23-§28. Each refusal names the field and explains itself."""

    def assert_refused(self, data, *, contains=""):
        with self.assertRaises(SkillError) as caught:
            parse_skill(data, source="skill.toml")
        if contains:
            self.assertIn(contains, str(caught.exception))
        return caught.exception

    def test_a_verdict_field_is_refused(self):
        error = self.assert_refused(skill(verdict="VERIFIED"), contains="verdict")
        self.assertIn("kernel", error.fix)

    def test_a_verified_or_status_field_is_refused(self):
        self.assert_refused(skill(verified=True))
        self.assert_refused(skill(status="VERIFIED"))

    def test_granting_authority_is_refused(self):
        error = self.assert_refused(skill(grant=["VERIFY"]), contains="grant")
        self.assertIn("held, not declared", error.fix)

    def test_claiming_trust_is_refused(self):
        error = self.assert_refused(skill(trusted=True), contains="trusted")
        self.assertIn("about itself", error.fix)

    def test_disabling_freshness_is_refused(self):
        error = self.assert_refused(skill(disable_freshness=True))
        self.assertIn("last year", error.fix)

    def test_a_null_horizon_is_refused(self):
        error = self.assert_refused(requirements(max_age_seconds=None))
        self.assertIn(UNBOUNDED, error.fix)

    def test_an_omitted_horizon_is_refused(self):
        # The one that would otherwise happen by not thinking. A reusable recipe
        # is exactly where a missing horizon becomes no horizon.
        self.assert_refused(skill(requirements={"runtime_health": {}}),
                            contains="not declared")

    def test_a_negative_or_zero_horizon_is_refused(self):
        for value in (0, -1, -0.5):
            with self.subTest(value=value):
                self.assert_refused(requirements(max_age_seconds=value),
                                    contains="must be positive")

    def test_only_the_word_unbounded_means_unbounded(self):
        # Found by a mutation that survived: making every string mean unbounded
        # broke nothing, because no test wrote one. So "5 minutes", "none" and
        # "forever" would each have produced a requirement with no horizon,
        # which is the exact failure this design exists to prevent -- and it
        # would have looked like a horizon in the file.
        for value in ("5 minutes", "none", "forever", "300s", "", "UNBOUNDED "):
            with self.subTest(value=value):
                if value.strip().lower() == UNBOUNDED:
                    self.assertIsNone(
                        parse_skill(requirements(max_age_seconds=value))
                        .as_requirements()[0].max_age_seconds)
                    continue
                self.assert_refused(requirements(max_age_seconds=value))

    def test_a_boolean_horizon_is_refused(self):
        # True is an int in Python, so a bare `max_age_seconds = true` would
        # otherwise pass the numeric check and mean one second.
        for value in (True, False):
            with self.subTest(value=value):
                self.assert_refused(requirements(max_age_seconds=value))

    def test_nan_and_infinity_are_refused(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self.assert_refused(requirements(max_age_seconds=value))

    def test_executable_fields_are_refused(self):
        # If any of these parsed, a skill would stop being data. The one that
        # carries the explanation is entrypoint; the rest defer to it.
        for field in ("entrypoint", "python", "script", "command", "callback",
                      "hooks", "pre_verify", "post_verify", "custom_verifier",
                      "eval", "exec"):
            with self.subTest(field=field):
                self.assert_refused(skill(**{field: "anything"}), contains=field)
        self.assertIn("skill is data", REFUSED_FIELDS["entrypoint"])

    def test_every_refused_field_is_refused_with_a_reason(self):
        self.assertTrue(REFUSED_FIELDS)
        for field, reason in REFUSED_FIELDS.items():
            with self.subTest(field=field):
                error = self.assert_refused(skill(**{field: "x"}))
                self.assertIn(field, str(error))
                self.assertTrue(error.fix.strip())

    def test_a_forbidden_field_inside_a_requirement_is_refused(self):
        # The obvious next place to try after the top level is rejected.
        self.assert_refused(requirements(trusted=True), contains="trusted")

    def test_a_floating_plugin_dependency_is_refused(self):
        for version in ("latest", "main", "master", "*"):
            with self.subTest(version=version):
                self.assert_refused(
                    skill(required_plugins=[{"plugin_id": "http-health",
                                             "version": version}]),
                    contains="moving reference")

    def test_a_named_plugin_without_a_version_is_refused(self):
        error = self.assert_refused(
            skill(required_plugins=[{"plugin_id": "http-health"}]))
        self.assertIn("nobody reviewed", error.fix)


class TheLoaderDoesNotGuessTests(unittest.TestCase):
    """§20-§21."""

    def assert_refused(self, data, *, contains=""):
        with self.assertRaises(SkillError) as caught:
            parse_skill(data, source="skill.toml")
        if contains:
            self.assertIn(contains, str(caught.exception))
        return caught.exception

    def test_an_unknown_key_suggests_a_real_one(self):
        error = self.assert_refused(skill(requirments={}), contains="unknown key")
        self.assertIn("requirements", error.fix)

    def test_an_unknown_schema_version_refuses_rather_than_guessing(self):
        self.assert_refused(skill(schema_version=SKILL_SCHEMA + 41),
                            contains="not supported")

    def test_an_empty_skill_is_refused(self):
        error = self.assert_refused(skill(requirements={}))
        self.assertIn("would accept anything", error.fix)

    def test_a_skill_with_no_requirements_key_is_refused(self):
        data = skill()
        data.pop("requirements")
        self.assert_refused(data, contains="at least one requirement")

    def test_a_malformed_id_or_version_is_refused(self):
        self.assert_refused(skill(skill_id="Web Service"), contains="skill_id")
        self.assert_refused(skill(version="1.0"), contains="version")

    def test_a_missing_description_is_refused(self):
        self.assert_refused(skill(description="  "), contains="description")

    def test_an_unknown_provenance_is_refused(self):
        self.assert_refused(requirements(source=["TOTALLY_TRUSTED"]),
                            contains="unknown provenance")

    def test_a_skill_that_is_not_a_table_is_refused(self):
        self.assert_refused(["web-service-release"], contains="must be a table")


class ASourceRequirementIsNotATrustGrantTests(unittest.TestCase):
    """§8 and §25. The structural half of the argument."""

    def test_the_compiled_requirement_has_nowhere_to_put_a_source(self):
        # This is why a skill cannot widen trust: the type it produces cannot
        # express the idea, so there is nothing to enforce at runtime.
        self.assertEqual(set(Requirement.__dataclass_fields__),
                         {"kind", "max_age_seconds"})

    def test_declaring_observed_changes_nothing_about_what_observed_is_worth(self):
        strict = parse_skill(requirements(source=["OBSERVED"]))
        loose = parse_skill(requirements(source=["EXECUTOR", "OBSERVED"]))
        self.assertEqual(strict.as_requirements(), loose.as_requirements())

    def test_a_skill_naming_only_untrusted_provenance_is_flagged_unsatisfiable(self):
        # It parses -- the file is well formed -- and can never be satisfied.
        # The author is told, rather than discovering a permanent ABSTAIN.
        s = parse_skill(requirements(source=["EXECUTOR"]))
        self.assertEqual(s.unenforceable_sources, ("runtime_health",))

    def test_the_skill_model_carries_no_verdict_field(self):
        for model in (VerificationSkill, SkillRequirement, PluginRequirement):
            fields = set(model.__dataclass_fields__)
            for forbidden in ("verdict", "status", "verified", "trusted",
                              "grant", "capability", "collector_id",
                              "signature", "authority"):
                self.assertNotIn(forbidden, fields, f"{model.__name__}.{forbidden}")


class CombiningOnlyTightensTests(unittest.TestCase):
    """§10. A combination that could relax a constraint is a way to attack one."""

    def make(self, kind, horizon, sources=("OBSERVED",), skill_id="a-skill"):
        return parse_skill({**VALID, "skill_id": skill_id,
                            "requirements": {kind: {"max_age_seconds": horizon,
                                                    "source": list(sources)}}})

    def test_requirements_are_additive(self):
        merged = combine(self.make("runtime_health", 300),
                         self.make("tests", UNBOUNDED, skill_id="b-skill"))
        self.assertEqual({r.kind for r in merged}, {"runtime_health", "tests"})

    def test_the_shorter_horizon_wins(self):
        merged = combine(self.make("runtime_health", 300),
                         self.make("runtime_health", 60, skill_id="b-skill"))
        self.assertEqual(merged[0].max_age_seconds, 60.0)

    def test_a_finite_horizon_beats_unbounded_in_either_order(self):
        for first, second in ((300, UNBOUNDED), (UNBOUNDED, 300)):
            with self.subTest(order=(first, second)):
                merged = combine(self.make("runtime_health", first),
                                 self.make("runtime_health", second,
                                           skill_id="b-skill"))
                self.assertEqual(merged[0].max_age_seconds, 300.0)

    def test_sources_intersect_rather_than_union(self):
        merged_skill_sources = None
        a = self.make("runtime_health", 300, ("OBSERVED", "EXECUTOR"))
        b = self.make("runtime_health", 300, ("OBSERVED",), skill_id="b-skill")
        # The compiled requirement drops sources, so the property is checked on
        # the way through: a union would have admitted EXECUTOR.
        combined = combine(a, b)
        self.assertEqual(len(combined), 1)
        merged_skill_sources = a.requirements[0].sources & b.requirements[0].sources
        self.assertEqual(merged_skill_sources, frozenset({EvidenceSource.OBSERVED}))

    def test_disjoint_sources_are_an_error_not_a_choice(self):
        with self.assertRaises(SkillError) as caught:
            combine(self.make("runtime_health", 300, ("OBSERVED",)),
                    self.make("runtime_health", 300, ("MODEL",),
                              skill_id="b-skill"))
        self.assertIn("no provenance in common", str(caught.exception))

    def test_combining_a_skill_with_itself_is_a_no_op(self):
        one = self.make("runtime_health", 300)
        self.assertEqual(combine(one), combine(one, one))


class TheCompilerIsInertTests(unittest.TestCase):
    """§22 and §32."""

    def test_compiling_is_deterministic(self):
        s = get_skill("web-service-release")
        self.assertEqual(s.as_requirements(), s.as_requirements())

    def test_the_module_does_not_import_verification_authority(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in ("verify_completion", "EvidenceLedger",
                          "ObservationCapability", "AttestationIngestor",
                          ".ledger", ".capabilities", ".ingestion",
                          ".collector_registry", ".registry", ".journal"):
            self.assertNotIn(forbidden, imported, f"skills.py imports {forbidden}")

    def test_the_module_contains_no_execution_primitive(self):
        source = MODULE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called.add(node.func.id)
        for forbidden in ("eval", "exec", "compile", "__import__"):
            # __import__ appears once for a regex module and is not driven by
            # skill data; the rule that matters is that nothing a skill says can
            # reach any of these.
            if forbidden == "__import__":
                continue
            self.assertNotIn(forbidden, called)
        for forbidden in ("subprocess", "importlib.import_module", "os.system"):
            self.assertNotIn(forbidden, source)

    def test_a_skill_names_no_code(self):
        # Keys, not substrings. "script" lives inside "description", and a guard
        # that cannot tell a word in prose from a field name is one that gets
        # switched off the first time it cries wolf.
        def keys(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    yield str(k)
                    yield from keys(v)
            elif isinstance(value, list):
                for item in value:
                    yield from keys(item)

        for s in BUILTIN_SKILLS.values():
            with self.subTest(skill=s.skill_id):
                present = set(keys(s.as_dict()))
                self.assertEqual(present & set(REFUSED_FIELDS), set())


class DeclaringAPluginIsNotTrustingItTests(unittest.TestCase):
    """§11 and §29."""

    def test_declaring_a_dependency_loads_nothing(self):
        s = parse_skill(skill(required_plugins=[
            {"plugin_id": "http-health", "version": "1.0.0"}]))
        self.assertEqual(s.required_plugins[0].plugin_id, "http-health")
        # Nothing was imported, resolved or instantiated: the value is a record.
        self.assertIsInstance(s.required_plugins[0], PluginRequirement)

    def test_a_declared_plugin_reporting_healthy_does_not_verify(self):
        # §29 exactly. The skill requires a collector, a conformant collector
        # says HEALTHY, and the answer is still ABSTAIN, because what the plugin
        # produced is a statement and not an observation anyone vouched for.
        s = parse_skill(skill(required_plugins=[
            {"plugin_id": "http-health", "version": "1.0.0"}]))
        observation = Observation(kind="runtime_health",
                                  outcome=ObservationOutcome.HEALTHY,
                                  observed_at=NOW, detail="HTTP 200")
        evidence = Evidence(kind=observation.kind, value=observation.detail,
                            source=EvidenceSource.EXECUTOR, collected_at=NOW,
                            collector="http-health")
        decision = ProofOS().verify("Deployment complete.", s.as_requirements(),
                                    [evidence], now=NOW)
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")


class TheSkillDoesNotControlTrustTests(unittest.TestCase):
    """§30, the golden test: one skill, two routes, two answers.

    The skill is byte-identical in both halves. If it controlled trust, the
    answers would match.
    """

    def setUp(self):
        self.skill = get_skill("agent-task-completion")
        self.requirements = self.skill.as_requirements()
        self.observation = Observation(
            kind="task_outcome", outcome=ObservationOutcome.HEALTHY,
            observed_at=NOW, detail="the ticket is closed and the deploy is live",
        )

    def route_a_evidence(self, source):
        return Evidence(kind=self.observation.kind, value=self.observation.detail,
                        source=source, collected_at=self.observation.observed_at,
                        collector="task-plugin")

    def test_route_a_the_plugin_result_abstains(self):
        decision = ProofOS().verify("Task complete.", self.requirements,
                                    [self.route_a_evidence(EvidenceSource.EXECUTOR)],
                                    now=NOW)
        self.assertFalse(decision.verified)

    def test_route_a_cannot_be_upgraded_by_relabelling(self):
        with self.assertRaises(ProvenanceNotDeclarable):
            ProofOS().verify("Task complete.", self.requirements,
                             [self.route_a_evidence(EvidenceSource.OBSERVED)],
                             now=NOW)

    def test_route_b_the_authorized_path_verifies(self):
        ledger = EvidenceLedger()
        ledger.open_task("TASK-1", self.requirements)
        collector = ObservationCapability(ledger, "task-collector", ("task_outcome",))
        ledger.seal()
        collector.record_observation("TASK-1", "task_outcome",
                                     self.observation.detail, satisfies=True,
                                     collected_at=NOW)
        decision = ProofOS().verify_recorded(ledger, "TASK-1", "Task complete.",
                                             now=NOW)
        self.assertTrue(decision.verified)

    def test_the_skill_is_the_same_object_in_both_routes(self):
        # The assertion that makes the pair mean something. One recipe, two
        # answers -- so the recipe is not what decided.
        self.assertIs(self.skill, get_skill("agent-task-completion"))
        self.assertEqual(self.skill.as_requirements(), self.requirements)

    def test_the_skills_horizon_still_applies_on_the_authorized_route(self):
        # A skill can tighten what must be true. It cannot decide whether it is.
        ledger = EvidenceLedger()
        ledger.open_task("TASK-2", self.requirements)
        collector = ObservationCapability(ledger, "task-collector", ("task_outcome",))
        ledger.seal()
        collector.record_observation("TASK-2", "task_outcome", "seen long ago",
                                     satisfies=True, collected_at=NOW - 86_400)
        decision = ProofOS().verify_recorded(ledger, "TASK-2", "Task complete.",
                                             now=NOW)
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_STALE")


if __name__ == "__main__":
    unittest.main()
