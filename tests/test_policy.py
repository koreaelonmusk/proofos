"""Configuration is a place where verification quietly stops working.

A policy file is edited by people under time pressure, often by the same agent
whose work it governs. The failure that matters is not a crash -- it is a policy
that parses, looks right, and no longer requires what the author thought it
required. ``max_age_second`` instead of ``max_age_seconds`` is one character and
turns a freshness horizon into nothing.

So the loader refuses everything it does not understand, and these tests pin
that refusal: unknown keys, unknown provenance, unknown schema versions, and
requirements that name no provenance this build can trust. The error messages
are tested too, because an error that does not say what to do is a defect with
better manners.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from proofos.policy import (
    POLICY_SCHEMA,
    STARTER_POLICY,
    Policy,
    PolicyError,
    load_policy,
    parse_policy,
)
from proofos.verifier import EvidenceSource

MINIMAL = {
    "version": POLICY_SCHEMA,
    "requirements": {"runtime_health": {"source": ["OBSERVED"], "max_age_seconds": 300}},
}


def write(text: str, suffix: str = ".toml") -> pathlib.Path:
    tmp = tempfile.mkdtemp()
    path = pathlib.Path(tmp) / f"policy{suffix}"
    path.write_text(text, encoding="utf-8")
    return path


class ParsingTests(unittest.TestCase):
    def test_a_minimal_policy_parses(self):
        policy = parse_policy(MINIMAL)
        self.assertEqual(len(policy.requirements), 1)
        req = policy.requirements[0]
        self.assertEqual(req.kind, "runtime_health")
        self.assertEqual(req.max_age_seconds, 300.0)
        self.assertIn(EvidenceSource.OBSERVED, req.sources)

    def test_it_compiles_to_the_kernels_own_requirement_type(self):
        # One model. The policy layer describes; the kernel decides, using the
        # same type every other entry point hands it.
        requirements = parse_policy(MINIMAL).as_requirements()
        self.assertEqual(requirements[0].kind, "runtime_health")
        self.assertEqual(requirements[0].max_age_seconds, 300.0)

    def test_a_requirement_with_no_declared_source_defaults_to_observed(self):
        # The safe default is the only one consistent with the product: an
        # omitted source must not quietly admit a self-report.
        policy = parse_policy({"version": POLICY_SCHEMA,
                               "requirements": {"tests": {}}})
        self.assertEqual(policy.requirements[0].sources,
                         frozenset({EvidenceSource.OBSERVED}))

    def test_the_starter_policy_this_tool_writes_is_valid(self):
        policy = load_policy(write(STARTER_POLICY))
        self.assertEqual({r.kind for r in policy.requirements},
                         {"runtime_health", "tests"})
        self.assertEqual(policy.unenforceable_sources, ())


class ItRefusesWhatItDoesNotUnderstandTests(unittest.TestCase):
    def assert_refuses(self, data, *, contains=""):
        with self.assertRaises(PolicyError) as caught:
            parse_policy(data, source="policy.toml")
        if contains:
            self.assertIn(contains, str(caught.exception))
        return caught.exception

    def test_a_misspelled_freshness_key_is_an_error_not_a_silent_disable(self):
        # The whole reason this loader is strict. Accepting this key would
        # remove the freshness horizon and nothing else would look wrong.
        error = self.assert_refuses(
            {"version": POLICY_SCHEMA,
             "requirements": {"runtime_health": {"max_age_second": 300}}},
            contains="unknown key 'max_age_second'",
        )
        self.assertIn("did you mean 'max_age_seconds'", error.fix)
        self.assertIn("requirements.runtime_health.max_age_second", error.path)

    def test_an_unknown_top_level_key_is_an_error(self):
        error = self.assert_refuses(
            {"version": POLICY_SCHEMA, "requirements": {"tests": {}}, "requirments": {}},
            contains="unknown key",
        )
        self.assertIn("did you mean 'requirements'", error.fix)

    def test_an_unknown_provenance_is_an_error(self):
        error = self.assert_refuses(
            {"version": POLICY_SCHEMA,
             "requirements": {"tests": {"source": ["TOTALLY_TRUSTED"]}}},
            contains="unknown provenance",
        )
        self.assertIn("OBSERVED", str(error))

    def test_an_unknown_schema_version_refuses_rather_than_guessing(self):
        error = self.assert_refuses(
            {"version": POLICY_SCHEMA + 98, "requirements": {"tests": {}}},
            contains="not supported by this build",
        )
        self.assertEqual(error.path, "version")

    def test_a_missing_version_is_an_error(self):
        self.assert_refuses({"requirements": {"tests": {}}}, contains="missing 'version'")

    def test_a_policy_with_no_requirements_is_an_error(self):
        # A policy that requires nothing would accept anything, which is a more
        # dangerous file than one that fails to parse.
        self.assert_refuses({"version": POLICY_SCHEMA, "requirements": {}},
                            contains="at least one requirement")
        self.assert_refuses({"version": POLICY_SCHEMA}, contains="at least one requirement")

    def test_a_non_numeric_freshness_is_an_error(self):
        self.assert_refuses(
            {"version": POLICY_SCHEMA,
             "requirements": {"tests": {"max_age_seconds": "five minutes"}}},
            contains="must be a number",
        )

    def test_a_non_positive_freshness_is_an_error(self):
        self.assert_refuses(
            {"version": POLICY_SCHEMA, "requirements": {"tests": {"max_age_seconds": 0}}},
            contains="must be positive",
        )

    def test_an_empty_source_list_is_an_error(self):
        self.assert_refuses(
            {"version": POLICY_SCHEMA, "requirements": {"tests": {"source": []}}},
            contains="non-empty",
        )

    def test_a_policy_that_is_not_a_table_is_an_error(self):
        self.assert_refuses(["runtime_health"], contains="must be a table")


class PolicyCannotWidenTrustTests(unittest.TestCase):
    """A policy says what must be proven. It cannot say what counts as proof."""

    def test_a_requirement_naming_only_executor_is_flagged_as_unsatisfiable(self):
        # Someone writes source = ["EXECUTOR"] hoping to accept a self-report.
        # It parses -- the file is well-formed -- but the kernel will never
        # satisfy it, and the operator is told so rather than discovering a
        # permanent ABSTAIN weeks later.
        policy = parse_policy({
            "version": POLICY_SCHEMA,
            "requirements": {"runtime_health": {"source": ["EXECUTOR"]}},
        })
        self.assertEqual(policy.unenforceable_sources, ("runtime_health",))

    def test_a_requirement_naming_observed_is_not_flagged(self):
        policy = parse_policy({
            "version": POLICY_SCHEMA,
            "requirements": {"runtime_health": {"source": ["EXECUTOR", "OBSERVED"]}},
        })
        self.assertEqual(policy.unenforceable_sources, ())

    def test_the_policy_model_carries_no_verdict_field(self):
        fields = set(Policy.__dataclass_fields__)
        for forbidden in ("status", "verified", "decision", "verdict", "trusted_sources"):
            self.assertNotIn(forbidden, fields)

    def test_the_policy_module_never_names_a_verdict(self):
        source = (pathlib.Path(__file__).resolve().parent.parent
                  / "proofos" / "policy.py").read_text(encoding="utf-8")
        for literal in ("VerificationStatus", "VERIFIED", "verify_completion"):
            self.assertNotIn(literal, source,
                             f"policy.py mentions {literal!r}; policies do not decide")


class FormatsAgreeTests(unittest.TestCase):
    """Three syntaxes, one model."""

    def test_toml_and_json_produce_the_same_policy(self):
        toml = write(
            "version = 1\n"
            '[requirements.runtime_health]\n'
            'source = ["OBSERVED"]\n'
            "max_age_seconds = 300\n"
        )
        js = write(json.dumps(MINIMAL), suffix=".json")
        a, b = load_policy(toml), load_policy(js)
        self.assertEqual(a.as_dict()["requirements"], b.as_dict()["requirements"])

    def test_yaml_produces_the_same_policy_when_pyyaml_is_present(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is an optional dependency and is absent")
        path = write(
            "version: 1\n"
            "requirements:\n"
            "  runtime_health:\n"
            "    source: [OBSERVED]\n"
            "    max_age_seconds: 300\n",
            suffix=".yaml",
        )
        self.assertEqual(
            load_policy(path).as_dict()["requirements"],
            parse_policy(MINIMAL).as_dict()["requirements"],
        )

    def test_an_unsupported_extension_is_refused(self):
        with self.assertRaises(PolicyError) as caught:
            load_policy(write("version = 1", suffix=".ini"))
        self.assertIn("unsupported policy format", str(caught.exception))

    def test_a_missing_file_says_how_to_create_one(self):
        with self.assertRaises(PolicyError) as caught:
            load_policy("definitely-not-a-policy.toml")
        self.assertIn("proofos init", str(caught.exception))


class ErrorMessageQualityTests(unittest.TestCase):
    """An error that does not say what to do is a defect with better manners."""

    def test_every_error_names_the_file_the_problem_and_a_fix(self):
        cases = [
            {"version": POLICY_SCHEMA, "requirements": {"t": {"max_age_second": 1}}},
            {"version": 99, "requirements": {"t": {}}},
            {"requirements": {"t": {}}},
            {"version": POLICY_SCHEMA, "requirements": {}},
        ]
        for data in cases:
            with self.assertRaises(PolicyError) as caught:
                parse_policy(data, source="proofos.toml")
            rendered = caught.exception.render()
            self.assertIn("proofos.toml", rendered)
            self.assertTrue(caught.exception.problem)
            self.assertIn("fix", rendered, f"no suggested fix for {data}")


if __name__ == "__main__":
    unittest.main()
