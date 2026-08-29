"""A plugin connects ProofOS to the world. It does not get a vote on the verdict.

The claim under test is one sentence: installing a plugin does not make its
output trusted evidence. That is easy to write in a README and hard to keep
true, because every convenience anyone will ever ask for -- "just let my
collector mark it observed", "let this one skip the freshness check" -- is a
request to make it false.

So the tests here are mostly refusals, and the important ones are structural
rather than behavioural. A test that a particular malicious manifest is rejected
proves something about that manifest. A test that the permission vocabulary
contains no way to spell "verify" proves something about every manifest that
will ever be written.
"""

from __future__ import annotations

import ast
import json
import pathlib
import tempfile
import unittest

from proofos.plugins import (
    FLOATING_REFERENCES,
    PLUGIN_SCHEMA,
    REFUSED_PERMISSIONS,
    Permission,
    PluginError,
    PluginKind,
    PluginManifest,
    load_manifest,
    parse_manifest,
)

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "plugins.py"

VALID = {
    "schema_version": PLUGIN_SCHEMA,
    "plugin_id": "http-health",
    "version": "1.0.0",
    "kind": "collector",
    "entrypoint": "acme.health:Collector",
    "description": "Probes an HTTP health endpoint and reports what it saw.",
    "minimum_proofos_version": "0.1.0",
    "permissions": ["network", "submit_observation"],
    "network_scope": ["status.example.com"],
    "evidence_kinds": ["runtime_health"],
}


def manifest(**overrides) -> dict:
    return {**VALID, **overrides}


class AWellFormedManifestParsesTests(unittest.TestCase):
    def test_the_reference_manifest_parses(self):
        m = parse_manifest(VALID)
        self.assertEqual(m.plugin_id, "http-health")
        self.assertIs(m.kind, PluginKind.COLLECTOR)
        self.assertEqual(m.permissions,
                         frozenset({Permission.NETWORK, Permission.SUBMIT_OBSERVATION}))

    def test_it_round_trips_through_its_own_dict(self):
        first = parse_manifest(VALID)
        second = parse_manifest({**first.as_dict(), "schema_version": PLUGIN_SCHEMA})
        self.assertEqual(first, second)

    def test_toml_and_json_agree(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        (tmp / "p.json").write_text(json.dumps(VALID), encoding="utf-8")
        (tmp / "p.toml").write_text(
            f'schema_version = {PLUGIN_SCHEMA}\n'
            'plugin_id = "http-health"\n'
            'version = "1.0.0"\n'
            'kind = "collector"\n'
            'entrypoint = "acme.health:Collector"\n'
            'description = "Probes an HTTP health endpoint and reports what it saw."\n'
            'minimum_proofos_version = "0.1.0"\n'
            'permissions = ["network", "submit_observation"]\n'
            'network_scope = ["status.example.com"]\n'
            'evidence_kinds = ["runtime_health"]\n',
            encoding="utf-8",
        )
        self.assertEqual(load_manifest(tmp / "p.json"), load_manifest(tmp / "p.toml"))


class TheVocabularyCannotExpressAuthorityTests(unittest.TestCase):
    """The strongest tests here. These constrain manifests nobody has written yet."""

    def test_no_permission_grants_verification(self):
        # Not "verify is rejected" -- there is no such permission to reject.
        # Adding one would fail here before any manifest existed to use it.
        vocabulary = {str(p) for p in Permission}
        for forbidden in ("verify", "verification", "decide", "set_verified",
                          "write_observed", "observed", "disable_freshness",
                          "modify_policy", "modify_registry", "append_journal",
                          "impersonate_collector"):
            self.assertNotIn(forbidden, vocabulary,
                             f"the permission vocabulary can spell {forbidden!r}")

    def test_there_is_no_verifier_plugin_kind(self):
        # Two verification kernels means the verdict depends on which was asked.
        kinds = {str(k) for k in PluginKind}
        for forbidden in ("verifier", "verification", "judge", "arbiter"):
            self.assertNotIn(forbidden, kinds)

    def test_a_manifest_carries_no_verdict_and_no_provenance_field(self):
        fields = set(PluginManifest.__dataclass_fields__)
        for forbidden in ("source", "provenance", "trusted", "verdict", "status",
                          "verified", "collector_id", "grant", "capability"):
            self.assertNotIn(forbidden, fields,
                             f"a manifest can declare {forbidden!r}")

    def test_the_module_has_no_route_to_provenance_assignment(self):
        # Provenance is assigned at the ingestion boundary by the one holder of
        # an observation capability. If this module could import that, the
        # rest of these tests would be describing a fence with a gate in it.
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in ("EvidenceSource", "ObservationCapability",
                          "AttestationIngestor", "proofos.ingestion",
                          "proofos.capabilities", "CollectorRegistry",
                          ".ingestion", ".capabilities", ".collector_registry",
                          ".verifier"):
            self.assertNotIn(forbidden, imported,
                             f"plugins.py imports {forbidden}")


class RefusedByNameTests(unittest.TestCase):
    """An author reaching for authority gets told why, not 'unknown value'."""

    def test_every_refused_permission_is_refused_with_a_reason(self):
        self.assertTrue(REFUSED_PERMISSIONS, "the refusal list is empty")
        for name, reason in REFUSED_PERMISSIONS.items():
            with self.subTest(permission=name):
                with self.assertRaises(PluginError) as caught:
                    parse_manifest(manifest(permissions=[name]))
                rendered = str(caught.exception)
                self.assertIn(name, rendered)
                self.assertIn(reason.split(".")[0][:24], rendered,
                              "the refusal does not explain itself")

    def test_asking_for_a_verifier_kind_says_why_there_is_none(self):
        with self.assertRaises(PluginError) as caught:
            parse_manifest(manifest(kind="verifier"))
        self.assertIn("one verification kernel", str(caught.exception).lower())


class MalformedManifestsAreRefusedTests(unittest.TestCase):
    def assert_refuses(self, data, *, contains=""):
        with self.assertRaises(PluginError) as caught:
            parse_manifest(data, source="plugin.toml")
        if contains:
            self.assertIn(contains, str(caught.exception))
        return caught.exception

    def test_an_unknown_key_is_an_error(self):
        error = self.assert_refuses(manifest(permisions=["network"]),
                                    contains="unknown key")
        self.assertIn("permissions", error.fix)

    def test_an_unknown_schema_version_refuses_rather_than_guessing(self):
        self.assert_refuses(manifest(schema_version=PLUGIN_SCHEMA + 40),
                            contains="not supported by this build")

    def test_a_missing_required_key_is_an_error(self):
        for key in ("plugin_id", "version", "kind", "entrypoint", "description",
                    "minimum_proofos_version", "permissions"):
            with self.subTest(key=key):
                data = manifest()
                data.pop(key)
                self.assert_refuses(data, contains=f"missing '{key}'")

    def test_permissions_must_be_a_list_even_when_empty(self):
        self.assert_refuses(manifest(permissions="network"), contains="must be a list")

    def test_an_unknown_permission_suggests_a_real_one(self):
        error = self.assert_refuses(manifest(permissions=["netwrok"]),
                                    contains="unknown permission")
        self.assertIn("network", error.fix)

    def test_a_manifest_that_is_not_a_table_is_an_error(self):
        self.assert_refuses(["http-health"], contains="must be a table")

    def test_an_id_that_is_not_a_plain_name_is_an_error(self):
        for bad in ("Http Health", "http_health", "../etc/passwd", ""):
            with self.subTest(plugin_id=bad):
                with self.assertRaises(PluginError):
                    parse_manifest(manifest(plugin_id=bad))


class PinningTests(unittest.TestCase):
    """An integration that can change underneath you is one nobody reviewed."""

    def test_a_floating_version_is_refused(self):
        for reference in sorted(FLOATING_REFERENCES):
            if reference == "*":
                continue
            with self.subTest(version=reference):
                with self.assertRaises(PluginError):
                    parse_manifest(manifest(version=reference))

    def test_a_floating_commit_is_refused(self):
        with self.assertRaises(PluginError):
            parse_manifest(manifest(source_commit="main"))

    def test_a_version_alone_is_not_pinning(self):
        # A tag can move. Only a commit or a digest answers "the same code".
        self.assertFalse(parse_manifest(VALID).is_pinned)
        pinned = parse_manifest(manifest(source_commit="a" * 40))
        self.assertTrue(pinned.is_pinned)


class CoherenceTests(unittest.TestCase):
    """Individually valid fields that are jointly nonsense."""

    def test_network_permission_without_a_scope_is_refused(self):
        with self.assertRaises(PluginError) as caught:
            parse_manifest(manifest(network_scope=[]))
        self.assertIn("names no hosts", str(caught.exception))

    def test_a_scope_without_the_permission_is_refused(self):
        with self.assertRaises(PluginError):
            parse_manifest(manifest(permissions=["submit_observation"]))

    def test_only_evidence_producing_kinds_may_declare_evidence_kinds(self):
        with self.assertRaises(PluginError):
            parse_manifest(manifest(kind="reporter", permissions=["report"],
                                    network_scope=[], evidence_kinds=["tests"]))

    def test_a_collector_that_cannot_submit_has_nothing_to_do(self):
        with self.assertRaises(PluginError):
            parse_manifest(manifest(permissions=["network"]))


class IdentitiesStaySeparateTests(unittest.TestCase):
    def test_a_plugin_id_is_not_a_collector_id(self):
        # A plugin that ships a collector does not become one by being installed.
        # The identity that matters is the one whose key the sealed registry
        # holds, and a manifest cannot mention it at all.
        m = parse_manifest(VALID)
        self.assertEqual(m.plugin_id, "http-health")
        self.assertFalse(hasattr(m, "collector_id"))
        self.assertNotIn("collector_id", m.as_dict())

    def test_plugin_version_is_its_own_field(self):
        m = parse_manifest(VALID)
        self.assertEqual(m.version, "1.0.0")
        self.assertNotEqual(m.version, m.minimum_proofos_version)


if __name__ == "__main__":
    unittest.main()
