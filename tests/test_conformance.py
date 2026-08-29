"""A suite is only worth running if it fails the plugins it should fail.

Three reference plugins pass it, which proves it is not impossible. The rest of
this file is plugins built to break each check in turn, because a conformance
suite that nothing fails is a suite nobody has tested -- and an author who runs
it would be collecting a green tick rather than a property.
"""

from __future__ import annotations

import ast
import pathlib
import socket
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from examples.plugins.artifact_digest import ArtifactDigest  # noqa: E402
from examples.plugins.ci_result import CiResult  # noqa: E402
from examples.plugins.http_health import HttpHealth  # noqa: E402
from proofos.conformance import (  # noqa: E402
    Observation,
    ObservationOutcome,
    ObservationRequest,
    FindingSeverity,
    check_plugin,
)
from proofos.plugins import PLUGIN_SCHEMA, parse_manifest  # noqa: E402

MODULE = ROOT / "proofos" / "conformance.py"

BASE = {
    "schema_version": PLUGIN_SCHEMA,
    "plugin_id": "adversary",
    "version": "1.0.0",
    "kind": "collector",
    "entrypoint": "tests:Adversary",
    "description": "A plugin written to break one rule at a time.",
    "minimum_proofos_version": "0.1.0",
    "permissions": ["submit_observation"],
    "evidence_kinds": ["runtime_health"],
    "source_commit": "0" * 40,
}


def failures(report) -> list[str]:
    return [f.check for f in report.findings if f.severity is FindingSeverity.FAIL]


class TheReferencePluginsConformTests(unittest.TestCase):
    def test_all_three_pass(self):
        for cls in (HttpHealth, CiResult, ArtifactDigest):
            with self.subTest(plugin=cls.__name__):
                report = check_plugin(cls())
                self.assertTrue(report.conformant, report.render())

    def test_a_passing_report_says_what_it_did_not_check(self):
        # A green tick that implies completeness is worse than no tick.
        report = check_plugin(CiResult())
        self.assertTrue(report.not_checked)
        self.assertIn("shells out", " ".join(report.not_checked))

    def test_the_reference_plugins_are_pinned(self):
        for cls in (HttpHealth, CiResult, ArtifactDigest):
            with self.subTest(plugin=cls.__name__):
                self.assertTrue(cls.manifest.is_pinned)

    def test_only_the_http_plugin_asks_for_the_network(self):
        self.assertTrue(HttpHealth.manifest.may_reach_network)
        self.assertFalse(CiResult.manifest.may_reach_network)
        self.assertFalse(ArtifactDigest.manifest.may_reach_network)


class AnUnreachableTargetMustNotLookHealthyTests(unittest.TestCase):
    def test_a_plugin_that_reports_healthy_when_it_saw_nothing_fails(self):
        class Optimist:
            manifest = parse_manifest(BASE)

            def observe(self, request):
                return Observation(kind=request.kind,
                                   outcome=ObservationOutcome.HEALTHY,
                                   observed_at=time.time(), detail="looks fine")

        self.assertIn("fails_closed", failures(check_plugin(Optimist())))

    def test_reporting_unhealthy_for_an_outage_also_fails(self):
        # Subtler and more common. Not reaching something is not finding it
        # broken, and only one of those is evidence about the target.
        class Pessimist:
            manifest = parse_manifest(BASE)

            def observe(self, request):
                return Observation(kind=request.kind,
                                   outcome=ObservationOutcome.UNHEALTHY,
                                   observed_at=time.time(), detail="down")

        self.assertIn("fails_closed", failures(check_plugin(Pessimist())))

    def test_raising_instead_of_returning_fails(self):
        class Thrower:
            manifest = parse_manifest(BASE)

            def observe(self, request):
                raise ConnectionRefusedError("nope")

        report = check_plugin(Thrower())
        self.assertIn("fails_closed", failures(report))
        self.assertIn("ConnectionRefusedError", report.render())


class TheReturnTypeIsTheBoundaryTests(unittest.TestCase):
    def test_returning_something_other_than_an_observation_fails(self):
        class Dictish:
            manifest = parse_manifest(BASE)

            def observe(self, request):
                return {"outcome": "HEALTHY", "source": "OBSERVED"}

        self.assertIn("return_type", failures(check_plugin(Dictish())))

    def test_smuggling_provenance_onto_the_return_value_fails(self):
        class Smuggler:
            manifest = parse_manifest(BASE)

            def observe(self, request):
                class Sneaky(Observation):
                    source = "OBSERVED"

                return Sneaky(kind=request.kind,
                              outcome=ObservationOutcome.UNAVAILABLE,
                              observed_at=time.time(), detail="")

        report = check_plugin(Smuggler())
        self.assertIn("return_type", failures(report))
        self.assertIn("source", report.render())

    def test_an_observation_has_nowhere_to_put_provenance(self):
        # The structural half of the argument: not "we reject it" but "there is
        # no field". A plugin cannot label its own output for the same reason it
        # cannot return a colour.
        fields = set(Observation.__dataclass_fields__)
        for forbidden in ("source", "provenance", "collector_id", "signature",
                          "nonce", "trusted", "verdict", "accepted"):
            self.assertNotIn(forbidden, fields)

    def test_a_request_carries_no_nonce_and_no_capability(self):
        fields = set(ObservationRequest.__dataclass_fields__)
        for forbidden in ("nonce", "capability", "grant", "key", "signing_key",
                          "collector_id"):
            self.assertNotIn(forbidden, fields)

    def test_unavailable_is_not_conclusive(self):
        blank = Observation(kind="runtime_health",
                            outcome=ObservationOutcome.UNAVAILABLE,
                            observed_at=0.0, detail="")
        self.assertFalse(blank.is_conclusive)
        seen = Observation(kind="runtime_health",
                           outcome=ObservationOutcome.UNHEALTHY,
                           observed_at=0.0, detail="")
        self.assertTrue(seen.is_conclusive)


class NetworkScopeTests(unittest.TestCase):
    def test_opening_a_socket_without_declaring_the_network_fails(self):
        class Sneaky:
            manifest = parse_manifest(BASE)  # no network permission

            def observe(self, request):
                try:
                    with socket.socket() as s:
                        s.settimeout(0.2)
                        s.connect(("127.0.0.1", 9))
                except OSError:
                    pass
                return Observation(kind=request.kind,
                                   outcome=ObservationOutcome.UNAVAILABLE,
                                   observed_at=time.time(), detail="")

        report = check_plugin(Sneaky())
        self.assertIn("undeclared_network", failures(report))

    def test_contacting_a_host_outside_the_declared_scope_fails(self):
        declared = parse_manifest({**BASE, "permissions":
                                   ["submit_observation", "network"],
                                   "network_scope": ["status.example.com"]})

        class Wanderer:
            manifest = declared

            def observe(self, request):
                with socket.socket() as s:
                    s.settimeout(0.2)
                    s.connect(("192.0.2.1", 80))
                return Observation(kind=request.kind,
                                   outcome=ObservationOutcome.UNAVAILABLE,
                                   observed_at=time.time(), detail="")

        self.assertIn("network_scope", failures(check_plugin(Wanderer())))

    def test_the_suite_restores_the_socket_it_replaced(self):
        original = socket.socket
        check_plugin(CiResult())
        self.assertIs(socket.socket, original)


class ManifestChecksTests(unittest.TestCase):
    def test_a_plugin_without_a_parsed_manifest_fails(self):
        class Bare:
            manifest = {"plugin_id": "bare"}

            def observe(self, request):
                return Observation(kind="x", outcome=ObservationOutcome.UNAVAILABLE,
                                   observed_at=0.0, detail="")

        report = check_plugin(Bare())
        self.assertFalse(report.conformant)
        self.assertIn("manifest", failures(report))

    def test_an_unpinned_plugin_warns_rather_than_fails(self):
        # Not pinned is a real risk and not a defect. Failing it would push
        # authors to write a commit hash they had not checked.
        unpinned = parse_manifest({k: v for k, v in BASE.items()
                                   if k != "source_commit"})

        class Floating:
            manifest = unpinned

            def observe(self, request):
                return Observation(kind=request.kind,
                                   outcome=ObservationOutcome.UNAVAILABLE,
                                   observed_at=time.time(), detail="")

        report = check_plugin(Floating())
        self.assertTrue(report.conformant, report.render())
        self.assertIn("pinning", [f.check for f in report.findings])


class TheSuiteCannotReachTheKernelTests(unittest.TestCase):
    def test_conformance_never_imports_the_ingestion_boundary(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in (".ingestion", ".capabilities", ".collector_registry",
                          "EvidenceSource", "ObservationCapability",
                          "AttestationIngestor", "verify_completion"):
            self.assertNotIn(forbidden, imported)


class TheReferencePluginsBehaveTests(unittest.TestCase):
    """Beyond conformance: do they actually report the right thing?"""

    def test_ci_result_reads_a_passing_run(self):
        tmp = pathlib.Path(tempfile.mkdtemp()) / "ci.json"
        tmp.write_text('{"conclusion": "success", "failed": 0, "run_id": 7}',
                       encoding="utf-8")
        observation = CiResult().observe(
            ObservationRequest(kind="tests", target=str(tmp)))
        self.assertIs(observation.outcome, ObservationOutcome.HEALTHY)
        self.assertEqual(observation.facts["run_id"], "7")

    def test_ci_result_reads_a_failing_run(self):
        tmp = pathlib.Path(tempfile.mkdtemp()) / "ci.json"
        tmp.write_text('{"conclusion": "failure", "failed": 3}', encoding="utf-8")
        observation = CiResult().observe(
            ObservationRequest(kind="tests", target=str(tmp)))
        self.assertIs(observation.outcome, ObservationOutcome.UNHEALTHY)

    def test_a_truncated_ci_file_is_unavailable_not_failing(self):
        tmp = pathlib.Path(tempfile.mkdtemp()) / "ci.json"
        tmp.write_text('{"conclusion": "suc', encoding="utf-8")
        observation = CiResult().observe(
            ObservationRequest(kind="tests", target=str(tmp)))
        self.assertIs(observation.outcome, ObservationOutcome.UNAVAILABLE)

    def test_artifact_digest_matches_hashlib(self):
        import hashlib

        tmp = pathlib.Path(tempfile.mkdtemp()) / "artifact.bin"
        payload = b"proofos" * 5000
        tmp.write_bytes(payload)
        observation = ArtifactDigest().observe(
            ObservationRequest(kind="artifact", target=str(tmp)))
        self.assertEqual(observation.response_digest,
                         hashlib.sha256(payload).hexdigest())
        self.assertEqual(observation.facts["bytes"], len(payload))

    def test_a_missing_artifact_is_unavailable_not_an_empty_digest(self):
        observation = ArtifactDigest().observe(
            ObservationRequest(kind="artifact", target="does-not-exist.bin"))
        self.assertIs(observation.outcome, ObservationOutcome.UNAVAILABLE)
        self.assertEqual(observation.response_digest, "")


if __name__ == "__main__":
    unittest.main()
