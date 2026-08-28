"""The public surface: what a developer touches, and what it must never let them do.

Two different anxieties are being tested here.

The first is ordinary product quality. Does the demo run with no account and no
network. Does `doctor` stay useful when optional integrations are absent. Do the
exit codes mean distinct things, because a CI pipeline reads them and cannot ask
a follow-up question.

The second is the one that matters. A friendlier entry point is exactly where a
second, slightly different definition of truth tends to appear -- a convenience
flag, a default that trusts the caller, an API that accepts a verdict instead of
evidence. So these tests assert what the surface *cannot* do: there is no way in,
through the façade or the CLI, to make a self-report satisfy a requirement.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
import pathlib

from proofos import Decision, Evidence, EvidenceSource, ProofOS, Requirement
from proofos.cli import (
    EXIT_ABSTAIN,
    EXIT_OPERATIONAL,
    EXIT_USAGE,
    EXIT_VERIFIED,
    main,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
NOW = 1_700_000_000.0


def executor_evidence(kind="runtime_health", at=NOW):
    return Evidence(kind=kind, value="agent says it is up",
                    source=EvidenceSource.EXECUTOR, collected_at=at,
                    collector="deploy-agent")


def observed_evidence(kind="runtime_health", at=NOW):
    return Evidence(kind=kind, value="probe HEALTHY",
                    source=EvidenceSource.OBSERVED, collected_at=at,
                    collector="http-health-collector")


def run(argv):
    out = io.StringIO()
    code = main(argv, out=out)
    return code, out.getvalue()


class PublicApiTests(unittest.TestCase):
    """The documented imports are a contract; refactoring must not break them."""

    def test_the_documented_symbols_import(self):
        import proofos

        for name in ("ProofOS", "Decision", "Requirement", "Evidence",
                     "EvidenceSource", "VerificationStatus", "FailureClass"):
            self.assertTrue(hasattr(proofos, name), f"proofos.{name} is not exported")

    def test_the_public_surface_is_declared(self):
        import proofos

        self.assertIn("ProofOS", proofos.__all__)
        self.assertIn("Decision", proofos.__all__)

    def test_the_facade_refuses_a_self_report(self):
        decision = ProofOS().verify(
            claim="Deployment complete.",
            requirements=[Requirement("runtime_health", max_age_seconds=300)],
            evidence=[executor_evidence()],
            now=NOW,
        )
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")
        self.assertEqual(len(decision.rejected), 1)
        self.assertEqual(len(decision.accepted), 0)

    def test_the_facade_accepts_an_independent_observation(self):
        decision = ProofOS().verify(
            claim="Deployment complete.",
            requirements=[Requirement("runtime_health", max_age_seconds=300)],
            evidence=[executor_evidence(), observed_evidence()],
            now=NOW,
        )
        self.assertTrue(decision.verified)
        # The self-report is still refused; it just no longer matters.
        self.assertEqual([a.source for a in decision.rejected], ["EXECUTOR"])
        self.assertEqual([a.source for a in decision.accepted], ["OBSERVED"])

    def test_the_facade_honours_freshness(self):
        decision = ProofOS().verify(
            claim="Deployment complete.",
            requirements=[Requirement("runtime_health", max_age_seconds=300)],
            evidence=[observed_evidence(at=NOW - 86_400)],
            now=NOW,
        )
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_STALE")

    def test_the_facade_abstains_rather_than_raising_on_bad_input(self):
        # A verification layer that crashes on malformed input has handed the
        # caller an exception to swallow. It abstains instead.
        decision = ProofOS().verify(claim="", requirements=[], evidence=[], now=NOW)
        self.assertFalse(decision.verified)

    def test_the_decision_carries_the_kernels_own_result(self):
        decision = ProofOS().verify(
            "done", [Requirement("runtime_health")], [observed_evidence()], now=NOW
        )
        self.assertIs(decision.status, decision.raw.status)
        self.assertIs(decision.reason, decision.raw.failure)

    def test_the_facade_never_constructs_a_status_of_its_own(self):
        # `status=result.status` is a copy, not an assertion, so a crude
        # substring check would flag the correct code. The property that
        # matters is narrower: every field of the decision is read off the
        # kernel result, and no verdict literal appears anywhere.
        import inspect
        import re

        source = inspect.getsource(ProofOS)
        assignments = re.findall(r"(status|reason)\s*=\s*([^,\r\n]+)", source)
        for field, value in assignments:
            self.assertTrue(value.strip().startswith("result."),
                            f"{field} is set from {value.strip()!r}, not from the kernel")
        for literal in ("VerificationStatus.VERIFIED", "\"VERIFIED\"", "'VERIFIED'",
                        "force", "override", "trust_"):
            self.assertNotIn(literal, source,
                             f"the facade contains {literal!r}; it should only ask")

    def test_the_facade_signature_takes_evidence_not_a_verdict(self):
        import inspect

        params = list(inspect.signature(ProofOS.verify).parameters)
        self.assertEqual(params, ["self", "claim", "requirements", "evidence", "now"])


class ExitCodeTests(unittest.TestCase):
    """CI reads exit codes and cannot ask a follow-up question."""

    def test_the_codes_are_distinct(self):
        self.assertEqual(
            len({EXIT_VERIFIED, EXIT_ABSTAIN, EXIT_USAGE, EXIT_OPERATIONAL}), 4
        )

    def test_abstain_is_not_zero_and_not_an_error_code(self):
        # ABSTAIN is a product result. It must be distinguishable from success
        # and from a crash, because a pipeline treats those three differently.
        self.assertNotEqual(EXIT_ABSTAIN, EXIT_VERIFIED)
        self.assertNotEqual(EXIT_ABSTAIN, EXIT_OPERATIONAL)

    def test_no_arguments_prints_help_and_reports_usage(self):
        code, text = run([])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("usage: proofos", text)


class DoctorTests(unittest.TestCase):
    def test_doctor_succeeds_on_a_working_install(self):
        code, text = run(["doctor"])
        self.assertEqual(code, EXIT_VERIFIED)
        self.assertIn("REQUIRED", text)
        self.assertIn("OPTIONAL", text)

    def test_doctor_json_is_machine_readable(self):
        code, text = run(["doctor", "--json"])
        self.assertEqual(code, EXIT_VERIFIED)
        data = json.loads(text)
        self.assertEqual(data["schema_version"], 1)
        self.assertTrue(data["healthy"])
        self.assertTrue(data["required"])
        self.assertIn("optional", data)

    def test_a_missing_optional_integration_does_not_fail_the_install(self):
        # Absence of a cloud SDK is information, not a fault. A developer who
        # only wants the deterministic core must not be told they are broken.
        code, text = run(["doctor", "--json"])
        data = json.loads(text)
        absent = [c for c in data["optional"] if not c["present"]]
        self.assertEqual(code, EXIT_VERIFIED,
                         f"doctor failed despite only optional gaps: {absent}")


class DemoTests(unittest.TestCase):
    """The demo must teach the product, and must be a real verification."""

    def test_the_demo_shows_refusal_before_acceptance(self):
        code, text = run(["demo"])
        self.assertEqual(code, EXIT_VERIFIED)
        self.assertLess(text.index("ABSTAIN"), text.index("VERIFIED"),
                        "the demo reaches VERIFIED before showing the refusal")

    def test_the_demo_names_the_reason_the_self_report_was_refused(self):
        _, text = run(["demo"])
        self.assertIn("EVIDENCE_UNTRUSTED", text)
        self.assertIn("EXECUTOR", text)

    def test_the_demo_verdicts_come_from_the_kernel(self):
        # Not a printed story: re-running the same inputs through the façade
        # must produce the same two verdicts the demo displayed.
        proof = ProofOS()
        reqs = [Requirement("runtime_health", max_age_seconds=300)]
        first = proof.verify("Deployment complete.", reqs, [executor_evidence()], now=NOW)
        second = proof.verify(
            "Deployment complete.", reqs, [executor_evidence(), observed_evidence()], now=NOW
        )
        _, text = run(["demo"])
        self.assertIn(str(first.status), text)
        self.assertIn(str(second.status), text)

    def test_the_demo_json_has_both_steps(self):
        code, text = run(["demo", "--json"])
        self.assertEqual(code, EXIT_VERIFIED)
        data = json.loads(text)
        steps = {s["step"]: s for s in data["steps"]}
        self.assertEqual(steps["self_report_only"]["status"], "ABSTAIN")
        self.assertEqual(steps["independent_observation"]["status"], "VERIFIED")

    def test_the_demo_makes_no_network_call(self):
        source = (ROOT / "proofos" / "cli.py").read_text(encoding="utf-8")
        for primitive in ("urlopen", "requests", "httpx", "socket",
                          "XMLHttpRequest", "urllib.request"):
            self.assertNotIn(primitive, source,
                             f"the CLI can reach the network via {primitive}")

    def test_the_cli_imports_no_cloud_sdk_at_module_level(self):
        # `proofos --help` must stay instant and must not fail because an
        # optional integration is missing.
        source = (ROOT / "proofos" / "cli.py").read_text(encoding="utf-8")
        head = source.split("# -- presentation", 1)[0]
        for heavy in ("google", "fastapi", "cryptography", "firestore"):
            self.assertNotIn(heavy, head,
                             f"cli.py imports {heavy} at module level")


class VerifyCommandTests(unittest.TestCase):
    def verify_file(self, payload):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evidence.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return run(["verify", str(path), "--json", "--now", str(NOW)])

    def test_a_self_report_alone_abstains_and_exits_one(self):
        code, text = self.verify_file({
            "claim": "Deployment complete.",
            "requirements": [{"kind": "runtime_health", "max_age_seconds": 300}],
            "evidence": [{"kind": "runtime_health", "value": "agent says up",
                          "source": "EXECUTOR", "collected_at": NOW,
                          "collector": "deploy-agent"}],
        })
        self.assertEqual(code, EXIT_ABSTAIN)
        self.assertEqual(json.loads(text)["reason"], "EVIDENCE_UNTRUSTED")

    def test_an_independent_observation_verifies_and_exits_zero(self):
        code, text = self.verify_file({
            "claim": "Deployment complete.",
            "requirements": [{"kind": "runtime_health", "max_age_seconds": 300}],
            "evidence": [
                {"kind": "runtime_health", "value": "agent says up", "source": "EXECUTOR",
                 "collected_at": NOW, "collector": "deploy-agent"},
                {"kind": "runtime_health", "value": "probe HEALTHY", "source": "OBSERVED",
                 "collected_at": NOW, "collector": "http-health-collector"},
            ],
        })
        self.assertEqual(code, EXIT_VERIFIED)
        self.assertEqual(json.loads(text)["status"], "VERIFIED")

    def test_a_caller_cannot_declare_its_evidence_observed_and_win(self):
        # This is the obvious attack on a file-driven CLI, and it is meant to
        # work: `source` is a claim about the evidence, and the file is written
        # by whoever runs the command. The defence is that a real deployment
        # never lets the agent write this file -- provenance is assigned by the
        # authorized ingestion path, not by the caller.
        #
        # The test pins the honest behaviour so nobody mistakes the CLI for a
        # trust boundary it is not.
        code, text = self.verify_file({
            "claim": "Deployment complete.",
            "requirements": [{"kind": "runtime_health"}],
            "evidence": [{"kind": "runtime_health", "value": "trust me",
                          "source": "OBSERVED", "collected_at": NOW,
                          "collector": "deploy-agent"}],
        })
        self.assertEqual(code, EXIT_VERIFIED)
        self.assertIn("collector", json.loads(text)["evidence"][0])

    def test_a_missing_file_is_a_usage_error_not_a_crash(self):
        code, _ = run(["verify", "definitely-not-a-file.json"])
        self.assertEqual(code, EXIT_USAGE)

    def test_malformed_json_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            code, _ = run(["verify", str(path)])
        self.assertEqual(code, EXIT_USAGE)

    def test_an_unknown_provenance_value_is_a_usage_error(self):
        code, _ = self.verify_file({
            "claim": "done",
            "requirements": [{"kind": "runtime_health"}],
            "evidence": [{"kind": "runtime_health", "source": "TOTALLY_TRUSTED"}],
        })
        self.assertEqual(code, EXIT_USAGE)

    def test_a_missing_required_key_is_a_usage_error(self):
        code, _ = self.verify_file({"requirements": [{"kind": "runtime_health"}]})
        self.assertEqual(code, EXIT_USAGE)


class PackagingTests(unittest.TestCase):
    def test_pyproject_declares_the_console_entry_point(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('proofos = "proofos.cli:main"', text)

    def test_the_core_install_has_no_required_dependencies(self):
        # Someone who wants to see how ProofOS refuses a self-report should not
        # be made to install a model runtime to find out.
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        block = text.split("dependencies = ", 1)[1].split("\n", 1)[0]
        self.assertEqual(block.strip(), "[]")

    def test_optional_extras_are_declared(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        for extra in ("attestation", "google", "service", "dev"):
            self.assertIn(f"{extra} = [", text)

    def test_the_wheel_does_not_ship_tests_or_the_web_console(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        packages = text.split("packages = [", 1)[1].split("]", 1)[0]
        for unwanted in ("tests", "web", "scripts", "artifacts"):
            self.assertNotIn(f'"{unwanted}"', packages)


class HelpIsFastTests(unittest.TestCase):
    def test_help_runs_in_a_subprocess_without_optional_dependencies(self):
        # Runs the real entry point, so a module-level import of an optional
        # SDK would show up here as a failure rather than in a user's terminal.
        result = subprocess.run(
            [sys.executable, "-m", "proofos.cli", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, EXIT_VERIFIED, result.stderr)
        # argparse rewraps the description, so compare on normalised whitespace.
        flattened = " ".join(result.stdout.split())
        self.assertIn("An agent claim is not proof", flattened)


if __name__ == "__main__":
    unittest.main()
