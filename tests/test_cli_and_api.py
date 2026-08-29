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

import inspect
import io
import json
import subprocess
import sys
import tempfile
import time
import unittest
import pathlib

from proofos import (
    Decision,
    Evidence,
    EvidenceLedger,
    EvidenceSource,
    ProofOS,
    Requirement,
)
from proofos.api import ProvenanceNotDeclarable
from proofos.capabilities import ObservationCapability
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
    """OBSERVED evidence, constructed directly.

    Kept because several tests need to prove that constructing one of these and
    handing it to the façade is refused. It is not how an observation reaches a
    verdict; ``recorded`` below is.
    """
    return Evidence(kind=kind, value="probe HEALTHY",
                    source=EvidenceSource.OBSERVED, collected_at=at,
                    collector="http-health-collector")


def recorded(*, requirements, self_report=True, observation_at=NOW,
             kind="runtime_health", task="T-1"):
    """A ledger holding evidence the way the runtime produces it.

    The self-report goes in directly, because saying "I did it" needs no
    authority. The observation goes through a capability, because writing
    OBSERVED does. That asymmetry is the product, so the tests build it rather
    than labelling two records differently.
    """
    ledger = EvidenceLedger()
    ledger.open_task(task, tuple(requirements))
    collector = ObservationCapability(ledger, "http-health-collector", (kind,))
    ledger.seal()
    if self_report:
        ledger.record(task, executor_evidence(kind=kind), None)
    if observation_at is not None:
        collector.record_observation(task, kind, "probe HEALTHY",
                                     satisfies=True, collected_at=observation_at)
    return ledger, task


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
        reqs = [Requirement("runtime_health", max_age_seconds=300)]
        ledger, task = recorded(requirements=reqs)
        decision = ProofOS().verify_recorded(ledger, task, "Deployment complete.",
                                             now=NOW)
        self.assertTrue(decision.verified)
        # The self-report is still refused; it just no longer matters.
        self.assertEqual([a.source for a in decision.rejected], ["EXECUTOR"])
        self.assertEqual([a.source for a in decision.accepted], ["OBSERVED"])

    def test_the_facade_honours_freshness(self):
        reqs = [Requirement("runtime_health", max_age_seconds=300)]
        ledger, task = recorded(requirements=reqs, self_report=False,
                                observation_at=NOW - 86_400)
        decision = ProofOS().verify_recorded(ledger, task, "Deployment complete.",
                                             now=NOW)
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_STALE")

    def test_the_facade_abstains_rather_than_raising_on_bad_input(self):
        # A verification layer that crashes on malformed input has handed the
        # caller an exception to swallow. It abstains instead.
        decision = ProofOS().verify(claim="", requirements=[], evidence=[], now=NOW)
        self.assertFalse(decision.verified)

    def test_the_decision_carries_the_kernels_own_result(self):
        ledger, task = recorded(requirements=[Requirement("runtime_health")])
        decision = ProofOS().verify_recorded(ledger, task, "done", now=NOW)
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
        claimed_ledger, task = recorded(requirements=reqs, observation_at=None)
        first = proof.verify_recorded(claimed_ledger, task, "Deployment complete.",
                                      now=NOW)
        resolved_ledger, task2 = recorded(requirements=reqs)
        second = proof.verify_recorded(resolved_ledger, task2, "Deployment complete.",
                                       now=NOW)
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

    def test_an_observation_cannot_arrive_through_a_file(self):
        # This used to exit 0. A file is written by whoever runs the command, so
        # accepting its `source` field meant the strongest statement in the
        # system was available to anyone who could type it.
        code, _ = self.verify_file({
            "claim": "Deployment complete.",
            "requirements": [{"kind": "runtime_health", "max_age_seconds": 300}],
            "evidence": [
                {"kind": "runtime_health", "value": "agent says up", "source": "EXECUTOR",
                 "collected_at": NOW, "collector": "deploy-agent"},
                {"kind": "runtime_health", "value": "probe HEALTHY", "source": "OBSERVED",
                 "collected_at": NOW, "collector": "http-health-collector"},
            ],
        })
        self.assertEqual(code, EXIT_USAGE)

    def test_a_caller_cannot_declare_its_evidence_observed_and_win(self):
        # This test asserted the opposite of its own name. It checked that
        # declaring OBSERVED *did* win, and a comment explained why that was
        # acceptable. Anyone reading the name would have concluded the hole was
        # closed; the assertion said it was open. A claim that is not supported
        # by its evidence is the thing this project exists to refuse, and it was
        # sitting in the test suite.
        code, text = self.verify_file({
            "claim": "Deployment complete.",
            "requirements": [{"kind": "runtime_health"}],
            "evidence": [{"kind": "runtime_health", "value": "trust me",
                          "source": "OBSERVED", "collected_at": NOW,
                          "collector": "deploy-agent"}],
        })
        self.assertEqual(code, EXIT_USAGE)

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


class InitCommandTests(unittest.TestCase):
    """Adding ProofOS to a project must never damage the project."""

    def test_init_creates_one_policy_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, text = run(["init", tmp])
            self.assertEqual(code, EXIT_VERIFIED)
            self.assertTrue((pathlib.Path(tmp) / "proofos.toml").exists())
            self.assertIn("created proofos.toml", text)

    def test_init_never_overwrites(self):
        # A tool that silently replaces configuration is a tool nobody runs a
        # second time, and in this project the file it would replace is the one
        # that says what must be proven.
        with tempfile.TemporaryDirectory() as tmp:
            policy = pathlib.Path(tmp) / "proofos.toml"
            policy.write_text("version = 1\n[requirements.mine]\n", encoding="utf-8")
            code, _ = run(["init", tmp])
            self.assertEqual(code, EXIT_USAGE)
            self.assertIn("requirements.mine", policy.read_text(encoding="utf-8"))

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, text = run(["init", tmp, "--dry-run"])
            self.assertEqual(code, EXIT_VERIFIED)
            self.assertFalse((pathlib.Path(tmp) / "proofos.toml").exists())
            self.assertIn("Would create", text)

    def test_init_json_lists_what_it_would_do(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, text = run(["init", tmp, "--dry-run", "--json"])
            self.assertEqual(code, EXIT_VERIFIED)
            data = json.loads(text)
            self.assertTrue(data["dry_run"])
            self.assertEqual(len(data["would_create"]), 1)
            self.assertEqual(data["already_present"], [])

    def test_a_missing_directory_is_a_usage_error(self):
        code, _ = run(["init", "definitely-not-a-directory"])
        self.assertEqual(code, EXIT_USAGE)

    def test_what_init_writes_is_immediately_usable(self):
        # The generated policy must parse with the same loader that verify
        # uses. A starter file that needs editing before it works is a starter
        # file that teaches the wrong thing.
        from proofos.policy import load_policy

        with tempfile.TemporaryDirectory() as tmp:
            run(["init", tmp])
            policy = load_policy(pathlib.Path(tmp) / "proofos.toml")
            self.assertTrue(policy.requirements)
            self.assertEqual(policy.unenforceable_sources, ())


class PolicyDrivenVerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        run(["init", str(self.dir)])
        self.policy = self.dir / "proofos.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def evidence(self, records):
        path = self.dir / "evidence.json"
        path.write_text(json.dumps({"claim": "Deployment complete.",
                                    "evidence": records}), encoding="utf-8")
        return path

    def test_a_policy_supplies_the_requirements(self):
        path = self.evidence([
            {"kind": "runtime_health", "value": "agent says up", "source": "EXECUTOR",
             "collected_at": NOW, "collector": "deploy-agent"},
        ])
        code, text = run(["verify", str(path), "--policy", str(self.policy),
                          "--json", "--now", str(NOW + 100)])
        self.assertEqual(code, EXIT_ABSTAIN)
        # The file named one kind; the policy is what says two are required.
        self.assertEqual(sorted(json.loads(text)["missing"]),
                         ["runtime_health", "tests"])

    def test_a_policy_does_not_let_a_file_declare_its_own_provenance(self):
        path = self.evidence([
            {"kind": "runtime_health", "value": "probe HEALTHY", "source": "OBSERVED",
             "collected_at": NOW, "collector": "http-collector"},
            {"kind": "tests", "value": "42 passed", "source": "OBSERVED",
             "collected_at": NOW, "collector": "ci"},
        ])
        code, _ = run(["verify", str(path), "--policy", str(self.policy),
                       "--now", str(NOW + 100)])
        self.assertEqual(code, EXIT_USAGE)

    def test_the_file_path_can_never_reach_verified(self):
        # The invariant left behind by the fix, stated as one property rather
        # than inferred from the cases above. Whatever a file says about where
        # its evidence came from, reading it cannot produce a verdict of
        # VERIFIED -- either the provenance is one the caller may not declare,
        # or it is one that cannot satisfy a requirement.
        for source in ("OBSERVED", "EXECUTOR", "MODEL"):
            with self.subTest(source=source):
                path = self.evidence([
                    {"kind": kind, "value": "whatever", "source": source,
                     "collected_at": NOW, "collector": "someone"}
                    for kind in ("runtime_health", "tests")
                ])
                code, _ = run(["verify", str(path), "--policy", str(self.policy),
                               "--now", str(NOW + 100)])
                self.assertNotEqual(code, EXIT_VERIFIED)

    def test_a_broken_policy_is_a_usage_error_not_a_verdict(self):
        broken = self.dir / "broken.toml"
        broken.write_text("version = 1\n[requirements.runtime_health]\n"
                          "max_age_second = 300\n", encoding="utf-8")
        path = self.evidence([])
        code, _ = run(["verify", str(path), "--policy", str(broken)])
        self.assertEqual(code, EXIT_USAGE)


class ProvenanceIsEarnedNotDeclaredTests(unittest.TestCase):
    """The façade used to accept a provenance its caller typed in.

    ``ProofOS().verify(evidence=[Evidence(..., source=OBSERVED)])`` returned
    verified=True. One line, through the documented front door, and the
    headline promise was false: the party asking for the verdict was supplying
    the independence.

    The kernel was never wrong about this. ``verify_completion`` is a decision
    function over evidence whose provenance is already settled, and every
    runtime path feeds it from a ledger. The façade was the one entry point
    where the label could be written rather than earned, and it was the first
    thing a new user would touch.
    """

    REQS = (Requirement("runtime_health", max_age_seconds=300),)

    def test_declaring_observed_is_refused(self):
        with self.assertRaises(ProvenanceNotDeclarable) as caught:
            ProofOS().verify("Deployment complete.", self.REQS,
                             [observed_evidence()], now=NOW)
        message = str(caught.exception)
        self.assertIn("runtime_health", message)
        self.assertIn("OBSERVED", message)

    def test_the_refusal_says_where_an_observation_comes_from(self):
        # An error that only says no teaches nothing. This one has to name the
        # path that does work, or the next thing the reader tries is a wrapper
        # around the thing that was just refused.
        with self.assertRaises(ProvenanceNotDeclarable) as caught:
            ProofOS().verify("done", self.REQS, [observed_evidence()], now=NOW)
        message = str(caught.exception)
        self.assertIn("ObservationCapability", message)
        self.assertIn("EvidenceLedger", message)

    def test_one_declared_record_taints_the_whole_call(self):
        # Not "filter it out and carry on". A caller who thought they were
        # supplying an observation should learn that, not receive a quieter
        # answer computed from the rest.
        with self.assertRaises(ProvenanceNotDeclarable):
            ProofOS().verify("done", self.REQS,
                             [executor_evidence(), observed_evidence()], now=NOW)

    def test_untrusted_provenance_is_still_answered_normally(self):
        # The refusal is about provenance a caller may not grant itself, not
        # about being strict with input. A self-report is a legitimate question.
        decision = ProofOS().verify("done", self.REQS, [executor_evidence()], now=NOW)
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")

    def test_the_refusal_is_derived_from_the_kernels_trusted_set(self):
        # If a later build decides some other provenance is independent, the
        # façade must refuse that one too. A hardcoded OBSERVED check would go
        # on passing while covering less than it did.
        from proofos.verifier import TRUSTED_SOURCES

        source = inspect.getsource(ProofOS._refuse_declared_provenance)
        self.assertIn("TRUSTED_SOURCES", source)
        self.assertNotIn("EvidenceSource.OBSERVED", source)
        self.assertIn(EvidenceSource.OBSERVED, TRUSTED_SOURCES)

    def test_a_ledger_observation_verifies(self):
        ledger, task = recorded(requirements=self.REQS)
        decision = ProofOS().verify_recorded(ledger, task, "Deployment complete.",
                                             now=NOW)
        self.assertTrue(decision.verified)
        self.assertEqual([a.source for a in decision.accepted], ["OBSERVED"])

    def test_the_ledger_path_takes_its_requirements_from_the_ledger(self):
        # A caller who could pass their own requirements here could ask an
        # easier question than the one the task was opened with.
        ledger, task = recorded(requirements=self.REQS, observation_at=None)
        decision = ProofOS().verify_recorded(ledger, task, "done", now=NOW)
        self.assertFalse(decision.verified)
        self.assertEqual(list(decision.missing), ["runtime_health"])

    def test_writing_observed_to_a_ledger_still_needs_a_grant(self):
        # The boundary the façade now defers to. Worth pinning here as well:
        # if this ever stopped holding, verify_recorded would inherit the hole
        # the façade just gave up.
        from proofos.capabilities import CapabilityDenied

        ledger = EvidenceLedger()
        ledger.open_task("T-2", self.REQS)
        ledger.seal()
        with self.assertRaises(CapabilityDenied):
            ledger.record("T-2", observed_evidence(), None)
