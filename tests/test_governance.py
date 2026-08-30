"""Governance documents must not drift into claiming things that are not true.

These tests guard a specific failure: a design document quietly reading as a
deployed state. Nothing here checks prose style. Each test defends one
load-bearing invariant, and each is written so that it fails if the invariant
stops holding rather than if the wording changes.
"""
from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SECURITY = ROOT / "SECURITY.md"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
DESIGN = ROOT / "docs" / "governance" / "branch-protection-design.md"

GOVERNANCE_DOCS = (SECURITY, CONTRIBUTING, DESIGN)


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


class GovernanceDocumentsExistTests(unittest.TestCase):
    def test_every_governance_document_is_present(self):
        for path in (SECURITY, CONTRIBUTING, CODEOWNERS, DESIGN):
            self.assertTrue(path.exists(), f"{path.name} is missing")


class TheDesignDoesNotClaimToBeAppliedTests(unittest.TestCase):
    """A proposal that reads as a deployed control is the failure to prevent."""

    def test_the_design_declares_itself_not_applied(self):
        text = read(DESIGN)
        self.assertIn("STATUS: DESIGNED, NOT APPLIED", text)
        self.assertIn("REMOTE ADMIN MUTATION: 0", text)

    def test_the_design_records_the_enforcement_state_as_negative(self):
        text = read(DESIGN).lower()
        for line in ("ruleset created    no", "ruleset enabled    no",
                     "ruleset applied    no"):
            self.assertIn(line, text,
                          "the design must state that nothing is enforcing")

    def test_no_ruleset_identifier_is_committed(self):
        """A ruleset id would be evidence of a ruleset that exists remotely."""
        for path in GOVERNANCE_DOCS:
            text = read(path)
            self.assertIsNone(
                re.search(r"ruleset[_ ]?id[\"']?\s*[:=]\s*[\"']?\d+", text, re.I),
                f"{path.name} carries something shaped like a real ruleset id")

    def test_required_checks_are_not_presented_as_active(self):
        """Observed check names may be recorded; they may not be called enforced."""
        text = read(DESIGN)
        self.assertIn("Activation precondition", text)
        # the names appear, but the document must say they are not yet entered
        self.assertIn("not as an authorization to enter them", text)


class SecurityPolicyIsAccurateTests(unittest.TestCase):
    def test_private_vulnerability_reporting_is_not_claimed_to_be_enabled(self):
        """Observed remote state is `enabled: false`. The policy must not imply otherwise."""
        text = read(SECURITY)
        self.assertIn("Status: not enabled", text)
        self.assertIsNone(
            re.search(r"private vulnerability reporting is (now )?(enabled|available)",
                      text, re.I),
            "SECURITY.md claims a private channel that does not exist")

    def test_unreleased_builds_are_not_described_as_releases(self):
        text = read(SECURITY)
        self.assertIn("are **not** public releases", text)

    def test_the_separated_questions_are_stated(self):
        text = read(SECURITY)
        for phrase in ("Signed", "is not", "Trusted signer", "Authorized collector"):
            self.assertIn(phrase, text)


class ContributingPreservesMutationSemanticsTests(unittest.TestCase):
    def test_upstream_kills_are_not_equated_with_target_kills(self):
        text = read(CONTRIBUTING)
        self.assertIn("KILLED_UPSTREAM` is not equivalent to `KILLED_AT_TARGET", text)

    def test_all_four_mutation_states_are_documented(self):
        text = read(CONTRIBUTING)
        for state in ("KILLED_AT_TARGET", "KILLED_UPSTREAM", "SURVIVED", "NOT_APPLIED"):
            self.assertIn(state, text)

    def test_the_documented_gate_commands_exist(self):
        """A contributing guide that names a script nobody can run is a trap."""
        text = read(CONTRIBUTING)
        for script in re.findall(r"python (scripts/[\w./]+\.py)", text):
            self.assertTrue((ROOT / script).exists(), f"{script} does not exist")


class CodeownersDescribesRealPathsTests(unittest.TestCase):
    def test_every_owned_path_exists(self):
        """CODEOWNERS entries for paths that do not exist silently own nothing."""
        missing = []
        for raw in read(CODEOWNERS).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            pattern = line.split()[0]
            if pattern == "*":
                continue
            if not (ROOT / pattern.lstrip("/")).exists():
                missing.append(pattern)
        self.assertEqual([], missing, f"CODEOWNERS owns paths that do not exist: {missing}")

    def test_codeowners_does_not_claim_to_be_enforcement(self):
        text = read(CODEOWNERS)
        self.assertIn("it enforces nothing", text.lower().replace("by itself ", ""))


class GovernanceKeepsTheVerdictVocabularyTests(unittest.TestCase):
    def test_the_two_outcomes_are_the_only_ones_named(self):
        """Governance prose must not invent a third verdict."""
        invented = ("PARTIALLY_VERIFIED", "LIKELY_VERIFIED", "PROBABLY_VERIFIED",
                    "AUTO_VERIFIED", "TRUSTED_VERIFIED")
        for path in GOVERNANCE_DOCS:
            text = read(path)
            for word in invented:
                self.assertNotIn(word, text, f"{path.name} invents the verdict {word}")

    def test_no_governance_document_grants_authority_to_an_adapter(self):
        text = read(CONTRIBUTING)
        self.assertIn("Adapter translates. Kernel decides.", text)
        for bad in ("adapters may mint", "adapter may mark", "framework state is authority"):
            self.assertNotIn(bad, text.lower())


if __name__ == "__main__":
    unittest.main()
