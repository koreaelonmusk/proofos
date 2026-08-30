"""The red-team arena is itself a claim, so it needs its own guards.

An arena that cannot report a break, or that counts an out-of-scope move as
one, produces numbers that look like security evidence and are not. These
tests defend the two failure directions.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

sys.path.insert(0, str(ROOT / "redteam"))
import arena  # noqa: E402


class TheArenaDefeatsEveryWrittenAttemptTests(unittest.TestCase):
    def test_no_attempt_produces_a_confirmed_bypass(self):
        broke = []
        for name, mod in arena.load_attempts():
            result = arena.adjudicate(mod)
            if result["outcome"] == arena.BYPASS_CONFIRMED:
                broke.append((name, result["detail"]))
        self.assertEqual([], broke, f"a red-team attempt reached VERIFIED: {broke}")

    def test_no_attempt_is_merely_broken(self):
        """An attempt that errors is not evidence of anything; it is a bug."""
        broken = [name for name, mod in arena.load_attempts()
                  if arena.adjudicate(mod)["outcome"] == arena.ATTEMPT_ERROR]
        self.assertEqual([], broken, f"attempts failed to run: {broken}")

    def test_the_corpus_is_not_empty(self):
        self.assertGreaterEqual(len(list(arena.load_attempts())), 5)


class TheArenaClassifiesOutOfScopeCorrectlyTests(unittest.TestCase):
    """The load-bearing one: this attempt DOES reach VERIFIED."""

    def test_minting_a_capability_is_not_counted_as_a_bypass(self):
        found = dict(arena.load_attempts("out_of_scope"))
        self.assertTrue(found, "the out-of-scope example is missing from the corpus")
        for name, mod in found.items():
            result = arena.adjudicate(mod)
            self.assertEqual(
                arena.OUT_OF_SCOPE, result["outcome"],
                f"{name} must be OUT_OF_SCOPE, not {result['outcome']}: "
                "arbitrary in-process code is a documented non-defense")


class TheAdjudicatorCanReportABreakTests(unittest.TestCase):
    def test_a_weakened_verifier_produces_a_confirmed_bypass(self):
        """If this stops failing, no green result from the arena means anything."""
        import proofos.verifier as verifier
        from proofos import EvidenceSource

        original = verifier.TRUSTED_SOURCES
        try:
            verifier.TRUSTED_SOURCES = frozenset({EvidenceSource.OBSERVED,
                                                  EvidenceSource.EXECUTOR})
            outcomes = [arena.adjudicate(mod)["outcome"]
                        for _, mod in arena.load_attempts("self_report")]
        finally:
            verifier.TRUSTED_SOURCES = original
        self.assertIn(arena.BYPASS_CONFIRMED, outcomes,
                      "the adjudicator could not detect a bypass it was handed")

    def test_the_trusted_set_is_restored_afterwards(self):
        import proofos.verifier as verifier
        from proofos import EvidenceSource
        self.assertEqual(frozenset({EvidenceSource.OBSERVED}),
                         frozenset(verifier.TRUSTED_SOURCES))


class TheChallengeDoesNotOverclaimTests(unittest.TestCase):
    def test_the_readme_states_that_no_external_red_team_has_run(self):
        text = (ROOT / "redteam" / "README.md").read_text(encoding="utf-8")
        self.assertIn("EXTERNAL RED TEAM         NOT PERFORMED", text)
        self.assertIn("EXTERNAL ATTEMPTS         0", text)

    def test_the_readme_does_not_claim_the_system_is_unbreakable(self):
        text = (ROOT / "redteam" / "README.md").read_text(encoding="utf-8").lower()
        for phrase in ("unhackable", "cannot be bypassed", "unbreakable",
                       "proven secure", "no vulnerabilities"):
            self.assertNotIn(phrase, text, f"the challenge claims {phrase!r}")


if __name__ == "__main__":
    unittest.main()
