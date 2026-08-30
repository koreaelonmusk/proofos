"""The red-team arena is itself a claim, so it needs its own guards.

An arena that cannot report a break, or that counts an out-of-scope move as
one, produces numbers that look like security evidence and are not. These
tests defend the two failure directions.
"""
from __future__ import annotations

import pathlib
import re
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



class TheChallengeScopeIsExplicitTests(unittest.TestCase):
    """An external attacker must be able to argue scope from the document."""

    def setUp(self):
        self.text = (ROOT / "redteam" / "README.md").read_text(encoding="utf-8")

    def test_the_in_scope_win_condition_is_stated(self):
        for phrase in ("IN-SCOPE BYPASS", "decision.verified is True",
                       "authority boundary remain intact"):
            self.assertIn(phrase, self.text)

    def test_every_out_of_scope_move_is_listed(self):
        for move in ("replacing the verifier",
                     "altering trusted collector configuration",
                     "constructing a separate permissive ledger",
                     "injecting a malicious trust root as the operator",
                     "arbitrary code execution that rewrites the running process",
                     "changing the challenge adjudicator"):
            self.assertIn(move, self.text, f"out-of-scope move not listed: {move}")

    def test_the_sealed_ledger_observation_is_not_upgraded_into_a_claim(self):
        """One configuration refusing one path is not a general defence."""
        self.assertIn("does **not** mean", self.text)
        # The sentence may be quoted, but only to be refused. Every occurrence
        # must sit inside a negation; an earlier version of this test stripped
        # the quote marks and so manufactured the match it then flagged.
        claim = "ProofOS protects against arbitrary same-process compromise"
        for match in re.finditer(re.escape(claim), self.text):
            preceding = self.text[max(0, match.start() - 60):match.start()]
            self.assertIn("not", preceding,
                          "the sealed-ledger result is stated as a general defence")


class TheChallengeIsFrozenTests(unittest.TestCase):
    def test_the_freeze_exists_and_matches(self):
        self.assertTrue((ROOT / "redteam" / "FREEZE.json").exists(),
                        "the challenge must be frozen before it is published")
        self.assertTrue(arena.verify_freeze(quiet=True),
                        "the challenge has drifted from its recorded freeze")

    def test_the_freeze_records_every_judged_surface(self):
        import json
        frozen = json.loads((ROOT / "redteam" / "FREEZE.json").read_text(encoding="utf-8"))
        for field in ("rc_sha", "proofos_package_digest", "spec_sha", "arena_sha",
                      "adjudicator_sha", "attack_corpus_sha", "challenge_version"):
            self.assertIn(field, frozen)
        self.assertEqual(arena.RC_SHA, frozen["rc_sha"])

    def test_the_freeze_does_not_reference_itself(self):
        import json
        raw = (ROOT / "redteam" / "FREEZE.json").read_text(encoding="utf-8")
        self.assertNotIn("FREEZE.json", raw,
                         "a self-referential checksum cannot be verified")


class TheChallengeDocumentDoesNotCarryItsOwnDigestTests(unittest.TestCase):
    """A document cannot state its own hash and stay correct."""

    def test_the_readme_does_not_embed_a_spec_sha_value(self):
        text = (ROOT / "redteam" / "README.md").read_text(encoding="utf-8")
        embedded = re.findall(r"spec_sha\s+([0-9a-f]{64})", text)
        self.assertEqual([], embedded,
                         "the challenge document prints its own digest, which "
                         "is wrong the moment the document is saved")

if __name__ == "__main__":
    unittest.main()
