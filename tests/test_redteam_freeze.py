"""Guards for the w3-e2.2 repair: checkout-independent hashing and the public contract.

Version w3-e2.1 shipped a freeze that verified on the author's machine and
failed on every fresh clone, because Git converts line endings on checkout and
the digest was taken over working-tree bytes. These tests pin the fix, and --
more importantly -- pin its limit: canonicalization may erase how content is
represented, never the content itself.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "redteam"))
import arena  # noqa: E402

FREEZE = ROOT / "redteam" / "FREEZE.json"
README = ROOT / "redteam" / "README.md"

LF = b"import os" + bytes([10]) + b"print(os.name)" + bytes([10])
CRLF = b"import os" + bytes([13, 10]) + b"print(os.name)" + bytes([13, 10])


class CanonicalHashingIsCheckoutIndependentTests(unittest.TestCase):
    def test_crlf_and_lf_of_the_same_content_canonicalize_alike(self):
        self.assertEqual(arena.canonical_bytes(LF, is_text=True),
                         arena.canonical_bytes(CRLF, is_text=True))

    def test_without_canonicalization_the_two_differ(self):
        """Proves the normalization is load-bearing rather than decorative."""
        self.assertNotEqual(LF, CRLF)
        self.assertNotEqual(arena.canonical_bytes(LF, is_text=False),
                            arena.canonical_bytes(CRLF, is_text=False))

    def test_a_real_content_change_still_moves_the_result(self):
        """Representation may be erased. Content never may.

        A canonicalizer that hid a semantic edit would be worse than the bug it
        was written to fix.
        """
        before = b"satisfies=False" + bytes([10])
        after = b"satisfies=True" + bytes([10])
        self.assertNotEqual(arena.canonical_bytes(before, is_text=True),
                            arena.canonical_bytes(after, is_text=True))

    def test_a_semantic_edit_to_a_real_attack_changes_the_corpus_digest(self):
        """The same property against the shipped corpus, not a fixture."""
        target = ROOT / "redteam" / "attempts" / "self_report.py"
        original = target.read_bytes()
        before = arena._frozen_set()["attack_corpus_sha"]
        try:
            target.write_bytes(original.replace(b"deploy-agent", b"deploy-agent-2"))
            after = arena._frozen_set()["attack_corpus_sha"]
        finally:
            target.write_bytes(original)
        self.assertNotEqual(before, after,
                            "canonicalization erased a real content change")
        self.assertEqual(before, arena._frozen_set()["attack_corpus_sha"],
                         "the corpus was not restored after the test")

    def test_a_line_ending_only_change_does_not_move_the_corpus_digest(self):
        """The whole point: the same commit, checked out either way, agrees."""
        target = ROOT / "redteam" / "attempts" / "self_report.py"
        original = target.read_bytes()
        before = arena._frozen_set()["attack_corpus_sha"]
        try:
            # Flip to whichever representation the file is not currently in,
            # so the fixture works regardless of how git checked it out.
            if bytes([13, 10]) in original:
                flipped = original.replace(bytes([13, 10]), bytes([10]))
            else:
                flipped = original.replace(bytes([10]), bytes([13, 10]))
            self.assertNotEqual(original, flipped, "the fixture did not change bytes")
            target.write_bytes(flipped)
            after = arena._frozen_set()["attack_corpus_sha"]
        finally:
            target.write_bytes(original)
        self.assertEqual(before, after,
                         "a pure line-ending difference still moved the digest")

    def test_unknown_formats_are_not_rewritten(self):
        blob = bytes([0x89]) + b"PNG" + bytes([13, 10, 0x1a, 10])
        self.assertEqual(blob, arena.canonical_bytes(blob, is_text=False))


class FreezeDriftIsDetectedTests(unittest.TestCase):
    def _freeze_with(self, **overrides) -> pathlib.Path:
        frozen = json.loads(FREEZE.read_text(encoding="utf-8"))
        frozen.update(overrides)
        tmp = pathlib.Path(tempfile.mkdtemp()) / "FREEZE.json"
        tmp.write_text(json.dumps(frozen, indent=2, sort_keys=True), encoding="utf-8")
        return tmp

    def test_a_stale_corpus_digest_is_caught(self):
        self.assertFalse(arena.verify_freeze(
            quiet=True, path=self._freeze_with(attack_corpus_sha="0" * 64)))

    def test_a_stale_challenge_version_is_caught(self):
        self.assertFalse(arena.verify_freeze(
            quiet=True, path=self._freeze_with(challenge_version="w3-e2.1")))

    def test_a_stale_package_digest_is_caught(self):
        self.assertFalse(arena.verify_freeze(
            quiet=True, path=self._freeze_with(proofos_package_digest="0" * 64)))

    def test_a_stale_spec_digest_is_caught(self):
        self.assertFalse(arena.verify_freeze(
            quiet=True, path=self._freeze_with(spec_sha="0" * 64)))

    def test_the_freeze_binds_every_required_field(self):
        frozen = json.loads(FREEZE.read_text(encoding="utf-8"))
        for field in ("challenge_version", "rc_sha", "proofos_package_digest",
                      "arena_sha", "adjudicator_sha", "spec_sha", "attack_corpus_sha"):
            self.assertIn(field, frozen)

    def test_the_current_freeze_matches_the_tree(self):
        self.assertTrue(arena.verify_freeze(quiet=True))


class ThePublicContractIsCompleteTests(unittest.TestCase):
    def setUp(self):
        self.text = README.read_text(encoding="utf-8")

    def test_the_attempt_count_sits_beside_the_bypass_count(self):
        """A zero bypass count alone reads as an achievement. It is not one."""
        self.assertIn("External attempts     0", self.text)
        self.assertIn("Confirmed bypasses    0", self.text)
        gap = abs(self.text.index("Confirmed bypasses    0")
                  - self.text.index("External attempts     0"))
        self.assertLess(gap, 120,
                        "the counters must appear together; in separate sections "
                        "one can be quoted without the other")

    def test_the_empty_scoreboard_is_named_as_such(self):
        self.assertIn("is not a security result", self.text)

    def test_attempt_error_is_not_counted_as_a_defence(self):
        self.assertIn("`ATTEMPT_ERROR` is not a defence success", self.text)

    def test_every_result_class_is_documented(self):
        for cls in ("BYPASS_CONFIRMED", "NO_BYPASS", "REFUSED",
                    "OUT_OF_SCOPE", "ATTEMPT_ERROR"):
            self.assertIn(cls, self.text)

    def test_every_submission_evidence_field_is_required(self):
        for field in ("attacker handle", "challenge version", "FREEZE.json digest",
                      "attempt code", "reproduction command", "environment",
                      "adjudicator output"):
            self.assertIn(field, self.text,
                          f"the submission contract omits: {field}")

    def test_the_header_version_matches_the_freeze(self):
        frozen = json.loads(FREEZE.read_text(encoding="utf-8"))
        self.assertIn(f"Challenge version     {frozen['challenge_version']}", self.text)


class TheLineEndingPolicyIsDeclaredTests(unittest.TestCase):
    def test_gitattributes_pins_the_challenge_to_lf(self):
        attrs = (ROOT / ".gitattributes")
        self.assertTrue(attrs.exists(), ".gitattributes is missing")
        text = attrs.read_text(encoding="utf-8")
        self.assertIn("redteam/**", text)
        self.assertIn("eol=lf", text)

    def test_the_canonicalization_rule_is_documented(self):
        """Defence in depth is not the fix, and the code should say so."""
        source = (ROOT / "redteam" / "arena.py").read_text(encoding="utf-8")
        # The rule is prose and wraps across lines, so compare on collapsed
        # whitespace rather than pinning one particular line break.
        flat = " ".join(source.split())
        self.assertIn("CRLF becomes LF", flat)
        self.assertIn("must never erase content", flat)


if __name__ == "__main__":
    unittest.main()
