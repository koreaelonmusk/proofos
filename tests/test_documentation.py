"""Documentation describes authority. It never grants any -- and it can be wrong.

Prose drifts. A verdict name gets renamed in code and survives in a table; a
transport is added and the matrix that claims to be complete quietly is not; a
Python version appears in a document that the package cannot run on. None of
that breaks a build, which is exactly why it is worth a test.

These check contracts, not English. Nothing here parses prose for meaning or
counts sentences: each test takes a value the code owns and asserts the
documentation names the same one. A test that failed on a rewritten paragraph
would be deleted within a month, and then the real drift would go with it.

The security-language checks are the exception, and they are deliberately
narrow. They look for a small set of sentences that would be dangerous if a
normative document asserted them, and they permit those sentences inside the
negative examples where the documents say them in order to refuse them.
"""

from __future__ import annotations

import pathlib
import re
import tomllib
import unittest

import proofos
from proofos.adapters import CLAIMED_NAMESPACE, RESERVED_METADATA_KEYS
from proofos.bundle import BUNDLE_KIND
from proofos.github import CheckConclusion
from proofos.verifier import (
    TRUSTED_SOURCES,
    EvidenceSource,
    FailureClass,
    VerificationStatus,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

#: The documents this test treats as normative. A page describing the hackathon
#: submission or a demo script is not held to these contracts; a page claiming
#: to state what the system enforces is.
NORMATIVE = (
    "architecture.md", "trust-boundary.md", "evidence-lifecycle.md",
    "proof-bundles.md", "attestations.md", "threat-model.md",
    "integrations.md", "operator-runbook.md", "governance.md",
)

#: Every semantic adapter the package ships. The transport matrix claims to be
#: complete, so this is what completeness means.
SEMANTIC_ADAPTERS = ("adapters", "github", "mcp", "a2a", "adk")


#: Verdict names the code does not have. Compiled with real word
#: boundaries so that CAPABILITY_DENIED -- which is a genuine FailureClass --
#: does not read as an invented verdict.
INVENTED_VERDICTS = tuple(
    re.compile(rf"\b{word}\b") for word in
    ("PASSED", "FAILED_VERIFICATION", "REJECTED", "APPROVED", "DENIED")
)


def read(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def normative_text() -> dict[str, str]:
    return {name: read(name) for name in NORMATIVE}


class TheDocumentsExistTests(unittest.TestCase):
    def test_every_normative_document_is_present(self):
        for name in NORMATIVE:
            with self.subTest(document=name):
                self.assertTrue((DOCS / name).is_file(), f"docs/{name} is missing")

    def test_architecture_links_to_each_of_them(self):
        # The entry point has to reach the rest, or the rest is not documentation
        # so much as files in a directory.
        index = read("architecture.md")
        for name in NORMATIVE:
            if name == "architecture.md":
                continue
            with self.subTest(document=name):
                self.assertIn(f"]({name})", index,
                              f"architecture.md does not link to {name}")

    def test_every_internal_link_resolves(self):
        for name, text in normative_text().items():
            for target in re.findall(r"\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)", text):
                with self.subTest(document=name, link=target):
                    self.assertTrue((DOCS / target).exists()
                                    or (ROOT / target).exists(),
                                    f"docs/{name} links to a missing {target}")


class TheVocabularyMatchesTheCodeTests(unittest.TestCase):
    """M1, M2, M6, M9: a name the code owns, named the same way in prose."""

    def test_the_documented_verdicts_are_the_code_verdicts(self):
        lifecycle = read("evidence-lifecycle.md")
        for status in VerificationStatus:
            self.assertIn(str(status), lifecycle)
        # And no invented aliases anywhere normative.
        for name, text in normative_text().items():
            # Word-bounded: CAPABILITY_DENIED is a real FailureClass, and a
            # substring check would call it an invented verdict.
            for invented in INVENTED_VERDICTS:
                with self.subTest(document=name, alias=invented.pattern):
                    self.assertIsNone(
                        invented.search(text),
                        f"docs/{name} names a verdict the code does not have")

    def test_the_invented_verdict_guard_can_fire(self):
        # This test exists because the guard above was inert while it was
        # being written: the word boundaries had been saved as literal
        # backspace bytes, so the pattern was "\x08DENIED\x08" and matched
        # nothing. It read correctly in an editor and in inspect.getsource,
        # because a backspace is invisible.
        #
        # A guard nobody has watched fail is a guard nobody has watched.
        offending = "The verifier returned DENIED for this task."
        self.assertTrue(any(p.search(offending) for p in INVENTED_VERDICTS))
        # And the real FailureClass it must not trip on.
        self.assertFalse(any(p.search("`CAPABILITY_DENIED` is a refusal")
                             for p in INVENTED_VERDICTS))

    def test_every_failure_class_is_documented(self):
        # A reason a user can be shown is a reason a user can look up.
        prose = "\n".join(normative_text().values())
        for failure in FailureClass:
            if failure is FailureClass.NONE:
                continue
            with self.subTest(failure=str(failure)):
                self.assertIn(str(failure), prose)

    def test_the_provenance_vocabulary_matches(self):
        lifecycle = read("evidence-lifecycle.md")
        for source in EvidenceSource:
            self.assertIn(str(source), lifecycle)
        self.assertEqual({str(s) for s in TRUSTED_SOURCES}, {"OBSERVED"},
                         "TRUSTED_SOURCES changed; the documents describe "
                         "OBSERVED as the only independent provenance")

    def test_the_claimed_namespace_matches(self):
        boundary = read("trust-boundary.md")
        self.assertIn(CLAIMED_NAMESPACE, boundary)
        for key in sorted(RESERVED_METADATA_KEYS):
            with self.subTest(key=key):
                self.assertIn(f"`{key}`", boundary,
                              f"trust-boundary.md does not list the reserved "
                              f"metadata key {key}")

    def test_the_bundle_schema_name_matches(self):
        self.assertIn(BUNDLE_KIND, read("proof-bundles.md"))

    def test_the_github_conclusions_match(self):
        lifecycle = read("evidence-lifecycle.md")
        self.assertIn(str(CheckConclusion.ACTION_REQUIRED), lifecycle)
        self.assertIn("neutral", lifecycle,
                      "the documents must explain why neutral is absent")


class TheTransportMatrixIsCompleteTests(unittest.TestCase):
    """M5: an adapter added without a row is a matrix that lies about itself."""

    def test_every_shipped_semantic_adapter_has_a_row(self):
        boundary = read("trust-boundary.md")
        for module in SEMANTIC_ADAPTERS:
            with self.subTest(module=module):
                self.assertIn(f"proofos.{module}", boundary,
                              f"the transport matrix omits proofos.{module}")

    def test_the_adapter_list_matches_what_the_package_ships(self):
        # If a new adapter module appears, this test is what notices.
        shipped = {p.stem for p in (ROOT / "proofos").glob("*.py")}
        expected = set(SEMANTIC_ADAPTERS)
        missing = expected - shipped
        self.assertEqual(missing, set(),
                         f"the matrix names modules that do not exist: {missing}")

    def test_no_transport_is_documented_as_verifying(self):
        boundary = read("trust-boundary.md")
        # The matrix is the table with nine columns. Selecting on "proofos."
              # alone would also catch the three-authorities table above it.
        table = [line for line in boundary.splitlines()
                 if line.startswith("| ") and "proofos." in line
                 and len(line.strip("|").split("|")) == 9]
        self.assertGreaterEqual(len(table), 6, "the matrix lost its rows")
        for row in table:
            cells = [c.strip() for c in row.strip("|").split("|")]
            # Columns after the first three are: creates EXECUTOR, creates
            # OBSERVED, verifies, grants capabilities, determines verdict.
            with self.subTest(row=cells[0]):
                self.assertEqual(cells[4:], ["no"] * 5,
                                 "a transport row claims an authority column")


class TheStatedFactsMatchTheProjectTests(unittest.TestCase):
    """M6, M7, M8: numbers that drift silently."""

    def test_the_documented_python_support_matches_pyproject(self):
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        requires = project["requires-python"]
        self.assertEqual(requires, ">=3.11")
        claimed = {c.rsplit(" ", 1)[-1] for c in project["classifiers"]
                   if "Programming Language :: Python :: 3." in c}

        workflow = (ROOT / ".github" / "workflows" / "release-gate.yml"
                    ).read_text(encoding="utf-8")
        blocking = re.search(r'python: \[([^\]]+)\]', workflow).group(1)
        tested = {v.strip().strip('"') for v in blocking.split(",")}
        self.assertEqual(tested, claimed,
                         "the blocking CI matrix and the package classifiers "
                         "disagree about which Python versions are supported")

    def test_no_document_claims_a_python_the_package_cannot_run(self):
        for name, text in normative_text().items():
            with self.subTest(document=name):
                self.assertNotIn("3.10", text,
                                 f"docs/{name} mentions 3.10; the codebase uses "
                                 f"enum.StrEnum and tomllib")

    def test_the_root_api_count_is_stated_correctly_where_stated(self):
        actual = len(proofos.__all__)
        self.assertEqual(actual, 26)
        for name, text in normative_text().items():
            for stated in re.findall(r"root API[^.\n]*?(\d+) names", text):
                with self.subTest(document=name):
                    self.assertEqual(int(stated), actual)

    def test_the_readme_test_count_matches_the_recorded_one(self):
        import json

        recorded = json.loads(
            (ROOT / "artifacts" / "cloud-proof.json").read_text(encoding="utf-8")
        )["test_count"]
        self.assertIn(f"**{recorded} tests.**",
                      (ROOT / "README.md").read_text(encoding="utf-8"))


class DocumentationGrantsNoAuthorityTests(unittest.TestCase):
    """M2, M3, M4, M10: sentences that would be false if asserted.

    Narrow on purpose. Each pattern is a claim the implementation refuses, and
    each is permitted inside a table row or list item where the document is
    naming it in order to reject it -- those lines contain a refusal marker.
    """

    DANGEROUS = (
        (re.compile(r"(?i)signature\s+proves\s+(?:the\s+)?(?:claim|task|truth)"),
         "a signature proves who signed bytes"),
        (re.compile(r"(?i)signed\s+evidence\s+is\s+trusted"),
         "signed is not trusted"),
        (re.compile(r"(?i)replay\s+(?:observes|creates?\s+(?:a\s+)?new\s+observation)"),
         "replay never observes"),
        (re.compile(r"(?i)recorded[_ ]verdict\s+is\s+authoritative"),
         "the recorded verdict is never an input"),
        (re.compile(r"(?i)authenticated\s+(?:means|implies)\s+trusted"),
         "authentication establishes who is speaking"),
        (re.compile(r"(?i)completed\s+means\s+verified"),
         "a task state is a claim"),
        (re.compile(r"(?i)ProofOS\s+guarantees\s+correctness"),
         "no correctness guarantee is made"),
    )

    #: A line naming a dangerous claim in order to refuse it. Table rows and
    #: bullets in the threat model and non-goals do this constantly.
    REFUSAL = re.compile(
        r"(?i)\b(not|never|cannot|does not|forbidden|must not|refus|abstain|"
        r"do not|neither|nothing|without)\b")

    def test_no_normative_document_asserts_a_dangerous_claim(self):
        for name, text in normative_text().items():
            for number, line in enumerate(text.splitlines(), start=1):
                for pattern, why in self.DANGEROUS:
                    if pattern.search(line) and not self.REFUSAL.search(line):
                        self.fail(f"docs/{name}:{number} asserts a claim the "
                                  f"implementation refuses ({why}):\n    {line}")

    def test_the_check_can_actually_fail(self):
        # A guard nobody has seen fail is a guard nobody has seen.
        offending = "A valid signature proves the claim."
        self.assertTrue(
            any(pattern.search(offending) for pattern, _ in self.DANGEROUS))
        self.assertFalse(self.REFUSAL.search(offending))

    def test_the_permitted_form_is_permitted(self):
        allowed = "A valid signature proves who signed bytes; it does not prove the claim."
        self.assertTrue(self.REFUSAL.search(allowed))


class ThePermanentLawsAreStatedTests(unittest.TestCase):
    """The sentences the project has committed to keeping."""

    LAWS = {
        "trust-boundary.md": [
            "Who said it is metadata. Whether it is true is not.",
        ],
        "proof-bundles.md": [
            "A bundle can carry evidence. It cannot carry permission to believe it.",
            "Replayed evidence is not a new observation.",
            "Recorded VERIFIED is not replay authority.",
        ],
        "attestations.md": [
            "A valid signature proves who signed some bytes. It does not prove the claim",
        ],
        "governance.md": [
            "A worktree separates files.",
            "A lease separates authority.",
            "A ruleset enforces what a lease can only request.",
            "Fetch is observation. Pull is mutation.",
            "A remote can contaminate a verified line without a push.",
        ],
    }

    def test_each_law_appears_in_its_document(self):
        for document, laws in self.LAWS.items():
            text = " ".join(read(document).split())
            for law in laws:
                with self.subTest(document=document, law=law[:40]):
                    self.assertIn(" ".join(law.split()), text)


class ReleaseClaimsStayHonestTests(unittest.TestCase):
    """M10: local evidence and remote CI evidence are different claims."""

    def test_no_document_claims_remote_ci_success(self):
        for name, text in normative_text().items():
            lowered = text.lower()
            for phrase in ("ci is green", "ci passes on every", "all checks pass on github",
                           "github actions confirms"):
                with self.subTest(document=name, phrase=phrase):
                    self.assertNotIn(phrase, lowered)

    def test_the_runbook_separates_the_two(self):
        runbook = read("operator-runbook.md")
        self.assertIn("local evidence and remote ci evidence are separate",
                      runbook.lower())


if __name__ == "__main__":
    unittest.main()
