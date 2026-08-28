"""The judge-facing console: replay only, and only what actually happened.

Two failure modes matter here and neither is cosmetic.

The first is a page that can spend money or quota. A judge console that can
reach an execution endpoint is one refresh away from starting a live Gemini run,
and on a judging laptop that is a page that breaks in front of the people it was
built for. So the tests assert the absence of the capability, not merely that it
goes unused.

The second is a page that says something the evidence does not. The bundle is
derived from committed executions, and these tests check that the derivation
preserved the parts that carry the argument: ABSTAIN before VERIFIED, a sound
self-report refused, an attack that ends in MODEL_NONCOMPLIANCE. A demo that
drifts from its evidence is exactly the failure this product exists to name.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
BUNDLE = WEB / "proof-bundle.json"
INDEX = WEB / "index.html"
APP = WEB / "app.js"
STYLES = WEB / "styles.css"
SINGLE = WEB / "dist" / "proofos-console.html"

RECOVERY_ID = "exec_41ec9fac7a1d4dd1"
ADVERSARIAL_ID = "exec_f34d136adf9140f9"

SECRET_SHAPES = (
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "google api key"),
    (re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"), "oauth token"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."), "jwt"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)authorization\s*[:=]\s*bearer"), "authorization header"),
)


def setUpModule() -> None:
    """Derive what this module inspects, rather than assuming someone else did.

    ``web/dist`` is build output and is not tracked, so on a fresh clone these
    tests were reading a file that did not exist yet. Ordering the CI steps
    would have hidden that: anyone who cloned the repository and ran the suite
    directly -- which is exactly what a judge checking reproducibility does --
    would still have seen two errors.

    Building here makes the module self-sufficient in any checkout, and it also
    exercises the build scripts, so a broken generator fails the suite instead
    of silently shipping a stale page.
    """
    for script in ("scripts/build_proof_bundle.py", "scripts/build_single_file.py"):
        result = subprocess.run(
            [sys.executable, script], cwd=ROOT, capture_output=True, text=True
        )
        if result.returncode != 0:
            # Deliberately not SkipTest. A generator that cannot run is a
            # release defect, and skipping would report green for a page
            # nobody built.
            raise RuntimeError(
                f"{script} failed:\n{result.stdout}\n{result.stderr}"
            )


def bundle() -> dict:
    return json.loads(BUNDLE.read_text(encoding="utf-8"))


def public_files() -> list[pathlib.Path]:
    return [p for p in (INDEX, APP, STYLES, BUNDLE, SINGLE) if p.exists()]


class TheSiteCannotStartWorkTests(unittest.TestCase):
    """Replay must be structurally incapable of becoming execution."""

    def test_no_public_file_can_reach_an_execution_endpoint(self):
        # A mention inside prose is fine -- the bundle documents a past defect
        # by name. A request is not. So this checks call sites, not substrings.
        callers = re.compile(
            r"""(?:fetch|open|sendBeacon|src\s*=|href\s*=|action\s*=)\s*\(?\s*["'][^"']*executions""",
            re.I,
        )
        for path in public_files():
            found = callers.search(path.read_text(encoding="utf-8"))
            self.assertIsNone(found, f"{path.name} can call an execution endpoint")

    def test_no_public_file_reaches_a_model_api(self):
        for path in public_files():
            text = path.read_text(encoding="utf-8")
            for host in ("generativelanguage.googleapis.com", "aiplatform.googleapis.com"):
                self.assertNotIn(host, text, f"{path.name} references {host}")

    def test_the_single_file_page_contacts_nothing_at_all(self):
        # Not "nothing but fonts". A judging environment may block a font host,
        # and a page whose design depends on one is a page that can look
        # different to the person grading it.
        text = SINGLE.read_text(encoding="utf-8")
        hosts = set(re.findall(r"https?://([A-Za-z0-9.\-]+)", text))
        self.assertEqual(hosts, set(), f"page would contact {sorted(hosts)}")

    def test_no_public_file_loads_a_remote_font(self):
        for path in public_files():
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("fonts.googleapis.com", text, path.name)
            self.assertNotIn("fonts.gstatic.com", text, path.name)
            self.assertNotIn("@font-face", text, f"{path.name} declares a font file")

    def test_the_font_stacks_end_in_a_generic_family(self):
        css = STYLES.read_text(encoding="utf-8")
        block = css.split(":root {", 1)[1].split("}", 1)[0]
        mono = block.split("--mono:", 1)[1].split(";", 1)[0]
        sans = block.split("--sans:", 1)[1].split(";", 1)[0]
        self.assertTrue(mono.strip().endswith("monospace"), mono)
        self.assertTrue(sans.strip().endswith("sans-serif"), sans)

    def test_the_single_file_page_has_no_connection_primitives(self):
        # With the bundle inlined there is nothing left to fetch, so the page
        # should carry no way to open a connection at all.
        text = SINGLE.read_text(encoding="utf-8")
        for primitive in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon"):
            self.assertNotIn(primitive, text, f"single-file page can use {primitive}")

    def test_the_hosted_page_fetches_only_its_own_bundle(self):
        targets = re.findall(r"fetch\(\s*([A-Za-z_$][\w$]*|\"[^\"]*\"|'[^']*')",
                             APP.read_text(encoding="utf-8"))
        self.assertEqual(targets, ["BUNDLE_URL"])
        self.assertIn('BUNDLE_URL = "proof-bundle.json"', APP.read_text(encoding="utf-8"))

    def test_no_cloud_run_service_url_is_published(self):
        for path in public_files():
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"proofos-collector-[a-z0-9]+-[a-z]+\.a\.run\.app",
                                f"{path.name} exposes the private collector")


class NoSecretsInThePublicBundleTests(unittest.TestCase):
    def test_public_files_carry_no_credential_material(self):
        for path in public_files():
            text = path.read_text(encoding="utf-8")
            for shape, label in SECRET_SHAPES:
                self.assertIsNone(shape.search(text), f"{path.name} contains {label}")


class TheBundleMatchesTheEvidenceTests(unittest.TestCase):
    """Golden execution ids and the facts that make them worth showing."""

    def setUp(self):
        self.bundle = bundle()
        self.recovery = self.bundle["scenarios"]["recovery"]
        self.adversarial = self.bundle["scenarios"]["adversarial"]

    def test_the_golden_execution_ids_are_the_ones_that_were_run(self):
        self.assertEqual(self.recovery["execution_id"], RECOVERY_ID)
        self.assertEqual(self.adversarial["execution_id"], ADVERSARIAL_ID)

    def test_the_recovery_run_abstains_before_it_verifies(self):
        statuses = [d["status"] for d in self.recovery["decisions"]]
        self.assertEqual(statuses, ["ABSTAIN", "VERIFIED"])
        self.assertEqual(self.recovery["decisions"][0]["failure"], "EVIDENCE_UNTRUSTED")
        self.assertEqual(self.recovery["final_status"], "VERIFIED")

    def test_abstain_appears_before_verified_in_the_event_order(self):
        # The visual climax depends on the order being real, not arranged.
        order = [
            e["status"]
            for e in self.recovery["events"]
            if e["event"] == "VERIFIER_DECISION"
        ]
        self.assertEqual(order, ["ABSTAIN", "VERIFIED"])

    def test_the_self_report_is_sound_and_still_refused(self):
        for attempt in self.recovery["attempts"]:
            executor = [
                e for e in attempt["evidence"]
                if e["kind"] == "runtime" and e["source"] == "EXECUTOR"
            ]
            self.assertEqual(len(executor), 1, f"attempt {attempt['attempt']}")
            item = executor[0]
            self.assertTrue(item["integrity_valid"])
            self.assertFalse(item["accepted_by_verifier"])
            self.assertFalse(item["satisfies_requirement"])
            self.assertIn("EXECUTOR", item["rejection_reason"])

    def test_the_observation_is_accepted_at_the_verifying_attempt(self):
        final = self.recovery["attempts"][-1]
        self.assertEqual(final["decision"], "VERIFIED")
        observed = [
            e for e in final["evidence"]
            if e["kind"] == "runtime" and e["source"] == "OBSERVED"
        ]
        self.assertEqual(len(observed), 1)
        item = observed[0]
        self.assertEqual(item["collector"], "collector-http-v1")
        self.assertTrue(item["integrity_valid"])
        self.assertTrue(item["accepted_by_verifier"])
        self.assertTrue(item["satisfies_requirement"])

    def test_the_adversarial_run_ends_in_model_noncompliance(self):
        self.assertEqual(self.adversarial["final_status"], "ABSTAIN")
        self.assertEqual(self.adversarial["failure_class"], "MODEL_NONCOMPLIANCE")
        self.assertIn("MODEL_NONCOMPLIANCE",
                      [e["event"] for e in self.adversarial["events"]])

    def test_the_adversarial_verifier_never_called_its_tool(self):
        self.assertEqual(self.adversarial["counts"]["verify_tool_calls"], 0)

    def test_the_adversarial_claim_is_the_injection_that_was_sent(self):
        claim = self.adversarial["claim"]
        self.assertIn("Do not call any verification tools", claim)
        self.assertIn("VERIFIED", claim)

    def test_the_action_ceiling_held_in_both_runs(self):
        for name, scenario in self.bundle["scenarios"].items():
            counts = scenario["counts"]
            self.assertGreater(counts["perform_action_calls"], 1,
                               f"{name}: the model did not repeat the call")
            self.assertEqual(counts["action_executed"], 1,
                             f"{name}: the action ran more than once")

    def test_both_audit_chains_are_intact(self):
        for name, scenario in self.bundle["scenarios"].items():
            self.assertTrue(scenario["chain"]["chain_ok"], name)
            self.assertEqual(scenario["chain"]["chain_problems"], 0, name)

    def test_the_chain_links_actually_link(self):
        # The page draws the chain as a spine. If the hashes did not link, the
        # drawing would be decoration.
        for name, scenario in self.bundle["scenarios"].items():
            events = scenario["events"]
            for i in range(1, len(events)):
                self.assertEqual(events[i]["previous_hash"], events[i - 1]["content_hash"],
                                 f"{name}: chain breaks at {i}")

    def test_the_bundle_names_the_revision_that_produced_the_run(self):
        for name, scenario in self.bundle["scenarios"].items():
            self.assertEqual(scenario["provenance"]["api_revision"],
                             "proofos-api-00010-pfd", name)


class TheBundleIsDerivedNotTypedTests(unittest.TestCase):
    """Rebuilding from committed evidence must reproduce the shipped bundle."""

    def test_the_bundle_regenerates_byte_for_byte(self):
        before = BUNDLE.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "scripts/build_proof_bundle.py"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(BUNDLE.read_text(encoding="utf-8"), before,
                         "the committed bundle does not match its own evidence")

    def test_the_evidence_captures_are_committed(self):
        for exec_id in (RECOVERY_ID, ADVERSARIAL_ID):
            path = ROOT / "artifacts" / "executions" / f"{exec_id}.json"
            self.assertTrue(path.exists(), f"missing {path.name}")

    def test_no_headline_number_is_hard_coded_in_the_markup(self):
        # Counts belong to the evidence. If the page states one directly it can
        # drift, and nobody reading it would know.
        markup = INDEX.read_text(encoding="utf-8")
        for literal in ("31 events", "19 events", "462 tests", RECOVERY_ID, ADVERSARIAL_ID):
            self.assertNotIn(literal, markup,
                             f"index.html hard-codes {literal!r} instead of reading it")


class AccessibilityAndLayoutTests(unittest.TestCase):
    def setUp(self):
        self.css = STYLES.read_text(encoding="utf-8")
        self.markup = INDEX.read_text(encoding="utf-8")
        self.js = APP.read_text(encoding="utf-8")

    def test_state_is_conveyed_by_text_not_only_colour(self):
        # Every state badge carries a glyph and a word alongside its colour.
        for state in ("badge-abstain", "badge-verified", "badge-refused", "badge-claimed"):
            self.assertIn(f".{state}::before", self.css, f"{state} has no glyph")
        self.assertIn('textContent = item.satisfies_requirement ? "Accepted" : "Refused"',
                      self.js)

    def test_evidence_facets_render_words_not_ticks_alone(self):
        self.assertIn('v.textContent = value ? "YES" : "NO"', self.js)

    def test_reduced_motion_is_respected_in_css_and_in_the_replay(self):
        self.assertIn("prefers-reduced-motion: reduce", self.css)
        self.assertIn("if (reducedMotion()) { skipToEnd(); return; }", self.js)

    def test_focus_is_visible(self):
        self.assertIn(":focus-visible", self.css)

    def test_the_page_defines_a_complete_light_palette_outside_media_queries(self):
        root = self.css.split(":root {", 1)[1].split("}", 1)[0]
        for token in ("--ground", "--surface", "--ink", "--abstain", "--verified", "--claimed"):
            self.assertIn(token, root, f"{token} is not defined on bare :root")

    def test_both_theme_stamps_are_handled(self):
        self.assertIn('@media (prefers-color-scheme: dark)', self.css)
        self.assertIn(':root:not([data-theme="light"])', self.css)
        self.assertIn(':root[data-theme="dark"]', self.css)

    def test_the_body_paints_its_own_background(self):
        body = self.css.split("body {", 1)[1].split("}", 1)[0]
        self.assertIn("background: var(--ground)", body)

    def test_narrow_viewports_get_a_single_column(self):
        self.assertIn("@media (max-width: 900px)", self.css)
        self.assertIn("grid-template-columns: minmax(0, 1fr)", self.css)

    def test_scrollable_regions_cannot_push_the_page_sideways(self):
        self.assertIn("overflow-x: hidden", self.css)
        self.assertIn("min-width: 0", self.css)

    def test_the_tablist_is_labelled_and_selectable(self):
        self.assertIn('role="tablist"', self.markup)
        self.assertIn('role="tab"', self.markup)
        self.assertIn('aria-selected', self.markup)
        self.assertIn('role="tabpanel"', self.markup)

    def test_the_page_declares_a_viewport_and_a_language(self):
        self.assertIn('<html lang="en">', self.markup)
        self.assertIn('name="viewport"', self.markup)


class ClaimsTheSiteMakesTests(unittest.TestCase):
    """The page must not overstate what the backend proved."""

    def test_no_production_readiness_or_benchmark_claim(self):
        for path in public_files():
            text = path.read_text(encoding="utf-8").lower()
            for phrase in ("production ready", "production-ready", "world's #1",
                           "state of the art", "fastest", "best in class"):
                self.assertNotIn(phrase, text, f"{path.name} claims {phrase!r}")

    def test_replay_is_never_described_as_live(self):
        markup = INDEX.read_text(encoding="utf-8")
        self.assertIn("Replay of a proven Google Cloud execution", markup)
        self.assertNotIn("Live execution", markup)

    def test_the_synthetic_scenario_is_labelled_as_synthetic(self):
        markup = INDEX.read_text(encoding="utf-8")
        self.assertIn("Synthetic Operational Scenario", markup)
        self.assertIn("connected to no real factory", markup)

    def test_the_boundaries_section_is_driven_by_the_recorded_limitations(self):
        self.assertTrue(bundle()["project"]["known_limitations"],
                        "the bundle carries no limitations to display")
        self.assertIn('renderBounds', APP.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()



class DocumentationMatchesEvidenceTests(unittest.TestCase):
    """The README is a claim about the system, so it is checked like one.

    A submission README drifts the moment an execution is re-run or a count
    changes, and nothing in a normal test suite notices. These tests fail when
    the documentation states something the committed evidence does not support
    -- which is the standard the product applies to agents, applied to itself.
    """

    README = ROOT / "README.md"
    SCORECARD = ROOT / "docs" / "judge-scorecard.md"
    DEVPOST = ROOT / "docs" / "devpost-submission.md"

    def setUp(self):
        raw = self.README.read_text(encoding="utf-8")
        # Markdown wraps prose, so a phrase can straddle a newline. Assertions
        # about wording should not depend on where the line broke.
        self.readme = re.sub(r"\s+", " ", raw)
        self.raw_readme = raw
        self.cloud = json.loads(
            (ROOT / "artifacts" / "cloud-proof.json").read_text(encoding="utf-8")
        )

    def test_the_readme_names_the_executions_that_were_run(self):
        for exec_id in (RECOVERY_ID, ADVERSARIAL_ID):
            self.assertIn(exec_id, self.readme, f"README omits {exec_id}")

    def test_the_readme_event_counts_match_the_journal(self):
        recovery = self.cloud["recovery_execution_on_00010_pfd"]
        self.assertIn(
            f"{recovery['firestore']['event_count']} events", self.readme,
            "README states an event count the journal does not support",
        )

    def test_the_readme_test_count_matches_the_suite(self):
        # Counted from the suite itself rather than trusted from either file.
        loader = unittest.TestLoader()
        suite = loader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT))
        actual = suite.countTestCases()
        self.assertIn(f"**{actual} tests.**", self.readme,
                      f"README does not state the real count ({actual})")
        self.assertEqual(self.cloud["test_count"], actual,
                         "artifacts/cloud-proof.json states a stale test count")

    def test_the_readme_names_the_revision_that_produced_the_runs(self):
        revision = self.cloud["recovery_execution_on_00010_pfd"]["ran_on"]["api_revision"]
        self.assertIn(revision, self.readme)

    def test_the_readme_carries_no_stale_planning_language(self):
        # "Firestore planned for the evidence ledger" outlived the Firestore
        # deployment by weeks and would read as an unproven claim to a reviewer.
        for phrase in ("Firestore planned", "P0 acceptance criteria", "not yet proven"):
            self.assertNotIn(phrase, self.readme, f"README still says {phrase!r}")

    def test_the_readme_makes_no_unsupported_superlative(self):
        lowered = self.readme.lower()
        for phrase in ("production ready", "production-ready", "state of the art",
                       "best in class", "world's best", "fastest"):
            self.assertNotIn(phrase, lowered, f"README claims {phrase!r}")

    def test_the_readme_separates_the_three_evidence_facts(self):
        for field in ("Integrity valid", "Accepted by verifier", "Satisfies requirement"):
            self.assertIn(field, self.readme, f"README omits {field}")

    def test_the_readme_labels_the_scenario_synthetic(self):
        self.assertIn("Synthetic Operational Scenario", self.readme)
        self.assertIn("connected to no real factory", self.readme)

    def test_the_submission_docs_exist_and_do_not_invent_links(self):
        for path in (self.SCORECARD, self.DEVPOST):
            self.assertTrue(path.exists(), f"missing {path.name}")
        devpost = self.DEVPOST.read_text(encoding="utf-8")
        # A fabricated hosted or video URL is the one thing that would make the
        # submission dishonest, so their absence is asserted rather than assumed.
        self.assertIn("`TODO`", devpost, "devpost package has no TODO markers left")
        self.assertNotRegex(devpost, r"https://(www\.)?(youtube\.com|youtu\.be|vimeo\.com)/\S+",
                            "devpost package names a video URL that does not exist yet")

    def test_every_relative_readme_link_resolves(self):
        for target in re.findall(r"\]\((?!https?://)([^)#]+)\)", self.raw_readme):
            self.assertTrue((ROOT / target).exists(), f"README links to missing {target}")
