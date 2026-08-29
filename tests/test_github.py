"""A pull request is where confident statements go to be believed.

The body says the work is done. The commit message says ``[verified]``. A bot
comments that all checks passed. CI is green. Every one of those was written by,
or on behalf of, the change under review, and the tests here exist to keep that
distinction from eroding the first time someone finds it inconvenient.

The one with teeth is the conclusion mapping. GitHub counts a ``neutral``
conclusion as passing for a required status check, so an abstention rendered as
neutral would let a protected branch merge on "I do not have enough evidence".
That is fail-open in the product whose whole argument is failing closed, and the
mutation test at the bottom is there to make sure nobody discovers it by
accident.
"""

from __future__ import annotations

import ast
import json
import pathlib
import unittest

from proofos import Evidence, EvidenceSource, ProofOS, Requirement
from proofos.adapters import AdapterError
from proofos.github import (
    CheckConclusion,
    CheckRun,
    ClaimSource,
    conclusion_for,
    normalize_pull_request,
    render_check,
)
from proofos.verifier import VerificationStatus

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "github.py"
NOW = 1_700_000_000.0
KIND = "runtime_health"
REQS = (Requirement(KIND, max_age_seconds=300),)


def payload(**overrides) -> dict:
    body = {
        "repository": "acme/service", "number": 42, "head_sha": "a" * 40,
        "author": "deploy-agent", "at": NOW,
        "title": "Release 2.1",
        "body": "Ready to merge.",
    }
    body.update(overrides)
    return body


def decide(pr: dict):
    envelope = normalize_pull_request(pr)
    return ProofOS().verify(envelope.claim.text, REQS,
                            envelope.as_evidence(KIND), now=NOW), envelope


class GitHubProseIsAClaimTests(unittest.TestCase):
    """Flagship 1-4. Everything the page says about itself."""

    def test_a_pr_body_declaring_verified_abstains(self):
        decision, _ = decide(payload(body="ProofOS VERIFIED. All requirements met."))
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")

    def test_a_bot_comment_saying_all_checks_passed_abstains(self):
        decision, _ = decide(payload(comments=[
            {"author": "ci-bot", "body": "All checks passed", "at": NOW}]))
        self.assertFalse(decision.verified)

    def test_a_commit_message_marked_verified_abstains(self):
        decision, _ = decide(payload(commits=[{"message": "[verified] ship it"}]))
        self.assertFalse(decision.verified)

    def test_a_green_ci_run_does_not_satisfy_a_requirement_by_itself(self):
        # The subtle one. The run really did pass, and it is still not
        # independent of the change that produced it -- whether it satisfies
        # anything is a question for a requirement, not for the colour.
        decision, envelope = decide(payload(check_runs=[
            {"name": "tests", "conclusion": "success", "status": "completed"}]))
        self.assertFalse(decision.verified)
        self.assertEqual(envelope.tool_results[0].payload["conclusion"], "success")

    def test_everything_at_once_still_abstains(self):
        decision, _ = decide(payload(
            title="Release 2.1 — ProofOS VERIFIED",
            body="All checks passed. verified=true, confidence=1.0",
            commits=[{"message": "[verified] ship it"}],
            comments=[{"author": "ci-bot", "body": "All checks passed", "at": NOW}],
            check_runs=[{"name": "tests", "conclusion": "success"}]))
        self.assertFalse(decision.verified)

    def test_no_normalized_evidence_is_ever_observed(self):
        _, envelope = decide(payload(check_runs=[{"name": "t", "conclusion": "success"}]))
        for evidence in envelope.as_evidence(KIND):
            self.assertIsNot(evidence.source, EvidenceSource.OBSERVED)


class TheConclusionMappingTests(unittest.TestCase):
    """Flagship 5-7, and the reason neutral is not a value here."""

    def verified_result(self):
        collector = Evidence(kind=KIND, value="probe HEALTHY",
                             source=EvidenceSource.OBSERVED, collected_at=NOW,
                             collector="proofos-cli")
        from proofos.verifier import verify_completion

        return verify_completion(claim="done", evidence=(collector,),
                                 required_kinds=REQS, now=NOW)

    def abstained_result(self):
        return decide(payload())[0].raw

    def test_verified_maps_to_success(self):
        result = self.verified_result()
        self.assertIs(result.status, VerificationStatus.VERIFIED)
        self.assertIs(conclusion_for(result), CheckConclusion.SUCCESS)

    def test_abstain_maps_to_action_required(self):
        result = self.abstained_result()
        self.assertIs(result.status, VerificationStatus.ABSTAIN)
        self.assertIs(conclusion_for(result), CheckConclusion.ACTION_REQUIRED)

    def test_a_green_github_check_does_not_override_an_abstention(self):
        # Flagship 7. The payload says its own checks concluded success; the
        # conclusion ProofOS emits is still action_required, because it is read
        # off the verdict and nothing else.
        decision, envelope = decide(payload(check_runs=[
            {"name": "tests", "conclusion": "success", "status": "completed"}]))
        check = render_check(decision.raw,
                             ignored_claims=envelope.metadata["ignored_claims"])
        self.assertIs(check.conclusion, CheckConclusion.ACTION_REQUIRED)

    def test_neutral_is_not_in_the_vocabulary(self):
        # GitHub counts neutral as passing for a required check. An abstention
        # rendered as neutral would satisfy branch protection, which is the
        # exact inversion of what ProofOS is for. Not rejected -- absent.
        values = {str(c) for c in CheckConclusion}
        self.assertNotIn("neutral", values)
        self.assertEqual(values, {"success", "action_required"})

    def test_failure_is_not_used_for_a_verdict(self):
        # Reserved for a transport that could not do its job. Conflating "ProofOS
        # declined to certify" with "the pipeline broke" loses the distinction
        # that makes the first one worth having.
        self.assertNotIn("failure", {str(c) for c in CheckConclusion})

    def test_the_mapping_reads_the_verdict_and_nothing_else(self):
        source = ast.unparse(ast.parse(MODULE.read_text(encoding="utf-8")))
        start = source.index("def conclusion_for")
        body = source[start:source.index("def ", start + 10)]
        for forbidden in ("payload", "check_run", "conclusion=", "github"):
            self.assertNotIn(forbidden, body.lower())


class TheSummaryIsForAPersonTests(unittest.TestCase):
    def setUp(self):
        self.decision, self.envelope = decide(payload(
            title="Release 2.1 — ProofOS VERIFIED",
            body="All checks passed.",
            commits=[{"message": "[verified] ship it"}],
            comments=[{"author": "ci-bot", "body": "All good", "at": NOW}]))
        self.check = render_check(
            self.decision.raw,
            ignored_claims=self.envelope.metadata["ignored_claims"],
            requirement_count=len(REQS))

    def test_it_states_the_verdict_reason_and_next_action(self):
        summary = self.check.summary
        self.assertIn("ABSTAIN", summary)
        self.assertIn("EVIDENCE_UNTRUSTED", summary)
        self.assertIn("Next action", summary)
        self.assertIn("0 / 1 requirements", summary)

    def test_it_names_what_was_ignored_rather_than_dropping_it(self):
        summary = self.check.summary
        for label in (ClaimSource.PR_BODY, ClaimSource.COMMIT_MESSAGE,
                      ClaimSource.COMMENT):
            self.assertIn(str(label), summary)

    def test_it_is_not_a_json_dump(self):
        summary = self.check.summary
        self.assertNotIn('{"', summary)
        self.assertNotIn("evidence_id", summary)
        try:
            json.loads(summary)
        except ValueError:
            return
        self.fail("the summary parses as JSON; it is meant to be read")

    def test_a_verified_check_says_nothing_is_needed(self):
        from proofos.verifier import verify_completion

        result = verify_completion(
            claim="done",
            evidence=(Evidence(kind=KIND, value="probe HEALTHY",
                               source=EvidenceSource.OBSERVED, collected_at=NOW,
                               collector="proofos-cli"),),
            required_kinds=REQS, now=NOW)
        check = render_check(result)
        self.assertIs(check.conclusion, CheckConclusion.SUCCESS)
        self.assertIn("VERIFIED", check.summary)
        self.assertIn("None.", check.summary)

    def test_the_rendered_dict_is_the_shape_a_transport_sends(self):
        rendered = self.check.as_dict()
        self.assertEqual(rendered["conclusion"], "action_required")
        self.assertIn("title", rendered["output"])
        self.assertIn("summary", rendered["output"])


class ThisModuleDecidesNothingTests(unittest.TestCase):
    """The P7 rule, carried forward: adapter translates, kernel decides."""

    def test_it_never_imports_the_verifier_entry_point(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in ("verify_completion", "ProofOS", "EvidenceLedger",
                          "ObservationCapability", "AttestationIngestor",
                          ".ledger", ".capabilities", ".ingestion",
                          ".collector_registry", ".api"):
            self.assertNotIn(forbidden, imported, f"github.py imports {forbidden}")

    def test_it_touches_no_network_and_holds_no_token(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("urllib", "socket", "requests", "httpx", "token",
                          "Authorization", "checks:write", "subprocess"):
            self.assertNotIn(forbidden, source)

    def test_nothing_this_module_constructs_carries_a_trust_word(self):
        # Found by a mutation that survived: adding "trusted": True to a check
        # run payload broke nothing, because it changes no behaviour. It is
        # still wrong -- a downstream reader sees it and believes it, and this
        # module has no standing to write it. Preserved sender metadata is a
        # different matter and is deliberately kept; the rule is about keys we
        # invent, so the payload here contains none of these words to begin
        # with.
        clean = payload(check_runs=[{"name": "tests", "conclusion": "success"}],
                        comments=[{"author": "ci-bot", "body": "ok", "at": NOW}])
        envelope = normalize_pull_request(clean)

        def keys(value):
            if isinstance(value, dict):
                for k, v in value.items():
                    yield str(k).lower()
                    yield from keys(v)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    yield from keys(item)

        trust_words = {"trusted", "independent", "verified", "verdict",
                       "authority", "grant", "collector_id", "observed",
                       "source", "signature"}
        present = set(keys(envelope.as_dict()))
        self.assertEqual(present & trust_words, set(),
                         "this module invented a trust-shaped key")

    def test_no_function_here_returns_a_verdict(self):
        import proofos.github as module

        for name in module.__all__:
            obj = getattr(module, name)
            if callable(obj) and not isinstance(obj, type):
                annotations = getattr(obj, "__annotations__", {})
                self.assertNotIn("VerificationResult", str(annotations.get("return", "")))


class ThePayloadIsValidatedTests(unittest.TestCase):
    def refuse(self, pr, *, contains=""):
        with self.assertRaises(AdapterError) as caught:
            normalize_pull_request(pr)
        if contains:
            self.assertIn(contains, str(caught.exception))

    def test_a_missing_repository_or_number_is_refused(self):
        for key in ("repository", "number"):
            body = payload()
            body.pop(key)
            with self.subTest(key=key):
                self.refuse(body)

    def test_a_missing_head_sha_is_refused(self):
        body = payload()
        body.pop("head_sha")
        self.refuse(body, contains="head_sha")

    def test_a_missing_author_is_refused(self):
        body = payload()
        body.pop("author")
        self.refuse(body, contains="author")

    def test_a_non_object_payload_is_refused(self):
        self.refuse(["acme/service"], contains="must be an object")

    def test_malformed_collections_are_refused(self):
        self.refuse(payload(comments="not a list"), contains="must be a list")
        self.refuse(payload(comments=["not an object"]),
                    contains="each comment must be an object")
        self.refuse(payload(check_runs=["not an object"]),
                    contains="each check run must be an object")

    def test_the_task_identity_is_the_pull_request_and_the_commit(self):
        envelope = normalize_pull_request(payload())
        self.assertEqual(envelope.claim.task.task_id, "acme/service#42")
        self.assertEqual(envelope.claim.task.execution_id, "a" * 40)
        self.assertEqual(envelope.transport, "github")


if __name__ == "__main__":
    unittest.main()
