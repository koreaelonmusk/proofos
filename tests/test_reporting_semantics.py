"""D19: what the API says about evidence must be what the verifier did.

The kernel was always right. The reporting layer computed

    satisfies_requirement = item.valid

which is integrity, not acceptance, so a self-report the verifier had just
refused was rendered as satisfying -- in the one direction that flatters the
system. A judge reading the JSON would have concluded that ProofOS accepts an
agent's word about its own work, which is the exact claim the product denies.

These tests pin three separable properties:

* integrity, acceptance, and satisfaction are distinct and independently
  observable;
* acceptance is a fact about one verification attempt, not a permanent
  property stamped on an evidence object;
* the reporting projection cannot move the verdict.

The mutation test is the load-bearing one: reverting the field to ``item.valid``
must fail, or this file is decoration.
"""

from __future__ import annotations

import time
import unittest

from proofos.verifier import (
    Evidence,
    EvidenceSource,
    FailureClass,
    Requirement,
    VerificationStatus,
    verify_completion,
)

CLAIM = "The bug is fixed and the service is healthy."


def executor_selfreport(value: str = "executor-v1 states: I verified it myself"):
    return Evidence(
        kind="runtime",
        value=value,
        source=EvidenceSource.EXECUTOR,
        valid=True,
        collected_at=time.time(),
        collector="executor-v1",
    )


def observed_runtime(valid: bool = True, at: float | None = None):
    return Evidence(
        kind="runtime",
        value="probe HEALTHY: 200 in 12ms",
        source=EvidenceSource.OBSERVED,
        valid=valid,
        collected_at=time.time() if at is None else at,
        collector="collector-http-v1",
    )


def observed_tests():
    return Evidence(
        kind="tests",
        value="42 passed",
        source=EvidenceSource.OBSERVED,
        valid=True,
        collected_at=time.time(),
        collector="collector-ci-v1",
    )


def assess(evidence, required=("runtime",)):
    result = verify_completion(
        claim=CLAIM,
        evidence=evidence,
        required_kinds=[Requirement(k) for k in required],
    )
    return result, {(a.kind, a.source): a for a in result.assessments}


class IntegrityIsNotAcceptanceTests(unittest.TestCase):
    """The three flags must be able to disagree, and here they do."""

    def test_a_valid_executor_self_report_is_sound_and_still_refused(self):
        # The item is not malformed and not tampered with. It is simply the
        # word of the agent under scrutiny, which is not evidence.
        result, by_source = assess([executor_selfreport()])

        item = by_source[("runtime", "EXECUTOR")]
        self.assertTrue(item.integrity_valid)
        self.assertFalse(item.accepted_by_verifier)
        self.assertFalse(item.satisfies_requirement)
        self.assertIn("EXECUTOR", item.rejection_reason)

        self.assertIs(result.status, VerificationStatus.ABSTAIN)
        self.assertIs(result.failure, FailureClass.EVIDENCE_UNTRUSTED)

    def test_a_signed_observation_is_sound_accepted_and_satisfying(self):
        result, by_source = assess([observed_runtime()])

        item = by_source[("runtime", "OBSERVED")]
        self.assertTrue(item.integrity_valid)
        self.assertTrue(item.accepted_by_verifier)
        self.assertTrue(item.satisfies_requirement)
        self.assertEqual(item.rejection_reason, "")

        self.assertIs(result.status, VerificationStatus.VERIFIED)

    def test_tampered_evidence_fails_every_acceptance_field(self):
        item = observed_runtime()
        # Edit the record without recomputing its digest -- exactly what a
        # tamper looks like from the ledger's side.
        object.__setattr__(item, "value", "probe HEALTHY: forged")

        result, by_source = assess([item])
        assessment = by_source[("runtime", "OBSERVED")]
        self.assertFalse(assessment.integrity_valid)
        self.assertFalse(assessment.accepted_by_verifier)
        self.assertFalse(assessment.satisfies_requirement)
        self.assertIs(result.failure, FailureClass.EVIDENCE_TAMPERED)

    def test_an_authentic_but_unhealthy_observation_is_kept_and_counts_for_nothing(self):
        # A signed observation of a 503. Authentic, retained, and unable to
        # support a completion claim.
        result, by_source = assess([observed_runtime(valid=False)])

        item = by_source[("runtime", "OBSERVED")]
        self.assertFalse(item.integrity_valid)
        self.assertFalse(item.accepted_by_verifier)
        self.assertFalse(item.satisfies_requirement)
        self.assertIs(result.status, VerificationStatus.ABSTAIN)

    def test_a_superseded_observation_is_accepted_but_does_not_satisfy(self):
        """Acceptance and satisfaction are not the same question."""
        older = observed_runtime(at=time.time() - 60)
        newer = observed_runtime()
        result, _ = assess([older, newer])

        by_id = {a.evidence_id: a for a in result.assessments}
        self.assertTrue(by_id[older.content_hash].accepted_by_verifier)
        self.assertFalse(by_id[older.content_hash].satisfies_requirement)
        self.assertIn("Superseded", by_id[older.content_hash].rejection_reason)

        self.assertTrue(by_id[newer.content_hash].satisfies_requirement)
        self.assertIs(result.status, VerificationStatus.VERIFIED)


class MutationTests(unittest.TestCase):
    """Reverting the fix must break something."""

    def test_satisfies_requirement_is_not_item_valid(self):
        # This is the mutation, stated directly: the old expression and the
        # correct one must disagree on a real case. If someone restores
        # `satisfies_requirement = item.valid`, this fails.
        item = executor_selfreport()
        _, by_source = assess([item])
        assessment = by_source[("runtime", "EXECUTOR")]

        self.assertTrue(item.valid, "precondition: the self-report is not malformed")
        self.assertNotEqual(
            assessment.satisfies_requirement,
            item.valid,
            "satisfies_requirement has been reverted to item.valid",
        )

    def test_accepted_by_verifier_is_not_item_valid(self):
        item = executor_selfreport()
        _, by_source = assess([item])
        self.assertNotEqual(
            by_source[("runtime", "EXECUTOR")].accepted_by_verifier, item.valid
        )

    def test_no_evidence_is_accepted_when_the_verdict_is_untrusted(self):
        # A blanket property that survives refactoring: if the verifier
        # abstained for want of trusted evidence of a kind, nothing of that
        # kind may be reported as satisfying.
        result, _ = assess([executor_selfreport()])
        self.assertIs(result.failure, FailureClass.EVIDENCE_UNTRUSTED)
        for assessment in result.assessments:
            if assessment.kind == "runtime":
                self.assertFalse(assessment.satisfies_requirement)


class ReportingCannotMoveTheVerdictTests(unittest.TestCase):
    """The projection observes; it does not vote."""

    def test_the_model_facing_tool_result_is_unchanged_by_reporting(self):
        # Assessments are a runtime side channel. If they leaked into the tool
        # payload the model would see the verifier's internal reasoning, and a
        # reporting change would become a prompt change.
        from proofos.ledger import EvidenceLedger
        from proofos_agent.verification_tool import build_verification_tool

        ledger = EvidenceLedger()
        ledger.open_task("T1", (Requirement("runtime"),))
        tool = build_verification_tool(ledger)
        payload = tool("T1", CLAIM)

        self.assertEqual(
            set(payload), {"status", "reason", "missing", "failure"}
        )
        for key in ("evidence", "assessments", "accepted_evidence_ids"):
            self.assertNotIn(key, payload)

    def test_the_side_channel_records_without_altering_the_decision(self):
        from proofos.ledger import EvidenceLedger
        from proofos_agent.verification_tool import build_verification_tool

        ledger = EvidenceLedger()
        ledger.open_task("T1", (Requirement("runtime"),))
        tool = build_verification_tool(ledger)

        first = tool("T1", CLAIM)
        second = tool("T1", CLAIM)
        self.assertEqual(first, second, "reading assessments changed the verdict")
        self.assertEqual(len(tool.results), 2)
        self.assertIs(tool.results[-1].status, VerificationStatus.ABSTAIN)

    def test_assessment_ids_are_the_evidence_content_hashes(self):
        # The join key between a decision and the ledger has to be the
        # evidence's own digest, or reporting would be matching on something
        # forgeable.
        item = observed_runtime()
        result, _ = assess([item])
        self.assertEqual(result.accepted_evidence_ids, (item.content_hash,))
        self.assertEqual(result.rejected_evidence_ids, ())

    def test_untrusted_evidence_lands_in_rejected_ids(self):
        item = executor_selfreport()
        result, _ = assess([item])
        self.assertEqual(result.rejected_evidence_ids, (item.content_hash,))
        self.assertEqual(result.accepted_evidence_ids, ())


class MixedEvidenceTests(unittest.TestCase):
    """The shape of a real ProofOS execution at the moment it verifies."""

    def test_the_executor_claim_and_the_observation_are_told_apart(self):
        claim_item = executor_selfreport()
        observation = observed_runtime()
        result, by_source = assess(
            [observed_tests(), claim_item, observation],
            required=("tests", "runtime"),
        )

        self.assertIs(result.status, VerificationStatus.VERIFIED)

        executor = by_source[("runtime", "EXECUTOR")]
        collector = by_source[("runtime", "OBSERVED")]
        self.assertEqual(
            (executor.integrity_valid, executor.accepted_by_verifier,
             executor.satisfies_requirement),
            (True, False, False),
        )
        self.assertEqual(
            (collector.integrity_valid, collector.accepted_by_verifier,
             collector.satisfies_requirement),
            (True, True, True),
        )

    def test_evidence_of_an_undeclared_kind_satisfies_nothing(self):
        stray = Evidence(
            kind="vibes",
            value="looks fine to me",
            source=EvidenceSource.OBSERVED,
            collected_at=time.time(),
            collector="collector-http-v1",
        )
        result, _ = assess([observed_runtime(), stray])
        by_kind = {a.kind: a for a in result.assessments}
        self.assertFalse(by_kind["vibes"].accepted_by_verifier)
        self.assertFalse(by_kind["vibes"].satisfies_requirement)
        self.assertIn("No requirement", by_kind["vibes"].rejection_reason)


if __name__ == "__main__":
    unittest.main()
