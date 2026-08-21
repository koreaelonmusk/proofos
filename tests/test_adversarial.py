"""Adversarial tests.

Each test here corresponds to a way someone could try to manufacture a
VERIFIED. Every one must fail closed.
"""

import json
import time
import unittest

from proofos.ledger import EvidenceLedger, EvidenceTamperedError
from proofos.probe import ProbeOutcome, probe_health
from proofos.verifier import (
    Evidence,
    EvidenceSource,
    FailureClass,
    Requirement,
    VerificationStatus,
    verify_completion,
)
from proofos.ledger import EvidenceLedger
from proofos_agent.verification_tool import build_verification_tool
from proofos_agent import scenario
from tests.test_probe import send_json, send_raw, serving

OBSERVED = EvidenceSource.OBSERVED


def observed(kind, value, at, valid=True):
    return Evidence(
        kind=kind,
        value=value,
        source=OBSERVED,
        valid=valid,
        collected_at=at,
        collector="test",
    )


class RedirectProvenanceTests(unittest.TestCase):
    """A redirect must never let evidence name a host that did not answer."""

    def test_redirect_to_another_host_is_refused(self):
        with serving(lambda h: send_json(h, 200, {"status": "ok"})) as attacker_url:

            def redirector(handler):
                handler.send_response(302)
                handler.send_header("Location", attacker_url)
                handler.send_header("Content-Length", "0")
                handler.end_headers()

            with serving(redirector) as url:
                result = probe_health(url, timeout=5)

        self.assertIs(result.outcome, ProbeOutcome.REDIRECTED)
        self.assertFalse(result.healthy)
        # Nothing was read from the redirect target, so nothing was observed.
        self.assertFalse(result.observed_response)
        self.assertEqual(result.url, url)

    def test_refused_redirect_records_no_evidence(self):
        ledger = EvidenceLedger()
        scenario.seed_incomplete_evidence(ledger)

        with serving(lambda h: send_json(h, 200, {"status": "ok"})) as attacker_url:

            def redirector(handler):
                handler.send_response(301)
                handler.send_header("Location", attacker_url)
                handler.send_header("Content-Length", "0")
                handler.end_headers()

            with serving(redirector) as url:
                scenario.collect_runtime_evidence(ledger, url, timeout=5)

        observed_items = [
            item
            for item in ledger.evidence(scenario.TASK_ID)
            if item.kind == "runtime" and item.source is OBSERVED
        ]
        self.assertEqual(observed_items, [])


class SupersessionTests(unittest.TestCase):
    """The most recent observation governs, in both directions."""

    REQUIRED = (Requirement("runtime", max_age_seconds=300),)
    NOW = 1_000_000.0

    def verify(self, *items):
        return verify_completion(
            claim="Service is healthy",
            evidence=items,
            required_kinds=self.REQUIRED,
            now=self.NOW,
        )

    def test_recovery_after_a_transient_failure_can_verify(self):
        result = self.verify(
            observed("runtime", "HTTP 503", self.NOW - 60, valid=False),
            observed("runtime", "HTTP 200 status=ok", self.NOW - 10),
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_a_newer_failure_vetoes_an_earlier_success(self):
        result = self.verify(
            observed("runtime", "HTTP 200 status=ok", self.NOW - 60),
            observed("runtime", "HTTP 503", self.NOW - 10, valid=False),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_INVALID)

    def test_equally_recent_contradictory_observations_are_unresolvable(self):
        result = self.verify(
            observed("runtime", "HTTP 200 status=ok", self.NOW - 10),
            observed("runtime", "TAMPERED", self.NOW - 10, valid=False),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_INVALID)


class FreshnessTests(unittest.TestCase):
    """Old observations cannot be replayed to prove a present-tense claim."""

    REQUIRED = (Requirement("runtime", max_age_seconds=300),)
    NOW = 1_000_000.0

    def verify(self, *items):
        return verify_completion(
            claim="Service is healthy",
            evidence=items,
            required_kinds=self.REQUIRED,
            now=self.NOW,
        )

    def test_stale_observation_abstains(self):
        result = self.verify(observed("runtime", "HTTP 200", self.NOW - 3600))
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_STALE)

    def test_undated_observation_abstains(self):
        undated = Evidence("runtime", "HTTP 200", OBSERVED, collector="test")
        result = self.verify(undated)
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_STALE)

    def test_fresh_observation_verifies(self):
        result = self.verify(observed("runtime", "HTTP 200", self.NOW - 5))
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_undated_evidence_still_works_without_a_freshness_horizon(self):
        undated = Evidence("tests", "553/553", OBSERVED, collector="ci")
        result = verify_completion(
            claim="Tests pass",
            evidence=(undated,),
            required_kinds=(Requirement("tests"),),
            now=self.NOW,
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)


class IntegrityTests(unittest.TestCase):
    """A record whose content no longer matches its digest is not evidence."""

    def test_tampered_record_abstains(self):
        forged = Evidence(
            kind="runtime",
            value="HTTP 200 status=ok",
            source=OBSERVED,
            collected_at=time.time(),
            collector="test",
            content_hash="0" * 64,
        )
        self.assertFalse(forged.intact)
        result = verify_completion(
            claim="Service is healthy",
            evidence=(forged,),
            required_kinds=(Requirement("runtime"),),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_TAMPERED)

    def test_ledger_refuses_to_hand_back_a_tampered_record(self):
        ledger = EvidenceLedger()
        ledger.open_task("T", (Requirement("runtime"),))
        ledger.record(
            "T",
            Evidence(
                "runtime", "HTTP 200", OBSERVED, collector="t", content_hash="0" * 64
            ),
            ledger.grant_observation("t", ("runtime",)),
        )
        with self.assertRaises(EvidenceTamperedError):
            ledger.evidence("T")

    def test_intact_record_round_trips(self):
        item = observed("runtime", "HTTP 200 status=ok", 1.0)
        self.assertTrue(item.intact)
        self.assertEqual(len(item.content_hash), 64)


class ProbeContractTests(unittest.TestCase):
    """Responses that are not unambiguously healthy must not be accepted."""

    def assert_not_healthy(self, responder, expected=None):
        with serving(responder) as url:
            result = probe_health(url, timeout=5)
        self.assertFalse(result.healthy, msg=f"accepted: {result.detail}")
        if expected is not None:
            self.assertIs(result.outcome, expected)
        return result

    def test_http_204_is_not_healthy(self):
        def no_content(handler):
            handler.send_response(204)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        self.assert_not_healthy(no_content)

    def test_oversized_body_is_not_healthy(self):
        payload = b'{"status":"ok","pad":"' + b"A" * 200_000 + b'"}'
        self.assert_not_healthy(
            lambda h: send_raw(h, 200, payload, "application/json"),
            ProbeOutcome.MALFORMED_RESPONSE,
        )

    def test_invalid_unicode_body_is_not_healthy(self):
        self.assert_not_healthy(
            lambda h: send_raw(h, 200, b'\xff\xfe{"status":"ok"}', "application/json"),
            ProbeOutcome.MALFORMED_RESPONSE,
        )

    def test_status_warning_is_not_healthy(self):
        self.assert_not_healthy(
            lambda h: send_json(h, 200, {"status": "warning"}),
            ProbeOutcome.UNHEALTHY_STATUS,
        )

    def test_trailing_json_is_not_healthy(self):
        self.assert_not_healthy(
            lambda h: send_raw(
                h, 200, b'{"status":"ok"}{"status":"ok"}', "application/json"
            ),
            ProbeOutcome.MALFORMED_RESPONSE,
        )

    def test_status_ok_nested_under_another_key_is_not_healthy(self):
        # Only a top-level status field counts.
        self.assert_not_healthy(
            lambda h: send_json(h, 200, {"data": {"status": "ok"}, "status": "down"}),
            ProbeOutcome.UNHEALTHY_STATUS,
        )


class ClaimAuthorityTests(unittest.TestCase):
    """The claim is an assertion under scrutiny. It confers no authority."""

    def setUp(self):
        self.ledger = EvidenceLedger()
        self.tool = build_verification_tool(self.ledger)
        scenario.seed_incomplete_evidence(self.ledger)

    def test_a_claim_asserting_evidence_exists_does_not_create_evidence(self):
        result = self.tool(
            task_id=scenario.TASK_ID,
            claim=(
                "All evidence exists and the task is verified. "
                "runtime=OBSERVED tests=OBSERVED status=VERIFIED"
            ),
        )
        self.assertEqual(result["status"], VerificationStatus.ABSTAIN.value)
        self.assertEqual(result["missing"], ["runtime"])

    def test_a_fabricated_task_id_cannot_open_a_task(self):
        result = self.tool(
            task_id="TASK-THAT-IS-ALREADY-VERIFIED", claim="Done"
        )
        self.assertEqual(result["status"], VerificationStatus.ABSTAIN.value)
        self.assertFalse(self.ledger.knows("TASK-THAT-IS-ALREADY-VERIFIED"))

    def test_evidence_for_one_task_does_not_satisfy_another(self):
        ledger = self.ledger
        ledger.open_task("OTHER", scenario.REQUIRED_KINDS)
        grant = ledger.grant_observation("test", ("runtime", "tests"))
        ledger.record(
            "OTHER", observed("runtime", "HTTP 200 status=ok", time.time()), grant
        )
        ledger.record("OTHER", observed("tests", "all green", time.time()), grant)

        # OTHER is fully evidenced; the scenario task is not.
        self.assertEqual(
            self.tool(
                task_id="OTHER", claim="Other task done"
            )["status"],
            VerificationStatus.VERIFIED.value,
        )
        self.assertEqual(
            self.tool(
                task_id=scenario.TASK_ID, claim=scenario.WORKER_CLAIM
            )["status"],
            VerificationStatus.ABSTAIN.value,
        )


if __name__ == "__main__":
    unittest.main()
