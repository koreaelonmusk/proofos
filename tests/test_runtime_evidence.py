"""End-to-end: real probe -> ledger -> verifier.

Proves the runtime evidence that reaches the verifier came from an actual
network response, and that every probe failure mode fails closed.
"""

import unittest

from proofos.ledger import EvidenceLedger
from proofos.verifier import (
    EvidenceSource,
    FailureClass,
    VerificationStatus,
    verify_completion,
)
from proofos_agent import scenario
from tests.test_probe import (
    closed_port_url,
    send_json,
    send_raw,
    serving,
    slow_responder,
)


class RuntimeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ledger = EvidenceLedger()
        scenario.seed_incomplete_evidence(self.ledger)

    def verify(self):
        return verify_completion(
            claim=scenario.WORKER_CLAIM,
            evidence=self.ledger.evidence(scenario.TASK_ID),
            required_kinds=self.ledger.requirements(scenario.TASK_ID),
        )

    def runtime_items(self):
        return [
            item
            for item in self.ledger.evidence(scenario.TASK_ID)
            if item.kind == "runtime"
        ]

    def test_worker_self_report_alone_never_verifies(self):
        result = self.verify()
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))
        self.assertEqual(result.failure, FailureClass.EVIDENCE_UNTRUSTED)

    def test_healthy_probe_produces_observed_evidence_and_verifies(self):
        with serving(lambda h: send_json(h, 200, {"status": "ok"})) as url:
            probe = scenario.collect_runtime_evidence(self.ledger, url, timeout=5)

        self.assertTrue(probe.healthy)
        observed = [
            item
            for item in self.runtime_items()
            if item.source is EvidenceSource.OBSERVED
        ]
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0].valid)
        # The evidence value carries the real response, not a canned string.
        self.assertIn("HTTP 200", observed[0].value)
        self.assertIn(url, observed[0].value)

        self.assertEqual(self.verify().status, VerificationStatus.VERIFIED)

    def test_5xx_records_invalid_evidence_and_abstains(self):
        with serving(lambda h: h.send_error(503, "unavailable")) as url:
            scenario.collect_runtime_evidence(self.ledger, url, timeout=5)

        observed = [
            item
            for item in self.runtime_items()
            if item.source is EvidenceSource.OBSERVED
        ]
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].valid)
        self.assertIn("503", observed[0].value)

        result = self.verify()
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_INVALID)

    def test_malformed_response_abstains(self):
        with serving(lambda h: send_raw(h, 200, b"<html>OK</html>")) as url:
            scenario.collect_runtime_evidence(self.ledger, url, timeout=5)

        result = self.verify()
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_INVALID)

    def test_timeout_records_no_observed_evidence_and_abstains(self):
        with serving(slow_responder(3)) as url:
            probe = scenario.collect_runtime_evidence(self.ledger, url, timeout=0.3)

        self.assertFalse(probe.observed_response)
        # Nothing was observed, so nothing was recorded.
        self.assertEqual(
            [i for i in self.runtime_items() if i.source is EvidenceSource.OBSERVED],
            [],
        )
        result = self.verify()
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_UNTRUSTED)

    def test_connection_failure_records_no_observed_evidence_and_abstains(self):
        probe = scenario.collect_runtime_evidence(
            self.ledger, closed_port_url(), timeout=5
        )
        self.assertFalse(probe.observed_response)
        self.assertEqual(
            [i for i in self.runtime_items() if i.source is EvidenceSource.OBSERVED],
            [],
        )
        self.assertEqual(self.verify().status, VerificationStatus.ABSTAIN)

    def test_probe_cannot_be_satisfied_by_a_lying_endpoint_shape(self):
        # An endpoint that returns 200 but does not meet the contract must not
        # be accepted just because it responded.
        with serving(lambda h: send_json(h, 200, {"status": "degraded"})) as url:
            scenario.collect_runtime_evidence(self.ledger, url, timeout=5)
        self.assertEqual(self.verify().status, VerificationStatus.ABSTAIN)


if __name__ == "__main__":
    unittest.main()


class DemoEndpointTests(unittest.TestCase):
    """The demo entrypoint must probe a real endpoint, not a stub."""

    def test_local_demo_service_answers_a_real_probe(self):
        from proofos.probe import ProbeOutcome, probe_health
        from proofos_agent.run_demo import health_endpoint

        import os

        saved = os.environ.pop("PROOFOS_HEALTH_URL", None)
        try:
            with health_endpoint() as (url, kind):
                self.assertEqual(kind, "local-demo-service")
                result = probe_health(url, timeout=5)
        finally:
            if saved is not None:
                os.environ["PROOFOS_HEALTH_URL"] = saved

        self.assertIs(result.outcome, ProbeOutcome.HEALTHY)

    def test_configured_url_overrides_the_demo_service(self):
        import os

        from proofos_agent.run_demo import health_endpoint

        os.environ["PROOFOS_HEALTH_URL"] = "https://example.invalid/healthz"
        try:
            with health_endpoint() as (url, kind):
                self.assertEqual(url, "https://example.invalid/healthz")
                self.assertEqual(kind, "configured")
        finally:
            os.environ.pop("PROOFOS_HEALTH_URL", None)
