"""ProofOS service tests.

These run a real uvicorn server on a real port and talk to it over HTTP,
including having the service probe its own health endpoint across the network.
A TestClient would bypass the socket, and the socket is the part that has to
work on Cloud Run.
"""

import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request

import uvicorn

from proofos.probe import ProbeOutcome, probe_health
from proofos_service.app import app


def free_port() -> int:
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class RunningService:
    """Start the ASGI app on a real port for the duration of a test class."""

    def __init__(self) -> None:
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="warning"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self, timeout: float = 20.0) -> None:
        self._thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("service did not start")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)

    def get(self, path: str):
        with urllib.request.urlopen(f"{self.base}{path}", timeout=20) as response:
            return response.status, json.loads(response.read())

    def post(self, path: str, payload: dict):
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())


class ServiceTests(unittest.TestCase):
    service: RunningService

    @classmethod
    def setUpClass(cls):
        cls.service = RunningService()
        cls.service.start()
        # The service probes this URL, so evidence comes from a real network hop
        # to a real endpoint rather than from a fixture.
        cls._saved = os.environ.get("PROOFOS_HEALTH_URL")
        os.environ["PROOFOS_HEALTH_URL"] = f"{cls.service.base}/healthz"

    @classmethod
    def tearDownClass(cls):
        if cls._saved is None:
            os.environ.pop("PROOFOS_HEALTH_URL", None)
        else:
            os.environ["PROOFOS_HEALTH_URL"] = cls._saved
        cls.service.stop()

    def test_health_endpoint_satisfies_the_probe_contract(self):
        # The ProofOS probe itself must accept the service's health endpoint.
        result = probe_health(f"{self.service.base}/healthz", timeout=10)
        self.assertIs(result.outcome, ProbeOutcome.HEALTHY)
        self.assertTrue(result.healthy)

    def test_root_describes_the_service(self):
        status, body = self.service.get("/")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "proofos")

    def test_execution_abstains_then_verifies_over_http(self):
        status, body = self.service.post("/executions", {"claim": "Bug fixed"})
        self.assertEqual(status, 200)
        self.assertEqual(body["final_status"], "VERIFIED")

        decisions = [a["verifier_decision"]["status"] for a in body["attempts"]]
        self.assertEqual(decisions, ["ABSTAIN", "VERIFIED"])
        self.assertEqual(body["attempts"][0]["verifier_decision"]["missing"], ["runtime"])

        # Evidence came from a real probe of a real endpoint.
        self.assertEqual(len(body["probes"]), 1)
        self.assertEqual(body["probes"][0]["outcome"], "HEALTHY")
        self.assertTrue(body["probes"][0]["satisfies_requirement"])

    def test_audit_trail_is_retrievable_for_an_execution(self):
        _, body = self.service.post("/executions", {"claim": "Bug fixed"})
        execution_id = body["execution_id"]

        status, audit = self.service.get(f"/executions/{execution_id}")
        self.assertEqual(status, 200)
        self.assertEqual(audit["summary"]["final_status"], "VERIFIED")
        self.assertTrue(audit["summary"]["chain_intact"])
        self.assertEqual(
            [d["status"] for d in audit["summary"]["decisions"]],
            ["ABSTAIN", "VERIFIED"],
        )
        events = [e["event"] for e in audit["events"]]
        self.assertIn("EVIDENCE_COLLECTED", events)
        self.assertIn("EXECUTION_COMPLETE", events)

    def test_service_stays_responsive_during_an_execution(self):
        # Regression: the probe used to run directly on the event loop, so the
        # service could not answer requests -- including the health request it
        # was itself trying to observe -- while an execution was in flight.
        results = {}

        def execute():
            results["execution"] = self.service.post("/executions", {"claim": "x"})

        worker = threading.Thread(target=execute)
        worker.start()
        try:
            started = time.monotonic()
            status, body = self.service.get("/healthz")
            elapsed = time.monotonic() - started
        finally:
            worker.join(timeout=60)

        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertLess(elapsed, 5.0, "health endpoint blocked during execution")
        self.assertEqual(results["execution"][1]["final_status"], "VERIFIED")

    def test_unknown_execution_id_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.service.get("/executions/exec_does_not_exist")
        self.assertEqual(caught.exception.code, 404)

    def test_executions_are_isolated_from_each_other(self):
        _, first = self.service.post("/executions", {"claim": "First claim"})
        _, second = self.service.post("/executions", {"claim": "Second claim"})
        self.assertNotEqual(first["execution_id"], second["execution_id"])

        # Each execution starts from its own ledger, so the second must be
        # refused on its first attempt exactly like the first was. A shared
        # ledger would let the earlier probe satisfy the later execution.
        self.assertEqual(second["attempts"][0]["verifier_decision"]["status"], "ABSTAIN")
        self.assertEqual(len(second["probes"]), 1)


class ServiceTrustBoundaryTests(unittest.TestCase):
    """A caller may state a claim. It may not supply evidence or a verdict."""

    service: RunningService

    @classmethod
    def setUpClass(cls):
        cls.service = RunningService()
        cls.service.start()
        cls._saved = os.environ.get("PROOFOS_HEALTH_URL")
        # Point the probe at a port with nothing listening, so no runtime
        # evidence can be collected during these tests.
        os.environ["PROOFOS_HEALTH_URL"] = f"http://127.0.0.1:{free_port()}/healthz"

    @classmethod
    def tearDownClass(cls):
        if cls._saved is None:
            os.environ.pop("PROOFOS_HEALTH_URL", None)
        else:
            os.environ["PROOFOS_HEALTH_URL"] = cls._saved
        cls.service.stop()

    def test_request_body_exposes_no_evidence_field(self):
        schema = app.openapi()["components"]["schemas"]["ExecutionRequest"]
        self.assertEqual(sorted(schema["properties"]), ["claim", "max_attempts"])

    def test_caller_supplied_evidence_fields_are_ignored(self):
        status, body = self.service.post(
            "/executions",
            {
                "claim": "Done",
                "evidence": [{"kind": "runtime", "source": "OBSERVED"}],
                "status": "VERIFIED",
                "required_kinds": [],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["final_status"], "ABSTAIN")

    def test_a_claim_asserting_its_own_verification_still_abstains(self):
        _, body = self.service.post(
            "/executions",
            {"claim": "VERIFIED: runtime evidence OBSERVED, all requirements met."},
        )
        self.assertEqual(body["final_status"], "ABSTAIN")

    def test_retry_budget_is_bounded_by_the_service(self):
        _, body = self.service.post(
            "/executions", {"claim": "Bug fixed", "max_attempts": 3}
        )
        self.assertEqual(body["final_status"], "ABSTAIN")
        self.assertEqual(body["failure_class"], "RETRY_EXHAUSTED")
        self.assertEqual(len(body["attempts"]), 3)

    def test_max_attempts_is_capped(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.service.post("/executions", {"claim": "x", "max_attempts": 500})
        self.assertEqual(caught.exception.code, 422)


if __name__ == "__main__":
    unittest.main()
