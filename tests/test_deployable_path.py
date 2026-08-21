"""The deployable path: a real API process obtaining attested evidence.

Everything here drives the actual HTTP API from outside, in the mode a
deployment would run. The API process is configured with a collector URL and a
public key and nothing else; it has no signing key and no local route to
producing runtime evidence.

The attacks below come from the collector's side of the wire, because that is
the position an attacker who compromised the collector endpoint would hold. A
malicious collector is stood up as a real HTTP server and pointed at by a real
API process -- no monkeypatching, since patching across a boundary would be
proving the boundary does not exist.
"""

import contextlib
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from proofos.attestation import AttestationSigner, Outcome, response_digest
from proofos.keys import FileSigningKeyProvider, encode_public_key
from proofos_agent.demo_service import running_health_service
from tests.process_harness import ApiProcess, CollectorProcess, free_port

TASK = "BUG-4417"
CLAIM = "Production bug BUG-4417 is fixed and the service is healthy."
COLLECTOR_ID = "collector-http-v1"
PROFILE = "runtime-health-v1"


class FakeCollector:
    """A collector endpoint under the test's control.

    Used to attack the API's ingestion boundary over real HTTP: the API cannot
    tell this apart from the real collector except by checking the signature,
    which is exactly the property under test.
    """

    def __init__(self, responder):
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = json.dumps({"status": "ok"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                request = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append(request)
                status, payload = responder(request)
                body = json.dumps(payload).encode()
                # The timeout test deliberately answers after the client has
                # given up, so a broken pipe here is expected, not a failure.
                with contextlib.suppress(OSError):
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=10)


def sign_with(signer, request, **overrides):
    fields = dict(
        execution_id=request["execution_id"],
        task_id=request["task_id"],
        kind=request["evidence_kind"],
        profile_id=request["profile_id"],
        request_nonce=request["request_nonce"],
        observed_at=time.time(),
        outcome=Outcome.HEALTHY,
        status_code=200,
        response_digest_value=response_digest(b'{"status":"ok"}'),
        detail="HEALTHY via runtime-health-v1",
    )
    fields.update(overrides)
    return signer.sign(**fields)


class DeployableExecutionTests(unittest.TestCase):
    """The required end-to-end chain, driven through the real API."""

    @classmethod
    def setUpClass(cls):
        cls._target = running_health_service()
        cls.target_url = cls._target.__enter__()
        cls.collector = CollectorProcess(cls.target_url).start()
        cls.api = ApiProcess(cls.collector.base_url, cls.collector.public_key_b64).start()

    @classmethod
    def tearDownClass(cls):
        cls.api.stop()
        cls.collector.stop()
        cls._target.__exit__(None, None, None)

    def execute(self, claim=CLAIM, **extra):
        return self.api.post("/executions", {"claim": claim, **extra})

    def test_the_api_and_collector_are_separate_processes(self):
        pids = {os.getpid(), self.api.pid, self.collector.pid}
        self.assertEqual(len(pids), 3)

    def test_the_api_reports_remote_attested_mode(self):
        _, config = self.api.get("/config")
        self.assertEqual(config["collector_mode"], "remote")
        self.assertTrue(config["attested_evidence"])
        self.assertEqual(config["collector_id"], COLLECTOR_ID)

    def test_config_carries_no_key_material_or_internal_target(self):
        _, config = self.api.get("/config")
        rendered = json.dumps(config)
        self.assertNotIn(self.collector.public_key_b64, rendered)
        self.assertNotIn(self.target_url, rendered)
        self.assertNotIn("PRIVATE", rendered.upper())

    def test_abstain_then_attested_collection_then_verified(self):
        status, body = self.execute()
        self.assertEqual(status, 200)
        self.assertEqual(body["final_status"], "VERIFIED")
        self.assertEqual(
            [d["status"] for d in body["decisions"]], ["ABSTAIN", "VERIFIED"]
        )
        self.assertEqual(body["decisions"][0]["failure"], "EVIDENCE_UNTRUSTED")
        self.assertEqual(body["decisions"][0]["missing"], ["runtime"])

    def test_runtime_evidence_is_attributed_to_the_separate_collector(self):
        _, body = self.execute()
        runtime = {
            (e["source"], e["collector"])
            for e in body["evidence"]
            if e["kind"] == "runtime"
        }
        # The executor's self-report is present and refused; the attested
        # observation is what carries the requirement.
        self.assertIn(("EXECUTOR", "executor-v1"), runtime)
        self.assertIn(("OBSERVED", COLLECTOR_ID), runtime)

    def test_the_audit_trail_shows_the_whole_chain(self):
        _, body = self.execute()
        _, audit = self.api.get(f"/executions/{body['execution_id']}")

        self.assertTrue(audit["chain_ok"])
        self.assertEqual(audit["chain_problems"], [])
        self.assertEqual(audit["summary"]["final_status"], "VERIFIED")

        events = [e["event"] for e in audit["events"]]
        for required in (
            "EXECUTION_START",
            "VERIFIER_DECISION",
            "COLLECTION_REQUESTED",
            "COLLECTOR_RESPONSE_RECEIVED",
            "ATTESTATION_ACCEPTED",
            "EVIDENCE_COLLECTED",
            "EXECUTION_COMPLETE",
        ):
            self.assertIn(required, events)

        # Ordering matters: the acceptance precedes the verdict it enables.
        self.assertLess(
            events.index("ATTESTATION_ACCEPTED"),
            len(events) - 1 - events[::-1].index("VERIFIER_DECISION"),
        )
        self.assertEqual(
            [d["status"] for d in audit["summary"]["decisions"]],
            ["ABSTAIN", "VERIFIED"],
        )

    def test_every_event_shares_the_execution_and_task(self):
        _, body = self.execute()
        _, audit = self.api.get(f"/executions/{body['execution_id']}")
        for event in audit["events"]:
            self.assertEqual(event["execution_id"], body["execution_id"])
            self.assertEqual(event["task_id"], TASK)
            self.assertEqual(event["trace_id"], body["trace_id"])
            self.assertTrue(event["agent"])

    def test_the_journal_carries_no_secrets(self):
        _, body = self.execute()
        _, audit = self.api.get(f"/executions/{body['execution_id']}")
        rendered = json.dumps(audit)
        self.assertNotIn(self.collector.public_key_b64, rendered)
        for forbidden in ("Authorization", "Bearer ", "BEGIN PRIVATE KEY"):
            self.assertNotIn(forbidden, rendered)

    def test_caller_supplied_trust_fields_are_refused(self):
        for extra in (
            {"source": "OBSERVED"},
            {"collector_id": COLLECTOR_ID},
            {"request_nonce": "nonce_mine"},
            {"status_code": 200},
            {"url": "http://169.254.169.254/"},
            {"evidence": [{"kind": "runtime"}]},
            {"attestation": {"outcome": "HEALTHY"}},
        ):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.execute(**extra)
            self.assertEqual(caught.exception.code, 422, msg=f"accepted {extra}")


class ApiHoldsNoSigningKeyTests(unittest.TestCase):
    """Authority separation checked against the artifact, not the class model."""

    @classmethod
    def setUpClass(cls):
        cls._target = running_health_service()
        cls.target_url = cls._target.__enter__()
        cls.collector = CollectorProcess(cls.target_url).start()
        cls.api = ApiProcess(cls.collector.base_url, cls.collector.public_key_b64).start()

    @classmethod
    def tearDownClass(cls):
        cls.api.stop()
        cls.collector.stop()
        cls._target.__exit__(None, None, None)

    def test_the_api_process_has_no_private_key_configured(self):
        # The harness scrubs both routes before starting the API.
        _, config = self.api.get("/config")
        self.assertTrue(config["attested_evidence"])

    def test_the_api_image_contains_no_signing_key(self):
        """The deployable API image must not ship collector key material."""
        with open("Dockerfile", encoding="utf-8") as handle:
            dockerfile = handle.read()
        self.assertNotIn("proofos_collector", dockerfile)
        self.assertNotIn("PRIVATE_KEY", dockerfile)

    def test_the_api_source_tree_imports_no_signer(self):
        import ast
        import pathlib

        source = pathlib.Path("proofos_service/app.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                names.update(a.name for a in node.names)
                names.add(node.module or "")
            elif isinstance(node, ast.Import):
                names.update(a.name for a in node.names)
        self.assertNotIn("AttestationSigner", names)
        self.assertNotIn("proofos_collector", names)
        self.assertNotIn("proofos.keys", names)

    def test_no_committed_private_key_exists(self):
        import subprocess

        tracked = subprocess.run(
            ["git", "ls-files"], capture_output=True, text=True, check=True
        ).stdout.splitlines()
        for path in tracked:
            if path.endswith((".pem", ".key")):
                self.fail(f"key material is tracked in git: {path}")


class RemoteModeHasNoLocalFallbackTests(unittest.TestCase):
    """In remote mode there must be exactly one route to trusted evidence."""

    def test_a_dead_collector_abstains_rather_than_collecting_locally(self):
        with running_health_service() as target:
            # The API is pointed at a collector that is not there, while a
            # perfectly healthy target sits alongside. A fallback would find it.
            dead = f"http://127.0.0.1:{free_port()}"
            os.environ["PROOFOS_HEALTH_URL"] = target
            try:
                with ApiProcess(dead, _throwaway_public_key()) as api:
                    _, body = api.post("/executions", {"claim": CLAIM})
            finally:
                os.environ.pop("PROOFOS_HEALTH_URL", None)

        self.assertEqual(body["final_status"], "ABSTAIN")
        observed = [
            e
            for e in body["evidence"]
            if e["kind"] == "runtime" and e["source"] == "OBSERVED"
        ]
        self.assertEqual(observed, [], "runtime evidence was produced locally")

    def test_remote_mode_refuses_to_start_without_a_collector_url(self):
        from proofos_service.config import ConfigurationError, build_runtime_config

        with self.assertRaises(ConfigurationError):
            build_runtime_config({"PROOFOS_COLLECTOR_MODE": "remote"})

    def test_remote_mode_refuses_to_start_without_a_public_key(self):
        from proofos_service.config import ConfigurationError, build_runtime_config

        saved = os.environ.pop("PROOFOS_COLLECTOR_PUBLIC_KEY", None)
        try:
            with self.assertRaises(ConfigurationError):
                build_runtime_config(
                    {
                        "PROOFOS_COLLECTOR_MODE": "remote",
                        "PROOFOS_COLLECTOR_URL": "http://collector:8081",
                    }
                )
        finally:
            if saved is not None:
                os.environ["PROOFOS_COLLECTOR_PUBLIC_KEY"] = saved

    def test_remote_is_the_default_mode(self):
        from proofos_service.config import CollectorMode, ConfigurationError, build_runtime_config

        # No mode given: it must not quietly pick the in-process collector.
        with self.assertRaises(ConfigurationError) as caught:
            build_runtime_config({})
        self.assertIn("remote", str(caught.exception))
        self.assertEqual(CollectorMode("remote"), CollectorMode.REMOTE)


def _throwaway_public_key() -> str:
    return AttestationSigner.generate(COLLECTOR_ID).public_key_b64()


class MaliciousCollectorTests(unittest.TestCase):
    """Attacks launched from the collector's side of the wire."""

    @classmethod
    def setUpClass(cls):
        cls.signer = AttestationSigner.generate(COLLECTOR_ID)
        cls.public_key = cls.signer.public_key_b64()

    def run_against(self, responder, mode="remote", **api_kwargs):
        with FakeCollector(responder) as collector:
            with ApiProcess(
                collector.base_url, self.public_key, mode=mode, **api_kwargs
            ) as api:
                _, body = api.post("/executions", {"claim": CLAIM})
                _, audit = api.get(f"/executions/{body['execution_id']}")
        return body, audit

    def assert_abstains(self, responder, expect_rejection=True, **kwargs):
        body, audit = self.run_against(responder, **kwargs)
        self.assertEqual(body["final_status"], "ABSTAIN")
        observed = [
            e
            for e in body["evidence"]
            if e["kind"] == "runtime" and e["source"] == "OBSERVED"
        ]
        self.assertEqual(observed, [], "a bad attestation became evidence")
        if expect_rejection:
            self.assertIn(
                "ATTESTATION_REJECTED", [e["event"] for e in audit["events"]]
            )
        return body, audit

    # -- the honest baseline ------------------------------------------------

    def test_a_correctly_signed_attestation_verifies(self):
        body, _ = self.run_against(
            lambda r: (200, {"attestation": sign_with(self.signer, r).to_dict()})
        )
        self.assertEqual(body["final_status"], "VERIFIED")

    # -- signature and identity --------------------------------------------

    def test_an_attestation_signed_by_the_wrong_key_abstains(self):
        impostor = AttestationSigner.generate(COLLECTOR_ID)
        self.assert_abstains(
            lambda r: (200, {"attestation": sign_with(impostor, r).to_dict()})
        )

    def test_an_unsigned_payload_abstains(self):
        def responder(request):
            payload = sign_with(self.signer, request).to_dict()
            payload["signature"] = ""
            return 200, {"attestation": payload}

        self.assert_abstains(responder)

    def test_a_malformed_attestation_abstains(self):
        self.assert_abstains(lambda r: (200, {"attestation": {"nonsense": True}}))

    def test_a_response_without_an_attestation_abstains(self):
        # No attestation at all is a transport failure, not a rejection.
        self.assert_abstains(lambda r: (200, {"ok": True}), expect_rejection=False)

    def test_an_unknown_collector_id_abstains(self):
        stranger = AttestationSigner.generate("collector-rogue-v1")
        self.assert_abstains(
            lambda r: (200, {"attestation": sign_with(stranger, r).to_dict()})
        )

    # -- tampering ----------------------------------------------------------

    def tampered(self, **changes):
        def responder(request):
            payload = sign_with(self.signer, request).to_dict()
            payload.update(changes)
            return 200, {"attestation": payload}

        return responder

    def test_a_tampered_status_code_abstains(self):
        self.assert_abstains(self.tampered(status_code=500))

    def test_a_tampered_outcome_abstains(self):
        self.assert_abstains(self.tampered(outcome="UNHEALTHY_STATUS"))

    def test_a_tampered_body_digest_abstains(self):
        self.assert_abstains(self.tampered(response_digest="0" * 64))

    def test_a_tampered_task_id_abstains(self):
        self.assert_abstains(self.tampered(task_id="OTHER-TASK"))

    def test_a_tampered_execution_id_abstains(self):
        self.assert_abstains(self.tampered(execution_id="exec_elsewhere"))

    def test_a_tampered_nonce_abstains(self):
        self.assert_abstains(self.tampered(request_nonce="nonce_mine"))

    def test_a_tampered_profile_abstains(self):
        self.assert_abstains(self.tampered(profile_id="anything-v1"))

    def test_an_injected_source_field_abstains(self):
        # Asserting trust on the wire is refused, not ignored.
        self.assert_abstains(self.tampered(source="OBSERVED"))

    # -- time and replay -----------------------------------------------------

    def test_a_stale_attestation_abstains(self):
        def responder(request):
            payload = sign_with(
                self.signer, request, observed_at=time.time() - 100_000
            ).to_dict()
            return 200, {"attestation": payload}

        self.assert_abstains(responder)

    def test_a_future_dated_attestation_abstains(self):
        def responder(request):
            payload = sign_with(
                self.signer, request, observed_at=time.time() + 100_000
            ).to_dict()
            return 200, {"attestation": payload}

        self.assert_abstains(responder)

    def test_a_replayed_attestation_from_a_previous_execution_abstains(self):
        captured: dict = {}

        def capture(request):
            payload = sign_with(self.signer, request).to_dict()
            captured.update(payload)
            return 200, {"attestation": payload}

        first, _ = self.run_against(capture)
        self.assertEqual(first["final_status"], "VERIFIED")

        # The same genuine attestation, offered to a fresh execution.
        self.assert_abstains(lambda r: (200, {"attestation": dict(captured)}))

    # -- collector failures --------------------------------------------------

    def test_a_collector_error_response_abstains(self):
        self.assert_abstains(
            lambda r: (500, {"detail": "collector exploded"}), expect_rejection=False
        )

    def test_a_collector_timeout_abstains(self):
        def slow(request):
            time.sleep(6)
            return 200, {"attestation": sign_with(self.signer, request).to_dict()}

        self.assert_abstains(slow, expect_rejection=False, client_timeout="1")

    def test_a_signed_unhealthy_observation_is_recorded_but_does_not_verify(self):
        def responder(request):
            payload = sign_with(
                self.signer,
                request,
                outcome=Outcome.UNHEALTHY_STATUS,
                status_code=503,
                detail="UNHEALTHY_STATUS via runtime-health-v1",
            ).to_dict()
            return 200, {"attestation": payload}

        body, audit = self.run_against(responder)
        self.assertEqual(body["final_status"], "ABSTAIN")

        observed = [
            e
            for e in body["evidence"]
            if e["kind"] == "runtime" and e["source"] == "OBSERVED"
        ]
        # Authentic, kept, and unable to satisfy the claim.
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0]["satisfies_requirement"])
        events = [e["event"] for e in audit["events"]]
        self.assertIn("ATTESTATION_ACCEPTED", events)
        self.assertNotIn("ATTESTATION_REJECTED", events)


class BodyDigestTests(unittest.TestCase):
    """The response digest must reflect the bytes actually received."""

    def digest_for(self, body: dict) -> str:
        from tests.test_probe import send_json, serving

        with serving(lambda h: send_json(h, 200, body)) as target:
            collector = CollectorProcess(target).start()
            try:
                request = {
                    "execution_id": "exec_d",
                    "task_id": TASK,
                    "evidence_kind": "runtime",
                    "profile_id": PROFILE,
                    "request_nonce": "nonce_d",
                }
                payload = json.dumps(request).encode()
                req = urllib.request.Request(
                    f"{collector.base_url}/v1/collect",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as response:
                    return json.loads(response.read())["attestation"]
            finally:
                collector.stop()

    def test_a_healthy_response_yields_a_full_sha256_digest(self):
        attestation = self.digest_for({"status": "ok"})
        self.assertEqual(attestation["outcome"], "HEALTHY")
        self.assertEqual(len(attestation["response_digest"]), 64)
        self.assertNotEqual(attestation["response_digest"], "0" * 64)

    def test_changing_the_response_body_changes_the_digest(self):
        first = self.digest_for({"status": "ok"})
        second = self.digest_for({"status": "ok", "build": "2"})
        self.assertNotEqual(
            first["response_digest"],
            second["response_digest"],
            "the digest does not depend on the response body",
        )


class CollectorIdentityPersistenceTests(unittest.TestCase):
    """A restart must not rotate the collector's identity."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.key_file = os.path.join(self._dir.name, "collector.pem")
        self._target = running_health_service()
        self.target_url = self._target.__enter__()
        self.addCleanup(self._target.__exit__, None, None, None)

    def start_collector(self, port=None):
        collector = CollectorProcess(
            self.target_url, private_key_file=self.key_file, port=port
        ).start()
        self.addCleanup(collector.stop)
        return collector

    def test_identity_survives_a_restart(self):
        first = self.start_collector()
        identity = first.public_key_b64
        port = first.port
        first.stop()

        second = self.start_collector(port=port)
        self.assertEqual(
            second.public_key_b64, identity, "the collector rotated its identity"
        )

        # And an API configured for the original identity still verifies.
        with ApiProcess(second.base_url, identity) as api:
            _, body = api.post("/executions", {"claim": CLAIM})
        self.assertEqual(body["final_status"], "VERIFIED")

    def test_the_key_file_is_a_private_key_and_is_not_the_public_key(self):
        collector = self.start_collector()
        content = open(self.key_file, encoding="utf-8").read()
        self.assertIn("BEGIN PRIVATE KEY", content)
        self.assertNotIn(collector.public_key_b64, content)

    def test_loading_the_same_file_twice_yields_the_same_identity(self):
        provider = FileSigningKeyProvider(self.key_file)
        first = encode_public_key(provider.load_private_key().public_key())
        second = encode_public_key(provider.load_private_key().public_key())
        self.assertEqual(first, second)

    def test_a_rotated_key_is_rejected_until_trust_is_reconfigured(self):
        original = self.start_collector()
        old_identity = original.public_key_b64
        port = original.port
        original.stop()

        # Replace the key file: same collector id, new identity.
        os.remove(self.key_file)
        rotated = self.start_collector(port=port)
        self.assertNotEqual(rotated.public_key_b64, old_identity)

        # An API still configured with the old public key must refuse it.
        with ApiProcess(rotated.base_url, old_identity) as api:
            _, body = api.post("/executions", {"claim": CLAIM})
            _, audit = api.get(f"/executions/{body['execution_id']}")

        self.assertEqual(body["final_status"], "ABSTAIN")
        self.assertIn("ATTESTATION_REJECTED", [e["event"] for e in audit["events"]])

        # Deliberately reconfiguring trust to the new key accepts it again.
        with ApiProcess(rotated.base_url, rotated.public_key_b64) as api:
            _, body = api.post("/executions", {"claim": CLAIM})
        self.assertEqual(body["final_status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()
