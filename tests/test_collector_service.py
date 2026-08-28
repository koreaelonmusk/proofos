"""Collector service tests: SSRF surface and caller-supplied fields.

Putting the probe behind an API is the moment SSRF becomes possible, so these
tests attack the request shape directly. The collector must never let a caller
choose what to look at, only which approved profile to run.
"""

import json
import os
import threading
import time
import unittest
import urllib.error
import urllib.request

import uvicorn

from proofos.profiles import (
    ALLOWED_SCHEMES,
    CollectionProfile,
    ProfileError,
    ProfileRegistry,
    ProfileScopeViolation,
    UnknownProfile,
    default_profiles,
)
from tests.process_harness import free_port
from tests.test_probe import send_json, serving


class RunningCollector:
    def __init__(self, target_url: str):
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        os.environ["PROOFOS_COLLECTOR_TARGET"] = target_url
        os.environ["PROOFOS_COLLECTOR_ID"] = "collector-http-v1"
        # Import after the environment is set so the app picks up the target.
        import importlib

        import proofos_collector.app as module

        self.module = importlib.reload(module)
        config = uvicorn.Config(
            self.module.app, host="127.0.0.1", port=self.port, log_level="error"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self):
        self._thread.start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self._server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("collector did not start")

    def stop(self):
        self._server.should_exit = True
        self._thread.join(timeout=10)
        os.environ.pop("PROOFOS_COLLECTOR_TARGET", None)
        os.environ.pop("PROOFOS_COLLECTOR_ID", None)

    def post(self, path, payload):
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())

    def get(self, path):
        with urllib.request.urlopen(f"{self.base}{path}", timeout=20) as response:
            return response.status, json.loads(response.read())


def valid_request(**overrides):
    body = {
        "execution_id": "exec_1",
        "task_id": "BUG-4417",
        "evidence_kind": "runtime",
        "profile_id": "runtime-health-v1",
        "request_nonce": "nonce_abc",
    }
    body.update(overrides)
    return body


class CollectorServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._target = serving(lambda h: send_json(h, 200, {"status": "ok"}))
        cls.target_url = cls._target.__enter__()
        cls.collector = RunningCollector(cls.target_url).start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()
        cls._target.__exit__(None, None, None)

    def post(self, payload):
        return self.collector.post("/v1/collect", payload)

    def expect_status(self, payload, code):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.post(payload)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_a_valid_request_returns_a_signed_attestation(self):
        status, body = self.post(valid_request())
        self.assertEqual(status, 200)
        attestation = body["attestation"]
        self.assertEqual(attestation["outcome"], "HEALTHY")
        self.assertEqual(attestation["collector_id"], "collector-http-v1")
        self.assertTrue(attestation["signature"])

    def test_the_response_never_carries_a_source_or_trust_field(self):
        _, body = self.post(valid_request())
        for forbidden in ("source", "valid", "verified", "status"):
            self.assertNotIn(forbidden, body["attestation"])

    def test_the_response_does_not_disclose_the_target_url(self):
        # A caller that may not choose the target should not learn it either.
        _, body = self.post(valid_request())
        self.assertNotIn(self.target_url, json.dumps(body))

    def test_profiles_endpoint_does_not_disclose_targets(self):
        _, body = self.collector.get("/v1/profiles")
        self.assertNotIn(self.target_url, json.dumps(body))
        self.assertEqual(body["profiles"][0]["profile_id"], "runtime-health-v1")


class SsrfTests(CollectorServiceTests):
    """A caller must never be able to choose what gets fetched."""

    def test_a_raw_url_field_is_refused(self):
        self.expect_status(valid_request(url="http://169.254.169.254/"), 422)

    def test_a_metadata_endpoint_target_cannot_be_injected(self):
        for field in ("url", "target", "host", "endpoint"):
            self.expect_status(
                valid_request(**{field: "http://169.254.169.254/computeMetadata/v1/"}),
                422,
            )

    def test_a_file_scheme_cannot_be_injected(self):
        self.expect_status(valid_request(url="file:///etc/passwd"), 422)

    def test_an_unknown_profile_is_refused(self):
        self.expect_status(valid_request(profile_id="anything-i-like"), 404)

    def test_a_profile_cannot_be_used_for_another_evidence_kind(self):
        self.expect_status(valid_request(evidence_kind="tests"), 403)

    def test_caller_supplied_collector_id_is_refused(self):
        self.expect_status(valid_request(collector_id="collector-ci-v1"), 422)

    def test_caller_supplied_observed_at_is_refused(self):
        self.expect_status(valid_request(observed_at=0), 422)

    def test_caller_supplied_outcome_is_refused(self):
        self.expect_status(valid_request(outcome="HEALTHY"), 422)

    def test_caller_supplied_source_is_refused(self):
        self.expect_status(valid_request(source="OBSERVED"), 422)

    def test_caller_supplied_signature_is_refused(self):
        self.expect_status(valid_request(signature="AAAA"), 422)

    def test_caller_supplied_status_code_is_refused(self):
        self.expect_status(valid_request(status_code=200), 422)

    def test_caller_supplied_valid_flag_is_refused(self):
        self.expect_status(valid_request(valid=True), 422)

    def test_missing_required_fields_are_refused(self):
        body = valid_request()
        del body["request_nonce"]
        self.expect_status(body, 422)

    def test_the_collector_reports_what_it_saw_not_what_was_asked(self):
        # The caller cannot influence the outcome; it comes from the probe.
        _, body = self.post(valid_request())
        self.assertEqual(body["attestation"]["status_code"], 200)


class ProfilePolicyTests(unittest.TestCase):
    """Profiles are configuration. Nothing at request time may widen them."""

    def test_only_http_and_https_targets_are_accepted(self):
        for scheme in ("file", "ftp", "gopher", "data"):
            with self.assertRaises(ProfileError):
                CollectionProfile(
                    profile_id="p",
                    collector_id="c",
                    allowed_kind="runtime",
                    target=f"{scheme}://somewhere/x",
                )
        self.assertEqual(ALLOWED_SCHEMES, frozenset({"http", "https"}))

    def test_a_target_without_a_host_is_refused(self):
        with self.assertRaises(ProfileError):
            CollectionProfile(
                profile_id="p",
                collector_id="c",
                allowed_kind="runtime",
                target="http:///nowhere",
            )

    def test_profiles_seal(self):
        registry = default_profiles("http://127.0.0.1:1/healthz", "c")
        self.assertTrue(registry.sealed)
        with self.assertRaises(ProfileError):
            registry.register(
                CollectionProfile(
                    profile_id="late",
                    collector_id="c",
                    allowed_kind="runtime",
                    target="http://127.0.0.1:2/healthz",
                )
            )

    def test_resolve_enforces_kind_and_owner(self):
        registry = default_profiles("http://127.0.0.1:1/healthz", "collector-http-v1")
        with self.assertRaises(ProfileScopeViolation):
            registry.resolve("runtime-health-v1", "tests", "collector-http-v1")
        with self.assertRaises(ProfileScopeViolation):
            registry.resolve("runtime-health-v1", "runtime", "someone-else")
        with self.assertRaises(UnknownProfile):
            registry.resolve("nope", "runtime", "collector-http-v1")

    def test_duplicate_profile_ids_are_refused(self):
        registry = ProfileRegistry()
        profile = CollectionProfile(
            profile_id="p",
            collector_id="c",
            allowed_kind="runtime",
            target="http://127.0.0.1:1/x",
        )
        registry.register(profile)
        with self.assertRaises(ProfileError):
            registry.register(profile)


class CollectorFailureTests(unittest.TestCase):
    """A collector that cannot see must not pretend it did."""

    @classmethod
    def setUpClass(cls):
        # Point the profile at a port with nothing listening.
        cls.dead = f"http://127.0.0.1:{free_port()}/healthz"
        cls.collector = RunningCollector(cls.dead).start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()

    def test_an_unreachable_target_is_attested_as_unreachable(self):
        status, body = self.collector.post("/v1/collect", valid_request())
        self.assertEqual(status, 200)
        # Still signed, still authentic -- and unable to satisfy anything.
        self.assertEqual(body["attestation"]["outcome"], "UNREACHABLE")
        self.assertTrue(body["attestation"]["signature"])


class RedirectTests(unittest.TestCase):
    def test_a_redirecting_target_is_attested_as_redirected(self):
        with serving(lambda h: send_json(h, 200, {"status": "ok"})) as evil:

            def redirector(handler):
                handler.send_response(302)
                handler.send_header("Location", evil)
                handler.send_header("Content-Length", "0")
                handler.end_headers()

            with serving(redirector) as target:
                collector = RunningCollector(target).start()
                try:
                    _, body = collector.post("/v1/collect", valid_request())
                finally:
                    collector.stop()

        # Redirects stay disabled: the probe refuses to be pointed elsewhere.
        self.assertEqual(body["attestation"]["outcome"], "REDIRECTED")


if __name__ == "__main__":
    unittest.main()
