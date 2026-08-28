"""HTTP probe tests.

These run against real HTTP servers on real sockets. The probe is the component
that turns a network response into evidence, so stubbing the network here would
defeat the point of the test.
"""

import contextlib
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from proofos.probe import ProbeOutcome, probe_health


def make_handler(responder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            responder(self)

        def log_message(self, *args):
            pass

    return Handler


@contextlib.contextmanager
def serving(responder):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(responder))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/healthz"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def send_json(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def send_raw(handler, status, body: bytes, content_type="text/html"):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def slow_responder(delay: float):
    """A handler that answers too late for the probe's timeout.

    The client will have disconnected by the time it writes, so the resulting
    connection error is expected and suppressed to keep test output readable.
    """

    def respond(handler):
        time.sleep(delay)
        with contextlib.suppress(OSError):
            send_json(handler, 200, {"status": "ok"})

    return respond


def closed_port_url() -> str:
    """Bind and immediately release a port so nothing is listening on it."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return f"http://127.0.0.1:{port}/healthz"


class ProbeSuccessTests(unittest.TestCase):
    def test_successful_healthcheck_is_healthy(self):
        with serving(lambda h: send_json(h, 200, {"status": "ok"})) as url:
            result = probe_health(url, timeout=5)
        self.assertIs(result.outcome, ProbeOutcome.HEALTHY)
        self.assertTrue(result.healthy)
        self.assertTrue(result.observed_response)
        self.assertEqual(result.status_code, 200)
        # The detail is derived from the real response, not a canned string.
        self.assertIn(url, result.detail)


class ProbeFailureTests(unittest.TestCase):
    """Every failure path must report not-healthy so the verifier fails closed."""

    def assert_not_healthy(self, result, expected_outcome):
        self.assertIs(result.outcome, expected_outcome)
        self.assertFalse(result.healthy)

    def test_5xx_is_unhealthy(self):
        with serving(lambda h: h.send_error(503, "unavailable")) as url:
            result = probe_health(url, timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.UNHEALTHY_STATUS)
        self.assertEqual(result.status_code, 503)
        self.assertTrue(result.observed_response)

    def test_500_is_unhealthy(self):
        with serving(lambda h: h.send_error(500, "boom")) as url:
            result = probe_health(url, timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.UNHEALTHY_STATUS)
        self.assertEqual(result.status_code, 500)

    def test_non_json_body_is_malformed(self):
        with serving(lambda h: send_raw(h, 200, b"<html>OK</html>")) as url:
            result = probe_health(url, timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.MALFORMED_RESPONSE)

    def test_json_without_status_field_is_malformed(self):
        with serving(lambda h: send_json(h, 200, {"uptime": 123})) as url:
            result = probe_health(url, timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.MALFORMED_RESPONSE)

    def test_json_array_body_is_malformed(self):
        with serving(lambda h: send_json(h, 200, ["ok"])) as url:
            result = probe_health(url, timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.MALFORMED_RESPONSE)

    def test_status_not_ok_is_unhealthy(self):
        with serving(lambda h: send_json(h, 200, {"status": "degraded"})) as url:
            result = probe_health(url, timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.UNHEALTHY_STATUS)

    def test_timeout_is_reported_and_not_healthy(self):
        with serving(slow_responder(3)) as url:
            started = time.monotonic()
            result = probe_health(url, timeout=0.3)
            elapsed = time.monotonic() - started

        self.assert_not_healthy(result, ProbeOutcome.TIMEOUT)
        # Nothing came back, so nothing was observed.
        self.assertFalse(result.observed_response)
        self.assertLess(elapsed, 3, "probe did not honour its timeout")

    def test_connection_failure_is_unreachable(self):
        result = probe_health(closed_port_url(), timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.UNREACHABLE)
        self.assertFalse(result.observed_response)

    def test_invalid_url_is_unreachable(self):
        result = probe_health("http://proofos.invalid./healthz", timeout=5)
        self.assert_not_healthy(result, ProbeOutcome.UNREACHABLE)
        self.assertFalse(result.observed_response)


if __name__ == "__main__":
    unittest.main()
