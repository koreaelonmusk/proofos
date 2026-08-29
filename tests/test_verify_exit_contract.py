"""The four exit codes a CI pipeline reads, each reachable and each distinct.

Exit 0 was unreachable for a while, and why is worth keeping. The old path let
an input file declare ``"source": "OBSERVED"`` and believed it, so closing that
hole removed the only route to a verdict. Restoring the route by relaxing the
refusal would have been restoring the hole.

So the CLI observes things itself. Given an instruction -- probe this URL, hash
this file -- it carries it out and records the result under its own collector
identity. It is then genuinely the component that looked, which is what OBSERVED
has always meant. The positive case here runs against a real loopback server for
the same reason: a stub returning a canned probe result would be testing the
fixture.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from proofos import EvidenceLedger, Requirement
from proofos.capabilities import CapabilityDenied, ObservationCapability
from proofos.cli import (
    CLI_COLLECTOR,
    EXIT_ABSTAIN,
    EXIT_OPERATIONAL,
    EXIT_USAGE,
    EXIT_VERIFIED,
    main,
)

NOW = 1_700_000_000.0


def run(argv):
    out = io.StringIO()
    code = main(argv, out=out)
    return code, out.getvalue()


def respond(handler, status, body):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@contextlib.contextmanager
def serving(responder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            responder(self)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/health"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class FileVerificationExitContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, body):
        path = self.dir / name
        path.write_text(json.dumps(body) if isinstance(body, dict) else body,
                        encoding="utf-8")
        return path

    def verify(self, path, *extra):
        return run(["verify", str(path), "--json", "--now", str(NOW), *extra])

    def artifact(self, content=b"release bytes"):
        path = self.dir / "artifact.bin"
        path.write_bytes(content)
        return path

    # -- exit 0: an observation the CLI actually made ---------------------------

    def test_a_digest_the_cli_computed_verifies(self):
        path = self.write("a.json", {
            "claim": "Release complete.",
            "requirements": [{"kind": "artifact"}],
            "observations": [{"kind": "artifact", "check": "digest",
                              "path": str(self.artifact())}],
        })
        code, text = self.verify(path)
        self.assertEqual(code, EXIT_VERIFIED)
        data = json.loads(text)
        self.assertEqual(data["status"], "VERIFIED")
        self.assertEqual([e["source"] for e in data["evidence"]], ["OBSERVED"])
        self.assertEqual(data["evidence"][0]["collector"], CLI_COLLECTOR)

    def test_a_probe_the_cli_ran_verifies(self):
        with serving(lambda h: respond(h, 200, b'{"status":"ok"}')) as url:
            path = self.write("a.json", {
                "claim": "Deployment complete.",
                "requirements": [{"kind": "runtime_health"}],
                "observations": [{"kind": "runtime_health", "check": "http",
                                  "url": url}],
            })
            code, text = self.verify(path)
        self.assertEqual(code, EXIT_VERIFIED)
        self.assertEqual(json.loads(text)["evidence"][0]["collector"], CLI_COLLECTOR)

    def test_the_verdict_is_not_reachable_by_asserting_it(self):
        # The same claim, with the file saying it was observed instead of the
        # CLI going and looking. This is the shape that used to exit 0.
        path = self.write("a.json", {
            "claim": "Release complete.",
            "requirements": [{"kind": "artifact"}],
            "evidence": [{"kind": "artifact", "value": "trust me",
                          "source": "OBSERVED", "collector": "build-agent",
                          "collected_at": NOW}],
        })
        code, _ = self.verify(path)
        self.assertEqual(code, EXIT_USAGE)

    # -- exit 1: real results that are not a pass -------------------------------

    def test_a_self_report_alone_abstains(self):
        path = self.write("b.json", {
            "claim": "Release complete.",
            "requirements": [{"kind": "artifact"}],
            "evidence": [{"kind": "artifact", "value": "agent says it built",
                          "source": "EXECUTOR", "collector": "build-agent",
                          "collected_at": NOW}],
        })
        code, text = self.verify(path)
        self.assertEqual(code, EXIT_ABSTAIN)
        self.assertEqual(json.loads(text)["reason"], "EVIDENCE_UNTRUSTED")

    def test_an_unhealthy_service_abstains(self):
        with serving(lambda h: respond(h, 500, b'{"status":"down"}')) as url:
            path = self.write("b.json", {
                "claim": "Deployment complete.",
                "requirements": [{"kind": "runtime_health"}],
                "observations": [{"kind": "runtime_health", "check": "http",
                                  "url": url}],
            })
            code, _ = self.verify(path)
        self.assertEqual(code, EXIT_ABSTAIN)

    def test_an_observation_that_could_not_be_made_records_nothing(self):
        # The distinction the conformance suite draws, here at the CLI. Not
        # reaching something is not a finding about it, so nothing is written
        # and the requirement is simply unmet -- rather than a record saying an
        # observation happened when it did not.
        path = self.write("b.json", {
            "claim": "Release complete.",
            "requirements": [{"kind": "artifact"}],
            "observations": [{"kind": "artifact", "check": "digest",
                              "path": str(self.dir / "absent.bin")}],
        })
        code, text = self.verify(path)
        self.assertEqual(code, EXIT_ABSTAIN)
        data = json.loads(text)
        self.assertEqual(data["evidence"], [])
        self.assertEqual(data["missing"], ["artifact"])

    # -- exit 2: the caller got it wrong ----------------------------------------

    def test_malformed_json_is_a_usage_error(self):
        code, _ = self.verify(self.write("c.json", "{ not json"))
        self.assertEqual(code, EXIT_USAGE)

    def test_a_missing_file_is_a_usage_error(self):
        code, _ = self.verify(self.dir / "nowhere.json")
        self.assertEqual(code, EXIT_USAGE)

    def test_a_malformed_observation_is_a_usage_error(self):
        for spec in ({"kind": "artifact"},
                     {"kind": "artifact", "check": "telepathy"},
                     {"kind": "artifact", "check": "digest"},
                     {"check": "digest", "path": "x"},
                     "not an object"):
            with self.subTest(spec=spec):
                path = self.write("c.json", {
                    "claim": "c", "requirements": [{"kind": "artifact"}],
                    "observations": [spec]})
                self.assertEqual(self.verify(path)[0], EXIT_USAGE)

    def test_observations_must_be_a_list(self):
        path = self.write("c.json", {
            "claim": "c", "requirements": [{"kind": "artifact"}],
            "observations": {"kind": "artifact"}})
        self.assertEqual(self.verify(path)[0], EXIT_USAGE)

    # -- exit 3: the environment failed -----------------------------------------

    def test_an_unreadable_input_is_an_operational_failure(self):
        # Naming the wrong file is the caller's mistake and exits 2. A path the
        # process cannot open is the environment failing, and a pipeline needs
        # to tell those apart to know whether retrying is sensible.
        unreadable = self.dir / "adir.json"
        unreadable.mkdir()
        self.assertEqual(self.verify(unreadable)[0], EXIT_OPERATIONAL)

    def test_the_four_exit_codes_are_distinct(self):
        self.assertEqual(
            len({EXIT_VERIFIED, EXIT_ABSTAIN, EXIT_USAGE, EXIT_OPERATIONAL}), 4)


class TheCliCollectorIsBoundedTests(unittest.TestCase):
    """The fix rests on a capability, so the capability is checked too."""

    def test_it_may_only_write_the_kinds_it_was_asked_to_check(self):
        ledger = EvidenceLedger()
        ledger.open_task("t", (Requirement("artifact"),))
        collector = ObservationCapability(ledger, CLI_COLLECTOR, ("artifact",))
        ledger.seal()
        with self.assertRaises(CapabilityDenied):
            collector.record_observation("t", "runtime_health", "probe HEALTHY",
                                         satisfies=True, collected_at=NOW)

    def test_it_may_only_write_under_its_own_identity(self):
        from proofos import Evidence, EvidenceSource

        ledger = EvidenceLedger()
        ledger.open_task("t", (Requirement("artifact"),))
        collector = ObservationCapability(ledger, CLI_COLLECTOR, ("artifact",))
        ledger.seal()
        forged = Evidence(kind="artifact", value="x",
                          source=EvidenceSource.OBSERVED, collected_at=NOW,
                          collector="someone-else")
        with self.assertRaises(CapabilityDenied):
            ledger.record("t", forged, collector._grant)


if __name__ == "__main__":
    unittest.main()
