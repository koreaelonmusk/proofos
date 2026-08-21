"""Process separation, proved against real OS processes.

The collector runs under its own interpreter, generates its own Ed25519 key,
and is reachable only over TCP. This process never sees the private half.

These tests are the ones that would fail if the separation were cosmetic: an
in-memory TestClient would pass a happy-path assertion while proving nothing
about where the key lives.
"""

import asyncio
import os
import time
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofos.attestation import AttestationSigner, ObservationAttestation, Outcome
from proofos.journal import EventType, InMemoryJournalSink
from proofos.verifier import EvidenceSource
from proofos_agent.attested_scenario import build_attested_fleet, run_attested_scenario
from proofos_agent.collector_client import (
    CollectorUnavailable,
    GoogleIdTokenCollectorClient,
    HttpCollectorClient,
    build_collector_client,
)
from proofos_agent.demo_service import running_health_service
from tests.process_harness import CollectorProcess, free_port
from tests.test_authority import reachable_types

TASK = "BUG-4417"


def run(coro):
    return asyncio.run(coro)


class RelayingClient:
    """Wraps a real client and lets a test tamper with what comes back.

    This is the orchestrator's actual position in the architecture: it holds
    the bytes on their way to the ingestor. If relaying were the same as
    authoring, tampering here would work.
    """

    def __init__(self, inner, mutate=None):
        self.inner = inner
        self.mutate = mutate
        self.last = None

    def collect(self, **kwargs):
        payload = self.inner.collect(**kwargs)
        self.last = dict(payload)
        return self.mutate(dict(payload)) if self.mutate else payload


class ProcessSeparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._target = running_health_service()
        cls.target_url = cls._target.__enter__()
        cls.collector = CollectorProcess(cls.target_url).start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()
        cls._target.__exit__(None, None, None)

    def client(self, mutate=None):
        return RelayingClient(HttpCollectorClient(self.collector.base_url), mutate)

    def execute(self, client, **kwargs):
        return run(
            run_attested_scenario(
                InMemoryJournalSink(), self.collector.public_key_b64, client, **kwargs
            )
        )

    # -- the boundary itself ------------------------------------------------

    def test_the_collector_runs_in_a_different_os_process(self):
        self.assertNotEqual(os.getpid(), self.collector.pid)
        self.assertGreater(self.collector.pid, 0)

    def test_this_process_holds_no_signing_key(self):
        self.assertNotIn("PROOFOS_COLLECTOR_PRIVATE_KEY", os.environ)

        fleet, attested, journal, ledger, collectors = build_attested_fleet(
            InMemoryJournalSink(), self.collector.public_key_b64, self.client()
        )
        for root in (fleet.executor, fleet.verifier, attested, collectors):
            types = reachable_types(root, max_depth=8)
            self.assertNotIn(
                Ed25519PrivateKey,
                types,
                msg=f"a private key is reachable from {type(root).__name__}",
            )
            self.assertNotIn(AttestationSigner, types)

    def test_the_published_key_is_only_the_public_half(self):
        """An Ed25519 private seed is also 32 bytes, so length proves nothing.

        What proves it: treating the published bytes as a private seed derives
        a *different* public key. If the private half had leaked, the two would
        match.
        """
        import base64

        from cryptography.hazmat.primitives import serialization

        raw = base64.b64decode(self.collector.public_key_b64, validate=True)
        self.assertEqual(len(raw), 32)

        derived = (
            Ed25519PrivateKey.from_private_bytes(raw)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        self.assertNotEqual(derived, raw)

    # -- the happy path, end to end ----------------------------------------

    def test_abstain_then_collect_across_processes_then_verified(self):
        outcome, journal, ledger = self.execute(self.client())

        self.assertEqual(outcome["final_status"], "VERIFIED")
        self.assertEqual(
            [d["status"] for d in outcome["decisions"]], ["ABSTAIN", "VERIFIED"]
        )
        self.assertEqual(outcome["decisions"][0]["failure"], "EVIDENCE_UNTRUSTED")

        runtime = [i for i in ledger.evidence(TASK) if i.kind == "runtime"]
        sources = {(i.source, i.collector) for i in runtime}
        self.assertIn((EvidenceSource.EXECUTOR, "executor-v1"), sources)
        self.assertIn((EvidenceSource.OBSERVED, "collector-http-v1"), sources)

        events = [str(e.event) for e in journal.events()]
        for expected in (
            "COLLECTION_REQUESTED",
            "COLLECTOR_RESPONSE_RECEIVED",
            "ATTESTATION_ACCEPTED",
            "EVIDENCE_COLLECTED",
        ):
            self.assertIn(expected, events)
        self.assertTrue(journal.verify()[0])

    def test_a_real_network_probe_actually_ran(self):
        client = self.client()
        self.execute(client)
        # The attestation commits to a digest of bytes that came back over the
        # wire, and to a 200 the collector observed for itself.
        self.assertEqual(client.last["status_code"], 200)
        self.assertEqual(client.last["outcome"], "HEALTHY")
        self.assertEqual(len(client.last["response_digest"]), 64)

    # -- tampering in transit ----------------------------------------------

    def assert_relay_tamper_fails(self, mutate):
        outcome, journal, ledger = self.execute(self.client(mutate))
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        observed = [
            i
            for i in ledger.evidence(TASK)
            if i.kind == "runtime" and i.source is EvidenceSource.OBSERVED
        ]
        self.assertEqual(observed, [], "tampered attestation became evidence")
        self.assertIn(
            "ATTESTATION_REJECTED", [str(e.event) for e in journal.events()]
        )

    def test_relayer_cannot_change_the_status_code(self):
        self.assert_relay_tamper_fails(lambda p: {**p, "status_code": 201})

    def test_relayer_cannot_upgrade_an_unhealthy_reading_to_healthy(self):
        """The tamper worth the most: turning a 503 into a 200."""
        from tests.test_probe import serving

        with serving(lambda h: h.send_error(503, "down")) as sick:
            collector = CollectorProcess(sick).start()
            try:
                client = RelayingClient(
                    HttpCollectorClient(collector.base_url),
                    lambda p: {**p, "outcome": "HEALTHY", "status_code": 200},
                )
                outcome, journal, ledger = run(
                    run_attested_scenario(
                        InMemoryJournalSink(), collector.public_key_b64, client
                    )
                )
            finally:
                collector.stop()

        self.assertEqual(client.last["outcome"], "UNHEALTHY_STATUS")
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertIn(
            "ATTESTATION_REJECTED", [str(e.event) for e in journal.events()]
        )

    def test_relayer_cannot_change_the_task(self):
        self.assert_relay_tamper_fails(lambda p: {**p, "task_id": "OTHER-TASK"})

    def test_relayer_cannot_change_the_execution(self):
        self.assert_relay_tamper_fails(lambda p: {**p, "execution_id": "exec_other"})

    def test_relayer_cannot_freshen_the_timestamp(self):
        self.assert_relay_tamper_fails(
            lambda p: {**p, "observed_at": time.time() + 30}
        )

    def test_relayer_cannot_strip_the_signature(self):
        self.assert_relay_tamper_fails(lambda p: {**p, "signature": ""})

    def test_relayer_cannot_add_a_trust_field(self):
        self.assert_relay_tamper_fails(lambda p: {**p, "source": "OBSERVED"})

    def test_relayer_cannot_substitute_its_own_signature(self):
        impostor = AttestationSigner.generate("collector-http-v1")

        def forge(payload):
            attestation = ObservationAttestation.from_dict(payload)
            replacement = impostor.sign(
                execution_id=attestation.execution_id,
                task_id=attestation.task_id,
                kind=attestation.kind,
                profile_id=attestation.profile_id,
                request_nonce=attestation.request_nonce,
                observed_at=attestation.observed_at,
                outcome=Outcome.HEALTHY,
                status_code=200,
                response_digest_value=attestation.response_digest,
                detail=attestation.detail,
            )
            return replacement.to_dict()

        self.assert_relay_tamper_fails(forge)

    def test_relayer_cannot_replay_an_attestation_into_a_second_execution(self):
        first_client = self.client()
        self.execute(first_client)
        stolen = first_client.last

        class ReplayClient:
            def collect(self, **kwargs):
                return dict(stolen)

        outcome, journal, ledger = self.execute(ReplayClient())
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(
            [
                i
                for i in ledger.evidence(TASK)
                if i.source is EvidenceSource.OBSERVED and i.kind == "runtime"
            ],
            [],
        )

    # -- collector failures -------------------------------------------------

    def test_an_unhealthy_target_is_attested_and_still_abstains(self):
        from tests.test_probe import serving

        with serving(lambda h: h.send_error(503, "down")) as sick:
            collector = CollectorProcess(sick).start()
            try:
                outcome, journal, ledger = run(
                    run_attested_scenario(
                        InMemoryJournalSink(),
                        collector.public_key_b64,
                        HttpCollectorClient(collector.base_url),
                    )
                )
            finally:
                collector.stop()

        self.assertEqual(outcome["final_status"], "ABSTAIN")
        # The negative observation is authentic and is kept.
        observed = [
            i
            for i in ledger.evidence(TASK)
            if i.kind == "runtime" and i.source is EvidenceSource.OBSERVED
        ]
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].valid)
        self.assertIn("UNHEALTHY_STATUS", observed[0].value)

    def test_an_unreachable_collector_abstains(self):
        dead = f"http://127.0.0.1:{free_port()}"
        outcome, journal, ledger = run(
            run_attested_scenario(
                InMemoryJournalSink(),
                self.collector.public_key_b64,
                HttpCollectorClient(dead),
            )
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(ledger.evidence(TASK)[0].kind, "tests")

    def test_a_collector_returning_junk_abstains(self):
        class JunkClient:
            def collect(self, **kwargs):
                return {"not": "an attestation"}

        outcome, _, ledger = self.execute(JunkClient())
        self.assertEqual(outcome["final_status"], "ABSTAIN")


class TransportSelectionTests(unittest.TestCase):
    """Credentials are chosen by the target, not by the caller's optimism."""

    def test_loopback_gets_the_unauthenticated_client(self):
        client = build_collector_client("http://127.0.0.1:9999")
        self.assertIsInstance(client, HttpCollectorClient)

    def test_a_remote_target_requires_google_identity(self):
        client = build_collector_client("https://proofos-collector-abc.a.run.app")
        self.assertIsInstance(client, GoogleIdTokenCollectorClient)
        self.assertEqual(client.audience, "https://proofos-collector-abc.a.run.app")

    def test_the_unauthenticated_client_refuses_a_remote_target(self):
        with self.assertRaises(ValueError):
            HttpCollectorClient("https://proofos-collector-abc.a.run.app")

    def test_the_google_client_reports_missing_credentials_as_unavailable(self):
        # No ADC in this environment: it must fail closed, not proceed.
        client = GoogleIdTokenCollectorClient("https://example.a.run.app")
        with self.assertRaises(CollectorUnavailable):
            client.collect(
                execution_id="e",
                task_id="t",
                evidence_kind="runtime",
                profile_id="runtime-health-v1",
                request_nonce="n",
            )


if __name__ == "__main__":
    unittest.main()
