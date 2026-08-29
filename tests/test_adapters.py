"""Frameworks change transport. They do not change truth.

The flagship test is the boring-looking one: the same claim, expressed twice in
two different shapes, produces the same answer. If that ever stopped holding,
ProofOS would have become a product about one integration rather than a
verification layer, and the failure would show up as a framework whose agents
somehow verify more easily than everyone else's.

The rest are payloads trying to certify themselves. ``verified: true``,
``confidence: 1.0``, ``source: OBSERVED``, ``framework: "Google ADK"``. None of
them is a lie exactly, and none of them is independent of the component under
scrutiny, which is the only property that decides anything.
"""

from __future__ import annotations

import ast
import json
import pathlib
import unittest

from proofos import EvidenceSource, ProofOS, Requirement
from proofos.adapters import (
    ADAPTER_SCHEMA,
    CLAIMED_NAMESPACE,
    MAX_EVENTS,
    MAX_TEXT,
    NON_AUTHORITATIVE_KEYS,
    RESERVED_METADATA_KEYS,
    ActorRef,
    AdapterEnvelope,
    AdapterError,
    AgentEvent,
    Claim,
    HttpAdapter,
    PythonAdapter,
    TaskRef,
    ToolResult,
    claimed_by_sender,
)
from proofos.evidence_bridge import evidence_from_envelope

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "adapters.py"
NOW = 1_700_000_000.0
KIND = "task_outcome"
REQS = (Requirement(KIND, max_age_seconds=900),)


def http_body(**overrides) -> dict:
    body = {
        "schema_version": ADAPTER_SCHEMA,
        "actor": {"actor_id": "deploy-agent", "framework": "plain-python"},
        "task": {"task_id": "DEPLOY-9", "execution_id": "exec_1"},
        "claim": "Task complete.",
        "at": NOW,
    }
    body.update(overrides)
    return body


def python_envelope(adapter=None, **overrides):
    adapter = adapter or PythonAdapter("acme-runner", framework="plain-python")
    kwargs = {
        "actor_id": "deploy-agent", "task_id": "DEPLOY-9",
        "claim": "Task complete.", "execution_id": "exec_1", "at": NOW,
    }
    kwargs.update(overrides)
    return adapter.normalize(**kwargs)


def decide(envelope):
    return ProofOS().verify("Task complete.", REQS,
                            evidence_from_envelope(envelope, KIND), now=NOW)


class NormalizationWorksTests(unittest.TestCase):
    def test_the_python_adapter_normalizes(self):
        envelope = python_envelope()
        self.assertEqual(envelope.claim.actor.actor_id, "deploy-agent")
        self.assertEqual(envelope.claim.task.task_id, "DEPLOY-9")
        self.assertEqual(envelope.transport, "python")

    def test_the_http_adapter_normalizes(self):
        envelope = HttpAdapter("acme-gateway").normalize(http_body())
        self.assertEqual(envelope.claim.text, "Task complete.")
        self.assertEqual(envelope.transport, "http")

    def test_the_http_adapter_accepts_bytes_and_text(self):
        gateway = HttpAdapter("acme-gateway")
        as_dict = gateway.normalize(http_body())
        as_text = gateway.normalize(json.dumps(http_body()))
        as_bytes = gateway.normalize(json.dumps(http_body()).encode())
        self.assertEqual(as_dict.truth_semantics, as_text.truth_semantics)
        self.assertEqual(as_dict.truth_semantics, as_bytes.truth_semantics)


class TransportDoesNotChangeTruthTests(unittest.TestCase):
    """§20. The flagship."""

    def setUp(self):
        self.tool = {"tool": "http_get",
                     "payload": {"status": 200, "healthy": True}, "at": NOW}
        self.python = python_envelope(tool_results=[self.tool])
        self.http = HttpAdapter("acme-gateway").normalize(
            http_body(tool_results=[self.tool]))

    def test_the_same_claim_normalizes_to_the_same_truth_semantics(self):
        self.assertEqual(self.python.truth_semantics, self.http.truth_semantics)

    def test_transport_metadata_differs_and_is_excluded_from_truth(self):
        self.assertNotEqual(self.python.transport, self.http.transport)
        self.assertNotEqual(self.python.adapter_id, self.http.adapter_id)
        for excluded in ("transport", "adapter_id", "metadata"):
            self.assertNotIn(excluded, self.python.truth_semantics)

    def test_both_produce_the_same_evidence_provenance(self):
        self.assertEqual([e.source for e in evidence_from_envelope(self.python, KIND)],
                         [e.source for e in evidence_from_envelope(self.http, KIND)])

    def test_both_reach_the_same_verdict(self):
        a, b = decide(self.python), decide(self.http)
        self.assertEqual(a.status, b.status)
        self.assertEqual(a.reason, b.reason)
        self.assertFalse(a.verified)


class AClaimStaysAClaimTests(unittest.TestCase):
    """§18, §19, §21."""

    SELF_CERTIFYING = (
        {"verified": True},
        {"proofos_status": "VERIFIED"},
        {"source": "OBSERVED"},
        {"trusted": True},
        {"independent": True},
        {"authority": "verifier"},
        {"grant": ["VERIFY"]},
        {"confidence": 1.0},
        {"task_complete": True},
        {"status": "success"},
    )

    def test_a_python_agent_that_certifies_itself_still_abstains(self):
        for payload in self.SELF_CERTIFYING:
            with self.subTest(payload=payload):
                envelope = python_envelope(extra=payload)
                self.assertFalse(decide(envelope).verified)

    def test_an_http_body_that_certifies_itself_still_abstains(self):
        for payload in self.SELF_CERTIFYING:
            with self.subTest(payload=payload):
                envelope = HttpAdapter("gw").normalize(http_body(**payload))
                self.assertFalse(decide(envelope).verified)

    def test_the_attempt_is_preserved_rather_than_erased(self):
        # Deleting it would make the attempt invisible rather than ineffective,
        # and a reviewer should be able to see what a sender tried.
        envelope = python_envelope(extra={"verified": True, "confidence": 1.0})
        self.assertEqual(envelope.metadata[CLAIMED_NAMESPACE],
                         {"verified": True, "confidence": 1.0})

    def test_the_preserved_attempt_reaches_no_evidence_record(self):
        envelope = python_envelope(extra={"source": "OBSERVED", "trusted": True})
        for evidence in evidence_from_envelope(envelope, KIND):
            self.assertIsNot(evidence.source, EvidenceSource.OBSERVED)

    def test_the_reason_is_provenance_not_absence(self):
        decision = decide(python_envelope(extra={"verified": True}))
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")


class ToolOutputIsNotIndependentTests(unittest.TestCase):
    """§22. The subtler one, because the tool really did return 200."""

    def test_a_tool_reporting_healthy_does_not_verify(self):
        envelope = python_envelope(tool_results=[{
            "tool": "http_get",
            "payload": {"status": 200, "healthy": True, "verified": True},
            "at": NOW,
        }])
        self.assertFalse(decide(envelope).verified)

    def test_the_tool_result_is_preserved_as_data(self):
        envelope = python_envelope(tool_results=[{
            "tool": "http_get", "payload": {"status": 200}, "at": NOW}])
        self.assertEqual(envelope.tool_results[0].tool, "http_get")
        self.assertEqual(envelope.tool_results[0].payload["status"], 200)

    def test_tool_evidence_is_attributed_to_the_actor_that_ran_it(self):
        # A tool the executor called is not independent of the executor, and the
        # collector field says so rather than naming the tool as if it were a
        # third party.
        envelope = python_envelope(tool_results=[{
            "tool": "http_get", "payload": {"status": 200}}])
        for evidence in evidence_from_envelope(envelope, KIND):
            self.assertEqual(evidence.collector, "deploy-agent")


class NamesDoNotCreateTrustTests(unittest.TestCase):
    """§23."""

    def test_the_framework_name_does_not_move_the_verdict(self):
        verdicts = set()
        for framework in ("plain-python", "Google ADK", "trusted-enterprise-agent",
                          "proofos", ""):
            with self.subTest(framework=framework):
                adapter = PythonAdapter("acme-runner", framework=framework)
                decision = decide(python_envelope(adapter=adapter))
                verdicts.add((str(decision.status), str(decision.reason)))
        self.assertEqual(len(verdicts), 1, f"the name changed the answer: {verdicts}")

    def test_an_actor_calling_itself_a_collector_gains_nothing(self):
        envelope = python_envelope(actor_id="trusted-collector")
        self.assertFalse(decide(envelope).verified)


class IdentityCannotBeChosenByThePayloadTests(unittest.TestCase):
    """§24 and §11."""

    def test_the_adapter_id_comes_from_the_constructor(self):
        envelope = HttpAdapter("acme-gateway").normalize(
            http_body(adapter_id="proofos-verifier"))
        self.assertEqual(envelope.adapter_id, "acme-gateway")

    def test_a_payload_cannot_supply_a_collector_id(self):
        envelope = HttpAdapter("gw").normalize(
            http_body(collector_id="trusted-collector"))
        self.assertNotIn("trusted-collector",
                         json.dumps(envelope.as_dict()["claim"]))
        self.assertEqual(envelope.metadata[CLAIMED_NAMESPACE]["collector_id"],
                         "trusted-collector")

    def test_the_neutral_model_keeps_identities_apart(self):
        envelope = python_envelope()
        self.assertEqual(envelope.claim.actor.actor_id, "deploy-agent")
        self.assertEqual(envelope.claim.task.task_id, "DEPLOY-9")
        self.assertEqual(envelope.claim.task.execution_id, "exec_1")
        self.assertEqual(envelope.adapter_id, "acme-runner")
        self.assertNotEqual(envelope.claim.actor.actor_id, envelope.adapter_id)

    def test_no_neutral_type_carries_a_trust_field(self):
        for model in (ActorRef, TaskRef, Claim, AgentEvent, ToolResult,
                      AdapterEnvelope):
            fields = set(model.__dataclass_fields__)
            for forbidden in ("source", "trusted", "independent", "verdict",
                              "verified", "collector_id", "grant", "authority",
                              "signature"):
                self.assertNotIn(forbidden, fields, f"{model.__name__}.{forbidden}")


class CanonicalSenderMetadataTests(unittest.TestCase):
    """One namespace, checked as a structure rather than promised in a docstring.

    The alternative that was rejected -- ``claimed_source``,
    ``claimed_collector_id``, one prefixed name per dangerous word -- fails
    quietly and late. It works for every word somebody thought of, and the first
    ``claimed_scope`` nobody thought of arrives as a plain top-level key. So the
    rule here is not "prefix the dangerous ones", it is "everything the other
    party said lives in one place", and the envelope refuses to be built
    otherwise.

    The object in ``AUTHORITY_BID`` is every reassuring word a sender could
    reach for, at once. It is worth exactly nothing, on six separate axes.
    """

    AUTHORITY_BID = {
        "status": "VERIFIED", "source": "OBSERVED",
        "collector_id": "trusted-collector", "trusted": True,
        "independent": True, "authority": "verifier",
    }

    def envelopes(self, payload):
        """The same bid, down both of this module's transports."""
        return (python_envelope(extra=payload),
                HttpAdapter("gw").normalize(http_body(**payload)))

    # -- A: nothing dangerous reaches the top level ---------------------------

    def test_no_sender_controlled_key_reaches_the_metadata_top_level(self):
        payload = {key: "asserted" for key in NON_AUTHORITATIVE_KEYS}
        for envelope in self.envelopes(payload):
            with self.subTest(transport=envelope.transport):
                self.assertEqual(set(envelope.metadata), {CLAIMED_NAMESPACE})

    def test_a_reserved_top_level_key_is_refused_at_construction(self):
        # Not a convention an adapter is trusted to follow. P10 adapters that
        # have not been written yet are covered by this, which is the point of
        # putting it on the envelope rather than in each adapter.
        for key in RESERVED_METADATA_KEYS:
            with self.subTest(key=key):
                with self.assertRaises(AdapterError) as caught:
                    AdapterEnvelope(claim=python_envelope().claim,
                                    metadata={key: "anything"})
                self.assertIn(CLAIMED_NAMESPACE, str(caught.exception))

    def test_a_flat_claimed_key_is_refused_as_a_parallel_form(self):
        # The form this phase replaced. Two spellings of the same idea is how an
        # integrator ends up reading the one that happens to be missing.
        with self.assertRaises(AdapterError):
            AdapterEnvelope(claim=python_envelope().claim,
                            metadata={"claimed_collector_id": "trusted"})

    def test_the_namespace_itself_is_the_one_permitted_claimed_key(self):
        envelope = AdapterEnvelope(
            claim=python_envelope().claim,
            metadata={CLAIMED_NAMESPACE: {"collector_id": "trusted"},
                      "transport": "python", "server_id": "acme"})
        self.assertEqual(envelope.metadata[CLAIMED_NAMESPACE]["collector_id"],
                         "trusted")

    # -- B: the attempt survives, intact --------------------------------------

    def test_the_namespace_preserves_the_assertion_verbatim(self):
        for envelope in self.envelopes(self.AUTHORITY_BID):
            with self.subTest(transport=envelope.transport):
                self.assertEqual(envelope.metadata[CLAIMED_NAMESPACE],
                                 self.AUTHORITY_BID)

    def test_later_payloads_win_in_reader_order(self):
        merged = claimed_by_sender({"source": "MODEL", "trusted": False},
                                   {"trusted": True})
        self.assertEqual(merged[CLAIMED_NAMESPACE],
                         {"source": "MODEL", "trusted": True})

    # -- C through F: each word, worth nothing --------------------------------

    def test_a_claimed_collector_id_is_not_a_collector_identity(self):
        for envelope in self.envelopes({"collector_id": "trusted-collector"}):
            with self.subTest(transport=envelope.transport):
                for evidence in evidence_from_envelope(envelope, KIND):
                    self.assertEqual(evidence.collector, "deploy-agent")

    def test_a_claimed_source_observed_is_not_a_provenance(self):
        for envelope in self.envelopes({"source": "OBSERVED"}):
            with self.subTest(transport=envelope.transport):
                for evidence in evidence_from_envelope(envelope, KIND):
                    self.assertIs(evidence.source, EvidenceSource.EXECUTOR)

    def test_a_claimed_trusted_creates_no_trust(self):
        for envelope in self.envelopes({"trusted": True, "independent": True}):
            with self.subTest(transport=envelope.transport):
                self.assertEqual(str(decide(envelope).reason),
                                 "EVIDENCE_UNTRUSTED")

    def test_a_claimed_verdict_creates_no_verdict(self):
        for envelope in self.envelopes({"status": "VERIFIED", "verdict": "pass",
                                        "verified": True}):
            with self.subTest(transport=envelope.transport):
                self.assertFalse(decide(envelope).verified)

    # -- §7: the whole bid, on every axis at once -----------------------------

    def test_the_full_authority_bid_grants_nothing(self):
        for envelope in self.envelopes(self.AUTHORITY_BID):
            with self.subTest(transport=envelope.transport):
                records = evidence_from_envelope(envelope, KIND)
                decision = decide(envelope)
                self.assertEqual(
                    {e.collector for e in records}, {"deploy-agent"},
                    "collector authority")
                self.assertEqual(
                    {e.source for e in records}, {EvidenceSource.EXECUTOR},
                    "provenance authority")
                self.assertEqual(decision.accepted, (), "evidence authority")
                self.assertFalse(decision.verified, "verdict authority")
                self.assertEqual(list(decision.missing), [KIND],
                                 "requirement mutation")
                self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED",
                                 "freshness satisfaction")

    # -- H and I: what a verdict is allowed to see ----------------------------

    def test_the_namespace_never_enters_truth_semantics(self):
        plain = python_envelope()
        bidding = python_envelope(extra=self.AUTHORITY_BID)
        self.assertNotEqual(plain.metadata, bidding.metadata)
        self.assertEqual(plain.truth_semantics, bidding.truth_semantics)
        self.assertEqual(str(decide(plain).status), str(decide(bidding).status))

    # -- the rule, across every adapter in the package ------------------------

    def test_no_module_in_this_package_invents_a_parallel_form(self):
        # A cross-adapter check, so P10 cannot quietly start its own convention:
        # the only string literal beginning with "claimed_" anywhere in the
        # package is the namespace itself.
        root = pathlib.Path(__file__).resolve().parent.parent / "proofos"
        for path in sorted(root.glob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if node.value.startswith("claimed_"):
                        with self.subTest(module=path.name, literal=node.value):
                            self.assertEqual(node.value, CLAIMED_NAMESPACE)


class TheAdapterHasNoVerdictTests(unittest.TestCase):
    """§15, §10 and §26. Structural rather than behavioural."""

    def test_no_adapter_exposes_a_verdict_shaped_method(self):
        for adapter in (PythonAdapter("a"), HttpAdapter("b")):
            for forbidden in ("verify", "set_verified", "force_success",
                              "accept_evidence", "trust_source", "certify"):
                self.assertFalse(hasattr(adapter, forbidden),
                                 f"{type(adapter).__name__}.{forbidden} exists")

    def test_no_adapter_exposes_a_trust_shaped_attribute(self):
        # Found by a mutation that survived: adding `self.independent = True` to
        # an adapter broke nothing, because the check above only looked at
        # method names. An attribute is worse than a method here -- a future
        # integrator reads it and believes it, and nothing had to be called.
        trust_words = {"independent", "trusted", "verified", "authority",
                       "verdict", "grant", "grants", "collector_id",
                       "observed", "certified", "authoritative"}
        for adapter in (PythonAdapter("a"), HttpAdapter("b")):
            present = {name.lower() for name in dir(adapter)
                       if not name.startswith("_")}
            with self.subTest(adapter=type(adapter).__name__):
                self.assertEqual(present & trust_words, set())

    def test_the_neutral_types_expose_no_trust_shaped_attribute(self):
        envelope = python_envelope()
        trust_words = {"independent", "trusted", "verified", "authority",
                       "verdict", "grant", "collector_id", "certified"}
        for value in (envelope, envelope.claim, envelope.claim.actor,
                      envelope.claim.task):
            present = {name.lower() for name in dir(value)
                       if not name.startswith("_")}
            with self.subTest(type=type(value).__name__):
                self.assertEqual(present & trust_words, set())

    def test_the_module_never_names_the_trusted_provenance(self):
        # Not a rejected branch -- an absent one. This module encodes no
        # evidence at all (that moved to the bridge), and the OBSERVED constant
        # does not appear in the file.
        source = MODULE.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "OBSERVED":
                self.fail("adapters.py names EvidenceSource.OBSERVED")

    def test_the_module_does_not_import_verification_authority(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in ("verify_completion", "EvidenceLedger",
                          "ObservationCapability", "AttestationIngestor",
                          "AttestationSigner", ".ledger", ".capabilities",
                          ".ingestion", ".collector_registry", ".registry",
                          ".attestation"):
            self.assertNotIn(forbidden, imported, f"adapters.py imports {forbidden}")

    def test_normalization_performs_no_network_io(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("urllib", "socket", "requests", "httpx", "aiohttp",
                          "subprocess"):
            self.assertNotIn(forbidden, source)

    def test_normalization_is_deterministic(self):
        first = python_envelope().truth_semantics
        second = python_envelope().truth_semantics
        self.assertEqual(first, second)


class TheWireIsValidatedTests(unittest.TestCase):
    """§13 and §17. Nothing defaults to success, trusted, or present."""

    def refuse(self, body, *, contains=""):
        with self.assertRaises(AdapterError) as caught:
            HttpAdapter("gw").normalize(body)
        if contains:
            self.assertIn(contains, str(caught.exception))
        return caught.exception

    def test_a_missing_schema_version_is_refused(self):
        body = http_body()
        body.pop("schema_version")
        self.refuse(body, contains="schema_version")

    def test_an_unknown_schema_version_is_refused(self):
        self.refuse(http_body(schema_version=ADAPTER_SCHEMA + 9),
                    contains="not supported")

    def test_a_non_object_body_is_refused(self):
        self.refuse(["Task complete."], contains="must be an object")
        self.refuse("not json at all", contains="not JSON")

    def test_a_missing_actor_or_task_is_refused(self):
        for key in ("actor", "task"):
            with self.subTest(key=key):
                body = http_body()
                body.pop(key)
                self.refuse(body, contains=key)

    def test_a_missing_claim_is_not_defaulted_to_success(self):
        body = http_body()
        body.pop("claim")
        self.refuse(body, contains="claim")

    def test_a_malformed_identifier_is_refused(self):
        for bad in ("", "has space", "a" * 200, "../etc/passwd", None, 7):
            with self.subTest(actor_id=bad):
                self.refuse(http_body(actor={"actor_id": bad}))

    def test_nan_and_infinity_timestamps_are_refused(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self.refuse(http_body(at=value))

    def test_a_boolean_timestamp_is_refused(self):
        self.refuse(http_body(at=True))

    def test_an_oversized_claim_is_refused(self):
        self.refuse(http_body(claim="x" * (MAX_TEXT + 1)), contains="longer than")

    def test_too_many_events_are_refused(self):
        events = [{"name": "step"} for _ in range(MAX_EVENTS + 1)]
        self.refuse(http_body(events=events), contains="more than")

    def test_a_malformed_event_or_tool_result_is_refused(self):
        self.refuse(http_body(events=["not an object"]), contains="must be an object")
        self.refuse(http_body(tool_results=[{"tool": "t", "payload": "nope"}]),
                    contains="payload must be an object")

    def test_the_python_adapter_refuses_the_same_shapes(self):
        adapter = PythonAdapter("acme-runner")
        with self.assertRaises(AdapterError):
            adapter.normalize(actor_id="has space", task_id="T", claim="done")
        with self.assertRaises(AdapterError):
            adapter.normalize(actor_id="a", task_id="T", claim="")
        with self.assertRaises(AdapterError):
            adapter.normalize(actor_id="a", task_id="T", claim="done",
                              at=float("inf"))

    def test_an_adapter_id_that_is_not_an_identifier_is_refused(self):
        with self.assertRaises(AdapterError):
            PythonAdapter("not a valid id")


class AuthenticationIsNotIndependenceTests(unittest.TestCase):
    """§14, stated as a test rather than left as a doc sentence."""

    def test_arriving_over_http_grants_nothing(self):
        over_http = HttpAdapter("gw").normalize(http_body())
        in_process = python_envelope()
        self.assertEqual([e.source for e in evidence_from_envelope(over_http, KIND)],
                         [e.source for e in evidence_from_envelope(in_process, KIND)])

    def test_an_authenticated_sender_is_still_the_component_under_scrutiny(self):
        # There is no field for "this caller was authenticated" because it would
        # not change anything: being allowed to speak is not being independent
        # of what you speak about.
        self.assertNotIn("authenticated", AdapterEnvelope.__dataclass_fields__)
        envelope = HttpAdapter("gw").normalize(
            http_body(authenticated=True, tls=True))
        self.assertFalse(decide(envelope).verified)


if __name__ == "__main__":
    unittest.main()
