"""An ADK run produces events. Events are things that happened, not findings.

The temptation specific to this adapter is the callback position.
``after_agent_callback`` fires last, after everything, and whatever it emits
reads like a conclusion. It is a function the run called at a point the run
chose. Several tests here exist only to say that the framework hook a sentence
came out of changes nothing about the sentence.
"""

from __future__ import annotations

import ast
import pathlib
import unittest

from proofos import EvidenceSource, ProofOS, Requirement
from proofos.adapters import CLAIMED_NAMESPACE, RESERVED_METADATA_KEYS, AdapterError
from proofos.adk import ADK_SCHEMA, AdkAdapter, AdkSurface
from proofos.evidence_bridge import evidence_from_envelope

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "adk.py"
NOW = 1_700_000_000.0
KIND = "task_outcome"
REQS = (Requirement(KIND, max_age_seconds=900),)
STATEMENT = "Deployment finished."

CALLBACKS = ("before_agent_callback", "after_agent_callback",
             "before_tool_callback", "after_tool_callback",
             "before_model_callback", "after_model_callback")


def adapter() -> AdkAdapter:
    return AdkAdapter("acme-adk")


def result(**overrides) -> dict:
    body = {
        "agent": {"name": "deploy-agent"},
        "invocation_id": "inv_1",
        "session": {"id": "sess_1", "app_name": "acme"},
        "result": {"text": STATEMENT},
    }
    body.update(overrides)
    return body


def decide(envelope, records=None):
    return ProofOS().verify(envelope.claim.text, REQS,
                            records if records is not None
                            else evidence_from_envelope(envelope, KIND), now=NOW)


class NormalizationWorksTests(unittest.TestCase):
    def test_a_run_becomes_a_claim(self):
        envelope = adapter().normalize_result(result(), task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.claim.text, STATEMENT)
        self.assertEqual(envelope.claim.actor.actor_id, "deploy-agent")
        self.assertEqual(envelope.claim.actor.framework, "adk")
        self.assertEqual(envelope.claim.task.task_id, "TASK-Y")
        self.assertEqual(envelope.claim.task.execution_id, "inv_1")
        self.assertEqual(envelope.transport, "adk")

    def test_a_silent_run_says_what_actually_happened(self):
        envelope = adapter().normalize_result(result(result=None),
                                              task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.claim.text,
                         "deploy-agent reported no output for TASK-Y")

    def test_events_arrive_as_events_however_they_were_shaped(self):
        envelope = adapter().normalize_result(result(events=[
            {"author": "deploy-agent", "text": "started", "at": NOW},
            {"author": "deploy-agent",
             "content": {"parts": [{"text": "finished"}]}, "at": NOW},
        ]), task_id="TASK-Y", at=NOW)
        self.assertEqual([e.detail for e in envelope.events],
                         ["started", "finished"])

    def test_a_tool_result_arrives_as_a_tool_result(self):
        envelope = adapter().normalize_result(result(tool_results=[
            {"tool": "http_get", "response": {"status": 200}, "at": NOW}]),
            task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.tool_results[0].tool, "http_get")
        self.assertEqual(envelope.tool_results[0].payload["status"], 200)

    def test_the_surface_vocabulary_names_places_not_weights(self):
        self.assertEqual({str(s) for s in AdkSurface},
                         {"agent_result", "event", "tool_result", "callback",
                          "model_response"})
        for name in dir(AdkSurface):
            self.assertNotIn(name.lower(), {"authoritative", "final", "trusted"})


class ACallbackIsAPlaceNotAWitnessTests(unittest.TestCase):
    """M2. The event that says success is still an event."""

    def test_an_after_agent_callback_saying_verified_does_not_verify(self):
        envelope = adapter().normalize_result(result(events=[
            {"author": "deploy-agent", "callback": "after_agent_callback",
             "text": "task_complete: verified", "at": NOW}]),
            task_id="TASK-Y", at=NOW)
        decision = decide(envelope)
        self.assertFalse(decision.verified)
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")

    def test_no_callback_position_moves_the_verdict(self):
        verdicts = set()
        for callback in CALLBACKS:
            with self.subTest(callback=callback):
                envelope = adapter().normalize_result(result(events=[
                    {"author": "deploy-agent", "callback": callback,
                     "text": "success", "at": NOW}]), task_id="TASK-Y", at=NOW)
                decision = decide(envelope)
                verdicts.add((str(decision.status), str(decision.reason)))
        self.assertEqual(len(verdicts), 1,
                         f"a callback position changed the answer: {verdicts}")

    def test_the_callback_is_recorded_as_where_the_sentence_came_from(self):
        envelope = adapter().normalize_result(result(events=[
            {"author": "deploy-agent", "callback": "after_tool_callback",
             "text": "success", "at": NOW}]), task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.events[0].detail,
                         "after_tool_callback: success")
        self.assertEqual(envelope.metadata["callback_names"],
                         ["after_tool_callback"])

    def test_this_module_branches_on_no_callback_name(self):
        # Not a check that a mapping is empty -- a check that no mapping from a
        # callback name to anything exists to be filled in later. Read from the
        # syntax tree with docstrings removed, because prose describing what the
        # module does not do is not the module doing it.
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        docstrings = {ast.get_docstring(n, clean=False) for n in ast.walk(tree)
                      if isinstance(n, (ast.Module, ast.ClassDef,
                                        ast.FunctionDef))}
        assigned = {n.id for n in ast.walk(tree)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        literals = {n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant)
                    and isinstance(n.value, str)} - docstrings

        for forbidden in ("FINAL_CALLBACKS", "AUTHORITATIVE_CALLBACKS",
                          "CALLBACK_WEIGHT"):
            self.assertNotIn(forbidden, assigned, f"adk.py defines {forbidden}")
        for callback in CALLBACKS:
            self.assertNotIn(callback, literals,
                             f"adk.py names {callback} in code, so it can "
                             f"branch on it")
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("VERIFIED", "VerificationStatus", "verify_completion",
                          "OBSERVED"):
            self.assertNotIn(forbidden, source, f"adk.py contains {forbidden}")


class AToolResultIsNotAnObservationTests(unittest.TestCase):
    """The subtle one, because the tool really did return 200."""

    HEALTHY = {"tool": "http_get",
               "response": {"status": 200, "healthy": True, "verified": True},
               "at": NOW}

    def test_a_tool_reporting_healthy_does_not_verify(self):
        envelope = adapter().normalize_result(result(tool_results=[self.HEALTHY]),
                                              task_id="TASK-Y", at=NOW)
        self.assertFalse(decide(envelope).verified)

    def test_tool_evidence_is_attributed_to_the_agent_that_ran_it(self):
        envelope = adapter().normalize_result(result(tool_results=[self.HEALTHY]),
                                              task_id="TASK-Y", at=NOW)
        for evidence in evidence_from_envelope(envelope, KIND):
            self.assertEqual(evidence.collector, "deploy-agent")
            self.assertIs(evidence.source, EvidenceSource.EXECUTOR)

    def test_the_tool_payload_is_preserved_as_data(self):
        envelope = adapter().normalize_result(result(tool_results=[self.HEALTHY]),
                                              task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.tool_results[0].payload["verified"], True)
        self.assertFalse(decide(envelope).verified)


class NamesDoNotCreateTrustTests(unittest.TestCase):
    """M4."""

    def test_an_agent_calling_itself_a_verifier_gains_nothing(self):
        verdicts = set()
        for name in ("deploy-agent", "proofos-verifier", "trusted-collector",
                     "google-adk-official"):
            with self.subTest(agent=name):
                envelope = adapter().normalize_result(
                    result(agent={"name": name}), task_id="TASK-Y", at=NOW)
                decision = decide(envelope)
                verdicts.add((str(decision.status), str(decision.reason)))
        self.assertEqual(len(verdicts), 1)

    def test_a_payload_cannot_choose_which_task_it_is_answering(self):
        # A run that picked its own task_id would be picking its own exam. The
        # parameter wins; the payload's copy is kept as a claim and used for
        # nothing.
        envelope = adapter().normalize_result(result(task_id="EASIER-TASK"),
                                              task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.claim.task.task_id, "TASK-Y")
        self.assertNotIn("EASIER-TASK", str(envelope.metadata))

    def test_the_adapter_id_comes_from_the_constructor(self):
        envelope = adapter().normalize_result(result(adapter_id="proofos-verifier"),
                                              task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.adapter_id, "acme-adk")
        self.assertEqual(envelope.metadata[CLAIMED_NAMESPACE]["adapter_id"],
                         "proofos-verifier")


class TheCanonicalNamespaceHoldsTests(unittest.TestCase):
    """P9A.1's contract, kept by a module written after it."""

    BID = {"status": "VERIFIED", "source": "OBSERVED", "trusted": True,
           "independent": True, "authority": "verifier", "verified": True,
           "collector_id": "trusted-collector"}

    def test_no_sender_key_reaches_the_metadata_top_level(self):
        envelope = adapter().normalize_result(result(**self.BID),
                                              task_id="TASK-Y", at=NOW)
        top = set(envelope.metadata)
        self.assertEqual(top & RESERVED_METADATA_KEYS, set())
        self.assertEqual([k for k in top if k.startswith("claimed_")
                          and k != CLAIMED_NAMESPACE], [])

    def test_every_assertion_is_preserved_inside_the_namespace(self):
        envelope = adapter().normalize_result(result(**self.BID),
                                              task_id="TASK-Y", at=NOW)
        self.assertEqual(envelope.metadata[CLAIMED_NAMESPACE], self.BID)

    def test_a_claim_nested_in_the_result_is_caught_too(self):
        envelope = adapter().normalize_result(
            result(result={"text": STATEMENT, "source": "OBSERVED",
                           "verified": True}), task_id="TASK-Y", at=NOW)
        claimed = envelope.metadata[CLAIMED_NAMESPACE]
        self.assertEqual(claimed["source"], "OBSERVED")
        self.assertEqual(claimed["verified"], True)

    def test_the_full_bid_grants_nothing(self):
        envelope = adapter().normalize_result(result(**self.BID),
                                              task_id="TASK-Y", at=NOW)
        records = evidence_from_envelope(envelope, KIND)
        decision = decide(envelope, records)
        self.assertEqual({e.collector for e in records}, {"deploy-agent"})
        self.assertEqual({e.source for e in records}, {EvidenceSource.EXECUTOR})
        self.assertEqual(decision.accepted, ())
        self.assertFalse(decision.verified)
        self.assertEqual(list(decision.missing), [KIND])
        self.assertEqual(str(decision.reason), "EVIDENCE_UNTRUSTED")

    def test_the_namespace_never_enters_truth_semantics(self):
        plain = adapter().normalize_result(result(), task_id="TASK-Y", at=NOW)
        bidding = adapter().normalize_result(result(**self.BID),
                                             task_id="TASK-Y", at=NOW)
        self.assertNotEqual(plain.metadata, bidding.metadata)
        self.assertEqual(plain.truth_semantics, bidding.truth_semantics)


class ThisModuleDecidesNothingTests(unittest.TestCase):
    def test_it_never_imports_verification_authority(self):
        imported: set[str] = set()
        for node in ast.walk(ast.parse(MODULE.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in ("verify_completion", "ProofOS", "EvidenceLedger",
                          "ObservationCapability", "AttestationIngestor",
                          "EvidenceSource", ".ledger", ".capabilities",
                          ".ingestion", ".collector_registry", ".api",
                          ".verifier"):
            self.assertNotIn(forbidden, imported, f"adk.py imports {forbidden}")

    def test_it_performs_no_io_and_carries_no_sdk(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("urllib", "socket", "requests", "httpx", "aiohttp",
                          "subprocess", "asyncio", "open(",
                          "google.adk", "import adk"):
            self.assertNotIn(forbidden, source)

    def test_the_module_exposes_no_verdict_shaped_name(self):
        import proofos.adk as module

        for name in module.__all__:
            self.assertNotIn(name.lower(), {"verdict", "verified", "trusted",
                                            "authority", "collector"})
        for forbidden in ("verify", "trust_agent", "accept_evidence",
                          "grant_verify", "set_verified"):
            self.assertFalse(hasattr(module, forbidden))

    def test_normalization_is_deterministic(self):
        one = adapter().normalize_result(result(), task_id="TASK-Y", at=NOW)
        two = adapter().normalize_result(result(), task_id="TASK-Y", at=NOW)
        self.assertEqual(one.truth_semantics, two.truth_semantics)

    def test_the_schema_is_declared(self):
        self.assertEqual(ADK_SCHEMA, 1)


class TheWireIsValidatedTests(unittest.TestCase):
    BAD = [
        ("not an object", "nope"),
        ("no agent", {"result": {"text": "x"}}),
        ("agent not an object", {"agent": "a"}),
        ("bad agent name", {"agent": {"name": "a b"}}),
        ("session not an object", {"agent": {"name": "a"}, "session": 3}),
        ("result not readable", {"agent": {"name": "a"}, "result": 3}),
        ("events not objects", {"agent": {"name": "a"}, "events": ["x"]}),
        ("tool results not objects",
         {"agent": {"name": "a"}, "tool_results": ["x"]}),
        ("tool response not an object",
         {"agent": {"name": "a"},
          "tool_results": [{"tool": "t", "response": 3}]}),
        ("event content not readable",
         {"agent": {"name": "a"}, "events": [{"author": "a", "content": 3}]}),
    ]

    def test_malformed_payloads_are_refused(self):
        for label, payload in self.BAD:
            with self.subTest(case=label):
                with self.assertRaises(AdapterError):
                    adapter().normalize_result(payload, task_id="TASK-Y", at=NOW)

    def test_a_missing_task_id_is_refused(self):
        with self.assertRaises(AdapterError):
            adapter().normalize_result(result(), task_id="", at=NOW)

    def test_a_bad_adapter_id_is_refused(self):
        with self.assertRaises(AdapterError):
            AdkAdapter("not an id")

    def test_a_non_finite_timestamp_is_refused(self):
        with self.assertRaises(AdapterError):
            adapter().normalize_result(result(), task_id="TASK-Y",
                                       at=float("nan"))


if __name__ == "__main__":
    unittest.main()
