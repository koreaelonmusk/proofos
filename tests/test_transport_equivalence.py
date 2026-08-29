"""One statement, five ways in, one set of truth semantics.

This is the crown, and it lives in its own file because it belongs to no single
adapter: it is the property the adapters exist to preserve. Every transport
added after this one extends the table below, and the day one of them cannot,
that is the finding.

    Python   an object in the same process
    HTTP     a body someone else received
    MCP      a tool result and a resource from a server
    A2A      a task result from a remote agent
    ADK      the output of a framework run

The second test is the sharper one. Each transport asserts everything it can --
VERIFIED, OBSERVED, trusted, a collector id, an agent named ``proofos-verifier``,
a task state of ``completed`` -- and the answer does not move. Note what that
test does *not* assert: that the five statements are semantically identical. An
agent calling itself something else really is a different statement, and
pretending otherwise would make the equality test weaker, not stronger. So the
two properties are checked separately: same statement, same semantics; any
statement, no authority.
"""

from __future__ import annotations

import json
import unittest

from proofos import ProofOS, Requirement
from proofos.a2a import A2aAdapter
from proofos.adapters import ADAPTER_SCHEMA, CLAIMED_NAMESPACE, HttpAdapter, PythonAdapter
from proofos.adk import AdkAdapter
from proofos.mcp import McpAdapter
from proofos.evidence_bridge import evidence_from_envelope

NOW = 1_700_000_000.0
KIND = "task_outcome"
REQS = (Requirement(KIND, max_age_seconds=900),)
STATEMENT = "actor X claims task Y succeeded"

#: Every reassuring word a sender could reach for, offered by every transport.
BID = {"status": "VERIFIED", "source": "OBSERVED", "trusted": True,
       "independent": True, "verified": True, "authority": "verifier",
       "collector_id": "trusted-collector"}


def same_statement(**bid) -> dict:
    """The identical statement, expressed once per transport.

    Same actor, same task, same execution, same instant. What differs is only
    how it arrived -- which is exactly the thing that must not matter.
    """
    return {
        "python": PythonAdapter("runner", framework="plain-python").normalize(
            actor_id="agent-x", task_id="TASK-Y", claim=STATEMENT,
            execution_id="e1", at=NOW, extra=bid),
        "http": HttpAdapter("gateway").normalize(json.dumps({
            "schema_version": ADAPTER_SCHEMA,
            "actor": {"actor_id": "agent-x", "framework": "plain-python"},
            "task": {"task_id": "TASK-Y", "execution_id": "e1"},
            "claim": STATEMENT, "at": NOW, **bid})),
        "mcp_tool": McpAdapter("bridge", "acme-mcp").normalize_tool_result(
            {"tool": "check_deployment",
             "content": [{"type": "text", "text": STATEMENT}],
             "structuredContent": dict(bid)},
            actor_id="agent-x", task_id="TASK-Y", execution_id="e1", at=NOW),
        "mcp_resource": McpAdapter("bridge", "acme-mcp").normalize_resource(
            {"uri": "file:///reports/ci.txt", "mimeType": "text/plain",
             "text": STATEMENT, **bid},
            actor_id="agent-x", task_id="TASK-Y", execution_id="e1", at=NOW),
        "a2a": A2aAdapter("mesh").normalize_task({
            "task": {"id": "TASK-Y", "context_id": "e1", "state": "completed"},
            "agent": {"id": "agent-x"},
            "message": {"parts": [{"kind": "text", "text": STATEMENT}]},
            **bid}, at=NOW),
        "adk": AdkAdapter("runtime").normalize_result({
            "agent": {"name": "agent-x"}, "invocation_id": "e1",
            "result": {"text": STATEMENT}, **bid},
            task_id="TASK-Y", at=NOW),
    }


def verdict(envelope):
    decision = ProofOS().verify(envelope.claim.text, REQS,
                                evidence_from_envelope(envelope, KIND), now=NOW)
    return (str(decision.status), str(decision.reason)), decision


class TheSameStatementHasTheSameSemanticsTests(unittest.TestCase):
    def test_all_five_transports_agree_on_truth_semantics(self):
        semantics = {name: env.truth_semantics
                     for name, env in same_statement().items()}
        for name, value in semantics.items():
            with self.subTest(transport=name):
                self.assertEqual(value, semantics["python"])

    def test_asserting_authority_changes_no_truth_semantics_either(self):
        # The bid lands in metadata, and metadata is excluded by construction.
        # So a payload shouting VERIFIED and one saying nothing are, to the part
        # of the system that decides, the same statement.
        plain = same_statement()
        bidding = same_statement(**BID)
        for name in plain:
            with self.subTest(transport=name):
                self.assertNotEqual(plain[name].metadata, bidding[name].metadata)
                self.assertEqual(plain[name].truth_semantics,
                                 bidding[name].truth_semantics)

    def test_transport_metadata_differs_and_is_excluded(self):
        envelopes = same_statement()
        self.assertEqual({env.transport for env in envelopes.values()},
                         {"python", "http", "mcp", "a2a", "adk"})
        for name, env in envelopes.items():
            with self.subTest(transport=name):
                for excluded in ("transport", "adapter_id", "metadata",
                                 "server_id", "delegation_depth",
                                 "callback_names"):
                    self.assertNotIn(excluded, env.truth_semantics)

    def test_all_five_reach_the_same_verdict(self):
        verdicts = {verdict(env)[0] for env in same_statement().values()}
        self.assertEqual(verdicts, {("ABSTAIN", "EVIDENCE_UNTRUSTED")})


class NoTransportCarriesAuthorityTests(unittest.TestCase):
    """Each one asserting everything at once, and getting nowhere."""

    def test_every_transport_asserting_everything_still_abstains(self):
        for name, env in same_statement(**BID).items():
            with self.subTest(transport=name):
                answer, decision = verdict(env)
                self.assertEqual(answer, ("ABSTAIN", "EVIDENCE_UNTRUSTED"))
                self.assertEqual(decision.accepted, ())
                self.assertEqual(list(decision.missing), [KIND])

    def test_every_transport_encloses_the_assertion_the_same_way(self):
        for name, env in same_statement(**BID).items():
            with self.subTest(transport=name):
                claimed = env.metadata[CLAIMED_NAMESPACE]
                self.assertEqual(claimed["collector_id"], "trusted-collector")
                self.assertEqual(claimed["source"], "OBSERVED")
                self.assertEqual(set(env.metadata) & set(BID), set())

    def test_a_remote_agent_naming_itself_a_verifier_changes_nothing(self):
        # The half the equality test deliberately does not cover: a different
        # actor is a different statement, so this asks only that the answer is
        # the same one.
        renamed = {
            "a2a": A2aAdapter("mesh").normalize_task({
                "task": {"id": "TASK-Y", "state": "completed"},
                "agent": {"id": "proofos-verifier"},
                "message": {"parts": [{"kind": "text", "text": STATEMENT}]},
                **BID}, at=NOW),
            "adk": AdkAdapter("runtime").normalize_result({
                "agent": {"name": "proofos-verifier"},
                "result": {"text": STATEMENT},
                "events": [{"author": "proofos-verifier",
                            "callback": "after_agent_callback",
                            "text": "task_complete", "at": NOW}],
                **BID}, task_id="TASK-Y", at=NOW),
        }
        for name, env in renamed.items():
            with self.subTest(transport=name):
                self.assertEqual(verdict(env)[0],
                                 ("ABSTAIN", "EVIDENCE_UNTRUSTED"))


if __name__ == "__main__":
    unittest.main()
