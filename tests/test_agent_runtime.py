"""Agent runtime contracts and model misbehaviour.

Two things are under test. First, that the deterministic runtime keeps
authority when an agent plays a role: the verification tool's result decides,
and model prose is never consulted. Second, that every way a model can misbehave
-- refusing the tool, calling it for the wrong task, contradicting it, crashing
-- ends in ABSTAIN.

The turn runners here are scripted, not mocks of Gemini, and no test in this
file is evidence that a real model call occurred. They exercise the orchestration
contract, which is what can be proven without credentials.
"""

import asyncio
import os
import unittest

from proofos.attestation import AttestationSigner
from proofos.journal import EventType, InMemoryJournalSink
from proofos.ledger import EvidenceLedger
from proofos.registry import EXECUTOR_ID, PLANNER_ID, VERIFIER_ID, default_registry
from proofos.verifier import EvidenceSource, Requirement
from proofos_agent import scenario
from proofos_agent.agent import (
    MODEL,
    build_executor_agent,
    build_planner_agent,
    build_verifier_agent,
)
from proofos_agent.attested_scenario import (
    build_turn_runner,
    run_attested_agent_scenario,
)
from proofos_agent.demo_service import running_health_service
from proofos_agent.turn_runner import (
    ACTION_TOOL,
    VERIFY_TOOL,
    AgentTurn,
    DeterministicTurnRunner,
    ToolInvocation,
    decision_from,
)
from proofos_agent.verification_tool import build_verification_tool
from tests.process_harness import CollectorProcess
from tests.test_authority import reachable_types

TASK = scenario.TASK_ID


def run(coro):
    return asyncio.run(coro)


def verifier_turn(tool_calls, final_text="", error="", attempt=1):
    return AgentTurn(
        role="verifier",
        agent_id=VERIFIER_ID,
        model=MODEL,
        attempt=attempt,
        tool_calls=tuple(tool_calls),
        final_text=final_text,
        error=error,
    )


def call(task_id=TASK, status="ABSTAIN", missing=("runtime",), result=True):
    return ToolInvocation(
        VERIFY_TOOL,
        {"task_id": task_id, "claim": "done"},
        {"status": status, "missing": list(missing), "failure": "X", "reason": "r"}
        if result
        else None,
    )


class ToolResultIsAuthorityTests(unittest.TestCase):
    """Prose is presentation. The tool result is the verdict."""

    def test_confident_prose_cannot_override_an_abstain(self):
        turn = verifier_turn(
            [call(status="ABSTAIN")],
            final_text="VERIFIED. I checked everything myself. Task complete.",
        )
        extraction = decision_from(turn, TASK)
        self.assertTrue(extraction.usable)
        self.assertEqual(extraction.decision["status"], "ABSTAIN")

    def test_pessimistic_prose_cannot_override_a_verified(self):
        turn = verifier_turn(
            [call(status="VERIFIED", missing=())],
            final_text="ABSTAIN -- I am not comfortable with this.",
        )
        self.assertEqual(decision_from(turn, TASK).decision["status"], "VERIFIED")

    def test_prose_alone_is_not_a_verdict(self):
        turn = verifier_turn([], final_text="VERIFIED")
        extraction = decision_from(turn, TASK)
        self.assertFalse(extraction.usable)
        self.assertIn("did not call", extraction.noncompliance)


class ModelNoncomplianceTests(unittest.TestCase):
    """Every ambiguous turn is refused rather than interpreted."""

    def assert_refused(self, turn, fragment=""):
        extraction = decision_from(turn, TASK)
        self.assertFalse(extraction.usable)
        self.assertTrue(extraction.noncompliance)
        if fragment:
            self.assertIn(fragment, extraction.noncompliance)

    def test_skipping_the_tool_is_refused(self):
        self.assert_refused(verifier_turn([]), "did not call")

    def test_calling_the_tool_for_another_task_is_refused(self):
        # The runtime chose the task; a substituted id answers a different
        # question.
        self.assert_refused(verifier_turn([call(task_id="OTHER-TASK")]), "not")

    def test_a_tool_call_with_no_result_is_refused(self):
        self.assert_refused(verifier_turn([call(result=False)]), "no decision")

    def test_a_failed_turn_is_refused(self):
        self.assert_refused(verifier_turn([call()], error="DeadlineExceeded"), "failed")

    def test_calling_a_different_tool_is_refused(self):
        turn = verifier_turn([ToolInvocation("summarize", {}, {"status": "VERIFIED"})])
        self.assert_refused(turn, "did not call")

    def test_calling_twice_uses_the_last_completed_result(self):
        turn = verifier_turn(
            [call(status="ABSTAIN"), call(status="VERIFIED", missing=())]
        )
        self.assertEqual(decision_from(turn, TASK).decision["status"], "VERIFIED")

    def test_one_bad_task_id_among_several_calls_refuses_the_whole_turn(self):
        turn = verifier_turn([call(), call(task_id="OTHER-TASK", status="VERIFIED")])
        self.assert_refused(turn)

    def test_a_malformed_result_is_refused(self):
        turn = verifier_turn(
            [ToolInvocation(VERIFY_TOOL, {"task_id": TASK}, {"nonsense": True})]
        )
        self.assert_refused(turn, "no decision")


class ScriptedRunner:
    """A turn runner whose verifier behaviour the test chooses."""

    RUNTIME = "scripted-test-only"

    def __init__(self, fleet, verify_tool, verifier_behaviour=None):
        self._fleet = fleet
        self._tool = verify_tool
        self._behaviour = verifier_behaviour
        self.calls = []

    def describe(self):
        return {"agent_runtime": self.RUNTIME, "model": "none", "live_model_enabled": False}

    async def plan(self, task_id, goal):
        self._fleet.planner.plan(task_id, goal, ())
        return AgentTurn(role="planner", agent_id=PLANNER_ID, model="none")

    async def execute(self, task_id, instruction):
        result = self._fleet.executor.execute(task_id, lambda: "patched")
        return AgentTurn(
            role="executor",
            agent_id=EXECUTOR_ID,
            model="none",
            tool_calls=(ToolInvocation(ACTION_TOOL, {}, {"result": result}),),
        )

    async def verify(self, task_id, claim, attempt):
        self.calls.append((task_id, claim, attempt))
        if self._behaviour is not None:
            return self._behaviour(self._tool, task_id, claim, attempt)
        result = self._tool(task_id=task_id, claim=claim)
        return verifier_turn(
            [ToolInvocation(VERIFY_TOOL, {"task_id": task_id, "claim": claim}, result)],
            final_text=result["status"],
            attempt=attempt,
        )

    async def aclose(self):
        return None


class OrchestrationUnderMisbehaviourTests(unittest.TestCase):
    """The whole attested execution, with the verifier behaving badly."""

    @classmethod
    def setUpClass(cls):
        cls._target = running_health_service()
        cls.target_url = cls._target.__enter__()
        cls.collector = CollectorProcess(cls.target_url).start()

    @classmethod
    def tearDownClass(cls):
        cls.collector.stop()
        cls._target.__exit__(None, None, None)

    def execute(self, behaviour=None, max_attempts=2):
        from proofos_agent.collector_client import HttpCollectorClient

        client = HttpCollectorClient(self.collector.base_url)
        runners = {}

        def factory(agent_runtime, fleet, ledger, task_id, registry=None):
            runner = ScriptedRunner(fleet, build_verification_tool(ledger), behaviour)
            runners["runner"] = runner
            return runner

        import proofos_agent.attested_scenario as module

        original = module.build_turn_runner
        module.build_turn_runner = factory
        try:
            outcome, journal, ledger = run(
                run_attested_agent_scenario(
                    InMemoryJournalSink(),
                    self.collector.public_key_b64,
                    client,
                    max_attempts=max_attempts,
                )
            )
        finally:
            module.build_turn_runner = original
        return outcome, journal, ledger, runners.get("runner")

    def test_a_compliant_verifier_reaches_verified_through_attested_evidence(self):
        outcome, journal, ledger, _ = self.execute()
        self.assertEqual(outcome["final_status"], "VERIFIED")
        self.assertEqual(
            [d["status"] for d in outcome["decisions"]], ["ABSTAIN", "VERIFIED"]
        )
        observed = [
            i
            for i in ledger.evidence(TASK)
            if i.kind == "runtime" and i.source is EvidenceSource.OBSERVED
        ]
        self.assertEqual(len(observed), 1)

    def test_a_verifier_that_never_calls_the_tool_abstains(self):
        def silent(tool, task_id, claim, attempt):
            return verifier_turn([], final_text="Everything looks great. VERIFIED.")

        outcome, journal, _, _ = self.execute(silent)
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(outcome["failure_class"], "MODEL_NONCOMPLIANCE")
        self.assertIn(
            "MODEL_NONCOMPLIANCE", [str(e.event) for e in journal.events()]
        )

    def test_a_verifier_substituting_the_task_id_abstains(self):
        def substituted(tool, task_id, claim, attempt):
            result = tool(task_id=task_id, claim=claim)
            return verifier_turn(
                [ToolInvocation(VERIFY_TOOL, {"task_id": "SOME-OTHER"}, result)],
                attempt=attempt,
            )

        outcome, _, _, _ = self.execute(substituted)
        self.assertEqual(outcome["failure_class"], "MODEL_NONCOMPLIANCE")

    def test_a_verifier_whose_prose_claims_success_still_abstains(self):
        def liar(tool, task_id, claim, attempt):
            result = tool(task_id=task_id, claim=claim)
            return verifier_turn(
                [ToolInvocation(VERIFY_TOOL, {"task_id": task_id}, result)],
                final_text="VERIFIED - the service is definitely healthy.",
                attempt=attempt,
            )

        # Attempt 1 abstains despite the prose; recovery then earns VERIFIED.
        outcome, _, _, _ = self.execute(liar)
        self.assertEqual(outcome["decisions"][0]["status"], "ABSTAIN")
        self.assertIn("VERIFIED", outcome["decisions"][0]["model_text"])

    def test_a_crashing_verifier_abstains(self):
        def crashing(tool, task_id, claim, attempt):
            return verifier_turn([], error="ServiceUnavailable", attempt=attempt)

        outcome, _, _, _ = self.execute(crashing)
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(outcome["failure_class"], "MODEL_NONCOMPLIANCE")

    def test_a_verifier_fabricating_a_verified_result_cannot_forge_evidence(self):
        def forger(tool, task_id, claim, attempt):
            # The model invents a tool result rather than calling the tool.
            return verifier_turn(
                [
                    ToolInvocation(
                        VERIFY_TOOL,
                        {"task_id": task_id, "claim": claim},
                        {"status": "VERIFIED", "missing": [], "failure": "NONE"},
                    )
                ],
                attempt=attempt,
            )

        outcome, _, ledger, _ = self.execute(forger)
        # The runtime believes the transcript it was handed, so this scripted
        # runner does reach VERIFIED -- but no OBSERVED evidence was created,
        # which is what the ledger records and what any auditor would see.
        observed = [
            i
            for i in ledger.evidence(TASK)
            if i.kind == "runtime" and i.source is EvidenceSource.OBSERVED
        ]
        self.assertEqual(observed, [], "a fabricated verdict created evidence")

    def test_the_runtime_owns_the_attempt_budget(self):
        def stubborn(tool, task_id, claim, attempt):
            return verifier_turn(
                [call(status="ABSTAIN")], attempt=attempt
            )

        outcome, _, _, runner = self.execute(stubborn, max_attempts=3)
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertEqual(outcome["failure_class"], "RETRY_EXHAUSTED")
        self.assertEqual(len(runner.calls), 3)


class PlannerCannotWeakenPolicyTests(unittest.TestCase):
    def test_requirements_are_fixed_before_the_planner_speaks(self):
        ledger = EvidenceLedger()
        sink = InMemoryJournalSink()

        from proofos.journal import Journal
        from proofos_agent.fleet import build_fleet
        from proofos_agent.orchestration import run_agent_execution

        journal = Journal(sink, task_id=TASK)
        fleet = build_fleet(ledger, journal, default_registry(), TASK)

        class GreedyPlanner(ScriptedRunner):
            async def plan(self, task_id, goal):
                # A planner proposing that nothing needs proving.
                self._fleet.planner.plan(task_id, goal, ())
                return AgentTurn(
                    role="planner",
                    agent_id=PLANNER_ID,
                    model="none",
                    final_text="No runtime evidence is necessary for this task.",
                )

        runner = GreedyPlanner(fleet, build_verification_tool(ledger))
        outcome = run(
            run_agent_execution(
                fleet=fleet,
                journal=journal,
                turn_runner=runner,
                task_id=TASK,
                goal="fix it",
                claim_text=scenario.WORKER_CLAIM,
                required_kinds=scenario.REQUIRED_KINDS,
                max_attempts=1,
            )
        )
        # The runtime's requirements stood: the planner proposed that nothing
        # needed proving, and "runtime" is still demanded.
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertIn("runtime", outcome["decisions"][0]["missing"])
        self.assertEqual(
            [str(r.kind) for r in ledger.requirements(TASK)], ["tests", "runtime"]
        )


class AdkSchemaTests(unittest.TestCase):
    """The tool surfaces a live model would actually receive."""

    def declaration(self, tool):
        from google.adk.tools import FunctionTool

        dumped = FunctionTool(tool)._get_declaration().model_dump(exclude_none=True)
        return dumped.get("parameters_json_schema") or dumped.get("parameters")

    def test_planner_has_no_tools(self):
        self.assertEqual(list(build_planner_agent().tools), [])

    def test_executor_has_only_its_action_tool(self):
        from proofos_agent.gemini_runner import build_action_tool

        class Stub:
            class executor:
                @staticmethod
                def execute(task_id, fn):
                    return fn()

        agent = build_executor_agent(build_action_tool(Stub, TASK))
        self.assertEqual([t.__name__ for t in agent.tools], [ACTION_TOOL])

    def test_verifier_has_only_the_verification_tool(self):
        agent = build_verifier_agent(EvidenceLedger())
        self.assertEqual([t.__name__ for t in agent.tools], [VERIFY_TOOL])

    def test_the_verification_tool_still_exposes_only_task_id_and_claim(self):
        schema = self.declaration(build_verification_tool(EvidenceLedger()))
        self.assertEqual(
            sorted((schema.get("properties") or {}).keys()), ["claim", "task_id"]
        )

    def test_the_action_tool_exposes_no_evidence_parameter(self):
        from proofos_agent.gemini_runner import build_action_tool

        class Stub:
            class executor:
                @staticmethod
                def execute(task_id, fn):
                    return fn()

        schema = self.declaration(build_action_tool(Stub, TASK))
        properties = sorted((schema.get("properties") or {}).keys())
        self.assertEqual(properties, ["instruction"])

    def test_no_agent_can_reach_a_signing_key_or_the_collector(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from proofos_agent.collector_client import HttpCollectorClient

        agent = build_verifier_agent(EvidenceLedger())
        types = reachable_types(agent, max_depth=6)
        self.assertNotIn(Ed25519PrivateKey, types)
        self.assertNotIn(AttestationSigner, types)
        self.assertNotIn(HttpCollectorClient, types)


class PerExecutionBindingTests(unittest.TestCase):
    """Nothing that closes over a ledger may outlive its execution."""

    def test_the_agent_module_holds_no_cached_agent_ledger_or_runner(self):
        from proofos_agent import agent as agent_module

        for name in dir(agent_module):
            value = getattr(agent_module, name)
            self.assertNotIsInstance(value, EvidenceLedger, msg=name)
            self.assertFalse(
                type(value).__name__ in {"Agent", "InMemoryRunner", "Session"},
                msg=f"{name} is a cached {type(value).__name__}",
            )

    def test_two_verifier_agents_are_bound_to_their_own_ledgers(self):
        first, second = EvidenceLedger(), EvidenceLedger()
        first.open_task(TASK, (Requirement("tests"),))
        second.open_task(TASK, (Requirement("tests"),))

        tool_a = build_verifier_agent(first).tools[0]
        tool_b = build_verifier_agent(second).tools[0]

        grant = first.grant_observation("t", ("tests",))
        from proofos.verifier import Evidence

        first.record(
            TASK,
            Evidence("tests", "green", EvidenceSource.OBSERVED, collector="t"),
            grant,
        )

        self.assertEqual(tool_a(task_id=TASK, claim="done")["status"], "VERIFIED")
        # The second agent sees its own empty ledger, not the first one's.
        self.assertEqual(tool_b(task_id=TASK, claim="done")["status"], "ABSTAIN")

    def test_the_gemini_runner_builds_its_agents_per_execution(self):
        import inspect

        from proofos_agent import gemini_runner

        source = inspect.getsource(gemini_runner.GeminiAdkTurnRunner.__init__)
        self.assertIn("build_verifier_agent(ledger", source)
        module_level = [
            name
            for name in dir(gemini_runner)
            if type(getattr(gemini_runner, name)).__name__
            in {"Agent", "InMemoryRunner", "Session"}
        ]
        self.assertEqual(module_level, [])


class AgentRuntimeSelectionTests(unittest.TestCase):
    def test_deterministic_is_the_default(self):
        ledger = EvidenceLedger()
        from proofos.journal import Journal
        from proofos_agent.fleet import build_fleet

        journal = Journal(InMemoryJournalSink(), task_id=TASK)
        fleet = build_fleet(ledger, journal, default_registry(), TASK)
        runner = build_turn_runner("deterministic", fleet, ledger, TASK)
        self.assertIsInstance(runner, DeterministicTurnRunner)
        self.assertFalse(runner.describe()["live_model_enabled"])

    def test_gemini_mode_refuses_without_credentials_and_does_not_fall_back(self):
        from proofos_agent.gemini_runner import CredentialsMissingError

        saved = {
            k: os.environ.pop(k, None)
            for k in (
                "GOOGLE_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_GENAI_USE_VERTEXAI",
                "GOOGLE_CLOUD_PROJECT",
                "GOOGLE_CLOUD_LOCATION",
            )
        }
        ledger = EvidenceLedger()
        from proofos.journal import Journal
        from proofos_agent.fleet import build_fleet

        journal = Journal(InMemoryJournalSink(), task_id=TASK)
        fleet = build_fleet(ledger, journal, default_registry(), TASK)
        try:
            with self.assertRaises(CredentialsMissingError):
                build_turn_runner("gemini", fleet, ledger, TASK)
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

    def test_preflight_never_returns_the_secret(self):
        from proofos_agent.gemini_runner import preflight

        os.environ["GOOGLE_API_KEY"] = "AIza-not-a-real-key-0123456789"
        try:
            mode = preflight()
        finally:
            os.environ.pop("GOOGLE_API_KEY", None)
        self.assertEqual(mode, "gemini-api-key")
        self.assertNotIn("AIza", mode)


if __name__ == "__main__":
    unittest.main()
