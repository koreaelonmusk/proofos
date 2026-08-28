"""Recovery-loop integration tests.

These exercise the real ledger, the real verifier, and the real ADK tool
function. Only the live model call is substituted, so the orchestration and the
verification decision are genuinely under test.
"""

import asyncio
import functools
import unittest

from proofos_agent import scenario
from proofos.ledger import EvidenceLedger
from proofos_agent.verification_tool import build_verification_tool
from proofos_agent.recovery import Turn, run_verification_loop
from tests.test_probe import send_json, serving


def run(coro):
    return asyncio.run(coro)


def make_compliant_agent_turn(tool):
    """A stand-in for a model that obeys its instruction and calls the tool."""

    async def compliant_agent_turn(attempt: int) -> Turn:
        turn = Turn(attempt=attempt)
        args = {"task_id": scenario.TASK_ID, "claim": scenario.WORKER_CLAIM}
        turn.tool_calls.append({"name": "verify_task_completion", "args": args})
        result = tool(**args)
        turn.tool_results.append(result)
        turn.final_text = result["status"]
        return turn

    return compliant_agent_turn


async def self_certifying_agent_turn(attempt: int) -> Turn:
    """Stands in for a model that skips the tool and asserts success itself."""
    return Turn(attempt=attempt, final_text="All done, I am confident it works.")


class RecoveryLoopTests(unittest.TestCase):
    def setUp(self):
        LEDGER = EvidenceLedger()
        self.LEDGER = LEDGER
        self.verify_task_completion = build_verification_tool(LEDGER)
        self.compliant_agent_turn = make_compliant_agent_turn(self.verify_task_completion)
        scenario.seed_incomplete_evidence(LEDGER)
        self._server = serving(lambda h: send_json(h, 200, {"status": "ok"}))
        self.health_url = self._server.__enter__()
        self.addCleanup(self._server.__exit__, None, None, None)
        # Collectors run the real probe against the live server above.
        self.collectors = {
            kind: functools.partial(collect, self.LEDGER, self.health_url, 5)
            for kind, collect in scenario.COLLECTORS.items()
        }

    def test_abstains_then_verifies_after_recovery(self):
        outcome = run(
            run_verification_loop(self.compliant_agent_turn, self.collectors, max_attempts=2)
        )
        self.assertEqual(outcome["final_status"], "VERIFIED")

        first, second = outcome["attempts"]
        self.assertEqual(first["verifier_decision"]["status"], "ABSTAIN")
        self.assertEqual(first["verifier_decision"]["missing"], ["runtime"])
        self.assertEqual(second["verifier_decision"]["status"], "VERIFIED")

    def test_terminates_when_no_collector_exists_for_missing_evidence(self):
        outcome = run(
            run_verification_loop(self.compliant_agent_turn, {}, max_attempts=3)
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertIn("No collector available", outcome["terminal_reason"])
        self.assertEqual(len(outcome["attempts"]), 1)

    def test_retry_budget_is_bounded(self):
        # A collector probing a dead endpoint must not loop forever.
        from tests.test_probe import closed_port_url

        dead = closed_port_url()
        noop = {
            "runtime": functools.partial(
                scenario.collect_runtime_evidence, self.LEDGER, dead, 2
            )
        }
        outcome = run(
            run_verification_loop(self.compliant_agent_turn, noop, max_attempts=3)
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertIn("RETRY_EXHAUSTED", outcome["terminal_reason"])
        self.assertEqual(len(outcome["attempts"]), 3)

    def test_agent_that_skips_the_verifier_cannot_produce_success(self):
        outcome = run(
            run_verification_loop(
                self_certifying_agent_turn, self.collectors, max_attempts=2
            )
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertIn("did not call the verification tool", outcome["terminal_reason"])


class PreflightTests(unittest.TestCase):
    def test_preflight_refuses_to_run_without_credentials(self):
        import os
        from proofos_agent.gemini_runner import CredentialsMissingError, preflight

        saved = {
            key: os.environ.pop(key, None)
            for key in (
                "GOOGLE_GENAI_USE_VERTEXAI",
                "GOOGLE_API_KEY",
                "GEMINI_API_KEY",
                "GOOGLE_CLOUD_PROJECT",
                "GOOGLE_CLOUD_LOCATION",
            )
        }
        try:
            with self.assertRaises(CredentialsMissingError):
                preflight()
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
