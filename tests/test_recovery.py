"""Recovery-loop integration tests.

These exercise the real ledger, the real verifier, and the real ADK tool
function. Only the live model call is substituted, so the orchestration and the
verification decision are genuinely under test.
"""

import asyncio
import functools
import unittest

from proofos_agent import scenario
from proofos_agent.agent import LEDGER, verify_task_completion
from proofos_agent.recovery import Turn, run_verification_loop


def run(coro):
    return asyncio.run(coro)


async def compliant_agent_turn(attempt: int) -> Turn:
    """Stands in for a model that obeys its instruction and calls the tool."""
    turn = Turn(attempt=attempt)
    args = {"task_id": scenario.TASK_ID, "claim": scenario.WORKER_CLAIM}
    turn.tool_calls.append({"name": "verify_task_completion", "args": args})
    result = verify_task_completion(**args)
    turn.tool_results.append(result)
    turn.final_text = result["status"]
    return turn


async def self_certifying_agent_turn(attempt: int) -> Turn:
    """Stands in for a model that skips the tool and asserts success itself."""
    return Turn(attempt=attempt, final_text="All done, I am confident it works.")


class RecoveryLoopTests(unittest.TestCase):
    def setUp(self):
        LEDGER.reset()
        scenario.seed_incomplete_evidence(LEDGER)
        self.collectors = {
            kind: functools.partial(collect, LEDGER)
            for kind, collect in scenario.COLLECTORS.items()
        }

    def test_abstains_then_verifies_after_recovery(self):
        outcome = run(
            run_verification_loop(compliant_agent_turn, self.collectors, max_attempts=2)
        )
        self.assertEqual(outcome["final_status"], "VERIFIED")

        first, second = outcome["attempts"]
        self.assertEqual(first["verifier_decision"]["status"], "ABSTAIN")
        self.assertEqual(first["verifier_decision"]["missing"], ["runtime"])
        self.assertEqual(second["verifier_decision"]["status"], "VERIFIED")

    def test_terminates_when_no_collector_exists_for_missing_evidence(self):
        outcome = run(
            run_verification_loop(compliant_agent_turn, {}, max_attempts=3)
        )
        self.assertEqual(outcome["final_status"], "ABSTAIN")
        self.assertIn("No collector available", outcome["terminal_reason"])
        self.assertEqual(len(outcome["attempts"]), 1)

    def test_retry_budget_is_bounded(self):
        # A collector that cannot actually obtain the evidence must not loop forever.
        noop = {"runtime": lambda: None}
        outcome = run(
            run_verification_loop(compliant_agent_turn, noop, max_attempts=3)
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
        from proofos_agent.run_demo import CredentialsMissingError, preflight

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
