"""Bounded retries for temporary Gemini transport failures."""

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from proofos_agent.gemini_runner import GeminiAdkTurnRunner, _is_transient_server_error


class ServerError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(f"{status_code} provider error")


class FlakyRunner:
    def __init__(self, failures):
        self.failures = failures
        self.calls = 0

    async def run_async(self, **_kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise ServerError(503)
        if False:
            yield None


class TransientGeminiRetryTests(unittest.TestCase):
    def test_only_retryable_server_statuses_are_classified_transient(self):
        for status in (500, 502, 503, 504):
            self.assertTrue(_is_transient_server_error(ServerError(status)))
        for status in (400, 401, 403, 404):
            self.assertFalse(_is_transient_server_error(ServerError(status)))

    def test_503_is_retried_twice_then_succeeds(self):
        runner = GeminiAdkTurnRunner.__new__(GeminiAdkTurnRunner)
        runner._model = "test-model"
        runner._pace = AsyncMock()
        flaky = FlakyRunner(failures=2)
        runner._session_for = AsyncMock(return_value=(flaky, "session"))

        with patch("proofos_agent.gemini_runner.asyncio.sleep", new=AsyncMock()) as sleep:
            turn = asyncio.run(runner._run("verifier", object(), "verifier-v1", "verify"))

        self.assertEqual(flaky.calls, 3)
        self.assertEqual(turn.error, "")
        self.assertEqual([call.args[0] for call in sleep.await_args_list], [5.0, 10.0])


if __name__ == "__main__":
    unittest.main()
