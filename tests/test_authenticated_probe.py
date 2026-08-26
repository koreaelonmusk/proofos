"""Cross-service observation of an IAM-protected target, and the action ceiling.

D17: the collector could only observe anonymous endpoints, so on Cloud Run it
ended up watching its own health endpoint instead of the service under scrutiny.
An observer that can only reach unprotected things is not much of an observer.

The fix gives the collector its own identity. These tests pin the two properties
that make that safe: the token is the collector's, and a token is never
optional-by-accident -- a target that needs one and cannot get one fails rather
than quietly probing anonymously.
"""

import json
import unittest

from proofos.probe import ProbeOutcome, probe_health
from proofos.profiles import CollectionProfile, default_profiles
from proofos_agent.gemini_runner import MAX_ACTION_INVOCATIONS, build_action_tool
from tests.test_probe import send_json, serving


def authed_only(expected_token):
    """A target that answers only when the right bearer token is presented."""

    def responder(handler):
        got = handler.headers.get("Authorization", "")
        if got == f"Bearer {expected_token}":
            send_json(handler, 200, {"status": "ok"})
        else:
            handler.send_error(403, "forbidden")

    return responder


class AuthenticatedProbeTests(unittest.TestCase):
    TOKEN = "test-identity-token"

    def test_an_anonymous_probe_of_a_protected_target_fails(self):
        with serving(authed_only(self.TOKEN)) as url:
            result = probe_health(url, timeout=5)
        self.assertIs(result.outcome, ProbeOutcome.UNHEALTHY_STATUS)
        self.assertEqual(result.status_code, 403)
        self.assertFalse(result.healthy)

    def test_an_authenticated_probe_of_the_same_target_succeeds(self):
        with serving(authed_only(self.TOKEN)) as url:
            result = probe_health(url, timeout=5, auth_token=self.TOKEN)
        self.assertIs(result.outcome, ProbeOutcome.HEALTHY)
        self.assertTrue(result.healthy)
        self.assertEqual(len(result.body_digest), 64)

    def test_a_wrong_token_is_refused(self):
        with serving(authed_only(self.TOKEN)) as url:
            result = probe_health(url, timeout=5, auth_token="not-the-token")
        self.assertFalse(result.healthy)

    def test_the_token_never_appears_in_the_result(self):
        # The result is journalled and carried into an attestation. A credential
        # in an audit record is a credential that leaks.
        with serving(authed_only(self.TOKEN)) as url:
            result = probe_health(url, timeout=5, auth_token=self.TOKEN)
        rendered = json.dumps(
            {
                "detail": result.detail,
                "url": result.url,
                "digest": result.body_digest,
                "collector": result.collector,
            }
        )
        self.assertNotIn(self.TOKEN, rendered)
        self.assertNotIn("Authorization", rendered)
        self.assertNotIn("Bearer", rendered)


class ProfileAuthFlagTests(unittest.TestCase):
    def test_profiles_default_to_anonymous(self):
        registry = default_profiles("https://example.test/health", "c")
        self.assertFalse(registry.get("runtime-health-v1").requires_auth)

    def test_a_profile_can_declare_that_its_target_is_protected(self):
        registry = default_profiles(
            "https://example.test/health", "c", requires_auth=True
        )
        self.assertTrue(registry.get("runtime-health-v1").requires_auth)

    def test_requires_auth_is_server_owned_not_caller_supplied(self):
        # It lives on the profile, which the caller cannot create or edit.
        profile = CollectionProfile(
            profile_id="p",
            collector_id="c",
            allowed_kind="runtime",
            target="https://example.test/health",
            requires_auth=True,
        )
        self.assertTrue(profile.requires_auth)
        with self.assertRaises(Exception):
            # Profiles are frozen; a request cannot flip this at collection time.
            profile.requires_auth = False


class ActionCeilingTests(unittest.TestCase):
    """The model may call; the runtime decides how often that does work."""

    class StubFleet:
        class executor:
            calls = []

            @staticmethod
            def execute(task_id, fn):
                ActionCeilingTests.StubFleet.executor.calls.append(task_id)
                return fn()

    def setUp(self):
        self.StubFleet.executor.calls = []

    def test_the_action_runs_once_by_default(self):
        tool = build_action_tool(self.StubFleet, "T")
        first = tool("fix it")
        self.assertIn("applied: fix it", first)
        self.assertEqual(len(self.StubFleet.executor.calls), 1)

    def test_repeat_calls_do_not_perform_the_action_again(self):
        tool = build_action_tool(self.StubFleet, "T")
        tool("fix it")
        for _ in range(6):
            repeat = tool("fix it again")
        # Seven calls, one execution -- the live run's exact failure mode.
        self.assertEqual(len(self.StubFleet.executor.calls), 1)
        self.assertIn("Already completed", repeat)

    def test_a_repeat_call_answers_rather_than_erroring(self):
        # An error invites a retry loop; a truthful "already done" ends one.
        tool = build_action_tool(self.StubFleet, "T")
        tool("fix it")
        self.assertIsInstance(tool("again"), str)

    def test_the_ceiling_is_configurable_for_a_task_that_needs_retries(self):
        tool = build_action_tool(self.StubFleet, "T", max_invocations=3)
        for _ in range(5):
            tool("step")
        self.assertEqual(len(self.StubFleet.executor.calls), 3)

    def test_the_default_ceiling_is_one(self):
        self.assertEqual(MAX_ACTION_INVOCATIONS, 1)

    def test_the_tool_still_exposes_only_its_instruction_parameter(self):
        from google.adk.tools import FunctionTool

        tool = build_action_tool(self.StubFleet, "T")
        dumped = FunctionTool(tool)._get_declaration().model_dump(exclude_none=True)
        schema = dumped.get("parameters_json_schema") or dumped.get("parameters")
        self.assertEqual(sorted((schema.get("properties") or {}).keys()), ["instruction"])


if __name__ == "__main__":
    unittest.main()
