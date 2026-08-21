"""The live Gemini overlay: what reaches which container.

Credentials are a capability. Handing them to a service that has no use for
them widens what an attacker gets for compromising it, so these tests assert
the negative case as carefully as the positive one: the API may talk to Gemini,
and the collector may not.

They also pin the two properties that make the overlay safe to commit -- no key
literal appears in any YAML, and an absent key refuses startup rather than
quietly running deterministically under a "live" label.
"""

import os
import pathlib
import re
import shutil
import subprocess
import unittest

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
BASE_COMPOSE = REPO / "docker-compose.yml"
LIVE_COMPOSE = REPO / "docker-compose.live.yml"

GEMINI_ENV = (
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_APPLICATION_CREDENTIALS",
)


def load(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def env_of(compose: dict, service: str) -> dict:
    return dict((compose.get("services", {}).get(service, {}) or {}).get("environment", {}) or {})


class BaseComposeIsDeterministicTests(unittest.TestCase):
    """The normal topology must not become live by accident."""

    def setUp(self):
        self.compose = load(BASE_COMPOSE)

    def test_the_base_api_names_no_agent_runtime(self):
        # Absent means the service's own default applies, which is
        # deterministic. Nothing here opts into a model.
        self.assertNotIn("PROOFOS_AGENT_RUNTIME", env_of(self.compose, "api"))

    def test_the_base_topology_passes_no_gemini_credentials_anywhere(self):
        for service in ("api", "collector"):
            environment = env_of(self.compose, service)
            for name in GEMINI_ENV:
                self.assertNotIn(name, environment, msg=f"{service} receives {name}")

    def test_the_base_api_still_uses_the_remote_collector(self):
        environment = env_of(self.compose, "api")
        self.assertEqual(environment["PROOFOS_COLLECTOR_MODE"], "remote")


class LiveOverlayTests(unittest.TestCase):
    def setUp(self):
        self.overlay = load(LIVE_COMPOSE)

    def test_the_overlay_requests_gemini_by_name(self):
        self.assertEqual(
            env_of(self.overlay, "api")["PROOFOS_AGENT_RUNTIME"], "gemini"
        )

    def test_the_overlay_offers_both_credential_paths(self):
        environment = env_of(self.overlay, "api")
        for name in GEMINI_ENV:
            self.assertIn(name, environment, msg=f"api cannot receive {name}")

    def test_the_overlay_does_not_touch_the_collector(self):
        # The collector observes the network and signs what it saw. A model
        # plays no part in that, so it is given no way to reach one.
        self.assertNotIn("collector", self.overlay.get("services", {}))

    def test_the_overlay_defaults_are_empty_so_absence_stays_absent(self):
        environment = env_of(self.overlay, "api")
        for name in ("GOOGLE_API_KEY", "GEMINI_API_KEY"):
            # ${VAR:-} -- an unset key becomes empty, and empty fails preflight.
            self.assertTrue(
                environment[name].endswith(":-}"),
                msg=f"{name} has a non-empty default",
            )

    def test_location_defaults_to_the_global_vertex_endpoint(self):
        self.assertEqual(
            env_of(self.overlay, "api")["GOOGLE_CLOUD_LOCATION"],
            "${GOOGLE_CLOUD_LOCATION:-global}",
        )


class NoKeyMaterialInRepoTests(unittest.TestCase):
    """A committed key would be worse than no overlay at all."""

    SECRET_SHAPES = (
        re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
        re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/]{40,}"),
    )

    def test_no_compose_file_contains_a_key_literal(self):
        for path in (BASE_COMPOSE, LIVE_COMPOSE):
            text = path.read_text(encoding="utf-8")
            for shape in self.SECRET_SHAPES:
                self.assertIsNone(
                    shape.search(text), msg=f"{path.name} looks like it contains a key"
                )

    def test_every_credential_value_is_a_substitution(self):
        # Values must be ${...}, never a literal. This is what makes the file
        # safe to commit at all.
        environment = env_of(load(LIVE_COMPOSE), "api")
        for name in GEMINI_ENV:
            self.assertTrue(
                environment[name].startswith("${"),
                msg=f"{name} is a literal, not a substitution",
            )

    def test_no_credential_file_is_tracked_by_git(self):
        tracked = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO,
        ).stdout.splitlines()
        for path in tracked:
            name = pathlib.PurePosixPath(path).name
            self.assertNotEqual(name, ".env", msg="a .env file is tracked")
            self.assertFalse(
                path.startswith("secrets/") or name.endswith((".pem", ".key")),
                msg=f"credential material is tracked: {path}",
            )

    def test_gitignore_covers_the_local_credential_file(self):
        ignored = (REPO / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".env", ignored)
        self.assertIn("secrets/", ignored)


class LiveModeFailsClosedTests(unittest.TestCase):
    """Requesting a live model without one must stop the service."""

    def test_gemini_mode_refuses_to_start_without_credentials(self):
        from proofos_service.config import ConfigurationError, build_runtime_config

        saved = {k: os.environ.pop(k, None) for k in GEMINI_ENV}
        try:
            with self.assertRaises(ConfigurationError) as caught:
                build_runtime_config(
                    {
                        "PROOFOS_COLLECTOR_MODE": "inprocess-test-only",
                        "PROOFOS_AGENT_RUNTIME": "gemini",
                    }
                )
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

        message = str(caught.exception)
        self.assertIn("GOOGLE_API_KEY", message)
        # The refusal says why there is no fallback, so nobody adds one later.
        self.assertIn("will not fall back", message)

    def test_an_empty_credential_string_is_treated_as_absent(self):
        # ${GOOGLE_API_KEY:-} yields "", which must not look like a credential.
        from proofos_service.config import ConfigurationError, build_runtime_config

        saved = {k: os.environ.pop(k, None) for k in GEMINI_ENV}
        os.environ["GOOGLE_API_KEY"] = ""
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = ""
        try:
            with self.assertRaises(ConfigurationError):
                build_runtime_config(
                    {
                        "PROOFOS_COLLECTOR_MODE": "inprocess-test-only",
                        "PROOFOS_AGENT_RUNTIME": "gemini",
                    }
                )
        finally:
            os.environ.pop("GOOGLE_API_KEY", None)
            os.environ.pop("GOOGLE_GENAI_USE_VERTEXAI", None)
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

    def test_there_is_no_gemini_to_deterministic_fallback_in_the_code(self):
        import ast

        source = (REPO / "proofos_agent" / "attested_scenario.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            for handler in node.handlers:
                body = ast.dump(ast.Module(body=handler.body, type_ignores=[]))
                self.assertNotIn(
                    "DeterministicTurnRunner",
                    body,
                    msg="a failure in live mode falls back to the deterministic runtime",
                )


@unittest.skipUnless(shutil.which("docker"), "docker is not available")
class LiveContainerFailsClosedTests(unittest.TestCase):
    """The same property, checked against the built artifact."""

    IMAGE = "proofos-live-check:test"

    @classmethod
    def setUpClass(cls):
        build = subprocess.run(
            ["docker", "build", "-q", "-t", cls.IMAGE, "-f", "Dockerfile", "."],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            raise unittest.SkipTest(f"could not build the API image: {build.stderr[-200:]}")

    def test_the_api_container_exits_when_live_mode_has_no_credentials(self):
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", "PROOFOS_COLLECTOR_MODE=remote",
                "-e", "PROOFOS_COLLECTOR_URL=http://collector:8080",
                "-e", "PROOFOS_COLLECTOR_AUTH=none",
                "-e", "PROOFOS_COLLECTOR_PUBLIC_KEY=" + "A" * 43 + "=",
                "-e", "PROOFOS_AGENT_RUNTIME=gemini",
                self.IMAGE,
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertNotEqual(result.returncode, 0, "the container started without a model")
        combined = result.stdout + result.stderr
        self.assertIn("live Gemini mode requires", combined)
        self.assertIn("will not fall back", combined)


if __name__ == "__main__":
    unittest.main()
