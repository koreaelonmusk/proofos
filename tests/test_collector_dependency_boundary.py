"""The collector deployment must stay smaller than the ProofOS control plane."""

from __future__ import annotations

import ast
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "proofos_collector"

REQUIRED_DISTRIBUTIONS = {
    "fastapi",
    "uvicorn",
    "cryptography",
    "google-auth",
    "requests",
}

FORBIDDEN_DISTRIBUTIONS = {
    "google-adk",
    "google-genai",
    "google-cloud-firestore",
}

FORBIDDEN_IMPORT_PREFIXES = (
    "proofos_agent",
    "proofos_service",
    "proofos.firestore_journal",
    "proofos.journal_backend",
    "proofos.verifier",
    "google.adk",
    "google.genai",
    "google.cloud.firestore",
)


def imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


class CollectorDependencyBoundaryTests(unittest.TestCase):
    def test_vercel_entrypoint_stays_on_the_collector(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            data["tool"]["vercel"]["entrypoint"],
            "proofos_collector.app:app",
        )
        self.assertEqual(
            data["project"]["requires-python"],
            ">=3.12",
            "Vercel Python runtime contract drifted from the supported 3.12+ baseline",
        )

    def test_vercel_runtime_has_no_agent_or_journal_dependencies(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        dependencies = data["project"]["dependencies"]
        names = {
            item.split("[", 1)[0]
            .split(">", 1)[0]
            .split("<", 1)[0]
            .split("=", 1)[0]
            .strip()
            .lower()
            for item in dependencies
        }
        missing = REQUIRED_DISTRIBUTIONS - names
        self.assertEqual(
            missing,
            set(),
            f"Vercel collector lost required runtime dependencies: {sorted(missing)}",
        )
        overlap = names & FORBIDDEN_DISTRIBUTIONS
        self.assertEqual(
            overlap,
            set(),
            f"Vercel collector gained control-plane dependencies: {sorted(overlap)}",
        )

    def test_collector_package_cannot_import_control_plane_modules(self):
        violations: list[str] = []
        for path in sorted(COLLECTOR.glob("*.py")):
            for module in sorted(imported_modules(path)):
                if any(
                    module == prefix or module.startswith(prefix + ".")
                    for prefix in FORBIDDEN_IMPORT_PREFIXES
                ):
                    violations.append(f"{path.name}: {module}")
        self.assertEqual(
            violations,
            [],
            "collector package crossed the authority boundary: "
            + ", ".join(violations),
        )


if __name__ == "__main__":
    unittest.main()
