"""Fail closed when the Vercel collector deployment contract drifts.

This validates the repository-level facts Vercel depends on before a deployment
is attempted. It intentionally avoids network access and secret material.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys
import tomllib

from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proofos_collector.runtime_provenance import public_runtime_provenance

PYPROJECT = ROOT / "pyproject.toml"
EXPECTED_ENTRYPOINT = "proofos_collector.app:app"
REQUIRED_DEPENDENCIES = {
    "fastapi",
    "uvicorn",
    "cryptography",
    "google-auth",
    "requests",
}
FORBIDDEN_DEPENDENCIES = {
    "google-adk",
    "google-genai",
    "google-cloud-firestore",
}
REQUIRED_ROUTES = {
    "/",
    "/healthz",
    "/readyz",
    "/v1/profiles",
    "/v1/collect",
}


def _dependency_name(spec: str) -> str:
    """Return the normalized distribution name from a PEP 508 dependency string."""
    head = spec.split(";", 1)[0].strip()
    for marker in ("[", "<", ">", "=", "!", "~", " "):
        head = head.split(marker, 1)[0]
    return head.strip().lower().replace("_", "-")


def validate() -> list[str]:
    issues: list[str] = []

    if not PYPROJECT.exists():
        return ["pyproject_missing"]

    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data.get("project", {})
    tool = data.get("tool", {})
    vercel = tool.get("vercel", {}) if isinstance(tool, dict) else {}

    if vercel.get("entrypoint") != EXPECTED_ENTRYPOINT:
        issues.append("vercel_entrypoint_drift")

    if project.get("requires-python") != ">=3.12":
        issues.append("python_runtime_contract_drift")

    deps = {
        _dependency_name(item)
        for item in project.get("dependencies", [])
        if isinstance(item, str)
    }
    missing = sorted(REQUIRED_DEPENDENCIES - deps)
    if missing:
        issues.append("missing_runtime_dependencies:" + ",".join(missing))

    forbidden = sorted(FORBIDDEN_DEPENDENCIES & deps)
    if forbidden:
        issues.append("control_plane_dependencies_present:" + ",".join(forbidden))

    module_name, attr_name = EXPECTED_ENTRYPOINT.split(":", 1)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        issues.append(f"entrypoint_import_failed:{type(exc).__name__}")
        return issues

    app = getattr(module, attr_name, None)
    if not isinstance(app, FastAPI):
        issues.append("entrypoint_is_not_fastapi")
        return issues

    routes = {getattr(route, "path", None) for route in app.routes}
    missing_routes = sorted(REQUIRED_ROUTES - routes)
    if missing_routes:
        issues.append("missing_required_routes:" + ",".join(missing_routes))

    conflicting = ROOT / "vercel.json"
    if conflicting.exists():
        issues.append("unexpected_vercel_json_present")

    sample_env = {
        "VERCEL": "1",
        "VERCEL_ENV": "preview",
        "VERCEL_DEPLOYMENT_ID": "dpl_contract_test",
        "VERCEL_REGION": "icn1",
        "VERCEL_URL": "proofos-contract-test.vercel.app",
        "GEMINI_API_KEY": "must-not-leak",
        "VERCEL_OIDC_TOKEN": "must-not-leak",
    }
    provenance = public_runtime_provenance(sample_env)
    expected_provenance = {
        "platform": "vercel",
        "environment": "preview",
        "deployment_id": "dpl_contract_test",
        "region": "icn1",
        "url": "https://proofos-contract-test.vercel.app",
    }
    if provenance != expected_provenance:
        issues.append("runtime_provenance_contract_drift")
    if "must-not-leak" in repr(provenance):
        issues.append("runtime_provenance_secret_leak")

    return issues


def main() -> int:
    issues = validate()
    if issues:
        print("Vercel deploy contract FAILED")
        for issue in issues:
            print(f"- {issue}")
        return 1

    print("Vercel deploy contract OK")
    print(f"- entrypoint: {EXPECTED_ENTRYPOINT}")
    print("- runtime: Python >=3.12")
    print("- collector dependency boundary: OK")
    print("- required FastAPI routes: OK")
    print("- conflicting vercel.json: absent")
    print("- public runtime provenance allowlist: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
