"""Drive the ProofOS API and print what actually happened.

This used to be a second architecture: it ran a live Gemini verifier against the
*in-process* collector, which meant the one command that looked like a live demo
exercised a weaker trust path than the deployable service. Two architectures
means the one you demo is not the one you ship.

So this is now a client. It calls the real API and reports what that instance
did. Whether the run used live Gemini or deterministic roles, and whether
evidence came from a separate collector, are properties of the service's
configuration -- reported by the service, never asserted here.

    uvicorn proofos_service.app:app --port 8080          # or docker compose up
    python -m proofos_agent.run_demo

Exit codes: 0 VERIFIED, 1 ABSTAIN, 2 the API could not be reached.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API_URL_ENV = "PROOFOS_API_URL"
DEFAULT_API_URL = "http://127.0.0.1:8080"
DEFAULT_CLAIM = "Production bug BUG-4417 is fixed and the service is healthy."


class ApiUnreachable(RuntimeError):
    pass


def _get(base: str, path: str) -> dict:
    try:
        with urllib.request.urlopen(f"{base}{path}", timeout=120) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise ApiUnreachable(f"GET {path} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ApiUnreachable(f"GET {path} failed: {type(exc).__name__}") from exc


def _post(base: str, path: str, payload: dict) -> dict:
    request = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise ApiUnreachable(f"POST {path} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ApiUnreachable(f"POST {path} failed: {type(exc).__name__}") from exc


def render(config: dict, outcome: dict, audit: dict) -> str:
    lines = [
        "=== ProofOS ===",
        f"  agent runtime : {config.get('agent_runtime')} "
        f"(live model: {config.get('live_model_enabled')})",
        f"  collector mode: {config.get('collector_mode')} "
        f"(attested: {config.get('attested_evidence')})",
        f"  model         : {outcome.get('model', config.get('model', 'n/a'))}",
        "",
        f"  claim   : {outcome.get('claim')}",
        f"  decision: {outcome.get('final_status')} ({outcome.get('failure_class')})",
        "",
        "  verifier decisions (from the tool, not the prose):",
    ]
    for decision in outcome.get("decisions", []):
        lines.append(
            f"    attempt {decision['attempt']}: {decision['status']:<8} "
            f"{decision.get('failure', ''):<20} missing={decision.get('missing')}"
        )
        prose = (decision.get("model_text") or "").strip().replace("\n", " ")
        if prose:
            lines.append(f"      model said: {prose[:100]!r}")

    if outcome.get("agent_turns"):
        lines += ["", "  agent turns:"]
        for turn in outcome["agent_turns"]:
            tools = ", ".join(c["tool"] for c in turn.get("tool_calls", [])) or "-"
            lines.append(
                f"    {turn['role']:<9} {turn['agent_id']:<18} tools=[{tools}]"
                f" {turn.get('error') or ''}"
            )

    lines += ["", "  evidence:"]
    for item in outcome.get("evidence", []):
        lines.append(
            f"    {item['kind']:<8} {item['source']:<9} by {item['collector']:<20}"
            f" satisfies={item['satisfies_requirement']}"
        )

    lines += [
        "",
        f"  audit chain intact: {audit.get('chain_ok')}",
        f"  execution_id      : {outcome.get('execution_id')}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    base = os.environ.get(API_URL_ENV, DEFAULT_API_URL).rstrip("/")
    claim = argv[0] if argv else DEFAULT_CLAIM

    try:
        config = _get(base, "/config")
        outcome = _post(base, "/executions", {"claim": claim})
        audit = _get(base, f"/executions/{outcome['execution_id']}")
    except ApiUnreachable as exc:
        print(
            f"ProofOS API at {base} is not reachable: {exc}\n"
            "Start it with `docker compose up` or "
            "`uvicorn proofos_service.app:app --port 8080`.",
            file=sys.stderr,
        )
        return 2

    print(render(config, outcome, audit))
    if os.environ.get("PROOFOS_DEMO_JSON"):
        print(json.dumps({"config": config, "outcome": outcome}, indent=2))

    return 0 if outcome.get("final_status") == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
