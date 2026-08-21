"""Run the ProofOS P0 scenario against a live Gemini model via Google ADK.

This is a real model + tool execution. Nothing about the decision is hard-coded:
the model must call the verification tool, and the tool reads evidence from a
ledger the model cannot write to.

Usage:
    python -m proofos_agent.run_demo
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import sys

from google.adk.runners import InMemoryRunner
from google.genai import types

from proofos_agent import scenario
from proofos_agent.agent import LEDGER, MODEL, root_agent
from proofos_agent.recovery import MAX_ATTEMPTS, Turn, run_verification_loop

APP_NAME = "proofos"
USER_ID = "proofos-operator"


class CredentialsMissingError(RuntimeError):
    pass


def preflight() -> str:
    """Confirm a credential path exists before attempting a live model call."""
    if os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").upper() in {"TRUE", "1"}:
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION")
        if not project or not location:
            raise CredentialsMissingError(
                "Vertex AI mode requires GOOGLE_CLOUD_PROJECT and "
                "GOOGLE_CLOUD_LOCATION."
            )
        return f"vertex-ai project={project} location={location}"
    if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        return "gemini-api-key"
    raise CredentialsMissingError(
        "No Google credentials found. Set GOOGLE_API_KEY, or set "
        "GOOGLE_GENAI_USE_VERTEXAI=TRUE with GOOGLE_CLOUD_PROJECT and "
        "GOOGLE_CLOUD_LOCATION (see .env.example)."
    )


async def run_live_turn(runner: InMemoryRunner, session_id: str, attempt: int) -> Turn:
    """One live model turn. Records everything the model actually did."""
    turn = Turn(attempt=attempt)
    prompt = (
        f"A worker reports on task {scenario.TASK_ID}: "
        f'"{scenario.WORKER_CLAIM}" '
        "Verify this claim and report the outcome."
    )
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    async for event in runner.run_async(
        user_id=USER_ID, session_id=session_id, new_message=message
    ):
        content = getattr(event, "content", None)
        for part in getattr(content, "parts", None) or []:
            if getattr(part, "function_call", None):
                call = part.function_call
                turn.tool_calls.append(
                    {"name": call.name, "args": dict(call.args or {})}
                )
            if getattr(part, "function_response", None):
                turn.tool_results.append(dict(part.function_response.response or {}))
            if getattr(part, "text", None) and not getattr(event, "partial", False):
                turn.final_text += part.text
    return turn


async def main() -> int:
    credential_mode = preflight()

    LEDGER.reset()
    scenario.seed_incomplete_evidence(LEDGER)

    runner = InMemoryRunner(agent=root_agent, app_name=APP_NAME)
    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id=USER_ID
    )

    collectors = {
        kind: functools.partial(collect, LEDGER)
        for kind, collect in scenario.COLLECTORS.items()
    }

    outcome = await run_verification_loop(
        run_turn=functools.partial(run_live_turn, runner, session.id),
        collectors=collectors,
        max_attempts=MAX_ATTEMPTS,
    )

    report = {
        "model": MODEL,
        "credential_mode": credential_mode,
        "task_id": scenario.TASK_ID,
        "claim": scenario.WORKER_CLAIM,
        **outcome,
    }
    print(json.dumps(report, indent=2))
    return 0 if outcome["final_status"] == "VERIFIED" else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except CredentialsMissingError as exc:
        print(f"PREFLIGHT FAILED: {exc}", file=sys.stderr)
        sys.exit(2)
