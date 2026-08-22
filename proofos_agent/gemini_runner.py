"""Live Gemini turns through Google ADK.

Three real agents, each built for one execution and bound to that execution's
ledger. Nothing is cached across executions: a verifier agent whose tool closes
over a ledger is, in effect, a capability, and caching it globally would let one
request's verifier answer questions about another request's evidence.

Each role gets its own ADK session. A planner and a verifier sharing a
conversation would let the planner's framing leak into the verdict, which is a
strange way to run a system built to distrust framing.

The runner captures what the model did -- tool names, arguments, results, final
text -- and hands it back. It draws no conclusions. Whether a turn produced a
verdict is decided by ``decision_from``, from the tool result alone.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any, Callable

from google.adk.runners import InMemoryRunner
from google.genai import types

from proofos.registry import AgentRegistry, default_registry

from .agent import (
    MODEL,
    build_executor_agent,
    build_planner_agent,
    build_verifier_agent,
)
from .turn_runner import ACTION_TOOL, VERIFY_TOOL, AgentTurn, ToolInvocation

APP_NAME = "proofos"
USER_ID = "proofos-runtime"

#: Free-tier Gemini allows a handful of requests per minute per model, and a
#: full ProofOS execution needs roughly a dozen. A rate limit is a transport
#: condition, not a verdict, so it is waited out rather than treated as a
#: failed turn -- but only a bounded number of times, because an execution that
#: cannot finish must still end.
#: Free tiers cap requests per minute, and retrying after a rejection still
#: spends attempts. Spacing turns proactively keeps a run under the cap instead
#: of discovering the cap and then fighting it.
TURN_DELAY_ENV = "PROOFOS_GEMINI_TURN_DELAY_SECONDS"

RATE_LIMIT_RETRIES = 4
RATE_LIMIT_BACKOFF_SECONDS = 20.0
MAX_BACKOFF_SECONDS = 75.0


def _is_rate_limit(exc: Exception) -> bool:
    name = type(exc).__name__
    return "ResourceExhausted" in name or "429" in str(exc)[:64]


def _retry_delay(exc: Exception, attempt: int) -> float:
    """Honour the server's RetryInfo when it offers one."""
    match = re.search(r"retryDelay['\"]?:\s*['\"]?(\d+(?:\.\d+)?)s", str(exc))
    if match:
        return min(float(match.group(1)) + 1.0, MAX_BACKOFF_SECONDS)
    return min(RATE_LIMIT_BACKOFF_SECONDS * attempt, MAX_BACKOFF_SECONDS)


class CredentialsMissingError(RuntimeError):
    """Raised when live mode is requested without a usable credential path."""


def preflight() -> str:
    """Confirm a credential path exists. Never returns or logs the secret.

    Reports only which mode is configured, and for Vertex the project and
    location -- enough to diagnose a misconfiguration, nothing that could
    authenticate anyone.
    """
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
        # Which variable, never its value.
        return "gemini-api-key"

    raise CredentialsMissingError(
        "live Gemini mode requires GOOGLE_API_KEY, or "
        "GOOGLE_GENAI_USE_VERTEXAI=TRUE with GOOGLE_CLOUD_PROJECT and "
        "GOOGLE_CLOUD_LOCATION. ProofOS will not fall back to a deterministic "
        "runtime, because that would make a live demo fake."
    )


def build_action_tool(fleet, task_id: str) -> Callable[[str], str]:
    """The executor's only tool.

    Named ``perform_action`` because the registry permits exactly that name for
    the executor role, and the agent build refuses anything else. It performs
    work and reports what it did; it writes nothing the verifier will read.
    """

    def perform_action(instruction: str) -> str:
        """Carry out the assigned action and report what was done.

        Args:
            instruction: What to do.

        Returns:
            A short description of what was done. Not evidence.
        """
        return fleet.executor.execute(task_id, lambda: f"applied: {instruction}")

    return perform_action


class GeminiAdkTurnRunner:
    """Runs the real ADK agents for one execution."""

    RUNTIME = "gemini"

    def __init__(
        self,
        fleet,
        ledger,
        task_id: str,
        registry: AgentRegistry | None = None,
        credential_mode: str = "",
        model: str = MODEL,
    ) -> None:
        self._fleet = fleet
        self._task_id = task_id
        self._registry = registry or default_registry()
        self._model = model
        self._credential_mode = credential_mode

        # Built here, per execution. The verifier's tool closes over this
        # execution's ledger and must not outlive it.
        self._planner = build_planner_agent(self._registry)
        self._executor = build_executor_agent(
            build_action_tool(fleet, task_id), self._registry
        )
        self._verifier = build_verifier_agent(ledger, self._registry)

        self._runners: dict[str, InMemoryRunner] = {}
        self._sessions: dict[str, str] = {}

    def describe(self) -> dict[str, Any]:
        return {
            "agent_runtime": self.RUNTIME,
            "model": self._model,
            "live_model_enabled": True,
            "credential_mode": self._credential_mode,
        }

    # -- ADK plumbing -------------------------------------------------------

    async def _session_for(self, role: str, agent) -> tuple[InMemoryRunner, str]:
        """One runner and one session per role, created on first use."""
        if role not in self._runners:
            runner = InMemoryRunner(agent=agent, app_name=f"{APP_NAME}-{role}")
            session = await runner.session_service.create_session(
                app_name=f"{APP_NAME}-{role}", user_id=USER_ID
            )
            self._runners[role] = runner
            self._sessions[role] = session.id
        return self._runners[role], self._sessions[role]

    async def _pace(self) -> None:
        try:
            delay = float(os.environ.get(TURN_DELAY_ENV, "0"))
        except ValueError:
            delay = 0.0
        if delay > 0:
            await asyncio.sleep(delay)

    async def _run(self, role: str, agent, agent_id: str, prompt: str, attempt: int = 0) -> AgentTurn:
        await self._pace()
        started = time.time()
        calls: list[ToolInvocation] = []
        pending: list[dict[str, Any]] = []
        final_text = ""
        error = ""
        session_id = ""

        for rate_attempt in range(1, RATE_LIMIT_RETRIES + 2):
            calls, pending, final_text, error = [], [], "", ""
            try:
                runner, session_id = await self._session_for(role, agent)
                message = types.Content(role="user", parts=[types.Part(text=prompt)])

                async for event in runner.run_async(
                    user_id=USER_ID, session_id=session_id, new_message=message
                ):
                    content = getattr(event, "content", None)
                    for part in getattr(content, "parts", None) or []:
                        call = getattr(part, "function_call", None)
                        if call is not None:
                            pending.append(
                                {"name": call.name, "args": dict(call.args or {})}
                            )
                        response = getattr(part, "function_response", None)
                        if response is not None:
                            matched = _match(pending, response.name)
                            calls.append(
                                ToolInvocation(
                                    name=response.name
                                    or (matched or {}).get("name", ""),
                                    args=(matched or {}).get("args", {}),
                                    result=_as_dict(response.response),
                                )
                            )
                        text = getattr(part, "text", None)
                        if text and not getattr(event, "partial", False):
                            final_text += text
                break
            except Exception as exc:  # noqa: BLE001 - a model failure is a turn failure
                # The exception type only. Provider messages can carry request
                # echoes, and this string is journaled.
                error = f"{type(exc).__name__}"
                if _is_rate_limit(exc) and rate_attempt <= RATE_LIMIT_RETRIES:
                    await asyncio.sleep(_retry_delay(exc, rate_attempt))
                    continue
                break

        # A call the model made that never produced a response is recorded as
        # unanswered rather than dropped, so a partial stream is visible.
        for unanswered in pending:
            calls.append(ToolInvocation(unanswered["name"], unanswered["args"], None))

        return AgentTurn(
            role=role,
            agent_id=agent_id,
            model=self._model,
            attempt=attempt,
            session_id=session_id,
            tool_calls=tuple(calls),
            final_text=final_text.strip(),
            started_at=started,
            completed_at=time.time(),
            error=error,
        )

    # -- roles --------------------------------------------------------------

    async def plan(self, task_id: str, goal: str) -> AgentTurn:
        prompt = (
            f"Task {task_id}. Goal: {goal}\n"
            "Describe the steps, and state what independent evidence would "
            "prove the goal was achieved. You do not perform the work and you "
            "do not decide whether it is complete."
        )
        turn = await self._run(
            "planner", self._planner, self._fleet.planner._ctx.agent_id, prompt
        )
        # The plan is advisory. Requirements were fixed by the runtime before
        # this turn and are not reopened by whatever the planner proposes.
        self._fleet.planner.plan(task_id, goal, ())
        return turn

    async def execute(self, task_id: str, instruction: str) -> AgentTurn:
        prompt = (
            f"Task {task_id}. {instruction}\n"
            "Use perform_action to carry it out, then report plainly what you "
            "did. Do not assert that the task is verified."
        )
        return await self._run(
            "executor", self._executor, self._fleet.executor._ctx.agent_id, prompt
        )

    async def verify(self, task_id: str, claim: str, attempt: int) -> AgentTurn:
        prompt = (
            f"A worker reports on task {task_id}: \"{claim}\"\n"
            f"Call verify_task_completion with task_id=\"{task_id}\" and that "
            "claim exactly, then report the tool's status."
        )
        return await self._run(
            "verifier",
            self._verifier,
            self._fleet.verifier._ctx.agent_id,
            prompt,
            attempt,
        )

    async def aclose(self) -> None:
        for runner in self._runners.values():
            close = getattr(runner, "close", None)
            if close is not None:
                try:
                    result = close()
                    if hasattr(result, "__await__"):
                        await result
                except Exception:  # noqa: BLE001 - teardown must not mask results
                    pass
        self._runners.clear()
        self._sessions.clear()


def _match(pending: list[dict[str, Any]], name: str | None) -> dict[str, Any] | None:
    for index, call in enumerate(pending):
        if call["name"] == name:
            return pending.pop(index)
    return None


def _as_dict(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    return {"result": value}


__all__ = [
    ACTION_TOOL,
    VERIFY_TOOL,
    "CredentialsMissingError",
    "GeminiAdkTurnRunner",
    "build_action_tool",
    "preflight",
]
