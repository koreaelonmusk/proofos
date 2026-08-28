"""Runtime configuration for the ProofOS API.

The collector mode is explicit and has no fallback. If the API is configured to
obtain runtime evidence from a separate collector and that collector cannot be
reached, the answer is ABSTAIN -- never "collect it locally instead". A silent
downgrade from attested evidence to self-produced evidence would be the exact
failure this architecture exists to prevent, and it would be invisible in the
happy path.

Misconfiguration stops startup. An API that cannot be told which collector to
trust must not run, because the alternative is trusting whichever collector
answers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from proofos.keys import KeyMaterialError, verification_provider_from_env
from proofos_agent.collector_client import AUTH_AUTO, AUTH_MODES
from proofos.profiles import RUNTIME_HEALTH_PROFILE
from proofos.registry import COLLECTOR_ID

MODE_ENV = "PROOFOS_COLLECTOR_MODE"
URL_ENV = "PROOFOS_COLLECTOR_URL"
COLLECTOR_ID_ENV = "PROOFOS_COLLECTOR_ID"
PROFILE_ENV = "PROOFOS_COLLECTOR_PROFILE"
TIMEOUT_ENV = "PROOFOS_COLLECTOR_CLIENT_TIMEOUT"
AUTH_ENV = "PROOFOS_COLLECTOR_AUTH"
AGENT_RUNTIME_ENV = "PROOFOS_AGENT_RUNTIME"


class CollectorMode(StrEnum):
    #: Runtime evidence comes from a separate collector process, over the
    #: signed-attestation boundary. The only mode intended for deployment.
    REMOTE = "remote"

    #: The collector runs in this process and writes evidence through an
    #: in-process grant. Retained for deterministic unit tests of the
    #: orchestration itself; it is not a deployment mode, and its name says so.
    INPROCESS_TEST_ONLY = "inprocess-test-only"


class AgentRuntime(StrEnum):
    #: Roles are played by deterministic Python. The default, because CI must
    #: not depend on an external model, and because a run that never called a
    #: model should never be described as one that did.
    DETERMINISTIC = "deterministic"

    #: Roles are played by live Gemini agents through Google ADK. Requested by
    #: name only -- never inferred from the presence of credentials.
    GEMINI = "gemini"


class ConfigurationError(RuntimeError):
    """Raised when the service is not safely configured to start."""


@dataclass(frozen=True)
class RuntimeConfig:
    mode: CollectorMode
    collector_url: str = ""
    collector_id: str = COLLECTOR_ID
    profile_id: str = RUNTIME_HEALTH_PROFILE
    public_key_b64: str = ""
    client_timeout: float = 15.0
    auth: str = AUTH_AUTO
    agent_runtime: AgentRuntime = AgentRuntime.DETERMINISTIC
    model: str = ""

    @property
    def is_remote(self) -> bool:
        return self.mode is CollectorMode.REMOTE

    def describe(self) -> dict:
        """Safe to expose. Carries no key material and no internal target."""
        return {
            "collector_mode": str(self.mode),
            "collector_id": self.collector_id,
            "profile_id": self.profile_id,
            "attested_evidence": self.is_remote,
            "collector_auth": self.auth,
            "agent_runtime": str(self.agent_runtime),
            "live_model_enabled": self.agent_runtime is AgentRuntime.GEMINI,
            # The model a live run would call. Reported even in deterministic
            # mode so what "live" would mean is inspectable before enabling it.
            "model": self.model,
        }


def build_runtime_config(env: dict[str, str] | None = None) -> RuntimeConfig:
    """Read configuration, or refuse to start.

    Remote is the default: getting attested evidence should be what happens
    when nobody configures anything, and running the in-process collector
    should require asking for it by name.
    """
    source = os.environ if env is None else env
    raw_mode = source.get(MODE_ENV, CollectorMode.REMOTE.value).strip().lower()

    try:
        mode = CollectorMode(raw_mode)
    except ValueError as exc:
        allowed = [m.value for m in CollectorMode]
        raise ConfigurationError(
            f"unknown {MODE_ENV}={raw_mode!r}; allowed: {allowed}"
        ) from exc

    collector_id = source.get(COLLECTOR_ID_ENV, COLLECTOR_ID)
    profile_id = source.get(PROFILE_ENV, RUNTIME_HEALTH_PROFILE)

    raw_runtime = source.get(
        AGENT_RUNTIME_ENV, AgentRuntime.DETERMINISTIC.value
    ).strip().lower()
    try:
        agent_runtime = AgentRuntime(raw_runtime)
    except ValueError as exc:
        raise ConfigurationError(
            f"unknown {AGENT_RUNTIME_ENV}={raw_runtime!r}; "
            f"allowed: {[r.value for r in AgentRuntime]}"
        ) from exc

    from proofos_agent.agent import MODEL as GEMINI_MODEL

    if agent_runtime is AgentRuntime.GEMINI:
        # Fail here, not at the first request. A service advertising a live
        # model must not start without one.
        from proofos_agent.gemini_runner import CredentialsMissingError, preflight

        try:
            preflight()
        except CredentialsMissingError as exc:
            raise ConfigurationError(str(exc)) from exc

    if mode is CollectorMode.INPROCESS_TEST_ONLY:
        return RuntimeConfig(
            mode=mode,
            collector_id=collector_id,
            profile_id=profile_id,
            agent_runtime=agent_runtime,
            model=GEMINI_MODEL,
        )

    url = source.get(URL_ENV, "").strip()
    if not url:
        raise ConfigurationError(
            f"{MODE_ENV}=remote requires {URL_ENV}. ProofOS will not fall back "
            "to producing runtime evidence in this process."
        )

    try:
        public_key = verification_provider_from_env().load_public_key_b64()
    except KeyMaterialError as exc:
        raise ConfigurationError(str(exc)) from exc

    try:
        timeout = float(source.get(TIMEOUT_ENV, "15"))
    except ValueError as exc:
        raise ConfigurationError(f"{TIMEOUT_ENV} must be a number") from exc
    if timeout <= 0:
        raise ConfigurationError(f"{TIMEOUT_ENV} must be positive")

    auth = source.get(AUTH_ENV, AUTH_AUTO).strip().lower()
    if auth not in AUTH_MODES:
        raise ConfigurationError(
            f"unknown {AUTH_ENV}={auth!r}; allowed: {list(AUTH_MODES)}"
        )

    return RuntimeConfig(
        mode=mode,
        collector_url=url,
        collector_id=collector_id,
        profile_id=profile_id,
        public_key_b64=public_key,
        client_timeout=timeout,
        auth=auth,
        agent_runtime=agent_runtime,
        model=GEMINI_MODEL,
    )
