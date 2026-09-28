"""Configuration readiness, separate from liveness and target availability."""

from collections.abc import Mapping
import math
from urllib.parse import urlsplit


def configuration_issues(env: Mapping[str, str]) -> tuple[str, ...]:
    issues = []
    if not env.get("PROOFOS_COLLECTOR_PRIVATE_KEY_FILE", "").strip():
        issues.append("signing_key_not_configured")
    if env.get("PROOFOS_COLLECTOR_CREATE_KEY", "").strip().lower() in {"1", "true", "yes"}:
        issues.append("automatic_key_creation_enabled")
    target = env.get("PROOFOS_COLLECTOR_TARGET", "").strip()
    try:
        parts = urlsplit(target)
        valid_target = parts.scheme in {"http", "https"} and bool(parts.hostname)
        valid_target = valid_target and parts.username is None and parts.password is None
        valid_target = valid_target and not parts.fragment
        _ = parts.port
    except ValueError:
        valid_target = False
    if not valid_target:
        issues.append("observation_target_not_configured_or_invalid")
    try:
        timeout = float(env.get("PROOFOS_COLLECTOR_TIMEOUT", "5"))
        valid_timeout = math.isfinite(timeout) and timeout > 0
    except ValueError:
        valid_timeout = False
    if not valid_timeout:
        issues.append("observation_timeout_invalid")
    return tuple(issues)
