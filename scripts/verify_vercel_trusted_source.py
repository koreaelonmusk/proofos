"""Probe Vercel Deployment Protection with a GitHub Actions OIDC identity.

This probe is diagnostic and evidence-only. It never performs collection or
signing. It tests whether Vercel Trusted Sources accepts the GitHub Actions OIDC
token for the exact production deployment, then records health/readiness without
persisting the token.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

SCHEMA_VERSION = 1
KIND = "vercel-trusted-source-observation"
MAX_BODY = 64 * 1024
TRUSTED_SOURCE_ERROR_RE = re.compile(r"^TRUSTED_SOURCES_[A-Z0-9_]{1,80}$")
OIDC_CLAIM_KEYS = (
    "iss",
    "aud",
    "sub",
    "repository",
    "repository_id",
    "repository_owner",
    "repository_owner_id",
    "ref",
    "ref_type",
    "workflow",
    "workflow_ref",
    "workflow_sha",
    "event_name",
    "runner_environment",
)


class TrustedSourceProbeError(RuntimeError):
    pass


def _origin(value: str) -> str:
    parts = urlsplit(value.strip())
    if (
        parts.scheme != "https"
        or not parts.hostname
        or not parts.hostname.lower().endswith(".vercel.app")
        or parts.username is not None
        or parts.password is not None
        or parts.port not in {None, 443}
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise TrustedSourceProbeError(
            "deployment URL must be an exact https://*.vercel.app origin"
        )
    return f"https://{parts.hostname.lower()}"


def _git_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise TrustedSourceProbeError("source git SHA must be a full 40-character SHA")
    return value


def _positive_int(value: str, *, label: str) -> int:
    value = value.strip()
    if not value.isdigit() or int(value) <= 0:
        raise TrustedSourceProbeError(f"{label} must be a positive integer")
    return int(value)


def _environment(value: str) -> str:
    value = value.strip().lower()
    if value not in {"production", "preview", "development"}:
        raise TrustedSourceProbeError("deployment environment is unsupported")
    return value


def _event_binding(
    *,
    deployment_id: str,
    deployment_status_id: str,
    environment: str,
    environment_url: str,
    source_git_sha: str,
) -> dict[str, Any]:
    return {
        "github_deployment_id": _positive_int(
            deployment_id, label="GitHub deployment id"
        ),
        "github_deployment_status_id": _positive_int(
            deployment_status_id, label="GitHub deployment status id"
        ),
        "environment": _environment(environment),
        "environment_url": _origin(environment_url),
        "source_git_sha": _git_sha(source_git_sha),
    }


def _oidc_claim_projection(token: str) -> dict[str, str]:
    """Decode a minimal diagnostic projection without using it for authorization."""

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise TrustedSourceProbeError("GitHub OIDC token is not a JWT")
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedSourceProbeError("GitHub OIDC payload could not be decoded") from exc
    if not isinstance(claims, dict):
        raise TrustedSourceProbeError("GitHub OIDC payload is not an object")

    projected: dict[str, str] = {}
    required = {"iss", "aud", "sub", "repository"}
    for key in OIDC_CLAIM_KEYS:
        value = claims.get(key)
        if value is None or value == "":
            if key in required:
                raise TrustedSourceProbeError(f"GitHub OIDC claim {key} is missing")
            continue
        if not isinstance(value, str) or len(value) > 600:
            raise TrustedSourceProbeError(f"GitHub OIDC claim {key} is invalid")
        projected[key] = value

    if projected.get("iss") != "https://token.actions.githubusercontent.com":
        raise TrustedSourceProbeError("GitHub OIDC issuer is unexpected")
    if projected.get("repository") != "koreaelonmusk/proofos":
        raise TrustedSourceProbeError("GitHub OIDC repository claim is unexpected")
    if "aud" not in projected or "sub" not in projected:
        raise TrustedSourceProbeError("GitHub OIDC audience/subject claims are missing")
    return projected


def _headers(token: str) -> dict[str, str]:
    token = token.strip()
    if not token:
        raise TrustedSourceProbeError("GitHub OIDC token is unavailable")
    return {
        "Accept": "application/json",
        "User-Agent": "proofos-vercel-trusted-source/1",
        "x-vercel-trusted-oidc-idp-token": token,
    }


def _read_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustedSourceProbeError(f"{label} did not return valid JSON") from exc


def _trusted_source_error_code(raw: bytes) -> str | None:
    """Extract only a bounded Vercel Trusted Sources error code.

    Rejection bodies can contain provider messages or request metadata. None of
    that is evidence-safe. Parse JSON opportunistically and retain only a stable
    code with the documented TRUSTED_SOURCES_* namespace.
    """

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    def visit(value: Any, depth: int = 0) -> str | None:
        if depth > 4:
            return None
        if isinstance(value, dict):
            for key in ("code", "errorCode", "error_code"):
                candidate = value.get(key)
                if (
                    isinstance(candidate, str)
                    and TRUSTED_SOURCE_ERROR_RE.fullmatch(candidate.strip())
                ):
                    return candidate.strip()
            for key in ("error", "details", "cause"):
                if key in value:
                    found = visit(value[key], depth + 1)
                    if found:
                        return found
        elif isinstance(value, list):
            for item in value[:8]:
                found = visit(item, depth + 1)
                if found:
                    return found
        return None

    return visit(payload)


def _health(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"status", "service", "runtime"}:
        raise TrustedSourceProbeError("health response schema drifted")
    if payload.get("status") != "ok" or payload.get("service") != "proofos-collector":
        raise TrustedSourceProbeError("health response identity is invalid")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict):
        raise TrustedSourceProbeError("health runtime provenance is missing")
    allowed = {"platform", "environment", "deployment_id", "region", "git_sha", "url"}
    if set(runtime) - allowed:
        raise TrustedSourceProbeError("health runtime contains non-allowlisted fields")
    return {
        "status": "ok",
        "service": "proofos-collector",
        "runtime": {key: runtime[key] for key in sorted(runtime)},
    }


def _readiness(payload: Any, status: int) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"status", "service", "issues"}:
        raise TrustedSourceProbeError("readiness response schema drifted")
    if payload.get("service") != "proofos-collector":
        raise TrustedSourceProbeError("readiness service identity is invalid")
    issues = payload.get("issues")
    if not isinstance(issues, list) or any(
        not isinstance(item, str) or not item or len(item) > 120 for item in issues
    ):
        raise TrustedSourceProbeError("readiness issue list is invalid")

    state = payload.get("status")
    if state == "ready":
        if status != 200 or issues:
            raise TrustedSourceProbeError("ready response is inconsistent")
    elif state == "not_ready":
        if status != 503:
            raise TrustedSourceProbeError("not_ready response must use HTTP 503")
    else:
        raise TrustedSourceProbeError("readiness status is invalid")

    return {
        "status": state,
        "service": "proofos-collector",
        "issues": sorted(issues),
    }


def _request_json(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    accepted_error_statuses: set[int] | None = None,
) -> tuple[int, Any]:
    accepted_error_statuses = accepted_error_statuses or set()
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, _read_json(
                response.read(MAX_BODY), label=urlsplit(url).path or "/"
            )
    except HTTPError as exc:
        raw = exc.read(MAX_BODY)
        if exc.code in accepted_error_statuses:
            return exc.code, _read_json(raw, label=urlsplit(url).path or "/")
        if exc.code in {401, 403}:
            return exc.code, {"vercel_error_code": _trusted_source_error_code(raw)}
        raise TrustedSourceProbeError(
            f"trusted-source request returned unexpected HTTP {exc.code}"
        ) from exc
    except URLError as exc:
        raise TrustedSourceProbeError(
            f"trusted-source request was unreachable: {type(exc.reason).__name__}"
        ) from exc


def _hash(value: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        **value,
        "evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def observe(
    origin: str,
    *,
    oidc_token: str,
    timeout: float,
    source_git_sha: str,
    deployment_event: dict[str, Any],
) -> dict[str, Any]:
    origin = _origin(origin)
    if deployment_event["environment"] != "production":
        raise TrustedSourceProbeError("trusted-source probe is production-only")
    if deployment_event["environment_url"] != origin:
        raise TrustedSourceProbeError(
            "target origin does not match deployment event environment URL"
        )
    if deployment_event["source_git_sha"] != _git_sha(source_git_sha):
        raise TrustedSourceProbeError(
            "source SHA does not match deployment event source SHA"
        )

    oidc_claims = _oidc_claim_projection(oidc_token)
    headers = _headers(oidc_token)
    health_status, health_payload = _request_json(
        f"{origin}/healthz",
        headers=headers,
        timeout=timeout,
    )

    if health_status in {401, 403}:
        return _hash(
            {
                "schema_version": SCHEMA_VERSION,
                "kind": KIND,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "observer": "github-actions-oidc",
                "target_origin": origin,
                "workflow_source_git_sha": _git_sha(source_git_sha),
                "deployment_event": deployment_event,
                "outcome": "TRUSTED_SOURCE_REJECTED",
                "http_status": health_status,
                "oidc_claims": oidc_claims,
                **(
                    {"vercel_error_code": health_payload["vercel_error_code"]}
                    if isinstance(health_payload, dict)
                    and health_payload.get("vercel_error_code")
                    else {}
                ),
                "claim_boundary": [
                    "proves the Vercel edge did not accept this GitHub Actions OIDC request",
                    "does not reveal or persist the OIDC token",
                    "does not prove application health or readiness",
                ],
            }
        )

    if health_status != 200:
        raise TrustedSourceProbeError("health endpoint did not return HTTP 200")

    health = _health(health_payload)
    runtime = health["runtime"]
    if runtime.get("platform") != "vercel":
        raise TrustedSourceProbeError("health runtime is not Vercel")
    if runtime.get("environment") != "production":
        raise TrustedSourceProbeError("health runtime is not production")
    if runtime.get("git_sha") != _git_sha(source_git_sha):
        raise TrustedSourceProbeError("health runtime Git SHA does not match source SHA")
    if runtime.get("url") and _origin(runtime["url"]) != origin:
        raise TrustedSourceProbeError("health runtime URL does not match target origin")

    ready_status, ready_payload = _request_json(
        f"{origin}/readyz",
        headers=headers,
        timeout=timeout,
        accepted_error_statuses={503},
    )
    if ready_status in {401, 403}:
        raise TrustedSourceProbeError(
            "trusted source passed health but was rejected before readiness"
        )

    readiness = _readiness(ready_payload, ready_status)
    outcome = (
        "TRUSTED_SOURCE_ACCEPTED_READY"
        if readiness["status"] == "ready"
        else "TRUSTED_SOURCE_ACCEPTED_NOT_READY"
    )

    return _hash(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "observer": "github-actions-oidc",
            "target_origin": origin,
            "workflow_source_git_sha": _git_sha(source_git_sha),
            "deployment_event": deployment_event,
            "outcome": outcome,
            "oidc_claims": oidc_claims,
            "health": health,
            "readiness": readiness,
            "claim_boundary": [
                "proves Vercel Trusted Sources accepted the GitHub Actions OIDC request",
                "records only the public health/readiness contract after edge authentication",
                "does not prove authenticated collector invocation or signed evidence collection",
                "does not reveal or persist the OIDC token",
            ],
        }
    )


def _self_test() -> None:
    origin = "https://proofos-preview.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"
    binding = _event_binding(
        deployment_id="123",
        deployment_status_id="456",
        environment="production",
        environment_url=origin,
        source_git_sha=sha,
    )
    assert binding["environment"] == "production"
    assert _origin(origin + "/") == origin
    assert _git_sha(sha.upper()) == sha
    assert _headers("opaque-token")["x-vercel-trusted-oidc-idp-token"] == "opaque-token"
    fake_claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "https://github.com/koreaelonmusk",
        "sub": "repo:koreaelonmusk/proofos:ref:refs/heads/main",
        "repository": "koreaelonmusk/proofos",
        "repository_id": "1341515802",
        "repository_owner": "koreaelonmusk",
        "repository_owner_id": "44775845",
        "ref": "",
        "ref_type": "branch",
        "workflow": "Vercel Live Smoke Evidence",
        "workflow_ref": "koreaelonmusk/proofos/.github/workflows/vercel-live-smoke.yml@refs/heads/main",
        "workflow_sha": sha,
        "event_name": "deployment_status",
        "runner_environment": "github-hosted",
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(fake_claims, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    projected = _oidc_claim_projection(f"e30.{payload}.sig")
    assert projected["aud"] == "https://github.com/koreaelonmusk"
    assert "ref" not in projected
    assert (
        _trusted_source_error_code(
            b'{"error":{"code":"TRUSTED_SOURCES_OIDC_DISCOVERY_FAILED","message":"secret detail"}}'
        )
        == "TRUSTED_SOURCES_OIDC_DISCOVERY_FAILED"
    )
    assert _trusted_source_error_code(b'{"code":"SOME_OTHER_ERROR"}') is None
    assert _trusted_source_error_code(b"not-json") is None

    for invalid in (
        "http://proofos.vercel.app",
        "https://example.com",
        "https://proofos.vercel.app/path",
    ):
        try:
            _origin(invalid)
        except TrustedSourceProbeError:
            continue
        raise AssertionError("unsafe origin accepted")

    print("Vercel trusted-source probe self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--github-deployment-id", default="")
    parser.add_argument("--github-deployment-status-id", default="")
    parser.add_argument("--github-environment", default="")
    parser.add_argument("--environment-url", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if not args.url or args.output is None:
        parser.error("--url and --output are required unless --self-test is used")

    try:
        binding = _event_binding(
            deployment_id=args.github_deployment_id,
            deployment_status_id=args.github_deployment_status_id,
            environment=args.github_environment,
            environment_url=args.environment_url,
            source_git_sha=args.expected_git_sha,
        )
        evidence = observe(
            args.url,
            oidc_token=os.environ.get("VERCEL_TRUSTED_OIDC_TOKEN", ""),
            timeout=args.timeout,
            source_git_sha=args.expected_git_sha,
            deployment_event=binding,
        )
    except TrustedSourceProbeError as exc:
        print(f"Vercel trusted-source probe FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Vercel trusted-source probe: {evidence['outcome']}")
    print(f"evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
