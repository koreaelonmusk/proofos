"""Observe the live Vercel collector trust surface and write bounded evidence.

This probe answers two questions that /healthz cannot:

1. Is the deployed collector configuration ready to exercise live authority?
2. Can an unauthenticated caller reach /v1/collect?

A configuration that is intentionally not ready is recorded as evidence rather
than mislabeled as an outage. An application-reached anonymous collect request
must be denied with HTTP 401; any other application response fails the probe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

EXPECTED_READY_KEYS = {"status", "service", "issues"}
ALLOWED_READY_STATUSES = {"ready", "not_ready"}
PROTECTION_STATUSES = {401, 403}


class TrustSmokeFailure(RuntimeError):
    pass


def _validated_vercel_origin(raw: str) -> str:
    parts = urlsplit(raw.strip())
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
        raise TrustSmokeFailure(
            "deployment URL must be an exact https://*.vercel.app origin"
        )
    return f"https://{parts.hostname.lower()}"


def _validated_git_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise TrustSmokeFailure("expected git SHA is not a full 40-character SHA")
    return value


def _validated_ready_payload(payload: Any, http_status: int) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TrustSmokeFailure("readiness response must be a JSON object")
    if set(payload) != EXPECTED_READY_KEYS:
        raise TrustSmokeFailure("readiness response contains unexpected public fields")
    if payload.get("service") != "proofos-collector":
        raise TrustSmokeFailure("unexpected readiness service identity")

    status = payload.get("status")
    if status not in ALLOWED_READY_STATUSES:
        raise TrustSmokeFailure("unknown readiness status")

    issues = payload.get("issues")
    if not isinstance(issues, list) or any(not isinstance(item, str) for item in issues):
        raise TrustSmokeFailure("readiness issues must be a list of stable strings")
    if any(len(item) > 120 for item in issues):
        raise TrustSmokeFailure("readiness issue exceeds the public contract")

    if status == "ready":
        if http_status != 200 or issues:
            raise TrustSmokeFailure("ready response is inconsistent")
    else:
        if http_status != 503:
            raise TrustSmokeFailure("not_ready response must use HTTP 503")

    return {
        "status": status,
        "service": "proofos-collector",
        "issues": sorted(issues),
    }


def _headers(bypass_secret: str) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "proofos-live-trust-smoke/1",
    }
    if bypass_secret:
        headers["x-vercel-protection-bypass"] = bypass_secret
    return headers


def _read_json_error(exc: HTTPError) -> Any:
    try:
        raw = exc.read(64 * 1024)
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError):
        return None


def _observe_readiness(
    origin: str,
    *,
    timeout: float,
    bypass_secret: str,
) -> dict[str, Any]:
    request = Request(f"{origin}/readyz", headers=_headers(bypass_secret))
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(64 * 1024)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise TrustSmokeFailure("readiness did not return valid JSON") from exc
            validated = _validated_ready_payload(payload, response.status)
            return {
                "outcome": "READY",
                "http_status": response.status,
                "observation": validated,
            }
    except HTTPError as exc:
        payload = _read_json_error(exc)
        if exc.code == 503 and payload is not None:
            validated = _validated_ready_payload(payload, exc.code)
            return {
                "outcome": "CONFIG_NOT_READY",
                "http_status": exc.code,
                "observation": validated,
            }
        if exc.code in PROTECTION_STATUSES and payload is None:
            return {
                "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
                "http_status": exc.code,
            }
        raise TrustSmokeFailure(
            f"unexpected readiness HTTP status {exc.code}"
        ) from exc
    except URLError as exc:
        raise TrustSmokeFailure(
            f"readiness endpoint unreachable: {type(exc.reason).__name__}"
        ) from exc


def _observe_anonymous_collect_denial(
    origin: str,
    *,
    timeout: float,
    bypass_secret: str,
) -> dict[str, Any]:
    body = json.dumps(
        {
            "execution_id": "smoke-no-authority",
            "task_id": "smoke-no-authority",
            "evidence_kind": "runtime",
            "profile_id": "runtime-health-v1",
            "request_nonce": "smoke-no-authority",
        }
    ).encode("utf-8")
    headers = {
        **_headers(bypass_secret),
        "Content-Type": "application/json",
    }
    request = Request(
        f"{origin}/v1/collect",
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            response.read(64 * 1024)
            raise TrustSmokeFailure(
                f"anonymous collection unexpectedly returned HTTP {response.status}"
            )
    except HTTPError as exc:
        payload = _read_json_error(exc)

        if exc.code == 401 and isinstance(payload, dict):
            if set(payload) != {"detail"}:
                raise TrustSmokeFailure(
                    "anonymous denial response contains unexpected public fields"
                )
            if payload.get("detail") != "collector caller authentication failed":
                raise TrustSmokeFailure("anonymous denial reason drifted")
            return {
                "outcome": "ANONYMOUS_COLLECTION_DENIED",
                "http_status": 401,
            }

        if exc.code in PROTECTION_STATUSES and payload is None:
            return {
                "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
                "http_status": exc.code,
            }

        raise TrustSmokeFailure(
            f"anonymous collection returned unexpected HTTP {exc.code}"
        ) from exc
    except URLError as exc:
        raise TrustSmokeFailure(
            f"collection endpoint unreachable: {type(exc.reason).__name__}"
        ) from exc


def _hash_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(
        evidence, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        **evidence,
        "evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def observe(
    origin: str,
    *,
    timeout: float = 10.0,
    bypass_secret: str = "",
    expected_git_sha: str = "",
) -> dict[str, Any]:
    origin = _validated_vercel_origin(origin)
    readiness = _observe_readiness(
        origin,
        timeout=timeout,
        bypass_secret=bypass_secret,
    )
    anonymous_collect = _observe_anonymous_collect_denial(
        origin,
        timeout=timeout,
        bypass_secret=bypass_secret,
    )

    application_reached = (
        readiness["outcome"] != "BLOCKED_BY_DEPLOYMENT_PROTECTION"
        or anonymous_collect["outcome"] != "BLOCKED_BY_DEPLOYMENT_PROTECTION"
    )

    if (
        application_reached
        and anonymous_collect["outcome"] != "ANONYMOUS_COLLECTION_DENIED"
    ):
        raise TrustSmokeFailure(
            "application was reachable but anonymous collection denial was not proven"
        )

    if (
        readiness["outcome"] == "BLOCKED_BY_DEPLOYMENT_PROTECTION"
        and anonymous_collect["outcome"] == "BLOCKED_BY_DEPLOYMENT_PROTECTION"
    ):
        outcome = "BLOCKED_BY_DEPLOYMENT_PROTECTION"
    elif readiness["outcome"] == "BLOCKED_BY_DEPLOYMENT_PROTECTION":
        outcome = "READINESS_BLOCKED_AND_ANONYMOUS_DENIED"
    elif readiness["outcome"] == "READY":
        outcome = "READY_AND_ANONYMOUS_DENIED"
    else:
        outcome = "CONFIG_NOT_READY_AND_ANONYMOUS_DENIED"

    return _hash_evidence(
        {
            "schema_version": 1,
            "kind": "vercel-live-trust-surface-observation",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "observer": "github-actions-http",
            "target_origin": origin,
            "workflow_source_git_sha": (
                _validated_git_sha(expected_git_sha) if expected_git_sha else None
            ),
            "bypass_attempted": bool(bypass_secret),
            "outcome": outcome,
            "readiness": readiness,
            "anonymous_collect": anonymous_collect,
            "claim_boundary": [
                "records whether the live collector configuration is ready or explicitly not ready",
                "proves anonymous collection is denied only when the application response is reached",
                "does not prove an authenticated end-to-end collection succeeds",
                "does not expose signing keys, bearer tokens, WIF tokens, target URLs, or bypass secrets",
            ],
        }
    )


def _self_test() -> None:
    ready = _validated_ready_payload(
        {"status": "ready", "service": "proofos-collector", "issues": []},
        200,
    )
    assert ready["status"] == "ready"

    not_ready = _validated_ready_payload(
        {
            "status": "not_ready",
            "service": "proofos-collector",
            "issues": ["signing_key_not_configured", "vercel_caller_auth_not_configured"],
        },
        503,
    )
    assert not_ready["status"] == "not_ready"

    for payload, status in (
        (
            {
                "status": "ready",
                "service": "proofos-collector",
                "issues": ["should_be_empty"],
            },
            200,
        ),
        (
            {"status": "ready", "service": "proofos-collector", "issues": [], "token": "x"},
            200,
        ),
        (
            {"status": "not_ready", "service": "proofos-collector", "issues": []},
            200,
        ),
    ):
        try:
            _validated_ready_payload(payload, status)
        except TrustSmokeFailure:
            continue
        raise AssertionError("invalid readiness contract was accepted")

    for invalid in (
        "http://proofos.vercel.app",
        "https://proofos.vercel.app/path",
        "https://example.com",
        "https://user:pass@proofos.vercel.app",
    ):
        try:
            _validated_vercel_origin(invalid)
        except TrustSmokeFailure:
            continue
        raise AssertionError(f"unsafe deployment URL accepted: {invalid}")

    print("live trust smoke self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if not args.url or not args.output:
        parser.error("--url and --output are required unless --self-test is used")

    try:
        evidence = observe(
            args.url,
            timeout=args.timeout,
            bypass_secret=os.environ.get("VERCEL_AUTOMATION_BYPASS_SECRET", ""),
            expected_git_sha=args.expected_git_sha,
        )
    except TrustSmokeFailure as exc:
        print(f"live trust smoke FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"live trust smoke: {evidence['outcome']}")
    print(f"evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
