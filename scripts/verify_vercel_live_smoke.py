"""Observe a live Vercel collector and write bounded smoke evidence.

This is an independent HTTP observation from the workflow runner. It proves only
that the endpoint answered the expected public health contract and returned the
allowlisted runtime provenance. It does not prove IAM policy, signing-key
durability, readiness, or end-to-end verification authority.
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

ALLOWED_RUNTIME_KEYS = {
    "platform",
    "environment",
    "deployment_id",
    "region",
    "url",
}
EXPECTED_TOP_LEVEL_KEYS = {"status", "service", "runtime"}


class SmokeFailure(RuntimeError):
    pass


def _validated_vercel_origin(raw: str) -> str:
    value = raw.strip()
    parts = urlsplit(value)
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
        raise SmokeFailure("deployment URL must be an exact https://*.vercel.app origin")
    return f"https://{parts.hostname.lower()}"


def _validated_health(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SmokeFailure("health response must be a JSON object")

    unexpected_top = sorted(set(payload) - EXPECTED_TOP_LEVEL_KEYS)
    if unexpected_top:
        raise SmokeFailure("health response contains unexpected public fields")

    if payload.get("status") != "ok":
        raise SmokeFailure("health status is not ok")
    if payload.get("service") != "proofos-collector":
        raise SmokeFailure("unexpected service identity")

    runtime = payload.get("runtime")
    if not isinstance(runtime, dict):
        raise SmokeFailure("runtime provenance is missing")

    unexpected_runtime = sorted(set(runtime) - ALLOWED_RUNTIME_KEYS)
    if unexpected_runtime:
        raise SmokeFailure("runtime provenance contains non-allowlisted fields")

    if runtime.get("platform") != "vercel":
        raise SmokeFailure("runtime platform is not vercel")

    deployment_id = runtime.get("deployment_id")
    if not isinstance(deployment_id, str) or not deployment_id.startswith("dpl_"):
        raise SmokeFailure("Vercel deployment id is missing or malformed")

    environment = runtime.get("environment")
    if environment not in {"production", "preview", "development"}:
        raise SmokeFailure("Vercel environment is missing or invalid")

    runtime_url = runtime.get("url")
    if runtime_url is not None:
        _validated_vercel_origin(runtime_url)

    return {
        "status": "ok",
        "service": "proofos-collector",
        "runtime": {key: runtime[key] for key in sorted(runtime) if key in ALLOWED_RUNTIME_KEYS},
    }


def _hash_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**evidence, "evidence_sha256": hashlib.sha256(canonical).hexdigest()}


def observe(
    origin: str,
    *,
    timeout: float = 10.0,
    bypass_secret: str = "",
    record_protection_block: bool = False,
) -> dict[str, Any]:
    origin = _validated_vercel_origin(origin)
    health_url = f"{origin}/healthz"
    headers = {
        "Accept": "application/json",
        "User-Agent": "proofos-live-smoke/1",
    }
    if bypass_secret:
        headers["x-vercel-protection-bypass"] = bypass_secret

    request = Request(health_url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(64 * 1024)
    except HTTPError as exc:
        if exc.code in {401, 403} and record_protection_block:
            return _hash_evidence(
                {
                    "schema_version": 1,
                    "kind": "vercel-live-smoke-observation",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "observer": "github-actions-http",
                    "target_origin": origin,
                    "health_url": health_url,
                    "http_status": exc.code,
                    "outcome": "BLOCKED_BY_DEPLOYMENT_PROTECTION",
                    "bypass_attempted": bool(bypass_secret),
                    "claim_boundary": [
                        "proves the deployment edge rejected the workflow request before application health was observed",
                        "does not prove the collector is healthy or unhealthy",
                        "does not expose or record the automation bypass secret",
                    ],
                }
            )
        raise SmokeFailure(f"health endpoint returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise SmokeFailure(f"health endpoint was unreachable: {type(exc.reason).__name__}") from exc

    if status != 200:
        raise SmokeFailure(f"health endpoint returned HTTP {status}")

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeFailure("health endpoint did not return valid UTF-8 JSON") from exc

    validated = _validated_health(payload)
    return _hash_evidence(
        {
            "schema_version": 1,
            "kind": "vercel-live-smoke-observation",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "observer": "github-actions-http",
            "target_origin": origin,
            "health_url": health_url,
            "http_status": 200,
            "outcome": "OBSERVED_HEALTH",
            "bypass_attempted": bool(bypass_secret),
            "observation": validated,
            "claim_boundary": [
                "proves the HTTPS health endpoint answered the expected public contract",
                "records only allowlisted runtime provenance exposed by the collector",
                "does not prove IAM policy, readiness, signing-key durability, or an end-to-end VERIFIED execution",
            ],
        }
    )


def _self_test() -> None:
    good = {
        "status": "ok",
        "service": "proofos-collector",
        "runtime": {
            "platform": "vercel",
            "environment": "preview",
            "deployment_id": "dpl_contract_test",
            "region": "icn1",
            "url": "https://proofos-preview.vercel.app",
        },
    }
    validated = _validated_health(good)
    assert validated["runtime"]["deployment_id"] == "dpl_contract_test"

    leaked = {
        **good,
        "runtime": {**good["runtime"], "token": "must-not-leak"},
    }
    try:
        _validated_health(leaked)
    except SmokeFailure:
        pass
    else:
        raise AssertionError("non-allowlisted runtime field was accepted")

    for invalid in (
        "http://proofos.vercel.app",
        "https://proofos.vercel.app/path",
        "https://example.com",
        "https://user:pass@proofos.vercel.app",
    ):
        try:
            _validated_vercel_origin(invalid)
        except SmokeFailure:
            continue
        raise AssertionError(f"unsafe deployment URL accepted: {invalid}")

    print("live smoke self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--record-protection-block", action="store_true")
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
            record_protection_block=args.record_protection_block,
        )
    except SmokeFailure as exc:
        print(f"live smoke FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if evidence["outcome"] == "OBSERVED_HEALTH":
        print(f"live smoke OK: {evidence['observation']['runtime']['deployment_id']}")
    else:
        print(f"live smoke recorded: {evidence['outcome']} (HTTP {evidence['http_status']})")
    print(f"evidence: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
