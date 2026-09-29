"""Public, non-secret runtime provenance for deployed collectors.

Only platform-owned identifiers from a strict allowlist are surfaced. This
module must never read arbitrary application configuration or credentials.
"""

from __future__ import annotations

from collections.abc import Mapping


def _clean(value: str | None, *, max_length: int = 200) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value or len(value) > max_length:
        return None
    return value


def public_runtime_provenance(env: Mapping[str, str]) -> dict[str, str]:
    """Return a minimal, public-safe description of the running deployment."""
    if env.get("VERCEL"):
        result = {
            "platform": "vercel",
            "environment": _clean(env.get("VERCEL_ENV")),
            "deployment_id": _clean(env.get("VERCEL_DEPLOYMENT_ID")),
            "region": _clean(env.get("VERCEL_REGION")),
        }
        url = _clean(env.get("VERCEL_URL"))
        if url:
            result["url"] = f"https://{url}"
        return {key: value for key, value in result.items() if value is not None}

    revision = _clean(env.get("K_REVISION"))
    service = _clean(env.get("K_SERVICE"))
    if service or revision:
        result = {
            "platform": "cloud-run",
            "service": service,
            "revision": revision,
        }
        return {key: value for key, value in result.items() if value is not None}

    return {"platform": "local"}
