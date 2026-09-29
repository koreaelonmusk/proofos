"""Inbound caller authentication for the Vercel-hosted collector.

The ProofOS API already calls remote collectors with a Google-signed OIDC ID
token. A Vercel collector must verify that token before exercising signing
authority; network reachability is not identity.

This module never logs or returns bearer-token material.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from urllib.parse import urlsplit

import google.auth.transport.requests
import google.oauth2.id_token

CALLER_AUDIENCE_ENV = "PROOFOS_COLLECTOR_CALLER_AUDIENCE"
CALLER_SERVICE_ACCOUNT_ENV = "PROOFOS_COLLECTOR_CALLER_SERVICE_ACCOUNT"

SERVICE_ACCOUNT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*@"
    r"[A-Za-z0-9][A-Za-z0-9.-]*\.iam\.gserviceaccount\.com$"
)


class CallerAuthConfigurationError(RuntimeError):
    """Raised when the collector cannot identify who is allowed to call it."""


class CallerAuthenticationError(RuntimeError):
    """Raised for missing, invalid, or unauthorized caller identity."""


@dataclass(frozen=True)
class CallerAuthConfig:
    audience: str
    service_account: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "CallerAuthConfig":
        audience = env.get(CALLER_AUDIENCE_ENV, "").strip()
        service_account = env.get(CALLER_SERVICE_ACCOUNT_ENV, "").strip()

        parts = urlsplit(audience)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
        ):
            raise CallerAuthConfigurationError(
                f"{CALLER_AUDIENCE_ENV} must be an exact HTTPS origin"
            )

        if SERVICE_ACCOUNT_RE.fullmatch(service_account) is None:
            raise CallerAuthConfigurationError(
                f"{CALLER_SERVICE_ACCOUNT_ENV} is invalid"
            )

        return cls(
            audience=f"{parts.scheme}://{parts.netloc}",
            service_account=service_account.lower(),
        )


def _bearer_token(authorization: str) -> str:
    scheme, separator, token = authorization.strip().partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not token.strip()
        or " " in token.strip()
    ):
        raise CallerAuthenticationError("Google OIDC bearer token is required")
    return token.strip()


def verify_google_caller(
    authorization: str,
    *,
    env: Mapping[str, str],
    verifier=google.oauth2.id_token.verify_oauth2_token,
    request_factory=google.auth.transport.requests.Request,
) -> dict:
    """Verify Google signature/audience and pin the allowed service identity."""

    config = CallerAuthConfig.from_env(env)
    token = _bearer_token(authorization)

    try:
        claims = verifier(
            token,
            request_factory(),
            audience=config.audience,
        )
    except Exception as exc:  # noqa: BLE001 - provider details are redacted
        raise CallerAuthenticationError(
            f"Google caller identity verification failed ({type(exc).__name__})"
        ) from exc

    if not isinstance(claims, dict):
        raise CallerAuthenticationError("Google caller identity carried no claims")

    email = claims.get("email")
    if not isinstance(email, str) or email.lower() != config.service_account:
        raise CallerAuthenticationError("Google caller identity is not authorized")

    if claims.get("email_verified") is not True:
        raise CallerAuthenticationError("Google caller email is not verified")

    return {
        "email": config.service_account,
        "audience": config.audience,
    }
