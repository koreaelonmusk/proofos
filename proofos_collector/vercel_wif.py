"""Vercel OIDC -> Google Workload Identity Federation for Cloud Run ID tokens.

This path exists so a Vercel-hosted caller can authenticate to an IAM-protected
Google Cloud service without a long-lived service-account key. The Vercel OIDC
subject token is exchanged by Google STS and then used only to request a
Google-signed ID token for the exact Cloud Run audience.

No token value is logged or included in an exception message.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from google.auth import identity_pool
from google.auth.transport.requests import AuthorizedSession

OIDC_TOKEN_ENV = "VERCEL_OIDC_TOKEN"
WIF_PROVIDER_ENV = "PROOFOS_GCP_WIF_PROVIDER"
SERVICE_ACCOUNT_ENV = "PROOFOS_GCP_WIF_SERVICE_ACCOUNT"

SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_URL = "https://sts.googleapis.com/v1/token"
IAM_CREDENTIALS_BASE = "https://iamcredentials.googleapis.com/v1"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
REQUEST_TIMEOUT_SECONDS = 10.0


class WifConfigurationError(RuntimeError):
    """Raised before any network request when WIF configuration is incomplete."""


class WifExchangeError(RuntimeError):
    """Raised when Google cannot mint an ID token. Contains no credential data."""


@dataclass(frozen=True)
class VercelWifConfig:
    provider: str
    service_account: str
    oidc_token: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "VercelWifConfig":
        provider = env.get(WIF_PROVIDER_ENV, "").strip()
        service_account = env.get(SERVICE_ACCOUNT_ENV, "").strip()
        oidc_token = env.get(OIDC_TOKEN_ENV, "").strip()

        if not provider:
            raise WifConfigurationError(f"{WIF_PROVIDER_ENV} is required")
        if not provider.startswith("//iam.googleapis.com/projects/"):
            raise WifConfigurationError(f"{WIF_PROVIDER_ENV} is not a Google WIF provider")
        if "/locations/global/workloadIdentityPools/" not in provider or "/providers/" not in provider:
            raise WifConfigurationError(f"{WIF_PROVIDER_ENV} is not a Google WIF provider")

        if (
            not service_account
            or "@" not in service_account
            or "/" in service_account
            or "?" in service_account
            or "#" in service_account
        ):
            raise WifConfigurationError(f"{SERVICE_ACCOUNT_ENV} is invalid")

        if not oidc_token:
            raise WifConfigurationError(
                f"{OIDC_TOKEN_ENV} is unavailable; Vercel OIDC must be enabled"
            )

        return cls(
            provider=provider,
            service_account=service_account,
            oidc_token=oidc_token,
        )


class VercelOidcSupplier:
    """google-auth subject-token supplier backed by Vercel's short-lived token."""

    def __init__(self, token: str) -> None:
        self._token = token

    def get_subject_token(self, context, request=None) -> str:  # noqa: ANN001
        del context, request
        return self._token


def _validated_target_audience(target_audience: str) -> str:
    parts = urlsplit(target_audience)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise WifConfigurationError("Cloud Run target audience must be an HTTPS origin")
    return f"{parts.scheme}://{parts.netloc}"


def fetch_id_token(
    target_audience: str,
    *,
    env: Mapping[str, str],
    session_factory=AuthorizedSession,
) -> str:
    """Mint a Google-signed ID token without long-lived Google credentials."""

    audience = _validated_target_audience(target_audience)
    config = VercelWifConfig.from_env(env)

    credentials = identity_pool.Credentials(
        audience=config.provider,
        subject_token_type=SUBJECT_TOKEN_TYPE,
        token_url=TOKEN_URL,
        subject_token_supplier=VercelOidcSupplier(config.oidc_token),
        scopes=[CLOUD_PLATFORM_SCOPE],
    )
    session = session_factory(credentials)
    url = (
        f"{IAM_CREDENTIALS_BASE}/projects/-/serviceAccounts/"
        f"{config.service_account}:generateIdToken"
    )

    try:
        response = session.post(
            url,
            json={"audience": audience, "includeEmail": True},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - redact provider details by design
        raise WifExchangeError(
            f"Google IAM ID-token exchange failed ({type(exc).__name__})"
        ) from exc

    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise WifExchangeError("Google IAM ID-token exchange returned no token")
    return token
