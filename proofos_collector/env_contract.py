"""Least-privilege environment contract for the ProofOS collector.

The collector is an authority plane, not a general application runtime. Giving it
model, journal, or verifier configuration expands the blast radius of a
collector compromise without helping it observe or sign evidence.

This module classifies names only. It never reads or prints secret values.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping

TRUTHY = frozenset({"1", "true", "yes", "on"})

COLLECTOR_REQUIRED_LIVE = frozenset(
    {
        "PROOFOS_COLLECTOR_PRIVATE_KEY_FILE",
        "PROOFOS_COLLECTOR_TARGET",
    }
)

COLLECTOR_OPTIONAL = frozenset(
    {
        "PROOFOS_COLLECTOR_ID",
        "PROOFOS_COLLECTOR_TIMEOUT",
        "PROOFOS_COLLECTOR_PUBKEY_FILE",
        "PROOFOS_COLLECTOR_TARGET_REQUIRES_AUTH",
    }
)

# Static metadata required for Vercel -> Google Workload Identity Federation.
# VERCEL_OIDC_TOKEN is platform-managed by Vercel and is never user configuration.
VERCEL_WIF_CONFIGURATION = frozenset(
    {
        "PROOFOS_GCP_WIF_PROVIDER",
        "PROOFOS_GCP_WIF_SERVICE_ACCOUNT",
    }
)

# Vercel exposes VERCEL_OIDC_TOKEN as a system environment variable. It is
# classified separately so it cannot be confused with a team-managed secret.
PLATFORM_MANAGED_ENVIRONMENT = frozenset(
    {
        "VERCEL",
        "VERCEL_ENV",
        "VERCEL_TARGET_ENV",
        "VERCEL_OIDC_TOKEN",
        "K_SERVICE",
    }
)

# These belong to the API/model/journal/verifier side of ProofOS. Their
# presence in the collector is configuration bleed even when the value is not
# itself a secret.
FOREIGN_SERVICE_CONFIGURATION = frozenset(
    {
        "PROOFOS_AGENT_RUNTIME",
        "PROOFOS_GEMINI_MODEL",
        "PROOFOS_GEMINI_TURN_DELAY_SECONDS",
        "PROOFOS_JOURNAL_BACKEND",
        "PROOFOS_FIRESTORE_PROJECT",
        "PROOFOS_FIRESTORE_DATABASE",
        "PROOFOS_COLLECTOR_URL",
        "PROOFOS_COLLECTOR_PUBLIC_KEY",
        "PROOFOS_COLLECTOR_PUBLIC_KEY_FILE",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
    }
)

# Model credentials have no legitimate purpose in the collector on any
# platform.
FORBIDDEN_MODEL_CREDENTIALS = frozenset(
    {
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
    }
)

# On Vercel the collector must use the platform OIDC token for GCP federation,
# never a long-lived service-account credential file.
VERCEL_FORBIDDEN_CREDENTIALS = frozenset({"GOOGLE_APPLICATION_CREDENTIALS"})


def _present(env: Mapping[str, str], name: str) -> bool:
    return bool(env.get(name, "").strip())


def _truthy(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in TRUTHY


def collector_boundary_issues(env: Mapping[str, str]) -> tuple[str, ...]:
    """Return stable issue codes without revealing values or variable names."""

    issues: list[str] = []

    if any(_present(env, name) for name in FORBIDDEN_MODEL_CREDENTIALS):
        issues.append("model_credential_present")

    if any(_present(env, name) for name in FOREIGN_SERVICE_CONFIGURATION):
        issues.append("foreign_service_configuration_present")

    if _present(env, "VERCEL") and any(
        _present(env, name) for name in VERCEL_FORBIDDEN_CREDENTIALS
    ):
        issues.append("static_google_credentials_forbidden_on_vercel")

    if _present(env, "VERCEL") and _truthy(
        env, "PROOFOS_COLLECTOR_TARGET_REQUIRES_AUTH"
    ):
        # The runtime subject token is request-scoped, so startup readiness can
        # validate only the static federation metadata.
        if not all(_present(env, name) for name in VERCEL_WIF_CONFIGURATION):
            issues.append("vercel_wif_not_configured")

    return tuple(issues)


def contract_document() -> dict[str, object]:
    """A machine-readable contract safe for CI logs and documentation tooling."""

    return {
        "collector_required_live": sorted(COLLECTOR_REQUIRED_LIVE),
        "collector_optional": sorted(COLLECTOR_OPTIONAL),
        "vercel_wif_configuration": sorted(VERCEL_WIF_CONFIGURATION),
        "platform_managed_environment": sorted(PLATFORM_MANAGED_ENVIRONMENT),
        "foreign_service_configuration": sorted(FOREIGN_SERVICE_CONFIGURATION),
        "forbidden_model_credentials": sorted(FORBIDDEN_MODEL_CREDENTIALS),
        "vercel_forbidden_credentials": sorted(VERCEL_FORBIDDEN_CREDENTIALS),
        "rules": {
            "private_signing_key": "file-path-only; never inline environment key material",
            "vercel_gcp_auth": "short-lived Vercel OIDC -> Google WIF; no service-account key file",
            "collector_scope": "observation and signing only; no model, journal, or verifier capability",
            "runtime_oidc_source": "VERCEL_OIDC_TOKEN platform system environment, never caller configuration",
        },
    }


def validate_contract() -> None:
    """Refuse an ambiguous contract before it reaches a deployment."""

    collector_names = COLLECTOR_REQUIRED_LIVE | COLLECTOR_OPTIONAL
    forbidden_names = (
        FOREIGN_SERVICE_CONFIGURATION
        | FORBIDDEN_MODEL_CREDENTIALS
        | VERCEL_FORBIDDEN_CREDENTIALS
    )
    overlap = collector_names & forbidden_names
    if overlap:
        raise RuntimeError(f"collector environment contract overlaps: {sorted(overlap)}")

    if "PROOFOS_COLLECTOR_PRIVATE_KEY_FILE" not in COLLECTOR_REQUIRED_LIVE:
        raise RuntimeError("collector private key file stopped being a live requirement")

    classified_environment = (
        collector_names
        | VERCEL_WIF_CONFIGURATION
        | PLATFORM_MANAGED_ENVIRONMENT
        | forbidden_names
    )
    if "PROOFOS_COLLECTOR_PRIVATE_KEY" in classified_environment:
        raise RuntimeError("inline collector private key environment variables are forbidden")

    if "VERCEL_OIDC_TOKEN" not in PLATFORM_MANAGED_ENVIRONMENT:
        raise RuntimeError("Vercel build/local OIDC environment token is not classified")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate the static contract")
    parser.add_argument("--json", action="store_true", help="print the contract as JSON")
    args = parser.parse_args(argv)

    validate_contract()
    if args.json:
        print(json.dumps(contract_document(), indent=2, sort_keys=True))
    elif args.check:
        print("collector environment contract OK")
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
