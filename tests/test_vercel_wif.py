"""Collector environment isolation and Vercel -> GCP federation."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from proofos_collector.env_contract import (
    collector_boundary_issues,
    contract_document,
    validate_contract,
)
from proofos_collector.readiness import configuration_issues
from proofos_collector.vercel_wif import (
    CLOUD_PLATFORM_SCOPE,
    SERVICE_ACCOUNT_ENV,
    SUBJECT_TOKEN_TYPE,
    TOKEN_URL,
    WIF_PROVIDER_ENV,
    VercelOidcSupplier,
    WifExchangeError,
    fetch_id_token,
)


PROVIDER = (
    "//iam.googleapis.com/projects/123456789/locations/global/"
    "workloadIdentityPools/vercel/providers/proofos"
)
SERVICE_ACCOUNT = "proofos-vercel-caller@example.iam.gserviceaccount.com"
OIDC_TOKEN = "opaque-vercel-subject-token"
TARGET = "https://proofos-api-abc-uc.a.run.app"


class CollectorEnvironmentContractTests(unittest.TestCase):
    def test_contract_is_disjoint_and_machine_readable(self):
        validate_contract()
        document = contract_document()
        self.assertIn(
            "PROOFOS_COLLECTOR_PRIVATE_KEY_FILE",
            document["collector_required_live"],
        )
        self.assertIn("GOOGLE_API_KEY", document["forbidden_model_credentials"])
        self.assertIn(
            "PROOFOS_AGENT_RUNTIME",
            document["foreign_service_configuration"],
        )
        self.assertIn("PROOFOS_GCP_WIF_PROVIDER", document["vercel_wif_configuration"])
        self.assertIn(
            "PROOFOS_COLLECTOR_CALLER_SERVICE_ACCOUNT",
            document["vercel_caller_auth_configuration"],
        )
        self.assertIn("VERCEL_OIDC_TOKEN", document["platform_managed_environment"])

    def test_collector_rejects_foreign_capabilities_without_echoing_values(self):
        secret = "do-not-echo-this"
        issues = collector_boundary_issues(
            {
                "GOOGLE_API_KEY": secret,
                "PROOFOS_AGENT_RUNTIME": "gemini",
            }
        )
        self.assertEqual(
            issues,
            (
                "model_credential_present",
                "foreign_service_configuration_present",
            ),
        )
        self.assertNotIn(secret, repr(issues))

    def test_vercel_rejects_static_google_credentials(self):
        issues = collector_boundary_issues({
            "VERCEL": "1",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/service-account.json",
        })
        self.assertIn("static_google_credentials_forbidden_on_vercel", issues)

    def test_vercel_private_target_requires_short_lived_wif(self):
        base = {
            "VERCEL": "1",
            "PROOFOS_COLLECTOR_PRIVATE_KEY_FILE": "/run/secrets/collector.pem",
            "PROOFOS_COLLECTOR_TARGET": f"{TARGET}/health",
            "PROOFOS_COLLECTOR_TARGET_REQUIRES_AUTH": "true",
        }
        base_issues = configuration_issues(base)
        self.assertIn("vercel_wif_not_configured", base_issues)
        self.assertEqual(
            base_issues.count("vercel_oidc_token_unavailable"),
            1,
            "readiness issue codes must be stable and non-duplicated",
        )

        ready = {
            **base,
            WIF_PROVIDER_ENV: PROVIDER,
            SERVICE_ACCOUNT_ENV: SERVICE_ACCOUNT,
            "VERCEL_OIDC_TOKEN": OIDC_TOKEN,
            "PROOFOS_COLLECTOR_CALLER_AUDIENCE": "https://proofos.example.vercel.app",
            "PROOFOS_COLLECTOR_CALLER_SERVICE_ACCOUNT": SERVICE_ACCOUNT,
        }
        ready_issues = configuration_issues(ready)
        self.assertNotIn("vercel_wif_not_configured", ready_issues)
        self.assertNotIn("vercel_oidc_token_unavailable", ready_issues)
        self.assertNotIn("vercel_caller_auth_not_configured", ready_issues)


class VercelWorkloadIdentityTests(unittest.TestCase):
    def test_invalid_provider_and_service_account_fail_before_network(self):
        from proofos_collector.vercel_wif import VercelWifConfig, WifConfigurationError

        with self.assertRaises(WifConfigurationError):
            VercelWifConfig.from_env({
                WIF_PROVIDER_ENV: "https://example.com/not-a-provider",
                SERVICE_ACCOUNT_ENV: SERVICE_ACCOUNT,
            })
        with self.assertRaises(WifConfigurationError):
            VercelWifConfig.from_env({
                WIF_PROVIDER_ENV: PROVIDER,
                SERVICE_ACCOUNT_ENV: "not-an-email",
            })

    def test_id_token_audience_must_be_exact_https_origin(self):
        from proofos_collector.vercel_wif import WifConfigurationError, _validated_target_audience

        self.assertEqual(_validated_target_audience(TARGET), TARGET)
        self.assertEqual(_validated_target_audience(TARGET + "/"), TARGET)

        for invalid in (
            TARGET + "/health",
            TARGET + "?debug=1",
            TARGET + "#fragment",
            "http://proofos-api.example.com",
            "https://api.example.com",
            "https://user:pass@proofos-api.example.com",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(WifConfigurationError):
                    _validated_target_audience(invalid)

    def test_missing_runtime_oidc_token_fails_before_network(self):
        from proofos_collector.vercel_wif import WifConfigurationError

        with self.assertRaises(WifConfigurationError):
            fetch_id_token(
                TARGET,
                env={
                    WIF_PROVIDER_ENV: PROVIDER,
                    SERVICE_ACCOUNT_ENV: SERVICE_ACCOUNT,
                },
                subject_token="",
                session_factory=lambda _credentials: self.fail("network session created"),
            )

    def test_subject_supplier_returns_only_the_platform_token(self):
        supplier = VercelOidcSupplier(OIDC_TOKEN)
        self.assertEqual(supplier.get_subject_token(object()), OIDC_TOKEN)

    def test_exchange_requests_google_signed_id_token_and_app_uses_it(self):
        observed = {}

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {"token": "google-signed-id-token"}

        class Session:
            def __init__(self, credentials):
                observed["credentials"] = credentials

            def post(self, url, *, json, timeout):
                observed["url"] = url
                observed["json"] = json
                observed["timeout"] = timeout
                return Response()

        env = {
            WIF_PROVIDER_ENV: PROVIDER,
            SERVICE_ACCOUNT_ENV: SERVICE_ACCOUNT,
        }

        with patch(
            "proofos_collector.vercel_wif.identity_pool.Credentials"
        ) as factory:
            credentials = object()
            factory.return_value = credentials
            token = fetch_id_token(
                TARGET,
                env=env,
                subject_token=OIDC_TOKEN,
                session_factory=Session,
            )

        self.assertEqual(token, "google-signed-id-token")
        self.assertIs(observed["credentials"], credentials)
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["audience"], PROVIDER)
        self.assertEqual(kwargs["subject_token_type"], SUBJECT_TOKEN_TYPE)
        self.assertEqual(kwargs["token_url"], TOKEN_URL)
        self.assertEqual(kwargs["scopes"], [CLOUD_PLATFORM_SCOPE])
        self.assertEqual(
            kwargs["subject_token_supplier"].get_subject_token(object()),
            OIDC_TOKEN,
        )
        self.assertTrue(
            observed["url"].endswith(
                f"/serviceAccounts/{SERVICE_ACCOUNT}:generateIdToken"
            )
        )
        self.assertEqual(observed["json"]["audience"], TARGET)
        self.assertTrue(observed["json"]["includeEmail"])

        import proofos_collector.app as app_module

        with patch.dict(
            os.environ,
            {"VERCEL": "1", "VERCEL_OIDC_TOKEN": OIDC_TOKEN},
            clear=False,
        ), patch.object(
            app_module,
            "fetch_vercel_wif_id_token",
            return_value="google-signed-id-token",
        ) as fetch:
            self.assertEqual(
                app_module._identity_token_for(f"{TARGET}/health"),
                "google-signed-id-token",
            )
            fetch.assert_called_once_with(
                TARGET,
                env=os.environ,
                subject_token=OIDC_TOKEN,
            )

    def test_exchange_errors_never_echo_the_subject_token(self):
        class BrokenSession:
            def __init__(self, credentials):
                del credentials

            def post(self, url, *, json, timeout):
                del url, json, timeout
                raise RuntimeError(f"provider failed with {OIDC_TOKEN}")

        env = {
            WIF_PROVIDER_ENV: PROVIDER,
            SERVICE_ACCOUNT_ENV: SERVICE_ACCOUNT,
        }
        with self.assertRaises(WifExchangeError) as caught:
            fetch_id_token(
                TARGET,
                env=env,
                subject_token=OIDC_TOKEN,
                session_factory=BrokenSession,
            )

        self.assertNotIn(OIDC_TOKEN, str(caught.exception))
        self.assertIn("RuntimeError", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
