"""Inbound identity boundary for a Vercel-hosted collector."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from proofos_collector.caller_auth import (
    CALLER_AUDIENCE_ENV,
    CALLER_SERVICE_ACCOUNT_ENV,
    CallerAuthenticationError,
    CallerAuthConfig,
    CallerAuthConfigurationError,
    verify_google_caller,
)

AUDIENCE = "https://proofos.example.vercel.app"
CALLER = "proofos-api@example.iam.gserviceaccount.com"
TOKEN = "opaque-google-id-token"


class CallerAuthConfigurationTests(unittest.TestCase):
    def test_configuration_requires_exact_origin_and_service_account(self):
        config = CallerAuthConfig.from_env(
            {
                CALLER_AUDIENCE_ENV: AUDIENCE + "/",
                CALLER_SERVICE_ACCOUNT_ENV: CALLER,
            }
        )
        self.assertEqual(config.audience, AUDIENCE)
        self.assertEqual(config.service_account, CALLER)

        for bad_audience in (
            "",
            "http://proofos.example.vercel.app",
            "https://collector.example.com",
            AUDIENCE + "/v1/collect",
            AUDIENCE + "?debug=1",
            "https://user:pass@proofos.example.vercel.app",
        ):
            with self.subTest(audience=bad_audience):
                with self.assertRaises(CallerAuthConfigurationError):
                    CallerAuthConfig.from_env(
                        {
                            CALLER_AUDIENCE_ENV: bad_audience,
                            CALLER_SERVICE_ACCOUNT_ENV: CALLER,
                        }
                    )

        with self.assertRaises(CallerAuthConfigurationError):
            CallerAuthConfig.from_env(
                {
                    CALLER_AUDIENCE_ENV: AUDIENCE,
                    CALLER_SERVICE_ACCOUNT_ENV: "not-a-service-account",
                }
            )

    def test_bearer_token_is_required(self):
        env = {
            CALLER_AUDIENCE_ENV: AUDIENCE,
            CALLER_SERVICE_ACCOUNT_ENV: CALLER,
        }
        for header in ("", "Basic abc", "Bearer", "Bearer a b"):
            with self.subTest(header=header):
                with self.assertRaises(CallerAuthenticationError):
                    verify_google_caller(header, env=env)


class CallerIdentityVerificationTests(unittest.TestCase):
    def test_valid_google_identity_is_pinned_to_audience_and_email(self):
        observed = {}

        def verifier(token, request, *, audience):
            observed["token"] = token
            observed["request"] = request
            observed["audience"] = audience
            return {
                "email": CALLER,
                "email_verified": True,
                "aud": audience,
            }

        marker = object()
        result = verify_google_caller(
            f"Bearer {TOKEN}",
            env={
                CALLER_AUDIENCE_ENV: AUDIENCE,
                CALLER_SERVICE_ACCOUNT_ENV: CALLER,
            },
            verifier=verifier,
            request_factory=lambda: marker,
        )
        self.assertEqual(observed["token"], TOKEN)
        self.assertIs(observed["request"], marker)
        self.assertEqual(observed["audience"], AUDIENCE)
        self.assertEqual(result, {"email": CALLER, "audience": AUDIENCE})

    def test_wrong_or_unverified_identity_is_refused(self):
        env = {
            CALLER_AUDIENCE_ENV: AUDIENCE,
            CALLER_SERVICE_ACCOUNT_ENV: CALLER,
        }
        claims = (
            {"email": "other@example.iam.gserviceaccount.com", "email_verified": True},
            {"email": CALLER, "email_verified": False},
            {},
        )
        for payload in claims:
            with self.subTest(payload=payload):
                with self.assertRaises(CallerAuthenticationError):
                    verify_google_caller(
                        f"Bearer {TOKEN}",
                        env=env,
                        verifier=lambda *_args, **_kwargs: payload,
                        request_factory=lambda: object(),
                    )

    def test_provider_failure_never_echoes_bearer_token(self):
        def broken(*_args, **_kwargs):
            raise RuntimeError(f"bad token {TOKEN}")

        with self.assertRaises(CallerAuthenticationError) as caught:
            verify_google_caller(
                f"Bearer {TOKEN}",
                env={
                    CALLER_AUDIENCE_ENV: AUDIENCE,
                    CALLER_SERVICE_ACCOUNT_ENV: CALLER,
                },
                verifier=broken,
                request_factory=lambda: object(),
            )
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertIn("RuntimeError", str(caught.exception))


class CollectorEndpointCallerGateTests(unittest.TestCase):
    def test_vercel_rejects_unauthenticated_before_probe_or_signing(self):
        import proofos_collector.app as module

        request = module.CollectRequest(
            execution_id="e",
            task_id="t",
            evidence_kind="runtime",
            profile_id="runtime-health-v1",
            request_nonce="n",
        )
        http_request = SimpleNamespace(headers={})

        with patch.dict(os.environ, {"VERCEL": "1"}, clear=False), patch.object(
            module,
            "READINESS_ISSUES",
            (),
        ), patch.object(
            module,
            "verify_google_caller",
            side_effect=CallerAuthenticationError("denied"),
        ) as verify, patch.object(module, "probe_health") as probe:
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(module.collect(request, http_request))

        self.assertEqual(caught.exception.status_code, 401)
        verify.assert_called_once()
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
