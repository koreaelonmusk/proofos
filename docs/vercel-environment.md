# Vercel collector environment boundary

Vercel deploys only `proofos_collector.app:app`. Treat that deployment as an
observer/signing authority, not as a copy of the ProofOS API runtime.

The rule is simple:

> Give the collector only the capabilities required to observe and sign.

The executable source of truth is `proofos_collector/env_contract.py`. CI runs
`python -m proofos_collector.env_contract --check` so this document cannot be
quietly weakened by an ambiguous variable classification.

## Collector variables

### Required for live collection

| Variable | Classification | Purpose |
| --- | --- | --- |
| `PROOFOS_COLLECTOR_PRIVATE_KEY_FILE` | secret-file path | Stable Ed25519 signing identity. The private key value is never accepted inline. |
| `PROOFOS_COLLECTOR_TARGET` | configuration | Approved observation target. |

### Optional

| Variable | Purpose |
| --- | --- |
| `PROOFOS_COLLECTOR_ID` | Stable collector identifier. |
| `PROOFOS_COLLECTOR_TIMEOUT` | Positive finite probe timeout. |
| `PROOFOS_COLLECTOR_PUBKEY_FILE` | Local/deployment convenience for publishing the public half. |
| `PROOFOS_COLLECTOR_TARGET_REQUIRES_AUTH` | Require an identity token when probing the target. |

`PROOFOS_COLLECTOR_CREATE_KEY` is a local bootstrap flag only. A cloud runtime
that sees it enabled remains not-ready. A failed secret mount must never be
answered by minting a new signing identity.

## Forbidden capability bleed

The Vercel collector must not receive model credentials or configuration owned
by the API, journal, or verifier plane. Examples include:

- `GOOGLE_API_KEY`
- `GEMINI_API_KEY`
- `PROOFOS_AGENT_RUNTIME`
- `PROOFOS_GEMINI_MODEL`
- `PROOFOS_GEMINI_TURN_DELAY_SECONDS`
- `PROOFOS_JOURNAL_BACKEND`
- `PROOFOS_FIRESTORE_PROJECT`
- `PROOFOS_FIRESTORE_DATABASE`
- `PROOFOS_COLLECTOR_URL`
- `PROOFOS_COLLECTOR_PUBLIC_KEY`
- `PROOFOS_COLLECTOR_PUBLIC_KEY_FILE`
- `GOOGLE_GENAI_USE_VERTEXAI`
- `GOOGLE_CLOUD_PROJECT`
- `GOOGLE_CLOUD_LOCATION`

A non-empty value from either forbidden class is a readiness failure. The
readiness response contains only stable issue codes; it never echoes variable
values.

## Vercel -> Google without a service-account key

When the observation target is private Google Cloud Run, a Vercel-hosted
collector can use Vercel's platform-issued OIDC token as the external subject
token for Google Workload Identity Federation.

Required configuration:

| Variable | Source |
| --- | --- |
| `VERCEL_OIDC_TOKEN` | Vercel system environment; short-lived platform token |
| `PROOFOS_GCP_WIF_PROVIDER` | Google workload identity provider resource name |
| `PROOFOS_GCP_WIF_SERVICE_ACCOUNT` | Service account allowed to mint the Cloud Run ID token |

The path is:

```text
Vercel OIDC
   |
   v
Google STS / Workload Identity Federation
   |
   v
IAM Credentials generateIdToken
   |
   v
Google-signed ID token, audience = exact Cloud Run origin
```

The Vercel federation helper accepts only `https://*.run.app` origins. It will
not mint or forward a Google identity token to an arbitrary HTTPS host. If a
future deployment uses a Cloud Run custom domain, add that trust surface
explicitly with its own validation and tests rather than weakening this rule.

Vercel supplies `VERCEL_OIDC_TOKEN` as a platform system environment variable.
It is not a team-managed ProofOS secret and must never be copied into Shared
Environment Variables. The collector reads only this platform value; callers
cannot supply or override the federation subject token through the request body.

The external principal needs only `iam.serviceAccounts.getOpenIdToken` on the
selected service account. Prefer Google's narrow
`roles/iam.serviceAccountOpenIdTokenCreator` role when this is the only token
operation required.

The Google workload identity provider must also validate the Vercel token's
issuer/audience and restrict who may federate. Do not create a provider that
accepts every token from the team. Bind the provider to the intended Vercel
issuer and allowed audience, map the project/environment claims, and use an
attribute condition that admits only the ProofOS project and intended deployment
environment. Google's STS remains the authority that validates the signed Vercel
JWT; ProofOS does not parse an unverified JWT and make authorization decisions
from its claims.

This matters because the platform `VERCEL_OIDC_TOKEN` carries Vercel's normal
project identity audience. If the Google provider expects a different audience,
the exchange must fail closed. Configure Google's allowed audience to the
audience issued for this Vercel project/team rather than weakening validation or
introducing a static Google credential.

On Vercel, `GOOGLE_APPLICATION_CREDENTIALS` is rejected by the collector
boundary. A long-lived service-account key would recreate the secret-management
problem that federation removes.

Cloud Run keeps its existing metadata-server path. The WIF path is selected only
when `VERCEL` is present.

## Signing-key boundary remains separate

OIDC removes the need for a static **Google** credential. It does not solve the
collector's **Ed25519 signing identity**.

ProofOS deliberately accepts only a private-key file path for signing. Do not
turn the PEM into a Shared Environment Variable to make a Vercel deployment
green. If the runtime cannot provision the stable signing key as a protected
file, `/readyz` should stay 503 and live collection should stay disabled.

For the proven authority plane, Cloud Run + Secret Manager remains the reference
deployment because it supplies a durable private-key file and per-service IAM
identity without widening the collector's capabilities.

## Vercel dashboard policy

For team Shared Environment Variables:

1. Prefer **Selected Projects** over applying secrets to every project.
2. Link ProofOS collector only to the collector variables above.
3. Mark API keys, tokens, and other secret values as **Sensitive**.
4. Keep Production and Preview credentials separate.
5. Do not share the production ProofOS signing identity with Preview.
6. Never add an inline `PROOFOS_COLLECTOR_PRIVATE_KEY` variable.
7. After changing environment variables, redeploy/restart before evaluating
   `/readyz`; readiness is intentionally snapshotted at process startup.

For an authenticated target on Vercel, startup readiness also requires the
platform-provided `VERCEL_OIDC_TOKEN`. If it is unavailable, `/readyz` returns
503 with `vercel_oidc_token_unavailable`; the collector never falls back to an
anonymous probe or a static Google key.

The public `/healthz` endpoint proves process liveness only. `/readyz` proves
that the collector configuration passed the local launch gate. Neither endpoint
alone proves IAM policy, target reachability, signing-key durability, or an
end-to-end VERIFIED execution.
