# Live launch gates

The public evidence console replays recorded executions. A successful Vercel
build or `/healthz` response does not prove live verification is configured.

## Collector configuration gate

`GET /healthz` reports process liveness. `GET /readyz` returns 200 only when the
loaded configuration has an explicit signing-key file and observation target,
automatic key creation is disabled, and the probe timeout is finite and positive.
Otherwise it returns 503 with stable issue codes and `Cache-Control: no-store`.
It exposes neither key material nor target URLs. Readiness uses a startup snapshot;
changing environment variables requires a process restart.

On Vercel (`VERCEL`) and Cloud Run (`K_SERVICE`), `/v1/collect` refuses requests
with 503 while configuration is incomplete. Local test harnesses retain their
existing ephemeral-key behavior. Invalid configured key files still fail startup.

This gate does **not** prove key-storage durability, target reachability, IAM
policy, or verifier trust. Do not interpret `ready` as an end-to-end launch pass.

## Required live verification

1. Confirm the intended GCP project and observation URL with the operator.
2. Reuse the existing Secret Manager signing-key mount. Never replace the signing
   identity to make a deployment pass. Do not store private keys in the repository.
3. Confirm separate collector/API identities, authenticated invocation, and the
   API's independently configured verification key.
4. Confirm anonymous collection is denied by Cloud Run IAM. Vercel configuration
   readiness is not a replacement for caller authentication.
5. Collect and verify an observation with a fresh nonce. Confirm tampering,
   nonce replay, and wrong-profile evidence are rejected.
6. Restart the services and verify previously recorded evidence using the same
   configured public key and durable journal.
7. Record commit, revision, exact commands, exit codes, and non-secret results.

Local regression command:

```sh
python -m unittest tests.test_collector_readiness tests.test_collector_service -v
```

The historical Cloud Run record is `artifacts/cloud-proof.json`; it is not a
substitute for rerunning the launch checks against the current deployment.

## Vercel live trust evidence

Every successful Vercel deployment now triggers two independent HTTP evidence
collectors.

- `verify_vercel_live_smoke.py` proves the public health contract and runtime
  provenance, including Git SHA binding.
- `verify_vercel_live_trust.py` records the authority-plane surface:
  `/readyz` and an unauthenticated `POST /v1/collect`.

The trust evidence distinguishes three states instead of collapsing them:

- `READY_AND_ANONYMOUS_DENIED`: readiness returned HTTP 200 with no issues,
  and the application itself denied anonymous collection with HTTP 401.
- `CONFIG_NOT_READY_AND_ANONYMOUS_DENIED`: readiness returned HTTP 503 with
  stable issue codes, while anonymous collection was still denied before probe
  or signing authority.
- `READINESS_BLOCKED_AND_ANONYMOUS_DENIED`: readiness could not be observed
  through the Vercel edge, but the application-level anonymous collection denial
  was reached and proved.
- `BLOCKED_BY_DEPLOYMENT_PROTECTION`: the Vercel edge blocked both probes, so
  application readiness and caller-auth behavior were not observed.

A not-ready collector is not described as unhealthy. It is evidence that the
runtime correctly refused live authority because its configuration gate did not
pass. The workflow never records bearer tokens, WIF tokens, signing keys,
observation target URLs, or Vercel automation bypass secrets.

Before upload, `verify_live_evidence_pair.py` independently validates both
artifacts again and requires them to name the same exact Vercel origin and the
same full workflow source Git SHA. It then derives a pair digest from the two
constituent evidence hashes. Individually valid artifacts from different
deployments therefore cannot be presented as one observation set.

## Explicit live model selection

`PROOFOS_GEMINI_MODEL` selects the model used by all three live ADK roles.
When unset, the existing `gemini-3.5-flash` default is preserved; an empty value
fails startup. `/config` and execution metadata report the selected model.
This setting does not enable Gemini mode, grant credentials, or provide an
automatic fallback. A provider outage still ends in ABSTAIN. Before switching
production, validate the chosen model's availability and tool-calling behavior
against the complete authenticated execution path.

Temporary Gemini server failures (HTTP 500, 502, 503, or 504) are retried twice
with bounded 5 and 10 second delays. Other client and authentication failures
are not retried. Exhaustion still ends in ABSTAIN; it never changes the verdict
or switches to an unconfigured model.
