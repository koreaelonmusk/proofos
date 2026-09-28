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
