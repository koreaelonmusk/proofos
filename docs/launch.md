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

## Authenticated E2E workflow authorization

The manual `Authenticated E2E Evidence` workflow is subordinate to the sealed
live launch verdict. A deployment URL and a successful build are not authority.

The workflow is split into two GitHub Actions jobs with different authority.

The `authorize` job has only `contents: read` and `actions: read`. It has no
`id-token: write` permission and references no repository secrets. It verifies
that the supplied source run is a successfully completed
`Vercel Live Smoke Evidence` deployment-status run for the exact requested Git
SHA, downloads the sealed health/trust/manifest/verdict artifacts, and
independently re-verifies the bundle.

A direct verdict of `READY_FOR_AUTHENTICATED_E2E`, bound to the exact
requested Vercel origin and source SHA, authorizes the second
`privileged-e2e` job. A public `HOLD` can also authorize that next evidence
step only through a separate Trusted Promotion Proof. The proof is valid only
when the public HOLD is caused solely by Vercel Deployment Protection blocking
both public observations and a same-run Trusted Source independently proves
`TRUSTED_SOURCE_ACCEPTED_READY_AND_ANONYMOUS_DENIED` for the exact same
origin, Git SHA, GitHub deployment ID, deployment-status ID, production
environment, and main live-workflow identity. The public verdict itself remains
HOLD and is never rewritten.

The `privileged-e2e` job alone has `id-token: write`. After authorization,
GitHub OIDC is exchanged through Google Workload Identity Federation for a
short-lived service-account ID token. Stored caller bearer-token secrets and
service-account JSON keys remain forbidden. The ID-token audience comes from the
verified authorization output, not directly from the workflow-dispatch input.

The two identities are intentionally non-substitutable: GitHub OIDC grants only
the right to cross the Vercel Deployment Protection boundary, while the Google
ID token grants only the configured ProofOS application caller identity. Possession
of either token alone is insufficient for a successful authenticated collection.

When Deployment Protection is enabled, authenticated E2E uses two independent
short-lived identities instead of a static bypass secret. The privileged job
mints a GitHub Actions OIDC token and sends it only as Vercel's
`x-vercel-trusted-oidc-idp-token` edge-authentication header. Separately,
Google Workload Identity Federation mints the ProofOS caller ID token used in the
`Authorization: Bearer` header. The authenticated-E2E workflow contract forbids
`VERCEL_AUTOMATION_BYPASS_SECRET` and `x-vercel-protection-bypass` entirely.
Neither short-lived token is passed on the command line or persisted in evidence.

The workflow always checks out the current trusted verifier implementation.
`expected_git_sha` identifies the deployment under test and is verified against
the sealed evidence bundle; it is not used to roll the verifier code back to an
older deployment revision.

### Vercel Trusted Source diagnostic

The regular live-smoke job remains credential-free and continues to record what an
ordinary external observer can prove. A credential-free
`trusted-source-authorize` job first checks a successful production deployment
event, checks out full `main` history, and proves the deployed commit is contained
in `origin/main` with `git merge-base --is-ancestor`. Only its
`authorized=true` output can create the separate `trusted-source` job that has
job-local `id-token: write`. This avoids depending on provider-specific
`deployment.ref` formatting while preserving the main-only authority boundary.

That job follows Vercel's official Trusted Sources flow: GitHub Actions mints a
short-lived OIDC token, masks it immediately, and the probe sends it only as
`x-vercel-trusted-oidc-idp-token`. The token is never written to evidence,
workflow artifacts, or logs.

The diagnostic records one of:

- `TRUSTED_SOURCE_REJECTED`: Vercel's edge still returned 401/403. This is a
  configuration observation, not an application failure. When Vercel returns a
  bounded machine code in the `TRUSTED_SOURCES_*` namespace, the evidence may
  include only that code as `vercel_error_code`. Raw response bodies, provider
  messages, request metadata, and OIDC tokens are never persisted.
- `TRUSTED_SOURCE_ACCEPTED_NOT_READY_AND_ANONYMOUS_DENIED`: edge
  authentication succeeded, application readiness was reached and reported
  not-ready, and the same trusted-source path reached `/v1/collect` where
  ProofOS itself returned the exact anonymous caller-auth denial.
- `TRUSTED_SOURCE_ACCEPTED_READY_AND_ANONYMOUS_DENIED`: edge authentication
  succeeded, application health/readiness were observed as ready, and the same
  trusted-source path proved anonymous collection is denied before any probe or
  signing authority is exercised. This still does not prove an authenticated
  signed collection; that remains the next independent E2E gate.

The public smoke job has no `id-token: write`. The trusted OIDC authority is
isolated to this diagnostic job and is not reused as Google Cloud identity.

Accepted Trusted Source evidence is intentionally stronger than a successful
`/healthz` or `/readyz` response. After the edge accepts the GitHub OIDC token,
the probe also sends an application-anonymous `POST /v1/collect` using the same
edge identity but no ProofOS caller credential. The artifact is accepted only
when the response is exactly HTTP 401 with
`{"detail":"collector caller authentication failed"}`. Any other 401/403 is
treated as an edge/authentication ambiguity and the probe fails closed. No
collection probe or signing work can run in this anonymous request path.

For rejected Trusted Sources requests, the diagnostic may also persist a strict
non-secret projection of the GitHub OIDC payload: `iss`, `aud`, `sub`,
repository identifiers, `ref`, workflow identity, event name, and runner type.
GitHub can emit empty optional claims for event types such as
`deployment_status`; empty optional values are omitted instead of being treated
as an authentication failure. Issuer, audience, subject, and repository remain
mandatory.
The JWT signature and raw token are never persisted, and the projection is
diagnostic only. It is not used as authorization input. The independent artifact
verifier requires the GitHub Actions issuer, the ProofOS repository, and the
default repository-owner audience before accepting the projection.

GitHub may emit either the legacy repository subject prefix or its immutable-ID
form. ProofOS accepts only the two exact repository-bound shapes: the legacy
`repo:koreaelonmusk/proofos:` prefix, or an immutable prefix derived from the
separately verified `repository_owner_id` and `repository_id` claims. Arbitrary
owner/repository IDs or broader subject prefixes are rejected.

### Trusted Source follow-up diagnostic

Production evidence from run `36677450734` proved that the original
`deployment_status` Trusted Source job mints a GitHub OIDC token whose subject
can end in an empty ref segment (for example `...:ref:`). Vercel rejected that
token even though the ProofOS-side token projection was valid and safely bound to
the repository.

ProofOS therefore adds a second, diagnostic-only path:
`.github/workflows/vercel-trusted-source-followup.yml`. It is triggered only by
a successfully completed main-branch `Vercel Live Smoke Evidence` run. Its
credential-free authorization job re-verifies the source workflow identity,
downloads the exact run-scoped public evidence bundle, independently verifies the
launch verdict, and requires the deployment environment to be production.

Only after those checks does a separate job receive `id-token: write` and mint
a fresh GitHub OIDC identity from the main workflow-run context. The follow-up
probe uses the already sealed deployment origin, Git SHA, deployment ID and
deployment-status ID from the verified source run. This path does not rewrite
the original Trusted Source artifact and does not yet authorize Trusted
Promotion. It exists to prove whether changing only the GitHub OIDC event context
is enough for Vercel Trusted Sources to accept the request.

The original `deployment_status` path remains in place as a comparison control.
Static Vercel bypass secrets remain forbidden in the follow-up path.

### Provider capability diagnosis

Live follow-up run `36684524588` normalized the GitHub OIDC identity to
`ref:refs/heads/main` but Vercel still returned
`TRUSTED_SOURCE_REJECTED`. This disproves the empty-ref event-context
hypothesis for the observed deployment.

The follow-up workflow now compares the independently verified original
`deployment_status` Trusted Source artifact with the independently verified
`workflow_run` follow-up artifact for the exact same origin, Git SHA,
deployment ID and deployment-status ID. When both are rejected even though the
follow-up identity is main-ref bound, it emits a separate provider capability
diagnosis:

`PROVIDER_CONFIGURATION_REQUIRED / EVENT_CONTEXT_NOT_ROOT_CAUSE`

This diagnosis does not mutate provider settings and does not authorize
Authenticated E2E. It converts a previously ambiguous red path into bounded
evidence that the next unresolved dependency is Vercel project/provider trust
configuration.

A valid but non-promotable Trusted Source artifact is also a normal HOLD state.
The Authenticated E2E authorization workflow independently verifies the artifact
and exits green with `authorized=false` instead of treating provider rejection
as a code failure. Tampered, mismatched, or unverifiable artifacts remain hard
failures.

### Provider Admission Contract

The Provider Admission Contract is a non-authorizing evidence object that decides
whether the run-bound `workflow_run` Trusted Source observation is eligible to
become an input to Trusted Promotion.

It consumes four independently verifiable artifacts for one deployment:

- the original `deployment_status` Trusted Source observation;
- the main-ref `workflow_run` follow-up observation;
- the run-bound provider capability diagnosis;
- the exact source and follow-up workflow run IDs.

The contract emits one of three bounded states:

- `ADMITTED_FOR_TRUSTED_PROMOTION` only when the follow-up observation is
  `TRUSTED_SOURCE_ACCEPTED_READY_AND_ANONYMOUS_DENIED`, its OIDC identity is
  bound to the main follow-up workflow, and the diagnosis independently records
  `FOLLOWUP_TRUST_PATH_ACCEPTED`;
- `HOLD_TRUSTED_SOURCE_NOT_READY` when edge identity is accepted but the
  application is not ready;
- `HOLD_PROVIDER_CONFIGURATION_REQUIRED` while Vercel still rejects the
  follow-up identity.

This contract does not authorize privileged E2E, mint credentials, or rewrite
the public launch verdict. It only establishes whether follow-up evidence may be
used by a future Trusted Promotion bridge. The contract is independently
re-derived before persistence and contains no raw token or provider response
body.

### Trusted Promotion Proof

`build_trusted_promotion_proof.py` is a narrow authority bridge, not a second
launch verdict. It consumes five independently verifiable inputs from one
`Vercel Live Smoke Evidence` run: public health, public trust, the sealed
manifest, the public launch verdict, and the Trusted Source artifact.

It emits `AUTHORIZED_FOR_AUTHENTICATED_E2E` only when all of the following are
true:

- the public verdict is exactly `HOLD`;
- both public health and trust outcomes are
  `BLOCKED_BY_DEPLOYMENT_PROTECTION`;
- the HOLD has no readiness/configuration reason outside the edge-protection
  boundary;
- the Trusted Source outcome is exactly
  `TRUSTED_SOURCE_ACCEPTED_READY_AND_ANONYMOUS_DENIED`;
- both evidence planes bind the same origin, full Git SHA, deployment ID,
  deployment-status ID, and production environment;
- the Trusted Source OIDC projection is bound to the main
  `vercel-live-smoke.yml` deployment-status workflow.

The proof contains only hashes, deployment identity, the verified GitHub
source-run ID, bounded outcomes, and the next-evidence scope. It never contains
either OIDC token. The source-run ID is supplied only after the workflow has
verified the source run identity and downloaded every constituent through the
run-scoped artifact API. The independent `verify_trusted_promotion_proof.py`
requires the expected run ID and re-derives the proof from all five constituents
instead of trusting the producer. This closes cross-run splicing where two
reruns of the same deployment event could otherwise contribute individually
valid artifacts to one promotion.

The credential-free authorization job creates and independently verifies this
proof before it may return `authorized=true`. The privileged job then
downloads the original source-run artifacts again, rebuilds the Trusted
Promotion Proof from scratch, and requires the rebuilt SHA-256 to equal the hash
authorized by the credential-free job before minting either short-lived
identity. This prevents an authorization-time proof from being swapped before
use.

### Sequential trust pipeline

The automatic trust pipeline is serialized as:

`Vercel Live Smoke Evidence -> Vercel Trusted Source Follow-up -> Authenticated E2E Evidence`.

Authenticated E2E no longer subscribes directly to the live-smoke workflow.
Instead, a successful main-branch follow-up run must first publish exactly one
run-bound provider diagnosis artifact. The E2E authorization job resolves the
original live-smoke run ID from that artifact, downloads the original
Trusted Source evidence and follow-up Trusted Source evidence, and independently
re-verifies the provider diagnosis against both constituents before reading the
sealed live launch bundle.

The provider diagnosis schema binds both `source_run_id` and
`followup_run_id` into its SHA-256. This prevents a diagnosis from another
rerun from becoming an admission ticket. Manual recovery remains available and
continues to accept an explicitly supplied live-evidence run ID, but the
automatic path is strictly sequential.

### Trust Pipeline Receipt

Every Authenticated E2E authorization decision now emits a separate
`proofos-trust-pipeline-receipt`. The receipt is evidence, not authority. It
binds the original live-smoke run, optional Trusted Source follow-up run, current
Authenticated E2E run, deployment identity, Git SHA, manifest/verdict hashes,
authorization basis, optional Trusted Promotion hash, and provider diagnosis
hash into one canonical SHA-256.

Automatic receipts require the already independently verified provider diagnosis
and therefore bind all three workflow layers:

`source_run_id -> followup_run_id -> e2e_run_id`.

Manual recovery receipts are explicitly labeled `manual_recovery` and do not
pretend a follow-up diagnosis exists. The authorization result is persisted
separately and hashed into the receipt so an operator can independently
re-derive the exact decision without trusting workflow logs.

### Automatic authenticated-E2E promotion

The workflow also subscribes to completed `Vercel Live Smoke Evidence` runs.
Automatic promotion is accepted only when the source run completed successfully
and its `head_branch` is exactly `main`. Pull-request previews therefore cannot
open the OIDC-capable job, even if they can produce a syntactically valid evidence
bundle.

The credential-free `authorize` job resolves the source run ID and Git SHA from
the immutable `workflow_run` event, re-checks the source workflow identity with
the GitHub API, downloads the sealed bundle, and independently verifies the launch
verdict. Source artifacts are fetched by `download_run_artifact.py`, which
validates the exact run-scoped artifact identity and uses bounded backoff for the
short GitHub/Azure artifact replication window instead of treating an immediately
unavailable blob as a launch failure. The helper accepts only one bounded JSON
payload and never forwards the GitHub Authorization header to the blob host.
A `HOLD` verdict remains a normal green public result. It produces
`authorized=false` unless the same source run also contains a valid Trusted
Promotion Proof. Direct `READY_FOR_AUTHENTICATED_E2E` and a verified Trusted
Promotion Proof are the only two paths to `authorized=true`. Neither path is a
production GO decision.

Manual dispatch remains available for controlled recovery and debugging, but the
same source-run identity, main-branch, artifact, origin, SHA, and verdict checks
apply before any privileged identity can be created.

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
