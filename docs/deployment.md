# Cloud Run topology

**Status: DESIGNED and IMPLEMENTED in code. NOT DEPLOYED, NOT PROVEN.**
Nothing below has been executed against Google Cloud. No project, service,
service account, or IAM binding has been created.

## Two services, two identities

```text
proofos-api                      proofos-collector
  Dockerfile                       Dockerfile.collector
  identity:                        identity:
    proofos-orchestrator@...         proofos-collector@...
  public (demo)                    AUTHENTICATION REQUIRED
       |                                   ^
       |  OIDC ID token, audience =        |
       |  the collector's service URL      |
       +-----------------------------------+
```

The collector is the only holder of the Ed25519 signing key. The API service
receives the public key as configuration and can verify attestations but never
author them.

## Why per-service identity

Splitting the process is only half the boundary. If both services ran as the
same principal, anything that compromised the API could call the collector with
the API's own credentials. Separate service accounts make "who is calling" a
property Google asserts, not a header the caller writes.

```bash
# Least privilege: only the orchestrator may invoke the collector.
gcloud run services add-iam-policy-binding proofos-collector \
  --member="serviceAccount:proofos-collector-caller@PROJECT.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region=asia-northeast3
```

`X-Agent-Role: collector` would be data, not identity — anything that can reach
the endpoint can set it. Only a Google-signed OIDC token, validated by Cloud Run
against the audience, is worth anything.

## Ingress: IAM first, VPC later

The collector is deliberately **not** set to `--ingress=internal` in this
design. Internal ingress between Cloud Run services requires Direct VPC egress
or a connector; without that routing an otherwise correct deployment simply
becomes unreachable, and the failure looks like a bug rather than a policy.

For the first deployment, `--no-allow-unauthenticated` plus per-service identity
and a narrow `run.invoker` binding is a real boundary. Internal ingress and VPC
restriction are a later hardening unit, valuable but not a prerequisite.

## Regions

`GOOGLE_CLOUD_LOCATION=global` is the **Vertex AI** endpoint serving Gemini 3.5
Flash. It is not a Cloud Run region. Cloud Run needs a real region; this design
proposes `asia-northeast3` (Seoul).

## What remains unproven

| Item | Status |
| --- | --- |
| Collector container builds and runs | PROVEN locally |
| Process separation and signing boundary | PROVEN locally, real OS processes |
| Cloud Run deployment | NOT PROVEN |
| Per-service identity | DESIGNED |
| `roles/run.invoker` enforcement | NOT PROVEN |
| Google-signed OIDC token acquisition | IMPLEMENTED, NOT PROVEN |
| Collector service privacy | NOT PROVEN |
| Cloud Logging ingestion | NOT PROVEN |

## Known limitation: DNS rebinding

A collection profile naming a hostname resolves it at request time. A hostile
resolver could answer with an internal address, which an allowlisted hostname
does not prevent. Profiles that must not be rebound should name a literal
address; pinning the resolved address per request is the real fix and is not
implemented.
