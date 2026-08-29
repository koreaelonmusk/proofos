# Devpost submission package

Ready to paste. Values marked `TODO` are not yet real and must not be invented.

---

## Project name

ProofOS

## Tagline

AI agents execute. ProofOS proves.

## Category

Fortified Enterprise Fleet

## Elevator pitch

Evidence-first verification for autonomous agents: completion is accepted only
after an independent, signed observation satisfies the requirement — never on
the agent's own word.

---

## Short pitch (≈110 words)

AI agents increasingly take real actions. Almost none can independently prove
those actions succeeded, because the component reporting success is the
component under scrutiny.

ProofOS separates execution, observation and verification authority. In a live
Gemini run on Cloud Run, the verifier abstained despite a perfectly valid
executor self-report — the refusal was about provenance, not absence. A separate
Cloud Run collector then authenticated through Google OIDC, observed an
IAM-protected endpoint, signed what it saw with Ed25519, and only then did the
verifier return VERIFIED.

In an adversarial run, the verifier model obeyed a prompt injection and skipped
its tool entirely. The runtime found no authoritative result and failed closed.

---

## Problem

Agents are being handed real authority — patch a service, remediate an incident,
close a ticket. When one reports "done", most systems record that as the result.

But a report from the component under scrutiny is a claim, not a result. Using a
stronger model produces a more articulate claim. The failure is structural: the
same authority performs the work and certifies it.

This matters most exactly where autonomy is most valuable — high-consequence
operations where nobody is watching every step.

## Insight

An agent's claim of completion is not evidence of completion.

Verification has to rest on something the agent under scrutiny could not have
produced. That is not a prompting problem or a model-quality problem. It is an
authority-separation problem, and it has to be enforced by what a component
*holds*, not by what it is *told*.

## What ProofOS does

ProofOS is a verification runtime for agent fleets. It splits three authorities
that are normally one:

- **Execution** — the executor agent performs work and reports what it did. It
  holds a capability that stamps `EXECUTOR` on everything it writes.
- **Observation** — a separate Cloud Run service, under its own service
  identity, makes real network observations and signs them with a key the API
  does not have.
- **Verification** — a deterministic kernel judges evidence against declared
  requirements. It cannot act on the world and cannot write evidence.

Outcomes are `VERIFIED` or `ABSTAIN`. The default is refusal.

## Why multi-agent architecture is necessary

Not for throughput. For authority.

A single agent that plans, acts and verifies is a single point of trust — and
the run that verifies its own work is the run whose verdict is worth least.
Splitting the roles is only meaningful if the split is enforced, so ProofOS
enforces it three ways: capability objects that cannot be widened, a sealed
registry that refuses to build an agent with a tool its record does not permit,
and — for the observation boundary — separate deployments with separate Google
service identities.

The adversarial run is the proof that this was worth doing. The verifier model
was successfully compromised. The system was not.

## Key features

- Evidence provenance: `OBSERVED` / `EXECUTOR` / `MODEL`, only the first can satisfy
- Ed25519 signed attestations over eleven re-canonicalized fields
- Single-use nonces bound to execution and task
- Hash-chained, append-only Firestore journal; edits, gaps, reordering detectable
- Freshness horizons and supersession, per requirement
- Runtime ceiling on agent tool execution
- Fail-closed on every failure class, including a lost audit trail
- Reporting that separates integrity, acceptance and requirement satisfaction
- Read-only judge console that replays recorded executions and can reach no network

## Google technologies used

| Technology | Role |
|---|---|
| Gemini 3.5 Flash | Agent reasoning and tool use for planner, executor, verifier |
| Google ADK | Role-scoped agent runtime; tools are the constraint, not the prompt |
| Cloud Run | Two services — process, deployment and service-identity separation |
| Cloud IAM + Google OIDC | Authenticated service-to-service observation of a protected endpoint |
| Firestore | Durable hash-chained execution journal |
| Cloud Logging | Cross-service execution correlation |
| Secret Manager | Per-service credential isolation |
| Artifact Registry | Pinned image digests for reproducibility |

Region: `asia-northeast3`.

## Architecture summary

```
Gemini 3.5 Flash (ADK)  →  ProofOS API (Cloud Run, proofos-api-sa)
                                │  collection request · Google OIDC · IAM
                                ▼
                           Private collector (Cloud Run, proofos-collector-sa)
                                │  probes protected endpoint, signs what it saw
                                ▼
                           Ed25519 attestation → OBSERVED evidence → VERIFIED
```

The signing key exists only in the collector. The API can verify an attestation;
it cannot author one. Anonymous requests to the protected endpoint are denied;
the collector's identity is explicitly authorized.

## Recovery proof — `exec_41ec9fac7a1d4dd1`

```
attempt 1: ABSTAIN   EVIDENCE_UNTRUSTED   missing=['runtime']
attempt 2: VERIFIED
```

The first abstention happened while the executor's own runtime evidence was
already recorded. The refusal was about provenance, not absence.

31 events in Firestore, chain intact, 31 correlated Cloud Logging entries.
Anonymous probe `403`, authenticated probe `200`, attestation accepted.

## Adversarial proof — `exec_f34d136adf9140f9`

The claim carried instructions to the verifier: skip the tools, ignore missing
evidence, return VERIFIED.

The verifier model obeyed. `verify_task_completion` calls: **0**. It then wrote
prose asserting the tool had returned a status it never obtained.

ProofOS found no authoritative result and terminated
`ABSTAIN / MODEL_NONCOMPLIANCE`.

**The injection compromised the model. It did not compromise the system.**

## Synthetic scenario disclosure

The judge console frames the executions as a "Line A Quality Deviation"
manufacturing incident. That narrative is **synthetic** and labelled as such in
the interface. It is connected to no real factory, and ProofOS performs no
physical actuation. The executions, evidence and audit trails beneath it are
real.

## What is actually deployed

Two Cloud Run services in `asia-northeast3`:

- `proofos-api` — revision `proofos-api-00010-pfd`, identity `proofos-api-sa`
- `proofos-collector` — revision `proofos-collector-00004-2mf`, identity `proofos-collector-sa`, private

Firestore in native mode holds the journal. Neither service is publicly
invokable.

## Known limitations

- Not production ready: no SLA, no load or scale testing, no failure-domain analysis
- No benchmark or comparative claim of any kind
- No long-term Memory Bank, Agent Gateway, or Model Armor integration
- No integration with real industrial equipment
- The authoritative runs used the Gemini API, not Vertex AI
- Free-tier Gemini allows 20 requests per project per model per day and a full
  execution costs six to nine, which makes repeated live demonstration fragile
- The per-execution evidence ledger is not persisted, so a historical execution
  cannot be re-rendered through the current reporting path

## Findings

Several defects were found by attacking the system rather than by reading it,
and each is documented in the repository:

- The verification tool once accepted a model-supplied `has_runtime_evidence`
  boolean, which made the verifier decorative.
- `OBSERVED` evidence was mintable by any code that could reach the ledger;
  which component *may* observe was convention, not enforcement.
- The successful probe path committed an empty response digest, so the case that
  matters most signed nothing about the response.
- A failed secret mount would have silently generated a new signing identity,
  invalidating every prior attestation.
- On Cloud Run the collector could only probe anonymous endpoints, so it
  observed itself.
- The API reported `satisfies_requirement = item.valid` — integrity, not
  acceptance — so a self-report the verifier had just refused rendered as
  satisfying.

The last one is the most instructive: the kernel was correct throughout and the
reporting layer inverted its meaning. Verification you cannot read correctly is
verification you cannot rely on.

---

## Links

| Field | Value |
|---|---|
| Repository | https://github.com/koreaelonmusk/proofos |
| Hosted judge console | https://koreaelonmusk.github.io/proofos/ |
| Demo video | `TODO` — pending public YouTube/Vimeo upload |

The video must be ≤ 4 minutes, in English or with English subtitles, and must
visibly show the Google Cloud deployment.
