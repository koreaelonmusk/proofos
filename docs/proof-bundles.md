# Proof bundles and offline replay

> **A bundle can carry evidence. It cannot carry permission to believe it.**

A proof bundle is everything another person needs, on another machine, weeks
later, to work out a verdict again and get the same answer: the requirements,
the evidence records, the identities, the timestamps, the digests. What it does
not carry is authority.

Implemented in `proofos.bundle` (serialization) and `proofos.replay`
(recomputation). Schema `proofos.proof-bundle.v1`, version 1.

## What is in one

```
schema_version · bundle_kind · bundle_id · created_at · verification_time
claim · actor_id · task_id · execution_id · policy_id · profile_id
requirements[]  kind, max_age_seconds
evidence[]      kind, value, source, valid, collected_at, collector,
                content_hash, attestation_ref, attestation
recorded_verdict · recorded_reason          ← audit only, never an input
digest                                      ← covers everything above
```

`bundle_id` is derived from the content, so two exports of the same decision
name themselves the same thing. There is no field for a prompt, a transcript, a
model response or a screenshot — handled structurally rather than by scanning,
because a shape with nowhere to put a transcript cannot leak one by accident.

## The serializer cannot create evidence

`proofos.bundle` never imports `Evidence` and never constructs one. Not checked
for — absent. Loading a bundle yields `EvidenceRecord`, which is inert data whose
`source` is a *string describing what was recorded*. Turning that back into
something the kernel will look at happens in `proofos.replay`, under rules that
live there.

The distance between "reads a JSON file" and "declares an independent
observation" should be a wall rather than a code review.
Enforced by `tests/test_bundle.py::ThisModuleCannotCreateEvidenceTests`.

## Three layers, none substituting for another

| Layer | Answers | Mechanism |
|---|---|---|
| bundle digest | were these bytes altered? | `ProofBundle.compute_digest`, over the payload excluding the digest |
| record digest | was this evidence record altered? | `EvidenceRecord.recompute_hash`, the same fields and canonicalization the kernel uses |
| attestation signature | who produced this observation? | `proofos.portable_attestation`, against a registry from outside |
| trust anchor | is that collector one we accept? | supplied by the replaying environment |
| verification | do the accepted records satisfy the requirements? | `proofos.verifier` |

A bundle that fails its digest is never repaired by recomputing it. That would
establish only that the digest can be made to agree with anything.

## `recorded_verdict` is audit, not input

A bundle carries what the original run concluded, because a reviewer comparing
"what it said then" with "what it computes now" is the point. It is inside the
digest so it cannot be edited quietly, and it is read by nothing that decides.

The minimal malicious bundle:

```json
{ "recorded_verdict": "VERIFIED", "evidence": [] }
```

replays to `ABSTAIN` / `EVIDENCE_MISSING`. A forger who edits the verdict *and*
recomputes the digest gets an intact bundle and the same `ABSTAIN`, because the
recorded verdict was never an input. `ReplayResult.matches_recorded` reports the
disagreement, and a mismatch is the finding rather than an error to smooth over.

> **Recorded VERIFIED is not replay authority.**

## The seam where a file becomes evidence again

An in-process observation grant is authority held by an object, and no
arrangement of bytes carries that. So a bundle arriving with
`source: OBSERVED` on every record is, on its own, a document making an
assertion.

The resolution: **the replaying process names who it trusts, and the bundle
never can.**

```python
replay_historical(bundle, trust_anchor=registry)          # signed path
replay_historical(bundle, trusted_collectors=["name"])    # unsigned path
replay_historical(bundle)                                 # nothing vouched → ABSTAIN
```

`trust_anchor` is a `CollectorRegistry` — the same type production uses.
`trusted_collectors` is a weaker, name-only vouching for records that carry no
attestation. Both default to nothing, so a bundle replayed with no argument
abstains however many times it says `OBSERVED`.

And either can only **preserve** a provenance, never create one:

| recorded | vouched for | result |
|---|---|---|
| `OBSERVED` | yes | `OBSERVED` |
| `OBSERVED` | no | `EXECUTOR` (demoted, and reported in `ReplayResult.demoted`) |
| anything else | either | unchanged |

There is no branch that lifts a record above what the bundle recorded, so naming
a collector that only ever self-reported buys nothing.

A record carrying an attestation is admitted by that attestation **or not at
all** — naming its collector does nothing for it. Otherwise the weaker path
would quietly become the way around the stronger one.

`proofos.replay` never names `OBSERVED` anywhere in its code. Everything that
becomes an observation goes through `ObservationCapability`, and the capabilities
it mints come from `grant_plan`, which is bounded on both sides: a collector the
caller did not name gets no entry, and a kind that collector did not observe is
not covered.

> **Replayed evidence is not a new observation.**

## Two questions, two functions

`replay_historical(bundle, …)` reproduces the decision at the bundle's own
`verification_time`. This is reproducibility: the same records against the same
clock give the same answer on any machine.

`re_evaluate_at(bundle, now, …)` asks what the same sealed records are worth at
a later instant. No evidence is collected — there is nothing in the module that
could collect any — so a requirement with a freshness horizon finds its
observation outside it and abstains:

```
historical replay at T          VERIFIED
re-evaluation at T + horizon    ABSTAIN / EVIDENCE_STALE
```

That is correct, and it is the reason freshness horizons are worth declaring. An
old proof going quiet is the horizon doing its job.

They are deliberately two functions with two names. A single function with a
`now` argument would let "is this still true?" be asked by accident.

## Content safety

Export **fails closed** on anything that must not travel: private keys, bearer
tokens, cookies, AWS/OpenAI/GitHub/Slack/Google credentials, JWTs, signed URLs,
inline secrets, embedded media, paths naming a home or temp directory, and values
past a length bound.

Not redacted and not truncated. Both leave a file that still asserts a verdict
while no longer carrying what the verdict rested on. Refusing is the only
outcome that cannot mislead.

## Inspection has no authority

`proofos.bundle.inspect` and `render_inspection` report bundle id, schema,
verification time, integrity status, requirement and evidence counts, recorded
verdict and sensitive-content status. Nothing there computes a verdict, and the
rendering carries the sentence that has to be there: *recorded_verdict is what
the original run concluded. It is carried for comparison and is not evidence of
anything.*
