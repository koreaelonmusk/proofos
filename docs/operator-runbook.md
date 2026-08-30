# Operator runbook

What to do, in order, and what each failure means.

## 1. Define requirements

A requirement is a kind plus a freshness horizon. The horizon is the operator's
judgement about how long an observation of that kind stays meaningful, and it is
per requirement because a health probe and a recorded test run are not the same
kind of statement.

```python
Requirement("runtime_health", max_age_seconds=900)
Requirement("artifact_digest")                       # no horizon: it speaks for the commit
```

Requirements are written into the ledger when the task is opened, and
`verify_recorded` reads them from there. A caller cannot substitute an easier
set at verification time.

## 2. Register collectors

Each collector gets a record: id, public key, the kinds it may attest to, and
the profiles it may use.

```python
registry = registry_for("proofos-collector", public_key_b64,
                        allowed_kinds=("runtime_health",),
                        allowed_profiles=("cloud-run-health",))
```

Then **seal it**. `CollectorRegistry.seal()` refuses further registration: which
keys are trusted must not change while executions are running.

Scope is narrow on purpose. A collector authorized for `runtime_health` does not
gain `task_outcome` because a payload asks for it, because it signs it, or
because a caller trusts the key.

## 3. Grant observation capability, then seal the ledger

```python
capability = ObservationCapability(ledger, "proofos-collector", ("runtime_health",))
ledger.seal()
```

`seal()` fixes authority at wiring time. After it, `grant_observation` raises
`CapabilityDenied`. Reaching the ledger later does not let anyone mint a grant.

## 4. Observe

The collector runs in its own process with its own service identity and holds
the only copy of the private key. It observes, and signs what it saw. It has no
verification capability and no path to a verdict.

The runtime issues a single-use nonce bound to the execution, task and kind
before the observation, and the collector signs over it. That is what stops a
genuine attestation being replayed into a different execution or counted twice.

## 5. Verify

```python
decision = ProofOS().verify_recorded(ledger, task_id, claim, now=None)
```

Read `decision.status`, `decision.reason`, `decision.missing`, and
`decision.evidence` — the per-record assessment, which distinguishes *sound*,
*accepted* and *satisfying*. A record can be all three, or only the first.

## 6. Export a proof bundle

```python
bundle = export_bundle(claim=..., requirements=..., evidence=...,
                       task_id=..., verification_time=..., created_at=...,
                       recorded_verdict=str(decision.status),
                       recorded_reason=str(decision.reason),
                       attestations={...})
```

Export **fails closed** if anything that must not travel is present. Do not work
around it by redacting — that produces a file that still asserts a verdict while
no longer carrying what the verdict rested on. Fix the leak at collection time
and export again.

Record the bundle digest somewhere out of band. It is what lets a later reader
say "this is the file I was told about" rather than "this is a file".

## 7. Replay elsewhere

```python
result = replay_historical(load_bundle(text), trust_anchor=registry,
                           expected_digest=known_digest)
```

Supply the trust anchor from your environment. Without it every `OBSERVED`
record is demoted and the answer is `ABSTAIN` — which is the correct answer to
"should I believe a file I was handed".

`expected_digest` catches substitution: a file that is internally consistent and
is not the one you asked for.

## 8. Re-evaluate later

```python
result = re_evaluate_at(bundle, time.time(), trust_anchor=registry)
```

Different question, different function. Old evidence falls outside its horizon
and the verdict becomes `ABSTAIN` / `EVIDENCE_STALE`. Nothing is collected. If
you need a current answer, observe again.

## 9. Inspect

```python
print(render_inspection(bundle))
print(render_replay(result))
```

Inspection reports facts and decides nothing. `recorded_verdict` appears
labelled as recorded.

## Failure map

Everything fails closed. Each row is an answer, not an outage.

| Symptom | Meaning | Action |
|---|---|---|
| `ABSTAIN` / `EVIDENCE_UNTRUSTED` | only self-reports arrived | arrange an independent observation |
| `ABSTAIN` / `EVIDENCE_MISSING` | no evidence of a required kind | check the collector is scoped to that kind |
| `ABSTAIN` / `EVIDENCE_STALE` | real evidence, outside its horizon | observe again, or reconsider the horizon |
| `ABSTAIN` / `EVIDENCE_INVALID` | the governing observation reports failure | fix the system |
| `ABSTAIN` / `EVIDENCE_TAMPERED` | a record no longer matches its digest | treat the evidence set as untrustworthy |
| `ABSTAIN` / `VERIFIER_FAILURE` | the verifier errored | a crash is never read as success; investigate |
| `ABSTAIN` / `AUDIT_UNAVAILABLE` | the journal could not be written | a lost audit trail can only downgrade an outcome |
| `ProvenanceNotDeclarable` raised | a caller labelled its own evidence `OBSERVED` | use the observation path; this is a category error, not a weak answer |
| `CapabilityDenied` | something tried to write evidence it has no grant for | do not widen the grant to make it pass |
| `NO_TRUST_ANCHOR` on replay | no registry was supplied | supply one, from your environment |
| `SIGNATURE_INVALID` on replay | the registry's key for that collector is not the signer's | do not add the signer's key to make it pass |
| `BINDING_MISMATCH` on replay | a valid signature that belongs to a different observation | investigate; this is a substitution attempt or a corrupt export |
| `SIGNATURE_MACHINERY_UNAVAILABLE` | `cryptography` is not installed | `pip install 'proofos[attestation]'` |
| export raises `SensitiveContentError` | a credential or machine path would have travelled | fix at collection time; do not redact |

The pattern in the right-hand column is worth naming: the fix is never to widen
authority until the check passes. Every one of these refusals is the system
doing its job.

## Release gates

`python scripts/release_gate.py all` runs five gates locally: wheel contents and
reproducibility, a fresh-venv install with no extras, dependency audit,
repo-wide secret scan, and the full suite plus a clean-tree check.

A gate that cannot run reports `NOT RUN` and the runner exits non-zero. "The
check did not happen" and "the check passed" are different states.

CI invokes the same script. Until a workflow run is observed on a pushed commit,
local evidence and remote CI evidence are separate claims — see
[governance](governance.md).
