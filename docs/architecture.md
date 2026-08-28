# ProofOS architecture

Two services, three authorities, one invariant: no claim of completion without
independent evidence.

## The whole system

```mermaid
flowchart TB
    subgraph agents["Gemini 3.5 Flash · Google ADK"]
        direction LR
        P["Planner<br/><i>no tools</i>"]
        E["Executor<br/><i>perform_action</i>"]
        V["Verifier<br/><i>verify_task_completion</i>"]
    end

    subgraph api["Cloud Run · proofos-api-sa"]
        O["Orchestrator<br/>owns every transition"]
        L["Evidence ledger"]
        K["Verification kernel<br/><i>deterministic</i>"]
        I["Attestation ingestor<br/>holds the only observation grant"]
    end

    subgraph col["Cloud Run · proofos-collector-sa · private"]
        C["Bounded HTTP probe"]
        S["Ed25519 signing key<br/><b>exists only here</b>"]
    end

    T["Protected endpoint<br/>anonymous 403 · authenticated 200"]

    P -. "plan is advisory" .-> O
    O --> E
    E -- "claim → EXECUTOR evidence" --> L
    O --> V
    V -- "reads" --> K
    K -- "reads" --> L
    K -- "ABSTAIN · EVIDENCE_UNTRUSTED" --> O
    O == "collection request<br/>nonce issued" ==> C
    C == "Google OIDC · IAM" ==> T
    T -- "observed response" --> S
    S == "signed attestation" ==> I
    I -- "OBSERVED evidence" --> L
    K -- "VERIFIED" --> O
    O --> FS[("Firestore<br/>hash-chained journal")]
    O --> CL["Cloud Logging"]
```

## Trust boundaries

### 1. The executor cannot write evidence that counts

The executor holds a `ClaimCapability` whose `source` is hard-coded to
`EXECUTOR`. There is no parameter to override it and no second method. Reaching
the ledger by any route buys nothing: `EvidenceLedger.record` refuses `OBSERVED`
without a matching `ObservationGrant`, and the grant names the issuer, the
evidence kinds, and the collector identity it authorises.

This is enforced by object graph, not by prompt. The executor is handed no
ledger, no observation capability, no read access to evidence, and no verifier.
An executor that decides to cheat has nothing to cheat with.

### 2. The API cannot author an observation

The signing key exists only in the collector process. The API holds the public
key and can verify an attestation; it cannot produce one. Eleven checks run on
ingestion — signature, execution binding, task binding, collector identity,
profile, nonce, freshness, duplicate, outcome, kind, and canonical re-encoding
of every signed field.

`source` is never transmitted. It is assigned by the ingestor after verification
succeeds, so a collector cannot request its own provenance level.

### 3. The model narrates; it does not decide

Verdicts come from the verification tool's return value. `decision_from` reads
the tool result and refuses to guess when the turn is ambiguous: no tool call, a
call for a different task, or a call with no result are all
`MODEL_NONCOMPLIANCE`. A verifier that writes "VERIFIED" over an `ABSTAIN` tool
result has narrated, not decided.

This is what contained the live injection in `exec_f34d136adf9140f9`.

### 4. Two services, not two classes

Process-local separation is a promise. Separate Cloud Run deployments, separate
service accounts, and IAM-gated invocation are observable facts: an anonymous
request to the protected endpoint returns `403`, and the collector's identity is
explicitly authorized to invoke it.

## Why the collector has no agent

Its job is a bounded network probe. Putting a language model in front of it
would insert an untrusted step into the one path that has to stay observable.
The collector is deterministic on purpose.

## Evidence rules

A requirement is satisfied only when the most recent trusted observation of that
kind is valid, intact, non-empty, and within the requirement's freshness
horizon.

- **Provenance.** Only `OBSERVED` satisfies. `EXECUTOR` and `MODEL` are recorded
  and refused.
- **Supersession.** The latest trusted observation governs. An older failed
  probe does not veto a service since observed healthy; a newer failed probe
  does veto an earlier success.
- **Freshness.** Declared per requirement, because a health probe speaks for the
  moment it ran and a recorded test run speaks for the commit it describes.
- **Integrity.** Every record carries its own content hash. A record that no
  longer matches its digest fails the whole set closed.

## Reporting

Three separate facts, never collapsed:

| Field | Question |
|---|---|
| `integrity_valid` | Is the record internally sound? |
| `accepted_by_verifier` | Did it survive the trust policy for a requirement of its kind? |
| `satisfies_requirement` | Was it among the items that actually settled the requirement? |

All three come from the same verifier pass that produced the verdict. The
presentation layer joins on `evidence_id` and copies; it holds no trust rules of
its own. Acceptance belongs to an attempt, so the response carries `attempts[]`.

## Failure semantics

Every failure resolves to `ABSTAIN` with a named class. There is no path that
resolves to success on doubt.

| Class | Cause |
|---|---|
| `EVIDENCE_MISSING` | No evidence of a required kind |
| `EVIDENCE_UNTRUSTED` | Present, but self-reported |
| `EVIDENCE_INVALID` | Governing observation reports failure or is empty |
| `EVIDENCE_STALE` | Outside the requirement's freshness horizon |
| `EVIDENCE_TAMPERED` | A record no longer matches its own digest |
| `MODEL_NONCOMPLIANCE` | No authoritative tool result to read |
| `CAPABILITY_DENIED` | A component attempted something it does not hold |
| `AUDIT_UNAVAILABLE` | The decision could not be durably recorded |
| `COLLECTOR_UNAVAILABLE` | No collector for the missing evidence |
| `RETRY_EXHAUSTED` | Bounded attempts ran out |
| `VERIFIER_FAILURE` | The kernel itself raised |

## Journal

Append-only, hash-chained. Each event carries `sequence`, `previous_hash`, and a
content hash over its own fields. Firestore writes are transactional with an
idempotency index, and reads sort by explicit `sequence` rather than document
order. Edits, gaps, duplicates, and reordering are all detectable.

Losing the journal cannot manufacture a success: an unwritable audit trail
downgrades the outcome to `ABSTAIN / AUDIT_UNAVAILABLE`.
