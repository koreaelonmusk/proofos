# Evidence lifecycle

From "an agent said something" to "ProofOS answered". Every stage names the
module that performs it, so a reader can go and check.

## The verdict contract

`proofos.verifier.VerificationStatus` has exactly two values.

**`VERIFIED`** means: every declared requirement was satisfied by evidence the
authoritative verifier accepted, under the active provenance, integrity and
freshness rules.

**`ABSTAIN`** means: ProofOS does not have sufficient accepted evidence to
assert completion.

`ABSTAIN` is **not** failure, not `false`, not a judgement about the actor, and
not proof that the task failed. It is the system declining to certify. A service
can be perfectly healthy and a claim about it still abstain, because the
question is what has been *shown*, not what is true.

There is no `PASS`, no `FAIL`, and no third value. When ProofOS renders a GitHub
check, `ABSTAIN` maps to `action_required` rather than `neutral`, because GitHub
treats `neutral` as passing for a required check — see `proofos/github.py`.

Why a verdict was withheld is a separate field, `proofos.verifier.FailureClass`:
`NONE`, `EVIDENCE_MISSING`, `EVIDENCE_INVALID`, `EVIDENCE_UNTRUSTED`,
`EVIDENCE_STALE`, `EVIDENCE_TAMPERED`, `MALFORMED_INPUT`, `VERIFIER_FAILURE`.
A verifier that crashes reports `VERIFIER_FAILURE` and abstains; it is never
read as success.

## Claim or evidence

Everything in this list is a claim. None of it becomes `OBSERVED` on its own.

| What arrives | What it is |
|---|---|
| an agent saying "done" | a claim |
| a tool returning `{"status": "success"}` | a claim-bearing result |
| a GitHub check reporting success | a claim |
| an MCP tool named `proofos.verify` returning `VERIFIED` | a claim |
| an A2A task with `state: completed` | a claim |
| an ADK `after_agent_callback` emitting success | a claim |
| a proof bundle's `recorded_verdict: VERIFIED` | historical metadata |
| a payload field `"source": "OBSERVED"` | a claim, kept under `claimed_by_sender` |

The subtle one is the tool result. A probe really did return HTTP 200 — that is
a fact about that call, made by the executor, and not an independent finding
about the service.

`EvidenceSource` has three values and only one of them satisfies anything.
`OBSERVED` came from an independent, authorized observer. `EXECUTOR` came from
the component under scrutiny or a tool it ran. `MODEL` came from a language
model's own assertion — recorded because a reviewer should be able to see what
was said, and refused for the same reason `EXECUTOR` is. `TRUSTED_SOURCES` holds
`OBSERVED` alone, and every refusal in the codebase is derived from that set
rather than naming the constant, so a later build that changed it would change
the refusals with it.

## The stages

```
 1  arrival        a foreign payload                    (any transport)
 2  normalize      → AdapterEnvelope                    proofos.adapters, .mcp, .a2a, .adk, .github
 3  enclose        sender assertions → claimed_by_sender AdapterEnvelope.__post_init__
 4  encode         → Evidence(source=EXECUTOR)          proofos.evidence_bridge
    ── everything above is translation; nothing above can produce OBSERVED ──
 5  observe        a collector observes reality         proofos_collector, proofos.probe
 6  attest         → signed ObservationAttestation      proofos.attestation
 7  identify       collector_id → registered key        proofos.collector_registry
 8  scope          may this collector attest this kind? CollectorRegistry.require_scope
 9  authenticate   signature over re-canonicalized fields AttestationVerifier.verify
10  bind           execution, task, kind, profile, nonce proofos.ingestion
11  freshness      observed_at within the horizon       proofos.ingestion, proofos.verifier
12  admit          → Evidence(source=OBSERVED)          ObservationCapability.record_observation
    ── authority first appears here, and nowhere earlier ──
13  record         → EvidenceLedger, grant required     proofos.ledger
14  integrity      each record still matches its digest Evidence.intact
15  match          most recent trusted evidence per kind proofos.verifier._evaluate
16  decide         → VERIFIED | ABSTAIN                 verify_completion
```

Stages 1–4 are the claim path. Stages 5–12 are the observation path. They meet
only at the ledger, and only one of them can put `OBSERVED` in it.

## `OBSERVED` is not a string

`OBSERVED` is what `EvidenceSource.OBSERVED` means when it is written by code
holding the authority to write it. It is emphatically **not**:

- a string field a sender can set
- an adapter option
- a transport flag
- a JSON property
- anything a payload can arrive carrying

`source` never travels on the wire. `proofos.attestation.SIGNED_FIELDS` does not
include it: an attestation says *what was observed*, and whether that becomes
`OBSERVED` evidence is decided by the receiving runtime afterwards.

Two walls enforce this:

1. `proofos.api.ProofOS.verify` raises `ProvenanceNotDeclarable` when handed
   evidence already labelled with anything in `TRUSTED_SOURCES`. The refusal is
   derived from the kernel's own set, so a later build that changes what counts
   as independent changes this refusal too.
2. `EvidenceLedger.record` requires a matching `ObservationGrant` — issued by
   *that* ledger, for a kind that grant covers, under the collector's own
   identity — before it will store `OBSERVED`.

`ProofOS.verify_recorded` is the only entry point that can return `VERIFIED`,
and it reads both the evidence and the requirements from the ledger. A caller
who could pass different requirements than the task was opened with could ask an
easier question than the one being answered.

## Freshness

`Requirement.max_age_seconds` is a per-requirement horizon, not a global
setting. A health probe speaks for the moment it ran; a recorded test run speaks
for as long as the commit it describes. Undated evidence sorts oldest and can
never satisfy a requirement that declares a horizon — an observation that cannot
be placed in time cannot be shown to still hold.

Freshness is independent of everything else. A valid signature over old evidence
is a valid signature over old evidence.

## The most recent observation governs

Within a kind, the latest trusted observation decides. An older failed probe
does not veto a service since observed healthy; a newer failed probe does veto
an earlier success. Observations that are equally recent and disagree are
unresolvable and produce `EVIDENCE_INVALID`.

## Acceptance is about one decision

`EvidenceAssessment` reports three distinct flags, and collapsing them is how a
rejected self-report once came to be displayed as satisfying:

- `integrity_valid` — the record is internally sound. True for an honest
  self-report.
- `accepted_by_verifier` — it survived the trust policy for a requirement of its
  kind.
- `satisfies_requirement` — it was among the records that actually settled one.

A trusted but superseded observation is accepted and does not satisfy. The same
record can be rejected at attempt 1 and irrelevant at attempt 2, so acceptance
is reported per attempt rather than stamped on the evidence.
