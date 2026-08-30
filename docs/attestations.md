# Signed attestations

> **A valid signature proves who signed some bytes. It does not prove the claim
> is true.**

## Four states, kept apart

Collapsing any two of these is the failure this module exists to prevent.

| # | State | Established by | Still open |
|---|---|---|---|
| 1 | these bytes were signed | `AttestationVerifier.verify` | by whom |
| 2 | the signer holds the key registered for this `collector_id` | `CollectorRegistry.get` + the signature check | whether that collector is one *we* accept |
| 3 | that collector is trusted here and scoped to this kind and profile | the registry supplied by the environment | whether the observation satisfies anything |
| 4 | the accepted evidence satisfies the requirements | `proofos.verifier` | nothing — this is the verdict |

Only the fourth is a verdict, and it is reached somewhere else entirely.

## The contract

`proofos.attestation`, version `proofos.observation.v1`, Ed25519.

Signed fields — exactly these, not a subset and not a superset:

```
version · execution_id · task_id · kind · collector_id · profile_id
request_nonce · observed_at · outcome · status_code · response_digest
```

Two properties of the design are worth naming:

**`source` is never transmitted.** An attestation says what was observed, not
how much to trust it. Whether an observation becomes `OBSERVED` evidence is
decided by the receiving runtime after verification, and nothing on the wire can
assert it.

**Signatures cover re-canonicalized fields, not received bytes.** The payload is
parsed under a strict schema and serialized again deterministically before
verification, so reordered keys, whitespace, or smuggled extra fields cannot
change what was signed and what is checked. An envelope carrying an unexpected
field is refused rather than ignored — "ignored" is where smuggling lives.

**`detail` is not signed.** It is in the envelope and not in `SIGNED_FIELDS`,
and the recorded evidence value is built from it. So `detail` has bundle-level
integrity and not signature-level integrity. Nothing downstream reads it for
meaning, and `bind_to_record` compares the recorded value against a
reconstruction from the signed fields so the two must agree. Stated here because
it is a real limit of the contract rather than something to discover later.

## The trust root comes from outside

Verification never reads a key out of an envelope. It reads the `collector_id`,
asks the registry for *that collector's* key, and checks the signature against
it. The envelope has no field for a key, and the strict parse refuses one that
appears.

So this is the shape of the flagship negative test: an attacker with a real key
pair produces a cryptographically perfect signature over a perfectly formed
envelope naming `proofos-collector` and asserting everything it can — and the
answer is `ABSTAIN` / `SIGNATURE_INVALID`. Hand the same bytes a registry
holding the attacker's key and it verifies. The difference is the environment's
policy; nothing in the file changed between those two calls.

A bundle cannot bootstrap `trusted: true`, `authorized: true`, collector
authority or `OBSERVED` authority. Private signing keys never belong in a proof
bundle, and export refuses one.

Enforced by `tests/test_replay_attestation.py::FlagshipBTheAttackerSignsPerfectlyTests`
and `TheTrustRootComesFromOutsideTests`.

## Binding: a signature belongs to one observation

A signature lifted from one observation and dropped onto another verifies
perfectly well *as a signature*. The question is whether it is a signature over
*this* record. `portable_attestation.bind_to_record` checks the collector, kind,
timestamp, outcome and value against the record, and the signed `task_id` and
`execution_id` against the bundle carrying it.

| Substitution | Result |
|---|---|
| different evidence kind | `COLLECTOR_SCOPE_VIOLATION` or `BINDING_MISMATCH` |
| different timestamp | `SIGNATURE_INVALID` |
| different collector | `UNKNOWN_COLLECTOR` |
| different task | `TASK_MISMATCH` |
| edited value, everything resealed | `BINDING_MISMATCH` |
| observation dated in the future | `ATTESTATION_FUTURE_DATED` |

## What a signature does not beat

| Situation | Result |
|---|---|
| valid signature, trusted collector, evidence older than the horizon | `ABSTAIN` / `EVIDENCE_STALE` |
| valid signature for `runtime_health`, requirement asks `task_outcome` | `ABSTAIN` / `EVIDENCE_MISSING` |
| valid signature, collector not scoped to that kind | `COLLECTOR_SCOPE_VIOLATION` |
| valid signature, `recorded_verdict: VERIFIED`, no trust anchor | `ABSTAIN` / `NO_TRUST_ANCHOR` |

## The check that cannot survive the trip

Live ingestion spends a single-use nonce that *the runtime issued*, which is
what stops a genuine attestation being injected into a different execution or
counted twice. Offline that check is **unavailable, not weakened**: there is no
runtime that issued anything and no live execution to inject into.

What replaces it is binding. The signed `execution_id`, `task_id`, `kind`,
`observed_at` and `request_nonce` are checked against the record and the bundle
that claim them, so a signature cannot be moved between observations, tasks or
bundles. What is genuinely not available offline is "this runtime asked for this
observation", and it cannot be — so it is stated rather than papered over.

## Without the optional dependency

Signature verification needs `cryptography`, which is the `attestation` extra.
`proofos.bundle` and `proofos.replay` import without it; a bundle carrying no
attestation replays without it ever being looked for; a bundle carrying one, in
an environment without it, is demoted to a self-report and abstains with
`SIGNATURE_MACHINERY_UNAVAILABLE`.

An unchecked signature is not a weaker yes. It is not a yes.
