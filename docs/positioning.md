# ProofOS positioning

## Category

ProofOS is a **post-execution evidence verification runtime for autonomous agents**.

It answers a narrower and harder question than an evaluator or observability tool:

> **Did independently authorized evidence actually satisfy the configured completion requirement?**

The core path is:

```text
agent executes
→ agent may claim success
→ independent observation
→ provenance / trust / authorization / scope / freshness / integrity
→ deterministic requirement evaluation
→ VERIFIED | ABSTAIN
```

## The distinction that matters

ProofOS intentionally keeps these statements separate:

```text
CLAIM != EVIDENCE
SIGNED != TRUSTED
TRUSTED != AUTHORIZED
AUTHORIZED != REQUIREMENT SATISFIED
AUTHENTICATION != TRUTH
TRANSPORT != AUTHORITY
REPLAY != NEW OBSERVATION
NOT RUN != PASS
```

A valid signature can authenticate who produced a statement without making the statement true. A trusted identity can still lack authority for a requirement. Evidence can be intact and still fail the requirement it was offered to satisfy.

## What ProofOS is not

ProofOS is not:

- an LLM-as-a-judge score;
- a claim that model reasoning is formally proven correct;
- a generic agent framework;
- a replacement for red-team tooling, tracing, or observability;
- proof that every real-world outcome is knowable;
- a claim of being the world's first or world's best system.

Its job is to provide a fail-closed authority boundary around completion claims.

## What is demonstrated publicly

The public repository demonstrates:

- a real Cloud Run recovery execution that moves from `ABSTAIN` to `VERIFIED` only after independently observed evidence arrives;
- a prompt-injection case where the verifier model is compromised but the system still returns `ABSTAIN / MODEL_NONCOMPLIANCE`;
- separate execution, observation, and verification authorities;
- an Ed25519-signed collector attestation path;
- a hash-chained audit journal;
- a public mechanically adjudicated red-team challenge.

Public red-team challenge:

https://github.com/koreaelonmusk/proofos/blob/redteam/proofos-w3-e2.2/redteam/README.md

## Claim boundary

The strongest defensible statement is:

> **ProofOS turns an agent's completion claim into a fail-closed verdict grounded in independently authorized evidence.**

The project does **not** currently claim world leadership. External attack attempts, independent audits, independently reproduced benchmarks, and third-party production adoption are separate evidence classes and must be earned outside the project.

That constraint is deliberate: a verification system that certifies itself without independent evidence would contradict its own design.
