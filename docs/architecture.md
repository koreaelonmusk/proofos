# ProofOS P0 Architecture

```mermaid
flowchart TD
    U[User Goal] --> A[Gemini 3.5 Flash / ADK Agent]
    A --> C[Completion Claim]
    C --> V[Evidence Verifier]
    T[Test Evidence] --> V
    R[Runtime Evidence] --> V
    V -->|all required evidence valid| P[VERIFIED]
    V -->|missing / invalid / ambiguous| B[ABSTAIN]
    B --> X[Recovery / Retry - next milestone]
```

## Trust boundary

The executor's natural-language claim is **not evidence**.

Only independently observable evidence can satisfy a verification requirement.

## Current P0

The verifier contract is implemented and deterministic. The live Gemini/ADK and Cloud Run execution path is the next milestone.
