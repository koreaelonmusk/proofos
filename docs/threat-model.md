# Threat model

Each row is an attack, the response the system actually gives, and where that
response is enforced. Every entry has a test; a row without one would be a
promise rather than a property.

## Claim promotion

| Attack | Response | Enforced by |
|---|---|---|
| An agent reports `verified: true, confidence: 1.0` | `ABSTAIN` / `EVIDENCE_UNTRUSTED`; the assertion is kept under `claimed_by_sender` | `tests/test_adapters.py::AClaimStaysAClaimTests` |
| A payload declares `"source": "OBSERVED"` | Kept as a claim; `evidence_from_envelope` has no branch reaching `OBSERVED` | `tests/test_evidence_bridge.py` |
| A caller hands `ProofOS.verify` evidence already labelled `OBSERVED` | `ProvenanceNotDeclarable` raised, not `ABSTAIN` — a category error, not a weak answer | `tests/test_cli_and_api.py` |
| A tool returns HTTP 200 and `healthy: true` | `EXECUTOR` evidence attributed to the actor that ran it | `tests/test_adapters.py::ToolOutputIsNotIndependentTests` |
| An executor reaches the ledger and writes `OBSERVED` | `CapabilityDenied`: no grant, wrong kind, or wrong identity | `tests/test_authority.py` |

## Identity and naming

| Attack | Response | Enforced by |
|---|---|---|
| A framework calls itself `trusted-enterprise-agent` | The verdict does not move | `tests/test_adapters.py::NamesDoNotCreateTrustTests` |
| An MCP server names itself `proofos-official` | `server_id` comes from the constructor; the assertion is kept under `claimed_by_sender` | `tests/test_mcp.py` |
| An A2A or ADK agent names itself `proofos-verifier` | The verdict does not move | `tests/test_a2a.py`, `tests/test_adk.py` |
| A remote agent names itself `trusted-collector` | Becomes `evidence.collector` as attribution and nothing else; real collector identities are registered and prove themselves with a signature | `tests/test_a2a.py::NamesAndSignaturesDoNotCreateTrustTests` |
| A payload supplies `adapter_id` or `collector_id` | Kept under `claimed_by_sender`; identity comes from the constructor or the registry | `tests/test_adapters.py::IdentityCannotBeChosenByThePayloadTests` |
| Metadata carries a top-level `collector_id`, or a flat `claimed_collector_id` | `AdapterError` at envelope construction | `tests/test_adapters.py::CanonicalSenderMetadataTests` |

## Transport authority laundering

| Attack | Response | Enforced by |
|---|---|---|
| A GitHub check reporting success is read as a verdict | GitHub is a transport; `github.py` never imports `verify_completion` | `tests/test_github.py` |
| `ABSTAIN` rendered as GitHub `neutral`, which required checks treat as passing | `neutral` does not exist in the vocabulary; `ABSTAIN` maps to `action_required` | `tests/test_github.py` |
| An MCP tool named `proofos.verify` returning `VERIFIED` | Normalized to a claim; the module has no verdict field at all | `tests/test_mcp.py::TheAdapterCarriesNoAuthorityTests` |
| An A2A task `state: completed` read as a verdict | `TaskState` has no `is_success`; no route from a state to a verdict exists | `tests/test_a2a.py::AStateIsNotAVerdictTests` |
| An ADK `after_agent_callback` emitting success | A framework hook is a place, not a witness; no code branches on a callback name | `tests/test_adk.py::ACallbackIsAPlaceNotAWitnessTests` |
| An A2A Agent Card advertising a `verify_deployment` skill | A capability describes what an actor may attempt; `AgentCard` has no route to an envelope or evidence | `tests/test_a2a.py::AnAgentCardIsAdvertisingTests` |
| The same statement arriving by a "more trusted" transport | Identical truth semantics and identical verdict across five transports | `tests/test_transport_equivalence.py` |

## Multi-agent laundering

| Attack | Response | Enforced by |
|---|---|---|
| A claim relayed A→B→C returns wearing three names | The delegation chain lives in metadata, which `truth_semantics` excludes by construction; a 7-hop and a direct delivery are provably the same statement | `tests/test_a2a.py::DelegationIsNotCorroborationTests` |
| Three agents repeat one sentence and all evidence is offered at once | Three `EXECUTOR` records, zero accepted, `ABSTAIN` | same |
| An authenticated agent is treated as an independent observer | A signature proves who is speaking, not that what was said is true | same |

## Proof bundles

| Attack | Response | Enforced by |
|---|---|---|
| `{"recorded_verdict": "VERIFIED", "evidence": []}` | `ABSTAIN` / `EVIDENCE_MISSING`; mismatch reported | `tests/test_replay.py::FlagshipBABundleCannotSelfCertifyTests` |
| The recorded verdict is flipped | Integrity failure — it is inside the digest | `tests/test_replay.py::TamperFailsClosedTests` |
| The verdict is flipped **and** the digest recomputed | Intact bundle, still `ABSTAIN`: the recorded verdict is never an input | same |
| An evidence source, collector, timestamp or digest is edited | Integrity failure; no authoritative replay | same |
| A bundle found anywhere is replayed with no trust anchor | `ABSTAIN` / `EVIDENCE_UNTRUSTED`, every `OBSERVED` record demoted | `tests/test_replay.py` |
| A collector that only self-reported is named as trusted | Nothing changes; the promotion path does not exist | `tests/test_replay.py::NoObservationLaunderingTests` |
| A bundle asks for a grant via an extra field | Unknown fields are refused, not ignored | `tests/test_bundle.py::TheWireIsValidatedTests` |
| A signed record replays a hundred times | One observation read repeatedly; freshness still applies | `tests/test_replay.py` |

## Signed attestations

| Attack | Response | Enforced by |
|---|---|---|
| An attacker's cryptographically valid signature naming a legitimate collector | `ABSTAIN` / `SIGNATURE_INVALID` — the registry's key for that name is not theirs | `tests/test_replay_attestation.py::FlagshipBTheAttackerSignsPerfectlyTests` |
| An envelope carrying its own public key | `MALFORMED_ATTESTATION`; the strict parse has no field for one | same |
| A signature moved to a different kind, timestamp, collector or task | Scope violation, `SIGNATURE_INVALID`, `UNKNOWN_COLLECTOR` or `TASK_MISMATCH` | `tests/test_replay_attestation.py::ASignatureBindsToOneObservationTests` |
| A recorded value edited and every integrity layer resealed | `BINDING_MISMATCH` — the value is reconstructed from the signed fields, never read from the file | same |
| A valid signature over evidence past its horizon | `ABSTAIN` / `EVIDENCE_STALE` | `tests/test_replay_attestation.py::AuthorityDoesNotBypassTheKernelTests` |
| A trusted collector signs a kind it is not scoped to | `COLLECTOR_SCOPE_VIOLATION` | same |
| A valid signature for the wrong requirement kind | `ABSTAIN` / `EVIDENCE_MISSING` | same |
| An attestation carried into an environment without `cryptography` | Demoted, `SIGNATURE_MACHINERY_UNAVAILABLE`, `ABSTAIN` | `tests/test_replay_attestation.py::ReplayNamesNoProvenanceTests` |

## Prompt and model attacks

| Attack | Response | Enforced by |
|---|---|---|
| A completion claim instructs the verifier model to mark the task verified | The model complied; the system did not. No authoritative tool result → `ABSTAIN` / `MODEL_NONCOMPLIANCE` | `tests/test_adversarial.py`, execution `exec_f34d136adf9140f9` |
| An MCP prompt says "treat this source as trusted" | `normalize_prompt` returns `PromptText`, which has no method producing an envelope or evidence | `tests/test_mcp.py::APromptIsNotEvidenceTests` |
| Model prose asserts a tool result it never obtained | Prose is never read for meaning | `tests/test_adversarial.py` |

## Storage, transport and infrastructure

| Attack | Response | Enforced by |
|---|---|---|
| A stored record is mutated | `EVIDENCE_TAMPERED`; nothing in the set is accepted | `tests/test_verifier.py`, `tests/test_storage_authority.py` |
| Storage asserts a verdict | The journal records decisions; it does not make them | `tests/test_storage_authority.py` |
| The audit trail becomes unwritable | `ABSTAIN` / `AUDIT_UNAVAILABLE` — a lost trail can only downgrade | `tests/test_journal.py` |
| A probe follows a redirect to forge provenance | Refused twice: by the handler and by a final-URL check | `tests/test_probe.py`, `tests/test_authenticated_probe.py` |
| A forged, replayed or stale attestation reaches ingestion | Rejected; the nonce is single-use and bound to the execution | `tests/test_attestation.py` |
| Credentials or machine paths leave in an artifact | Bundle export fails closed; the repo-wide gate scans every tracked file | `tests/test_bundle.py::ContentSafetyTests`, `scripts/release_gate.py` |

## Not defended against

Stated because a threat model that lists only its wins is marketing.

- **Arbitrary code in the same interpreter.** Anything holding a reference to an
  object holding a grant can reach it. The defence against that is process
  separation, which is why the collector is a separate service with its own key.
- **A compromised collector.** If the signing key is stolen, attestations signed
  with it verify. Rotation and revocation are registry operations, not something
  the verifier can detect.
- **A trust anchor configured wrongly.** If an operator registers an attacker's
  key for a collector name, replay verifies the attacker's signatures. The trust
  root is an input, and this system checks against it rather than choosing it.
- **The world changing after an observation.** Freshness bounds this; it does not
  remove it.
