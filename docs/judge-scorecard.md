# Judge scorecard

Every rubric criterion mapped to something a reviewer can open and check. Where
there is no evidence, the row says so.

## Innovation & Operational Utility — 40%

| Claim | Where to verify it | Status |
|---|---|---|
| An agent cannot certify its own completion | `proofos/capabilities.py` — `ClaimCapability` hard-codes `EXECUTOR`; `tests/test_authority.py` | **PROVEN** |
| Refusal happens on provenance, not absence | `exec_41ec9fac7a1d4dd1` — attempt 1 abstains while executor evidence is already in the ledger | **PROVEN** |
| Autonomous evidence recovery | Same execution — runtime requests collection and re-verifies without human input | **PROVEN** |
| A compromised model cannot manufacture success | `exec_f34d136adf9140f9` — 0 tool calls, `MODEL_NONCOMPLIANCE` | **PROVEN** |
| Operational utility beyond a demo | Failure classes are named and each fails closed; `docs/architecture.md` | **PROVEN** |
| Unlikely hero | Manufacturing quality incident where the interesting agent is the one that refuses | **SYNTHETIC SCENARIO**, labelled |

## Architectural Discipline & Tech Stack — 30%

| Claim | Where to verify it | Status |
|---|---|---|
| Gemini 3.5 or newer | `gemini-3.5-flash` in both recorded executions | **PROVEN** |
| Google Agent Framework | Google ADK — `proofos_agent/agent.py`, `gemini_runner.py` | **PROVEN** |
| Google Cloud infrastructure | Cloud Run ×2, Firestore, Cloud Logging, Secret Manager, Artifact Registry | **PROVEN** |
| Strict role separation | Sealed registry + capability objects; 66 privilege-escalation tests | **PROVEN** |
| Intelligent delegation | Orchestrator owns every transition; agents get one bounded turn | **PROVEN** |
| Separate agent identities | `proofos-api-sa` and `proofos-collector-sa` | **PROVEN** |
| Zero-trust service-to-service | Google OIDC; anonymous `403`, authenticated `200` | **PROVEN** |
| Secure scoped tools | Agent build refuses a tool the registry does not permit; runtime action ceiling held 3 calls → 1 execution | **PROVEN** |
| Durable state | Firestore hash-chained journal, 31 events, `chain_ok=true` | **PROVEN** |
| Failure tolerance | Eleven named failure classes, all fail closed; `tests/test_adversarial.py`, `test_recovery.py` | **PROVEN** |
| Long-horizon context | Durable checkpoint, real process restart at day 21, action not repeated | `artifacts/continuity-proof.json` | **PROVEN DETERMINISTICALLY** |
| Agent discovery / versioning | First-party Agent Cards; pinned versions refuse silent upgrade | `proofos/agent_catalog.py` | **PROVEN** |
| Signed evidence transport | Ed25519 over eleven re-canonicalized fields; forgery, replay, staleness all rejected | **PROVEN** |

## Demo & Production Readiness — 30%

| Claim | Where to verify it | Status |
|---|---|---|
| Reproducible setup | `README.md` quickstart; suite builds its own derived artifacts | **PROVEN** |
| Architecture diagram | `README.md` and `docs/architecture.md`, Mermaid, renders on GitHub | **PROVEN** |
| CI | `.github/workflows/ci.yml` — compile, agent build, registry seal, full suite, both images, key-material scan | **PROVEN** |
| Public judge console | `web/`, replay-only, contacts zero hosts | **PROVEN** |
| Real cloud executions in the demo | Both replays are derived from committed sanitized captures | **PROVEN** |
| Replay independent of quota | Evidence inlined; no connection primitive in the standalone build | **PROVEN** |
| Visible Google Cloud proof | Revisions, digests, service accounts, region in `artifacts/cloud-proof.json` | **PROVEN** |
| Honest limitations | `README.md` — *Not claimed* | **PROVEN** |
| Hosted URL | GitHub Pages workflow ready; publishes from `main` | **PENDING MERGE** |
| Demo video | `docs/demo-script.md` written; recording not made | **NOT DONE** |

## Not claimed

Listing these as absent is more useful than implying otherwise, and it is the
standard ProofOS applies to agents.

| | Status |
|---|---|
| Google Memory Bank product | **NOT CLAIMED** |
| Enterprise Agent Gateway | **NOT CLAIMED** — the IAM-gated boundary is analogous, not a gateway product |
| Model Armor | **NOT CLAIMED** |
| Vertex AI in the authoritative runs | **NOT CLAIMED** — configuration path exists; the recorded runs used the Gemini API |
| Production readiness, SLA, benchmarks | **NOT CLAIMED** |
| Real industrial equipment integration | **NOT CLAIMED** |

## Release checklist

- [x] CI green on the pushed SHA
- [x] Full suite passes from a clean clone
- [x] README is a judge landing page, no stale claims
- [x] Architecture diagram renders on GitHub
- [x] Proof bundle regenerates byte-for-byte from committed evidence
- [x] Judge console contacts zero hosts
- [x] Secret scan clean across public files
- [x] Devpost package drafted
- [ ] Merged to `main` — root repository URL shows the submission
- [ ] GitHub Pages published
- [ ] Demo video recorded, ≤ 4 minutes, public URL
- [ ] Devpost submitted
