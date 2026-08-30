# Integration guide

Two paths reach the verifier and only one of them can produce `OBSERVED`.
Every integration is one or both of these.

## Path 1 — a framework has something to say

```
your framework
  → a semantic adapter        proofos.adapters / .mcp / .a2a / .adk / .github
  → AdapterEnvelope
  → evidence_from_envelope    proofos.evidence_bridge   → EXECUTOR evidence
  → the verifier
```

```python
from proofos import ProofOS, Requirement
from proofos.adapters import PythonAdapter
from proofos.evidence_bridge import evidence_from_envelope

envelope = PythonAdapter("acme-runner", framework="langgraph").normalize(
    actor_id="deploy-agent",
    task_id="DEPLOY-9",
    claim="Deployment complete.",
    tool_results=[{"tool": "http_get", "payload": {"status": 200}}],
    extra={"verified": True},          # kept under claimed_by_sender, worth nothing
)

decision = ProofOS().verify(
    envelope.claim.text,
    (Requirement("service_health", max_age_seconds=900),),
    evidence_from_envelope(envelope, "service_health"),
)
# ABSTAIN / EVIDENCE_UNTRUSTED  — correct, and the whole point
```

This path abstains. It is supposed to. Everything in it came from the component
whose claim is being examined.

Other transports are the same shape:
`HttpAdapter().normalize(body)`, `McpAdapter(...).normalize_tool_result(...)`,
`A2aAdapter(...).normalize_task(...)`, `AdkAdapter(...).normalize_result(...)`,
`github.normalize_pull_request(payload)`.

## Path 2 — something independent observed reality

```
collector process (separate service, holds the private key)
  → signed ObservationAttestation
  → AttestationIngestor.ingest      registry · scope · signature · binding · freshness
  → ObservationCapability.record_observation   → OBSERVED evidence
  → EvidenceLedger
  → ProofOS().verify_recorded(...)
```

```python
from proofos import EvidenceLedger, ProofOS, Requirement
from proofos.capabilities import ObservationCapability
from proofos.collector_registry import registry_for
from proofos.ingestion import AttestationIngestor, NonceLedger

ledger = EvidenceLedger()
ledger.open_task("DEPLOY-9", (Requirement("runtime_health", max_age_seconds=900),))
capability = ObservationCapability(ledger, "proofos-collector", ("runtime_health",))
ledger.seal()                                  # no further grants may be issued

registry = registry_for("proofos-collector", collector_public_key_b64,
                        ("runtime_health",), ("cloud-run-health",))
ingestor = AttestationIngestor({"proofos-collector": capability}, registry,
                               NonceLedger())

nonce = ingestor.issue_nonce(execution_id, "DEPLOY-9", "runtime_health")
# ... the collector observes, and signs over that nonce ...
result = ingestor.ingest(envelope, execution_id, "DEPLOY-9",
                         "runtime_health", "cloud-run-health", nonce, 900)

decision = ProofOS().verify_recorded(ledger, "DEPLOY-9", "Deployment complete.")
```

`verify_recorded` is the only entry point that can return `VERIFIED`, and it
reads the requirements from the ledger rather than from the caller.

## Portable proof

```python
from proofos.bundle import export_bundle, load_bundle, render_inspection
from proofos.replay import replay_historical, re_evaluate_at

bundle = export_bundle(
    claim=claim, requirements=ledger.requirements(task), evidence=ledger.evidence(task),
    task_id=task, verification_time=now, created_at=now,
    recorded_verdict=str(decision.status), recorded_reason=str(decision.reason),
    attestations={evidence.content_hash: attestation.to_dict()},
)

# elsewhere, later, on another machine
result = replay_historical(load_bundle(text), trust_anchor=registry,
                           expected_digest=known_digest)
```

`trust_anchor` comes from your environment. Without it, replay abstains.
See [proof bundles](proof-bundles.md).

## Patterns that must never be written

Each of these is a real shape somebody will reach for. None of them works, and
the reason is in the right-hand column.

| Do not | Why |
|---|---|
| `if framework_event == "success": VERIFIED` | a framework event is a claim by the thing being examined |
| `if http_status == 200: OBSERVED` | a probe the executor ran is a fact about that call |
| `if github_check.success: VERIFIED` | CI success is evidence *of CI*, not of an arbitrary runtime requirement |
| trust an MCP server because it is named `proofos-*` | a name is a string the other party chose |
| `if a2a_task.state == "completed": VERIFIED` | the state is what the remote agent decided to report |
| `if adk_callback == "after_agent_callback": OBSERVED` | a hook is a place, not a witness |
| set `source="OBSERVED"` on evidence you construct | `ProofOS.verify` raises `ProvenanceNotDeclarable` |
| trust a collector because a bundle says `trusted: true` | a bundle cannot carry permission to believe it |
| accept a signature without a trust anchor | a valid signature proves who signed bytes |
| count three relayed copies as three observations | relay is not corroboration |

## Handling `ABSTAIN`

`ABSTAIN` is an answer, not an error. `Decision.reason` says what to do:

| Reason | What is needed |
|---|---|
| `EVIDENCE_MISSING` | evidence of the missing kinds |
| `EVIDENCE_UNTRUSTED` | independent evidence; a report from the change under review cannot satisfy a requirement |
| `EVIDENCE_STALE` | observe again — the evidence is real but outside its horizon |
| `EVIDENCE_INVALID` | the governing observation reports failure; fix the system, not the evidence |
| `EVIDENCE_TAMPERED` | a record no longer matches its digest; do not trust this evidence set |
| `MALFORMED_INPUT` | the claim or evidence set is not well formed |
| `VERIFIER_FAILURE` | the verifier itself errored, and failed closed |

`proofos.github.render_check` turns a decision into something a person can act
on, including which confident-sounding text on the page was read and not counted.
