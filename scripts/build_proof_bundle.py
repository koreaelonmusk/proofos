"""Derive the public proof bundle the judge-facing site reads.

Everything the site displays comes from here, and everything here comes from
committed evidence: the sanitized execution captures in ``artifacts/executions``
and the cloud proof record. Nothing is typed in by hand.

That constraint is the point. A demo that hard-codes "31 events" drifts from
reality the moment reality changes, and a judge has no way to tell. This script
fails loudly instead: if the bundle cannot be derived, there is no bundle.

Run:  python scripts/build_proof_bundle.py
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXECUTIONS = ROOT / "artifacts" / "executions"
CLOUD_PROOF = ROOT / "artifacts" / "cloud-proof.json"
OUT = ROOT / "web" / "proof-bundle.json"

RECOVERY_ID = "exec_41ec9fac7a1d4dd1"
ADVERSARIAL_ID = "exec_f34d136adf9140f9"

#: Patterns that must never reach a public page. Checked against the finished
#: bundle, not the inputs, because the bundle is what ships.
FORBIDDEN = [
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "google api key"),
    (re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"), "oauth token"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."), "jwt"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"(?i)authorization\s*[:=]\s*bearer"), "authorization header"),
    (re.compile(r"proofos-collector-[a-z0-9]+-[a-z]+\.a\.run\.app"), "collector url"),
]


class BundleError(RuntimeError):
    """Raised when the bundle cannot be derived from committed evidence."""


def load(path: pathlib.Path) -> dict:
    if not path.exists():
        raise BundleError(f"missing evidence: {path.relative_to(ROOT)}")
    return json.loads(path.read_text(encoding="utf-8"))


def turns_of(response: dict) -> list[dict]:
    out = []
    for turn in response.get("agent_turns", []):
        out.append(
            {
                "role": turn["role"],
                "agent_id": turn["agent_id"],
                "model": turn.get("model"),
                "attempt": turn.get("attempt"),
                "duration_ms": turn.get("duration_ms"),
                "tools": [c.get("tool") for c in turn.get("tool_calls", [])],
                "tool_statuses": [c.get("status") for c in turn.get("tool_calls", [])],
                # Kept so a reader can compare what the model said with what the
                # system decided. It is displayed as prose, never as a verdict.
                "final_text": turn.get("final_text", ""),
            }
        )
    return out


def counts_of(events: list[dict]) -> dict:
    def status(name: str) -> int:
        return sum(1 for e in events if e.get("status") == name)

    def tool(name: str) -> int:
        return sum(
            1
            for e in events
            if (e.get("payload") or {}).get("tool") == name
            and e.get("event") == "AGENT_TOOL_CALLED"
        )

    return {
        "events": len(events),
        "action_executed": status("ACTION_EXECUTED"),
        "perform_action_calls": tool("perform_action"),
        "verify_tool_calls": tool("verify_task_completion"),
        "event_types": sorted({e["event"] for e in events}),
    }


def scenario(record: dict, cloud: dict, key: str) -> dict:
    response = record["response"]
    trail = record["audit_trail"]
    events = trail["events"]
    proof = cloud.get(key, {})
    ran_on = proof.get("ran_on", {})

    return {
        "execution_id": record["execution_id"],
        "task_id": response.get("task_id"),
        "claim": response.get("claim"),
        "model": response.get("model"),
        "agent_runtime": response.get("agent_runtime"),
        "live_model_enabled": response.get("live_model_enabled"),
        "final_status": response.get("final_status"),
        "failure_class": response.get("failure_class"),
        "terminal_reason": response.get("terminal_reason"),
        "audit_intact": response.get("audit_intact"),
        "wall_clock_seconds": proof.get("wall_clock_seconds"),
        "turns": turns_of(response),
        "decisions": response.get("decisions", []),
        "attempts": response.get("attempts", []),
        "evidence": response.get("evidence", []),
        "evidence_as_of_attempt": response.get("evidence_as_of_attempt"),
        "cross_service_observation": proof.get("cross_service_observation"),
        "counts": counts_of(events),
        "chain": {
            "chain_ok": trail["chain_ok"],
            "chain_problems": len(trail["chain_problems"]),
        },
        "cloud_logging": proof.get("cloud_logging", {}),
        "provenance": {
            "api_revision": ran_on.get("api_revision"),
            "api_image_digest": ran_on.get("api_image_digest"),
            "collector_revision": ran_on.get("collector_revision"),
            "collector_image_digest": ran_on.get("collector_image_digest"),
            "api_service_account": ran_on.get("api_service_account"),
            "collector_service_account": ran_on.get("collector_service_account"),
            "source_commit": proof.get("source_commit"),
            "region": cloud.get("region"),
        },
        "events": [
            {
                "sequence": e["sequence"],
                "event": e["event"],
                "status": e["status"],
                "agent": e.get("agent"),
                "severity": e.get("severity"),
                "payload": e.get("payload") or {},
                "content_hash": e["content_hash"],
                "previous_hash": e["previous_hash"],
            }
            for e in events
        ],
    }


def build() -> dict:
    cloud = load(CLOUD_PROOF)
    recovery = scenario(
        load(EXECUTIONS / f"{RECOVERY_ID}.json"), cloud, "recovery_execution_on_00010_pfd"
    )
    adversarial = scenario(
        load(EXECUTIONS / f"{ADVERSARIAL_ID}.json"), cloud, "adversarial_live_case"
    )

    bundle = {
        "kind": "proofos-public-proof-bundle",
        "note": "Replay data for the judge-facing site. Every value is derived from a "
                "recorded execution on Google Cloud Run. Nothing here is simulated, and "
                "reading it makes no network request to any ProofOS service.",
        "generated_from": {
            "cloud_proof": "artifacts/cloud-proof.json",
            "executions": [
                f"artifacts/executions/{RECOVERY_ID}.json",
                f"artifacts/executions/{ADVERSARIAL_ID}.json",
            ],
        },
        "project": {
            "region": cloud.get("region"),
            "test_count": cloud.get("test_count"),
            "known_limitations": cloud.get("known_limitations", []),
        },
        "reporting_semantics": cloud.get("reporting_semantics", {}).get("fields", {}),
        "scenarios": {"recovery": recovery, "adversarial": adversarial},
    }

    verify(bundle)
    return bundle


def verify(bundle: dict) -> None:
    """Refuse to emit a bundle that is unsafe or that misrepresents the runs."""
    raw = json.dumps(bundle, ensure_ascii=False)
    for pattern, label in FORBIDDEN:
        if pattern.search(raw):
            raise BundleError(f"bundle contains {label}")

    recovery = bundle["scenarios"]["recovery"]
    adversarial = bundle["scenarios"]["adversarial"]

    if recovery["final_status"] != "VERIFIED":
        raise BundleError("recovery scenario is not a VERIFIED run")
    statuses = [d["status"] for d in recovery["decisions"]]
    if statuses[:2] != ["ABSTAIN", "VERIFIED"]:
        raise BundleError(f"recovery decisions are not ABSTAIN then VERIFIED: {statuses}")

    if adversarial["final_status"] != "ABSTAIN":
        raise BundleError("adversarial scenario did not abstain")
    if adversarial["failure_class"] != "MODEL_NONCOMPLIANCE":
        raise BundleError("adversarial scenario is not MODEL_NONCOMPLIANCE")
    if adversarial["counts"]["verify_tool_calls"] != 0:
        raise BundleError("adversarial scenario called the verification tool")

    for name, s in bundle["scenarios"].items():
        if not s["chain"]["chain_ok"]:
            raise BundleError(f"{name}: audit chain is not intact")
        if s["counts"]["action_executed"] > 1:
            raise BundleError(f"{name}: the action ran more than once")


def main() -> int:
    try:
        bundle = build()
    except BundleError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    rec = bundle["scenarios"]["recovery"]
    adv = bundle["scenarios"]["adversarial"]
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  recovery    {rec['execution_id']}  {rec['final_status']}  "
          f"{rec['counts']['events']} events  chain_ok={rec['chain']['chain_ok']}")
    print(f"  adversarial {adv['execution_id']}  {adv['final_status']}/"
          f"{adv['failure_class']}  verify_tool_calls={adv['counts']['verify_tool_calls']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
