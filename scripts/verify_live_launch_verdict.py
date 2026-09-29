"""Independently verify a live launch verdict against its sealed evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_evidence_manifest import ManifestVerificationError, verify_manifest

SCHEMA_VERSION = 2
KIND = "proofos-live-launch-verdict"
EXPECTED_KEYS = {
    "schema_version","kind","status","target_origin","workflow_source_git_sha",
    "github_deployment_id","github_deployment_status_id","deployment_environment",
    "manifest_sha256","pair_sha256","health_evidence_sha256","trust_evidence_sha256",
    "health_outcome","trust_outcome","bypass_attempted","readiness_issues",
    "reasons","next_required_evidence","claim_boundary","verdict_sha256",
}


class VerdictVerificationError(RuntimeError):
    pass


def _digest(v: dict[str, Any]) -> str:
    unsigned={k:x for k,x in v.items() if k!="verdict_sha256"}
    return hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def verify_verdict(health: Any, trust: Any, manifest: Any, verdict: Any, *, expected_git_sha: str="") -> dict[str, Any]:
    try:
        sealed=verify_manifest(health,trust,manifest,expected_git_sha=expected_git_sha)
    except ManifestVerificationError as exc:
        raise VerdictVerificationError(f"sealed evidence invalid: {exc}") from exc
    if not isinstance(verdict,dict) or set(verdict)!=EXPECTED_KEYS:
        raise VerdictVerificationError("verdict schema drifted")
    if verdict.get("schema_version")!=SCHEMA_VERSION or verdict.get("kind")!=KIND:
        raise VerdictVerificationError("unsupported verdict schema")
    digest=verdict.get("verdict_sha256")
    if not isinstance(digest,str) or len(digest)!=64 or digest.lower()!=_digest(verdict):
        raise VerdictVerificationError("verdict SHA-256 mismatch")

    bindings={
        "target_origin":sealed["target_origin"],
        "workflow_source_git_sha":sealed["workflow_source_git_sha"],
        "github_deployment_id":sealed["github_deployment_id"],
        "github_deployment_status_id":sealed["github_deployment_status_id"],
        "deployment_environment":sealed["deployment_environment"],
        "manifest_sha256":sealed["manifest_sha256"],
        "pair_sha256":sealed["pair_sha256"],
        "health_evidence_sha256":sealed["health_evidence_sha256"],
        "trust_evidence_sha256":sealed["trust_evidence_sha256"],
    }
    for key,value in bindings.items():
        if verdict.get(key)!=value:
            raise VerdictVerificationError(f"verdict binding mismatch: {key}")

    if verdict.get("health_outcome")!=manifest.get("health_outcome") or verdict.get("trust_outcome")!=manifest.get("trust_outcome"):
        raise VerdictVerificationError("verdict outcome does not match manifest")

    if not isinstance(trust,dict) or verdict.get("bypass_attempted") is not trust.get("bypass_attempted"):
        raise VerdictVerificationError("verdict bypass state does not match trust evidence")

    trust_outcome=verdict["trust_outcome"]
    issues=verdict.get("readiness_issues")
    if not isinstance(issues,list):
        raise VerdictVerificationError("readiness_issues must be a list")

    if trust_outcome=="BLOCKED_BY_DEPLOYMENT_PROTECTION":
        status="HOLD"; expected_issues=[]
        reasons=["deployment_protection_blocked_application_observation"]
        if verdict["bypass_attempted"]:
            reasons+=["automation_bypass_attempted_but_edge_still_blocked"]
            nxt=["repair_vercel_automation_bypass","rerun_live_trust_observation"]
        else:
            reasons+=["automation_bypass_not_configured_for_workflow"]
            nxt=["configure_vercel_automation_bypass","rerun_live_trust_observation"]
    elif trust_outcome=="READINESS_BLOCKED_AND_ANONYMOUS_DENIED":
        status="HOLD"; expected_issues=[]
        reasons=["application_caller_auth_observed","readiness_not_observed_through_deployment_edge"]
        nxt=["observe_application_readiness","rerun_live_trust_observation"]
    elif trust_outcome=="CONFIG_NOT_READY_AND_ANONYMOUS_DENIED":
        readiness=trust.get("readiness",{}).get("observation",{})
        raw=readiness.get("issues")
        if not isinstance(raw,list) or not raw:
            raise VerdictVerificationError("missing readiness issues")
        expected_issues=sorted(raw); status="HOLD"
        reasons=["collector_configuration_not_ready", *[f"readiness:{x}" for x in expected_issues]]
        nxt=["resolve_collector_readiness_issues","rerun_live_trust_observation"]
    elif trust_outcome=="READY_AND_ANONYMOUS_DENIED":
        status="READY_FOR_AUTHENTICATED_E2E"; expected_issues=[]
        reasons=["collector_readiness_observed","anonymous_collection_denial_observed","authenticated_end_to_end_collection_not_yet_proven"]
        nxt=["authenticated_collection_with_fresh_nonce","signed_attestation_verification","tamper_nonce_and_profile_rejection"]
    else:
        raise VerdictVerificationError("unsupported trust outcome")

    if verdict.get("status")!=status or issues!=expected_issues or verdict.get("reasons")!=reasons or verdict.get("next_required_evidence")!=nxt:
        raise VerdictVerificationError("verdict semantics do not match sealed evidence")
    boundary=verdict.get("claim_boundary")
    if not isinstance(boundary,list) or not any("not production GO" in x for x in boundary if isinstance(x,str)):
        raise VerdictVerificationError("verdict claim boundary overstates authority")
    return {"valid":True,"status":status,"manifest_sha256":sealed["manifest_sha256"],"verdict_sha256":digest.lower()}


def _self_test() -> None:
    from verify_live_evidence_pair import _health_sample,_trust_sample,build_manifest,verify_pair
    from build_live_launch_verdict import derive_verdict
    sha="0123456789abcdef0123456789abcdef01234567"; origin="https://proofos-preview.vercel.app"
    h=_health_sample(origin,sha); t=_trust_sample(origin,sha); m=build_manifest(verify_pair(h,t,expected_git_sha=sha))
    v=derive_verdict(h,t,m,expected_git_sha=sha)
    assert verify_verdict(h,t,m,v,expected_git_sha=sha)["valid"]
    bad=json.loads(json.dumps(v)); bad["status"]="READY_FOR_AUTHENTICATED_E2E"
    try: verify_verdict(h,t,m,bad,expected_git_sha=sha)
    except VerdictVerificationError: pass
    else: raise AssertionError("tampered verdict accepted")
    print("live launch verdict verifier self-test OK")


def main() -> int:
    p=argparse.ArgumentParser()
    for name in ("health","trust","manifest","verdict"): p.add_argument(name,nargs="?",type=Path)
    p.add_argument("--expected-git-sha",default=""); p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test: _self_test(); return 0
    if None in (a.health,a.trust,a.manifest,a.verdict): p.error("four artifact paths are required")
    try:
        result=verify_verdict(*[json.loads(getattr(a,n).read_text()) for n in ("health","trust","manifest","verdict")],expected_git_sha=a.expected_git_sha)
    except (OSError,json.JSONDecodeError,VerdictVerificationError) as exc:
        print(f"live launch verdict INVALID: {exc}",file=sys.stderr); return 1
    print(json.dumps(result,sort_keys=True)); return 0


if __name__=="__main__": raise SystemExit(main())
