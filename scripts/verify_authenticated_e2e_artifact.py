"""Independently verify a persisted authenticated E2E proof artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

SCHEMA_VERSION = 1
KIND = "proofos-authenticated-collector-e2e"
EXPECTED_KEYS = {
    "schema_version","kind","observed_at","status","launch_verdict_sha256",
    "manifest_sha256","workflow_source_git_sha","github_deployment_id",
    "github_deployment_status_id","deployment_environment","target_origin",
    "transport","collector_id","profile_id","attestation_outcome",
    "signature_and_scope_verified","profile_mismatch_rejected",
    "nonce_binding_rejected","signed_field_tamper_rejected",
    "observed_evidence_recorded_once","attestation_sha256",
    "evidence_content_hash","nonce_sha256","claim_boundary","evidence_sha256",
}


class E2EArtifactError(RuntimeError):
    pass


def _hash_without_digest(value: dict[str, Any]) -> str:
    unsigned={k:v for k,v in value.items() if k!="evidence_sha256"}
    return hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":")).encode()).hexdigest()


def _hex(value: Any, length: int, field: str) -> str:
    if not isinstance(value,str) or len(value)!=length or any(c not in "0123456789abcdef" for c in value.lower()):
        raise E2EArtifactError(f"{field} is malformed")
    return value.lower()


def verify_artifact(value: Any) -> dict[str, Any]:
    if not isinstance(value,dict) or set(value)!=EXPECTED_KEYS:
        raise E2EArtifactError("artifact schema drifted")
    if value.get("schema_version")!=SCHEMA_VERSION or value.get("kind")!=KIND:
        raise E2EArtifactError("unsupported artifact schema")
    digest=_hex(value.get("evidence_sha256"),64,"evidence_sha256")
    if digest!=_hash_without_digest(value):
        raise E2EArtifactError("evidence SHA-256 mismatch")
    if value.get("status")!="AUTHENTICATED_E2E_PROVEN":
        raise E2EArtifactError("artifact does not prove authenticated E2E")
    if value.get("transport")!="google-oidc-ambient-service-identity":
        raise E2EArtifactError("unexpected authenticated transport")
    for field in (
        "signature_and_scope_verified","profile_mismatch_rejected",
        "nonce_binding_rejected","signed_field_tamper_rejected",
        "observed_evidence_recorded_once",
    ):
        if value.get(field) is not True:
            raise E2EArtifactError(f"{field} is not proven")
    for field in ("launch_verdict_sha256","manifest_sha256","attestation_sha256","evidence_content_hash","nonce_sha256"):
        _hex(value.get(field),64,field)
    _hex(value.get("workflow_source_git_sha"),40,"workflow_source_git_sha")
    if not isinstance(value.get("github_deployment_id"),int) or value["github_deployment_id"]<=0:
        raise E2EArtifactError("github_deployment_id is invalid")
    if not isinstance(value.get("github_deployment_status_id"),int) or value["github_deployment_status_id"]<=0:
        raise E2EArtifactError("github_deployment_status_id is invalid")
    if value.get("deployment_environment") not in {"production","preview","development"}:
        raise E2EArtifactError("deployment_environment is invalid")
    if not isinstance(value.get("collector_id"),str) or not value["collector_id"]:
        raise E2EArtifactError("collector_id is invalid")
    if not isinstance(value.get("profile_id"),str) or not value["profile_id"]:
        raise E2EArtifactError("profile_id is invalid")
    boundary=value.get("claim_boundary")
    if not isinstance(boundary,list) or not any(
        isinstance(x,str) and "does not prove restart durability" in x for x in boundary
    ):
        raise E2EArtifactError("claim boundary overstates E2E proof")
    return {
        "valid":True,
        "status":value["status"],
        "workflow_source_git_sha":value["workflow_source_git_sha"],
        "manifest_sha256":value["manifest_sha256"],
        "evidence_sha256":digest,
        "collector_id":value["collector_id"],
        "profile_id":value["profile_id"],
    }


def _self_test() -> None:
    body={
        "schema_version":1,"kind":KIND,"observed_at":1.0,
        "status":"AUTHENTICATED_E2E_PROVEN",
        "launch_verdict_sha256":"a"*64,"manifest_sha256":"b"*64,
        "workflow_source_git_sha":"0123456789abcdef0123456789abcdef01234567",
        "github_deployment_id":123,"github_deployment_status_id":456,
        "deployment_environment":"preview",
        "target_origin":"https://proofos-preview.vercel.app",
        "transport":"google-oidc-ambient-service-identity",
        "collector_id":"collector-http-v1","profile_id":"runtime-health-v1",
        "attestation_outcome":"HEALTHY",
        "signature_and_scope_verified":True,
        "profile_mismatch_rejected":True,"nonce_binding_rejected":True,
        "signed_field_tamper_rejected":True,"observed_evidence_recorded_once":True,
        "attestation_sha256":"c"*64,"evidence_content_hash":"d"*64,
        "nonce_sha256":"e"*64,
        "claim_boundary":[
            "proves one authenticated collector call returned a signed attestation accepted by the existing ingestion kernel",
            "does not prove restart durability, journal durability, or production release approval",
        ],
    }
    artifact={**body,"evidence_sha256":hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":")).encode()).hexdigest()}
    assert verify_artifact(artifact)["valid"]
    tampered=json.loads(json.dumps(artifact)); tampered["nonce_binding_rejected"]=False
    unsigned={k:v for k,v in tampered.items() if k!="evidence_sha256"}
    tampered["evidence_sha256"]=hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    try: verify_artifact(tampered)
    except E2EArtifactError: pass
    else: raise AssertionError("semantic forgery accepted")
    print("authenticated E2E artifact verifier self-test OK")


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("artifact",nargs="?",type=Path); p.add_argument("--self-test",action="store_true")
    a=p.parse_args()
    if a.self_test: _self_test(); return 0
    if a.artifact is None: p.error("artifact path required")
    try: result=verify_artifact(json.loads(a.artifact.read_text()))
    except (OSError,json.JSONDecodeError,E2EArtifactError) as exc:
        print(f"authenticated E2E artifact INVALID: {exc}",file=sys.stderr); return 1
    print(json.dumps(result,sort_keys=True)); return 0


if __name__=="__main__": raise SystemExit(main())
