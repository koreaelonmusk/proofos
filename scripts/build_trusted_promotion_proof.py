"""Build a Trusted Promotion Proof from independently verified live evidence.

This proof never rewrites the public launch verdict. It authorizes only the next
authenticated-E2E evidence step when the public observer was blocked at Vercel's
edge but a same-run GitHub OIDC Trusted Source independently proved production
health, readiness, and application-level anonymous caller denial.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_launch_verdict import VerdictVerificationError, verify_verdict
from verify_vercel_trusted_source_artifact import (
    TrustedSourceArtifactError,
    verify_evidence as verify_trusted_source,
)

SCHEMA_VERSION = 1
KIND = "proofos-trusted-promotion-proof"
STATUS = "AUTHORIZED_FOR_AUTHENTICATED_E2E"
TRUSTED_READY = "TRUSTED_SOURCE_ACCEPTED_READY_AND_ANONYMOUS_DENIED"
BLOCKED = "BLOCKED_BY_DEPLOYMENT_PROTECTION"
_ALLOWED_REASON_SETS = {
    frozenset(
        {
            "deployment_protection_blocked_application_observation",
            "automation_bypass_not_configured_for_workflow",
        }
    ),
    frozenset(
        {
            "deployment_protection_blocked_application_observation",
            "automation_bypass_attempted_but_edge_still_blocked",
        }
    ),
}


class TrustedPromotionError(RuntimeError):
    pass


def _canonical_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def derive_trusted_promotion(
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    trusted_source: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    try:
        launch = verify_verdict(
            health,
            trust,
            manifest,
            verdict,
            expected_git_sha=expected_git_sha,
        )
    except VerdictVerificationError as exc:
        raise TrustedPromotionError(f"public launch evidence invalid: {exc}") from exc

    try:
        trusted = verify_trusted_source(trusted_source)
    except TrustedSourceArtifactError as exc:
        raise TrustedPromotionError(f"trusted-source evidence invalid: {exc}") from exc

    if not isinstance(verdict, dict) or not isinstance(trusted_source, dict):
        raise TrustedPromotionError("promotion inputs must be JSON objects")

    if launch["status"] != "HOLD":
        raise TrustedPromotionError("trusted promotion is only defined for public HOLD")
    if verdict.get("health_outcome") != BLOCKED or verdict.get("trust_outcome") != BLOCKED:
        raise TrustedPromotionError(
            "public HOLD must be caused by deployment protection blocking both observations"
        )
    if verdict.get("readiness_issues") != []:
        raise TrustedPromotionError("public HOLD carries unrelated readiness issues")
    reasons = verdict.get("reasons")
    if not isinstance(reasons, list) or frozenset(reasons) not in _ALLOWED_REASON_SETS:
        raise TrustedPromotionError(
            "public HOLD contains reasons outside the deployment-protection boundary"
        )

    if launch["deployment_environment"] != "production":
        raise TrustedPromotionError("trusted promotion is production-only")
    if trusted["outcome"] != TRUSTED_READY:
        raise TrustedPromotionError(
            "trusted source did not prove ready plus anonymous denial"
        )
    if trusted["target_origin"] != launch["target_origin"]:
        raise TrustedPromotionError("trusted source targets a different origin")
    if trusted["workflow_source_git_sha"] != launch["workflow_source_git_sha"]:
        raise TrustedPromotionError("trusted source binds to a different Git SHA")

    event = trusted_source.get("deployment_event")
    if not isinstance(event, dict):
        raise TrustedPromotionError("trusted source deployment event is missing")
    if (
        event.get("github_deployment_id") != launch["github_deployment_id"]
        or event.get("github_deployment_status_id")
        != launch["github_deployment_status_id"]
        or event.get("environment") != "production"
        or event.get("environment_url") != launch["target_origin"]
        or event.get("source_git_sha") != launch["workflow_source_git_sha"]
    ):
        raise TrustedPromotionError(
            "trusted source and public bundle do not bind to the same deployment event"
        )

    claims = trusted_source.get("oidc_claims")
    if not isinstance(claims, dict):
        raise TrustedPromotionError("trusted-source OIDC claim projection is missing")
    if claims.get("event_name") != "deployment_status":
        raise TrustedPromotionError("trusted source was not minted for deployment_status")
    if claims.get("workflow_ref") != (
        "koreaelonmusk/proofos/.github/workflows/"
        "vercel-live-smoke.yml@refs/heads/main"
    ):
        raise TrustedPromotionError("trusted source is not bound to the main live workflow")

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": STATUS,
        "target_origin": launch["target_origin"],
        "workflow_source_git_sha": launch["workflow_source_git_sha"],
        "github_deployment_id": launch["github_deployment_id"],
        "github_deployment_status_id": launch["github_deployment_status_id"],
        "deployment_environment": launch["deployment_environment"],
        "manifest_sha256": launch["manifest_sha256"],
        "verdict_sha256": launch["verdict_sha256"],
        "trusted_source_evidence_sha256": trusted["evidence_sha256"],
        "public_status": launch["status"],
        "public_reasons": reasons,
        "trusted_source_outcome": trusted["outcome"],
        "authorization_scope": "authenticated_e2e_evidence_only",
        "next_required_evidence": [
            "fresh_dual_identity_authenticated_collection",
            "signed_attestation_verification",
            "tamper_nonce_and_profile_rejection",
        ],
        "claim_boundary": [
            "does not rewrite or upgrade the public observer launch verdict",
            "authorizes only the next authenticated E2E evidence step",
            "requires public HOLD to be caused only by Vercel edge observation blocking",
            "requires same-origin same-SHA same-deployment Trusted Source READY evidence",
            "does not prove authenticated collection or production GO",
        ],
    }
    return {**unsigned, "promotion_sha256": _canonical_hash(unsigned)}


def _self_test() -> None:
    from build_live_launch_verdict import _blocked_health, _blocked_trust, _manifest, derive_verdict
    from verify_vercel_trusted_source_artifact import _base, _signed

    origin = "https://proofos-production.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"
    health = _blocked_health(origin, sha)
    trust = _blocked_trust(origin, sha, bypass_attempted=False)

    # The launch fixtures default to preview. Trusted promotion is deliberately
    # production-only, so bind both constituent artifacts to production.
    for evidence in (health, trust):
        evidence["deployment_event"]["environment"] = "production"
        evidence["evidence_sha256"] = _canonical_hash(
            {k: v for k, v in evidence.items() if k != "evidence_sha256"}
        )

    manifest = _manifest(health, trust, sha)
    verdict = derive_verdict(health, trust, manifest, expected_git_sha=sha)

    trusted = _base(TRUSTED_READY)
    trusted.update(
        {
            "health": {
                "status": "ok",
                "service": "proofos-collector",
                "runtime": {
                    "platform": "vercel",
                    "environment": "production",
                    "deployment_id": "dpl_test",
                    "git_sha": sha,
                    "url": origin,
                },
            },
            "readiness": {
                "status": "ready",
                "service": "proofos-collector",
                "issues": [],
            },
            "anonymous_collect": {
                "outcome": "ANONYMOUS_COLLECTION_DENIED",
                "http_status": 401,
            },
            "claim_boundary": [
                "proves Vercel Trusted Sources accepted the GitHub Actions OIDC request",
                "records only the public health/readiness contract after edge authentication",
                "proves the reached application denied anonymous collection before probe or signing authority",
                "does not prove authenticated collector invocation or signed evidence collection",
                "does not reveal or persist the OIDC token",
            ],
        }
    )
    trusted["workflow_source_git_sha"] = sha
    trusted["target_origin"] = origin
    trusted["deployment_event"]["source_git_sha"] = sha
    trusted["deployment_event"]["environment_url"] = origin
    trusted["oidc_claims"]["workflow_sha"] = sha
    trusted = _signed(trusted)

    proof = derive_trusted_promotion(
        health, trust, manifest, verdict, trusted, expected_git_sha=sha
    )
    assert proof["status"] == STATUS
    assert len(proof["promotion_sha256"]) == 64

    bad = json.loads(json.dumps(trusted))
    bad["deployment_event"]["github_deployment_status_id"] = 999
    bad["evidence_sha256"] = _canonical_hash(
        {k: v for k, v in bad.items() if k != "evidence_sha256"}
    )
    try:
        derive_trusted_promotion(
            health, trust, manifest, verdict, bad, expected_git_sha=sha
        )
    except TrustedPromotionError:
        pass
    else:
        raise AssertionError("cross-deployment trusted evidence was accepted")

    print("trusted promotion proof self-test OK")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedPromotionError(
            f"could not read promotion input: {type(exc).__name__}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health", nargs="?", type=Path)
    parser.add_argument("trust", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("verdict", nargs="?", type=Path)
    parser.add_argument("trusted_source", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if any(
        item is None
        for item in (
            args.health,
            args.trust,
            args.manifest,
            args.verdict,
            args.trusted_source,
            args.output,
        )
    ):
        parser.error("five evidence inputs and --output are required")
    if not args.expected_git_sha:
        parser.error("--expected-git-sha is required")

    try:
        proof = derive_trusted_promotion(
            _load(args.health),
            _load(args.trust),
            _load(args.manifest),
            _load(args.verdict),
            _load(args.trusted_source),
            expected_git_sha=args.expected_git_sha,
        )
    except TrustedPromotionError as exc:
        print(f"trusted promotion proof FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(proof, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
