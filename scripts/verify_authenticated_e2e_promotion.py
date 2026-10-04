"""Cross-check live launch evidence with authenticated signed-collection evidence.

This gate proves continuity between the pre-auth deployment observation and the
authenticated collector round trip. It deliberately stops short of a production
GO decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verify_authenticated_collection_artifact import (
    AuthenticatedEvidenceVerificationError,
    PUBLIC_KEY_ENV,
    verify_evidence as verify_authenticated_evidence,
)
from verify_live_launch_verdict import (
    VerdictVerificationError,
    verify_verdict,
)
from verify_trusted_promotion_proof import (
    TrustedPromotionVerificationError,
    verify_promotion as verify_trusted_promotion,
)
from verify_followup_trusted_promotion import (
    FollowupTrustedPromotionVerificationError,
    verify_followup_promotion,
)

SCHEMA_VERSION = 3
KIND = "proofos-authenticated-e2e-promotion"
PROMOTED = "AUTHENTICATED_E2E_VERIFIED"
HOLD = "HOLD"


class PromotionVerificationError(RuntimeError):
    pass


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_promotion(
    health_evidence: Any,
    trust_evidence: Any,
    manifest: Any,
    launch_verdict: Any,
    authenticated_evidence: Any,
    *,
    expected_git_sha: str = "",
    trusted_source: Any | None = None,
    trusted_promotion: Any | None = None,
    followup_trusted_source: Any | None = None,
    provider_diagnosis: Any | None = None,
    provider_admission: Any | None = None,
    followup_promotion: Any | None = None,
    source_run_id: int = 0,
    followup_run_id: int = 0,
) -> dict[str, Any]:
    try:
        launch = verify_verdict(
            health_evidence,
            trust_evidence,
            manifest,
            launch_verdict,
            expected_git_sha=expected_git_sha,
        )
    except VerdictVerificationError as exc:
        raise PromotionVerificationError(f"launch verdict invalid: {exc}") from exc

    try:
        authenticated = verify_authenticated_evidence(
            authenticated_evidence,
            expected_git_sha=expected_git_sha,
        )
    except AuthenticatedEvidenceVerificationError as exc:
        raise PromotionVerificationError(
            f"authenticated collection evidence invalid: {exc}"
        ) from exc

    if launch["target_origin"] != authenticated["target_origin"]:
        raise PromotionVerificationError(
            "launch and authenticated evidence target different origins"
        )
    if launch["workflow_source_git_sha"] != authenticated["workflow_source_git_sha"]:
        raise PromotionVerificationError(
            "launch and authenticated evidence bind to different Git SHAs"
        )

    reasons: list[str] = []
    next_required: list[str] = []
    authorization_basis = "public_launch_verdict"
    trusted_promotion_sha256 = None
    authority_ready = launch["status"] == "READY_FOR_AUTHENTICATED_E2E"

    legacy_requested = trusted_promotion is not None
    followup_requested = any(
        item is not None
        for item in (
            followup_trusted_source,
            provider_diagnosis,
            provider_admission,
            followup_promotion,
        )
    )
    if (
        trusted_source is not None
        and not legacy_requested
        and not followup_requested
    ):
        raise PromotionVerificationError(
            "trusted source cannot be supplied without a promotion proof path"
        )

    if not authority_ready and legacy_requested:
        if trusted_source is None:
            raise PromotionVerificationError(
                "legacy trusted promotion requires the trusted source constituent"
            )
        try:
            promoted = verify_trusted_promotion(
                health_evidence,
                trust_evidence,
                manifest,
                launch_verdict,
                trusted_source,
                trusted_promotion,
                expected_git_sha=expected_git_sha,
                expected_source_run_id=source_run_id,
            )
        except TrustedPromotionVerificationError as exc:
            raise PromotionVerificationError(
                f"trusted promotion proof invalid: {exc}"
            ) from exc
        if promoted["target_origin"] != launch["target_origin"]:
            raise PromotionVerificationError(
                "trusted promotion and launch target different origins"
            )
        if promoted["workflow_source_git_sha"] != launch["workflow_source_git_sha"]:
            raise PromotionVerificationError(
                "trusted promotion and launch bind to different Git SHAs"
            )
        authority_ready = promoted["status"] == "AUTHORIZED_FOR_AUTHENTICATED_E2E"
        authorization_basis = "trusted_promotion_proof"
        trusted_promotion_sha256 = promoted["promotion_sha256"]

    followup_inputs = (
        followup_trusted_source,
        provider_diagnosis,
        provider_admission,
        followup_promotion,
    )
    if not authority_ready and followup_requested:
        if trusted_source is None or any(item is None for item in followup_inputs):
            raise PromotionVerificationError(
                "original Trusted Source, follow-up Trusted Source, provider diagnosis, "
                "provider admission, and follow-up promotion must be supplied together"
            )
        if (
            not isinstance(followup_run_id, int)
            or isinstance(followup_run_id, bool)
            or followup_run_id <= 0
        ):
            raise PromotionVerificationError(
                "follow-up promotion requires a positive follow-up run id"
            )
        try:
            promoted = verify_followup_promotion(
                health_evidence,
                trust_evidence,
                manifest,
                launch_verdict,
                trusted_source,
                followup_trusted_source,
                provider_diagnosis,
                provider_admission,
                followup_promotion,
                expected_git_sha=expected_git_sha,
                expected_source_run_id=source_run_id,
                expected_followup_run_id=followup_run_id,
            )
        except FollowupTrustedPromotionVerificationError as exc:
            raise PromotionVerificationError(
                f"follow-up trusted promotion proof invalid: {exc}"
            ) from exc
        if promoted["target_origin"] != launch["target_origin"]:
            raise PromotionVerificationError(
                "follow-up trusted promotion and launch target different origins"
            )
        if promoted["workflow_source_git_sha"] != launch["workflow_source_git_sha"]:
            raise PromotionVerificationError(
                "follow-up trusted promotion and launch bind to different Git SHAs"
            )
        authority_ready = promoted["status"] == "AUTHORIZED_FOR_AUTHENTICATED_E2E"
        authorization_basis = "followup_trusted_promotion_proof"
        trusted_promotion_sha256 = promoted["promotion_sha256"]

    if not authority_ready:
        status = HOLD
        reasons.append("launch_authority_not_ready_for_authenticated_e2e")
        next_required.extend(launch["next_required_evidence"])
    elif authenticated["attestation_outcome"] != "HEALTHY":
        status = HOLD
        reasons.append(
            "authenticated_collection_returned_" + authenticated["attestation_outcome"].lower()
        )
        next_required.append("repeat_authenticated_collection_after_target_recovery")
    elif authenticated["attestation_status_code"] != 200:
        status = HOLD
        reasons.append("authenticated_collection_status_not_200")
        next_required.append("repeat_authenticated_collection_after_target_recovery")
    elif authenticated["cryptographic_checks"] != {
        "signature_verified": True,
        "nonce_tamper_rejected": True,
        "profile_tamper_rejected": True,
    }:
        raise PromotionVerificationError(
            "authenticated cryptographic checks are incomplete"
        )
    else:
        status = PROMOTED
        reasons.extend(
            [
                (
                    "trusted_source_pre_auth_boundary_observed"
                    if authorization_basis in {
                        "trusted_promotion_proof",
                        "followup_trusted_promotion_proof",
                    }
                    else "pre_auth_health_observed"
                ),
                "collector_readiness_observed",
                "anonymous_collection_denial_observed",
                "authenticated_signed_collection_observed",
                "signature_verified",
                "fresh_nonce_bound",
                "profile_bound",
                "nonce_tamper_rejected",
                "profile_tamper_rejected",
            ]
        )
        next_required.extend(
            [
                "repeat_e2e_on_next_deployment",
                "operator_review_before_any_rollout_decision",
            ]
        )

    if not isinstance(launch_verdict, dict):
        raise PromotionVerificationError("launch verdict must be an object")
    launch_digest = launch_verdict.get("verdict_sha256")
    if not isinstance(launch_digest, str) or len(launch_digest) != 64:
        raise PromotionVerificationError("launch verdict digest is malformed")

    if not isinstance(authenticated_evidence, dict):
        raise PromotionVerificationError("authenticated evidence must be an object")
    auth_digest = authenticated_evidence.get("evidence_sha256")
    if not isinstance(auth_digest, str) or len(auth_digest) != 64:
        raise PromotionVerificationError("authenticated evidence digest is malformed")

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "status": status,
        "target_origin": launch["target_origin"],
        "workflow_source_git_sha": launch["workflow_source_git_sha"],
        "github_deployment_id": launch["github_deployment_id"],
        "github_deployment_status_id": launch["github_deployment_status_id"],
        "deployment_environment": launch["deployment_environment"],
        "launch_verdict_sha256": launch_digest.lower(),
        "manifest_sha256": launch["manifest_sha256"],
        "authorization_basis": authorization_basis,
        "trusted_promotion_sha256": trusted_promotion_sha256,
        "source_run_id": source_run_id if source_run_id > 0 else None,
        "followup_run_id": followup_run_id if followup_run_id > 0 else None,
        "authenticated_evidence_sha256": auth_digest.lower(),
        "collector_id": authenticated["collector_id"],
        "attestation_outcome": authenticated["attestation_outcome"],
        "attestation_status_code": authenticated["attestation_status_code"],
        "request_nonce_sha256": authenticated["request_nonce_sha256"],
        "cryptographic_checks": authenticated["cryptographic_checks"],
        "reasons": reasons,
        "next_required_evidence": list(dict.fromkeys(next_required)),
        "claim_boundary": [
            "proves continuity between one verified deployment evidence bundle and one authenticated signed collector observation",
            "AUTHENTICATED_E2E_VERIFIED proves the evidence path for this exact origin and Git SHA only",
            "does not authorize a production rollout, traffic shift, IAM change, release, or business decision",
        ],
    }
    return {**unsigned, "promotion_sha256": _digest(unsigned)}


def _auth_fixture(origin: str, sha: str, *, healthy: bool = True) -> dict[str, Any]:
    from proofos.attestation import AttestationSigner, Outcome

    signer = AttestationSigner.generate("collector-http-v1")
    os.environ[PUBLIC_KEY_ENV] = signer.public_key_b64()
    capture = 1_800_000_000.0
    nonce = "promotion-self-test-nonce"
    outcome = Outcome.HEALTHY if healthy else Outcome.UNHEALTHY_STATUS
    status_code = 200 if healthy else 503
    attestation = signer.sign(
        execution_id="promotion-e2e",
        task_id="PROMOTION-E2E",
        kind="runtime",
        profile_id="runtime-health-v1",
        request_nonce=nonce,
        observed_at=capture - 1,
        outcome=outcome,
        status_code=status_code,
        response_digest_value="d" * 64,
        detail=f"{outcome.value} via runtime-health-v1",
    )
    unsigned = {
        "schema_version": 1,
        "kind": "proofos-authenticated-collection-observation",
        "observed_at": capture,
        "target_origin": origin,
        "workflow_source_git_sha": sha,
        "outcome": "SIGNED_ATTESTATION_VERIFIED",
        "request": {
            "execution_id": "promotion-e2e",
            "task_id": "PROMOTION-E2E",
            "evidence_kind": "runtime",
            "profile_id": "runtime-health-v1",
            "request_nonce": nonce,
        },
        "attestation": attestation.to_dict(),
        "trusted_public_key_sha256": hashlib.sha256(
            signer.public_key_b64().encode("ascii")
        ).hexdigest(),
        "cryptographic_checks": {
            "signature_verified": True,
            "nonce_tamper_rejected": True,
            "profile_tamper_rejected": True,
        },
        "claim_boundary": [
            "proves a fresh authenticated request returned an attestation signed by the preconfigured collector public key",
            "proves execution, task, evidence kind, profile, and nonce were bound to the signed attestation",
            "proves nonce and profile tampering invalidate the signature",
            "retains the one-time nonce and signed attestation for independent replay-safe audit",
            "does not by itself promote the observed outcome into a ProofOS VERIFIED execution",
            "does not expose bearer tokens, private signing keys, or trusted public-key configuration",
        ],
    }
    return {**unsigned, "evidence_sha256": _digest(unsigned)}


def _self_test() -> None:
    from build_live_launch_verdict import (
        _manifest,
        _observed_health,
        _ready_trust,
        derive_verdict,
    )

    origin = "https://proofos-preview.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"
    health = _observed_health(origin, sha)
    trust = _ready_trust(origin, sha)
    manifest = _manifest(health, trust, sha)
    launch = derive_verdict(
        health,
        trust,
        manifest,
        expected_git_sha=sha,
    )

    try:
        authenticated = _auth_fixture(origin, sha, healthy=True)
        promoted = verify_promotion(
            health,
            trust,
            manifest,
            launch,
            authenticated,
            expected_git_sha=sha,
        )
        assert promoted["status"] == PROMOTED
        assert len(promoted["promotion_sha256"]) == 64

        unhealthy = _auth_fixture(origin, sha, healthy=False)
        held = verify_promotion(
            health,
            trust,
            manifest,
            launch,
            unhealthy,
            expected_git_sha=sha,
        )
        assert held["status"] == HOLD

        other_origin_auth = json.loads(json.dumps(authenticated))
        other_origin_auth["target_origin"] = "https://other-preview.vercel.app"
        other_unsigned = {
            key: value
            for key, value in other_origin_auth.items()
            if key != "evidence_sha256"
        }
        other_origin_auth["evidence_sha256"] = _digest(other_unsigned)
        try:
            verify_promotion(
                health,
                trust,
                manifest,
                launch,
                other_origin_auth,
                expected_git_sha=sha,
            )
        except PromotionVerificationError:
            pass
        else:
            raise AssertionError("cross-deployment authenticated evidence was accepted")

        from build_followup_trusted_promotion import (
            _fixture as _followup_fixture,
            derive_followup_promotion,
        )

        (
            f_health,
            f_trust,
            f_manifest,
            f_verdict,
            f_original,
            f_followup,
            f_diagnosis,
            f_admission,
            f_sha,
            f_source_run_id,
            f_followup_run_id,
        ) = _followup_fixture()
        f_promotion = derive_followup_promotion(
            f_health,
            f_trust,
            f_manifest,
            f_verdict,
            f_original,
            f_followup,
            f_diagnosis,
            f_admission,
            expected_git_sha=f_sha,
            source_run_id=f_source_run_id,
            followup_run_id=f_followup_run_id,
        )
        f_authenticated = _auth_fixture(
            f_verdict["target_origin"],
            f_sha,
            healthy=True,
        )
        f_promoted = verify_promotion(
            f_health,
            f_trust,
            f_manifest,
            f_verdict,
            f_authenticated,
            expected_git_sha=f_sha,
            trusted_source=f_original,
            followup_trusted_source=f_followup,
            provider_diagnosis=f_diagnosis,
            provider_admission=f_admission,
            followup_promotion=f_promotion,
            source_run_id=f_source_run_id,
            followup_run_id=f_followup_run_id,
        )
        assert f_promoted["status"] == PROMOTED
        assert f_promoted["authorization_basis"] == "followup_trusted_promotion_proof"
        assert f_promoted["followup_run_id"] == f_followup_run_id
    finally:
        os.environ.pop(PUBLIC_KEY_ENV, None)

    print("authenticated E2E promotion gate self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health_artifact", nargs="?", type=Path)
    parser.add_argument("trust_artifact", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("launch_verdict", nargs="?", type=Path)
    parser.add_argument("authenticated_evidence", nargs="?", type=Path)
    parser.add_argument("--trusted-source", type=Path)
    parser.add_argument("--trusted-promotion", type=Path)
    parser.add_argument("--followup-trusted-source", type=Path)
    parser.add_argument("--provider-diagnosis", type=Path)
    parser.add_argument("--provider-admission", type=Path)
    parser.add_argument("--followup-promotion", type=Path)
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    required = (
        args.health_artifact,
        args.trust_artifact,
        args.manifest,
        args.launch_verdict,
        args.authenticated_evidence,
        args.output,
    )
    if any(value is None for value in required):
        parser.error(
            "health, trust, manifest, launch verdict, authenticated evidence, and --output are required unless --self-test is used"
        )

    try:
        health = json.loads(args.health_artifact.read_text(encoding="utf-8"))
        trust = json.loads(args.trust_artifact.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        launch = json.loads(args.launch_verdict.read_text(encoding="utf-8"))
        authenticated = json.loads(
            args.authenticated_evidence.read_text(encoding="utf-8")
        )
        promotion = verify_promotion(
            health,
            trust,
            manifest,
            launch,
            authenticated,
            expected_git_sha=args.expected_git_sha,
            trusted_source=(
                json.loads(args.trusted_source.read_text(encoding="utf-8"))
                if args.trusted_source is not None
                else None
            ),
            trusted_promotion=(
                json.loads(args.trusted_promotion.read_text(encoding="utf-8"))
                if args.trusted_promotion is not None
                else None
            ),
            followup_trusted_source=(
                json.loads(args.followup_trusted_source.read_text(encoding="utf-8"))
                if args.followup_trusted_source is not None
                else None
            ),
            provider_diagnosis=(
                json.loads(args.provider_diagnosis.read_text(encoding="utf-8"))
                if args.provider_diagnosis is not None
                else None
            ),
            provider_admission=(
                json.loads(args.provider_admission.read_text(encoding="utf-8"))
                if args.provider_admission is not None
                else None
            ),
            followup_promotion=(
                json.loads(args.followup_promotion.read_text(encoding="utf-8"))
                if args.followup_promotion is not None
                else None
            ),
            source_run_id=args.source_run_id,
            followup_run_id=args.followup_run_id,
        )
    except (OSError, json.JSONDecodeError, PromotionVerificationError) as exc:
        print(f"authenticated E2E promotion INVALID: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(promotion, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(promotion, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
