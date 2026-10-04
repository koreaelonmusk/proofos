"""Authorize the privileged authenticated-E2E step from sealed launch evidence.

This module is deliberately credential-free. It independently verifies the
health, trust, manifest, and launch-verdict artifacts. Direct public READY may
authorize the next evidence step. A public HOLD may authorize only when an
independently verified Trusted Promotion Proof binds the same origin, Git SHA,
deployment event, public verdict, and Trusted Source evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit

from verify_live_launch_verdict import VerdictVerificationError, verify_verdict
from verify_trusted_promotion_proof import (
    TrustedPromotionVerificationError,
    verify_promotion as verify_trusted_promotion,
)
from verify_followup_trusted_promotion import (
    FollowupTrustedPromotionVerificationError,
    verify_followup_promotion,
)

READY = "READY_FOR_AUTHENTICATED_E2E"
TRUSTED_PROMOTED = "AUTHORIZED_FOR_AUTHENTICATED_E2E"


class E2EAuthorizationError(RuntimeError):
    pass


def _origin(raw: str) -> str:
    parts = urlsplit(raw.strip())
    if (
        parts.scheme != "https"
        or not parts.hostname
        or not parts.hostname.lower().endswith(".vercel.app")
        or parts.username is not None
        or parts.password is not None
        or parts.port not in {None, 443}
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise E2EAuthorizationError(
            "deployment URL must be an exact https://*.vercel.app origin"
        )
    return f"https://{parts.hostname.lower()}"


def authorize(
    health: Any,
    trust: Any,
    manifest: Any,
    verdict: Any,
    *,
    expected_git_sha: str,
    deployment_url: str,
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
        verified = verify_verdict(
            health,
            trust,
            manifest,
            verdict,
            expected_git_sha=expected_git_sha,
        )
    except VerdictVerificationError as exc:
        raise E2EAuthorizationError(f"launch evidence is invalid: {exc}") from exc

    requested_origin = (
        _origin(deployment_url)
        if deployment_url.strip()
        else verified["target_origin"]
    )
    if verified["target_origin"] != requested_origin:
        raise E2EAuthorizationError(
            "requested deployment does not match the sealed launch verdict origin"
        )

    authorized = verified["status"] == READY
    status = verified["status"]
    authorization_basis = "public_launch_verdict" if authorized else "none"
    promotion_sha256 = None

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
        raise E2EAuthorizationError(
            "trusted source cannot be supplied without a promotion proof path"
        )

    if not authorized and legacy_requested:
        if trusted_source is None:
            raise E2EAuthorizationError(
                "legacy trusted promotion requires the trusted source constituent"
            )
        try:
            promoted = verify_trusted_promotion(
                health,
                trust,
                manifest,
                verdict,
                trusted_source,
                trusted_promotion,
                expected_git_sha=expected_git_sha,
                expected_source_run_id=source_run_id,
            )
        except TrustedPromotionVerificationError as exc:
            raise E2EAuthorizationError(
                f"trusted promotion proof is invalid: {exc}"
            ) from exc
        if promoted["target_origin"] != verified["target_origin"]:
            raise E2EAuthorizationError(
                "trusted promotion targets a different deployment origin"
            )
        if promoted["workflow_source_git_sha"] != verified["workflow_source_git_sha"]:
            raise E2EAuthorizationError(
                "trusted promotion binds to a different Git SHA"
            )
        authorized = promoted["status"] == TRUSTED_PROMOTED
        status = promoted["status"]
        authorization_basis = "trusted_promotion_proof"
        promotion_sha256 = promoted["promotion_sha256"]

    followup_inputs = (
        followup_trusted_source,
        provider_diagnosis,
        provider_admission,
        followup_promotion,
    )
    if not authorized and followup_requested:
        if trusted_source is None or any(item is None for item in followup_inputs):
            raise E2EAuthorizationError(
                "original Trusted Source, follow-up Trusted Source, provider diagnosis, "
                "provider admission, and follow-up promotion must be supplied together"
            )
        if (
            not isinstance(followup_run_id, int)
            or isinstance(followup_run_id, bool)
            or followup_run_id <= 0
        ):
            raise E2EAuthorizationError(
                "follow-up promotion requires a positive follow-up run id"
            )
        try:
            promoted = verify_followup_promotion(
                health,
                trust,
                manifest,
                verdict,
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
            raise E2EAuthorizationError(
                f"follow-up trusted promotion proof is invalid: {exc}"
            ) from exc
        if promoted["target_origin"] != verified["target_origin"]:
            raise E2EAuthorizationError(
                "follow-up trusted promotion targets a different deployment origin"
            )
        if promoted["workflow_source_git_sha"] != verified["workflow_source_git_sha"]:
            raise E2EAuthorizationError(
                "follow-up trusted promotion binds to a different Git SHA"
            )
        authorized = promoted["status"] == TRUSTED_PROMOTED
        status = promoted["status"]
        authorization_basis = "followup_trusted_promotion_proof"
        promotion_sha256 = promoted["promotion_sha256"]

    return {
        "authorized": authorized,
        "status": status,
        "authorization_basis": authorization_basis,
        "trusted_promotion_sha256": promotion_sha256,
        "source_run_id": source_run_id if source_run_id > 0 else None,
        "followup_run_id": followup_run_id if followup_run_id > 0 else None,
        "target_origin": verified["target_origin"],
        "workflow_source_git_sha": verified["workflow_source_git_sha"],
        "github_deployment_id": verified["github_deployment_id"],
        "github_deployment_status_id": verified["github_deployment_status_id"],
        "deployment_environment": verified["deployment_environment"],
        "manifest_sha256": verified["manifest_sha256"],
        "verdict_sha256": verified["verdict_sha256"],
    }


def _self_test() -> None:
    from build_live_launch_verdict import (
        _blocked_health,
        _blocked_trust,
        _manifest,
        _observed_health,
        _ready_trust,
        derive_verdict,
    )

    origin = "https://proofos-preview.vercel.app"
    sha = "0123456789abcdef0123456789abcdef01234567"

    hold_health = _blocked_health(origin, sha)
    hold_trust = _blocked_trust(origin, sha, bypass_attempted=False)
    hold_manifest = _manifest(hold_health, hold_trust, sha)
    hold_verdict = derive_verdict(
        hold_health,
        hold_trust,
        hold_manifest,
        expected_git_sha=sha,
    )
    hold = authorize(
        hold_health,
        hold_trust,
        hold_manifest,
        hold_verdict,
        expected_git_sha=sha,
        deployment_url=origin,
    )
    assert hold["authorized"] is False
    assert hold["status"] == "HOLD"
    assert hold["authorization_basis"] == "none"

    ready_health = _observed_health(origin, sha)
    ready_trust = _ready_trust(origin, sha)
    ready_manifest = _manifest(ready_health, ready_trust, sha)
    ready_verdict = derive_verdict(
        ready_health,
        ready_trust,
        ready_manifest,
        expected_git_sha=sha,
    )
    result = authorize(
        ready_health,
        ready_trust,
        ready_manifest,
        ready_verdict,
        expected_git_sha=sha,
        deployment_url=origin,
    )
    assert result["authorized"] is True
    assert result["status"] == READY
    assert result["authorization_basis"] == "public_launch_verdict"

    automatic = authorize(
        ready_health,
        ready_trust,
        ready_manifest,
        ready_verdict,
        expected_git_sha=sha,
        deployment_url="",
    )
    assert automatic["authorized"] is True
    assert automatic["target_origin"] == origin

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
    promoted = authorize(
        f_health,
        f_trust,
        f_manifest,
        f_verdict,
        expected_git_sha=f_sha,
        deployment_url="",
        trusted_source=f_original,
        followup_trusted_source=f_followup,
        provider_diagnosis=f_diagnosis,
        provider_admission=f_admission,
        followup_promotion=f_promotion,
        source_run_id=f_source_run_id,
        followup_run_id=f_followup_run_id,
    )
    assert promoted["authorized"] is True
    assert promoted["authorization_basis"] == "followup_trusted_promotion_proof"
    assert promoted["followup_run_id"] == f_followup_run_id

    try:
        authorize(
            ready_health,
            ready_trust,
            ready_manifest,
            ready_verdict,
            expected_git_sha=sha,
            deployment_url="https://other-preview.vercel.app",
        )
    except E2EAuthorizationError:
        pass
    else:
        raise AssertionError("verdict was reusable against another deployment origin")

    print("authenticated E2E launch authorization self-test OK")


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise E2EAuthorizationError(
            f"could not read launch artifact: {type(exc).__name__}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health", nargs="?", type=Path)
    parser.add_argument("trust", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("verdict", nargs="?", type=Path)
    parser.add_argument("--trusted-source", type=Path)
    parser.add_argument("--trusted-promotion", type=Path)
    parser.add_argument("--followup-trusted-source", type=Path)
    parser.add_argument("--provider-diagnosis", type=Path)
    parser.add_argument("--provider-admission", type=Path)
    parser.add_argument("--followup-promotion", type=Path)
    parser.add_argument("--source-run-id", type=int, default=0)
    parser.add_argument("--followup-run-id", type=int, default=0)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--deployment-url", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if any(
        item is None for item in (args.health, args.trust, args.manifest, args.verdict)
    ):
        parser.error("health, trust, manifest, and verdict artifacts are required")
    if not args.expected_git_sha:
        parser.error("--expected-git-sha is required")

    try:
        result = authorize(
            _load(args.health),
            _load(args.trust),
            _load(args.manifest),
            _load(args.verdict),
            expected_git_sha=args.expected_git_sha,
            deployment_url=args.deployment_url,
            trusted_source=(
                _load(args.trusted_source) if args.trusted_source is not None else None
            ),
            trusted_promotion=(
                _load(args.trusted_promotion)
                if args.trusted_promotion is not None
                else None
            ),
            followup_trusted_source=(
                _load(args.followup_trusted_source)
                if args.followup_trusted_source is not None
                else None
            ),
            provider_diagnosis=(
                _load(args.provider_diagnosis)
                if args.provider_diagnosis is not None
                else None
            ),
            provider_admission=(
                _load(args.provider_admission)
                if args.provider_admission is not None
                else None
            ),
            followup_promotion=(
                _load(args.followup_promotion)
                if args.followup_promotion is not None
                else None
            ),
            source_run_id=args.source_run_id,
            followup_run_id=args.followup_run_id,
        )
    except E2EAuthorizationError as exc:
        print(f"authenticated E2E AUTHORIZATION INVALID: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
