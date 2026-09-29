"""Verify a persisted live-evidence bundle manifest independently."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from verify_live_evidence_pair import (
    EvidencePairError,
    MANIFEST_KIND,
    MANIFEST_SCHEMA_VERSION,
    build_manifest,
    verify_pair,
)

EXPECTED_KEYS = {
    "schema_version",
    "kind",
    "target_origin",
    "workflow_source_git_sha",
    "github_deployment_id",
    "github_deployment_status_id",
    "deployment_environment",
    "health_evidence_sha256",
    "trust_evidence_sha256",
    "health_outcome",
    "trust_outcome",
    "pair_sha256",
    "claim_boundary",
    "manifest_sha256",
}


class ManifestVerificationError(RuntimeError):
    pass


def _manifest_digest(manifest: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in manifest.items() if key != "manifest_sha256"
    }
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def verify_manifest(
    health_evidence: Any,
    trust_evidence: Any,
    manifest: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ManifestVerificationError("manifest must be a JSON object")
    if set(manifest) != EXPECTED_KEYS:
        raise ManifestVerificationError("manifest schema drifted")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ManifestVerificationError("unsupported manifest schema version")
    if manifest.get("kind") != MANIFEST_KIND:
        raise ManifestVerificationError("unexpected manifest kind")

    digest = manifest.get("manifest_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        raise ManifestVerificationError("manifest SHA-256 is malformed")
    if digest.lower() != _manifest_digest(manifest):
        raise ManifestVerificationError("manifest SHA-256 mismatch")

    boundary = manifest.get("claim_boundary")
    if not isinstance(boundary, list) or not boundary or not all(
        isinstance(item, str) and item.strip() for item in boundary
    ):
        raise ManifestVerificationError("manifest claim boundary is invalid")
    if not any(
        "does not promote deployment evidence into ProofOS VERIFIED authority" in item
        for item in boundary
    ):
        raise ManifestVerificationError("manifest claim boundary overstates authority")

    try:
        pair = verify_pair(
            health_evidence,
            trust_evidence,
            expected_git_sha=expected_git_sha,
        )
    except EvidencePairError as exc:
        raise ManifestVerificationError(
            f"constituent evidence pair is invalid: {exc}"
        ) from exc

    expected = build_manifest(pair)
    if manifest != expected:
        raise ManifestVerificationError(
            "manifest does not exactly match independently recomputed evidence pair"
        )

    return {
        "valid": True,
        "manifest_sha256": digest.lower(),
        "pair_sha256": pair["pair_sha256"],
        "health_evidence_sha256": pair["health_evidence_sha256"],
        "trust_evidence_sha256": pair["trust_evidence_sha256"],
        "github_deployment_id": pair["github_deployment_id"],
        "github_deployment_status_id": pair["github_deployment_status_id"],
        "deployment_environment": pair["deployment_environment"],
        "workflow_source_git_sha": pair["workflow_source_git_sha"],
        "target_origin": pair["target_origin"],
    }


def _self_test() -> None:
    from verify_live_evidence_pair import _health_sample, _trust_sample

    sha = "0123456789abcdef0123456789abcdef01234567"
    origin = "https://proofos-preview.vercel.app"
    health = _health_sample(origin, sha)
    trust = _trust_sample(origin, sha)
    pair = verify_pair(health, trust, expected_git_sha=sha)
    manifest = build_manifest(pair)

    verified = verify_manifest(
        health,
        trust,
        manifest,
        expected_git_sha=sha,
    )
    assert verified["valid"]

    tampered = json.loads(json.dumps(manifest))
    tampered["pair_sha256"] = "f" * 64
    try:
        verify_manifest(health, trust, tampered, expected_git_sha=sha)
    except ManifestVerificationError:
        pass
    else:
        raise AssertionError("tampered manifest was accepted")

    print("live evidence manifest verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("health_artifact", nargs="?", type=Path)
    parser.add_argument("trust_artifact", nargs="?", type=Path)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if args.health_artifact is None or args.trust_artifact is None or args.manifest is None:
        parser.error(
            "health artifact, trust artifact, and manifest are required unless --self-test is used"
        )

    try:
        health = json.loads(args.health_artifact.read_text(encoding="utf-8"))
        trust = json.loads(args.trust_artifact.read_text(encoding="utf-8"))
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = verify_manifest(
            health,
            trust,
            manifest,
            expected_git_sha=args.expected_git_sha,
        )
    except (
        OSError,
        json.JSONDecodeError,
        ManifestVerificationError,
    ) as exc:
        print(f"live evidence manifest INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
