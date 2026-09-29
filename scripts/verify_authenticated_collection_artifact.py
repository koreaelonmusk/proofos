"""Independently verify persisted authenticated ProofOS collection evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proofos.attestation import (
    AttestationVerifier,
    ObservationAttestation,
    SignatureInvalid,
)

SCHEMA_VERSION = 1
KIND = "proofos-authenticated-collection-observation"
PUBLIC_KEY_ENV = "PROOFOS_E2E_COLLECTOR_PUBLIC_KEY"
PROFILE_ID = "runtime-health-v1"
EVIDENCE_KIND = "runtime"
MAX_ATTESTATION_AGE_SECONDS = 300.0

EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "kind",
    "observed_at",
    "target_origin",
    "workflow_source_git_sha",
    "outcome",
    "request",
    "attestation",
    "trusted_public_key_sha256",
    "cryptographic_checks",
    "claim_boundary",
    "evidence_sha256",
}


class AuthenticatedEvidenceVerificationError(RuntimeError):
    pass


def _origin(raw: Any) -> str:
    if not isinstance(raw, str):
        raise AuthenticatedEvidenceVerificationError("target_origin must be a string")
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
        raise AuthenticatedEvidenceVerificationError(
            "target_origin must be an exact HTTPS Vercel origin"
        )
    return f"https://{parts.hostname.lower()}"


def _git_sha(value: Any) -> str:
    if not isinstance(value, str):
        raise AuthenticatedEvidenceVerificationError(
            "workflow_source_git_sha must be a string"
        )
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise AuthenticatedEvidenceVerificationError(
            "workflow_source_git_sha must be a full 40-character SHA"
        )
    return value


def _digest_without_self_hash(evidence: dict[str, Any]) -> str:
    unsigned = {
        key: value for key, value in evidence.items() if key != "evidence_sha256"
    }
    return hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _public_key_from_env() -> str:
    value = os.environ.get(PUBLIC_KEY_ENV, "").strip()
    if not value:
        raise AuthenticatedEvidenceVerificationError(
            f"{PUBLIC_KEY_ENV} is required for independent signature verification"
        )
    return value


def _tamper_rejection(
    attestation: ObservationAttestation,
    verifier: AttestationVerifier,
) -> dict[str, bool]:
    checks: dict[str, bool] = {}
    for name, field, value in (
        ("nonce_tamper_rejected", "request_nonce", "tampered-nonce"),
        ("profile_tamper_rejected", "profile_id", "tampered-profile"),
    ):
        payload = attestation.to_dict()
        payload[field] = value
        parsed = ObservationAttestation.from_dict(payload)
        try:
            verifier.verify(parsed)
        except SignatureInvalid:
            checks[name] = True
        else:
            raise AuthenticatedEvidenceVerificationError(
                f"{name.replace('_', ' ')} was not rejected"
            )
    return checks


def verify_evidence(
    evidence: Any,
    *,
    expected_git_sha: str = "",
) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise AuthenticatedEvidenceVerificationError(
            "authenticated evidence must be a JSON object"
        )
    if set(evidence) != EXPECTED_TOP_LEVEL_KEYS:
        raise AuthenticatedEvidenceVerificationError("authenticated evidence schema drifted")
    if evidence.get("schema_version") != SCHEMA_VERSION:
        raise AuthenticatedEvidenceVerificationError("unsupported evidence schema version")
    if evidence.get("kind") != KIND:
        raise AuthenticatedEvidenceVerificationError("unexpected evidence kind")
    if evidence.get("outcome") != "SIGNED_ATTESTATION_VERIFIED":
        raise AuthenticatedEvidenceVerificationError(
            "authenticated evidence outcome is not verified"
        )

    digest = evidence.get("evidence_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest.lower())
    ):
        raise AuthenticatedEvidenceVerificationError("evidence SHA-256 is malformed")
    if digest.lower() != _digest_without_self_hash(evidence):
        raise AuthenticatedEvidenceVerificationError("evidence SHA-256 mismatch")

    origin = _origin(evidence.get("target_origin"))
    source_sha = _git_sha(evidence.get("workflow_source_git_sha"))
    if expected_git_sha and source_sha != _git_sha(expected_git_sha):
        raise AuthenticatedEvidenceVerificationError(
            "authenticated evidence does not match expected Git SHA"
        )

    request = evidence.get("request")
    if not isinstance(request, dict) or set(request) != {
        "execution_id",
        "task_id",
        "evidence_kind",
        "profile_id",
        "request_nonce",
    }:
        raise AuthenticatedEvidenceVerificationError("request binding schema drifted")

    for field in ("execution_id", "task_id", "request_nonce"):
        if not isinstance(request.get(field), str) or not request[field]:
            raise AuthenticatedEvidenceVerificationError(
                f"request.{field} must be a non-empty string"
            )
    if request.get("evidence_kind") != EVIDENCE_KIND:
        raise AuthenticatedEvidenceVerificationError("request evidence kind mismatch")
    if request.get("profile_id") != PROFILE_ID:
        raise AuthenticatedEvidenceVerificationError("request profile mismatch")

    public_key = _public_key_from_env()
    key_digest = hashlib.sha256(public_key.encode("ascii")).hexdigest()
    if evidence.get("trusted_public_key_sha256") != key_digest:
        raise AuthenticatedEvidenceVerificationError(
            "configured collector public key does not match evidence fingerprint"
        )

    try:
        attestation = ObservationAttestation.from_dict(evidence.get("attestation"))
        verifier = AttestationVerifier.from_b64(public_key)
        verifier.verify(attestation)
    except Exception as exc:
        if isinstance(exc, AuthenticatedEvidenceVerificationError):
            raise
        raise AuthenticatedEvidenceVerificationError(
            f"attestation verification failed ({type(exc).__name__})"
        ) from exc

    bindings = {
        "execution_id": attestation.execution_id == request["execution_id"],
        "task_id": attestation.task_id == request["task_id"],
        "kind": attestation.kind == request["evidence_kind"],
        "profile_id": attestation.profile_id == request["profile_id"],
        "request_nonce": attestation.request_nonce == request["request_nonce"],
    }
    failed = sorted(key for key, valid in bindings.items() if not valid)
    if failed:
        raise AuthenticatedEvidenceVerificationError(
            "attestation binding mismatch: " + ",".join(failed)
        )

    now = time.time()
    age = now - attestation.observed_at
    if age < -30:
        raise AuthenticatedEvidenceVerificationError("attestation is future-dated")
    if age > MAX_ATTESTATION_AGE_SECONDS:
        raise AuthenticatedEvidenceVerificationError("attestation is stale")

    tamper = _tamper_rejection(attestation, verifier)
    expected_checks = {
        "signature_verified": True,
        **tamper,
    }
    if evidence.get("cryptographic_checks") != expected_checks:
        raise AuthenticatedEvidenceVerificationError(
            "persisted cryptographic checks do not match independent verification"
        )

    boundary = evidence.get("claim_boundary")
    if not isinstance(boundary, list) or not boundary or not all(
        isinstance(item, str) and item.strip() for item in boundary
    ):
        raise AuthenticatedEvidenceVerificationError("claim boundary is invalid")
    if not any(
        "does not by itself promote the observed outcome into a ProofOS VERIFIED execution"
        in item
        for item in boundary
    ):
        raise AuthenticatedEvidenceVerificationError("claim boundary overstates authority")

    return {
        "valid": True,
        "target_origin": origin,
        "workflow_source_git_sha": source_sha,
        "collector_id": attestation.collector_id,
        "attestation_outcome": str(attestation.outcome),
        "attestation_status_code": attestation.status_code,
        "request_nonce_sha256": hashlib.sha256(
            request["request_nonce"].encode("utf-8")
        ).hexdigest(),
        "evidence_sha256": digest.lower(),
        "cryptographic_checks": expected_checks,
    }


def _self_test() -> None:
    from proofos.attestation import AttestationSigner, Outcome

    signer = AttestationSigner.generate("collector-http-v1")
    os.environ[PUBLIC_KEY_ENV] = signer.public_key_b64()
    try:
        execution_id = "e2e-self-test"
        task_id = "E2E-SELF-TEST"
        nonce = "fresh-self-test-nonce"
        attestation = signer.sign(
            execution_id=execution_id,
            task_id=task_id,
            kind=EVIDENCE_KIND,
            profile_id=PROFILE_ID,
            request_nonce=nonce,
            observed_at=time.time(),
            outcome=Outcome.HEALTHY,
            status_code=200,
            response_digest_value="d" * 64,
            detail="HEALTHY via runtime-health-v1",
        )
        unsigned = {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "observed_at": time.time(),
            "target_origin": "https://proofos-preview.vercel.app",
            "workflow_source_git_sha": "0123456789abcdef0123456789abcdef01234567",
            "outcome": "SIGNED_ATTESTATION_VERIFIED",
            "request": {
                "execution_id": execution_id,
                "task_id": task_id,
                "evidence_kind": EVIDENCE_KIND,
                "profile_id": PROFILE_ID,
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
        evidence = {**unsigned, "evidence_sha256": _digest_without_self_hash(unsigned)}
        # _digest_without_self_hash also works on an unsigned body because there
        # is no evidence_sha256 key to remove.
        assert verify_evidence(
            evidence,
            expected_git_sha="0123456789abcdef0123456789abcdef01234567",
        )["valid"]

        tampered = json.loads(json.dumps(evidence))
        tampered["attestation"]["request_nonce"] = "forged"
        tampered_unsigned = {
            key: value for key, value in tampered.items() if key != "evidence_sha256"
        }
        tampered["evidence_sha256"] = hashlib.sha256(
            json.dumps(
                tampered_unsigned,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        try:
            verify_evidence(tampered)
        except AuthenticatedEvidenceVerificationError:
            pass
        else:
            raise AssertionError("re-hashed attestation tamper was accepted")
    finally:
        os.environ.pop(PUBLIC_KEY_ENV, None)

    print("authenticated collection artifact verifier self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", nargs="?", type=Path)
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0
    if args.artifact is None:
        parser.error("artifact path is required unless --self-test is used")

    try:
        evidence = json.loads(args.artifact.read_text(encoding="utf-8"))
        result = verify_evidence(
            evidence,
            expected_git_sha=args.expected_git_sha,
        )
    except (
        OSError,
        json.JSONDecodeError,
        AuthenticatedEvidenceVerificationError,
    ) as exc:
        print(f"authenticated collection artifact INVALID: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
