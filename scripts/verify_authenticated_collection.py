"""Collect and independently verify one authenticated ProofOS observation.

Live mode requires two caller-controlled environment variables:
- PROOFOS_E2E_CALLER_ID_TOKEN: short-lived Google OIDC ID token for the collector
- PROOFOS_E2E_COLLECTOR_PUBLIC_KEY: trusted base64 Ed25519 collector public key

Neither value is accepted on the command line, written to artifacts, or logged.
The public key is configuration, never discovered from the collector under test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

from proofos.attestation import (
    AttestationVerifier,
    ObservationAttestation,
    SignatureInvalid,
)

SCHEMA_VERSION = 1
KIND = "proofos-authenticated-collection-observation"
PROFILE_ID = "runtime-health-v1"
EVIDENCE_KIND = "runtime"
TOKEN_ENV = "PROOFOS_E2E_CALLER_ID_TOKEN"
PUBLIC_KEY_ENV = "PROOFOS_E2E_COLLECTOR_PUBLIC_KEY"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_ATTESTATION_AGE_SECONDS = 120.0


class AuthenticatedCollectionError(RuntimeError):
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
        raise AuthenticatedCollectionError(
            "collector URL must be an exact https://*.vercel.app origin"
        )
    return f"https://{parts.hostname.lower()}"


def _git_sha(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise AuthenticatedCollectionError(
            "expected Git SHA must be a full 40-character SHA"
        )
    return value


def _sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _load_secret_environment() -> tuple[str, str]:
    token = os.environ.get(TOKEN_ENV, "").strip()
    public_key = os.environ.get(PUBLIC_KEY_ENV, "").strip()
    if not token:
        raise AuthenticatedCollectionError(
            f"{TOKEN_ENV} is required for live authenticated collection"
        )
    if not public_key:
        raise AuthenticatedCollectionError(
            f"{PUBLIC_KEY_ENV} is required for live signature verification"
        )
    return token, public_key


def _request_json(
    origin: str,
    payload: dict[str, Any],
    *,
    bearer_token: str,
    timeout: float,
) -> dict[str, Any]:
    request = Request(
        f"{origin}/v1/collect",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
            "User-Agent": "proofos-authenticated-e2e/1",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(MAX_RESPONSE_BYTES)
    except HTTPError as exc:
        raise AuthenticatedCollectionError(
            f"authenticated collection returned HTTP {exc.code}"
        ) from exc
    except URLError as exc:
        raise AuthenticatedCollectionError(
            f"authenticated collection was unreachable: {type(exc.reason).__name__}"
        ) from exc

    if status != 200:
        raise AuthenticatedCollectionError(
            f"authenticated collection returned HTTP {status}"
        )

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthenticatedCollectionError(
            "authenticated collection did not return valid UTF-8 JSON"
        ) from exc

    if not isinstance(value, dict) or set(value) != {"attestation"}:
        raise AuthenticatedCollectionError(
            "authenticated collection response schema drifted"
        )
    return value


def _verify_binding(
    attestation: ObservationAttestation,
    *,
    execution_id: str,
    task_id: str,
    nonce: str,
) -> None:
    if attestation.execution_id != execution_id:
        raise AuthenticatedCollectionError("attestation execution_id mismatch")
    if attestation.task_id != task_id:
        raise AuthenticatedCollectionError("attestation task_id mismatch")
    if attestation.kind != EVIDENCE_KIND:
        raise AuthenticatedCollectionError("attestation evidence kind mismatch")
    if attestation.profile_id != PROFILE_ID:
        raise AuthenticatedCollectionError("attestation profile mismatch")
    if attestation.request_nonce != nonce:
        raise AuthenticatedCollectionError("attestation nonce mismatch")

    now = time.time()
    age = now - attestation.observed_at
    if age < -30:
        raise AuthenticatedCollectionError("attestation is future-dated")
    if age > MAX_ATTESTATION_AGE_SECONDS:
        raise AuthenticatedCollectionError("attestation is stale")


def _prove_tamper_rejection(
    payload: dict[str, Any],
    verifier: AttestationVerifier,
) -> dict[str, bool]:
    nonce_tamper = dict(payload)
    nonce_tamper["request_nonce"] = "tampered-nonce"
    profile_tamper = dict(payload)
    profile_tamper["profile_id"] = "tampered-profile"

    results: dict[str, bool] = {}
    for label, tampered in (
        ("nonce_tamper_rejected", nonce_tamper),
        ("profile_tamper_rejected", profile_tamper),
    ):
        parsed = ObservationAttestation.from_dict(tampered)
        try:
            verifier.verify(parsed)
        except SignatureInvalid:
            results[label] = True
        else:
            raise AuthenticatedCollectionError(
                f"{label.replace('_', ' ')} was not rejected"
            )
    return results


def verify_attestation_payload(
    payload: Any,
    *,
    public_key_b64: str,
    execution_id: str,
    task_id: str,
    nonce: str,
) -> tuple[ObservationAttestation, dict[str, bool]]:
    try:
        attestation = ObservationAttestation.from_dict(payload)
        verifier = AttestationVerifier.from_b64(public_key_b64)
        verifier.verify(attestation)
    except Exception as exc:  # redacted at the evidence boundary
        if isinstance(exc, AuthenticatedCollectionError):
            raise
        raise AuthenticatedCollectionError(
            f"attestation verification failed ({type(exc).__name__})"
        ) from exc

    _verify_binding(
        attestation,
        execution_id=execution_id,
        task_id=task_id,
        nonce=nonce,
    )
    tamper = _prove_tamper_rejection(attestation.to_dict(), verifier)
    return attestation, tamper


def observe(
    origin: str,
    *,
    expected_git_sha: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    origin = _origin(origin)
    source_sha = _git_sha(expected_git_sha)
    bearer_token, public_key = _load_secret_environment()

    execution_id = f"e2e-{uuid4().hex}"
    task_id = f"E2E-{uuid4().hex[:16]}"
    nonce = secrets.token_urlsafe(32)

    request_payload = {
        "execution_id": execution_id,
        "task_id": task_id,
        "evidence_kind": EVIDENCE_KIND,
        "profile_id": PROFILE_ID,
        "request_nonce": nonce,
    }
    response = _request_json(
        origin,
        request_payload,
        bearer_token=bearer_token,
        timeout=timeout,
    )
    attestation, tamper = verify_attestation_payload(
        response["attestation"],
        public_key_b64=public_key,
        execution_id=execution_id,
        task_id=task_id,
        nonce=nonce,
    )

    unsigned = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "observed_at": time.time(),
        "target_origin": origin,
        "workflow_source_git_sha": source_sha,
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
            public_key.encode("ascii")
        ).hexdigest(),
        "cryptographic_checks": {
            "signature_verified": True,
            **tamper,
        },
        "claim_boundary": [
            "proves a fresh authenticated request returned an attestation signed by the preconfigured collector public key",
            "proves execution, task, evidence kind, profile, and nonce were bound to the signed attestation",
            "proves nonce and profile tampering invalidate the signature",
            "does not by itself promote the observed outcome into a ProofOS VERIFIED execution",
            "retains the one-time nonce and signed attestation for independent replay-safe audit",
            "does not expose bearer tokens, private signing keys, or trusted public-key configuration",
        ],
    }
    return {**unsigned, "evidence_sha256": _sha256(unsigned)}


def _self_test() -> None:
    from proofos.attestation import AttestationSigner, Outcome

    signer = AttestationSigner.generate("collector-http-v1")
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
    parsed, tamper = verify_attestation_payload(
        attestation.to_dict(),
        public_key_b64=signer.public_key_b64(),
        execution_id=execution_id,
        task_id=task_id,
        nonce=nonce,
    )
    assert parsed.request_nonce == nonce
    assert tamper == {
        "nonce_tamper_rejected": True,
        "profile_tamper_rejected": True,
    }

    wrong_key = AttestationSigner.generate("collector-http-v1").public_key_b64()
    try:
        verify_attestation_payload(
            attestation.to_dict(),
            public_key_b64=wrong_key,
            execution_id=execution_id,
            task_id=task_id,
            nonce=nonce,
        )
    except AuthenticatedCollectionError:
        pass
    else:
        raise AssertionError("attestation signed by an untrusted key was accepted")

    print("authenticated collection evidence self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url")
    parser.add_argument("--expected-git-sha", default="")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if not args.url or not args.expected_git_sha or args.output is None:
        parser.error(
            "--url, --expected-git-sha, and --output are required unless --self-test is used"
        )

    try:
        evidence = observe(
            args.url,
            expected_git_sha=args.expected_git_sha,
            timeout=args.timeout,
        )
    except AuthenticatedCollectionError as exc:
        print(f"authenticated collection evidence FAILED: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "valid": True,
                "outcome": evidence["outcome"],
                "collector_id": evidence["attestation"]["collector_id"],
                "attestation_outcome": evidence["attestation"]["outcome"],
                "evidence_sha256": evidence["evidence_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
