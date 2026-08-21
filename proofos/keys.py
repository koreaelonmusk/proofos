"""Collector signing identity.

An ephemeral key is fine for a test and wrong for a service: restarting the
collector would rotate its identity, and every attestation signed before the
restart would stop verifying. A deployable collector needs a durable identity,
and the API needs to be told about it deliberately rather than discovering it.

Two providers, deliberately asymmetric:

* ``FileSigningKeyProvider`` -- reads a private key. Used only by the collector
  process.
* ``FileVerificationKeyProvider`` -- reads a public key. Used only by the API.

Formats, chosen and documented rather than incidental:

* private key: PKCS#8 PEM, unencrypted. Self-describing, standard tooling can
  read it, and a file that begins with ``-----BEGIN PRIVATE KEY-----`` is
  obvious to anyone who finds it in the wrong place.
* public key: raw 32-byte Ed25519 value, base64. Matches what the collector
  registry already stores, so no conversion sits between configuration and
  verification.

Trust is configured, never discovered. Nothing here fetches a key over the
network, and the collector serves no endpoint that hands one out: bootstrapping
trust from the party you are trying to verify is trust-on-first-use, and this
module deliberately makes that impossible rather than merely discouraged.

File permissions are tightened to owner-only where the platform supports it.
On Windows ``chmod`` does not carry that meaning, so the tightening is
best-effort and the real protection is that the file never enters the API's
image or environment.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY_ENV = "PROOFOS_COLLECTOR_PRIVATE_KEY_FILE"
PUBLIC_KEY_ENV = "PROOFOS_COLLECTOR_PUBLIC_KEY_FILE"
PUBLIC_KEY_INLINE_ENV = "PROOFOS_COLLECTOR_PUBLIC_KEY"


class KeyMaterialError(RuntimeError):
    """Raised when key material is missing, unreadable, or the wrong shape."""


class SigningKeyProvider(Protocol):
    def load_private_key(self) -> Ed25519PrivateKey: ...


class VerificationKeyProvider(Protocol):
    def load_public_key_b64(self) -> str: ...


def encode_public_key(key: Ed25519PublicKey) -> str:
    return base64.b64encode(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


def _restrict(path: Path) -> None:
    """Best-effort owner-only permissions."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - platform dependent
        pass


class FileSigningKeyProvider:
    """Loads (or creates) the collector's private key on disk.

    ``create_if_missing`` exists so a fresh deployment can bootstrap itself once
    and then keep that identity across restarts. It never overwrites an existing
    key: silently replacing a signing identity would invalidate every previously
    issued attestation without anyone asking for it.
    """

    def __init__(self, path: str | os.PathLike, create_if_missing: bool = True) -> None:
        self.path = Path(path)
        self.create_if_missing = create_if_missing

    def load_private_key(self) -> Ed25519PrivateKey:
        if not self.path.exists():
            if not self.create_if_missing:
                raise KeyMaterialError(f"no collector private key at {self.path}")
            return self._create()

        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise KeyMaterialError(
                f"collector private key at {self.path} is unreadable"
            ) from exc

        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise KeyMaterialError(
                f"collector private key at {self.path} is not a readable PEM key"
            ) from exc

        if not isinstance(key, Ed25519PrivateKey):
            raise KeyMaterialError(
                f"collector private key at {self.path} is "
                f"{type(key).__name__}, not Ed25519"
            )
        return key

    def _create(self) -> Ed25519PrivateKey:
        key = Ed25519PrivateKey.generate()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        _restrict(self.path)
        return key


class FileVerificationKeyProvider:
    """Loads the collector's public key from configuration.

    This is the API's only source of collector identity. It reads a file it was
    told to read; it never asks the collector who it is.
    """

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)

    def load_public_key_b64(self) -> str:
        try:
            encoded = self.path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KeyMaterialError(
                f"collector public key at {self.path} is unreadable"
            ) from exc
        return _validated(encoded, str(self.path))


class InlineVerificationKeyProvider:
    """Public key supplied directly, e.g. from a deployment variable."""

    def __init__(self, encoded: str) -> None:
        self.encoded = encoded

    def load_public_key_b64(self) -> str:
        return _validated(self.encoded, "inline configuration")


def _validated(encoded: str, source: str) -> str:
    if not encoded:
        raise KeyMaterialError(f"collector public key from {source} is empty")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise KeyMaterialError(
            f"collector public key from {source} is not valid base64"
        ) from exc
    if len(raw) != 32:
        raise KeyMaterialError(
            f"collector public key from {source} is {len(raw)} bytes, expected 32"
        )
    return encoded


def write_public_key(path: str | os.PathLike, key: Ed25519PublicKey) -> str:
    """Publish the public half so a separately configured API can be given it.

    Only the public key is ever written here. This is a deployment convenience
    for handing configuration to another container, not a trust bootstrap: the
    API is told which file to read, and reads only that.
    """
    encoded = encode_public_key(key)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(encoded, encoding="utf-8")
    return encoded


def verification_provider_from_env() -> VerificationKeyProvider:
    """Build the API's key provider from configuration, or fail loudly.

    There is no default and no discovery step. An API that cannot be told which
    collector to trust must not start, because the alternative is trusting
    whichever collector answers.
    """
    inline = os.environ.get(PUBLIC_KEY_INLINE_ENV)
    if inline:
        return InlineVerificationKeyProvider(inline)

    path = os.environ.get(PUBLIC_KEY_ENV)
    if path:
        return FileVerificationKeyProvider(path)

    raise KeyMaterialError(
        f"no collector public key configured: set {PUBLIC_KEY_INLINE_ENV} or "
        f"{PUBLIC_KEY_ENV}. ProofOS will not infer which collector to trust."
    )
