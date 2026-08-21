"""Provision a collector signing identity.

Run once before deploying, then mount the private key into the collector and
hand the public key to the API as configuration.

    python -m proofos_collector.keygen --private secrets/collector.pem \
                                       --public  secrets/collector.pub

Generating ahead of deployment rather than on first boot is deliberate: it
keeps trust something an operator configures, not something the API discovers
from whichever collector happens to answer. It also means the private key never
has to be written by a container that the API can see.

Refuses to overwrite an existing private key. Silently replacing a signing
identity would invalidate every attestation issued under it, without anyone
asking.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from proofos.keys import FileSigningKeyProvider, write_public_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provision a collector identity.")
    parser.add_argument("--private", required=True, help="path to write the PEM key")
    parser.add_argument("--public", required=True, help="path to write the public key")
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing private key (rotates the collector identity)",
    )
    args = parser.parse_args(argv)

    private_path = Path(args.private)
    if private_path.exists() and not args.force:
        print(
            f"refusing to overwrite {private_path}: rotating the signing identity "
            "invalidates every attestation issued under it. Pass --force if that "
            "is what you intend.",
            file=sys.stderr,
        )
        return 1
    if private_path.exists() and args.force:
        private_path.unlink()

    key = FileSigningKeyProvider(private_path, create_if_missing=True).load_private_key()
    encoded = write_public_key(args.public, key.public_key())

    # The private key is never printed. Only its location and the public half.
    print(f"private key: {private_path}")
    print(f"public key : {args.public}")
    print(f"identity   : {encoded}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
