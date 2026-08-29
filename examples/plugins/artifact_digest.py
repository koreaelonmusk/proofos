"""Hash a built artifact, so a claim about *which* artifact can be checked.

This one observes nothing about behaviour at all. It answers one question --
what are the bytes -- and that is exactly the kind of narrow, boring plugin the
contract is designed to make easy. A digest cannot be argued with, which is more
than can be said for most evidence.

It reports UNAVAILABLE for a missing file rather than a zero digest. A digest of
nothing is still a digest, and a caller that received one would have no way to
tell it apart from a real one.
"""

from __future__ import annotations

import hashlib
import pathlib
import time

from proofos.conformance import Observation, ObservationOutcome, ObservationRequest
from proofos.plugins import PLUGIN_SCHEMA, parse_manifest

MANIFEST = parse_manifest({
    "schema_version": PLUGIN_SCHEMA,
    "plugin_id": "artifact-digest",
    "version": "1.0.0",
    "kind": "collector",
    "entrypoint": "examples.plugins.artifact_digest:ArtifactDigest",
    "description": "Reports the SHA-256 of a built artifact on disk.",
    "minimum_proofos_version": "0.1.0",
    "permissions": ["submit_observation"],
    "evidence_kinds": ["artifact"],
    "source_repository": "https://github.com/koreaelonmusk/proofos",
    "source_commit": "0" * 40,
}, source="examples/plugins/artifact_digest.py")

_CHUNK = 1 << 20


class ArtifactDigest:
    manifest = MANIFEST

    def observe(self, request: ObservationRequest) -> Observation:
        started = time.time()
        path = pathlib.Path(request.target)
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(_CHUNK):
                    digest.update(chunk)
                    size += len(chunk)
        except (OSError, ValueError) as exc:
            return Observation(
                kind=request.kind, outcome=ObservationOutcome.UNAVAILABLE,
                observed_at=started,
                detail=f"could not read {path}: {type(exc).__name__}",
            )
        return Observation(
            kind=request.kind, outcome=ObservationOutcome.HEALTHY,
            observed_at=started,
            detail=f"{size} bytes",
            response_digest=digest.hexdigest(),
            facts={"bytes": size, "name": path.name},
        )
