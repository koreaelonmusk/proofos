"""Ask an HTTP endpoint how it is, and report the answer without embellishing it.

The whole plugin is the observation. It does not decide whether the service
being healthy satisfies anything, because it is not entitled to: a requirement
says what would count, and a verifier weighs it. This just looks.

Note what the manifest declares. ``network_scope`` names the host this
deployment probes, not a wildcard. A collector that may contact anything is a
collector whose blast radius nobody reviewed, and the conformance suite treats a
wildcard as the smell it is.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request

from proofos.conformance import Observation, ObservationOutcome, ObservationRequest
from proofos.plugins import PLUGIN_SCHEMA, parse_manifest

MANIFEST = parse_manifest({
    "schema_version": PLUGIN_SCHEMA,
    "plugin_id": "http-health",
    "version": "1.0.0",
    "kind": "collector",
    "entrypoint": "examples.plugins.http_health:HttpHealth",
    "description": "Reads a JSON health endpoint over HTTP and reports what it saw.",
    "minimum_proofos_version": "0.1.0",
    "permissions": ["network", "submit_observation"],
    "network_scope": ["status.example.com"],
    "evidence_kinds": ["runtime_health"],
    "source_repository": "https://github.com/koreaelonmusk/proofos",
    "source_commit": "0" * 40,
}, source="examples/plugins/http_health.py")


class HttpHealth:
    manifest = MANIFEST

    def observe(self, request: ObservationRequest) -> Observation:
        url = request.target if "://" in request.target else f"http://{request.target}"
        started = time.time()
        try:
            with urllib.request.urlopen(url, timeout=request.timeout_seconds) as response:
                body = response.read(65536)
                status = response.status
        except urllib.error.HTTPError as exc:
            # A 500 is the service answering, so this is something we learned.
            return Observation(
                kind=request.kind, outcome=ObservationOutcome.UNHEALTHY,
                observed_at=started, detail=f"HTTP {exc.code}", status_code=exc.code,
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # Nothing answered. That is not a fact about the service's health,
            # so it must not be reported as one.
            return Observation(
                kind=request.kind, outcome=ObservationOutcome.UNAVAILABLE,
                observed_at=started,
                detail=f"could not reach {url}: {type(exc).__name__}",
            )

        digest = hashlib.sha256(body).hexdigest()
        try:
            reported = json.loads(body).get("status")
        except (ValueError, AttributeError):
            reported = None
        healthy = status == 200 and reported == "ok"
        return Observation(
            kind=request.kind,
            outcome=ObservationOutcome.HEALTHY if healthy else ObservationOutcome.UNHEALTHY,
            observed_at=started,
            detail=f"HTTP {status}, status field {reported!r}",
            status_code=status,
            response_digest=digest,
        )
