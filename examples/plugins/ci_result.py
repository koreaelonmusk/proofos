"""Read a CI run's recorded result. No network, and it says so.

Worth reading next to http_health, because the difference is the point: this
plugin declares no network permission at all, and the conformance suite fails it
if it opens a socket anyway. Two plugins, two blast radiuses, one contract.

A CI result is a strong piece of evidence and a weak one at the same time. It is
strong because the build ran somewhere the agent under scrutiny did not control.
It is weak because a file on disk is only as independent as whoever wrote it --
which is why provenance is decided at the ingestion boundary and not here.
"""

from __future__ import annotations

import json
import pathlib
import time

from proofos.conformance import Observation, ObservationOutcome, ObservationRequest
from proofos.plugins import PLUGIN_SCHEMA, parse_manifest

MANIFEST = parse_manifest({
    "schema_version": PLUGIN_SCHEMA,
    "plugin_id": "ci-result",
    "version": "1.0.0",
    "kind": "collector",
    "entrypoint": "examples.plugins.ci_result:CiResult",
    "description": "Reads a recorded CI result from disk and reports pass or fail.",
    "minimum_proofos_version": "0.1.0",
    "permissions": ["submit_observation", "read_config"],
    "evidence_kinds": ["tests"],
    "source_repository": "https://github.com/koreaelonmusk/proofos",
    "source_commit": "0" * 40,
}, source="examples/plugins/ci_result.py")


class CiResult:
    manifest = MANIFEST

    def observe(self, request: ObservationRequest) -> Observation:
        started = time.time()
        path = pathlib.Path(request.target)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return Observation(
                kind=request.kind, outcome=ObservationOutcome.UNAVAILABLE,
                observed_at=started, detail=f"no CI result at {path}",
            )
        except (OSError, ValueError) as exc:
            # Unreadable is not the same as failing. A truncated file tells us
            # nothing about the build.
            return Observation(
                kind=request.kind, outcome=ObservationOutcome.UNAVAILABLE,
                observed_at=started,
                detail=f"could not read {path}: {type(exc).__name__}",
            )

        passed = data.get("conclusion") == "success"
        failed = int(data.get("failed") or 0)
        return Observation(
            kind=request.kind,
            outcome=ObservationOutcome.HEALTHY if passed and not failed
                    else ObservationOutcome.UNHEALTHY,
            observed_at=started,
            detail=f"conclusion={data.get('conclusion')!r} failed={failed}",
            facts={"run_id": str(data.get("run_id", "")), "failed": failed},
        )
