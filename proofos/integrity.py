"""Content hashing for evidence records.

Evidence becomes trustworthy only if you can tell whether it changed after it
was collected. In process, frozen dataclasses give that for free; once evidence
is persisted to an external store it no longer holds, so every record carries a
hash of its own canonical content.

This is deliberately the smallest mechanism that materially improves trust: a
digest over a canonical serialization. It detects silent mutation of stored
records. It is not a signature and does not prove who wrote the record.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

HASH_ALGORITHM = "sha256"


def canonical_payload(fields: Mapping[str, Any]) -> bytes:
    """Serialize deterministically so the same content always hashes the same."""
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def content_hash(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(fields)).hexdigest()
