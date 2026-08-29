"""A proof bundle is a record of a decision. It is not a decision.

The useful thing a verification system can hand you is not the word VERIFIED.
It is everything needed for someone else, on another machine, weeks later, to
work out the verdict again and get the same answer. That is what this file
serializes: the requirements, the evidence records, the identities, the
timestamps, the digests.

What it deliberately does not serialize is authority.

## This module cannot create evidence

``Evidence`` is never imported here and never constructed here. Not checked for
-- absent. A serializer that could mint an evidence record is a serializer that
could mint a provenance, and the distance between "reads a JSON file" and
"declares an independent observation" should be a wall rather than a code
review. Export reads evidence objects it was handed; load returns
``EvidenceRecord``, which is inert data. Turning those back into something the
kernel will look at happens in ``proofos.replay``, under rules that live there.

## recorded_verdict is audit, not input

A bundle carries what the original run concluded, because a reviewer comparing
"what it said then" with "what it computes now" is the entire point. It is
covered by the digest, so it cannot be edited quietly. It is never read by
anything that decides. A bundle saying ``recorded_verdict: VERIFIED`` with an
empty evidence list replays to ABSTAIN, and the mismatch is the finding.

## Fail closed on content that should not travel

A bundle is meant to be sent to people. Anything that looks like a credential,
a signed URL, a private key, or a path naming somebody's home directory stops
the export -- it does not get redacted, truncated or silently dropped, because
all three of those produce a bundle that still says VERIFIED while no longer
containing what the verdict rested on. Refusing is the only outcome that cannot
mislead.

Raw prompts and model reasoning are handled the other way round, structurally:
there is no field for them. A shape with nowhere to put a transcript cannot leak
one by mistake.

## Portability

Nothing here reads the clock unless asked, touches the filesystem, or looks at
the environment. Two exports of the same decision with the same ``created_at``
are byte-identical, on any machine, which is what makes the digest worth
comparing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .integrity import canonical_payload, content_hash

#: Bumped when the wire shape changes in a way older builds cannot read.
BUNDLE_SCHEMA = 1

#: Written into every bundle so a file's purpose is legible without context.
BUNDLE_KIND = "proofos.proof-bundle.v1"

#: Bounds. Not security boundaries -- a refusal to carry something unbounded
#: across a trust boundary, and a refusal to quietly truncate what a verdict
#: rested on.
MAX_VALUE = 8_192
MAX_EVIDENCE = 4_096
MAX_REQUIREMENTS = 256
MAX_TEXT = 16_384

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")

#: Things that must never travel in a portable file. Each pattern is narrow on
#: purpose: a scanner that fires on ordinary evidence would be turned off within
#: a week, and a scanner that is off protects nothing.
SENSITIVE_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("authorization header", re.compile(r"(?i)\bauthorization\s*:\s*\S")),
    ("cookie", re.compile(r"(?i)\bset-cookie\s*:\s*\S")),
    ("aws access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("json web token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("signed url", re.compile(r"(?i)[?&](?:x-goog-signature|x-amz-signature|"
                              r"sig|signature)=[A-Za-z0-9%._\-]{16,}")),
    ("inline credential", re.compile(r"(?i)\b(?:api[_\-]?key|client[_\-]?secret|"
                                     r"password|passwd|secret)\s*[=:]\s*\S{6,}")),
    ("embedded media", re.compile(r"(?i)\bdata:(?:image|video|audio)/")),
    ("windows home path", re.compile(r"(?i)[a-z]:\\users\\[^\\\s]+")),
    ("unix home path", re.compile(r"(?:/home|/Users)/[^/\s]+/")),
    ("machine temp path", re.compile(r"(?i)(?:/tmp/|/var/folders/|"
                                     r"[a-z]:\\[^\\\s]*\\temp\\)")),
)


class BundleError(ValueError):
    """A bundle this build will not read or will not write, and why."""

    def __init__(self, problem: str, *, path: str = "", fix: str = "") -> None:
        self.problem = problem
        self.path = path
        self.fix = fix
        where = f"proof bundle [{path}]" if path else "proof bundle"
        text = f"{where}: {problem}"
        if fix:
            text += f"\n  fix: {fix}"
        super().__init__(text)


class BundleIntegrityError(BundleError):
    """The payload no longer matches the digest that was written over it."""


class SensitiveContentError(BundleError):
    """Export refused: something in here must not leave the machine."""


@dataclass(frozen=True)
class RequirementRecord:
    """One requirement, as it was declared when the task was opened."""

    kind: str
    max_age_seconds: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "max_age_seconds": self.max_age_seconds}


@dataclass(frozen=True)
class EvidenceRecord:
    """One evidence record, as data. Inert on purpose.

    This is not an ``Evidence``. It has no provenance semantics, no freshness
    rule and no way to reach a ledger: ``source`` here is a string describing
    what the original run recorded, and turning that string back into a
    provenance is a decision ``proofos.replay`` makes under its own rules, not
    something this type carries with it.
    """

    kind: str
    value: str
    source: str
    valid: bool
    collected_at: float | None
    collector: str
    content_hash: str
    #: Where the signed attestation for this observation can be found, if the
    #: original run had one. A reference, never the envelope: this build cannot
    #: check a signature without an optional dependency, and carrying a
    #: signature nobody verifies is decoration that reads as assurance.
    attestation_ref: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "valid": self.valid,
            "collected_at": self.collected_at,
            "collector": self.collector,
            "content_hash": self.content_hash,
            "attestation_ref": self.attestation_ref,
        }

    def recompute_hash(self) -> str:
        """The digest the original ``Evidence`` would have carried.

        Deliberately the same field set and the same canonicalization the kernel
        uses, so a record whose value was edited in transit fails here for the
        same reason it would fail there.
        """
        return content_hash({
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "valid": self.valid,
            "collected_at": self.collected_at,
            "collector": self.collector,
        })

    @property
    def intact(self) -> bool:
        return self.content_hash == self.recompute_hash()


@dataclass(frozen=True)
class ProofBundle:
    """Everything needed to recompute one decision, and nothing else."""

    schema_version: int
    bundle_kind: str
    bundle_id: str
    created_at: float
    verification_time: float
    claim: str
    actor_id: str
    task_id: str
    execution_id: str
    policy_id: str
    profile_id: str
    requirements: tuple[RequirementRecord, ...]
    evidence: tuple[EvidenceRecord, ...]
    recorded_verdict: str
    recorded_reason: str
    digest: str

    # -- the authoritative payload --------------------------------------------

    def payload(self) -> dict[str, Any]:
        """Everything the digest covers, which is everything except the digest.

        ``recorded_verdict`` is inside. It has no authority, and it is still
        somebody's claim about what happened, so editing it quietly should not
        be possible either.
        """
        return {
            "schema_version": self.schema_version,
            "bundle_kind": self.bundle_kind,
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "verification_time": self.verification_time,
            "claim": self.claim,
            "actor_id": self.actor_id,
            "task_id": self.task_id,
            "execution_id": self.execution_id,
            "policy_id": self.policy_id,
            "profile_id": self.profile_id,
            # Order is preserved, never sorted. Which observation is most recent
            # is decided by timestamp, but the sequence is what the run did, and
            # a serializer that reorders it is editing the record.
            "requirements": [r.as_dict() for r in self.requirements],
            "evidence": [e.as_dict() for e in self.evidence],
            "recorded_verdict": self.recorded_verdict,
            "recorded_reason": self.recorded_reason,
        }

    def compute_digest(self) -> str:
        return content_hash(self.payload())

    @property
    def intact(self) -> bool:
        return self.digest == self.compute_digest()

    def require_intact(self) -> "ProofBundle":
        """Raise unless the payload still matches its digest.

        There is no branch here that recomputes and carries on. A bundle that
        fails this is not repaired into a valid one, because the only thing that
        would establish is that the digest can be made to agree with anything.
        """
        if not self.intact:
            raise BundleIntegrityError(
                "the payload does not match the digest written over it",
                path="digest",
                fix="obtain the original bundle. A digest that disagrees with "
                    "its payload is not repaired by recomputing it -- that "
                    "would only prove the digest can be made to agree with "
                    "anything",
            )
        return self

    def as_dict(self) -> dict[str, Any]:
        return {**self.payload(), "digest": self.digest}

    def to_json(self) -> str:
        return canonical_payload(self.as_dict()).decode("utf-8")


# -- export -------------------------------------------------------------------

def export_bundle(
    *,
    claim: str,
    requirements: Iterable[Any],
    evidence: Iterable[Any],
    task_id: str,
    verification_time: float,
    created_at: float,
    actor_id: str = "",
    execution_id: str = "",
    policy_id: str = "",
    profile_id: str = "",
    recorded_verdict: str = "",
    recorded_reason: str = "",
    attestation_refs: Mapping[str, str] | None = None,
) -> ProofBundle:
    """Serialize one decision into a portable bundle.

    Reads the requirement and evidence objects it is given; constructs neither.
    ``created_at`` is a parameter rather than a clock read so that two exports
    of the same decision are byte-identical, which is what makes comparing
    digests mean anything.
    """
    claim_text = _text(claim, "claim", required=True)
    refs = dict(attestation_refs or {})

    required: list[RequirementRecord] = []
    for index, item in enumerate(requirements):
        kind = getattr(item, "kind", item)
        required.append(RequirementRecord(
            kind=_text(kind, f"requirements[{index}].kind", required=True),
            max_age_seconds=_number(getattr(item, "max_age_seconds", None),
                                    f"requirements[{index}].max_age_seconds"),
        ))
    if not required:
        raise BundleError("a bundle with no requirements cannot reproduce a "
                          "decision", path="requirements")
    if len(required) > MAX_REQUIREMENTS:
        raise BundleError(f"more than {MAX_REQUIREMENTS} requirements",
                          path="requirements")

    records: list[EvidenceRecord] = []
    for index, item in enumerate(evidence):
        path = f"evidence[{index}]"
        value = _text(getattr(item, "value", ""), f"{path}.value", required=False)
        if len(value) > MAX_VALUE:
            raise BundleError(
                f"evidence value is longer than {MAX_VALUE} characters",
                path=f"{path}.value",
                fix="record a digest or a bounded summary at collection time. "
                    "Truncating it here would change what the verdict rested "
                    "on while leaving the verdict in place",
            )
        record = EvidenceRecord(
            kind=_text(getattr(item, "kind", ""), f"{path}.kind", required=True),
            value=value,
            source=str(getattr(item, "source", "")),
            valid=bool(getattr(item, "valid", True)),
            collected_at=_number(getattr(item, "collected_at", None),
                                 f"{path}.collected_at"),
            collector=_text(getattr(item, "collector", ""), f"{path}.collector",
                            required=False),
            content_hash=_text(getattr(item, "content_hash", ""),
                               f"{path}.content_hash", required=True),
            attestation_ref=_text(refs.get(getattr(item, "content_hash", ""), ""),
                                  f"{path}.attestation_ref", required=False),
        )
        if not record.intact:
            raise BundleError(
                "an evidence record does not match its own digest",
                path=path,
                fix="the record was mutated after collection. Exporting it "
                    "would carry a tampered record inside an intact bundle",
            )
        records.append(record)
    if len(records) > MAX_EVIDENCE:
        raise BundleError(f"more than {MAX_EVIDENCE} evidence records",
                          path="evidence")

    draft = ProofBundle(
        schema_version=BUNDLE_SCHEMA,
        bundle_kind=BUNDLE_KIND,
        bundle_id="",
        created_at=_require_number(created_at, "created_at"),
        verification_time=_require_number(verification_time, "verification_time"),
        claim=claim_text,
        actor_id=_maybe_id(actor_id, "actor_id"),
        task_id=_require_id(task_id, "task_id"),
        execution_id=_maybe_id(execution_id, "execution_id"),
        policy_id=_maybe_id(policy_id, "policy_id"),
        profile_id=_maybe_id(profile_id, "profile_id"),
        requirements=tuple(required),
        evidence=tuple(records),
        recorded_verdict=_text(recorded_verdict, "recorded_verdict",
                               required=False),
        recorded_reason=_text(recorded_reason, "recorded_reason", required=False),
        digest="",
    )

    # Content safety before anything is named or digested: a bundle that must
    # not exist should not acquire an id on the way to being refused.
    refuse_sensitive_content(draft)

    core = dict(draft.payload())
    core.pop("bundle_id")
    identified = _replace(draft, bundle_id=f"pb_{content_hash(core)[:32]}")
    return _replace(identified, digest=identified.compute_digest())


def refuse_sensitive_content(bundle: ProofBundle) -> None:
    """Raise if anything in here must not leave the machine.

    Every string in the payload is scanned, including ids and collector names --
    a credential pasted into a collector name is still a credential.
    """
    for path, text in _strings(bundle.payload(), ""):
        for label, pattern in SENSITIVE_PATTERNS:
            if pattern.search(text):
                raise SensitiveContentError(
                    f"a {label} would travel in this bundle",
                    path=path,
                    fix="a proof bundle is meant to be sent to people. Remove "
                        "it at collection time and export again -- redacting it "
                        "here would leave a bundle that still asserts a verdict "
                        "while no longer carrying what the verdict rested on",
                )


# -- load ---------------------------------------------------------------------

def load_bundle(data: Any) -> ProofBundle:
    """Parse a bundle under a strict schema.

    Unknown fields are refused rather than ignored. A field the parser drops
    silently is a field somebody can hide meaning in, and a field it defaults
    silently is one the digest never covered.
    """
    if isinstance(data, (str, bytes)):
        import json

        try:
            data = json.loads(data)
        except ValueError as exc:
            raise BundleError(f"not JSON: {exc}") from None
    if not isinstance(data, Mapping):
        raise BundleError("a bundle must be an object")

    expected = set(_BUNDLE_FIELDS)
    keys = set(data)
    if keys - expected:
        raise BundleError(f"unexpected fields: {sorted(keys - expected)}",
                          fix="a bundle carries requirements, evidence and "
                              "identifiers. It has no field for grants, "
                              "capabilities or policy overrides, and one that "
                              "arrived would be doing something")
    if expected - keys:
        raise BundleError(f"missing fields: {sorted(expected - keys)}")

    if data["schema_version"] != BUNDLE_SCHEMA:
        raise BundleError(
            f"schema_version {data['schema_version']!r} is not supported by "
            f"this build", path="schema_version",
            fix=f"this build reads schema {BUNDLE_SCHEMA}")
    if data["bundle_kind"] != BUNDLE_KIND:
        raise BundleError(f"not a {BUNDLE_KIND}", path="bundle_kind")

    raw_requirements = data["requirements"]
    if not isinstance(raw_requirements, (list, tuple)) or not raw_requirements:
        raise BundleError("'requirements' must be a non-empty list",
                          path="requirements")
    if len(raw_requirements) > MAX_REQUIREMENTS:
        raise BundleError(f"more than {MAX_REQUIREMENTS} requirements",
                          path="requirements")
    requirements = tuple(_requirement(item, f"requirements[{i}]")
                         for i, item in enumerate(raw_requirements))

    raw_evidence = data["evidence"]
    if not isinstance(raw_evidence, (list, tuple)):
        raise BundleError("'evidence' must be a list", path="evidence")
    if len(raw_evidence) > MAX_EVIDENCE:
        raise BundleError(f"more than {MAX_EVIDENCE} evidence records",
                          path="evidence")
    evidence = tuple(_evidence(item, f"evidence[{i}]")
                     for i, item in enumerate(raw_evidence))

    return ProofBundle(
        schema_version=BUNDLE_SCHEMA,
        bundle_kind=BUNDLE_KIND,
        bundle_id=_require_id(data["bundle_id"], "bundle_id"),
        created_at=_require_number(data["created_at"], "created_at"),
        verification_time=_require_number(data["verification_time"],
                                          "verification_time"),
        claim=_text(data["claim"], "claim", required=True),
        actor_id=_maybe_id(data["actor_id"], "actor_id"),
        task_id=_require_id(data["task_id"], "task_id"),
        execution_id=_maybe_id(data["execution_id"], "execution_id"),
        policy_id=_maybe_id(data["policy_id"], "policy_id"),
        profile_id=_maybe_id(data["profile_id"], "profile_id"),
        requirements=requirements,
        evidence=evidence,
        recorded_verdict=_text(data["recorded_verdict"], "recorded_verdict",
                               required=False),
        recorded_reason=_text(data["recorded_reason"], "recorded_reason",
                              required=False),
        digest=_text(data["digest"], "digest", required=True),
    )


# -- inspection ---------------------------------------------------------------

def inspect(bundle: ProofBundle) -> dict[str, Any]:
    """Describe a bundle without deciding anything about it.

    ``recorded_verdict`` appears here labelled as recorded, because that is what
    it is. Nothing in this function computes a verdict, and the value it reports
    for integrity is a property of the bytes, not a judgement about the claim.
    """
    sensitive = "clean"
    try:
        refuse_sensitive_content(bundle)
    except SensitiveContentError as exc:
        sensitive = exc.problem
    return {
        "bundle_id": bundle.bundle_id,
        "schema_version": bundle.schema_version,
        "bundle_kind": bundle.bundle_kind,
        "created_at": bundle.created_at,
        "verification_time": bundle.verification_time,
        "task_id": bundle.task_id,
        "actor_id": bundle.actor_id,
        "integrity": "intact" if bundle.intact else "BROKEN",
        "requirement_count": len(bundle.requirements),
        "evidence_count": len(bundle.evidence),
        "recorded_verdict": bundle.recorded_verdict or "(none)",
        "recorded_reason": bundle.recorded_reason or "(none)",
        "sensitive_content": sensitive,
        "digest": bundle.digest,
    }


def render_inspection(bundle: ProofBundle) -> str:
    """The same thing, for a person, with the disclaimer that has to be there."""
    facts = inspect(bundle)
    width = max(len(k) for k in facts)
    lines = [f"proof bundle {facts['bundle_id']}", ""]
    lines += [f"  {key:<{width}}  {facts[key]}" for key in facts]
    lines += [
        "",
        "  recorded_verdict is what the original run concluded. It is carried",
        "  for comparison and is not evidence of anything. Replay recomputes",
        "  the decision from the records above and reports any mismatch.",
    ]
    return "\n".join(lines)


# -- parsing helpers ----------------------------------------------------------

_BUNDLE_FIELDS: tuple[str, ...] = (
    "schema_version", "bundle_kind", "bundle_id", "created_at",
    "verification_time", "claim", "actor_id", "task_id", "execution_id",
    "policy_id", "profile_id", "requirements", "evidence", "recorded_verdict",
    "recorded_reason", "digest",
)

_REQUIREMENT_FIELDS: tuple[str, ...] = ("kind", "max_age_seconds")

_EVIDENCE_FIELDS: tuple[str, ...] = (
    "kind", "value", "source", "valid", "collected_at", "collector",
    "content_hash", "attestation_ref",
)


def _requirement(item: Any, path: str) -> RequirementRecord:
    _strict(item, _REQUIREMENT_FIELDS, path)
    return RequirementRecord(
        kind=_text(item["kind"], f"{path}.kind", required=True),
        max_age_seconds=_number(item["max_age_seconds"],
                                f"{path}.max_age_seconds"),
    )


def _evidence(item: Any, path: str) -> EvidenceRecord:
    _strict(item, _EVIDENCE_FIELDS, path)
    if not isinstance(item["valid"], bool):
        raise BundleError("'valid' must be a boolean", path=f"{path}.valid")
    value = _text(item["value"], f"{path}.value", required=False)
    if len(value) > MAX_VALUE:
        raise BundleError(f"evidence value is longer than {MAX_VALUE} characters",
                          path=f"{path}.value")
    return EvidenceRecord(
        kind=_text(item["kind"], f"{path}.kind", required=True),
        value=value,
        source=_text(item["source"], f"{path}.source", required=True),
        valid=item["valid"],
        collected_at=_number(item["collected_at"], f"{path}.collected_at"),
        collector=_text(item["collector"], f"{path}.collector", required=False),
        content_hash=_text(item["content_hash"], f"{path}.content_hash",
                           required=True),
        attestation_ref=_text(item["attestation_ref"], f"{path}.attestation_ref",
                              required=False),
    )


def _strict(item: Any, fields: tuple[str, ...], path: str) -> None:
    if not isinstance(item, Mapping):
        raise BundleError("must be an object", path=path)
    keys, expected = set(item), set(fields)
    if keys - expected:
        raise BundleError(f"unexpected fields: {sorted(keys - expected)}",
                          path=path)
    if expected - keys:
        raise BundleError(f"missing fields: {sorted(expected - keys)}", path=path)


def _text(value: Any, path: str, *, required: bool) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise BundleError("must be a string", path=path)
    if len(value) > MAX_TEXT:
        raise BundleError(f"longer than {MAX_TEXT} characters", path=path)
    if required and not value.strip():
        raise BundleError("is empty", path=path)
    return value


def _number(value: Any, path: str) -> float | None:
    if value is None:
        return None
    return _require_number(value, path)


def _require_number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BundleError("must be a number", path=path)
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise BundleError(f"is {value!r}", path=path,
                          fix="a finite unix timestamp")
    return number


def _require_id(value: Any, path: str) -> str:
    if not isinstance(value, str) or not _ID.match(value):
        raise BundleError("is not a usable identifier", path=path,
                          fix="letters, digits and . _ : - only, 1 to 128 "
                              "characters")
    return value


def _maybe_id(value: Any, path: str) -> str:
    if value in (None, ""):
        return ""
    return _require_id(value, path)


def _replace(bundle: ProofBundle, **changes: Any) -> ProofBundle:
    fields = {name: getattr(bundle, name) for name in _BUNDLE_FIELDS}
    fields.update(changes)
    return ProofBundle(**fields)


def _strings(value: Any, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path or "(root)", value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield from _strings(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]")


#: Tier 2. Imported from ``proofos.bundle`` by whoever is moving proofs between
#: machines; the root API is for someone verifying a claim.
__all__ = [
    "BUNDLE_SCHEMA",
    "BUNDLE_KIND",
    "MAX_VALUE",
    "SENSITIVE_PATTERNS",
    "BundleError",
    "BundleIntegrityError",
    "SensitiveContentError",
    "RequirementRecord",
    "EvidenceRecord",
    "ProofBundle",
    "export_bundle",
    "load_bundle",
    "refuse_sensitive_content",
    "inspect",
    "render_inspection",
]
