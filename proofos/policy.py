"""One policy model, whatever syntax it arrived in.

The CLI, the Python API, the HTTP service and any future adapter must compile
to the same thing: a list of requirements and what would satisfy each. Two
policy languages would eventually disagree, and a disagreement about what must
be proven is a disagreement about truth.

Syntax is not the model. TOML is the default because Python 3.11 parses it in
the standard library, so a policy file costs no dependency; YAML and JSON are
accepted when they are available or applicable. All three produce the same
``Policy``.

Validation is deliberately unforgiving. A configuration mistake in a
verification tool is not a cosmetic problem: ``max_age_second`` silently
ignored is a freshness horizon silently disabled, which turns a stale
observation into an accepted one. So an unknown key is an error, a
misspelling is an error that names the key you probably meant, and an
unrecognised schema version is an error rather than a hopeful parse.
"""

from __future__ import annotations

import difflib
import json
import pathlib
import tomllib
from dataclasses import dataclass, field
from typing import Any

from .verifier import EvidenceSource, Requirement

#: Bumped when a policy written for an older ProofOS could be misread by a
#: newer one. An unknown version refuses rather than guessing.
POLICY_SCHEMA = 1

_TOP_LEVEL = {"version", "requirements", "description"}
_REQUIREMENT_KEYS = {"source", "max_age_seconds", "description"}


class PolicyError(ValueError):
    """A configuration problem, phrased so the reader can fix it.

    Carries the file, the path within it, what was wrong, what is allowed, and
    what to do -- because "invalid config" tells someone nothing they did not
    already know.
    """

    def __init__(
        self,
        problem: str,
        *,
        source: str = "<policy>",
        path: str = "",
        allowed: object = None,
        fix: str = "",
    ) -> None:
        self.problem = problem
        self.source = source
        self.path = path
        self.allowed = allowed
        self.fix = fix
        super().__init__(self.render())

    def render(self) -> str:
        lines = [f"{self.source}: {self.problem}"]
        if self.path:
            lines.append(f"  at       {self.path}")
        if self.allowed:
            shown = self.allowed
            if isinstance(shown, (set, frozenset)):
                shown = ", ".join(sorted(str(x) for x in shown))
            elif isinstance(shown, (list, tuple)):
                shown = ", ".join(str(x) for x in shown)
            lines.append(f"  allowed  {shown}")
        if self.fix:
            lines.append(f"  fix      {self.fix}")
        return "\n".join(lines)


@dataclass(frozen=True)
class PolicyRequirement:
    """One thing that must be proven, and what may prove it."""

    kind: str
    sources: frozenset[EvidenceSource]
    max_age_seconds: float | None = None
    description: str = ""

    def as_requirement(self) -> Requirement:
        """The kernel's own type. The kernel decides; this only describes."""
        return Requirement(self.kind, self.max_age_seconds)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "source": sorted(str(s) for s in self.sources),
            "max_age_seconds": self.max_age_seconds,
            "description": self.description,
        }


@dataclass(frozen=True)
class Policy:
    """A parsed, validated policy. Immutable and syntax-independent."""

    requirements: tuple[PolicyRequirement, ...]
    version: int = POLICY_SCHEMA
    description: str = ""
    source: str = "<policy>"
    #: Requirements whose declared sources include something the kernel does
    #: not currently treat as trusted. Surfaced rather than silently honoured,
    #: because a policy cannot widen what counts as independent evidence.
    unenforceable_sources: tuple[str, ...] = field(default_factory=tuple)

    def as_requirements(self) -> tuple[Requirement, ...]:
        return tuple(r.as_requirement() for r in self.requirements)

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "description": self.description,
            "requirements": {r.kind: r.as_dict() for r in self.requirements},
        }


def _suggest(key: str, allowed: set[str]) -> str:
    close = difflib.get_close_matches(key, sorted(allowed), n=1, cutoff=0.6)
    return f"did you mean {close[0]!r}?" if close else ""


def _parse_sources(raw: Any, kind: str, source: str) -> frozenset[EvidenceSource]:
    if raw is None:
        # Defaulting to OBSERVED is the safe default and the only one that
        # matches the product's invariant: a requirement with no declared
        # source must not accidentally accept a self-report.
        return frozenset({EvidenceSource.OBSERVED})
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        raise PolicyError(
            "source must be a non-empty list of provenance names",
            source=source, path=f"requirements.{kind}.source",
            allowed=[str(s) for s in EvidenceSource],
            fix='source = ["OBSERVED"]',
        )
    parsed = set()
    for item in raw:
        try:
            parsed.add(EvidenceSource(str(item)))
        except ValueError:
            raise PolicyError(
                f"unknown provenance {item!r}",
                source=source, path=f"requirements.{kind}.source",
                allowed=[str(s) for s in EvidenceSource],
                fix=_suggest(str(item), {str(s) for s in EvidenceSource})
                    or 'use "OBSERVED" for independent evidence',
            ) from None
    return frozenset(parsed)


def _parse_age(raw: Any, kind: str, source: str) -> float | None:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise PolicyError(
            f"max_age_seconds must be a number, got {type(raw).__name__}",
            source=source, path=f"requirements.{kind}.max_age_seconds",
            fix="max_age_seconds = 300",
        )
    if raw <= 0:
        raise PolicyError(
            "max_age_seconds must be positive",
            source=source, path=f"requirements.{kind}.max_age_seconds",
            fix="omit the key entirely if the evidence does not expire",
        )
    return float(raw)


def parse_policy(data: Any, source: str = "<policy>") -> Policy:
    """Validate a decoded policy document into the one model.

    Rejects anything it does not understand. A verification tool that shrugs at
    an unrecognised key is a verification tool that can be misconfigured
    without anyone noticing.
    """
    if not isinstance(data, dict):
        raise PolicyError(
            f"a policy must be a table, got {type(data).__name__}",
            source=source, fix="see `proofos init` for a starting file",
        )

    unknown = set(data) - _TOP_LEVEL
    if unknown:
        key = sorted(unknown)[0]
        raise PolicyError(
            f"unknown key {key!r}",
            source=source, path=key, allowed=_TOP_LEVEL,
            fix=_suggest(key, _TOP_LEVEL) or "remove it",
        )

    if "version" not in data:
        raise PolicyError(
            "missing 'version'",
            source=source,
            fix=f"version = {POLICY_SCHEMA}",
        )
    version = data["version"]
    if version != POLICY_SCHEMA:
        raise PolicyError(
            f"policy schema {version!r} is not supported by this build",
            source=source, path="version", allowed=[POLICY_SCHEMA],
            fix="upgrade ProofOS, or write the policy for the supported schema",
        )

    raw_requirements = data.get("requirements")
    if not isinstance(raw_requirements, dict) or not raw_requirements:
        raise PolicyError(
            "a policy must declare at least one requirement",
            source=source, path="requirements",
            fix='[requirements.runtime_health]\nsource = ["OBSERVED"]',
        )

    trusted = {EvidenceSource.OBSERVED}
    requirements, unenforceable = [], []

    for kind, body in raw_requirements.items():
        path = f"requirements.{kind}"
        if not str(kind).strip():
            raise PolicyError("a requirement name cannot be empty",
                              source=source, path="requirements")
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise PolicyError(
                f"{kind!r} must be a table",
                source=source, path=path,
                fix=f'[requirements.{kind}]\nsource = ["OBSERVED"]',
            )
        unknown = set(body) - _REQUIREMENT_KEYS
        if unknown:
            key = sorted(unknown)[0]
            raise PolicyError(
                f"unknown key {key!r}",
                source=source, path=f"{path}.{key}", allowed=_REQUIREMENT_KEYS,
                # The named example is real: this exact typo would disable a
                # freshness horizon without any other symptom.
                fix=_suggest(key, _REQUIREMENT_KEYS) or "remove it",
            )

        sources = _parse_sources(body.get("source"), kind, source)
        if not sources & trusted:
            unenforceable.append(kind)

        requirements.append(
            PolicyRequirement(
                kind=str(kind),
                sources=sources,
                max_age_seconds=_parse_age(body.get("max_age_seconds"), kind, source),
                description=str(body.get("description", "")),
            )
        )

    return Policy(
        requirements=tuple(requirements),
        version=version,
        description=str(data.get("description", "")),
        source=source,
        unenforceable_sources=tuple(unenforceable),
    )


def load_policy(path: str | pathlib.Path) -> Policy:
    """Read a policy from TOML, YAML or JSON. All three yield one model."""
    path = pathlib.Path(path)
    if not path.exists():
        raise PolicyError(
            "no such policy file", source=str(path),
            fix="run `proofos init` to create one",
        )

    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    try:
        if suffix in (".toml", ""):
            data = tomllib.loads(text)
        elif suffix == ".json":
            data = json.loads(text)
        elif suffix in (".yaml", ".yml"):
            try:
                import yaml  # optional: only needed for YAML policies
            except ImportError:
                raise PolicyError(
                    "YAML policies need PyYAML",
                    source=str(path),
                    fix="pip install pyyaml, or write the policy as .toml",
                ) from None
            data = yaml.safe_load(text)
        else:
            raise PolicyError(
                f"unsupported policy format {suffix!r}",
                source=str(path), allowed=[".toml", ".yaml", ".yml", ".json"],
                fix="rename the file to proofos.toml",
            )
    except PolicyError:
        raise
    except Exception as exc:  # noqa: BLE001 - any decode failure is a config error
        raise PolicyError(
            f"could not parse: {exc}", source=str(path),
            fix="check the syntax against `proofos init` output",
        ) from exc

    return parse_policy(data, source=str(path))


#: What `proofos init` writes. Deliberately short: a starting policy should be
#: readable in one screen and correct by default.
STARTER_POLICY = '''# ProofOS policy
#
# Each requirement names something that must be proven before a claim of
# completion is accepted, and where that proof may come from.
#
# "OBSERVED" means evidence produced by something other than the agent under
# scrutiny. It is the only provenance that can satisfy a requirement -- a
# report from the agent doing the work is recorded and refused.

version = 1
description = "Verification policy for this project"

[requirements.runtime_health]
description = "The service responded to an independent probe"
source = ["OBSERVED"]
max_age_seconds = 300

[requirements.tests]
description = "The test suite passed, reported by CI rather than by the agent"
source = ["OBSERVED"]
'''


__all__ = [
    "POLICY_SCHEMA",
    "STARTER_POLICY",
    "Policy",
    "PolicyError",
    "PolicyRequirement",
    "load_policy",
    "parse_policy",
]
