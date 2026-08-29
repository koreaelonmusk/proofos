"""Declarative verification recipes: what must be proven, never whether it was.

A plugin answers *how* ProofOS can reach a system. A skill answers *what* has to
be true before a task counts as done. Neither answers *is it true* -- that stays
in one kernel, and everything here is arranged so that a skill has no way to
reach it.

The arrangement is structural rather than supervisory, in the same way the
plugin manifest has no word for "verify" and an ``Observation`` has no field for
provenance:

* A skill is data. There is no field that names a module, an entrypoint, a
  callback or a command, so loading one cannot run anything.
* A skill compiles to ``Requirement`` objects, and a ``Requirement`` holds a
  kind and a freshness horizon. There is nowhere in it to put a source, a
  grant, or a verdict -- so a skill declaring ``source = ["OBSERVED"]`` is
  stating what it would want, and the kernel goes on deciding what OBSERVED is
  worth exactly as it did before.
* Composition can only tighten. Two skills naming the same requirement resolve
  to the shorter horizon and the narrower source set, and an empty intersection
  is an error rather than a quiet widening.

## The one that is easy to get wrong

``max_age_seconds`` must be written down. Not defaulted, not omitted -- present,
as either a positive number of seconds or the word ``unbounded``. A recipe meant
to be reused is exactly where "we never decided" turns into "no horizon", and a
requirement with no horizon accepts evidence of any age. Making the unbounded
case a word someone had to type means it can be found, reviewed and argued with;
making it the default means it happens by not thinking.
"""

from __future__ import annotations

import difflib
import json
import math
import pathlib
from dataclasses import dataclass, field
from typing import Any, Iterable

from .plugins import FLOATING_REFERENCES, PluginKind
from .verifier import EvidenceSource, Requirement

#: Bumped when the skill shape changes in a way older builds cannot read.
SKILL_SCHEMA = 1

#: What a skill writes when it means "this evidence does not go stale". A word
#: rather than an omission, so the decision is visible in the file.
UNBOUNDED = "unbounded"

_SKILL_KEYS = frozenset({
    "schema_version", "skill_id", "version", "description", "requirements",
    "required_plugin_kinds", "required_plugins", "tags", "documentation_url",
})
_REQUIREMENT_KEYS = frozenset({"max_age_seconds", "source", "description"})
_PLUGIN_KEYS = frozenset({"plugin_id", "kind", "version"})

#: Fields that would make a skill something other than a description. Each is
#: refused by name with the reason, because someone writing one has a model of
#: the system that needs correcting rather than a typo that needs fixing.
REFUSED_FIELDS: dict[str, str] = {
    "verdict": "a skill says what must be proven; whether it was proven is the "
               "kernel's answer and there is nowhere here to write one",
    "verified": "same as verdict",
    "status": "same as verdict",
    "force_success": "there is no success to force. A requirement is satisfied "
                     "by evidence or it is not",
    "override_verdict": "a verdict that can be overridden was never a verdict",
    "bypass_verifier": "the verifier is the only thing that decides; a recipe "
                       "that could skip it would be deciding",
    "grant": "authority is held, not declared. A skill is a document",
    "grants": "authority is held, not declared. A skill is a document",
    "capabilities": "a capability is an object a component holds. Naming one in "
                    "a file does not produce it",
    "authority": "nothing in this file carries authority",
    "trusted": "trust is not a property a document can assert about itself",
    "write_observed": "provenance is assigned where an observation is made",
    "collector_id": "a collector identity is established by a key the sealed "
                    "registry holds, not by being named in a recipe",
    "attestation": "an attestation is signed by a collector; a skill has no key",
    "disable_freshness": "freshness is a property of a requirement. A recipe "
                         "that could switch it off could accept last year's "
                         "evidence for today's claim",
    "ignore_freshness": "see disable_freshness",
    "registry": "the registry seals at startup precisely so that later input "
                "cannot change what is trusted",
    "entrypoint": "a skill is data. Naming code to run would make it a program, "
                  "and a program can do anything the process can",
    "python": "see entrypoint",
    "script": "see entrypoint",
    "command": "see entrypoint",
    "callback": "see entrypoint",
    "hooks": "see entrypoint",
    "pre_verify": "see entrypoint",
    "post_verify": "see entrypoint",
    "custom_verifier": "there is one verifier and it is not extensible",
    "eval": "see entrypoint",
    "exec": "see entrypoint",
}

_SKILL_ID = __import__("re").compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SEMVER = __import__("re").compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")


class SkillError(ValueError):
    """A skill this build will not read, and what to do about it."""

    def __init__(self, problem: str, *, source: str = "", path: str = "",
                 fix: str = "") -> None:
        self.problem = problem
        self.source = source
        self.path = path
        self.fix = fix
        super().__init__(self.render())

    def render(self) -> str:
        where = self.source or "skill"
        if self.path:
            where += f" [{self.path}]"
        text = f"{where}: {self.problem}"
        if self.fix:
            text += f"\n  fix: {self.fix}"
        return text


@dataclass(frozen=True)
class SkillRequirement:
    """One fact a skill says must be established.

    ``sources`` records what the recipe's author considers appropriate. It is
    carried for humans and for the unsatisfiable check below, and it does not
    reach the kernel: ``as_requirement`` produces a ``Requirement``, which has a
    kind and a horizon and no room for anything else. A skill cannot widen what
    counts as independent evidence because the type it compiles into cannot
    express the idea.
    """

    kind: str
    max_age_seconds: float | None
    sources: frozenset[EvidenceSource] = frozenset({EvidenceSource.OBSERVED})
    description: str = ""

    def as_requirement(self) -> Requirement:
        return Requirement(self.kind, self.max_age_seconds)

    @property
    def is_unbounded(self) -> bool:
        return self.max_age_seconds is None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "max_age_seconds": UNBOUNDED if self.is_unbounded else self.max_age_seconds,
            "source": sorted(str(s) for s in self.sources),
            "description": self.description,
        }


@dataclass(frozen=True)
class PluginRequirement:
    """A dependency a skill declares. Declaring is not loading and not trusting.

    Nothing here resolves, imports or installs anything. A runtime that wanted
    to satisfy this would go and find the plugin, and finding it would still
    leave every question about what its output is worth exactly where it was.
    """

    kind: PluginKind | None = None
    plugin_id: str = ""
    version: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"kind": str(self.kind) if self.kind else "",
                "plugin_id": self.plugin_id, "version": self.version}


@dataclass(frozen=True)
class VerificationSkill:
    """A named, reusable statement of what a class of task has to prove."""

    skill_id: str
    version: str
    description: str
    requirements: tuple[SkillRequirement, ...]
    required_plugins: tuple[PluginRequirement, ...] = ()
    tags: tuple[str, ...] = ()
    documentation_url: str = ""
    schema_version: int = SKILL_SCHEMA

    def as_requirements(self) -> tuple[Requirement, ...]:
        """Compile to the kernel's own type.

        Deterministic, side-effect free, and reads nothing. It creates
        requirements; it never looks at evidence, never asks whether anything is
        satisfied, and has no path to a verdict.
        """
        return tuple(r.as_requirement() for r in self.requirements)

    @property
    def unenforceable_sources(self) -> tuple[str, ...]:
        """Requirements naming no provenance this build treats as independent.

        Surfaced rather than honoured. A recipe asking for EXECUTOR evidence is
        well-formed and can never be satisfied, and an operator should learn
        that here instead of discovering it as a permanent ABSTAIN.
        """
        from .verifier import TRUSTED_SOURCES

        return tuple(r.kind for r in self.requirements
                     if not (r.sources & TRUSTED_SOURCES))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "skill_id": self.skill_id,
            "version": self.version,
            "description": self.description,
            "requirements": {r.kind: r.as_dict() for r in self.requirements},
            "required_plugins": [p.as_dict() for p in self.required_plugins],
            "tags": list(self.tags),
            "documentation_url": self.documentation_url,
        }


def _suggest(unknown: str, known: Iterable[str]) -> str:
    close = difflib.get_close_matches(unknown, sorted(known), n=1, cutoff=0.6)
    return f"did you mean '{close[0]}'?" if close else ""


def _reject_forbidden(data: dict, source: str, path: str = "") -> None:
    for key in data:
        lowered = str(key).strip().lower()
        if lowered in REFUSED_FIELDS:
            raise SkillError(
                f"'{key}' is not something a skill can say",
                source=source, path=path or key, fix=REFUSED_FIELDS[lowered],
            )


def _freshness(raw: Any, source: str, path: str) -> float | None:
    if raw is None:
        raise SkillError(
            "'max_age_seconds' is null", source=source, path=path,
            fix=f"write a positive number of seconds, or '{UNBOUNDED}' if this "
                "evidence genuinely does not go stale. Null reads as 'no "
                "horizon' while looking like an oversight",
        )
    if isinstance(raw, str):
        if raw.strip().lower() == UNBOUNDED:
            return None
        raise SkillError(f"'max_age_seconds' is {raw!r}", source=source, path=path,
                         fix=f"a number of seconds, or '{UNBOUNDED}'")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise SkillError("'max_age_seconds' must be a number of seconds",
                         source=source, path=path)
    value = float(raw)
    if math.isnan(value) or math.isinf(value):
        raise SkillError(f"'max_age_seconds' is {raw!r}", source=source, path=path,
                         fix=f"use '{UNBOUNDED}' to say there is no horizon")
    if value <= 0:
        raise SkillError("'max_age_seconds' must be positive", source=source,
                         path=path,
                         fix="a horizon of zero or less can never be met")
    return value


def _sources(raw: Any, source: str, path: str) -> frozenset[EvidenceSource]:
    if raw is None:
        return frozenset({EvidenceSource.OBSERVED})
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        raise SkillError("'source' must be a non-empty list", source=source, path=path)
    out: set[EvidenceSource] = set()
    for item in raw:
        try:
            out.add(EvidenceSource(str(item).strip().upper()))
        except ValueError:
            raise SkillError(
                f"unknown provenance {item!r}", source=source, path=path,
                fix=_suggest(str(item).upper(), [str(s) for s in EvidenceSource])
                    or "one of: " + ", ".join(str(s) for s in EvidenceSource),
            ) from None
    return frozenset(out)


def _plugin_requirement(raw: Any, source: str, index: int) -> PluginRequirement:
    path = f"required_plugins[{index}]"
    if not isinstance(raw, dict):
        raise SkillError("each required plugin must be a table",
                         source=source, path=path)
    _reject_forbidden(raw, source, path)
    for key in raw:
        if key not in _PLUGIN_KEYS:
            raise SkillError(f"unknown key '{key}'", source=source, path=path,
                             fix=_suggest(key, _PLUGIN_KEYS))
    plugin_id = str(raw.get("plugin_id", "")).strip()
    kind_raw = str(raw.get("kind", "")).strip()
    version = str(raw.get("version", "")).strip()
    if not plugin_id and not kind_raw:
        raise SkillError("a plugin dependency names neither an id nor a kind",
                         source=source, path=path)
    kind = None
    if kind_raw:
        try:
            kind = PluginKind(kind_raw)
        except ValueError:
            raise SkillError(f"unknown plugin kind {kind_raw!r}", source=source,
                             path=path,
                             fix="one of: " + ", ".join(str(k) for k in PluginKind)
                             ) from None
    if plugin_id and not version:
        raise SkillError(
            f"plugin {plugin_id!r} is named without a version",
            source=source, path=path,
            fix="pin the version. A dependency that resolves to whatever is "
                "current is one nobody reviewed",
        )
    if version:
        if version.lower() in FLOATING_REFERENCES or "@" in version:
            raise SkillError(f"version {version!r} is a moving reference",
                             source=source, path=path,
                             fix="use an exact MAJOR.MINOR.PATCH version")
        if not _SEMVER.match(version):
            raise SkillError(f"version {version!r} is not a semantic version",
                             source=source, path=path)
    return PluginRequirement(kind=kind, plugin_id=plugin_id, version=version)


def parse_skill(data: Any, *, source: str = "skill") -> VerificationSkill:
    """Read a skill, refusing everything this build does not understand."""
    if not isinstance(data, dict):
        raise SkillError("a skill must be a table", source=source)

    _reject_forbidden(data, source)
    for key in data:
        if key not in _SKILL_KEYS:
            raise SkillError(
                f"unknown key '{key}'", source=source, path=key,
                fix=_suggest(key, _SKILL_KEYS) or "remove it; unknown keys are "
                    "refused so a skill cannot quietly mean more than it says",
            )

    schema = data.get("schema_version")
    if schema is None:
        raise SkillError("missing 'schema_version'", source=source,
                         fix=f"add schema_version = {SKILL_SCHEMA}")
    if schema != SKILL_SCHEMA:
        raise SkillError(f"schema_version {schema!r} is not supported by this build",
                         source=source, path="schema_version")

    skill_id = str(data.get("skill_id", "")).strip()
    if not _SKILL_ID.match(skill_id):
        raise SkillError(f"skill_id {skill_id!r} is not a lowercase hyphenated name",
                         source=source, path="skill_id",
                         fix="use something like 'web-service-release'")

    version = str(data.get("version", "")).strip()
    if not _SEMVER.match(version):
        raise SkillError(f"version {version!r} is not a semantic version",
                         source=source, path="version")

    description = str(data.get("description", "")).strip()
    if not description:
        raise SkillError("missing 'description'", source=source, path="description",
                         fix="say what class of task this recipe is for")

    raw_requirements = data.get("requirements")
    if not isinstance(raw_requirements, dict) or not raw_requirements:
        raise SkillError(
            "a skill must declare at least one requirement",
            source=source, path="requirements",
            fix="a recipe that requires nothing would accept anything, which is "
                "a more dangerous file than one that fails to parse",
        )

    requirements: list[SkillRequirement] = []
    for kind, body in raw_requirements.items():
        path = f"requirements.{kind}"
        if body is None:
            body = {}
        if not isinstance(body, dict):
            raise SkillError("a requirement must be a table", source=source, path=path)
        _reject_forbidden(body, source, path)
        for key in body:
            if key not in _REQUIREMENT_KEYS:
                raise SkillError(f"unknown key '{key}'", source=source,
                                 path=f"{path}.{key}",
                                 fix=_suggest(key, _REQUIREMENT_KEYS))
        if "max_age_seconds" not in body:
            raise SkillError(
                "'max_age_seconds' is not declared", source=source, path=path,
                fix=f"write a number of seconds, or '{UNBOUNDED}'. A reusable "
                    "recipe is exactly where an omitted horizon turns into no "
                    "horizon without anyone deciding",
            )
        requirements.append(SkillRequirement(
            kind=str(kind),
            max_age_seconds=_freshness(body["max_age_seconds"], source, path),
            sources=_sources(body.get("source"), source, path),
            description=str(body.get("description", "")).strip(),
        ))

    raw_plugins = data.get("required_plugins") or []
    if not isinstance(raw_plugins, (list, tuple)):
        raise SkillError("'required_plugins' must be a list", source=source,
                         path="required_plugins")
    plugins = tuple(_plugin_requirement(item, source, i)
                    for i, item in enumerate(raw_plugins))

    kinds_raw = data.get("required_plugin_kinds") or []
    if not isinstance(kinds_raw, (list, tuple)):
        raise SkillError("'required_plugin_kinds' must be a list", source=source,
                         path="required_plugin_kinds")
    for name in kinds_raw:
        try:
            plugins += (PluginRequirement(kind=PluginKind(str(name).strip())),)
        except ValueError:
            raise SkillError(f"unknown plugin kind {name!r}", source=source,
                             path="required_plugin_kinds") from None

    return VerificationSkill(
        skill_id=skill_id,
        version=version,
        description=description,
        requirements=tuple(requirements),
        required_plugins=plugins,
        tags=tuple(str(t) for t in (data.get("tags") or ())),
        documentation_url=str(data.get("documentation_url", "")).strip(),
    )


def load_skill(path: str | pathlib.Path) -> VerificationSkill:
    """Read a skill from TOML or JSON."""
    path = pathlib.Path(path)
    if not path.exists():
        raise SkillError(f"no skill at {path}", source=str(path))
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(text)
    elif suffix == ".toml":
        import tomllib

        data = tomllib.loads(text)
    else:
        raise SkillError(f"unsupported skill format '{suffix}'", source=str(path),
                         fix="use .toml or .json")
    return parse_skill(data, source=str(path))


def combine(*skills: VerificationSkill) -> tuple[Requirement, ...]:
    """Merge skills into one requirement set, never loosening anything.

    Two recipes naming the same kind resolve to the shorter horizon and the
    narrower source set. That direction is the whole rule: a combination that
    could relax a constraint would let anyone weaken a strict requirement by
    adding a lax skill next to it, which is the opposite of what combining
    recipes is for.

    An empty source intersection is an error rather than a silent widening --
    two authors who disagree about what may prove something have not produced a
    third answer, and picking one would be inventing it.
    """
    merged: dict[str, SkillRequirement] = {}
    for skill in skills:
        for requirement in skill.requirements:
            existing = merged.get(requirement.kind)
            if existing is None:
                merged[requirement.kind] = requirement
                continue
            sources = existing.sources & requirement.sources
            if not sources:
                raise SkillError(
                    f"two skills require {requirement.kind!r} with no provenance "
                    "in common",
                    source="combine",
                    fix=f"{sorted(str(s) for s in existing.sources)} and "
                        f"{sorted(str(s) for s in requirement.sources)} do not "
                        "overlap; one of them has to change",
                )
            horizons = [h for h in (existing.max_age_seconds,
                                    requirement.max_age_seconds) if h is not None]
            merged[requirement.kind] = SkillRequirement(
                kind=requirement.kind,
                max_age_seconds=min(horizons) if horizons else None,
                sources=sources,
                description=existing.description or requirement.description,
            )
    return tuple(r.as_requirement() for r in merged.values())


def _builtin(body: dict[str, Any]) -> VerificationSkill:
    return parse_skill(body, source=f"builtin:{body['skill_id']}")


#: Four, deliberately. These are examples of the shape, not a catalogue, and
#: each one is boring on purpose: a recipe with an interesting mechanism is a
#: recipe doing something a recipe should not.
BUILTIN_SKILLS: dict[str, VerificationSkill] = {
    skill.skill_id: skill for skill in (
        _builtin({
            "schema_version": SKILL_SCHEMA,
            "skill_id": "agent-task-completion",
            "version": "1.0.0",
            "description": "An agent reported a task complete. Require an "
                           "independent observation before accepting it.",
            "requirements": {
                "task_outcome": {
                    "max_age_seconds": 900,
                    "source": ["OBSERVED"],
                    "description": "Something other than the agent confirms the "
                                   "task's effect. The agent's own report is the "
                                   "claim under scrutiny, not evidence for it.",
                },
            },
            "tags": ["general"],
        }),
        _builtin({
            "schema_version": SKILL_SCHEMA,
            "skill_id": "web-service-release",
            "version": "1.0.0",
            "description": "A service was released. Require the artifact it was "
                           "built from and a live observation of the result.",
            "requirements": {
                "artifact": {
                    "max_age_seconds": UNBOUNDED,
                    "source": ["OBSERVED"],
                    "description": "A digest of what was deployed. Bytes do not "
                                   "go stale, so this has no horizon.",
                },
                "runtime_health": {
                    "max_age_seconds": 300,
                    "source": ["OBSERVED"],
                    "description": "A probe speaks only for the moment it ran.",
                },
            },
            "required_plugin_kinds": ["collector"],
            "tags": ["deployment"],
        }),
        _builtin({
            "schema_version": SKILL_SCHEMA,
            "skill_id": "github-pr-verification",
            "version": "1.0.0",
            "description": "A pull request claims to be ready. Require the "
                           "checks that ran, not the description that says so.",
            "requirements": {
                "tests": {
                    "max_age_seconds": UNBOUNDED,
                    "source": ["OBSERVED"],
                    "description": "A recorded run speaks for the commit it "
                                   "describes. The PR body, the commit message "
                                   "and any bot comment are claims.",
                },
                "artifact": {
                    "max_age_seconds": UNBOUNDED,
                    "source": ["OBSERVED"],
                    "description": "What the checks actually produced.",
                },
            },
            "tags": ["ci"],
        }),
        _builtin({
            "schema_version": SKILL_SCHEMA,
            "skill_id": "long-running-operation",
            "version": "1.0.0",
            "description": "An operation spanning restarts. Require that the "
                           "action happened and that something observed it "
                           "recently, whatever a checkpoint remembers.",
            "requirements": {
                "action_outcome": {
                    "max_age_seconds": UNBOUNDED,
                    "source": ["OBSERVED"],
                    "description": "That the action occurred is a fact about the "
                                   "past and does not expire.",
                },
                "runtime_health": {
                    "max_age_seconds": 300,
                    "source": ["OBSERVED"],
                    "description": "That the result still holds is a fact about "
                                   "now, and an observation from before the "
                                   "restart is not one.",
                },
            },
            "tags": ["continuity"],
        }),
    )
}


def get_skill(skill_id: str) -> VerificationSkill:
    """Look up a built-in skill by id."""
    try:
        return BUILTIN_SKILLS[skill_id]
    except KeyError:
        raise SkillError(
            f"no built-in skill {skill_id!r}",
            source="builtin",
            fix=_suggest(skill_id, BUILTIN_SKILLS)
                or "one of: " + ", ".join(sorted(BUILTIN_SKILLS)),
        ) from None


#: Tier 2. A skill author imports these from ``proofos.skills``; someone
#: verifying a claim never needs them, and the root API is for the second one.
__all__ = [
    "SKILL_SCHEMA",
    "UNBOUNDED",
    "VerificationSkill",
    "SkillRequirement",
    "PluginRequirement",
    "SkillError",
    "parse_skill",
    "load_skill",
    "combine",
    "get_skill",
    "BUILTIN_SKILLS",
    "REFUSED_FIELDS",
]
