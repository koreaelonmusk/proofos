"""What a plugin may declare, and what no plugin may ever claim.

A plugin connects ProofOS to something -- a health endpoint, a CI system, an
artifact store. It does not get to say whether the thing it connected to proves
anything. That decision stays in one kernel, and this module's job is to make
the boundary explicit enough that a plugin author can see where it is.

The invariant, stated once so the rest of the file can refer to it:

    INSTALLING A PLUGIN DOES NOT MAKE ITS OUTPUT TRUSTED EVIDENCE.

Three existing properties already enforce that, and this module is designed to
sit outside all of them rather than to re-implement any:

* ``ingestion.AttestationIngestor`` is the only holder of an observation
  capability and the only place a statement becomes ``OBSERVED``. A plugin
  never touches ``EvidenceSource``; it produces something that must survive the
  same twelve checks as anything else.
* ``collector_registry.CollectorRegistry`` seals at startup. A plugin loaded
  afterwards cannot add a key, so it cannot become a collector by arriving.
* ``plugin_id`` and ``collector_id`` are separate fields with separate
  lifetimes. A plugin that ships a collector does not thereby *become* one.

So the permission vocabulary below contains no way to spell "verify", "write
OBSERVED", or "disable freshness". Those are not permissions that are hard to
get; they are permissions that do not exist. A manifest asking for one is
rejected by name, because an author who tried deserves to be told why rather
than to see "unknown value" and try a synonym.

## The limit worth stating plainly

A loaded plugin is Python running in this process. It can import anything, read
anything the process can read, and open any socket the machine allows. This
module constrains what ProofOS *grants* a plugin, not what CPython *permits*
it. A manifest is a declaration that can be checked, reviewed and pinned -- it
is not a sandbox, and describing it as one would be the kind of claim this
project exists to refuse.

What that means in practice: the declaration is worth having because it makes
intent reviewable and because ProofOS refuses to route trust through it, not
because it stops a determined author from misbehaving in-process. Isolation, if
you need it, belongs in a process boundary, and ProofOS's own collector already
lives behind one.
"""

from __future__ import annotations

import difflib
import json
import pathlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

#: Bumped when the manifest shape changes in a way older builds cannot read.
PLUGIN_SCHEMA = 1


class PluginKind(StrEnum):
    """What a plugin connects.

    There is deliberately no ``VERIFIER``. One authoritative kernel decides
    VERIFIED or ABSTAIN; a second one would mean the answer depends on which
    was asked, which is the failure this whole system is built against.
    """

    COLLECTOR = "collector"
    EVIDENCE_ADAPTER = "evidence_adapter"
    STORAGE = "storage"
    TRANSPORT = "transport"
    REPORTER = "reporter"
    FRAMEWORK_ADAPTER = "framework_adapter"


class Permission(StrEnum):
    """Everything a plugin may ask ProofOS for.

    Read this list as the complete answer to "what can a plugin be allowed to
    do". Anything absent is absent on purpose.
    """

    #: Reach the network, to the hosts named in ``network_scope``.
    NETWORK = "network"
    #: Read its own configuration block. Not the policy, not other plugins'.
    READ_CONFIG = "read_config"
    #: Write scratch files under a directory ProofOS hands it.
    WRITE_TEMPORARY = "write_temporary"
    #: Read execution history. Reading is not appending and not editing.
    READ_JOURNAL = "read_journal"
    #: Produce material that will be offered to the ingestion boundary. The
    #: boundary decides what it becomes; this permission does not.
    SUBMIT_OBSERVATION = "submit_observation"
    #: Render a result somewhere. A reporter describes a decision it was given.
    REPORT = "report"


#: Permissions people will reasonably try to write, each refused by name. The
#: message matters more than the refusal: an author who reaches for "verify" has
#: a model of the system that needs correcting, not a typo that needs fixing.
REFUSED_PERMISSIONS: dict[str, str] = {
    "verify": (
        "verification is not delegable. One kernel decides VERIFIED or ABSTAIN, "
        "and a plugin that could decide would make the verdict depend on which "
        "plugin was installed"
    ),
    "write_observed": (
        "provenance is assigned at the ingestion boundary, never declared. "
        "Submit an observation with 'submit_observation' and let it be judged"
    ),
    "set_verified": (
        "a verdict is a conclusion, not a value that can be written"
    ),
    "disable_freshness": (
        "freshness is a security property of a requirement, not a plugin "
        "setting. A requirement that should tolerate older evidence says so in "
        "its own max_age_seconds"
    ),
    "modify_policy": (
        "policy says what must be proven. A component that could edit it could "
        "decide it had already been proven"
    ),
    "modify_registry": (
        "the collector registry seals at startup so trusted keys cannot change "
        "while executions run. A plugin loaded afterwards is exactly what "
        "sealing exists to keep out"
    ),
    "impersonate_collector": (
        "a collector_id is an identity only when a signature verifies against "
        "the registered key. There is nothing to impersonate without the key, "
        "and holding the key is not something a manifest can grant"
    ),
    "append_journal": (
        "the journal is appended by the runtime as things happen, so that what "
        "it records is what occurred rather than what a component wished to "
        "record"
    ),
}

#: References that mean "whatever is current", which is the opposite of what a
#: trusted integration needs. What ran yesterday must be what runs today.
FLOATING_REFERENCES = frozenset({"latest", "main", "master", "head", "trunk", "*"})

_PLUGIN_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")

_REQUIRED = (
    "schema_version", "plugin_id", "version", "kind", "entrypoint", "description",
    "minimum_proofos_version", "permissions",
)
_OPTIONAL = (
    "network_scope", "data_scope", "evidence_kinds", "config_schema",
    "publisher", "source_repository", "source_commit", "digest",
)
_KNOWN = frozenset(_REQUIRED + _OPTIONAL)


class PluginError(ValueError):
    """A manifest this build will not load, and what to do about it."""

    def __init__(self, problem: str, *, source: str = "", path: str = "",
                 fix: str = "") -> None:
        self.problem = problem
        self.source = source
        self.path = path
        self.fix = fix
        super().__init__(self.render())

    def render(self) -> str:
        where = f"{self.source or 'manifest'}"
        if self.path:
            where += f" [{self.path}]"
        text = f"{where}: {self.problem}"
        if self.fix:
            text += f"\n  fix: {self.fix}"
        return text


@dataclass(frozen=True)
class PluginManifest:
    """A declaration about a plugin, after this build has agreed to read it.

    Carries no capability and no trust. Holding one of these means a file
    parsed, not that anything it describes may be believed.
    """

    plugin_id: str
    version: str
    kind: PluginKind
    entrypoint: str
    description: str
    minimum_proofos_version: str
    permissions: frozenset[Permission] = frozenset()
    network_scope: tuple[str, ...] = ()
    data_scope: tuple[str, ...] = ()
    evidence_kinds: tuple[str, ...] = ()
    config_schema: dict[str, Any] = field(default_factory=dict)
    publisher: str = ""
    source_repository: str = ""
    source_commit: str = ""
    digest: str = ""
    schema_version: int = PLUGIN_SCHEMA

    @property
    def is_pinned(self) -> bool:
        """Can this reference only ever resolve to the code it resolved to today?

        A version alone is not pinning if the source can move underneath it, so
        a commit or a digest is what makes the answer yes.
        """
        return bool(self.source_commit or self.digest)

    @property
    def may_reach_network(self) -> bool:
        return Permission.NETWORK in self.permissions

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plugin_id": self.plugin_id,
            "version": self.version,
            "kind": str(self.kind),
            "entrypoint": self.entrypoint,
            "description": self.description,
            "minimum_proofos_version": self.minimum_proofos_version,
            "permissions": sorted(str(p) for p in self.permissions),
            "network_scope": list(self.network_scope),
            "data_scope": list(self.data_scope),
            "evidence_kinds": list(self.evidence_kinds),
            "config_schema": dict(self.config_schema),
            "publisher": self.publisher,
            "source_repository": self.source_repository,
            "source_commit": self.source_commit,
            "digest": self.digest,
        }


def _suggest(unknown: str, known: tuple[str, ...] | frozenset[str]) -> str:
    close = difflib.get_close_matches(unknown, sorted(known), n=1, cutoff=0.6)
    return f"did you mean '{close[0]}'?" if close else ""


def _require_str(data: dict, key: str, source: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PluginError(f"'{key}' must be a non-empty string",
                          source=source, path=key)
    return value.strip()


def parse_manifest(data: Any, *, source: str = "manifest") -> PluginManifest:
    """Read a manifest, refusing everything this build does not understand.

    Strictness is the point. A manifest that half-parses is a plugin whose
    declared limits are not the limits anyone reviewed.
    """
    if not isinstance(data, dict):
        raise PluginError("a manifest must be a table", source=source)

    for key in data:
        if key not in _KNOWN:
            raise PluginError(
                f"unknown key '{key}'", source=source, path=key,
                fix=_suggest(key, _KNOWN) or "remove it; unknown keys are refused "
                    "so a manifest cannot quietly mean more than it says",
            )

    schema = data.get("schema_version")
    if schema is None:
        raise PluginError("missing 'schema_version'", source=source,
                          fix=f"add schema_version = {PLUGIN_SCHEMA}")
    if schema != PLUGIN_SCHEMA:
        raise PluginError(
            f"schema_version {schema!r} is not supported by this build",
            source=source, path="schema_version",
            fix=f"this build reads schema_version {PLUGIN_SCHEMA}",
        )

    for key in _REQUIRED:
        if key not in data:
            raise PluginError(f"missing '{key}'", source=source, path=key)

    plugin_id = _require_str(data, "plugin_id", source)
    if not _PLUGIN_ID.match(plugin_id):
        raise PluginError(
            f"plugin_id {plugin_id!r} is not a lowercase hyphenated name",
            source=source, path="plugin_id",
            fix="use something like 'http-health'; ids appear in journals and "
                "error messages, where consistency is worth more than freedom",
        )

    version = _require_str(data, "version", source)
    if not _SEMVER.match(version):
        raise PluginError(
            f"version {version!r} is not a semantic version",
            source=source, path="version", fix="use MAJOR.MINOR.PATCH",
        )
    if version.lower() in FLOATING_REFERENCES:
        raise PluginError(f"version {version!r} names a moving target",
                          source=source, path="version")

    kind_raw = _require_str(data, "kind", source)
    try:
        kind = PluginKind(kind_raw)
    except ValueError:
        extra = ""
        if kind_raw in {"verifier", "verification", "judge"}:
            extra = (" There is one verification kernel and it is not "
                     "extensible; a plugin supplies evidence, it does not "
                     "weigh it.")
        raise PluginError(
            f"unknown plugin kind {kind_raw!r}", source=source, path="kind",
            fix=(_suggest(kind_raw, tuple(str(k) for k in PluginKind))
                 or "one of: " + ", ".join(str(k) for k in PluginKind)) + extra,
        ) from None

    permissions = _parse_permissions(data.get("permissions"), source)

    manifest = PluginManifest(
        plugin_id=plugin_id,
        version=version,
        kind=kind,
        entrypoint=_require_str(data, "entrypoint", source),
        description=_require_str(data, "description", source),
        minimum_proofos_version=_require_str(data, "minimum_proofos_version", source),
        permissions=permissions,
        network_scope=_string_tuple(data.get("network_scope"), "network_scope", source),
        data_scope=_string_tuple(data.get("data_scope"), "data_scope", source),
        evidence_kinds=_string_tuple(data.get("evidence_kinds"), "evidence_kinds", source),
        config_schema=dict(data.get("config_schema") or {}),
        publisher=str(data.get("publisher") or ""),
        source_repository=str(data.get("source_repository") or ""),
        source_commit=str(data.get("source_commit") or ""),
        digest=str(data.get("digest") or ""),
    )
    _check_coherence(manifest, source)
    return manifest


def _parse_permissions(raw: Any, source: str) -> frozenset[Permission]:
    if raw is None or not isinstance(raw, (list, tuple)):
        raise PluginError(
            "'permissions' must be a list, even when empty",
            source=source, path="permissions",
            fix="use permissions = [] to declare that it needs nothing",
        )
    out: set[Permission] = set()
    for item in raw:
        if not isinstance(item, str):
            raise PluginError(f"permission {item!r} is not a string",
                              source=source, path="permissions")
        name = item.strip().lower()
        if name in REFUSED_PERMISSIONS:
            raise PluginError(
                f"'{name}' is not a permission this system has",
                source=source, path="permissions",
                fix=REFUSED_PERMISSIONS[name],
            )
        try:
            out.add(Permission(name))
        except ValueError:
            raise PluginError(
                f"unknown permission {item!r}", source=source, path="permissions",
                fix=_suggest(name, tuple(str(p) for p in Permission))
                    or "one of: " + ", ".join(str(p) for p in Permission),
            ) from None
    return frozenset(out)


def _string_tuple(raw: Any, key: str, source: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise PluginError(f"'{key}' must be a list", source=source, path=key)
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise PluginError(f"'{key}' contains a non-string entry",
                              source=source, path=key)
    return tuple(str(item).strip() for item in raw)


def _check_coherence(manifest: PluginManifest, source: str) -> None:
    """Reject manifests that are individually well-formed and jointly nonsense."""
    if manifest.may_reach_network and not manifest.network_scope:
        raise PluginError(
            "declares the network permission but names no hosts",
            source=source, path="network_scope",
            fix="list the hosts it will contact; 'somewhere on the internet' "
                "is not a scope a reviewer can check",
        )
    if manifest.network_scope and not manifest.may_reach_network:
        raise PluginError(
            "names network hosts without declaring the network permission",
            source=source, path="permissions",
            fix="add 'network', or remove the hosts",
        )
    if manifest.evidence_kinds and manifest.kind not in {
        PluginKind.COLLECTOR, PluginKind.EVIDENCE_ADAPTER,
    }:
        raise PluginError(
            f"a {manifest.kind} plugin declares evidence_kinds",
            source=source, path="evidence_kinds",
            fix="only collectors and evidence adapters supply evidence; a "
                "reporter or transport that produced some would be producing it "
                "about work it also carried",
        )
    if (manifest.kind is PluginKind.COLLECTOR
            and Permission.SUBMIT_OBSERVATION not in manifest.permissions):
        raise PluginError(
            "a collector that cannot submit an observation has nothing to do",
            source=source, path="permissions",
            fix="add 'submit_observation'",
        )
    for reference in (manifest.source_commit, manifest.digest, manifest.version):
        if reference.lower() in FLOATING_REFERENCES:
            raise PluginError(
                f"{reference!r} is a moving reference",
                source=source,
                fix="pin to a commit or a digest; an integration that can "
                    "change underneath you is one you cannot have reviewed",
            )


def load_manifest(path: str | pathlib.Path) -> PluginManifest:
    """Read a manifest from TOML or JSON."""
    path = pathlib.Path(path)
    if not path.exists():
        raise PluginError(f"no manifest at {path}", source=str(path))
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(text)
    elif suffix == ".toml":
        import tomllib

        data = tomllib.loads(text)
    else:
        raise PluginError(
            f"unsupported manifest format '{suffix}'", source=str(path),
            fix="use .toml or .json",
        )
    return parse_manifest(data, source=str(path))


#: Tier 2. Public and documented, imported from ``proofos.plugins`` rather than
#: from the package root. A plugin author needs these; someone verifying a claim
#: does not, and the root API is for the second person.
__all__ = [
    "PLUGIN_SCHEMA",
    "PluginKind",
    "Permission",
    "PluginManifest",
    "PluginError",
    "parse_manifest",
    "load_manifest",
    "REFUSED_PERMISSIONS",
    "FLOATING_REFERENCES",
]
