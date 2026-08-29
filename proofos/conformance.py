"""What a plugin returns, and a suite an author can run before shipping one.

The manifest in ``plugins`` says what a plugin is allowed to ask for. This
module says what it is able to hand back, and the two do different jobs. A
manifest is a declaration a reviewer reads; the return type is a constraint the
language enforces on every call, including the ones nobody reviewed.

So ``Observation`` has no field for provenance, no field for a collector
identity, no signature and no nonce. A plugin cannot return OBSERVED evidence
for the same reason it cannot return a colour: there is nowhere to put it. What
it fills in is what it *saw*. Who is saying so, and for which request, is filled
in afterwards by a component holding a key -- and the sealed collector registry
decides whether that key means anything.

The conformance suite checks the properties that a type cannot:

* an unreachable target produces an unavailable outcome, not an optimistic one
* a plugin that did not declare the network does not open a socket
* a plugin that declared hosts does not contact different ones
* failure arrives as a value, not as an exception through the caller

Those are behavioural, so they are checked by running the plugin rather than by
reading it. The network checks work by replacing ``socket.socket`` for the
duration of a call, which catches a plugin that reaches out through any of the
usual libraries. It does not catch one that shells out to curl, and the report
says so rather than implying a completeness it does not have.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from .plugins import Permission, PluginKind, PluginManifest


class ObservationOutcome(StrEnum):
    """What the plugin saw. Deliberately not a verdict.

    ``UNAVAILABLE`` is the one that matters. A plugin that cannot reach its
    target has not learned that the target is unhealthy -- it has learned
    nothing, and saying so is the only honest option. Collapsing the two is how
    an outage becomes clean negative evidence.
    """

    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class ObservationRequest:
    """What the runtime hands a plugin: a question, and nothing else.

    Carries no nonce, no capability and no key. A plugin that wanted to forge an
    attestation would have to start by obtaining the things this deliberately
    does not include.
    """

    kind: str
    target: str
    timeout_seconds: float = 5.0
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Observation:
    """What a plugin saw, in the shape the eventual attestation commits to.

    The absent fields are the design. There is no ``source``, so a plugin cannot
    label its own output; no ``collector_id``, because identity belongs to
    whoever signs; no ``signature`` or ``nonce``, because those are issued at a
    boundary this type never reaches.
    """

    kind: str
    outcome: ObservationOutcome
    observed_at: float
    detail: str
    status_code: int | None = None
    response_digest: str = ""
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def is_conclusive(self) -> bool:
        """Did this observation learn anything about the target at all?"""
        return self.outcome is not ObservationOutcome.UNAVAILABLE


@runtime_checkable
class CollectorPlugin(Protocol):
    """Observe something and say what was seen.

    Two members. A protocol that needed more would be describing a framework,
    and the point of this one is that a useful plugin fits in a page.
    """

    manifest: PluginManifest

    def observe(self, request: ObservationRequest) -> Observation:
        ...


class FindingSeverity(StrEnum):
    """How much a conformance finding matters.

    Named for what it is rather than the shorter ``Severity``, because
    ``proofos.journal`` already has a ``Severity`` that means something else.
    Two public types with one name is a question a reader should never have to
    ask, and the root export can only ever point at one of them.
    """

    FAIL = "FAIL"
    WARN = "WARN"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    severity: FindingSeverity
    check: str
    detail: str

    def __str__(self) -> str:
        return f"{self.severity} {self.check}: {self.detail}"


@dataclass(frozen=True)
class ConformanceReport:
    plugin_id: str
    findings: tuple[Finding, ...]
    checks_run: tuple[str, ...]
    #: Stated so a passing report is not read as more than it is.
    not_checked: tuple[str, ...] = ()

    @property
    def conformant(self) -> bool:
        return not any(f.severity is FindingSeverity.FAIL for f in self.findings)

    def render(self) -> str:
        lines = [f"{self.plugin_id}: "
                 f"{'conformant' if self.conformant else 'NOT conformant'}"]
        for finding in self.findings:
            lines.append(f"  {finding}")
        if self.not_checked:
            lines.append("  not checked by this suite:")
            lines.extend(f"    - {item}" for item in self.not_checked)
        return "\n".join(lines)


NOT_CHECKED = (
    "a plugin that shells out to another process to reach the network",
    "a plugin that behaves differently when it is not being tested",
    "anything the plugin does before observe() is first called",
)


class _SocketWatcher:
    """Records connection attempts, and refuses them when they are not allowed.

    Replacing socket.socket catches urllib, http.client, requests and anything
    else that eventually opens one. It is a test harness, not a sandbox: a
    plugin determined to evade it can, and the report says as much.
    """

    def __init__(self, allowed: tuple[str, ...] | None) -> None:
        self.allowed = allowed
        self.attempts: list[str] = []
        self._original = socket.socket

    def __enter__(self) -> "_SocketWatcher":
        watcher = self

        class WatchedSocket(watcher._original):  # type: ignore[misc,valid-type]
            def connect(self, address, *args, **kwargs):  # noqa: ANN001
                host = address[0] if isinstance(address, tuple) else str(address)
                watcher.attempts.append(str(host))
                if watcher.allowed is not None and str(host) not in watcher.allowed:
                    raise PermissionError(
                        f"connection to {host} is outside the declared scope"
                    )
                return super().connect(address, *args, **kwargs)

        socket.socket = WatchedSocket  # type: ignore[assignment,misc]
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket = self._original  # type: ignore[assignment,misc]


def _fail(check: str, detail: str) -> Finding:
    return Finding(FindingSeverity.FAIL, check, detail)


def check_manifest(manifest: PluginManifest) -> list[Finding]:
    """Whether a parsed manifest is coherent for a collector.

    Parsing already refused the manifests that are wrong. This asks the softer
    question: is it *pinned*, and does it claim only what it needs?
    """
    findings: list[Finding] = []
    if manifest.kind is not PluginKind.COLLECTOR:
        findings.append(_fail("kind", f"{manifest.kind} is not a collector"))
    if not manifest.evidence_kinds:
        findings.append(_fail("evidence_kinds",
                              "a collector that names no evidence kind cannot be "
                              "matched to a requirement"))
    if not manifest.is_pinned:
        findings.append(Finding(
            FindingSeverity.WARN, "pinning",
            "no source_commit or digest; a version tag can move, so what runs "
            "tomorrow is not necessarily what was reviewed today",
        ))
    return findings


def check_observation_shape(observation: object) -> list[Finding]:
    """Whether what came back is an Observation and nothing more."""
    findings: list[Finding] = []
    if not isinstance(observation, Observation):
        return [_fail("return_type",
                      f"observe() returned {type(observation).__name__}, not an "
                      "Observation; only an Observation is structurally unable "
                      "to carry provenance")]
    for forbidden in ("source", "provenance", "collector_id", "signature",
                      "nonce", "trusted", "verdict", "status"):
        if hasattr(observation, forbidden):
            findings.append(_fail(
                "return_type",
                f"the observation carries {forbidden!r}; a plugin does not get "
                "to say where its output came from or what it proves",
            ))
    return findings


def check_fails_closed(plugin: CollectorPlugin,
                       request: ObservationRequest) -> list[Finding]:
    """An unreachable target must produce UNAVAILABLE, as a value.

    The request is pointed at a port nothing is listening on, which is the
    cheapest deterministic outage there is.
    """
    findings: list[Finding] = []
    try:
        observation = plugin.observe(request)
    except Exception as exc:  # noqa: BLE001 -- that is the finding
        return [_fail("fails_closed",
                      f"observe() raised {type(exc).__name__} instead of "
                      "returning an outcome; a caller cannot record an "
                      "exception as something that was observed")]
    findings.extend(check_observation_shape(observation))
    if isinstance(observation, Observation):
        if observation.outcome is ObservationOutcome.HEALTHY:
            findings.append(_fail(
                "fails_closed",
                "an unreachable target was reported HEALTHY",
            ))
        elif observation.outcome is ObservationOutcome.UNHEALTHY:
            findings.append(_fail(
                "fails_closed",
                "an unreachable target was reported UNHEALTHY; not reaching "
                "something is not the same as finding it broken, and only one "
                "of those is evidence about the target",
            ))
    return findings


def check_network_scope(plugin: CollectorPlugin,
                        request: ObservationRequest) -> list[Finding]:
    """Whether the plugin stays inside what its manifest declared."""
    manifest = plugin.manifest
    # The target this suite chose is allowed too. A probe plugin contacts what
    # it is pointed at, and failing it for obeying the request would only teach
    # authors to declare a wildcard scope -- which is the outcome this check
    # exists to prevent.
    target_host = request.target.rsplit(":", 1)[0] if request.target else ""
    allowed = (tuple(manifest.network_scope) + (target_host,)
               if manifest.may_reach_network else ())
    findings: list[Finding] = []
    with _SocketWatcher(allowed) as watcher:
        try:
            plugin.observe(request)
        except PermissionError as exc:
            findings.append(_fail("network_scope", str(exc)))
        except Exception:  # noqa: BLE001 -- covered by check_fails_closed
            pass
    if watcher.attempts and not manifest.may_reach_network:
        findings.append(_fail(
            "undeclared_network",
            f"opened a connection to {sorted(set(watcher.attempts))} without "
            "declaring the network permission",
        ))
    return findings


def check_plugin(plugin: CollectorPlugin, *,
                 unreachable_target: str = "127.0.0.1:9") -> ConformanceReport:
    """Run the suite against one collector plugin.

    Port 9 is discard; on a normal machine nothing is listening, which makes
    "cannot reach it" reproducible without a network.
    """
    findings: list[Finding] = []
    checks: list[str] = []

    manifest = getattr(plugin, "manifest", None)
    if not isinstance(manifest, PluginManifest):
        return ConformanceReport(
            plugin_id=getattr(manifest, "plugin_id", "<unknown>"),
            findings=(_fail("manifest",
                            "the plugin exposes no parsed PluginManifest"),),
            checks_run=("manifest",),
            not_checked=NOT_CHECKED,
        )

    checks.append("manifest")
    findings.extend(check_manifest(manifest))

    kind = manifest.evidence_kinds[0] if manifest.evidence_kinds else "unknown"
    outage = ObservationRequest(kind=kind, target=unreachable_target,
                                timeout_seconds=1.0)

    checks.append("fails_closed")
    findings.extend(check_fails_closed(plugin, outage))

    checks.append("network_scope")
    findings.extend(check_network_scope(plugin, outage))

    if Permission.SUBMIT_OBSERVATION not in manifest.permissions:
        findings.append(_fail(
            "permissions",
            "a collector without 'submit_observation' has nothing to offer",
        ))
    checks.append("permissions")

    return ConformanceReport(
        plugin_id=manifest.plugin_id,
        findings=tuple(findings),
        checks_run=tuple(checks),
        not_checked=NOT_CHECKED,
    )


#: Tier 2, for the same reason as ``proofos.plugins``: a plugin author runs this
#: suite, and nobody else needs to name its types.
__all__ = [
    "Observation",
    "ObservationOutcome",
    "ObservationRequest",
    "CollectorPlugin",
    "Finding",
    "FindingSeverity",
    "ConformanceReport",
    "check_plugin",
    "check_manifest",
    "check_observation_shape",
    "check_fails_closed",
    "check_network_scope",
    "NOT_CHECKED",
]
