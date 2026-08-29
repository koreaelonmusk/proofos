"""The ProofOS command line.

Two commands carry the product. ``proofos demo`` teaches what ProofOS is
without documentation, and ``proofos doctor`` tells you why your install is not
behaving. Everything else is there because a person needed it, not because a
function existed.

Nothing here is authority. The CLI formats decisions made by the verification
kernel; it cannot reach a verdict of its own, and there is no flag that makes
something verified.

Exit codes matter in CI, so they are distinct and stable:

    0   VERIFIED, or an informational command that succeeded
    1   ABSTAIN -- a real product result, not a crash
    2   configuration or usage error
    3   operational failure (something ProofOS could not do)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time
from typing import Sequence

from .api import Decision, ProofOS, ProvenanceNotDeclarable
from .capabilities import ObservationCapability
from .ledger import EvidenceLedger
from .policy import STARTER_POLICY, PolicyError, load_policy
from .probe import ProbeOutcome, probe_health
from .verifier import TRUSTED_SOURCES, Evidence, EvidenceSource, Requirement

EXIT_VERIFIED = 0
EXIT_ABSTAIN = 1
EXIT_USAGE = 2
EXIT_OPERATIONAL = 3

VERSION = "0.1.0"

# -- presentation --------------------------------------------------------------


def _c(text: str, code: str, colour: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if colour else text


def _use_colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def render(decision: Decision, colour: bool = False) -> str:
    """Human output. ABSTAIN is a result, so it is not styled as an error.

    Shows what was accepted, what was refused and why, and what to do next --
    the four things a person actually needs when a verification does not pass.
    """
    verified = decision.verified
    head = _c(str(decision.status), "32;1" if verified else "33;1", colour)

    lines = [f"STATUS    {head}"]
    if not verified:
        lines.append(f"REASON    {decision.reason}")
    lines.append(f"          {decision.explanation}")

    if decision.missing:
        lines += ["", "MISSING   " + ", ".join(decision.missing)]

    if decision.evidence:
        lines += ["", "EVIDENCE"]
        for a in decision.evidence:
            mark = _c("accepted", "32", colour) if a.accepted_by_verifier \
                else _c("refused ", "31", colour)
            lines.append(f"  {mark}  {a.kind:<16} {a.source:<9} {a.collector}")
            if a.rejection_reason:
                lines.append(f"            {a.rejection_reason}")

    if not verified:
        lines += ["", "NEXT      " + _next_action(decision)]
    return "\n".join(lines)


def _next_action(decision: Decision) -> str:
    reason = str(decision.reason)
    if reason == "EVIDENCE_UNTRUSTED":
        return ("Collect the missing evidence from an independent source. "
                "A report from the agent under scrutiny cannot satisfy it.")
    if reason == "EVIDENCE_STALE":
        return "Observe again. The evidence is real but outside its freshness horizon."
    if reason == "EVIDENCE_MISSING":
        return "No evidence of the required kind was supplied."
    if reason == "EVIDENCE_INVALID":
        return "The governing observation reports failure. Fix the system, not the evidence."
    if reason == "EVIDENCE_TAMPERED":
        return "A record no longer matches its own digest. Do not trust this evidence set."
    return "Supply evidence that satisfies every requirement."


# -- commands ------------------------------------------------------------------


def cmd_version(args, out) -> int:
    if args.json:
        json.dump({"proofos": VERSION, "python": sys.version.split()[0]}, out)
        out.write("\n")
    else:
        out.write(f"proofos {VERSION}\n")
    return EXIT_VERIFIED


def _probe(name: str, importable: str) -> dict:
    try:
        __import__(importable)
        return {"name": name, "present": True, "detail": ""}
    except Exception as exc:  # noqa: BLE001 - a missing optional is not a crash
        return {"name": name, "present": False, "detail": type(exc).__name__}


def cmd_doctor(args, out) -> int:
    """Report what works and what is merely absent. Absence is not failure.

    A local deterministic install is complete without any cloud credential, so
    missing optional integrations are reported and do not change the exit code.
    """
    required = [
        {"name": "python >= 3.11", "present": sys.version_info >= (3, 11),
         "detail": sys.version.split()[0]},
        _probe("proofos.verifier", "proofos.verifier"),
        _probe("proofos.journal", "proofos.journal"),
        _probe("proofos.continuity", "proofos.continuity"),
        _probe("proofos.agent_catalog", "proofos.agent_catalog"),
    ]
    optional = [
        _probe("cryptography (signed observation)", "cryptography"),
        _probe("google-adk (agent runtime)", "google.adk"),
        _probe("google-cloud-firestore (durable journal)", "google.cloud.firestore"),
        _probe("fastapi (http service)", "fastapi"),
    ]

    registry_ok, agents = True, []
    try:
        from .registry import default_registry
        registry = default_registry()
        agents = [r.agent_id for r in registry.records()]
        registry_ok = registry.sealed
    except Exception as exc:  # noqa: BLE001
        registry_ok = False
        agents = [f"unavailable: {type(exc).__name__}"]

    info = [
        {"name": "agent registry sealed", "present": registry_ok,
         "detail": f"{len(agents)} agents"},
    ]

    failed = [c for c in required if not c["present"]]

    if args.json:
        json.dump({
            "schema_version": 1,
            "proofos": VERSION,
            "healthy": not failed,
            "required": required,
            "optional": optional,
            "informational": info,
            "agents": agents,
        }, out, indent=2)
        out.write("\n")
    else:
        colour = _use_colour(out)
        def block(title, checks, mark_absent="absent"):
            out.write(f"\n{title}\n")
            for c in checks:
                ok = c["present"]
                tick = _c("ok     ", "32", colour) if ok else _c(mark_absent.ljust(7), "33", colour)
                detail = f"  {c['detail']}" if c["detail"] else ""
                out.write(f"  {tick} {c['name']}{detail}\n")
        out.write(f"proofos {VERSION}\n")
        block("REQUIRED", required, "MISSING")
        block("OPTIONAL", optional)
        block("INFORMATIONAL", info)
        if failed:
            out.write("\nInstall is not usable: a required component is missing.\n")
        else:
            out.write("\nDeterministic verification is ready. "
                      "Optional items are only needed for the integrations they name.\n")

    return EXIT_OPERATIONAL if failed else EXIT_VERIFIED


#: The task the demo opens. Named so the ledger has something to attach to;
#: nothing else depends on the value.
_DEMO_TASK = "DEMO-1"


#: The demo is a real verification, not a script that prints a story. Every
#: status below is produced by the kernel at the moment it is shown.
def cmd_demo(args, out) -> int:
    proof = ProofOS()
    now = time.time()
    requirements = [Requirement("runtime_health", max_age_seconds=300)]
    colour = _use_colour(out)

    # The self-report is something a caller can construct, because saying "I did
    # it" requires no authority. The observation is not: it is produced by a
    # capability, recorded in a ledger, and read back from there. That asymmetry
    # is the whole demo, so the demo has to be built the way the runtime is
    # rather than by labelling two records differently.
    self_report = Evidence(
        kind="runtime_health",
        value="deploy-agent states: the service is up",
        source=EvidenceSource.EXECUTOR,
        collected_at=now,
        collector="deploy-agent",
    )

    ledger = EvidenceLedger()
    ledger.open_task(_DEMO_TASK, tuple(requirements))
    collector = ObservationCapability(
        ledger, "http-health-collector", ("runtime_health",)
    )
    ledger.seal()
    ledger.record(_DEMO_TASK, self_report, None)

    claimed = proof.verify_recorded(ledger, _DEMO_TASK, "Deployment complete.",
                                    now=now)

    collector.record_observation(
        _DEMO_TASK, "runtime_health", "probe HEALTHY: HTTP 200 in 12ms",
        satisfies=True, collected_at=now,
    )
    resolved = proof.verify_recorded(ledger, _DEMO_TASK, "Deployment complete.",
                                     now=now)

    if args.json:
        json.dump({
            "schema_version": 1,
            "claim": "Deployment complete.",
            "steps": [
                {"step": "self_report_only", **claimed.as_dict()},
                {"step": "independent_observation", **resolved.as_dict()},
            ],
        }, out, indent=2)
        out.write("\n")
        return EXIT_VERIFIED if resolved.verified else EXIT_ABSTAIN

    out.write(_c("\n  The agent says it is done.\n", "1", colour))
    out.write('    deploy-agent: "Deployment complete."\n\n')
    out.write("  ProofOS asks what independent evidence supports that.\n")
    out.write("  The only runtime evidence came from deploy-agent itself.\n\n")
    out.write(render(claimed, colour) + "\n")
    out.write(_c("\n  An independent collector observes the service.\n", "1", colour))
    out.write("    http-health-collector: probe HEALTHY, HTTP 200\n\n")
    out.write(render(resolved, colour) + "\n")
    out.write(
        "\n  The self-report was sound and still refused. What changed the answer\n"
        "  was evidence the agent could not have produced.\n\n"
        "  Recorded executions on Google Cloud, including a live prompt-injection\n"
        "  attempt that failed closed: https://koreaelonmusk.github.io/proofos/\n"
    )
    return EXIT_VERIFIED if resolved.verified else EXIT_ABSTAIN


def cmd_init(args, out) -> int:
    """Add ProofOS to an existing project without disturbing it.

    Writes one policy file and nothing else. Never overwrites: a tool that
    silently replaces configuration is a tool nobody runs twice.
    """
    import pathlib

    target = pathlib.Path(args.directory or ".").resolve()
    if not target.is_dir():
        return _usage(f"not a directory: {target}")

    planned = [(target / "proofos.toml", STARTER_POLICY)]
    existing = [path for path, _ in planned if path.exists()]
    to_create = [path for path, _ in planned if path not in existing]

    if existing:
        for path in existing:
            sys.stderr.write(
                f"proofos: {path.name} already exists; leaving it alone\n"
            )

    if args.json:
        json.dump(
            {
                "schema_version": 1,
                "directory": str(target),
                "would_create": [str(p) for p in to_create],
                "already_present": [str(p) for p in existing],
                "dry_run": bool(args.dry_run),
            },
            out,
            indent=2,
        )
        out.write("\n")

    if not to_create:
        return EXIT_USAGE

    if args.dry_run:
        if not args.json:
            out.write(f"Would create in {target}:\n")
            for path in to_create:
                out.write(f"  {path.name}\n")
        return EXIT_VERIFIED

    for path, content in planned:
        if path in existing:
            continue
        path.write_text(content, encoding="utf-8")
        if not args.json:
            out.write(f"created {path.name}\n")

    if not args.json:
        out.write(
            "\nNext:\n"
            "  proofos verify --policy proofos.toml <evidence.json>\n"
        )
    return EXIT_VERIFIED


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise SystemExit(_usage(f"no such file: {path}"))
    except json.JSONDecodeError as exc:
        raise SystemExit(_usage(f"{path} is not valid JSON: {exc}"))
    except OSError as exc:
        # Present but unreadable. Naming the wrong file is a usage error; a file
        # the process cannot open is the environment failing, and a CI job needs
        # to tell those apart to know whether to retry.
        sys.stderr.write(f"proofos: could not read {path}: {type(exc).__name__}" + "\n")
        raise SystemExit(EXIT_OPERATIONAL)


def _usage(message: str) -> int:
    sys.stderr.write(f"proofos: {message}\n")
    return EXIT_USAGE


#: The identity this command writes observations under. It is a real collector
#: identity in the ledger's sense -- the CLI held a capability and wrote what it
#: saw -- and it claims nothing about the thing observed beyond that.
CLI_COLLECTOR = "proofos-cli"

#: The task the file-driven path opens. One run, one task; nothing persists.
_VERIFY_TASK = "cli-verify"


class _VerifyUsage(ValueError):
    """A malformed instruction in the input file."""


class _Unavailable(Exception):
    """A check that could not be carried out.

    Distinct from a check that found something wrong. Not reaching a service is
    not a finding about the service, and an observation that never happened must
    not leave a record saying it did.
    """

    def __init__(self, kind: str, reason: str) -> None:
        self.kind = kind
        self.reason = reason
        super().__init__(f"{kind}: {reason}")


def _observe(spec, index: int) -> tuple[str, str, bool]:
    """Go and check one thing, and report what was seen.

    This is what makes exit 0 reachable again without reopening the hole that
    closed it. The old path let a file say ``"source": "OBSERVED"`` and be
    believed. This one reads no provenance at all: it reads an instruction --
    probe this URL, hash this file -- carries it out, and records the result
    under the CLI's own collector identity. The CLI is then genuinely the thing
    that looked, which is the only way OBSERVED is ever earned.
    """
    path = f"observations[{index}]"
    if not isinstance(spec, dict):
        raise _VerifyUsage(f"{path} must be an object")
    kind = spec.get("kind")
    if not isinstance(kind, str) or not kind.strip():
        raise _VerifyUsage(f"{path}.kind is missing")
    check = spec.get("check")

    if check == "http":
        url = spec.get("url")
        if not isinstance(url, str) or not url.strip():
            raise _VerifyUsage(f"{path}.url is missing")
        result = probe_health(url, timeout=float(spec.get("timeout", 5.0)))
        if result.outcome in (ProbeOutcome.UNREACHABLE, ProbeOutcome.TIMEOUT):
            raise _Unavailable(kind, f"{result.outcome}: {result.detail}")
        return (kind, f"{result.outcome}: {result.detail}",
                result.outcome is ProbeOutcome.HEALTHY)

    if check == "digest":
        target = spec.get("path")
        if not isinstance(target, str) or not target.strip():
            raise _VerifyUsage(f"{path}.path is missing")
        try:
            data = pathlib.Path(target).read_bytes()
        except OSError as exc:
            raise _Unavailable(kind, f"could not read {target}: {type(exc).__name__}") from None
        return kind, f"sha256 {hashlib.sha256(data).hexdigest()}", True

    raise _VerifyUsage(
        f"{path}.check is {check!r}; this build can perform 'http' or 'digest'")


def cmd_verify(args, out) -> int:
    """Verify a claim against evidence supplied as JSON.

    A file is wire input, so the ``source`` field in it is a claim about
    provenance and not provenance itself. Reading it straight through was how
    ``{"source": "OBSERVED"}`` used to produce exit 0: the strongest statement
    in the system, available to anyone who could write a file.

    So this refuses to read an independent provenance out of a document. What
    remains is genuinely useful -- it answers what a set of self-reports is
    worth, which is ABSTAIN, and says why. Reaching VERIFIED needs an
    observation that was made rather than typed, and that arrives through the
    ingestion boundary rather than through argv.
    """
    data = _load(args.evidence)

    policy = None
    if args.policy:
        try:
            policy = load_policy(args.policy)
        except PolicyError as exc:
            sys.stderr.write(exc.render() + "\n")
            return EXIT_USAGE
        for kind in policy.unenforceable_sources:
            # A policy may name a provenance the kernel does not trust. It is
            # not silently honoured and it is not silently dropped -- the
            # requirement simply can never be satisfied, and the operator is
            # told so rather than discovering it as a permanent ABSTAIN.
            sys.stderr.write(
                f"proofos: requirement {kind!r} declares no provenance this build "
                "treats as independent; it can never be satisfied\n"
            )

    try:
        requirements = list(policy.as_requirements()) if policy else [
            Requirement(r["kind"], r.get("max_age_seconds"))
            if isinstance(r, dict) else Requirement(str(r))
            for r in data["requirements"]
        ]
        evidence = [
            Evidence(
                kind=e["kind"],
                value=e.get("value", ""),
                source=EvidenceSource(e["source"]),
                valid=e.get("valid", True),
                collected_at=e.get("collected_at"),
                collector=e.get("collector", "unspecified"),
            )
            for e in data.get("evidence", [])
        ]
        claim = data["claim"]
    except KeyError as exc:
        return _usage(f"{args.evidence} is missing required key {exc}")
    except ValueError as exc:
        return _usage(f"{args.evidence}: {exc}")

    declared = [e for e in evidence if e.source in TRUSTED_SOURCES]
    if declared:
        # The refusal that closed the hole, kept where the reader meets it, and
        # pointing at the path that does work rather than only saying no.
        kinds = sorted({e.kind for e in declared})
        labels = sorted({str(e.source) for e in declared})
        sys.stderr.write(
            f"proofos: {args.evidence}: evidence for {kinds} arrived labelled "
            f"{labels}. A file is written by whoever runs this command, so it "
            "cannot establish independent provenance." + "\n"
            "  To have ProofOS observe something itself, add an "
            "\"observations\" entry with a check of \"http\" or \"digest\"." + "\n")
        return EXIT_USAGE

    # One ledger for this run. The CLI grants itself an observation capability
    # for exactly the kinds it was asked to check, then seals -- so nothing
    # arriving later can widen what it may write.
    specs = data.get("observations") or ()
    if not isinstance(specs, (list, tuple)):
        return _usage(f"{args.evidence}: 'observations' must be a list")
    observed_kinds = tuple({str(s.get("kind")) for s in specs
                            if isinstance(s, dict) and s.get("kind")})

    ledger = EvidenceLedger()
    ledger.open_task(_VERIFY_TASK, tuple(requirements))
    collector = ObservationCapability(ledger, CLI_COLLECTOR, observed_kinds)
    ledger.seal()
    for item in evidence:
        ledger.record(_VERIFY_TASK, item, None)

    observed_at = args.now if args.now is not None else time.time()
    for index, spec in enumerate(specs):
        try:
            kind, value, satisfies = _observe(spec, index)
        except _VerifyUsage as exc:
            return _usage(f"{args.evidence}: {exc}")
        except _Unavailable as exc:
            # Nothing is recorded. A requirement with no observation is not
            # satisfied, and the operator is told why rather than meeting an
            # unexplained ABSTAIN.
            sys.stderr.write(f"proofos: could not observe {exc}" + "\n")
            continue
        collector.record_observation(_VERIFY_TASK, kind, value,
                                     satisfies=satisfies,
                                     collected_at=observed_at)

    try:
        decision = ProofOS().verify_recorded(ledger, _VERIFY_TASK, claim,
                                             now=args.now)
    except ProvenanceNotDeclarable as exc:
        sys.stderr.write(f"proofos: {args.evidence}: {exc}" + "\n")
        return EXIT_USAGE

    if args.json:
        json.dump({"schema_version": 1, **decision.as_dict()}, out, indent=2)
        out.write("\n")
    else:
        out.write(render(decision, _use_colour(out)) + "\n")
    return EXIT_VERIFIED if decision.verified else EXIT_ABSTAIN


# -- wiring --------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofos",
        description="Evidence-first verification for autonomous agents. "
                    "An agent claim is not proof.",
        epilog="Exit codes: 0 verified, 1 abstain, 2 usage, 3 operational.",
    )
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name, help_text, fn):
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.set_defaults(fn=fn)
        return p

    add("doctor", "Report what this installation can and cannot do.", cmd_doctor)
    init = add("init", "Add a ProofOS policy to this project.", cmd_init)
    init.add_argument("directory", nargs="?", default=".", help="project directory")
    init.add_argument("--dry-run", action="store_true", help="show what would be created")
    add("demo", "Watch a claim get refused, then verified by independent evidence.", cmd_demo)
    add("version", "Print version information.", cmd_version)

    verify = add("verify", "Verify a claim against evidence from a JSON file.", cmd_verify)
    verify.add_argument("evidence", help="path to a JSON file with claim, requirements, evidence")
    verify.add_argument("--policy", default=None,
                        help="policy file supplying the requirements (toml/yaml/json)")
    verify.add_argument("--now", type=float, default=None,
                        help="evaluate freshness at this unix time instead of now")
    return parser


def main(argv: Sequence[str] | None = None, out=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = out or sys.stdout

    if getattr(args, "version", False) and not args.command:
        out.write(f"proofos {VERSION}\n")
        return EXIT_VERIFIED
    if not args.command:
        parser.print_help(out)
        return EXIT_USAGE

    try:
        return args.fn(args, out)
    except SystemExit as exc:
        return int(exc.code or EXIT_USAGE)
    except Exception as exc:  # noqa: BLE001 - a crash must not read as success
        sys.stderr.write(f"proofos: {type(exc).__name__}: {exc}\n")
        return EXIT_OPERATIONAL


if __name__ == "__main__":
    raise SystemExit(main())
