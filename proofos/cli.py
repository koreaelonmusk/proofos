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
import json
import sys
import time
from typing import Sequence

from .api import Decision, ProofOS
from .verifier import Evidence, EvidenceSource, Requirement

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


#: The demo is a real verification, not a script that prints a story. Every
#: status below is produced by the kernel at the moment it is shown.
def cmd_demo(args, out) -> int:
    proof = ProofOS()
    now = time.time()
    requirements = [Requirement("runtime_health", max_age_seconds=300)]
    colour = _use_colour(out)

    self_report = Evidence(
        kind="runtime_health",
        value="deploy-agent states: the service is up",
        source=EvidenceSource.EXECUTOR,
        collected_at=now,
        collector="deploy-agent",
    )
    observation = Evidence(
        kind="runtime_health",
        value="probe HEALTHY: HTTP 200 in 12ms",
        source=EvidenceSource.OBSERVED,
        collected_at=now,
        collector="http-health-collector",
    )

    claimed = proof.verify("Deployment complete.", requirements, [self_report], now=now)
    resolved = proof.verify(
        "Deployment complete.", requirements, [self_report, observation], now=now
    )

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


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        raise SystemExit(_usage(f"no such file: {path}"))
    except json.JSONDecodeError as exc:
        raise SystemExit(_usage(f"{path} is not valid JSON: {exc}"))


def _usage(message: str) -> int:
    sys.stderr.write(f"proofos: {message}\n")
    return EXIT_USAGE


def cmd_verify(args, out) -> int:
    """Verify a claim against evidence supplied as JSON.

    Deliberately dumb about where the evidence came from. Provenance is a
    property of the evidence record, and the kernel decides what it is worth.
    """
    data = _load(args.evidence)
    try:
        requirements = [
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

    decision = ProofOS().verify(claim, requirements, evidence, now=args.now)

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
    add("demo", "Watch a claim get refused, then verified by independent evidence.", cmd_demo)
    add("version", "Print version information.", cmd_version)

    verify = add("verify", "Verify a claim against evidence from a JSON file.", cmd_verify)
    verify.add_argument("evidence", help="path to a JSON file with claim, requirements, evidence")
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
