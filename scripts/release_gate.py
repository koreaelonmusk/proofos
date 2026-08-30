"""Release gates that run, on the machine you are standing on.

A CI configuration is a claim. It says a check happens; it is not the check
happening, and a workflow file that has never been executed asserts exactly as
confidently as one that has. So every gate here is a function anybody can run
locally, and the workflow is a thin caller. If the workflow disappeared, the
gates would still be checkable; if the gates lived only inside YAML, they would
be checkable only by pushing.

Each gate returns a verdict and its evidence, and the runner prints both. A gate
that cannot run says so -- it does not pass by default, because "the check did
not happen" and "the check passed" are the distinction this whole project is
about.

    python scripts/release_gate.py all
    python scripts/release_gate.py wheel install deps secrets suite

Gates:

    wheel     build a wheel; assert what is in it and what is not; hash it
    install   install that wheel into a fresh venv with no extras; import; run the CLI
    deps      runtime dependencies are zero and the extras are the declared ones
    secrets   scan every tracked file for credentials, with a narrow, reasoned allowlist
    suite     the full test suite, plus: the suite must leave the tree clean
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time
import tomllib
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Modules that must reach an installed user. Not a full inventory -- the ones a
#: packaging mistake would plausibly drop, because they arrived late and are not
#: imported by the root package.
MUST_SHIP = (
    "proofos/__init__.py", "proofos/verifier.py", "proofos/ledger.py",
    "proofos/capabilities.py", "proofos/ingestion.py", "proofos/attestation.py",
    "proofos/collector_registry.py", "proofos/integrity.py", "proofos/journal.py",
    "proofos/api.py", "proofos/cli.py", "proofos/policy.py", "proofos/plugins.py",
    "proofos/conformance.py", "proofos/skills.py",
    "proofos/adapters.py", "proofos/adapter.py", "proofos/evidence_bridge.py",
    "proofos/github.py", "proofos/mcp.py", "proofos/a2a.py", "proofos/adk.py",
    "proofos/bundle.py", "proofos/replay.py", "proofos/portable_attestation.py",
    "proofos/py.typed",
)

#: Directory prefixes that must never be inside a wheel. Tests are how the
#: project argues with itself and examples are illustrations; neither is part of
#: what a user installs, and shipping them makes the package's own surface
#: ambiguous.
MUST_NOT_SHIP = ("tests/", "examples/", "scripts/", "artifacts/", "web/",
                 "docs/", ".github/")

#: Credential shapes. Narrow on purpose: a scanner that fires on ordinary source
#: is a scanner somebody turns off, and a scanner that is off protects nothing.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("openai-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("gcp service account", re.compile(r'"type"\s*:\s*"service_account"')),
    ("json web token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("inline credential", re.compile(
        r"(?i)\b(?:api[_\-]?key|client[_\-]?secret|password|passwd)\s*[=:]\s*"
        r"['\"][^'\"]{8,}['\"]")),
)

#: Permitted credential-shaped strings, keyed by (path, pattern) rather than by
#: path. Allowlisting a whole file would mean a real AWS key pasted into
#: ``keys.py`` tomorrow is covered by an entry written today about a PEM header
#: in a docstring. Each entry carries its reason and the runner prints all of
#: them: an allowlist is itself a claim, and a reviewer should be able to
#: disagree with it line by line.
SECRET_ALLOWLIST: dict[tuple[str, str], str] = {
    ("proofos/keys.py", "private key block"):
        "the PEM header quoted in the module docstring, documenting the format "
        "a collector private key file takes -- not key material",
    ("tests/test_journal.py", "inline credential"):
        "a placeholder credential passed to a journal event so a redaction test "
        "can assert the key is dropped. Described rather than quoted here: an "
        "exemption avoided is better than an exemption granted",
    ("tests/test_bundle.py", "private key block"):
        "synthetic credentials proving that bundle export refuses to carry any "
        "of these; the corpus is the test",
    ("tests/test_bundle.py", "aws access key"): "same corpus",
    ("tests/test_bundle.py", "openai-style key"): "same corpus",
    ("tests/test_bundle.py", "github token"): "same corpus",
    ("tests/test_bundle.py", "slack token"): "same corpus",
    ("tests/test_bundle.py", "google api key"): "same corpus",
    ("tests/test_bundle.py", "json web token"): "same corpus",
    ("tests/test_bundle.py", "bearer token"): "same corpus",
    ("tests/test_bundle_attestation.py", "private key block"):
        "a fake PEM used to prove a private key cannot enter a bundle",
}


class GateResult:
    def __init__(self, name: str) -> None:
        self.name = name
        self.passed: bool | None = None
        self.detail: list[str] = []

    def ok(self, *lines: str) -> "GateResult":
        self.passed, self.detail = True, list(lines)
        return self

    def fail(self, *lines: str) -> "GateResult":
        self.passed, self.detail = False, list(lines)
        return self

    def unavailable(self, why: str) -> "GateResult":
        # Deliberately not a pass. A check that did not happen has established
        # nothing, and recording it as green is how a suite comes to mean less
        # than it claims.
        self.passed, self.detail = None, [f"could not run: {why}"]
        return self


def run(*args: str, cwd: pathlib.Path | None = None,
        env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(cwd or ROOT), capture_output=True,
                          text=True, env=env)


def tracked_files() -> list[pathlib.Path]:
    out = run("git", "ls-files").stdout.splitlines()
    return [ROOT / line for line in out if line]


# -- gates --------------------------------------------------------------------

def gate_wheel(state: dict) -> GateResult:
    """Build a wheel and assert its contents, twice, and hash it."""
    result = GateResult("wheel")
    dist = ROOT / "dist"
    shutil.rmtree(dist, ignore_errors=True)
    shutil.rmtree(ROOT / "build", ignore_errors=True)

    # A fixed epoch so two builds of the same tree are comparable. Without it
    # zip timestamps differ and the only reproducibility on offer is "the file
    # names match", which is not much of a claim.
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000",
           "PYTHONHASHSEED": "0"}
    build = run(sys.executable, "-m", "build", "--wheel", env=env)
    if build.returncode != 0:
        return result.fail("build failed", build.stderr.strip()[-500:])

    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        return result.fail(f"expected exactly one wheel, found {len(wheels)}")
    wheel = wheels[0]
    names = set(zipfile.ZipFile(wheel).namelist())
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()

    missing = [m for m in MUST_SHIP if m not in names]
    shipped = sorted(n for n in names
                     if any(n.startswith(p) for p in MUST_NOT_SHIP))
    if missing:
        return result.fail(f"the wheel is missing {len(missing)} module(s):",
                           *(f"    {m}" for m in missing))
    if shipped:
        return result.fail(f"the wheel ships {len(shipped)} path(s) it must not:",
                           *(f"    {n}" for n in shipped[:10]))

    # Build again and compare. Same tree, same epoch, same bytes -- or say so.
    first = wheel.read_bytes()
    shutil.rmtree(dist, ignore_errors=True)
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    run(sys.executable, "-m", "build", "--wheel", env=env)
    second_path = sorted(dist.glob("*.whl"))[0]
    reproducible = hashlib.sha256(second_path.read_bytes()).hexdigest() == digest
    state["wheel"] = second_path

    return result.ok(
        f"wheel            {wheel.name}",
        f"sha256           {digest}",
        f"entries          {len(names)}",
        f"required modules {len(MUST_SHIP)}/{len(MUST_SHIP)} present",
        f"excluded paths   none of {', '.join(p.rstrip('/') for p in MUST_NOT_SHIP)}",
        f"reproducible     {'yes, byte-identical across two builds' if reproducible else 'NO -- two builds of the same tree differ'}",
    )


def gate_install(state: dict) -> GateResult:
    """Install into a fresh interpreter with no extras, then use it."""
    result = GateResult("install")
    wheel = state.get("wheel")
    if wheel is None or not wheel.exists():
        return result.unavailable("no wheel; run the wheel gate first")

    with tempfile.TemporaryDirectory(prefix="proofos-gate-") as tmp:
        venv = pathlib.Path(tmp) / "venv"
        made = run(sys.executable, "-m", "venv", str(venv))
        if made.returncode != 0:
            return result.unavailable(f"venv creation failed: {made.stderr[-300:]}")
        scripts = "Scripts" if os.name == "nt" else "bin"
        exe = ".exe" if os.name == "nt" else ""
        python = venv / scripts / f"python{exe}"
        cli = venv / scripts / f"proofos{exe}"

        installed = run(str(python), "-m", "pip", "install", "-q", str(wheel))
        if installed.returncode != 0:
            return result.fail("wheel install failed", installed.stderr[-500:])

        frozen = run(str(python), "-m", "pip", "list", "--format=freeze").stdout
        packages = sorted(line.split("==")[0].lower() for line in frozen.splitlines()
                          if line and line.split("==")[0].lower()
                          not in ("pip", "setuptools", "wheel"))
        if packages != ["proofos"]:
            return result.fail(
                "installing the core package pulled in more than itself",
                f"    {packages}")

        probe = (
            "import proofos, proofos.bundle, proofos.replay, proofos.a2a, "
            "proofos.adk, proofos.mcp, proofos.github, proofos.adapters, "
            "proofos.adapter, proofos.evidence_bridge, proofos.portable_attestation\n"
            "import sys\n"
            "assert not any(m.startswith('cryptography') for m in sys.modules), "
            "'a zero-dependency install imported cryptography'\n"
            "print(len(proofos.__all__))\n"
        )
        imported = run(str(python), "-c", probe)
        if imported.returncode != 0:
            return result.fail("import failed in a clean install",
                               imported.stderr.strip()[-500:])
        exported = imported.stdout.strip()

        smoke = {}
        for command in ("--help", "doctor", "demo"):
            smoke[command] = run(str(cli), command).returncode
        broken = [c for c, code in smoke.items() if code != 0]
        if broken:
            return result.fail(f"CLI commands exited non-zero: {broken}")

        return result.ok(
            f"fresh venv       {sys.version.split()[0]} on {sysconfig.get_platform()}",
            f"installed        {packages}",
            f"imports          11 modules, cryptography absent",
            f"root __all__     {exported}",
            f"cli              {' '.join(f'{c}=0' for c in smoke)}",
        )


def gate_deps(state: dict) -> GateResult:
    """The core package depends on nothing, and the extras are the declared set."""
    result = GateResult("deps")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    runtime = project.get("dependencies") or []
    extras = project.get("optional-dependencies") or {}
    expected_extras = {"attestation", "dev", "google", "service"}

    if runtime:
        return result.fail(f"the core package declares {len(runtime)} runtime "
                           f"dependency/ies: {runtime}")
    if set(extras) != expected_extras:
        return result.fail(
            f"extras changed: {sorted(set(extras) ^ expected_extras)} "
            f"differs from the declared set")

    return result.ok(
        f"runtime deps     0",
        f"requires-python  {project.get('requires-python')}",
        f"extras           {', '.join(sorted(extras))}",
        *(f"  {name:<12} {', '.join(extras[name])}" for name in sorted(extras)),
    )


def gate_secrets(state: dict) -> GateResult:
    """Scan every tracked file. An allowlist entry needs a reason, printed."""
    result = GateResult("secrets")
    files = tracked_files()
    if not files:
        return result.unavailable("git ls-files returned nothing")

    unexplained: list[str] = []
    allowed: dict[tuple[str, str], int] = {}
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in SECRET_PATTERNS:
            # Every occurrence, not just the first: a file with one allowlisted
            # match and one real one further down would otherwise hide the real
            # one behind the entry written for the other.
            for match in pattern.finditer(text):
                key = (relative, label)
                if key in SECRET_ALLOWLIST:
                    allowed[key] = allowed.get(key, 0) + 1
                else:
                    line = text[:match.start()].count("\n") + 1
                    unexplained.append(f"{relative}:{line}  {label}")

    if unexplained:
        return result.fail(f"{len(unexplained)} credential-shaped string(s) with "
                           f"no allowlist entry:", *(f"    {e}" for e in unexplained))

    lines = [f"scanned          {len(files)} tracked files",
             f"patterns         {len(SECRET_PATTERNS)}",
             f"unexplained      0"]
    if allowed:
        total = sum(allowed.values())
        lines.append(f"allowlisted      {total} match(es) in "
                     f"{len({p for p, _ in allowed})} file(s), each with a reason:")
        for (relative, label), count in sorted(allowed.items()):
            lines.append(f"    {relative}  [{label}] x{count}")
            lines.append(f"        {SECRET_ALLOWLIST[(relative, label)]}")
    unused = sorted(set(SECRET_ALLOWLIST) - set(allowed))
    if unused:
        # An allowlist entry that matches nothing is an exemption nobody needs,
        # and the next person reads it as evidence that something is there.
        #
        # One caveat, learned the hard way: this scan covers *tracked* files, so
        # an entry naming a file that is not yet committed will report as stale
        # and stop being stale the moment it is added. Check that before
        # deleting one.
        lines.append(f"stale entries    {len(unused)} allowlist entr(ies) match "
                     f"nothing in the tracked set:")
        lines += [f"    {p}  [{label}]" for p, label in unused]
    return result.ok(*lines)


def gate_suite(state: dict) -> GateResult:
    """Run everything, and require that running it changed nothing."""
    result = GateResult("suite")
    before = run("git", "status", "--porcelain").stdout
    started = time.monotonic()
    tests = run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".")
    elapsed = time.monotonic() - started
    tail = tests.stderr.strip().splitlines()[-3:]
    ran = next((line for line in tail if line.startswith("Ran ")), "?")

    if tests.returncode != 0:
        return result.fail(f"suite failed after {elapsed:.0f}s", *tail)

    after = run("git", "status", "--porcelain").stdout
    if after != before:
        changed = [l for l in after.splitlines() if l not in before.splitlines()]
        return result.fail(
            "the suite left the working tree modified. A test that writes into "
            "the repository makes the next run depend on this one:",
            *(f"    {c}" for c in changed))

    return result.ok(f"{ran} in {elapsed:.0f}s",
                     "working tree unchanged by the run")


GATES = {"wheel": gate_wheel, "install": gate_install, "deps": gate_deps,
         "secrets": gate_secrets, "suite": gate_suite}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("gates", nargs="*", default=["all"],
                        help=f"one or more of: all, {', '.join(GATES)}")
    chosen = parser.parse_args().gates
    if "all" in chosen:
        chosen = list(GATES)
    unknown = [g for g in chosen if g not in GATES]
    if unknown:
        print(f"unknown gate(s): {unknown}")
        return 2

    print(f"release gates  ({sys.version.split()[0]} on {sysconfig.get_platform()})")
    print(f"tree           {run('git', 'rev-parse', 'HEAD').stdout.strip()}")
    print()

    state: dict = {}
    results = []
    for name in chosen:
        outcome = GATES[name](state)
        results.append(outcome)
        mark = {True: "PASS", False: "FAIL", None: "NOT RUN"}[outcome.passed]
        print(f"  {name:<10} {mark}")
        for line in outcome.detail:
            print(f"      {line}")
        print()

    shutil.rmtree(ROOT / "dist", ignore_errors=True)
    shutil.rmtree(ROOT / "build", ignore_errors=True)

    failed = [r.name for r in results if r.passed is False]
    skipped = [r.name for r in results if r.passed is None]
    print(f"  {len(results) - len(failed) - len(skipped)}/{len(results)} passed"
          + (f", {len(failed)} failed: {failed}" if failed else "")
          + (f", {len(skipped)} not run: {skipped}" if skipped else ""))
    # A gate that did not run is not a gate that passed.
    return 1 if failed or skipped else 0


if __name__ == "__main__":
    raise SystemExit(main())
