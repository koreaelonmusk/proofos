"""Break one authority-critical line at a time, and require the right test to notice.

The chaos suite proves that hostile input does not gain authority. This proves
something different and harder: that the code which *withholds* that authority
is actually load-bearing. Delete a line, and a test must fail.

Two accounting refinements over the earlier phases, both earned:

**Three states, because a mutation that never applied is not a survivor.**
A harness that fails to edit anything sees the suite pass and reports the guard
as weak. That happened once, so the first thing after every substitution is a
check that the file really changed.

**Two kill locations, because failing is not the same as failing for the right
reason.** A mutation to the freshness rule that dies because a parser rejected
the input first has told you nothing about freshness. So each mutation names the
test that *should* catch it:

    KILLED_AT_TARGET    the named test failed. The defence is where it claims.
    KILLED_UPSTREAM     the named test passed; something else failed. The
                        mutation is caught, but not by the check it was aimed
                        at, and that gap is worth seeing.
    APPLIED_AND_SURVIVED  nothing failed. A defence with no test behind it.
    NOT_APPLIED         the anchor moved. Not a result.

Every authority-critical mutation should have a TARGET kill. An UPSTREAM kill is
reported rather than counted as one.

    python scripts/security_gate.py
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

KILLED_AT_TARGET = "KILLED_AT_TARGET"
KILLED_UPSTREAM = "KILLED_UPSTREAM"
SURVIVED = "APPLIED_AND_SURVIVED"
NOT_APPLIED = "NOT_APPLIED"

#: Run after the target test passes, to find out whether anything else noticed.
#: The security-relevant modules only -- the full suite would triple the runtime
#: and add nothing, since a mutation nothing here catches is already the finding.
BROAD = (
    "tests.test_verifier", "tests.test_authority", "tests.test_attestation",
    "tests.test_adapters", "tests.test_evidence_bridge", "tests.test_bundle",
    "tests.test_replay", "tests.test_replay_attestation", "tests.test_chaos",
    "tests.test_runtime_evidence", "tests.test_reporting_semantics",
)

#: (id, description, file, target test, find, replace)
MUTATIONS: tuple[tuple[str, str, str, str, str, str], ...] = (
    # -- A. the kernel verdict path -------------------------------------------
    ("K1", "insufficient evidence still verifies",
     "proofos/verifier.py", "tests.test_verifier",
     "    if unsatisfied:\n        distinct = set(failures)",
     "    if False:\n        distinct = set(failures)"),
    ("K2", "untrusted provenance is accepted",
     "proofos/verifier.py", "tests.test_verifier",
     "    trusted = [item for item in matching if item.source in TRUSTED_SOURCES]",
     "    trusted = list(matching)"),
    ("K3", "the freshness horizon stops applying",
     "proofos/verifier.py", "tests.test_verifier",
     "    if requirement.max_age_seconds is not None:",
     "    if False:"),
    ("K4", "evidence of the wrong kind satisfies a requirement",
     "proofos/verifier.py", "tests.test_verifier",
     "    matching = [item for item in items if item.kind.strip() == requirement.kind]",
     "    matching = list(items)"),
    ("K5", "one satisfied requirement carries the rest",
     "proofos/verifier.py", "tests.test_verifier",
     "    if unsatisfied:\n        distinct = set(failures)",
     "    if len(unsatisfied) == len(requirements):\n        distinct = set(failures)"),
    ("K6", "rejected evidence is reported as accepted",
     "proofos/verifier.py", "tests.test_reporting_semantics",
     "        accepted = id(item) in accepted_ids and _integrity_valid(item)",
     "        accepted = True"),
    ("K7", "a tampered record no longer fails the set closed",
     "proofos/verifier.py", "tests.test_verifier",
     "    if any(not item.intact for item in items):",
     "    if False:"),
    # Retargeted: the first version routed through "if False else _abstain(",
    # which is the original behaviour written at greater length -- an inert
    # mutation reported as a survivor until the anchor was checked.
    ("K8", "a crashing verifier is read as success",
     "proofos/verifier.py", "tests.test_verifier",
     '        return _abstain(\n            f"Verifier failed with an unexpected error: {type(exc).__name__}.",\n            FailureClass.VERIFIER_FAILURE,\n        )',
     '        return VerificationResult(\n            status=VerificationStatus.VERIFIED,\n            reason=f"swallowed {type(exc).__name__}")'),

    # -- B. the ingestion path, one gate at a time ----------------------------
    ("I1", "collector identity is not checked against the registry",
     "proofos/ingestion.py", "tests.test_attestation",
     "            record = self._collectors.require_scope(\n"
     "                attestation.collector_id, attestation.kind, attestation.profile_id\n"
     "            )",
     "            record = self._collectors.get(attestation.collector_id)"),
    ("I2", "the signature is not verified",
     "proofos/ingestion.py", "tests.test_attestation",
     "            record.verifier.verify(attestation)",
     "            pass"),
    ("I3", "execution binding is dropped",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if attestation.execution_id != execution_id:",
     "        if False:"),
    ("I4", "task binding is dropped",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if attestation.task_id != task_id:",
     "        if False:"),
    ("I5", "kind binding is dropped",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if attestation.kind != expected_kind:",
     "        if False:"),
    ("I6", "profile binding is dropped",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if attestation.profile_id != expected_profile:",
     "        if False:"),
    ("I7", "the answered-request binding is dropped",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if attestation.request_nonce != expected_nonce:",
     "        if False:"),
    ("I8", "a future-dated observation is accepted",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if attestation.observed_at > now + CLOCK_SKEW_TOLERANCE_SECONDS:",
     "        if False:"),
    ("I9", "stale attestations are accepted",
     "proofos/ingestion.py", "tests.test_attestation",
     "            and attestation.observed_at < now - max_age_seconds",
     "            and False"),
    ("I10", "a spent nonce accepts a different attestation",
     "proofos/ingestion.py", "tests.test_attestation",
     "            raise AttestationRejected(\n"
     "                RejectionReason.NONCE_REUSED,",
     "            return True\n"
     "            raise AttestationRejected(\n"
     "                RejectionReason.NONCE_REUSED,"),
    ("I11", "a nonce this runtime never issued is accepted",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if record is None:\n            raise AttestationRejected(",
     "        if False:\n            raise AttestationRejected("),
    ("I12", "an unknown collector still reaches a capability",
     "proofos/ingestion.py", "tests.test_attestation",
     "        if capability is None:",
     "        if False:"),

    # -- C. ledger and capability authority -----------------------------------
    ("L1", "OBSERVED is admitted without any grant",
     "proofos/ledger.py", "tests.test_authority",
     "        if evidence.source is EvidenceSource.OBSERVED:\n"
     "            self._check_grant(evidence, grant)",
     "        if False:\n            self._check_grant(evidence, grant)"),
    ("L2", "a grant covering another kind is accepted",
     "proofos/ledger.py", "tests.test_authority",
     "        if evidence.kind not in grant.kinds:",
     "        if False:"),
    ("L3", "a grant issued by another ledger is accepted",
     "proofos/ledger.py", "tests.test_authority",
     '        if getattr(grant, "_issuer", None) is not self._marker:',
     "        if False:"),
    ("L4", "a collector writes under another identity",
     "proofos/ledger.py", "tests.test_authority",
     "        if evidence.collector != grant.collector_id:",
     "        if False:"),
    ("L5", "a missing grant is treated as permission",
     "proofos/ledger.py", "tests.test_authority",
     "        if grant is None:\n            raise CapabilityDenied(",
     "        if False:\n            raise CapabilityDenied("),
    ("L6", "grants can still be minted after sealing",
     "proofos/ledger.py", "tests.test_authority",
     "        if self._sealed:\n            raise CapabilityDenied(",
     "        if False:\n            raise CapabilityDenied("),
    ("L7", "a mutated stored record is served as intact",
     "proofos/ledger.py", "tests.test_authority",
     "            if not item.intact:",
     "            if False:"),
    ("L8", "a capability writes a provenance it was not given",
     "proofos/capabilities.py", "tests.test_authority",
     "            source=EvidenceSource.OBSERVED,\n"
     "            valid=satisfies,",
     "            source=EvidenceSource.OBSERVED,\n"
     "            valid=True,"),

    # -- D. the replay and attestation boundary -------------------------------
    ("R1", "the recorded verdict drives replay",
     "proofos/replay.py", "tests.test_replay",
     "    decision = ProofOS().verify_recorded(ledger, bundle.task_id, bundle.claim,\n"
     "                                         now=now)",
     "    decision = ProofOS().verify_recorded(ledger, bundle.task_id, bundle.claim,\n"
     "                                         now=now)\n"
     "    if bundle.recorded_verdict == 'VERIFIED' and bundle.evidence:\n"
     "        from dataclasses import replace as _r\n"
     "        from .verifier import VerificationStatus as _S\n"
     "        decision = _r(decision, status=_S.VERIFIED)"),
    ("R2", "a failed attestation falls back to the weak trust path",
     "proofos/replay.py", "tests.test_replay_attestation",
     "        if record.attestation:",
     "        if record.attestation and record.collector not in trusted:"),
    # Retargeted: stripping only `public_key` left a second unknown field
    # in the test's envelope, so the strict parse refused it either way and
    # the mutation changed nothing. A lenient parse is how such a field
    # would come to exist in the first place.
    ("R3", "a key carried in the bundle becomes the trust root",
     "proofos/portable_attestation.py", "tests.test_replay_attestation",
     '    try:\n        attestation = attestation_module.ObservationAttestation.from_dict(envelope)',
     '    if isinstance(envelope, Mapping):\n        _known = set(attestation_module.ENVELOPE_FIELDS)\n        envelope = {k: v for k, v in envelope.items() if k in _known}\n    try:\n        attestation = attestation_module.ObservationAttestation.from_dict(envelope)'),
    ("R4", "a valid signature implies authorization",
     "proofos/portable_attestation.py", "tests.test_replay_attestation",
     "        record = registry.require_scope(attestation.collector_id, attestation.kind,\n"
     "                                        attestation.profile_id)",
     "        record = registry.get(attestation.collector_id)"),
    ("R5", "replay manufactures an observation",
     "proofos/replay.py", "tests.test_replay_attestation",
     "            refusal = _attestation_refusal(record, bundle, trust_anchor, now)",
     "            refusal = ''"),
    ("R6", "sealed evidence never goes stale",
     "proofos/replay.py", "tests.test_replay",
     "        Requirement(kind=r.kind, max_age_seconds=r.max_age_seconds)",
     "        Requirement(kind=r.kind, max_age_seconds=None)"),
    ("R7", "the bundle digest stops covering the evidence",
     "proofos/bundle.py", "tests.test_bundle",
     '            "evidence": [e.as_dict() for e in self.evidence],',
     '            "evidence": [],'),
    ("R8", "the export secret scan is skipped",
     "proofos/bundle.py", "tests.test_bundle",
     "    refuse_sensitive_content(draft)",
     "    pass"),

    # -- V. the CLI input boundary --------------------------------------------
    ("V1", "the CLI drops a condition the user asked for",
     "proofos/cli.py", "tests.test_verify_exit_contract",
     '    unknown = sorted(set(spec) - allowed)\n    if unknown:',
     '    unknown = sorted(set(spec) - allowed)\n    if unknown and False:'),

    ("V2", "the CLI drops a condition stated outside an observation",
     "proofos/cli.py", "tests.test_verify_exit_contract",
     '    unknown = sorted(set(obj) - allowed)\n    if unknown:',
     '    unknown = sorted(set(obj) - allowed)\n    if unknown and False:'),

    # -- E. the aggregation that reports all of the above ----------------------
    ("G1", "a gate that never ran counts as green",
     "scripts/release_gate.py", "tests.test_release_gate",
     "    return 1 if failed or skipped else 0",
     "    return 1 if failed else 0"),
    ("G2", "one failing gate is lost in the summary",
     "scripts/release_gate.py", "tests.test_release_gate",
     "    failed = [r for r in results if r.passed is False]\n"
     "    skipped = [r for r in results if r.passed is None]\n"
     "    return 1 if failed or skipped else 0",
     "    failed = [r for r in results if r.passed is False]\n"
     "    skipped = [r for r in results if r.passed is None]\n"
     "    return 0 if len(failed) < len(results) else 1"),
    ("G3", "an unavailable gate reports itself as passing",
     "scripts/release_gate.py", "tests.test_release_gate",
     "        self.passed, self.detail = None, [f\"could not run: {why}\"]",
     "        self.passed, self.detail = True, [f\"could not run: {why}\"]"),
)


def unittest_ok(*targets: str) -> bool:
    run = subprocess.run([sys.executable, "-m", "unittest", *targets],
                         cwd=str(ROOT), capture_output=True, text=True)
    if "_FailedTest" in run.stderr or "ModuleNotFoundError" in run.stderr:
        raise LookupError(run.stderr.strip().splitlines()[-1][:120])
    return run.returncode == 0


def working_tree_is_clean() -> tuple[bool, str]:
    """Refuse to start on a tree this harness may already have damaged.

    Learned the hard way: a run killed by an external timeout never reached its
    `finally`, and left a mutation in proofos/replay.py. The next gate run
    reported on poisoned source and looked like a catastrophic regression. A
    mutation harness that can leave the tree dirty must at least refuse to run
    on a dirty one.
    """
    # Only the files this run will actually mutate. Guarding all of proofos/
    # and scripts/ would refuse to run beside any unrelated edit, and a gate
    # that is inconvenient during development is a gate that gets skipped.
    targets = sorted({relative for _, _, relative, *_ in MUTATIONS})
    dirty = subprocess.run(["git", "status", "--porcelain", "--", *targets],
                           cwd=str(ROOT), capture_output=True,
                           text=True).stdout.strip()
    return (not dirty), dirty


def apply(identifier: str, description: str, relative: str, target: str,
          find: str, replace: str) -> tuple[str, str]:
    path = ROOT / relative
    if not path.exists():
        return NOT_APPLIED, f"{relative} does not exist"
    original = path.read_bytes()
    crlf = b"\r\n" in original
    decoded = original.decode("utf-8").replace("\r\n", "\n")
    if find not in decoded:
        return NOT_APPLIED, f"the anchor is not in {relative}"
    mutated = decoded.replace(find, replace, 1)
    if mutated == decoded:
        return NOT_APPLIED, "the substitution was a no-op"
    if crlf:
        mutated = mutated.replace("\n", "\r\n")

    # A sidecar copy, so a run killed between the write and the restore leaves
    # an obvious artefact and an automatic repair rather than silent damage.
    sidecar = path.with_suffix(path.suffix + ".mutation-backup")
    # Any bytecode compiled from the mutated source has to go with it. A
    # mutation that leaves the byte count unchanged -- None to True, say -- and
    # a cycle that completes inside one second produce a cached .pyc that
    # matches the *restored* source on both mtime and size. Python then treats
    # it as current and later runs mutated bytecode against clean source.
    caches = [c for c in ROOT.rglob("__pycache__") if c.is_dir()]

    try:
        sidecar.write_bytes(original)
        path.write_bytes(mutated.encode("utf-8"))
        if path.read_bytes() == original:
            return NOT_APPLIED, "the write did not take"
        try:
            if not unittest_ok(target):
                return KILLED_AT_TARGET, target
            if not unittest_ok(*BROAD):
                return KILLED_UPSTREAM, f"{target} passed; something else failed"
        except LookupError as exc:
            return NOT_APPLIED, f"could not load a test: {exc}"
        return SURVIVED, "nothing failed"
    finally:
        path.write_bytes(original)
        sidecar.unlink(missing_ok=True)
        stem = path.stem
        for cache in caches:
            for compiled in cache.glob(f"{stem}.*.pyc"):
                compiled.unlink(missing_ok=True)


def repair_from_sidecars() -> list[str]:
    """Undo a run that was killed before it could restore."""
    repaired = []
    for sidecar in sorted(ROOT.rglob("*.mutation-backup")):
        target = sidecar.with_suffix("")
        target.write_bytes(sidecar.read_bytes())
        sidecar.unlink()
        repaired.append(str(target.relative_to(ROOT)))
    return repaired


def main() -> int:
    repaired = repair_from_sidecars()
    if repaired:
        print(f"  repaired {len(repaired)} file(s) left mutated by an "
              f"interrupted run: {repaired}\n")

    clean, dirty = working_tree_is_clean()
    if not clean:
        print("security gate  NOT RUN")
        print("  the working tree under proofos/ and scripts/ is not clean:")
        for line in dirty.splitlines():
            print(f"    {line}")
        print("  This harness mutates source in place. Running it over "
              "uncommitted changes would report on a tree nobody can "
              "reconstruct, and a run killed midway would lose them.")
        return 2

    print(f"security gate  ({len(MUTATIONS)} authority-critical mutations)")
    print("break one line; require the test that claims to defend it to fail\n")

    results = []
    width = max(len(d) for _, d, *_ in MUTATIONS)
    group = ""
    for identifier, description, relative, target, find, replace in MUTATIONS:
        if identifier[0] != group:
            group = identifier[0]
            print()
        state, detail = apply(identifier, description, relative, target, find,
                              replace)
        results.append((identifier, state))
        print(f"  {identifier:<4} {description:<{width}}  {state:<20} {detail}")

    at_target = [r for r in results if r[1] == KILLED_AT_TARGET]
    upstream = [r for r in results if r[1] == KILLED_UPSTREAM]
    survived = [r for r in results if r[1] == SURVIVED]
    unapplied = [r for r in results if r[1] == NOT_APPLIED]

    print()
    print(f"  applied {len(results) - len(unapplied)}/{len(results)}"
          f"   killed at target {len(at_target)}"
          f"   killed upstream {len(upstream)}"
          f"   survived {len(survived)}"
          f"   not applied {len(unapplied)}")
    if upstream:
        print(f"  UPSTREAM kills, reported not counted: {[r[0] for r in upstream]}")
        print("  The defence held, but not where it claims to be. Worth a test "
              "at the target.")
    if survived:
        print(f"  SURVIVED: {[r[0] for r in survived]}")
        print("  A line that withholds authority with no test behind it.")
    if unapplied:
        print(f"  NOT_APPLIED: {[r[0] for r in unapplied]}")
        print("  A harness defect, excluded from the score rather than counted "
              "as a pass.")
    return 0 if not (survived or unapplied or upstream) else 1


if __name__ == "__main__":
    raise SystemExit(main())
