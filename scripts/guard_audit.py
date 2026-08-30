"""Watch each structural guard fail, or stop believing it is a guard.

A test that asserts something cannot happen is only as good as its ability to
notice when it does. That sounds obvious and it is not: one of these guards
spent an afternoon inert because its word boundaries had been saved as literal
backspace bytes, so its pattern was "\\x08DENIED\\x08" and matched nothing. It
read correctly in an editor. It read correctly in inspect.getsource. The suite
was green, and the check was not happening.

Ordinary tests do not have this problem, because a test of behaviour fails the
moment the behaviour is wrong. A *structural* guard -- one that parses a source
file and asserts an absence -- passes just as happily when it is broken as when
the property holds. The two states look identical from outside.

So: plant the violation each guard exists to catch, run that guard alone, and
require it to fail. Three outcomes, and the middle one is the finding:

    GUARD_FIRED       the violation was planted and the guard failed. Good.
    GUARD_INERT       the violation was planted and the guard passed anyway.
    NOT_PLANTED       the harness could not apply the violation. Not a result.

Every file is restored, including after a crash. Run it against a clean tree.

    python scripts/guard_audit.py
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

GUARD_FIRED = "GUARD_FIRED"
GUARD_INERT = "GUARD_INERT"
NOT_PLANTED = "NOT_PLANTED"

#: (label, test id, file, text to find, text to replace it with)
#:
#: Each violation is the smallest edit that makes the guarded property false.
#: If a guard's test id or its file moves, this reports NOT_PLANTED rather than
#: quietly auditing nothing.
GUARDS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "docs name no invented verdict",
        "tests.test_documentation.TheVocabularyMatchesTheCodeTests"
        ".test_the_documented_verdicts_are_the_code_verdicts",
        "docs/trust-boundary.md",
        "## Transport authority matrix",
        "## Transport authority matrix\n\nThe verifier returned DENIED.\n",
    ),
    (
        "transport matrix claims no authority",
        "tests.test_documentation.TheTransportMatrixIsCompleteTests"
        ".test_no_transport_is_documented_as_verifying",
        "docs/trust-boundary.md",
        "| MCP (`proofos.mcp`) | yes | yes | no | no | no | no | no | no |",
        "| MCP (`proofos.mcp`) | yes | yes | no | no | no | yes | no | no |",
    ),
    (
        "docs assert no dangerous claim",
        "tests.test_documentation.DocumentationGrantsNoAuthorityTests"
        ".test_no_normative_document_asserts_a_dangerous_claim",
        "docs/attestations.md",
        "## The trust root comes from outside",
        "Signed evidence is trusted.\n\n## The trust root comes from outside",
    ),
    (
        "documented python support matches the package",
        "tests.test_documentation.TheStatedFactsMatchTheProjectTests"
        ".test_the_documented_python_support_matches_pyproject",
        ".github/workflows/release-gate.yml",
        'python: ["3.11", "3.12"]',
        'python: ["3.11", "3.12", "3.13"]',
    ),
    (
        "no sender key reaches metadata top level",
        "tests.test_adapters.CanonicalSenderMetadataTests"
        ".test_no_sender_controlled_key_reaches_the_metadata_top_level",
        "proofos/adapters.py",
        "    return {CLAIMED_NAMESPACE: claims} if claims else {}",
        "    if claims:\n"
        "        return {CLAIMED_NAMESPACE: claims, 'source': claims.get('source')}\n"
        "    return {}",
    ),
    (
        "replay names no independent provenance",
        "tests.test_replay_attestation.ReplayNamesNoProvenanceTests"
        ".test_replay_never_writes_an_independent_provenance_by_hand",
        "proofos/replay.py",
        "    trusted = frozenset(str(name) for name in trusted_collectors if str(name))",
        "    _unused = 'OBSERVED'\n"
        "    trusted = frozenset(str(name) for name in trusted_collectors if str(name))",
    ),
    (
        "mcp invents no bare trust key",
        "tests.test_mcp.TheAdapterCarriesNoAuthorityTests"
        ".test_this_module_invents_no_bare_trust_key",
        "proofos/mcp.py",
        '            extra={"surface": str(McpSurface.TOOL_RESULT),',
        '            extra={"verdict": "pass",\n'
        '                   "surface": str(McpSurface.TOOL_RESULT),',
    ),
    (
        "the bundle serializer cannot construct evidence",
        "tests.test_bundle.ThisModuleCannotCreateEvidenceTests"
        ".test_it_never_imports_or_constructs_evidence",
        "proofos/bundle.py",
        "from .integrity import canonical_payload, content_hash",
        "from .integrity import canonical_payload, content_hash\n"
        "from .verifier import Evidence  # noqa: F401",
    ),
    (
        "a2a has no route from a state to a verdict",
        "tests.test_a2a.AStateIsNotAVerdictTests"
        ".test_this_module_contains_no_route_from_a_state_to_a_verdict",
        "proofos/a2a.py",
        "#: Bumped when the shapes this module reads change incompatibly.\nA2A_SCHEMA = 1",
        "#: Bumped when the shapes this module reads change incompatibly.\n"
        "A2A_SCHEMA = 1\n_OUTCOME = 'VERIFIED'",
    ),
    (
        "adk branches on no callback name",
        "tests.test_adk.ACallbackIsAPlaceNotAWitnessTests"
        ".test_this_module_branches_on_no_callback_name",
        "proofos/adk.py",
        "#: Bumped when the shapes this module reads change incompatibly.\nADK_SCHEMA = 1",
        "#: Bumped when the shapes this module reads change incompatibly.\n"
        "ADK_SCHEMA = 1\nFINAL_CALLBACKS = ('after_agent_callback',)",
    ),
    (
        "no evidence bridge reaches OBSERVED",
        "tests.test_evidence_bridge.D_BridgeNeverEmitsObservedTests"
        ".test_the_bridge_source_never_names_observed",
        "proofos/evidence_bridge.py",
        "from .verifier import Evidence, EvidenceSource",
        "from .verifier import Evidence, EvidenceSource\n_S = EvidenceSource.OBSERVED",
    ),
)


def audit(label: str, test_id: str, relative: str, find: str,
          replace: str) -> tuple[str, str]:
    path = ROOT / relative
    if not path.exists():
        return NOT_PLANTED, f"{relative} does not exist"
    # Bytes, not text. read_text/write_text translate newlines, so on Windows a
    # restore rewrites an LF file as CRLF -- the harness would leave every file
    # it audited modified, and an audit that dirties the tree is one nobody runs.
    original = path.read_bytes()
    # Match against LF regardless of how the file is stored, or a multi-line
    # anchor silently fails on a CRLF checkout and the audit reports that it
    # audited nothing -- which is honest, and still not a result.
    crlf = b"\r\n" in original
    decoded = original.decode("utf-8").replace("\r\n", "\n")
    if find not in decoded:
        return NOT_PLANTED, f"the anchor text is not in {relative}"
    planted = decoded.replace(find, replace, 1)
    if planted == decoded:
        return NOT_PLANTED, "the substitution was a no-op"
    if crlf:
        planted = planted.replace("\n", "\r\n")

    try:
        path.write_bytes(planted.encode("utf-8"))
        if path.read_bytes() == original:
            return NOT_PLANTED, "the write did not take"
        run = subprocess.run([sys.executable, "-m", "unittest", test_id],
                             cwd=str(ROOT), capture_output=True, text=True)
        if run.returncode == 0:
            return GUARD_INERT, "the violation was planted and the guard passed"

        # A test that could not be *loaded* also exits non-zero, and reading
        # that as the guard firing is how an audit comes to certify a guard
        # that does not exist. Found by this tool auditing itself: a mistyped
        # test id reported GUARD_FIRED.
        if "_FailedTest" in run.stderr or "ModuleNotFoundError" in run.stderr:
            return NOT_PLANTED, f"unittest could not load {test_id}"

        first = next((line for line in run.stderr.splitlines()
                      if line.startswith(("FAIL:", "ERROR:"))), "")
        return GUARD_FIRED, first[:96] or "the guard failed"
    finally:
        path.write_bytes(original)


def main() -> int:
    print(f"guard audit  ({len(GUARDS)} structural guards)")
    print("plant the violation each one exists to catch; require it to fail\n")

    results = []
    width = max(len(label) for label, *_ in GUARDS)
    for label, test_id, relative, find, replace in GUARDS:
        state, detail = audit(label, test_id, relative, find, replace)
        results.append((label, state))
        print(f"  {label:<{width}}  {state:<12} {detail}")

    fired = [r for r in results if r[1] == GUARD_FIRED]
    inert = [r for r in results if r[1] == GUARD_INERT]
    unplanted = [r for r in results if r[1] == NOT_PLANTED]
    print()
    print(f"  fired {len(fired)}/{len(results)}"
          + (f"   INERT {len(inert)}: {[r[0] for r in inert]}" if inert else "")
          + (f"   not planted {len(unplanted)}: {[r[0] for r in unplanted]}"
             if unplanted else ""))
    if inert:
        print("  An inert guard asserts nothing. Fix the guard, not the audit.")
    if unplanted:
        print("  A violation that could not be planted audited nothing. The "
              "guard may have moved; this is a harness defect, not a pass.")
    return 0 if not inert and not unplanted else 1


if __name__ == "__main__":
    raise SystemExit(main())
