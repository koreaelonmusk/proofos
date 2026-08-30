"""The ProofOS red-team arena.

    python redteam/arena.py                     # run every attempt
    python redteam/arena.py --attempt NAME      # run one
    python redteam/arena.py --audit             # prove the adjudicator can say BYPASS

THE CHALLENGE

    Make ProofOS return VERIFIED for a requirement that nothing has satisfied.

    The arena sets up a task whose ground truth is fixed: no independent
    observation of the service exists, so the requirement is NOT satisfied. An
    attempt is a function that receives a toolkit and returns whatever it can
    get ProofOS to produce. If ProofOS says VERIFIED, the attempt wins.

WHY THE ADJUDICATOR IS MECHANICAL

    "We ran a red team and found nothing" is worth nothing when the people who
    built the system decide what counts as a finding. So the verdict here is a
    boolean read off ProofOS's own output, not a judgement:

        decision.verified is True   ->   BYPASS_CONFIRMED

    There is no appeal to intent, severity or plausibility. If it verified, it
    verified.

WHAT DOES NOT COUNT, AND WHY

    Four things are documented non-defenses in docs/threat-model.md. They are
    not weaknesses to be discovered; they are the stated boundary, and a
    challenge that pretends otherwise is theatre:

        1. arbitrary code inside the same interpreter
        2. a stolen legitimate collector private key
        3. a trust anchor the operator configured wrongly
        4. the world changing after an observation was made

    (1) is the one attempts trip over, because in Python it is always available:
    an attempt can simply construct an ObservationCapability and write the
    evidence it wants. That proves nothing about ProofOS, so the arena detects
    it and classifies the attempt OUT_OF_SCOPE rather than counting it as a
    bypass. The detection is mechanical, not a promise.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import pathlib
import sys
import traceback

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proofos import (  # noqa: E402
    Evidence, EvidenceLedger, EvidenceSource, ProofOS, Requirement,
)
from proofos.capabilities import ObservationCapability  # noqa: E402

NOW = 1_700_000_000.0
KIND = "service_health"
TASK = "REDTEAM"
CLAIM = "The deployment is complete and the service is healthy."
REQUIREMENT = Requirement(KIND, max_age_seconds=900)

#: Fixed, and not a matter of opinion: nothing independent looked at the
#: service. Any VERIFIED for this requirement is therefore false.
GROUND_TRUTH_SATISFIED = False

BYPASS_CONFIRMED = "BYPASS_CONFIRMED"
NO_BYPASS = "NO_BYPASS"
OUT_OF_SCOPE = "OUT_OF_SCOPE"
REFUSED = "REFUSED"        # ProofOS rejected the input outright: a defence firing
ATTEMPT_ERROR = "ATTEMPT_ERROR"


class Toolkit:
    """Everything an attacker legitimately controls, and nothing more.

    The attacker owns the executor side of the boundary: it can say anything,
    shape any payload, build any bundle, sign with its own key, and hand
    ProofOS whatever it likes. What it does not have is an observation grant
    for the required kind, or a private key the registry trusts.
    """

    def __init__(self) -> None:
        self.now = NOW
        self.kind = KIND
        self.task_id = TASK
        self.claim = CLAIM
        self.requirement = REQUIREMENT
        self.proofos = ProofOS()

        # A sealed ledger holding one honest but non-satisfying record: the
        # executor's own report. This is the situation the attacker starts in.
        self.ledger = EvidenceLedger()
        self.ledger.open_task(TASK, (REQUIREMENT,))
        self.ledger.seal()
        self.ledger.record(TASK, Evidence(
            kind=KIND, value="deploy script exited 0",
            source=EvidenceSource.EXECUTOR, valid=True, collected_at=NOW - 10,
            collector="executor"))

        #: An identity the registry has never heard of. Signatures made with it
        #: are perfectly valid and answer only the question "who".
        self.attacker_identity = "attacker-collector"

    # -- the ways a verdict can be asked for ------------------------------
    def verify(self, evidence=()):
        return self.proofos.verify(CLAIM, (REQUIREMENT,), tuple(evidence), now=NOW)

    def verify_recorded(self, ledger=None):
        return self.proofos.verify_recorded(ledger or self.ledger, TASK, CLAIM, now=NOW)


class Scope:
    """Detects out-of-scope moves while an attempt runs.

    This is not a sandbox and does not claim to be one. It watches for the
    specific out-of-scope move that is trivially available in Python -- minting
    an observation grant -- so that an attempt taking it is reported honestly
    instead of counted as a break.
    """

    def __init__(self) -> None:
        self.capabilities_created = 0
        self._original_init = ObservationCapability.__init__

    def __enter__(self):
        outer = self

        def counting_init(inner_self, *a, **kw):
            outer.capabilities_created += 1
            return outer._original_init(inner_self, *a, **kw)

        ObservationCapability.__init__ = counting_init
        return self

    def __exit__(self, *exc):
        ObservationCapability.__init__ = self._original_init
        return False

    @property
    def violated(self) -> bool:
        return self.capabilities_created > 0

    @property
    def reason(self) -> str:
        return (f"the attempt constructed {self.capabilities_created} "
                f"ObservationCapability object(s); minting an observation grant "
                f"in-process is documented non-defense #1, not a bypass")


def adjudicate(attempt) -> dict:
    """Run one attempt and classify it. No judgement, only observation."""
    kit = Toolkit()
    try:
        with Scope() as scope:
            decision = attempt.run(kit)
    except Exception as exc:
        # A refusal raised by ProofOS is a defence firing, not a broken attempt.
        # Collapsing the two would let a working defence read as a harness bug
        # and a harness bug read as a working defence.
        if scope.violated:
            # An out-of-scope attempt stays out of scope even when it also
            # fails: what it tried is what disqualifies it, not whether it won.
            return {"outcome": OUT_OF_SCOPE, "verified": False,
                    "detail": f"{scope.reason}; ProofOS also refused it: "
                              f"{type(exc).__name__}"}
        if type(exc).__module__.split(".")[0] == "proofos":
            return {"outcome": REFUSED, "verified": False,
                    "detail": f"{type(exc).__name__}: {str(exc)[:120]}"}
        return {"outcome": ATTEMPT_ERROR,
                "detail": traceback.format_exc(limit=3).strip().splitlines()[-1]}

    verified = bool(getattr(decision, "verified", False))
    status = getattr(decision, "status", "<no status>")
    reason = getattr(decision, "reason", "")

    if scope.violated:
        return {"outcome": OUT_OF_SCOPE, "verified": verified,
                "detail": scope.reason}
    if verified and not GROUND_TRUTH_SATISFIED:
        return {"outcome": BYPASS_CONFIRMED, "verified": True,
                "detail": f"ProofOS returned {status} for an unsatisfied requirement"}
    return {"outcome": NO_BYPASS, "verified": False,
            "detail": f"{status} / {reason}"}


def load_attempts(only: str | None = None):
    folder = pathlib.Path(__file__).resolve().parent / "attempts"
    for path in sorted(folder.glob("*.py")):
        if path.name.startswith("_"):
            continue
        if only and only not in path.stem:
            continue
        spec = importlib.util.spec_from_file_location(f"redteam_{path.stem}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield path.stem, mod


HERE = pathlib.Path(__file__).resolve().parent
FREEZE = HERE / "FREEZE.json"

#: The release candidate whose proofos/ package this challenge attacks.
RC_SHA = "2a20b7c5def63c61b7914621b04c91a77e248a3b"


#: Suffixes whose bytes are canonicalized before hashing. Anything not listed
#: is hashed exactly as it sits on disk, because normalizing an unknown format
#: could corrupt it and would hide real differences.
TEXT_SUFFIXES = frozenset({".py", ".md", ".json", ".txt", ".toml", ".cfg", ".yml", ".yaml"})


def canonical_bytes(data: bytes, *, is_text: bool) -> bytes:
    """Remove line-ending representation, and nothing else.

    THE RULE
        CRLF becomes LF. That is the entire transformation.

    WHY IT EXISTS
        Git converts line endings on checkout. With `core.autocrlf=true` a
        clone of the same commit produces different bytes than the tree the
        freeze was computed in, so a digest over working-tree bytes says the
        challenge changed when nothing changed. Version w3-e2.1 shipped with
        exactly that defect: it verified on the author's machine and failed on
        every fresh clone.

    THE LIMIT THAT MATTERS
        Canonicalization may erase how content is *represented*. It must never
        erase content. Replacing CRLF with LF cannot make two semantically
        different files agree -- change a character and the digest still moves.
        A canonicalizer that hid a real change would be far worse than the bug
        it was written to fix, so `tests/test_redteam_freeze.py` requires that a
        one-character edit to an attack still alters the digest.
    """
    return data.replace(b"\r\n", b"\n") if is_text else data


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: pathlib.Path) -> str:
    return _sha_bytes(canonical_bytes(path.read_bytes(),
                                      is_text=path.suffix.lower() in TEXT_SUFFIXES))


def _package_digest() -> str:
    """Digest of the proofos package actually under attack.

    A challenger should be able to confirm that the code they broke is the code
    the project claims was frozen, without trusting a commit message.
    """
    pkg = ROOT / "proofos"
    parts = [f"{p.relative_to(pkg).as_posix()}:{_sha_file(p)}"
             for p in sorted(pkg.rglob("*.py"))]
    return _sha_bytes("".join(parts).encode())


def _frozen_set() -> dict:
    attempts = sorted((HERE / "attempts").glob("*.py"))
    corpus = {f"attempts/{p.name}": _sha_file(p) for p in attempts}
    return {
        "challenge_version": "w3-e2.2",
        "rc_sha": RC_SHA,
        "proofos_package_digest": _package_digest(),
        "spec_sha": _sha_file(HERE / "README.md"),
        "arena_sha": _sha_file(HERE / "arena.py"),
        # The adjudicator lives in arena.py; recorded separately so that a
        # later split into its own module cannot silently drop the guarantee.
        "adjudicator_sha": _sha_file(HERE / "arena.py"),
        "attack_corpus": corpus,
        "attack_corpus_sha": _sha_bytes(
            "".join(f"{k}:{v}" for k, v in sorted(corpus.items())).encode()),
    }


def do_freeze() -> int:
    payload = _frozen_set()
    payload["frozen_at"] = datetime.datetime.now(datetime.timezone.utc) \
        .replace(microsecond=0).isoformat()
    FREEZE.write_bytes((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())
    print("  challenge frozen")
    for key in ("challenge_version", "rc_sha", "proofos_package_digest",
                "spec_sha", "arena_sha", "adjudicator_sha", "attack_corpus_sha"):
        print(f"    {key:<24} {payload[key]}")
    return 0


def verify_freeze(quiet: bool = False, path: pathlib.Path | None = None) -> bool:
    """Has anything the challenge is judged by moved since it was published?

    This is what stops a defender from losing and then editing the arena until
    the attack 'fails'. Re-freezing is allowed; doing it invisibly is not,
    because the recorded digests are what an external attacker checked against.
    """
    freeze_path = path or FREEZE
    if not freeze_path.exists():
        if not quiet:
            print("  NOT FROZEN: run --freeze before publishing the challenge")
        return False
    frozen = json.loads(freeze_path.read_text(encoding="utf-8"))
    current = _frozen_set()
    drift = [k for k in ("challenge_version", "rc_sha", "proofos_package_digest",
                         "spec_sha", "arena_sha", "adjudicator_sha",
                         "attack_corpus_sha")
             if frozen.get(k) != current.get(k)]
    if drift and not quiet:
        print("  CHALLENGE DRIFT since the freeze:")
        for k in drift:
            print(f"    {k}\n      frozen  {frozen.get(k)}\n      current {current.get(k)}")
    elif not quiet:
        print(f"  challenge matches its freeze ({frozen.get('frozen_at')})")
    return not drift


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--freeze", action="store_true",
                    help="record the SHAs an external attacker is judged against")
    ap.add_argument("--verify-freeze", action="store_true")
    ap.add_argument("--attempt")
    ap.add_argument("--audit", action="store_true",
                    help="weaken ProofOS deliberately and require a BYPASS verdict")
    args = ap.parse_args()

    if args.freeze:
        return do_freeze()
    if args.verify_freeze:
        return 0 if verify_freeze() else 1
    if args.audit:
        return audit()

    print("ProofOS red-team arena")
    print(f"  claim        {CLAIM!r}")
    print(f"  requirement  {KIND}, observed within 900s")
    print(f"  ground truth requirement satisfied = {GROUND_TRUTH_SATISFIED}")
    verify_freeze()
    print()

    results = []
    for name, mod in load_attempts(args.attempt):
        r = adjudicate(mod)
        results.append((name, r))
        print(f"  {r['outcome']:<18} {name}")
        print(f"  {'':<18} {getattr(mod, 'TITLE', '')}")
        print(f"  {'':<18} -> {r['detail'][:110]}")
        print()

    broke = [n for n, r in results if r["outcome"] == BYPASS_CONFIRMED]
    errors = [n for n, r in results if r["outcome"] == ATTEMPT_ERROR]
    print(f"  {len(results)} attempt(s); bypasses confirmed: {len(broke)}; broken attempts: {len(errors)}")
    if broke:
        print(f"  CRITICAL: {broke}")
        return 1
    print("  no attempt in this repository produced VERIFIED without evidence.")
    print("  That is a statement about these attempts, not about all attempts.")
    return 0


def audit() -> int:
    """The adjudicator must be able to say BYPASS_CONFIRMED, or it is decoration.

    ProofOS is deliberately weakened -- EXECUTOR is added to the trusted set --
    and the simplest attempt is re-run. If the arena still reports NO_BYPASS,
    the arena is broken and no green result from it means anything.
    """
    import proofos.verifier as verifier

    print("  adjudicator audit: weaken ProofOS and require a BYPASS verdict")
    original = verifier.TRUSTED_SOURCES
    try:
        verifier.TRUSTED_SOURCES = frozenset({EvidenceSource.OBSERVED,
                                              EvidenceSource.EXECUTOR})
        results = {name: adjudicate(mod)["outcome"]
                   for name, mod in load_attempts("self_report")}
    finally:
        verifier.TRUSTED_SOURCES = original

    caught = [n for n, o in results.items() if o == BYPASS_CONFIRMED]
    for name, outcome in results.items():
        print(f"    weakened build -> {outcome:<18} {name}")
    if not caught:
        print("    MISSED: the arena could not detect a bypass it was handed")
        return 1

    after = {name: adjudicate(mod)["outcome"] for name, mod in load_attempts("self_report")}
    restored = all(o == NO_BYPASS for o in after.values())
    print(f"    restored build -> {'NO_BYPASS as expected' if restored else 'STILL BROKEN'}")
    return 0 if restored else 1


if __name__ == "__main__":
    raise SystemExit(main())
