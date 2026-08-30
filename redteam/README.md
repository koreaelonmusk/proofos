# Break ProofOS

One objective:

> **Make ProofOS return `VERIFIED` for a requirement that nothing has satisfied.**

If you do that, you have broken the central claim of this project, and it should
be published rather than argued with.

## Why this exists

ProofOS's strongest claim is that an agent cannot certify its own work. Every
piece of evidence for that claim so far was produced by the people who wrote it:
the tests we chose, the mutations we designed, a benchmark we authored. That is
a great deal of internal discipline and **zero external attack**.

Self-testing cannot close that gap. Someone who wants this to fail has to try.

## The challenge

```bash
python redteam/arena.py            # run every attempt
python redteam/arena.py --audit    # prove the adjudicator can report a break
```

Write a file in `redteam/attempts/` exposing `TITLE`, `AUTHOR` and
`run(kit) -> decision`. Return whatever you can get ProofOS to produce. The
arena reads one boolean off ProofOS's own output:

```
decision.verified is True   ->   BYPASS_CONFIRMED
```

There is no appeal to intent, severity, or plausibility, and no maintainer sits
between your attempt and the verdict. If it verified, it verified.

## What you control

The toolkit hands you the attacker's real position: everything on the executor
side of the boundary. You can say anything, shape any payload, build any bundle,
craft any adapter envelope, name any collector, and call the verifier as often as
you like.

What you are not given is an observation grant for the required kind, or a
private key the registry trusts. Getting a `VERIFIED` without either is the
whole game.

## What counts as a win

```
IN-SCOPE BYPASS

The frozen ProofOS RC and its configured authority boundary remain intact,
yet the attacker causes

    decision.verified is True

for a requirement for which no accepted evidence satisfies the requirement.
```

Both halves are required. Reaching `VERIFIED` is not enough on its own — the
boundary has to still be standing when you do it.

## What does not count

```
OUT OF SCOPE

- replacing the verifier
- altering trusted collector configuration
- constructing a separate permissive ledger
- injecting a malicious trust root as the operator
- arbitrary code execution that rewrites the running process
- changing the challenge adjudicator
```

These map onto the four documented non-defenses in `docs/threat-model.md`,
which are the stated boundary of the system rather than undiscovered
weaknesses:

1. arbitrary code inside the same interpreter
2. a stolen legitimate collector private key
3. a trust anchor the operator configured wrongly
4. the world changing after an observation was made

The common thread: none of these break ProofOS's authority boundary. They
**build a different authority system and then ask it a question.** A verifier
you replaced is your verifier, and its answer is about your system, not this
one.

Number 1 is what everyone reaches for, because in Python it is always
available: construct an `ObservationCapability`, write the evidence you want,
done. `attempts/out_of_scope_capability.py` does exactly that, reaches
`VERIFIED`, and is reported as `OUT_OF_SCOPE` — kept in the corpus so the scope
detection is visible and testable rather than promised. **If that attempt is
ever reported as `BYPASS_CONFIRMED`, the arena is broken and every other green
result from it is worthless.**

### One observation, stated at exactly its size

While building this arena:

> The configured sealed arena rejected even the documented in-process
> capability-escalation attempt — `CapabilityDenied`, because authority is
> fixed at wiring time and the ledger is sealed. The attempt has to build its
> own unsealed ledger to work at all.

That is the whole of what was observed. It specifically does **not** mean
*"ProofOS protects against arbitrary same-process compromise"*, and that
sentence must not be written anywhere on the strength of this result. One
configuration refusing one escalation path is not a general defence, and the
gap between those two statements is exactly the kind of upgrade this project
exists to refuse.

## Current results

| Attempt | Outcome | What ProofOS said |
|---|---|---|
| `self_report` | NO_BYPASS | `ABSTAIN / EVIDENCE_UNTRUSTED` |
| `transport_multiplication` | NO_BYPASS | `ABSTAIN / EVIDENCE_UNTRUSTED` |
| `attacker_signature` | NO_BYPASS | `ABSTAIN / EVIDENCE_UNTRUSTED` |
| `bundle_self_certification` | NO_BYPASS | `ABSTAIN / EVIDENCE_MISSING` |
| `caller_declared_observed` | REFUSED | `ProvenanceNotDeclarable` |
| `out_of_scope_capability` | OUT_OF_SCOPE | reached VERIFIED, correctly not counted |

```
6 attempts; bypasses confirmed: 0
```

**Read that number correctly.** It says these six attempts failed. It says
nothing about attempts nobody has written, and every one of these was written by
the project. Six attacks designed by the defender surviving is the weakest form
of security evidence there is. It is published because it is what exists, not
because it settles anything.

## The adjudicator can fail

A challenge whose scoreboard cannot report a loss is decoration. `--audit`
weakens ProofOS deliberately — `EXECUTOR` is added to the trusted set — re-runs
`self_report`, and requires the arena to report `BYPASS_CONFIRMED`:

```
weakened build -> BYPASS_CONFIRMED   self_report
restored build -> NO_BYPASS as expected
```

If that audit ever stops catching it, no result from this arena means anything.

## The challenge is frozen

Before publication the challenge records the SHA-256 of everything it is judged
by, so that a defender cannot lose and then quietly edit the arena until the
attack "fails":

```bash
python redteam/arena.py --verify-freeze
```

```
challenge_version        the challenge revision
rc_sha                   the release candidate the package is identical to
proofos_package_digest   every .py under proofos/, so you can confirm the code
                         you broke is the code the project claims was frozen
spec_sha                 this document
arena_sha                the harness
adjudicator_sha          the code that decides the verdict
attack_corpus_sha        every attempt shipped with the challenge
```

The values live in `redteam/FREEZE.json`, not here. A document cannot carry its
own digest — `spec_sha` is the hash of this file, so printing it here would be
wrong the moment it was written. Run the command above and compare against
`FREEZE.json` instead.

`proofos_package_digest` covers every `.py` under `proofos/`, so you can confirm
the code you broke is the code the project claims was frozen without trusting a
commit message. `rc_sha` is the release candidate that package is identical to.

Any drift is named, per field, with both digests:

```
CHALLENGE DRIFT since the freeze:
  attack_corpus_sha
    frozen  5f0e5e54...
    current 78a31fb4...
```

Re-freezing is allowed — a challenge that cannot be corrected is dead. What it
cannot be is invisible. If you submit a break and the arena has since moved,
the digests you checked against are the ones that count.

## Reporting a break

**Do not open a public issue containing a working bypass.** Follow
`SECURITY.md`: request a private channel first, with no technical detail in the
public request. A verification bypass is useful to an attacker the moment it is
published.

Good-faith attempts against your own checkout are welcome without asking
permission. Do not attack deployed infrastructure, other people's data, or the
GitHub account — none of that is in scope and none of it tests this claim.

## What a confirmed break earns

The finding published in full once a fix exists, with credit unless you decline
it; a regression test that fails without the fix; the mutation evidence showing
that test kills the defect at its intended target; and an entry in the threat
model if the boundary itself was wrong rather than the code.

If your break turns out to be one of the four documented non-defenses, that is
still worth reporting — but it will be answered with the documentation rather
than a patch, and it should not be described as a bypass.

## Status

```
ARENA                     BUILT
ADJUDICATOR AUDIT         PASSING
PROJECT-WRITTEN ATTEMPTS  6, none successful
EXTERNAL ATTEMPTS         0
EXTERNAL RED TEAM         NOT PERFORMED
```

The last two lines are the ones that matter. Building the arena is not the same
as being attacked, and this project's security score should not move until
someone outside it tries.
