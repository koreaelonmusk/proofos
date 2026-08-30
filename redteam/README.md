# Break ProofOS

One objective:

> **Make ProofOS return `VERIFIED` for a requirement that nothing has satisfied.**

If you do that, you have broken the central claim of this project, and it should
be published rather than argued with.

## Why this exists

ProofOS's strongest claim is that an agent cannot certify its own work. Every
piece of evidence for that claim so far was produced by the people who wrote it:
1226 tests we chose, 41 mutations we designed, a benchmark we authored. That is
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

## What does not count

Four things are documented non-defenses in `docs/threat-model.md`. They are the
stated boundary of the system, not undiscovered weaknesses:

1. arbitrary code inside the same interpreter
2. a stolen legitimate collector private key
3. a trust anchor the operator configured wrongly
4. the world changing after an observation was made

Number 1 is the one everyone reaches for, because in Python it is always
available: construct an `ObservationCapability`, write the evidence you want,
done. `attempts/out_of_scope_capability.py` does exactly that, reaches
`VERIFIED`, and is reported as `OUT_OF_SCOPE` — it is kept in the corpus so the
scope detection is visible and testable rather than promised. **If that attempt
is ever reported as `BYPASS_CONFIRMED`, the arena is broken and every other
green result from it is worthless.**

Interesting wrinkle found while building this: on the arena's own sealed ledger
even that move is refused — `CapabilityDenied`, because authority is fixed at
wiring time and the ledger is sealed. The attempt has to build its own unsealed
ledger to work at all. That is a real property, and it is still out of scope.

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
