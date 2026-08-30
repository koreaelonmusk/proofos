# Contributing to ProofOS

ProofOS decides whether something has been proven. That makes contribution
rules unusually load-bearing: a change that quietly widens what counts as
authority does not look like a bug in review, and it does not look like one in
a green test run either.

Everything below exists to make that specific failure hard.

## The rules the code is built around

```
Adapter translates. Kernel decides.
Claim is not evidence.
Signed is not trusted.
Unknown is not satisfied.
Uncertainty may reduce authority. It may never create authority.
```

If a change makes any of those less true, it is a change to the product's
thesis and needs to be argued as one — not merged as a refactor.

## Before you write code

1. Start from a clean tree. `git status --short` empty.
2. Name the authority boundary your change touches: provenance, trust root,
   authorization, scope, freshness, integrity, or none. "None" is a fine answer
   and makes review much faster.
3. Write the test first, and watch it fail. A test for an absence — "this must
   not become VERIFIED" — passes just as happily when it is broken as when the
   property holds. If you did not see it fail, you do not know it works.

## Things that are never acceptable

- converting missing evidence into success
- silently ignoring an unknown requirement field — an ignored requirement is not
  a satisfied requirement
- letting a bundle choose its own trust roots
- letting framework or transport state become ProofOS authority
- adding a runtime dependency without an explicit justification
- committing generated results as authoritative without stating how they
  reproduce and where they came from

## Running the gates

Use the commands, not a description of them.

```bash
python -m unittest discover -s tests -t .    # full suite
python scripts/release_gate.py all           # wheel, install, deps, secrets,
                                             # suite, guards, security
python scripts/guard_audit.py                # each structural guard, watched failing
python scripts/security_gate.py              # authority-critical mutations
```

`release_gate.py` runs the suite, the guard audit and the security gate as part
of `all`, so it is the single command to run before opening a pull request. A
gate that cannot run reports `NOT RUN` and the runner exits non-zero, because a
check that did not happen is not a check that passed.

Report `NOT_RUN` and `NOT_OBSERVED` explicitly. Neither is a failure. Both
become dishonest the moment they are quietly rendered as a pass.

## Mutation discipline

A change to an authority-critical path needs mutation evidence: break the line
you claim to have secured, and show that the test you added is what catches it.

Results distinguish four states, and they are not interchangeable:

```
KILLED_AT_TARGET   the test that claims to defend this line killed the mutation
KILLED_UPSTREAM    something else killed it first
SURVIVED           nothing killed it
NOT_APPLIED        the mutation did not change the program
```

**`KILLED_UPSTREAM` is not equivalent to `KILLED_AT_TARGET`.** A defence tested
only by its neighbour moves the day the neighbour is rewritten, and reporting
the two as one number is how that goes unnoticed for a release.

`NOT_APPLIED` deserves the same suspicion. A mutation that changes no bytes
tests nothing, and it reports as a clean run.

## Pull request description

```
BASELINE                 commit you started from
CLAIM                    what this change makes true
THREAT / FAILURE MODE    what goes wrong without it
CHANGE                   what you actually did
EVIDENCE                 commands run, and their output
MUTATION / NEGATIVE      what you broke to prove the test catches it
NOT OBSERVED             what you did not run, and why
BOUNDARIES NOT CHANGED   authority surfaces this change does not touch
```

A green CI run is evidence that the tests passed on that machine. It is not
evidence that the behaviour is right in the world, and a PR that offers only
"CI is green" under EVIDENCE will be asked for the rest.

## Scope

One change per pull request. No drive-by architecture edits, no opportunistic
reformatting of files you are not otherwise touching, no dependency added
because it was convenient. The trusted core should shrink over time; a change
that grows it needs to say why.

## Review ownership

`.github/CODEOWNERS` records who is responsible for which surfaces. It is
documentation of intent. It is **not** proof that a review happened, and it is
not enforcement — enforcement would require repository configuration that has
deliberately not been applied. See `docs/governance/branch-protection-design.md`.

## Terminology

The outcomes are `VERIFIED` and `ABSTAIN`. `ABSTAIN` is not a failure, not a
judgement about the actor, and not proof that the task failed — it means the
evidence does not establish the requirement. Please keep documentation and
error messages using those two words rather than inventing synonyms.
