```
STATUS: DESIGNED, NOT APPLIED
REMOTE ADMIN MUTATION: 0
```

# Branch protection design

This document proposes a ruleset for `main`. Nothing here has been created,
enabled, or applied. No repository setting was changed to write it. Applying
any of it requires a separate, explicit authorization naming the target
repository, the ref pattern, the exact rules, the expected existing
configuration, the allowed bypass actors, and the exact status check names.

The reason for the separation is the same reason the project exists: a document
describing a control is not the control. A ruleset that has been designed and a
ruleset that is enforcing are different states of the world, and conflating them
would be exactly the kind of claim ProofOS refuses elsewhere.

## Target

```
repository   koreaelonmusk/proofos
ref          refs/heads/main
```

Quarantined historical branches are out of scope. This design does not
rehabilitate, delete, or alter them.

## A. Require a pull request before merging

**Proposed: yes. Required approvals: 0.**

This repository has one maintainer. Requiring an approval count above zero, or
requiring Code Owner review, would mean the only person able to merge is also
the only person able to approve — and GitHub does not let an author approve
their own pull request. The result is not stronger governance; it is a locked
repository and a maintainer reaching for the bypass on the first urgent fix. A
control that must be routinely bypassed teaches everyone that bypass is normal.

So the honest first step is the part that is real today: changes arrive as pull
requests, which produces a diff, a checkpoint, and somewhere for CI to attach.

When a second trusted reviewer exists, this section becomes:

```
required approvals                              1
require review from Code Owners                 true
dismiss stale approvals on new commits          true
require approval of the most recent push        true
```

Not before. `.github/CODEOWNERS` documents intended ownership in the meantime
and says in its own text that it enforces nothing.

## B. Required status checks

**Proposed: yes — but not yet activatable on `main`, and this is the finding
that matters most in this document.**

The exact check names are known. They were observed on the frozen candidate
`2a20b7c5def63c61b7914621b04c91a77e248a3b`, not guessed:

| Check name (verbatim) | Workflow | Run | Result |
|---|---|---|---|
| `ubuntu-latest / py3.11` | Release gate | 33321655698 | success |
| `ubuntu-latest / py3.12` | Release gate | 33321655698 | success |
| `windows-latest / py3.11` | Release gate | 33321655698 | success |
| `windows-latest / py3.12` | Release gate | 33321655698 | success |
| `ubuntu / py3.13 (not claimed, advisory)` | Release gate | 33321655698 | success — advisory, **not** a blocking target |
| `verifier` | CI | 33321655675 | success |

**The blocking four cannot be required on `main` today.** They are produced by
`.github/workflows/release-gate.yml`, and that workflow exists only on the
release-candidate branch:

```
main                                    ci.yml, pages.yml
next/proofos-v1-platform-rc-2a20b7c     ci.yml, pages.yml, release-gate.yml
```

A required status check that no workflow on the target branch can ever produce
does not make merges safer — it makes them impossible, permanently, with the
administrator bypass as the only way through. That is strictly worse than no
rule, because it manufactures a habit of bypassing.

Activation precondition, therefore:

```
1. release-gate.yml exists on main
2. a run of it on a main-targeting pull request has been observed
3. the check names from THAT run are recorded here verbatim
4. only then are they entered into the ruleset
```

Names observed on a different branch are evidence about that branch. They are
reused here as the *expected* names, not as an authorization to enter them.

Python 3.13 stays advisory unless separately promoted. Python 3.10 is
unsupported and must never appear as a blocking target.

## C. Block force pushes

**Proposed: yes.**

Force-push to `main` is the one operation that can destroy history other people
have already relied on, and no legitimate workflow here needs it.

## D. Block branch deletion

**Proposed: yes.** Deleting `main` has no legitimate use.

## E. Require linear history

**Proposed: yes, deferred.**

Compatible only with squash or rebase merges. Enabling it while merge commits
are still permitted produces pull requests that pass every check and then refuse
to merge. Select and test the merge strategy first, then enable this in the same
change.

## F. Bypass

**Proposed: no routine bypass actors.**

If an emergency bypass is ever used it must be explicit, attributable,
time-bounded where the platform allows, and followed by requalification of the
affected ref. Administrator capability is not a normal path around governance,
and this document does not describe it as one. A bypass that leaves no trace and
triggers no re-verification is indistinguishable from the rule not existing.

## G. Branch creation

**Proposed: not restricted.**

Feature and release-candidate branches must remain creatable. Remote RC creation
is separately governed by exact-ref, create-only compare-and-swap pushes
(`--force-with-lease=<ref>:` with an empty expected value, meaning *the ref must
not already exist*), which is a stronger guarantee for that specific operation
than a branch rule would give.

## H. Enforcement state

```
ruleset created    NO
ruleset enabled    NO
ruleset applied    NO
```

A later authorization to apply must specify, and be checked against observed
reality before anything is written:

```
target repository
target ref pattern
exact rule set
expected existing configuration
allowed bypass actors
exact status check context names
```

If the observed remote configuration differs from the authorization's stated
precondition: **stop and report.** Do not adapt automatically. A ruleset applied
to a repository in an unexpected state is a change nobody reviewed.

## Summary

| Control | Proposed | Blocked on |
|---|---|---|
| Pull request required | yes | — |
| Required approvals | 0 → 1 later | a second trusted reviewer |
| Code Owner review | documented, not enforced | a second trusted reviewer |
| Required status checks | yes | `release-gate.yml` reaching `main` |
| Block force push | yes | — |
| Block deletion | yes | — |
| Linear history | yes | merge strategy decision |
| Bypass actors | none | — |
| Branch creation limits | none | — |

Everything in the "Proposed" column is a proposal. The applied state of this
repository is unchanged.
