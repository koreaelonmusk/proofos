```
STATUS: DESIGNED, NOT APPLIED
REMOTE ADMIN MUTATION: 0
```

# Branch protection design

Nothing in this document has been created, enabled, edited, or applied. No
repository setting was changed to write it. Applying any part of it requires a
separate, explicit authorization naming the target repository, the ref pattern,
the exact rules, the expected existing configuration, the allowed bypass actors,
and the exact status check names.

## Correction: `main` is already protected

An earlier reading of this repository concluded that `main` had no branch
protection, on the evidence that `GET /repos/{owner}/{repo}/branches/main/protection`
returns `404 Branch not protected`. **That conclusion was wrong.**

That endpoint reports only *classic* branch protection. This repository is
protected by a **ruleset**, which the classic endpoint does not see. Checking one
mechanism and concluding an absence is the same error as trusting a single
tolerant verifier, and it is recorded here rather than quietly fixed.

## Observed existing configuration

Read from `GET /repos/koreaelonmusk/proofos/rulesets/21147240` without
modification:

```
ruleset       id 21147240  "Protect main"
target        branch
conditions    ref_name include ["~DEFAULT_BRANCH"]
enforcement   active
bypass_actors [] (none)
created       2026-08-21
```

| Rule | Parameters |
|---|---|
| `deletion` | branch cannot be deleted |
| `non_fast_forward` | force-push blocked |
| `required_linear_history` | merge commits rejected |
| `pull_request` | approvals 0 · code-owner review false · stale dismissal false · last-push approval false · **review thread resolution true** · merge methods `merge, squash, rebase` |
| `required_status_checks` | strict true · `do_not_enforce_on_create` true · context **`verifier`** (integration 15368) |

The practical effect is that most of what a first-pass design would propose is
already enforcing, and it was configured sensibly: approvals are at 0 rather
than locking out the sole maintainer, and the one required check is `verifier`,
which the CI workflow on `main` actually produces.

## Delta between the observed state and this design

### Already enforced — no change proposed

- pull request required, approvals 0 (§A below)
- force-push blocked (§C)
- deletion blocked (§D)
- no bypass actors (§F)
- branch creation unrestricted (§G)

### D-1. Linear history conflicts with the allowed merge methods

**Severity: latent, live now.**

`required_linear_history` is enabled while `pull_request.allowed_merge_methods`
still contains `merge`. A contributor who selects "Create a merge commit" will
pass every check and then be refused at the merge button, with nothing
explaining why.

Proposed change: remove `merge` from `allowed_merge_methods`, leaving
`squash, rebase`. This is a narrowing, and it makes the two rules agree.

### D-2. The release-gate checks are not required, and must not be added yet

The blocking matrix is known. It was observed on the frozen candidate
`2a20b7c5def63c61b7914621b04c91a77e248a3b`, not guessed:

| Check name (verbatim) | Workflow | Run | Result |
|---|---|---|---|
| `ubuntu-latest / py3.11` | Release gate | 33321655698 | success |
| `ubuntu-latest / py3.12` | Release gate | 33321655698 | success |
| `windows-latest / py3.11` | Release gate | 33321655698 | success |
| `windows-latest / py3.12` | Release gate | 33321655698 | success |
| `ubuntu / py3.13 (not claimed, advisory)` | Release gate | 33321655698 | success — advisory, **not** a blocking target |
| `verifier` | CI | 33321655675 | success — already required |

**These four cannot be required on `main` today.** They are produced by
`.github/workflows/release-gate.yml`, and that workflow exists only on the
release-candidate branch:

```
main                                    ci.yml, pages.yml
next/proofos-v1-platform-rc-2a20b7c     ci.yml, pages.yml, release-gate.yml
```

A required check that no workflow on the target branch can produce does not make
merges safer — it makes them impossible, with administrator bypass as the only
way through. That is worse than no rule, because it manufactures the habit of
bypassing. `do_not_enforce_on_create` being true softens branch creation but does
not rescue pull requests.

Activation precondition:

```
1. release-gate.yml exists on main
2. a run of it against a main-targeting pull request has been observed
3. the check names from THAT run are recorded here verbatim
4. only then are they entered into the ruleset
```

Names observed on another branch are evidence about that branch. They are
recorded here as the *expected* names, not as an authorization to enter them.

Python 3.13 stays advisory unless separately promoted. Python 3.10 is
unsupported and must never appear as a blocking target.

### D-3. Code Owner review stays off

`.github/CODEOWNERS` now documents ownership. Enforcement stays disabled.

With one maintainer, requiring Code Owner review means the only person who can
merge is the only person who can approve, and GitHub does not permit
self-approval. The result is not stronger governance; it is a locked repository
and a maintainer reaching for a bypass on the first urgent fix. A control that
must routinely be bypassed teaches everyone that bypass is normal.

When a second trusted reviewer exists:

```
required approvals                              1
require review from Code Owners                 true
dismiss stale approvals on new commits          true
require approval of the most recent push        true
```

Not before.

## Sections retained for completeness

### A. Pull request required

Enforced, approvals 0. Correct for a single-maintainer repository. See D-3.

### C. Block force pushes

Enforced via `non_fast_forward`. No change.

### D. Block branch deletion

Enforced via `deletion`. No change.

### F. Bypass

`bypass_actors` is empty and should stay empty. Any emergency bypass must be
explicit, attributable, time-bounded where the platform allows, and followed by
requalification of the affected ref. Administrator capability is not a normal
path around governance, and this document does not describe it as one.

### G. Branch creation

Unrestricted, correctly. Remote RC creation is separately governed by exact-ref,
create-only compare-and-swap pushes (`--force-with-lease=<ref>:` with an empty
expected value, meaning *the ref must not already exist*), which is a stronger
guarantee for that operation than a branch rule.

## Enforcement state of *this design*

```
ruleset created by this work     NO
ruleset enabled by this work     NO
ruleset modified by this work    NO
```

Ruleset 21147240 pre-existed this work and was read, never written.

A later authorization to apply the D-1 and D-2 deltas must specify, and be
checked against observed reality before anything is written:

```
target repository
target ref pattern
exact rule set
expected existing configuration      (ruleset 21147240 as recorded above)
allowed bypass actors
exact status check context names
```

If the observed remote configuration differs from that stated precondition:
**stop and report.** Do not adapt automatically. A ruleset applied to a
repository in an unexpected state is a change nobody reviewed.

## Summary

| Control | Observed | Proposed |
|---|---|---|
| Pull request required | enforced, approvals 0 | unchanged |
| Code Owner review | off | off until a second reviewer exists |
| Required status checks | `verifier` | add the release-gate four **after** the workflow reaches `main` |
| Block force push | enforced | unchanged |
| Block deletion | enforced | unchanged |
| Linear history | enforced | drop `merge` from allowed merge methods (D-1) |
| Bypass actors | none | unchanged |
| Branch creation | unrestricted | unchanged |

The applied state of this repository is unchanged by this work.
