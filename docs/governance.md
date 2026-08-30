# Repository governance

The same argument this project makes about agents applies to the repository it
lives in. A session reporting that it stopped is a self-report. A branch
protection rule is a refusal.

## Three laws

> **A worktree separates files.
> A lease separates authority.
> A ruleset enforces what a lease can only request.**

`git worktree` gives each checkout its own working directory and its own index.
It does **not** give it its own `.git`. Refs, the object store and the remote
configuration are shared, so every worktree hanging off one gitdir is a single
writer for the purposes of anything that touches a ref. Filesystem isolation is
not authority isolation, and treating it as such is how two sessions come to
believe they are working alone.

## Fetch is observation. Pull is mutation.

These are not two flavours of "reading the remote".

| Operation | Writes | Use for |
|---|---|---|
| `git ls-remote` | nothing | establishing what the remote actually is |
| `git fetch` | `refs/remotes/*` | updating tracking refs, knowing that it does |
| `git pull` | working tree, index, `HEAD` | never, on a verified line, without a lease |

A remote-tracking ref is a memory of the last synchronisation, not the current
remote. Verifying a lease against `origin/branch` verifies against your own
memory. Only `ls-remote` answers the question.

And the consequence that is easy to miss:

> **A remote can contaminate a verified line without a push.**

A plain `git pull` on a branch whose upstream points at a quarantined line will
merge that line into a verified working tree. No push is involved. Both
directions need a lease.

## Recommended controls

**Separate clones for independent writers.** Not worktrees. A clone has its own
gitdir, refs, index and remote configuration; that is what "independent" has to
mean.

**Exactly one remote writer.** Within a set of checkouts sharing a gitdir, at
most one may push. The others may fetch and commit on their own branches.

**A lease that names the ref, not the directory.** At minimum:

```
repo · shared_gitdir · remote · remote_ref
writer_session_id · writer_worktree
expected_local_head
expected_remote_head · observed_via=ls-remote · observed_at
remote_write                      true for exactly one holder
remote_read_into_working_branch   pull is a mutation and needs its own permission
allowed_operations · allowed_refspec
upstream_expected · pull_policy
nonce · expiry · one_shot
```

Verify `expected_remote_head` with `ls-remote` immediately before mutating, not
from a tracking ref, and not from a value read earlier in the session.

**Verified lines get a name the remote does not have.** A branch with no
upstream cannot be the accidental target of a bare `git pull`, because there is
nothing for it to pull from.

**`pull.ff = only`** on writer clones. Diverged histories then refuse to merge
rather than merging. It can be bypassed by an explicit merge command, which is
exactly why it is a layer and not the answer.

**PR-only protected branches** for anything canonical. This is the only control
in the list that does not depend on every participant honouring an agreement.
A lease is a request; a ruleset is a refusal.

## Proving quiescence

Before a coordinated mutation, prove that the other writers stopped. A session
saying so is a self-report; two identical observations across a real interval
are evidence.

```
A   forensic baseline, taken while writers may still be running
    [ every sibling writer stopped ]
B   post-stop baseline
    [ an observation interval — minutes, not seconds ]
C   post-stop witness

QUIESCENT  ⇔  fingerprint(B) == fingerprint(C)
```

`A != B` proves nothing bad: it says a writer acted after A, which is expected.
`A == B` proves nothing good. Only B and C say anything, and only if they are
genuinely separated — a writer between two operations looks exactly like a
writer that stopped.

The snapshot must cover everything a sharer could move: the gitdir, every
linked worktree's `HEAD`, branch and index mtime, every local ref, every remote
ref read over the network, and the working tree's cleanliness.

## Local evidence and remote CI evidence are different

`scripts/release_gate.py` produces local evidence: these gates ran on this
machine, on this tree, with this result. A workflow file is a claim that they
will run somewhere else.

Until a workflow run is observed against a specific pushed commit, that commit
has local evidence and no remote CI evidence. Recording it as
`LOCAL_EVIDENCE_GO / REMOTE_CI_NOT_OBSERVED` keeps two different things from
being read as one, and costs nothing but a hyphen.

## Recovering from a concurrent-writer incident

1. Do not clean up first. An interrupted merge, an unmerged index and the reflog
   are the evidence of what happened.
2. Capture a forensic set: `git status --porcelain=v2`, `git ls-files -u`,
   `git reflog`, `ORIG_HEAD`, `FETCH_HEAD`, `MERGE_HEAD`, the worktree list —
   and the *contents* of the conflicting index stages, not just their hashes.
   A capsule that references objects in a store other writers control is not
   preserved.
3. Stop the other writers, and prove it with B/C snapshots.
4. Recover using the transaction boundary git recorded, not one you inferred.
   `ORIG_HEAD` is what `git merge --abort` returns to.
5. Quarantine the contaminated remote branch rather than force-pushing over it.
   Forcing lays new asphalt over the scene, and branch-level forensic evidence
   is lost even where the objects survive.
6. Publish the verified line under a **new** name. A non-force single-ref
   creation needs no force permission and leaves the incident intact for review.
