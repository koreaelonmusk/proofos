# Security policy

ProofOS exists to decide whether an agent's work can be declared complete. A
defect that makes it answer `VERIFIED` when the evidence does not support that
is not an ordinary bug: every downstream decision inherits the certification
and nothing further detects it. Reports in that class are the ones this
document most wants to receive.

## Supported versions

| Version | Status |
|---|---|
| 0.1.0 | current development line |

There is no published release on a package index yet. Locally qualified
release candidates are **not** public releases, and nothing in this repository
should be read as a support commitment for an unpublished build. When a
released version exists, this table will name it.

## Reporting a vulnerability

**Do not open a public issue containing exploit details, a working bypass, or a
proof-of-concept.** A verification bypass is useful to an attacker the moment
it is published, and this project has nothing deployed that could be patched
ahead of disclosure.

The intended mechanism is GitHub's private vulnerability reporting.

> **Status: not enabled.** As of this writing the repository's
> private-vulnerability-reporting setting reads `enabled: false`. This document
> does not claim a private channel that does not exist. Enabling it is a
> repository administration change and is tracked as governance work, not
> asserted here.

Until it is enabled, report in two steps:

1. Open a public issue whose entire content is a request for a private channel —
   a title such as *"security report — request private channel"* and no
   technical detail whatsoever. Not the component, not the symptom.
2. Wait for a private channel before sending anything substantive.

If you believe a defect is being actively exploited, say so in step 1. That is
the one piece of context worth the disclosure cost.

Please include, once a private channel exists: the version or commit, the
authority boundary you believe is crossed, a minimal reproducer, and what the
system returned instead of what it should have.

## The security model

ProofOS keeps six questions separate. Most systems that get this wrong have
collapsed two of them into one.

```
Who produced the evidence?
Was that producer trusted?
Was that producer authorized?
Does the evidence satisfy this requirement?
Is the evidence fresh?
Is the evidence intact?
```

The distinctions that follow are the product, not slogans:

```
Signed              is not   Trusted
Trusted signer      is not   Authorized collector
Authorized collector is not  Evidence satisfies requirement
```

A valid signature answers *who signed these bytes*. Registration answers
*whether that identity is known to this verifier*. Scope answers *what that
identity may speak to*. Satisfaction is a further question again, and freshness
and integrity are two more. A report showing any one of these silently standing
in for another is a report about the core of this system.

## High-value vulnerability classes

Anything that causes `VERIFIED` without evidence that genuinely satisfies the
stated requirement, including:

- forged or misattributed evidence provenance
- trust-anchor bypass
- collector authorization bypass
- signature-verification bypass
- replay accepted outside its intended scope
- stale evidence accepted as current
- tampered evidence accepted
- malformed evidence converted into success
- unknown or unimplemented requirements silently ignored
- fail-open behaviour on any error path
- leakage of secrets or private keys
- capability escalation — obtaining an observation grant without being given one
- journal or proof-bundle integrity bypass
- any path that converts uncertainty into authority

That last line is the general form of all the others. Uncertainty may reduce
authority. It may never create it.

## Boundaries this project does not claim to defend

These are documented limits, not undiscovered weaknesses. Reports here are
welcome as design discussion but will not be treated as vulnerabilities.

- **Arbitrary code executing inside the same interpreter.** An observation grant
  is authority held by an object; anything holding a reference to something that
  holds one can reach it. Genuine isolation needs process separation, which is
  why the collector is a separate service with its own key.
- **A stolen legitimate collector private key.** Whoever holds the key *is* that
  collector as far as any verifier can tell. Signatures answer *who*, and theft
  makes that answer wrong at the source.
- **An operator-supplied malicious trust root.** If an attacker's key is
  registered under a collector's name, verification will honour it. The trust
  root is an input to this system, not a decision it makes.
- **The world changing after an observation.** Freshness bounds this and does
  not remove it.
- **Third-party transports beyond the verification boundary.** Adapters
  normalise what a remote system said; the security of that remote system is
  its own.

See `docs/threat-model.md` for the full treatment. This section deliberately
does not duplicate it.

## What a good report earns

Confirmation of what was reproduced, a fix with a regression test that fails
without it, and credit unless you decline it. Where a report changes an
authority boundary, the change carries mutation evidence showing the new test
actually kills the defect at its intended target.
