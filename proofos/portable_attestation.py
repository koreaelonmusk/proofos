"""A valid signature proves who signed some bytes. It proves nothing else.

Four states, and this module exists to keep them apart:

    signed                     someone holding a key produced these bytes
    signed by a trusted key    that key is one the replaying environment vouches for
    authorized                 that collector is scoped to this kind and profile
    satisfies the requirement  the kernel's judgement, made somewhere else entirely

A proof bundle can carry the third and fourth nowhere. It carries an attestation
envelope -- the same one ``proofos.attestation`` defines, byte for byte -- and
the environment doing the replay supplies the registry that says whose keys mean
anything. **A bundle can carry evidence. It cannot carry permission to believe
it.**

## Nothing new is invented here

There is no second attestation format, no second canonicalization, and no
signature code. Parsing is ``ObservationAttestation.from_dict``, scoping is
``CollectorRegistry.require_scope``, and the signature check is the registered
key's own ``AttestationVerifier``. All three are trusted core and unmodified.
What this module adds is the binding between a verified envelope and the record
a bundle claims it belongs to.

## The one check that cannot survive the trip

Live ingestion spends a single-use nonce that *this runtime issued*, which is
what stops a genuine attestation being injected into a different execution or
counted twice. Offline, that check is not weakened -- it is unavailable, because
there is no runtime that issued anything and no live execution to inject into.

What replaces it is binding. The signed ``execution_id``, ``task_id``, ``kind``,
``observed_at`` and ``request_nonce`` are all checked against the record and the
bundle that claim them, so a signature cannot be moved between observations,
between tasks, or between bundles. What is genuinely not available offline is
"this runtime asked for this observation" -- and it cannot be, so it is stated
here rather than papered over.

## Without the optional dependency

Signature verification needs ``cryptography``, which is an optional extra. When
it is absent this module raises, replay demotes the record, and the answer is
ABSTAIN. An unverified signature is not a weaker yes; it is not a yes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

#: Mirrors ``proofos.ingestion.CLOCK_SKEW_TOLERANCE_SECONDS``. Clocks drift;
#: they do not run minutes ahead.
CLOCK_SKEW_TOLERANCE_SECONDS = 60.0

#: The extra that carries the signature implementation.
ATTESTATION_EXTRA = "attestation"


class AttestationUnavailable(RuntimeError):
    """Signature verification was asked for and cannot be performed here."""


class PortableAttestationRejected(ValueError):
    """A carried attestation this build will not turn into an observation."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class VerifiedObservation:
    """What a verified envelope says was observed. Still not a verdict.

    Everything here is read off signed fields. There is no ``trusted`` flag and
    no ``verdict``: whether this satisfies anything is decided by the kernel,
    over requirements this module never sees.
    """

    collector_id: str
    kind: str
    value: str
    satisfies: bool
    observed_at: float
    profile_id: str
    outcome: str


def observed_value(attestation: Any) -> str:
    """Rebuild the evidence text an ingestion would have recorded.

    Deliberately a reconstruction rather than a copy of the bundle's own
    ``value``: a value read from the file is a value an editor could change,
    while this one is derived from fields the signature covers -- except
    ``detail``, which the attestation contract does not sign. See
    ``bind_to_record`` for what that costs and what holds it down.

    ``tests/test_bundle_attestation.py`` pins this against what a real live
    ingestion produces, so the two cannot drift apart quietly.
    """
    return (f"attested {attestation.outcome.value} via "
            f"{attestation.profile_id}: {attestation.detail}")


def verify_portable(
    envelope: Mapping[str, Any],
    *,
    registry: Any,
    now: float,
    clock_skew: float = CLOCK_SKEW_TOLERANCE_SECONDS,
) -> VerifiedObservation:
    """Verify a carried attestation against a registry supplied from outside.

    ``registry`` is the trust root and it arrives as an argument. Nothing in the
    envelope -- not a key, not a fingerprint, not a ``trusted: true`` -- can add
    to it, because this function never reads a key from the envelope. It reads
    the ``collector_id``, asks the registry for that collector's record, and
    checks the signature against the key the registry holds. An envelope naming
    a collector the registry does not know is refused, however well signed.
    """
    if registry is None:
        raise PortableAttestationRejected(
            "NO_TRUST_ANCHOR",
            "no collector registry was supplied. A bundle cannot be its own "
            "trust root, so with nothing vouching for a key there is nothing "
            "to verify against")
    if not (hasattr(registry, "require_scope") and hasattr(registry, "get")):
        # Found by the chaos suite: a dict, a namespace or a stray integer
        # passed as a trust anchor used to reach `registry.require_scope` and
        # raise AttributeError out of replay. That fails closed -- nothing is
        # certified -- but it fails as a crash rather than a refusal, and a
        # caller cannot tell "your anchor is malformed" from "this library has
        # a bug". A refusal says which.
        raise PortableAttestationRejected(
            "MALFORMED_TRUST_ANCHOR",
            f"a trust anchor must be a CollectorRegistry; got "
            f"{type(registry).__name__}")

    attestation_module, registry_module = _crypto_modules()

    try:
        attestation = attestation_module.ObservationAttestation.from_dict(envelope)
    except attestation_module.AttestationError as exc:
        raise PortableAttestationRejected("MALFORMED_ATTESTATION", str(exc)) from exc

    if attestation.version != attestation_module.ATTESTATION_VERSION:
        raise PortableAttestationRejected("UNSUPPORTED_VERSION", attestation.version)

    # The registry decides who exists and what they may speak about. Both
    # failures come from trusted core, unmodified.
    try:
        record = registry.require_scope(attestation.collector_id, attestation.kind,
                                        attestation.profile_id)
    except registry_module.CollectorIdentityError as exc:
        unknown = "unknown" in str(exc) or "not active" in str(exc)
        raise PortableAttestationRejected(
            "UNKNOWN_COLLECTOR" if unknown else "COLLECTOR_SCOPE_VIOLATION",
            str(exc)) from exc

    # Against the key registered for that id, so relabelling an attestation
    # invalidates it rather than transferring it.
    try:
        record.verifier.verify(attestation)
    except attestation_module.AttestationError as exc:
        raise PortableAttestationRejected("SIGNATURE_INVALID", str(exc)) from exc

    if attestation.observed_at > now + clock_skew:
        raise PortableAttestationRejected(
            "ATTESTATION_FUTURE_DATED",
            f"observed_at is {attestation.observed_at - now:.0f}s ahead")

    return VerifiedObservation(
        collector_id=attestation.collector_id,
        kind=attestation.kind,
        value=observed_value(attestation),
        satisfies=attestation.outcome.satisfies,
        observed_at=attestation.observed_at,
        profile_id=attestation.profile_id,
        outcome=str(attestation.outcome),
    )


def bind_to_record(observation: VerifiedObservation, record: Any, *,
                   task_id: str, execution_id: str) -> None:
    """Refuse a verified signature that belongs to some other observation.

    This is what stops cut-and-paste. A signature lifted from one observation
    and dropped onto another verifies perfectly well as a signature -- the
    question is whether it is a signature over *this* record, and every field
    below is one the attestation signs.

    ``value`` is compared against the reconstruction rather than trusted from
    the file. The attestation contract does not sign ``detail``, so the tail of
    the text is not covered by the signature; what covers it is the bundle
    digest, and what this comparison adds is that the two must agree. An
    attacker who edits ``detail`` in the envelope and reseals the bundle changes
    both sides together and is caught by neither -- so the honest statement is
    that ``detail`` is descriptive text with bundle-level integrity and not
    signature-level integrity, and nothing downstream reads it for meaning.
    """
    mismatches = []
    if record.collector != observation.collector_id:
        mismatches.append(f"collector {record.collector!r} != signed "
                          f"{observation.collector_id!r}")
    if record.kind != observation.kind:
        mismatches.append(f"kind {record.kind!r} != signed {observation.kind!r}")
    if record.collected_at != observation.observed_at:
        mismatches.append(f"collected_at {record.collected_at!r} != signed "
                          f"observed_at {observation.observed_at!r}")
    if record.valid != observation.satisfies:
        mismatches.append(f"valid {record.valid!r} != signed outcome "
                          f"{observation.outcome}")
    if record.value != observation.value:
        mismatches.append("value does not match the attested observation")
    if mismatches:
        raise PortableAttestationRejected("BINDING_MISMATCH", "; ".join(mismatches))

    signed = _signed_ids(record.attestation)
    if signed["task_id"] != task_id:
        raise PortableAttestationRejected(
            "TASK_MISMATCH",
            f"signed for task {signed['task_id']!r}, carried in a bundle for "
            f"{task_id!r}")
    if execution_id and signed["execution_id"] != execution_id:
        raise PortableAttestationRejected(
            "EXECUTION_MISMATCH",
            f"signed for execution {signed['execution_id']!r}, carried in a "
            f"bundle for {execution_id!r}")


def available() -> bool:
    """Whether signature verification can be performed in this environment."""
    try:
        _crypto_modules()
    except AttestationUnavailable:
        return False
    return True


def _crypto_modules() -> tuple[Any, Any]:
    """Import the signature machinery, late and only when it is needed.

    Late so that ``proofos.bundle`` and ``proofos.replay`` stay importable in a
    zero-dependency install. A bundle that carries no attestation replays
    without ``cryptography`` ever being looked for.
    """
    try:
        from . import attestation as attestation_module
        from . import collector_registry as registry_module
    except ImportError as exc:  # pragma: no cover - exercised by the extra-less run
        raise AttestationUnavailable(
            "verifying a carried attestation needs the signature "
            f"implementation: pip install 'proofos[{ATTESTATION_EXTRA}]'. "
            "Without it a signed record cannot be checked, and an unchecked "
            "signature is not a weaker yes -- it is not a yes"
        ) from exc
    return attestation_module, registry_module


def _signed_ids(envelope: Any) -> dict[str, str]:
    if not isinstance(envelope, Mapping):
        raise PortableAttestationRejected("MALFORMED_ATTESTATION",
                                          "envelope is not an object")
    return {"task_id": str(envelope.get("task_id", "")),
            "execution_id": str(envelope.get("execution_id", ""))}


#: Tier 2. Imported from ``proofos.portable_attestation`` by whoever is
#: verifying a proof somebody else produced.
__all__ = [
    "ATTESTATION_EXTRA",
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "AttestationUnavailable",
    "PortableAttestationRejected",
    "VerifiedObservation",
    "observed_value",
    "verify_portable",
    "bind_to_record",
    "available",
]
