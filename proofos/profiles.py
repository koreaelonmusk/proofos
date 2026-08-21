"""Server-owned collection profiles.

Putting the probe behind an HTTP API creates an SSRF surface: if a caller can
name the target, the collector becomes a confused deputy with network reach the
caller does not have. So the caller does not name the target. It names a
profile, and the collector owns what that profile means.

A profile is configuration, not an agent message. Nothing a model says can
create one, edit one, or widen one. Unknown profile, or a profile that does not
cover the requested evidence kind: denied.

Scope of the SSRF defence, stated plainly rather than overclaimed:

* the caller cannot supply a URL, a scheme, a host, a port, or a path;
* schemes are restricted to the profile's own configuration;
* redirects stay disabled, so a target cannot bounce the probe elsewhere;
* responses are size-capped and content-type checked.

What this does **not** solve is DNS rebinding. A profile naming a hostname
resolves that hostname at request time, and a hostile resolver could answer
with an internal address. Pinning the resolved address is the real fix and is
not implemented here; profiles that must not be rebound should name a literal
address. This limitation is recorded rather than papered over.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024

#: Only these schemes may ever appear in a profile target. file:, ftp:, gopher:
#: and data: are not merely unused -- they are refused at construction.
ALLOWED_SCHEMES = frozenset({"http", "https"})


class ProfileError(ValueError):
    """Raised when a profile is unknown, misconfigured, or misused."""


class UnknownProfile(ProfileError):
    pass


class ProfileScopeViolation(ProfileError):
    pass


@dataclass(frozen=True)
class CollectionProfile:
    """One approved thing a collector is allowed to go and look at."""

    profile_id: str
    collector_id: str
    allowed_kind: str
    target: str
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    expected_content_type: str = "application/json"
    expected_status_field: str = "status"
    expected_status_value: str = "ok"

    def __post_init__(self) -> None:
        parts = urlsplit(self.target)
        if parts.scheme not in ALLOWED_SCHEMES:
            raise ProfileError(
                f"profile {self.profile_id!r} targets scheme {parts.scheme!r}; "
                f"allowed: {sorted(ALLOWED_SCHEMES)}"
            )
        if not parts.netloc:
            raise ProfileError(f"profile {self.profile_id!r} has no host")
        if self.timeout <= 0:
            raise ProfileError(f"profile {self.profile_id!r} needs a positive timeout")
        if self.max_response_bytes <= 0:
            raise ProfileError(
                f"profile {self.profile_id!r} needs a positive response cap"
            )


class ProfileRegistry:
    """The set of approved profiles, frozen once the service starts."""

    def __init__(self) -> None:
        self._profiles: dict[str, CollectionProfile] = {}
        self._sealed = False

    @property
    def sealed(self) -> bool:
        return self._sealed

    def register(self, profile: CollectionProfile) -> CollectionProfile:
        if self._sealed:
            raise ProfileError(
                f"cannot register {profile.profile_id!r}: profiles are sealed. "
                "What a collector may reach must not change while it is running."
            )
        if profile.profile_id in self._profiles:
            raise ProfileError(f"duplicate profile {profile.profile_id!r}")
        self._profiles[profile.profile_id] = profile
        return profile

    def seal(self) -> "ProfileRegistry":
        self._sealed = True
        return self

    def get(self, profile_id: str) -> CollectionProfile:
        try:
            return self._profiles[profile_id]
        except KeyError:
            raise UnknownProfile(f"unknown profile {profile_id!r}") from None

    def resolve(
        self, profile_id: str, kind: str, collector_id: str | None = None
    ) -> CollectionProfile:
        """Look up a profile and confirm it covers this request.

        The kind is checked against the profile rather than trusted, so a caller
        cannot ask a runtime-health profile to produce test evidence.
        """
        profile = self.get(profile_id)
        if profile.allowed_kind != kind:
            raise ProfileScopeViolation(
                f"profile {profile_id!r} covers {profile.allowed_kind!r} evidence, "
                f"not {kind!r}"
            )
        if collector_id is not None and profile.collector_id != collector_id:
            raise ProfileScopeViolation(
                f"profile {profile_id!r} belongs to {profile.collector_id!r}, "
                f"not {collector_id!r}"
            )
        return profile

    def profiles(self) -> tuple[CollectionProfile, ...]:
        return tuple(self._profiles.values())

    def ids(self) -> tuple[str, ...]:
        return tuple(self._profiles)


RUNTIME_HEALTH_PROFILE = "runtime-health-v1"


def default_profiles(
    target: str, collector_id: str, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> ProfileRegistry:
    """The profiles this collector serves, sealed."""
    registry = ProfileRegistry()
    registry.register(
        CollectionProfile(
            profile_id=RUNTIME_HEALTH_PROFILE,
            collector_id=collector_id,
            allowed_kind="runtime",
            target=target,
            timeout=timeout,
        )
    )
    return registry.seal()


def describe(profiles: Mapping[str, CollectionProfile]) -> list[dict]:
    """Public description of what is on offer -- without leaking targets.

    The target is deliberately omitted. A caller needs to know which profiles
    exist, not what internal address each one reaches.
    """
    return [
        {
            "profile_id": p.profile_id,
            "allowed_kind": p.allowed_kind,
            "collector_id": p.collector_id,
        }
        for p in profiles.values()
    ]
