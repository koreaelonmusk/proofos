"""Transport to the collector service.

Two implementations behind one interface:

* ``HttpCollectorClient`` -- plain HTTP, for a loopback collector in tests and
  local runs. It carries no credentials and must never be pointed at anything
  but a trusted local process.
* ``GoogleIdTokenCollectorClient`` -- obtains a Google-signed OIDC ID token from
  the ambient service identity, with the collector's URL as the audience, and
  presents it as a bearer token. This is what a private Cloud Run collector
  accepts: real identity issued by Google, not a header the caller made up.

An ``X-Agent-Role: collector`` header would be data, not identity. Anything that
can reach the endpoint can set it. Only a token the receiver can independently
validate is worth anything, which is why the cloud path uses OIDC and the local
path is restricted to loopback.

Nothing here logs an Authorization header, a token, or a key.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Protocol
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_SECONDS = 15.0
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class CollectorUnavailable(RuntimeError):
    """Raised when the collector could not be reached or refused the request.

    Always a failure to collect. Never a reason to proceed as though evidence
    had been obtained.
    """


class CollectorClient(Protocol):
    def collect(
        self,
        execution_id: str,
        task_id: str,
        evidence_kind: str,
        profile_id: str,
        request_nonce: str,
    ) -> dict[str, Any]: ...


class _BaseHttpClient:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _auth_header(self) -> dict[str, str]:
        return {}

    def collect(
        self,
        execution_id: str,
        task_id: str,
        evidence_kind: str,
        profile_id: str,
        request_nonce: str,
    ) -> dict[str, Any]:
        body = json.dumps(
            {
                "execution_id": execution_id,
                "task_id": task_id,
                "evidence_kind": evidence_kind,
                "profile_id": profile_id,
                "request_nonce": request_nonce,
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/v1/collect",
            data=body,
            headers={"Content-Type": "application/json", **self._auth_header()},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            # The status is useful; the body may be attacker-influenced, so it
            # is not carried into the failure message.
            raise CollectorUnavailable(
                f"collector returned HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CollectorUnavailable(
                f"collector unreachable: {type(exc.reason).__name__}"
            ) from exc
        except (OSError, ValueError) as exc:
            raise CollectorUnavailable(
                f"collector call failed: {type(exc).__name__}"
            ) from exc

        if not isinstance(payload, dict) or "attestation" not in payload:
            raise CollectorUnavailable("collector response carried no attestation")
        return payload["attestation"]


class HttpCollectorClient(_BaseHttpClient):
    """Unauthenticated transport.

    Loopback needs no argument. Any other host does: reaching a collector over
    a network without credentials means the only thing between a caller and the
    signing service is network reachability -- a real boundary on a private
    container network, and none at all on the internet. Naming ``allow_remote``
    makes that a decision someone took rather than one that happened.

    Note what it does not weaken. The attestation signature is checked either
    way. An unauthenticated transport governs who may *call* the collector; it
    never affects what the collector can be made to say.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        allow_remote: bool = False,
    ) -> None:
        host = urlsplit(base_url).hostname
        if host not in LOOPBACK_HOSTS and not allow_remote:
            raise ValueError(
                f"HttpCollectorClient carries no credentials and {host!r} is not "
                "loopback. Use GoogleIdTokenCollectorClient, or pass "
                "allow_remote=True to accept network reachability as the boundary."
            )
        super().__init__(base_url, timeout)


class GoogleIdTokenCollectorClient(_BaseHttpClient):
    """Authenticated transport for a private Cloud Run collector.

    IMPLEMENTED, NOT PROVEN: this has never run against Google Cloud. The token
    fetch, the audience binding, and ``roles/run.invoker`` enforcement are all
    unverified until a real deployment exercises them.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        audience: str | None = None,
    ) -> None:
        super().__init__(base_url, timeout)
        # Cloud Run expects the audience to be the receiving service's URL.
        self.audience = audience or self.base_url

    def _auth_header(self) -> dict[str, str]:
        try:
            import google.auth.transport.requests
            import google.oauth2.id_token
        except ImportError as exc:  # pragma: no cover - google-auth is a dependency
            raise CollectorUnavailable(
                "google-auth is required for authenticated collection"
            ) from exc

        try:
            token = google.oauth2.id_token.fetch_id_token(
                google.auth.transport.requests.Request(), self.audience
            )
        except Exception as exc:  # noqa: BLE001 - never leak token material
            raise CollectorUnavailable(
                f"could not obtain an ID token for the collector: {type(exc).__name__}"
            ) from exc

        return {"Authorization": f"Bearer {token}"}


AUTH_AUTO = "auto"
AUTH_NONE = "none"
AUTH_GOOGLE_OIDC = "google-oidc"
AUTH_MODES = (AUTH_AUTO, AUTH_NONE, AUTH_GOOGLE_OIDC)


def build_collector_client(
    base_url: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    auth: str = AUTH_AUTO,
) -> CollectorClient:
    """Pick the transport, defaulting to the safer choice.

    ``auto`` means loopback is unauthenticated and anything else must present a
    Google-signed identity -- the right default, since the common non-loopback
    case is Cloud Run. A private container network is the case in between: the
    collector is reachable by hostname and there is no Google identity to
    obtain, so such a deployment says ``none`` explicitly rather than having the
    requirement quietly dropped on its behalf.
    """
    if auth not in AUTH_MODES:
        raise ValueError(f"unknown collector auth mode {auth!r}; allowed: {AUTH_MODES}")

    if auth == AUTH_GOOGLE_OIDC:
        return GoogleIdTokenCollectorClient(base_url, timeout)
    if auth == AUTH_NONE:
        return HttpCollectorClient(base_url, timeout, allow_remote=True)

    host = urlsplit(base_url).hostname
    if host in LOOPBACK_HOSTS:
        return HttpCollectorClient(base_url, timeout)
    return GoogleIdTokenCollectorClient(base_url, timeout)
