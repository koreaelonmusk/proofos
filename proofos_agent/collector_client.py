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
    """Unauthenticated transport, restricted to a loopback collector.

    Refusing non-loopback targets keeps this from silently becoming the
    production path: a remote collector needs real identity, not an open port.
    """

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        host = urlsplit(base_url).hostname
        if host not in LOOPBACK_HOSTS:
            raise ValueError(
                f"HttpCollectorClient carries no credentials and is loopback-only; "
                f"{host!r} needs GoogleIdTokenCollectorClient"
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


def build_collector_client(
    base_url: str, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> CollectorClient:
    """Pick the transport the target actually requires.

    Loopback gets the unauthenticated client; anything else must present a
    Google-signed identity.
    """
    host = urlsplit(base_url).hostname
    if host in LOOPBACK_HOSTS:
        return HttpCollectorClient(base_url, timeout)
    return GoogleIdTokenCollectorClient(base_url, timeout)
