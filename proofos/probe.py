"""Real HTTP health probe.

This is an evidence *collector*: it performs an actual network request and
reports what came back. It never invents a result. Only a genuine, well-formed,
healthy HTTP response is reported as healthy; every other path -- timeout,
connection failure, error status, unparseable or off-contract body -- is
reported as not healthy, so the verifier fails closed.

Uses the standard library so that collecting evidence adds no dependency that
could itself become an unverified trust assumption.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum

DEFAULT_TIMEOUT_SECONDS = 5.0
# Cap what we read so a hostile or runaway endpoint cannot exhaust memory.
MAX_BODY_BYTES = 64 * 1024


COLLECTOR_ID = "proofos.probe.http"


class ProbeOutcome(StrEnum):
    HEALTHY = "HEALTHY"
    UNHEALTHY_STATUS = "UNHEALTHY_STATUS"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    REDIRECTED = "REDIRECTED"
    TIMEOUT = "TIMEOUT"
    UNREACHABLE = "UNREACHABLE"


class _RedirectRefused(urllib.error.HTTPError):
    """Raised instead of following a redirect."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so evidence always describes the host we asked.

    Following a redirect would let whoever controls the health URL point the
    probe at a machine of their choosing while the recorded evidence still named
    the original address. That is forged provenance, so a redirect is reported
    rather than followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _RedirectRefused(req.full_url, code, f"redirect to {newurl}", headers, fp)


_OPENER = urllib.request.build_opener(_NoRedirects())


@dataclass(frozen=True)
class ProbeResult:
    outcome: ProbeOutcome
    detail: str
    url: str
    status_code: int | None = None
    collector: str = COLLECTOR_ID

    @property
    def healthy(self) -> bool:
        """True only when a real response arrived and satisfied the contract."""
        return self.outcome is ProbeOutcome.HEALTHY

    @property
    def observed_response(self) -> bool:
        """True when bytes actually came back from the network."""
        return self.outcome in {
            ProbeOutcome.HEALTHY,
            ProbeOutcome.UNHEALTHY_STATUS,
            ProbeOutcome.MALFORMED_RESPONSE,
        }


def probe_health(
    url: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ProbeResult:
    """GET ``url`` and report the observed health of the service.

    The endpoint must return 2xx with a JSON body containing ``{"status": "ok"}``.
    Anything else is not healthy.
    """
    request = urllib.request.Request(url, method="GET")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status = getattr(response, "status", None)
            # A redirect handler cannot see a same-URL rewrite, so confirm the
            # response really came from the address we asked for.
            final_url = getattr(response, "url", url)
            if final_url != url:
                return ProbeResult(
                    outcome=ProbeOutcome.REDIRECTED,
                    detail=f"{url} redirected to {final_url}; refusing to follow",
                    url=url,
                )
            body = response.read(MAX_BODY_BYTES)
    except _RedirectRefused as exc:
        return ProbeResult(
            outcome=ProbeOutcome.REDIRECTED,
            detail=f"{url} returned HTTP {exc.code} {exc.reason}; refusing to follow",
            url=url,
            status_code=exc.code,
        )
    except urllib.error.HTTPError as exc:
        # A real response arrived, carrying an error status.
        return ProbeResult(
            outcome=ProbeOutcome.UNHEALTHY_STATUS,
            detail=f"HTTP {exc.code} from {url}",
            url=url,
            status_code=exc.code,
        )
    except socket.timeout:
        return ProbeResult(
            outcome=ProbeOutcome.TIMEOUT,
            detail=f"No response from {url} within {timeout}s",
            url=url,
        )
    except urllib.error.URLError as exc:
        # urllib wraps socket timeouts in URLError on some platforms.
        if isinstance(exc.reason, socket.timeout):
            return ProbeResult(
                outcome=ProbeOutcome.TIMEOUT,
                detail=f"No response from {url} within {timeout}s",
                url=url,
            )
        return ProbeResult(
            outcome=ProbeOutcome.UNREACHABLE,
            detail=f"Could not reach {url}: {exc.reason}",
            url=url,
        )
    except (OSError, ValueError) as exc:
        return ProbeResult(
            outcome=ProbeOutcome.UNREACHABLE,
            detail=f"Could not reach {url}: {type(exc).__name__}",
            url=url,
        )

    if status is None or not 200 <= status < 300:
        return ProbeResult(
            outcome=ProbeOutcome.UNHEALTHY_STATUS,
            detail=f"HTTP {status} from {url}",
            url=url,
            status_code=status,
        )

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ProbeResult(
            outcome=ProbeOutcome.MALFORMED_RESPONSE,
            detail=f"HTTP {status} from {url} with a non-JSON body",
            url=url,
            status_code=status,
        )

    if not isinstance(payload, dict) or "status" not in payload:
        return ProbeResult(
            outcome=ProbeOutcome.MALFORMED_RESPONSE,
            detail=f"HTTP {status} from {url} without a 'status' field",
            url=url,
            status_code=status,
        )

    reported = payload.get("status")
    if reported != "ok":
        return ProbeResult(
            outcome=ProbeOutcome.UNHEALTHY_STATUS,
            detail=f"HTTP {status} from {url} reporting status={reported!r}",
            url=url,
            status_code=status,
        )

    return ProbeResult(
        outcome=ProbeOutcome.HEALTHY,
        detail=f"HTTP {status} from {url} reporting status='ok'",
        url=url,
        status_code=status,
    )
