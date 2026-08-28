"""A minimal real HTTP service for the local demo.

The recovery probe must talk to something over an actual socket. In production
this is the deployed Cloud Run service; locally it is this process. Point
PROOFOS_HEALTH_URL at a Cloud Run URL to probe the real deployment instead.
"""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator


class HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.rstrip("/") not in {"/healthz", ""}:
            self.send_error(404, "not found")
            return
        body = json.dumps(
            {"status": "ok", "error_rate": 0.0, "window_seconds": 300}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        """Silence per-request logging so it does not pollute the demo report."""


@contextlib.contextmanager
def running_health_service(port: int = 0) -> Iterator[str]:
    """Run the health service on an ephemeral port; yield its /healthz URL."""
    server = ThreadingHTTPServer(("127.0.0.1", port), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/healthz"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
