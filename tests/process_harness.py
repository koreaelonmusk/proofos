"""Start the collector as a genuinely separate OS process.

An in-memory TestClient would prove nothing about process separation: the point
of this milestone is that the signing key lives somewhere the runtime cannot
reach, and a key in the same interpreter is reachable. So the collector is
launched with the real interpreter, talks over a real TCP socket, and its
private key is generated inside that process and never crosses back.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class CollectorProcess:
    """A collector service running in its own OS process."""

    def __init__(self, target_url: str, collector_id: str = "collector-http-v1"):
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.target_url = target_url
        self.collector_id = collector_id
        self._proc: subprocess.Popen | None = None
        self._key_dir: tempfile.TemporaryDirectory | None = None
        self.public_key_b64: str = ""

    @property
    def pid(self) -> int:
        if self._proc is None:
            raise RuntimeError("collector process is not running")
        return self._proc.pid

    def start(self, timeout: float = 60.0) -> "CollectorProcess":
        self._key_dir = tempfile.TemporaryDirectory()
        key_path = os.path.join(self._key_dir.name, "collector.pub")

        env = dict(os.environ)
        env.update(
            {
                "PROOFOS_COLLECTOR_ID": self.collector_id,
                "PROOFOS_COLLECTOR_TARGET": self.target_url,
                "PROOFOS_COLLECTOR_PUBKEY_FILE": key_path,
                "PROOFOS_COLLECTOR_TIMEOUT": "5",
                "PYTHONPATH": os.getcwd(),
                "PYTHONUNBUFFERED": "1",
            }
        )
        # No private key is passed in: the process generates its own, and only
        # the public half is ever written out.
        env.pop("PROOFOS_COLLECTOR_PRIVATE_KEY", None)

        self._proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "proofos_collector.app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--log-level",
                "warning",
            ],
            env=env,
            cwd=os.getcwd(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(
                    f"collector process exited early with {self._proc.returncode}"
                )
            try:
                with urllib.request.urlopen(
                    f"{self.base_url}/healthz", timeout=2
                ) as response:
                    if response.status == 200:
                        break
            except (urllib.error.URLError, OSError):
                time.sleep(0.15)
        else:
            self.stop()
            raise RuntimeError("collector process did not become healthy")

        for _ in range(100):
            if os.path.exists(key_path) and os.path.getsize(key_path) > 0:
                break
            time.sleep(0.05)
        with open(key_path, encoding="utf-8") as handle:
            self.public_key_b64 = handle.read().strip()
        if not self.public_key_b64:
            self.stop()
            raise RuntimeError("collector did not publish a public key")
        return self

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self._proc.kill()
                self._proc.wait(timeout=10)
            self._proc = None
        if self._key_dir is not None:
            self._key_dir.cleanup()
            self._key_dir = None

    def __enter__(self) -> "CollectorProcess":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
