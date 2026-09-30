"""Download one GitHub Actions artifact with bounded eventual-consistency retries.

The source workflow and run identity are verified separately before this helper is
called. This downloader adds transport hardening:

- exact run-scoped artifact name selection
- expired/ambiguous artifact rejection
- fresh GitHub redirect acquisition on every retry
- no Authorization header forwarded to the blob host
- bounded payload size
- exactly one JSON file, whether GitHub returns raw bytes or a ZIP archive
- no token or signed redirect URL in logs
"""

from __future__ import annotations

import argparse
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import time
from typing import Any
from urllib.parse import urlsplit
from zipfile import BadZipFile, ZipFile

import requests

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 512 * 1024
DEFAULT_ATTEMPTS = 6
RETRYABLE_STATUS = {404, 408, 409, 425, 429, 500, 502, 503, 504}
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_.-]+\.json$")


class ArtifactDownloadError(RuntimeError):
    pass


def _validated_repo(value: str) -> str:
    value = value.strip()
    if REPO_RE.fullmatch(value) is None:
        raise ArtifactDownloadError("repository must be owner/name")
    return value


def _validated_run_id(value: str | int) -> int:
    try:
        run_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ArtifactDownloadError("run id must be a positive integer") from exc
    if run_id <= 0:
        raise ArtifactDownloadError("run id must be a positive integer")
    return run_id


def _validated_artifact_name(value: str) -> str:
    value = value.strip()
    if ARTIFACT_RE.fullmatch(value) is None:
        raise ArtifactDownloadError("artifact name must be a simple JSON filename")
    return value


def _github_headers(token: str) -> dict[str, str]:
    token = token.strip()
    if not token:
        raise ArtifactDownloadError("GitHub token is unavailable")
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "proofos-artifact-fetch/1",
    }


def _safe_json_bytes(raw: bytes) -> bytes:
    if len(raw) > MAX_JSON_BYTES:
        raise ArtifactDownloadError("artifact JSON exceeds size limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactDownloadError("artifact is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ArtifactDownloadError("artifact JSON must be an object")
    return raw


def _extract_json_bytes(payload: bytes, artifact_name: str) -> bytes:
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ArtifactDownloadError("artifact payload exceeds size limit")

    if not payload.startswith(b"PK\x03\x04"):
        return _safe_json_bytes(payload)

    try:
        with ZipFile(BytesIO(payload)) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) != 1:
                raise ArtifactDownloadError(
                    "artifact archive must contain exactly one file"
                )
            member = members[0]
            path = PurePosixPath(member.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.name != artifact_name
            ):
                raise ArtifactDownloadError("artifact archive filename is invalid")
            if member.file_size > MAX_JSON_BYTES:
                raise ArtifactDownloadError("artifact JSON exceeds size limit")
            raw = archive.read(member)
    except BadZipFile as exc:
        raise ArtifactDownloadError("artifact ZIP is malformed") from exc

    return _safe_json_bytes(raw)


def _select_artifact(payload: Any, *, run_id: int, artifact_name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ArtifactDownloadError("artifact listing is not an object")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise ArtifactDownloadError("artifact listing has no artifacts array")

    matches: list[dict[str, Any]] = []
    for item in artifacts:
        if not isinstance(item, dict) or item.get("name") != artifact_name:
            continue
        workflow_run = item.get("workflow_run")
        if not isinstance(workflow_run, dict) or workflow_run.get("id") != run_id:
            continue
        matches.append(item)

    if len(matches) != 1:
        raise ArtifactDownloadError(
            f"expected exactly one artifact named {artifact_name}"
        )

    artifact = matches[0]
    if artifact.get("expired") is True:
        raise ArtifactDownloadError("artifact is expired")
    artifact_id = artifact.get("id")
    archive_url = artifact.get("archive_download_url")
    if not isinstance(artifact_id, int) or artifact_id <= 0:
        raise ArtifactDownloadError("artifact id is invalid")
    if not isinstance(archive_url, str) or not archive_url.startswith(
        "https://api.github.com/"
    ):
        raise ArtifactDownloadError("artifact download URL is invalid")
    return artifact


def _retry_delay(attempt: int) -> float:
    return min(2.0 ** attempt, 15.0)


def _list_artifact(
    session: requests.Session,
    *,
    repo: str,
    run_id: int,
    artifact_name: str,
    headers: dict[str, str],
    attempts: int,
    sleep_fn=time.sleep,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            response = session.get(
                url,
                headers=headers,
                params={"per_page": 100},
                timeout=15,
            )
            if response.status_code in RETRYABLE_STATUS:
                raise ArtifactDownloadError(
                    f"artifact listing temporarily unavailable ({response.status_code})"
                )
            if response.status_code != 200:
                raise ArtifactDownloadError(
                    f"artifact listing failed with HTTP {response.status_code}"
                )
            return _select_artifact(
                response.json(),
                run_id=run_id,
                artifact_name=artifact_name,
            )
        except (
            requests.RequestException,
            ValueError,
            ArtifactDownloadError,
        ) as exc:
            last_error = exc
            if attempt + 1 >= attempts:
                break
            sleep_fn(_retry_delay(attempt))

    raise ArtifactDownloadError(
        f"artifact metadata unavailable after {attempts} attempts"
    ) from last_error


def _download_payload(
    session: requests.Session,
    *,
    archive_url: str,
    headers: dict[str, str],
    attempts: int,
    sleep_fn=time.sleep,
) -> bytes:
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            gateway = session.get(
                archive_url,
                headers=headers,
                allow_redirects=False,
                timeout=15,
            )
            if gateway.status_code in RETRYABLE_STATUS:
                raise ArtifactDownloadError(
                    f"artifact gateway temporarily unavailable ({gateway.status_code})"
                )

            if gateway.status_code == 200:
                payload = gateway.content
            elif gateway.status_code in {301, 302, 303, 307, 308}:
                location = gateway.headers.get("Location", "").strip()
                parts = urlsplit(location)
                if (
                    parts.scheme != "https"
                    or not parts.hostname
                    or parts.username is not None
                    or parts.password is not None
                ):
                    raise ArtifactDownloadError("artifact redirect is not a safe HTTPS URL")

                # Deliberately omit the GitHub Authorization header on the
                # short-lived blob URL.
                blob = session.get(
                    location,
                    headers={"User-Agent": "proofos-artifact-fetch/1"},
                    timeout=20,
                )
                if blob.status_code in RETRYABLE_STATUS:
                    raise ArtifactDownloadError(
                        f"artifact blob temporarily unavailable ({blob.status_code})"
                    )
                if blob.status_code != 200:
                    raise ArtifactDownloadError(
                        f"artifact blob failed with HTTP {blob.status_code}"
                    )
                payload = blob.content
            else:
                raise ArtifactDownloadError(
                    f"artifact gateway failed with HTTP {gateway.status_code}"
                )

            if len(payload) > MAX_ARTIFACT_BYTES:
                raise ArtifactDownloadError("artifact payload exceeds size limit")
            return payload
        except (requests.RequestException, ArtifactDownloadError) as exc:
            last_error = exc
            if attempt + 1 >= attempts:
                break
            sleep_fn(_retry_delay(attempt))

    raise ArtifactDownloadError(
        f"artifact download unavailable after {attempts} attempts"
    ) from last_error


def download_artifact(
    *,
    repo: str,
    run_id: int,
    artifact_name: str,
    output: Path,
    token: str,
    attempts: int = DEFAULT_ATTEMPTS,
    session: requests.Session | None = None,
    sleep_fn=time.sleep,
) -> dict[str, Any]:
    repo = _validated_repo(repo)
    run_id = _validated_run_id(run_id)
    artifact_name = _validated_artifact_name(artifact_name)
    if attempts < 1 or attempts > 10:
        raise ArtifactDownloadError("attempt count must be between 1 and 10")

    headers = _github_headers(token)
    session = session or requests.Session()
    artifact = _list_artifact(
        session,
        repo=repo,
        run_id=run_id,
        artifact_name=artifact_name,
        headers=headers,
        attempts=attempts,
        sleep_fn=sleep_fn,
    )
    payload = _download_payload(
        session,
        archive_url=artifact["archive_download_url"],
        headers=headers,
        attempts=attempts,
        sleep_fn=sleep_fn,
    )
    raw = _extract_json_bytes(payload, artifact_name)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    return {
        "artifact_id": artifact["id"],
        "artifact_name": artifact_name,
        "run_id": run_id,
        "bytes": len(raw),
    }


def _self_test() -> None:
    from zipfile import ZIP_DEFLATED, ZipFile

    name = "vercel-123.json"
    raw = b'{"schema_version":1,"status":"ok"}'
    assert _extract_json_bytes(raw, name) == raw

    buf = BytesIO()
    with ZipFile(buf, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(name, raw)
    assert _extract_json_bytes(buf.getvalue(), name) == raw

    listing = {
        "artifacts": [
            {
                "id": 9,
                "name": name,
                "expired": False,
                "archive_download_url": (
                    "https://api.github.com/repos/o/r/actions/artifacts/9/zip"
                ),
                "workflow_run": {"id": 123},
            }
        ]
    }
    selected = _select_artifact(listing, run_id=123, artifact_name=name)
    assert selected["id"] == 9

    for bad in (
        b"not-json",
        b"[]",
    ):
        try:
            _extract_json_bytes(bad, name)
        except ArtifactDownloadError:
            pass
        else:
            raise AssertionError("invalid artifact payload was accepted")

    print("run artifact downloader self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo")
    parser.add_argument("--run-id")
    parser.add_argument("--artifact")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        _self_test()
        return 0

    if not args.repo or not args.run_id or not args.artifact or args.output is None:
        parser.error("--repo, --run-id, --artifact and --output are required")

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    try:
        result = download_artifact(
            repo=args.repo,
            run_id=_validated_run_id(args.run_id),
            artifact_name=args.artifact,
            output=args.output,
            token=token,
            attempts=args.attempts,
        )
    except ArtifactDownloadError as exc:
        print(f"artifact download FAILED: {exc}", file=sys.stderr)
        return 1

    print(
        "artifact download OK: "
        f"{result['artifact_name']} run={result['run_id']} bytes={result['bytes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
