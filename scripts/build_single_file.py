"""Inline the judge console into one self-contained page.

The hosted site loads three files. Some destinations serve exactly one, and a
page that quietly fails to fetch its evidence would be worse than no page, so
this produces a version with the stylesheet, the script, and the proof bundle
embedded.

The output deliberately omits the document skeleton (``<!doctype>``, ``<html>``,
``<head>``, ``<body>``). Hosts that wrap a fragment need it that way, and every
browser renders the fragment on its own regardless.

Run:  python scripts/build_single_file.py
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
OUT = WEB / "dist" / "proofos-console.html"

FORBIDDEN = [
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "google api key"),
    (re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"), "oauth token"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."), "jwt"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"proofos-collector-[a-z0-9]+-[a-z]+\.a\.run\.app"), "collector url"),
]

#: Hosts the page may reach: none. Fonts come from the system stack and the
#: evidence is inlined, so a judging environment with a strict CSP, a captive
#: portal, or no network at all renders exactly what was designed.
#:
#: Checking hosts rather than paths matters here, because the bundle
#: legitimately *mentions* "/executions" when describing a past defect, and a
#: guard that cannot tell a citation from a call is one that gets switched off
#: the first time it cries wolf.
ALLOWED_HOSTS = ()

#: A region of the hosted page that has no place in the offline copy. Today that
#: is the demo video, which streams from a release server -- exactly the kind of
#: dependency this build exists to remove.
#:
#: Removing markup before checking it would be a hole big enough to drive a
#: tracker through, so the region is inspected on its way out: it may reference
#: whatever hosts it needs, and it may not carry anything that executes.
HOSTED_ONLY = re.compile(
    r"<!--\s*hosted-only:start.*?<!--\s*hosted-only:end\s*-->", re.S
)
NOT_IN_HOSTED_ONLY = (
    (re.compile(r"<script\b", re.I), "a script element"),
    (re.compile(r"\son[a-z]+\s*=", re.I), "an inline event handler"),
    (re.compile(r"javascript:", re.I), "a javascript: url"),
    (re.compile(r"<iframe\b", re.I), "an iframe"),
)

#: Anything that could start work rather than replay it. A judge-facing page
#: able to reach an execution endpoint is a page able to spend quota, and it
#: stops being a replay the moment it does.
NETWORK_CALLS = re.compile(
    r"\b(XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts)\b"
)
FETCH_ARGS = re.compile(r"fetch\(\s*([A-Za-z_$][\w$]*|\"[^\"]*\"|'[^']*')")
URLS = re.compile(r"https?://([A-Za-z0-9.\-]+)")


def read(name: str) -> str:
    path = WEB / name
    if not path.exists():
        raise SystemExit(f"missing {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def build() -> str:
    html = read("index.html")
    css = read("styles.css")
    js = read("app.js")
    bundle = json.loads(read("proof-bundle.json"))

    # Keep only what lives inside <body>, then drop the external references the
    # inlined copies replace.
    body = html.split("<body>", 1)[1].split("</body>", 1)[0]
    body = body.replace('<script src="app.js"></script>', "")

    for removed in HOSTED_ONLY.findall(body):
        for pattern, label in NOT_IN_HOSTED_ONLY:
            if pattern.search(removed):
                raise SystemExit(
                    f"REFUSING: a hosted-only region contains {label}; "
                    "that region is not checked for hosts, so it may not run code"
                )
    body = HOSTED_ONLY.sub("", body)

    title = re.search(r"<title>(.*?)</title>", html, re.S).group(1).strip()
    fonts = re.findall(r'<link rel="(?:preconnect|stylesheet)"[^>]*>', html)
    fonts = [tag for tag in fonts if "fonts." in tag]

    # </script> inside a JSON string would close the block early.
    payload = json.dumps(bundle, ensure_ascii=False).replace("</", "<\\/")

    return "\n".join(
        [
            f"<title>{title}</title>",
            *fonts,
            "<style>",
            css,
            "</style>",
            body.strip(),
            "<script>",
            f"window.PROOFOS_BUNDLE = {payload};",
            js,
            "</script>",
            "",
        ]
    )


def verify(page: str) -> None:
    for pattern, label in FORBIDDEN:
        if pattern.search(page):
            raise SystemExit(f"REFUSING: page contains {label}")
    for host in sorted(set(URLS.findall(page))):
        if host not in ALLOWED_HOSTS:
            raise SystemExit(f"REFUSING: page would contact {host}")

    found = NETWORK_CALLS.search(page)
    if found:
        raise SystemExit(f"REFUSING: page can open a connection via {found.group(1)}")

    for arg in FETCH_ARGS.findall(page):
        if arg != "BUNDLE_URL":
            raise SystemExit(f"REFUSING: page fetches {arg}, not the bundle")

    if "PROOFOS_BUNDLE" not in page:
        raise SystemExit("REFUSING: bundle was not inlined")


def main() -> int:
    page = build()
    verify(page)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}  ({len(page):,} bytes, self-contained)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
