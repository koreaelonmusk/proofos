"""Wire the hosted demo's WebVTT captions into the HTML5 player.

The offline single-file console deliberately strips the hosted-only demo section.
This script runs only in the GitHub Pages build, after the committed evidence
bundle drift check, so it cannot rewrite source evidence or make the offline
console contact the network.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "web" / "index.html"
TRACK = ROOT / "web" / "proofos-demo.en.vtt"

TRACK_MARKUP = '''      <track
        kind="captions"
        src="proofos-demo.en.vtt"
        srclang="en"
        label="English"
        default>\n'''


def captioned_html(text: str) -> str:
    """Return hosted markup with one native English caption track.

    Fail closed when the expected video source moves instead of silently
    deploying a page whose subtitles disappeared again.
    """
    if 'src="proofos-demo.en.vtt"' in text:
        return text

    needle = '''      <source
        src="https://github.com/koreaelonmusk/proofos/releases/download/hackathon-demo-2026/proofos-hackathon-final.mp4"
        type="video/mp4">\n'''
    if text.count(needle) != 1:
        raise RuntimeError("demo video source changed; caption track was not injected")

    text = text.replace(needle, needle + TRACK_MARKUP)
    text = text.replace(
        "silent, with English subtitles as a separate file",
        "silent &middot; English captions enabled by default (CC)",
    )
    return text


def main() -> int:
    if not TRACK.exists():
        raise SystemExit("missing web/proofos-demo.en.vtt")
    source = INDEX.read_text(encoding="utf-8")
    updated = captioned_html(source)
    INDEX.write_text(updated, encoding="utf-8", newline="\n")
    print("demo captions: native English WebVTT track wired into hosted player")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
