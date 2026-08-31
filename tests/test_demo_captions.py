from __future__ import annotations

import importlib.util
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
INDEX = ROOT / "web" / "index.html"
TRACK = ROOT / "web" / "proofos-demo.en.vtt"
SCRIPT = ROOT / "scripts" / "inject_demo_captions.py"

spec = importlib.util.spec_from_file_location("inject_demo_captions", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class DemoCaptionTests(unittest.TestCase):
    def test_webvtt_exists_and_covers_the_full_demo(self):
        text = TRACK.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("WEBVTT\n"))
        cues = re.findall(r"(\d\d:\d\d:\d\d\.\d{3}) --> (\d\d:\d\d:\d\d\.\d{3})", text)
        self.assertGreaterEqual(len(cues), 10)
        self.assertEqual(cues[0][0], "00:00:00.000")
        self.assertEqual(cues[-1][1], "00:03:45.000")

    def test_deployment_transform_adds_one_default_english_caption_track(self):
        source = INDEX.read_text(encoding="utf-8")
        updated = module.captioned_html(source)
        self.assertEqual(updated.count('src="proofos-demo.en.vtt"'), 1)
        self.assertIn('kind="captions"', updated)
        self.assertIn('srclang="en"', updated)
        self.assertIn('label="English"', updated)
        self.assertRegex(updated, r'label="English"\s+default>')

    def test_transform_is_idempotent(self):
        source = INDEX.read_text(encoding="utf-8")
        once = module.captioned_html(source)
        twice = module.captioned_html(once)
        self.assertEqual(once, twice)

    def test_track_is_inside_hosted_only_section(self):
        updated = module.captioned_html(INDEX.read_text(encoding="utf-8"))
        hosted = updated.split("<!-- hosted-only:start", 1)[1].split("<!-- hosted-only:end -->", 1)[0]
        self.assertIn('src="proofos-demo.en.vtt"', hosted)


if __name__ == "__main__":
    unittest.main()
