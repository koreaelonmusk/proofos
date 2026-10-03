from __future__ import annotations

import sys
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_extropy_jev0_verification_receipt import (  # noqa: E402
    KIND,
    VERIFIER_PATH,
    ExtropyJev0ReceiptError,
    _fixture,
    build_receipt,
)
from verify_extropy_jev0_verification_receipt import (  # noqa: E402
    ExtropyJev0ReceiptVerificationError,
    verify_receipt,
)


class ExtropyJev0VerificationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report, self.executable, self.policy, self.capabilities = _fixture()
        self.receipt = build_receipt(
            self.report,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
        )

    def verify(self, receipt=None, report=None):
        return verify_receipt(
            self.receipt if receipt is None else receipt,
            self.report if report is None else report,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
        )

    def test_receipt_is_deterministic_and_content_addressed(self):
        second = build_receipt(
            self.report,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
        )
        self.assertEqual(self.receipt, second)
        self.assertEqual(self.receipt["kind"], KIND)
        self.assertEqual(len(self.receipt["receipt_sha256"]), 64)

    def test_receipt_round_trip_rederives_exactly(self):
        result = self.verify()
        self.assertTrue(result["valid"])
        self.assertEqual(
            result["receipt_sha256"],
            self.receipt["receipt_sha256"],
        )

    def test_receipt_binds_loaded_verifier_implementation_bytes(self):
        expected = hashlib.sha256(VERIFIER_PATH.read_bytes()).hexdigest()
        self.assertEqual(self.receipt["verifier_sha256"], expected)

    def test_builder_rejects_canonical_path_that_is_not_loaded_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            unrelated = Path(directory) / "other-verifier.py"
            unrelated.write_text("def verify_execution_report(): pass\n", encoding="utf-8")
            with patch(
                "build_extropy_jev0_verification_receipt.VERIFIER_PATH",
                unrelated,
            ):
                with self.assertRaisesRegex(
                    ExtropyJev0ReceiptError,
                    "loaded provenance verifier does not match canonical verifier path",
                ):
                    build_receipt(
                        self.report,
                        executable_bytes=self.executable,
                        policy_bytes=self.policy,
                        capabilities=self.capabilities,
                    )

    def test_rejects_tampered_receipt_digest(self):
        tampered = dict(self.receipt)
        tampered["verified_record_count"] = 2
        with self.assertRaisesRegex(
            ExtropyJev0ReceiptVerificationError,
            "SHA-256 mismatch",
        ):
            self.verify(receipt=tampered)

    def test_rejects_execution_report_drift(self):
        changed = dict(self.report)
        changed["runId"] = "run-2"
        with self.assertRaisesRegex(
            ExtropyJev0ReceiptVerificationError,
            "differs from re-derivation",
        ):
            self.verify(report=changed)

    def test_rejects_receipt_schema_drift(self):
        drifted = dict(self.receipt)
        drifted["unexpected"] = True
        with self.assertRaisesRegex(
            ExtropyJev0ReceiptVerificationError,
            "schema drifted",
        ):
            self.verify(receipt=drifted)


if __name__ == "__main__":
    unittest.main()
