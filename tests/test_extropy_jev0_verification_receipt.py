from __future__ import annotations

import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_extropy_jev0_verification_receipt import (  # noqa: E402
    KIND,
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
        self.verifier = b"proofos-verifier-v1"
        self.receipt = build_receipt(
            self.report,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
            verifier_bytes=self.verifier,
        )

    def verify(self, receipt=None, report=None, verifier=None):
        return verify_receipt(
            self.receipt if receipt is None else receipt,
            self.report if report is None else report,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
            verifier_bytes=self.verifier if verifier is None else verifier,
        )

    def test_receipt_is_deterministic_and_content_addressed(self):
        second = build_receipt(
            self.report,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
            verifier_bytes=self.verifier,
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

    def test_receipt_binds_verifier_implementation_bytes(self):
        with self.assertRaisesRegex(
            ExtropyJev0ReceiptVerificationError,
            "differs from re-derivation",
        ):
            self.verify(verifier=b"different-proofos-verifier")

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
