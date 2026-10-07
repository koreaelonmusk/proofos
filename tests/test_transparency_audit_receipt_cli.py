"""Operational CLI tests for signed transparency audit receipts."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofos.keys import encode_public_key
from proofos.quorum_certificate import QuorumCertificateSigner
from proofos.witness_gossip import WitnessGossipSigner
from tests.test_witness_gossip import T0, fixture

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from sign_transparency_audit_receipt import _write_create_only  # noqa: E402

SIGN = SCRIPTS / "sign_transparency_audit_receipt.py"
VERIFY = ROOT / "scripts" / "verify_transparency_audit_receipt.py"


class TransparencyAuditReceiptCliTests(unittest.TestCase):
    def setUp(self):
        (
            self.cp,
            self.votes,
            self.verifiers,
            self.witness_signers,
            self.policy,
            self.quorum,
        ) = fixture()
        self.gossip_signer = WitnessGossipSigner.generate("gossip-publisher-v1")
        self.bundle = self.gossip_signer.sign(
            policy=self.policy,
            result=self.quorum,
            votes=self.votes[:2],
            issued_at=T0 + 70,
        )
        self.cert_signer = QuorumCertificateSigner.generate("quorum-aggregator-v1")
        self.certificate = self.cert_signer.sign(self.quorum, issued_at=T0 + 71)

        self.auditor_key = Ed25519PrivateKey.generate()
        self.auditor_public_key = encode_public_key(self.auditor_key.public_key())

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.outside = root / "outside"
        self.outside.mkdir()
        self.gossip_path = root / "gossip.json"
        self.cert_path = root / "certificate.json"
        self.key_path = root / "auditor.pem"
        self.receipt_path = root / "receipt.json"

        self.gossip_path.write_text(
            json.dumps(self.bundle.to_dict()),
            encoding="utf-8",
        )
        self.cert_path.write_text(
            json.dumps(self.certificate.to_dict()),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            self.auditor_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def sign_cmd(self):
        return [
            sys.executable,
            str(SIGN),
            str(self.gossip_path),
            "--gossip-public-key",
            self.gossip_signer.public_key_b64(),
            "--gossip-publisher-id",
            "gossip-publisher-v1",
            "--expected-policy-digest",
            self.policy.digest(),
            "--certificate",
            str(self.cert_path),
            "--certificate-public-key",
            self.cert_signer.public_key_b64(),
            "--certificate-signer-id",
            "quorum-aggregator-v1",
            "--auditor-private-key",
            str(self.key_path),
            "--auditor-id",
            "external-auditor-v1",
            "--output",
            str(self.receipt_path),
        ]

    def verify_cmd(self):
        return [
            sys.executable,
            str(VERIFY),
            str(self.receipt_path),
            str(self.gossip_path),
            "--gossip-public-key",
            self.gossip_signer.public_key_b64(),
            "--gossip-publisher-id",
            "gossip-publisher-v1",
            "--expected-policy-digest",
            self.policy.digest(),
            "--certificate",
            str(self.cert_path),
            "--certificate-public-key",
            self.cert_signer.public_key_b64(),
            "--certificate-signer-id",
            "quorum-aggregator-v1",
            "--auditor-public-key",
            self.auditor_public_key,
            "--auditor-id",
            "external-auditor-v1",
        ]

    def create_receipt(self):
        result = subprocess.run(
            self.sign_cmd(),
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_sign_then_public_verify_works_outside_repository(self):
        signed = self.create_receipt()
        self.assertTrue(signed["valid"])
        self.assertEqual(signed["auditor_public_key"], self.auditor_public_key)

        verified = subprocess.run(
            self.verify_cmd(),
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        report = json.loads(verified.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["transparency_state"], "ACCEPTED")

    def test_signer_refuses_to_overwrite_existing_receipt(self):
        self.create_receipt()
        second = subprocess.run(
            self.sign_cmd(),
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(second.returncode, 2)
        report = json.loads(second.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("overwrite", report["detail"])

    def test_public_verifier_rejects_tampered_receipt(self):
        self.create_receipt()
        raw = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        raw["checkpoint_digest"] = "f" * 64
        self.receipt_path.write_text(json.dumps(raw), encoding="utf-8")

        result = subprocess.run(
            self.verify_cmd(),
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])

    def test_signer_rejects_non_ed25519_private_key(self):
        self.key_path.write_text("not a private key", encoding="utf-8")
        result = subprocess.run(
            self.sign_cmd(),
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("private key", report["detail"])

    def test_failed_fsync_never_publishes_partial_destination(self):
        target = pathlib.Path(self.tmp.name) / "atomic-receipt.json"
        payload = {"kind": "test-receipt", "value": 1}

        with mock.patch(
            "sign_transparency_audit_receipt.os.fsync",
            side_effect=OSError("disk full"),
        ):
            with self.assertRaises(OSError):
                _write_create_only(target, payload)

        self.assertFalse(target.exists())
        self.assertEqual(
            list(target.parent.glob(f".{target.name}.*.tmp")),
            [],
        )

        _write_create_only(target, payload)
        self.assertEqual(
            json.loads(target.read_text(encoding="utf-8")),
            payload,
        )

    def test_public_verifier_exposes_no_private_key_argument(self):
        result = subprocess.run(
            [sys.executable, str(VERIFY), "--help"],
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("private-key", result.stdout)
        self.assertIn("--auditor-public-key", result.stdout)


if __name__ == "__main__":
    unittest.main()
