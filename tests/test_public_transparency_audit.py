"""Offline public transparency audit CLI tests."""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from audit_transparency import audit  # noqa: E402
from proofos.quorum_certificate import (  # noqa: E402
    QuorumCertificateSigner,
)
from proofos.witness_gossip import (  # noqa: E402
    WitnessGossipSigner,
)
from tests.test_witness_gossip import T0, fixture  # noqa: E402


class PublicTransparencyAuditTests(unittest.TestCase):
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
            issued_at=T0 + 50,
        )
        self.cert_signer = QuorumCertificateSigner.generate("quorum-aggregator-v1")
        self.certificate = self.cert_signer.sign(self.quorum, issued_at=T0 + 51)

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.gossip_path = root / "gossip.json"
        self.cert_path = root / "certificate.json"
        self.gossip_path.write_text(
            json.dumps(self.bundle.to_dict()),
            encoding="utf-8",
        )
        self.cert_path.write_text(
            json.dumps(self.certificate.to_dict()),
            encoding="utf-8",
        )

    def kwargs(self):
        return {
            "gossip_path": self.gossip_path,
            "gossip_public_key": self.gossip_signer.public_key_b64(),
            "gossip_publisher_id": "gossip-publisher-v1",
            "expected_policy_digest": self.policy.digest(),
            "certificate_path": self.cert_path,
            "certificate_public_key": self.cert_signer.public_key_b64(),
            "certificate_signer_id": "quorum-aggregator-v1",
        }

    def test_offline_audit_accepts_valid_proof_chain(self):
        report = audit(**self.kwargs())
        self.assertTrue(report["valid"])
        self.assertTrue(report["accepted"])
        self.assertEqual(report["transparency_state"], "ACCEPTED")
        self.assertEqual(report["counted_witnesses"], ["witness-a", "witness-b"])

    def test_offline_audit_without_certificate_holds(self):
        args = self.kwargs()
        args["certificate_path"] = None
        args["certificate_public_key"] = None
        args["certificate_signer_id"] = None
        report = audit(**args)
        self.assertFalse(report["accepted"])
        self.assertEqual(report["transparency_state"], "HOLD_CERTIFICATE_REQUIRED")

    def test_wrong_external_policy_pin_is_rejected(self):
        args = self.kwargs()
        args["expected_policy_digest"] = "f" * 64
        with self.assertRaises(ValueError):
            audit(**args)

    def test_cli_returns_zero_and_machine_readable_json_for_acceptance(self):
        cmd = [
            sys.executable,
            str(SCRIPTS / "audit_transparency.py"),
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
        ]
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["accepted"])
        self.assertNotIn("verdict", report)

    def test_cli_runs_from_outside_repository_root(self):
        cmd = [
            sys.executable,
            str(SCRIPTS / "audit_transparency.py"),
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
        ]
        outside = pathlib.Path(self.tmp.name) / "outside"
        outside.mkdir()
        result = subprocess.run(
            cmd,
            cwd=outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["accepted"])

    def test_cli_fails_closed_on_tampered_gossip(self):
        forged = replace(self.bundle, checkpoint_digest="f" * 64)
        self.gossip_path.write_text(
            json.dumps(forged.to_dict()),
            encoding="utf-8",
        )
        cmd = [
            sys.executable,
            str(SCRIPTS / "audit_transparency.py"),
            str(self.gossip_path),
            "--gossip-public-key",
            self.gossip_signer.public_key_b64(),
            "--gossip-publisher-id",
            "gossip-publisher-v1",
            "--expected-policy-digest",
            self.policy.digest(),
        ]
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])


if __name__ == "__main__":
    unittest.main()
