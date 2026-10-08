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

from proofos.auditor_key_recovery import (
    AuditorKeyRecoverySigner,
    RecoveryPolicy,
)
from proofos.auditor_key_rotation import (
    KEY_TRANSITION_GENESIS,
    AuditorKeyTransitionSigner,
)
from proofos.governance_witness import (
    GOVERNANCE_GENESIS,
    GOVERNANCE_SNAPSHOT_VERSION,
    GovernanceAttestationSigner,
    GovernanceSnapshot,
    GovernanceWitnessBundle,
)
from proofos.governance_witness_policy_rotation import (
    GOVERNANCE_WITNESS_POLICY_GENESIS,
    GovernanceWitnessPolicyTransitionSigner,
)
from proofos.keys import encode_public_key
from proofos.quorum_certificate import QuorumCertificateSigner
from proofos.recovery_authority_revocation import (
    REVOCATION_GENESIS,
    RecoveryAuthorityRevocationSigner,
)
from proofos.recovery_policy_rotation import (
    RECOVERY_POLICY_TRANSITION_GENESIS,
    RecoveryPolicyTransitionSigner,
)
from proofos.witness_gossip import WitnessGossipSigner
from proofos.witness_quorum import WitnessQuorumPolicy
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
        self.auditor_initial_public_key = self.auditor_public_key

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = pathlib.Path(self.tmp.name)
        self.outside = root / "outside"
        self.outside.mkdir()
        self.gossip_path = root / "gossip.json"
        self.cert_path = root / "certificate.json"
        self.key_path = root / "auditor.pem"
        self.receipt_path = root / "receipt.json"
        self.transitions_path = root / "auditor-transitions.json"
        self.recovery_policy_path = root / "auditor-recovery-policy.json"
        self.governance_path = root / "governance.json"

        self.gossip_path.write_text(
            json.dumps(self.bundle.to_dict()),
            encoding="utf-8",
        )
        self.cert_path.write_text(
            json.dumps(self.certificate.to_dict()),
            encoding="utf-8",
        )
        self.transitions_path.write_text("[]", encoding="utf-8")
        self.governance_signers = {
            "gov-a": GovernanceAttestationSigner.generate("gov-a"),
            "gov-b": GovernanceAttestationSigner.generate("gov-b"),
            "gov-c": GovernanceAttestationSigner.generate("gov-c"),
        }
        self.governance_policy = WitnessQuorumPolicy(
            "governance-witness-v1",
            tuple(
                (wid, signer.public_key_b64())
                for wid, signer in self.governance_signers.items()
            ),
            2,
        )
        self.write_governance()
        self.key_path.write_bytes(
            self.auditor_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def write_governance(
        self,
        *,
        auditor_generation=0,
        auditor_digest=KEY_TRANSITION_GENESIS,
        recovery_policy_generation=0,
        recovery_policy_digest="0" * 64,
        recovery_policy_history_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
        revocation_generation=0,
        revocation_digest=REVOCATION_GENESIS,
    ):
        snapshot = GovernanceSnapshot(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            governance_generation=1,
            previous_snapshot_digest=GOVERNANCE_GENESIS,
            auditor_history_generation=auditor_generation,
            auditor_history_digest=auditor_digest,
            recovery_policy_generation=recovery_policy_generation,
            recovery_policy_digest=recovery_policy_digest,
            recovery_policy_history_digest=recovery_policy_history_digest,
            revocation_generation=revocation_generation,
            revocation_head_digest=revocation_digest,
            issued_at=T0 + 72,
        )
        attestations = tuple(
            self.governance_signers[wid].sign(snapshot, observed_at=T0 + 73)
            for wid in ("gov-a", "gov-b")
        )
        bundle = GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=snapshot,
            policy=self.governance_policy,
            attestations=attestations,
        )
        self.governance_path.write_text(
            json.dumps(bundle.to_dict()),
            encoding="utf-8",
        )
        self.governance_snapshot = snapshot

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
            "--auditor-initial-public-key",
            self.auditor_initial_public_key,
            "--auditor-key-transitions",
            str(self.transitions_path),
            "--expected-auditor-generation",
            "0",
            "--expected-auditor-transition-digest",
            KEY_TRANSITION_GENESIS,
            "--governance-witness-bundle",
            str(self.governance_path),
            "--expected-governance-witness-policy-digest",
            self.governance_policy.digest(),
            "--expected-governance-generation",
            "1",
            "--expected-governance-head-digest",
            self.governance_snapshot.snapshot_digest(),
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

    def test_public_verifier_accepts_proven_auditor_key_rotation(self):
        successor = Ed25519PrivateKey.generate()
        transition = AuditorKeyTransitionSigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            previous_private_key=self.auditor_key,
            next_private_key=successor,
            previous_transition_digest=KEY_TRANSITION_GENESIS,
            issued_at=T0 + 80,
        )
        self.transitions_path.write_text(
            json.dumps([transition.to_dict()]),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            successor.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.auditor_public_key = encode_public_key(successor.public_key())
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=transition.transition_digest(),
        )

        cmd = self.verify_cmd()
        gen_index = cmd.index("--expected-auditor-generation") + 1
        digest_index = cmd.index("--expected-auditor-transition-digest") + 1
        cmd[gen_index] = "1"
        cmd[digest_index] = transition.transition_digest()
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["auditor_key_generation"], 1)

    def test_public_verifier_rejects_stale_rotation_prefix(self):
        successor = Ed25519PrivateKey.generate()
        transition = AuditorKeyTransitionSigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            previous_private_key=self.auditor_key,
            next_private_key=successor,
            previous_transition_digest=KEY_TRANSITION_GENESIS,
            issued_at=T0 + 80,
        )
        self.transitions_path.write_text("[]", encoding="utf-8")
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=transition.transition_digest(),
        )

        cmd = self.verify_cmd()
        gen_index = cmd.index("--expected-auditor-generation") + 1
        digest_index = cmd.index("--expected-auditor-transition-digest") + 1
        cmd[gen_index] = "1"
        cmd[digest_index] = transition.transition_digest()
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("rollback", report["detail"])
    def test_public_verifier_accepts_threshold_emergency_recovery(self):
        recovery_a = Ed25519PrivateKey.generate()
        recovery_b = Ed25519PrivateKey.generate()
        recovery_c = Ed25519PrivateKey.generate()
        policy = RecoveryPolicy(
            "auditor-recovery-v1",
            (
                ("recovery-a", encode_public_key(recovery_a.public_key())),
                ("recovery-b", encode_public_key(recovery_b.public_key())),
                ("recovery-c", encode_public_key(recovery_c.public_key())),
            ),
            2,
        )
        replacement = Ed25519PrivateKey.generate()
        recovery = AuditorKeyRecoverySigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            compromised_public_key=self.auditor_initial_public_key,
            replacement_private_key=replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-CLI-001",
            policy=policy,
            authority_private_keys={
                "recovery-a": recovery_a,
                "recovery-b": recovery_b,
            },
            issued_at=T0 + 90,
        )
        self.transitions_path.write_text(
            json.dumps([recovery.to_dict()]),
            encoding="utf-8",
        )
        self.recovery_policy_path.write_text(
            json.dumps(policy.to_dict()),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            replacement.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.auditor_public_key = encode_public_key(replacement.public_key())
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=recovery.recovery_digest(),
            recovery_policy_generation=0,
            recovery_policy_digest=policy.digest(),
            recovery_policy_history_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
        )

        cmd = self.verify_cmd()
        gen_index = cmd.index("--expected-auditor-generation") + 1
        digest_index = cmd.index("--expected-auditor-transition-digest") + 1
        cmd[gen_index] = "1"
        cmd[digest_index] = recovery.recovery_digest()
        cmd.extend(
            [
                "--auditor-recovery-policy",
                str(self.recovery_policy_path),
                "--expected-auditor-recovery-policy-digest",
                policy.digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["auditor_key_generation"], 1)
        self.assertEqual(
            report["auditor_recovery_policy_digest"],
            policy.digest(),
        )

    def test_public_verifier_rejects_recovery_without_pinned_policy(self):
        recovery_a = Ed25519PrivateKey.generate()
        recovery_b = Ed25519PrivateKey.generate()
        policy = RecoveryPolicy(
            "auditor-recovery-v1",
            (
                ("recovery-a", encode_public_key(recovery_a.public_key())),
                ("recovery-b", encode_public_key(recovery_b.public_key())),
            ),
            2,
        )
        replacement = Ed25519PrivateKey.generate()
        recovery = AuditorKeyRecoverySigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            compromised_public_key=self.auditor_initial_public_key,
            replacement_private_key=replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-CLI-002",
            policy=policy,
            authority_private_keys={
                "recovery-a": recovery_a,
                "recovery-b": recovery_b,
            },
            issued_at=T0 + 90,
        )
        self.transitions_path.write_text(
            json.dumps([recovery.to_dict()]),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            replacement.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=recovery.recovery_digest(),
            recovery_policy_generation=0,
            recovery_policy_digest=policy.digest(),
            recovery_policy_history_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
        )

        cmd = self.verify_cmd()
        gen_index = cmd.index("--expected-auditor-generation") + 1
        digest_index = cmd.index("--expected-auditor-transition-digest") + 1
        cmd[gen_index] = "1"
        cmd[digest_index] = recovery.recovery_digest()
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("recovery policy", report["detail"])

    def test_public_verifier_accepts_rotated_recovery_policy(self):
        old_a = Ed25519PrivateKey.generate()
        old_b = Ed25519PrivateKey.generate()
        old_c = Ed25519PrivateKey.generate()
        old_policy = RecoveryPolicy(
            "auditor-recovery-old",
            (
                ("old-a", encode_public_key(old_a.public_key())),
                ("old-b", encode_public_key(old_b.public_key())),
                ("old-c", encode_public_key(old_c.public_key())),
            ),
            2,
        )
        new_a = Ed25519PrivateKey.generate()
        new_b = Ed25519PrivateKey.generate()
        new_c = Ed25519PrivateKey.generate()
        new_policy = RecoveryPolicy(
            "auditor-recovery-new",
            (
                ("new-a", encode_public_key(new_a.public_key())),
                ("new-b", encode_public_key(new_b.public_key())),
                ("new-c", encode_public_key(new_c.public_key())),
            ),
            2,
        )
        policy_transition = RecoveryPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=old_policy,
            next_policy=new_policy,
            previous_authority_private_keys={"old-a": old_a, "old-b": old_b},
            next_authority_private_keys={"new-a": new_a, "new-b": new_b},
            previous_transition_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
            issued_at=T0 + 95,
        )
        replacement = Ed25519PrivateKey.generate()
        recovery = AuditorKeyRecoverySigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            compromised_public_key=self.auditor_initial_public_key,
            replacement_private_key=replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-CLI-POLICY-ROTATE",
            policy=new_policy,
            authority_private_keys={"new-a": new_a, "new-c": new_c},
            issued_at=T0 + 96,
        )

        policy_initial = pathlib.Path(self.tmp.name) / "recovery-policy-initial.json"
        policy_history = pathlib.Path(self.tmp.name) / "recovery-policy-history.json"
        policy_initial.write_text(
            json.dumps(old_policy.to_dict()),
            encoding="utf-8",
        )
        policy_history.write_text(
            json.dumps([policy_transition.to_dict()]),
            encoding="utf-8",
        )
        self.transitions_path.write_text(
            json.dumps([recovery.to_dict()]),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            replacement.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=recovery.recovery_digest(),
            recovery_policy_generation=1,
            recovery_policy_digest=new_policy.digest(),
            recovery_policy_history_digest=policy_transition.transition_digest(),
        )

        cmd = self.verify_cmd()
        cmd[cmd.index("--expected-auditor-generation") + 1] = "1"
        cmd[cmd.index("--expected-auditor-transition-digest") + 1] = (
            recovery.recovery_digest()
        )
        cmd.extend(
            [
                "--auditor-recovery-initial-policy",
                str(policy_initial),
                "--auditor-recovery-policy-history",
                str(policy_history),
                "--expected-auditor-recovery-policy-generation",
                "1",
                "--expected-auditor-recovery-policy-history-digest",
                policy_transition.transition_digest(),
                "--expected-auditor-recovery-policy-digest",
                new_policy.digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["auditor_recovery_policy_generation"], 1)
        self.assertEqual(
            report["auditor_recovery_policy_digest"],
            new_policy.digest(),
        )

    def test_public_verifier_rejects_stale_recovery_policy_prefix(self):
        old_a = Ed25519PrivateKey.generate()
        old_b = Ed25519PrivateKey.generate()
        old_policy = RecoveryPolicy(
            "auditor-recovery-old",
            (
                ("old-a", encode_public_key(old_a.public_key())),
                ("old-b", encode_public_key(old_b.public_key())),
            ),
            2,
        )
        new_a = Ed25519PrivateKey.generate()
        new_b = Ed25519PrivateKey.generate()
        new_policy = RecoveryPolicy(
            "auditor-recovery-new",
            (
                ("new-a", encode_public_key(new_a.public_key())),
                ("new-b", encode_public_key(new_b.public_key())),
            ),
            2,
        )
        policy_transition = RecoveryPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=old_policy,
            next_policy=new_policy,
            previous_authority_private_keys={"old-a": old_a, "old-b": old_b},
            next_authority_private_keys={"new-a": new_a, "new-b": new_b},
            previous_transition_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
            issued_at=T0 + 95,
        )

        policy_initial = pathlib.Path(self.tmp.name) / "recovery-policy-initial.json"
        policy_history = pathlib.Path(self.tmp.name) / "recovery-policy-history.json"
        policy_initial.write_text(json.dumps(old_policy.to_dict()), encoding="utf-8")
        policy_history.write_text("[]", encoding="utf-8")
        self.create_receipt()
        self.write_governance(
            recovery_policy_generation=1,
            recovery_policy_digest=new_policy.digest(),
            recovery_policy_history_digest=policy_transition.transition_digest(),
        )

        cmd = self.verify_cmd()
        cmd.extend(
            [
                "--auditor-recovery-initial-policy",
                str(policy_initial),
                "--auditor-recovery-policy-history",
                str(policy_history),
                "--expected-auditor-recovery-policy-generation",
                "1",
                "--expected-auditor-recovery-policy-history-digest",
                policy_transition.transition_digest(),
                "--expected-auditor-recovery-policy-digest",
                new_policy.digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("rollback", report["detail"])

    def test_public_verifier_rejects_recovery_signed_by_revoked_authority(self):
        recovery_a = Ed25519PrivateKey.generate()
        recovery_b = Ed25519PrivateKey.generate()
        recovery_c = Ed25519PrivateKey.generate()
        policy = RecoveryPolicy(
            "auditor-recovery-v1",
            (
                ("recovery-a", encode_public_key(recovery_a.public_key())),
                ("recovery-b", encode_public_key(recovery_b.public_key())),
                ("recovery-c", encode_public_key(recovery_c.public_key())),
            ),
            2,
        )
        replacement = Ed25519PrivateKey.generate()
        recovery = AuditorKeyRecoverySigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            compromised_public_key=self.auditor_initial_public_key,
            replacement_private_key=replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-CLI-REV-001",
            policy=policy,
            authority_private_keys={
                "recovery-a": recovery_a,
                "recovery-b": recovery_b,
            },
            issued_at=T0 + 100,
        )
        revocation = RecoveryAuthorityRevocationSigner.sign(
            revocation_generation=1,
            policy=policy,
            authority_id="recovery-a",
            effective_from_auditor_generation=1,
            incident_id="INC-AUTH-REVOKE-001",
            authority_private_keys={
                "recovery-b": recovery_b,
                "recovery-c": recovery_c,
            },
            previous_revocation_digest=REVOCATION_GENESIS,
            issued_at=T0 + 99,
        )

        revocations_path = pathlib.Path(self.tmp.name) / "revocations.json"
        self.recovery_policy_path.write_text(
            json.dumps(policy.to_dict()),
            encoding="utf-8",
        )
        revocations_path.write_text(
            json.dumps([revocation.to_dict()]),
            encoding="utf-8",
        )
        self.transitions_path.write_text(
            json.dumps([recovery.to_dict()]),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            replacement.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=recovery.recovery_digest(),
            recovery_policy_generation=0,
            recovery_policy_digest=policy.digest(),
            recovery_policy_history_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
            revocation_generation=1,
            revocation_digest=revocation.revocation_digest(),
        )

        cmd = self.verify_cmd()
        cmd[cmd.index("--expected-auditor-generation") + 1] = "1"
        cmd[cmd.index("--expected-auditor-transition-digest") + 1] = (
            recovery.recovery_digest()
        )
        cmd.extend(
            [
                "--auditor-recovery-policy",
                str(self.recovery_policy_path),
                "--expected-auditor-recovery-policy-digest",
                policy.digest(),
                "--auditor-recovery-revocations",
                str(revocations_path),
                "--expected-auditor-revocation-generation",
                "1",
                "--expected-auditor-revocation-head-digest",
                revocation.revocation_digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("revoked", report["detail"])

    def test_public_verifier_preserves_pre_revocation_recovery(self):
        recovery_a = Ed25519PrivateKey.generate()
        recovery_b = Ed25519PrivateKey.generate()
        recovery_c = Ed25519PrivateKey.generate()
        policy = RecoveryPolicy(
            "auditor-recovery-v1",
            (
                ("recovery-a", encode_public_key(recovery_a.public_key())),
                ("recovery-b", encode_public_key(recovery_b.public_key())),
                ("recovery-c", encode_public_key(recovery_c.public_key())),
            ),
            2,
        )
        replacement = Ed25519PrivateKey.generate()
        recovery = AuditorKeyRecoverySigner.sign(
            auditor_id="external-auditor-v1",
            generation=1,
            compromised_public_key=self.auditor_initial_public_key,
            replacement_private_key=replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-CLI-REV-002",
            policy=policy,
            authority_private_keys={
                "recovery-a": recovery_a,
                "recovery-b": recovery_b,
            },
            issued_at=T0 + 100,
        )
        revocation = RecoveryAuthorityRevocationSigner.sign(
            revocation_generation=1,
            policy=policy,
            authority_id="recovery-a",
            effective_from_auditor_generation=2,
            incident_id="INC-AUTH-REVOKE-002",
            authority_private_keys={
                "recovery-b": recovery_b,
                "recovery-c": recovery_c,
            },
            previous_revocation_digest=REVOCATION_GENESIS,
            issued_at=T0 + 101,
        )

        revocations_path = pathlib.Path(self.tmp.name) / "revocations.json"
        self.recovery_policy_path.write_text(
            json.dumps(policy.to_dict()),
            encoding="utf-8",
        )
        revocations_path.write_text(
            json.dumps([revocation.to_dict()]),
            encoding="utf-8",
        )
        self.transitions_path.write_text(
            json.dumps([recovery.to_dict()]),
            encoding="utf-8",
        )
        self.key_path.write_bytes(
            replacement.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.create_receipt()
        self.write_governance(
            auditor_generation=1,
            auditor_digest=recovery.recovery_digest(),
            recovery_policy_generation=0,
            recovery_policy_digest=policy.digest(),
            recovery_policy_history_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
            revocation_generation=1,
            revocation_digest=revocation.revocation_digest(),
        )

        cmd = self.verify_cmd()
        cmd[cmd.index("--expected-auditor-generation") + 1] = "1"
        cmd[cmd.index("--expected-auditor-transition-digest") + 1] = (
            recovery.recovery_digest()
        )
        cmd.extend(
            [
                "--auditor-recovery-policy",
                str(self.recovery_policy_path),
                "--expected-auditor-recovery-policy-digest",
                policy.digest(),
                "--auditor-recovery-revocations",
                str(revocations_path),
                "--expected-auditor-revocation-generation",
                "1",
                "--expected-auditor-revocation-head-digest",
                revocation.revocation_digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["auditor_recovery_revocation_generation"], 1)

    def test_public_verifier_accepts_rotated_governance_witness_policy(self):
        old_signers = self.governance_signers
        old_policy = self.governance_policy
        new_signers = {
            "gov-a": GovernanceAttestationSigner.generate("gov-a"),
            "gov-b": GovernanceAttestationSigner.generate("gov-b"),
            "gov-c": GovernanceAttestationSigner.generate("gov-c"),
        }
        new_policy = WitnessQuorumPolicy(
            "governance-witness-v2",
            tuple(
                (wid, signer.public_key_b64())
                for wid, signer in new_signers.items()
            ),
            2,
        )
        transition = GovernanceWitnessPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=old_policy,
            next_policy=new_policy,
            previous_private_keys={
                "gov-a": old_signers["gov-a"]._key,
                "gov-b": old_signers["gov-b"]._key,
            },
            next_private_keys={
                "gov-a": new_signers["gov-a"]._key,
                "gov-b": new_signers["gov-b"]._key,
            },
            effective_from_governance_generation=1,
            previous_transition_digest=GOVERNANCE_WITNESS_POLICY_GENESIS,
            issued_at=T0 + 71,
        )
        initial_policy_path = pathlib.Path(self.tmp.name) / "governance-policy-initial.json"
        policy_history_path = pathlib.Path(self.tmp.name) / "governance-policy-history.json"
        initial_policy_path.write_text(
            json.dumps(
                {
                    "policy_id": old_policy.policy_id,
                    "witnesses": [
                        {"witness_id": wid, "public_key_b64": key}
                        for wid, key in old_policy.witnesses
                    ],
                    "threshold": old_policy.threshold,
                }
            ),
            encoding="utf-8",
        )
        policy_history_path.write_text(
            json.dumps([transition.to_dict()]),
            encoding="utf-8",
        )
        self.governance_signers = new_signers
        self.governance_policy = new_policy
        self.write_governance()
        self.create_receipt()

        cmd = self.verify_cmd()
        cmd.extend(
            [
                "--governance-witness-policy-initial",
                str(initial_policy_path),
                "--governance-witness-policy-history",
                str(policy_history_path),
                "--expected-governance-witness-policy-generation",
                "1",
                "--expected-governance-witness-policy-history-digest",
                transition.transition_digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["governance_witness_policy_generation"], 1)

    def test_public_verifier_rejects_stale_governance_witness_policy_prefix(self):
        old_signers = self.governance_signers
        old_policy = self.governance_policy
        new_signers = {
            "gov-a": GovernanceAttestationSigner.generate("gov-a"),
            "gov-b": GovernanceAttestationSigner.generate("gov-b"),
        }
        new_policy = WitnessQuorumPolicy(
            "governance-witness-v2",
            tuple(
                (wid, signer.public_key_b64())
                for wid, signer in new_signers.items()
            ),
            2,
        )
        transition = GovernanceWitnessPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=old_policy,
            next_policy=new_policy,
            previous_private_keys={
                "gov-a": old_signers["gov-a"]._key,
                "gov-b": old_signers["gov-b"]._key,
            },
            next_private_keys={
                "gov-a": new_signers["gov-a"]._key,
                "gov-b": new_signers["gov-b"]._key,
            },
            effective_from_governance_generation=1,
            issued_at=T0 + 71,
        )
        initial_policy_path = pathlib.Path(self.tmp.name) / "governance-policy-initial.json"
        policy_history_path = pathlib.Path(self.tmp.name) / "governance-policy-history.json"
        initial_policy_path.write_text(
            json.dumps(
                {
                    "policy_id": old_policy.policy_id,
                    "witnesses": [
                        {"witness_id": wid, "public_key_b64": key}
                        for wid, key in old_policy.witnesses
                    ],
                    "threshold": old_policy.threshold,
                }
            ),
            encoding="utf-8",
        )
        policy_history_path.write_text("[]", encoding="utf-8")
        self.governance_signers = new_signers
        self.governance_policy = new_policy
        self.write_governance()
        self.create_receipt()

        cmd = self.verify_cmd()
        cmd.extend(
            [
                "--governance-witness-policy-initial",
                str(initial_policy_path),
                "--governance-witness-policy-history",
                str(policy_history_path),
                "--expected-governance-witness-policy-generation",
                "1",
                "--expected-governance-witness-policy-history-digest",
                transition.transition_digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["valid"])
        self.assertIn("rollback", report["detail"])

    def test_public_verifier_accepts_published_policy_before_effective_generation(self):
        old_policy = self.governance_policy
        old_signers = self.governance_signers
        future_signers = {
            "gov-a": GovernanceAttestationSigner.generate("gov-a"),
            "gov-b": GovernanceAttestationSigner.generate("gov-b"),
            "gov-c": GovernanceAttestationSigner.generate("gov-c"),
        }
        future_policy = WitnessQuorumPolicy(
            "governance-witness-v2",
            tuple(
                (wid, signer.public_key_b64())
                for wid, signer in future_signers.items()
            ),
            2,
        )
        transition = GovernanceWitnessPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=old_policy,
            next_policy=future_policy,
            previous_private_keys={
                "gov-a": old_signers["gov-a"]._key,
                "gov-b": old_signers["gov-b"]._key,
            },
            next_private_keys={
                "gov-a": future_signers["gov-a"]._key,
                "gov-b": future_signers["gov-b"]._key,
            },
            effective_from_governance_generation=2,
            issued_at=T0 + 71,
        )
        initial_policy_path = pathlib.Path(self.tmp.name) / "future-policy-initial.json"
        policy_history_path = pathlib.Path(self.tmp.name) / "future-policy-history.json"
        initial_policy_path.write_text(
            json.dumps(
                {
                    "policy_id": old_policy.policy_id,
                    "witnesses": [
                        {"witness_id": wid, "public_key_b64": key}
                        for wid, key in old_policy.witnesses
                    ],
                    "threshold": old_policy.threshold,
                }
            ),
            encoding="utf-8",
        )
        policy_history_path.write_text(
            json.dumps([transition.to_dict()]),
            encoding="utf-8",
        )
        self.create_receipt()

        cmd = self.verify_cmd()
        cmd.extend(
            [
                "--governance-witness-policy-initial",
                str(initial_policy_path),
                "--governance-witness-policy-history",
                str(policy_history_path),
                "--expected-governance-witness-policy-generation",
                "1",
                "--expected-governance-witness-policy-history-digest",
                transition.transition_digest(),
            ]
        )
        result = subprocess.run(
            cmd,
            cwd=self.outside,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["governance_witness_policy_generation"], 1)

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
        self.assertNotIn("--auditor-public-key", result.stdout)
        self.assertIn("--auditor-initial-public-key", result.stdout)
        self.assertIn("--auditor-key-transitions", result.stdout)
        self.assertIn("--expected-auditor-generation", result.stdout)
        self.assertIn("--auditor-recovery-policy", result.stdout)
        self.assertIn("--expected-auditor-recovery-policy-digest", result.stdout)
        self.assertIn("--auditor-recovery-policy-history", result.stdout)
        self.assertIn("--expected-auditor-recovery-policy-generation", result.stdout)
        self.assertIn(
            "--expected-auditor-recovery-policy-history-digest",
            result.stdout,
        )
        self.assertIn("--auditor-recovery-revocations", result.stdout)
        self.assertIn("--expected-auditor-revocation-generation", result.stdout)
        self.assertIn("--expected-auditor-revocation-head-digest", result.stdout)
        self.assertIn("--governance-witness-policy-initial", result.stdout)
        self.assertIn("--governance-witness-policy-history", result.stdout)
        self.assertIn("--expected-governance-witness-policy-generation", result.stdout)


if __name__ == "__main__":
    unittest.main()
