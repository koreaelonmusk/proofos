"""Emergency auditor key recovery adversarial tests."""

import base64
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofos.auditor_key_recovery import (
    AUDITOR_KEY_RECOVERY_VERSION,
    AuditorKeyRecovery,
    AuditorKeyRecoveryContinuityError,
    AuditorKeyRecoverySigner,
    AuditorKeyRecoverySignatureInvalid,
    RecoveryPolicy,
    RecoveryPolicyError,
    parse_auditor_key_history,
    verify_auditor_key_history,
    verify_recovery,
)
from proofos.auditor_key_rotation import (
    KEY_TRANSITION_GENESIS,
    AuditorKeyTransitionSigner,
)
from proofos.keys import encode_public_key

AUDITOR = "external-auditor-v1"
T0 = 1_800_900_000.0


class AuditorKeyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.compromised = Ed25519PrivateKey.generate()
        self.replacement = Ed25519PrivateKey.generate()
        self.replacement2 = Ed25519PrivateKey.generate()
        self.a1 = Ed25519PrivateKey.generate()
        self.a2 = Ed25519PrivateKey.generate()
        self.a3 = Ed25519PrivateKey.generate()
        self.policy = RecoveryPolicy(
            "auditor-recovery-v1",
            (
                ("recovery-a", encode_public_key(self.a1.public_key())),
                ("recovery-b", encode_public_key(self.a2.public_key())),
                ("recovery-c", encode_public_key(self.a3.public_key())),
            ),
            2,
        )
        self.recovery = AuditorKeyRecoverySigner.sign(
            auditor_id=AUDITOR,
            generation=1,
            compromised_public_key=encode_public_key(self.compromised.public_key()),
            replacement_private_key=self.replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-2026-001",
            policy=self.policy,
            authority_private_keys={
                "recovery-a": self.a1,
                "recovery-b": self.a2,
            },
            issued_at=T0 + 1,
        )

    def test_threshold_recovery_round_trip_and_history_verify(self):
        parsed = AuditorKeyRecovery.from_dict(self.recovery.to_dict())
        verify_recovery(
            parsed,
            policy=self.policy,
            expected_policy_digest=self.policy.digest(),
        )
        final = verify_auditor_key_history(
            auditor_id=AUDITOR,
            initial_public_key=encode_public_key(self.compromised.public_key()),
            entries=(parsed,),
            expected_generation=1,
            expected_head_digest=parsed.recovery_digest(),
            recovery_policy=self.policy,
            expected_recovery_policy_digest=self.policy.digest(),
        )
        self.assertEqual(final, encode_public_key(self.replacement.public_key()))
        self.assertEqual(parsed.version, AUDITOR_KEY_RECOVERY_VERSION)

    def test_compromised_key_signature_is_not_required(self):
        fields = set(AuditorKeyRecovery.__dataclass_fields__)
        self.assertNotIn("compromised_key_signature", fields)
        self.assertNotIn("previous_key_signature", fields)

    def test_insufficient_recovery_approvals_are_rejected(self):
        with self.assertRaises(RecoveryPolicyError):
            AuditorKeyRecoverySigner.sign(
                auditor_id=AUDITOR,
                generation=1,
                compromised_public_key=encode_public_key(self.compromised.public_key()),
                replacement_private_key=self.replacement,
                previous_history_digest=KEY_TRANSITION_GENESIS,
                incident_id="INC-2026-002",
                policy=self.policy,
                authority_private_keys={"recovery-a": self.a1},
                issued_at=T0 + 1,
            )

    def test_unpinned_recovery_policy_is_rejected(self):
        with self.assertRaises(RecoveryPolicyError):
            verify_recovery(
                self.recovery,
                policy=self.policy,
                expected_policy_digest="f" * 64,
            )

    def test_recovery_authority_signature_tampering_is_rejected(self):
        approvals = list(self.recovery.approvals)
        raw = bytearray(base64.b64decode(approvals[0].signature))
        raw[0] ^= 1
        approvals[0] = replace(
            approvals[0],
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        forged = replace(self.recovery, approvals=tuple(approvals))
        with self.assertRaises(AuditorKeyRecoverySignatureInvalid):
            verify_recovery(
                forged,
                policy=self.policy,
                expected_policy_digest=self.policy.digest(),
            )

    def test_replacement_key_possession_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.recovery.replacement_key_signature))
        raw[-1] ^= 1
        forged = replace(
            self.recovery,
            replacement_key_signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(AuditorKeyRecoverySignatureInvalid):
            verify_recovery(
                forged,
                policy=self.policy,
                expected_policy_digest=self.policy.digest(),
            )

    def test_recovery_must_revoke_currently_trusted_key(self):
        other = Ed25519PrivateKey.generate()
        recovery = AuditorKeyRecoverySigner.sign(
            auditor_id=AUDITOR,
            generation=1,
            compromised_public_key=encode_public_key(other.public_key()),
            replacement_private_key=self.replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id="INC-2026-003",
            policy=self.policy,
            authority_private_keys={"recovery-a": self.a1, "recovery-b": self.a2},
            issued_at=T0 + 1,
        )
        with self.assertRaises(AuditorKeyRecoveryContinuityError):
            verify_auditor_key_history(
                auditor_id=AUDITOR,
                initial_public_key=encode_public_key(self.compromised.public_key()),
                entries=(recovery,),
                expected_generation=1,
                expected_head_digest=recovery.recovery_digest(),
                recovery_policy=self.policy,
                expected_recovery_policy_digest=self.policy.digest(),
            )

    def test_stale_recovery_history_is_rejected_by_pinned_head(self):
        second = AuditorKeyRecoverySigner.sign(
            auditor_id=AUDITOR,
            generation=2,
            compromised_public_key=encode_public_key(self.replacement.public_key()),
            replacement_private_key=self.replacement2,
            previous_history_digest=self.recovery.recovery_digest(),
            incident_id="INC-2026-004",
            policy=self.policy,
            authority_private_keys={"recovery-a": self.a1, "recovery-c": self.a3},
            issued_at=T0 + 2,
        )
        with self.assertRaises(AuditorKeyRecoveryContinuityError):
            verify_auditor_key_history(
                auditor_id=AUDITOR,
                initial_public_key=encode_public_key(self.compromised.public_key()),
                entries=(self.recovery,),
                expected_generation=2,
                expected_head_digest=second.recovery_digest(),
                recovery_policy=self.policy,
                expected_recovery_policy_digest=self.policy.digest(),
            )

    def test_normal_rotation_can_follow_emergency_recovery(self):
        transition = AuditorKeyTransitionSigner.sign(
            auditor_id=AUDITOR,
            generation=2,
            previous_private_key=self.replacement,
            next_private_key=self.replacement2,
            previous_transition_digest=self.recovery.recovery_digest(),
            issued_at=T0 + 2,
        )
        final = verify_auditor_key_history(
            auditor_id=AUDITOR,
            initial_public_key=encode_public_key(self.compromised.public_key()),
            entries=(self.recovery, transition),
            expected_generation=2,
            expected_head_digest=transition.transition_digest(),
            recovery_policy=self.policy,
            expected_recovery_policy_digest=self.policy.digest(),
        )
        self.assertEqual(final, encode_public_key(self.replacement2.public_key()))

    def test_history_parser_rejects_authority_field_smuggling(self):
        raw = self.recovery.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(Exception):
            parse_auditor_key_history([raw])

    def test_recovery_carries_no_completion_or_execution_authority(self):
        fields = set(AuditorKeyRecovery.__dataclass_fields__)
        for forbidden in (
            "verdict",
            "decision",
            "verified",
            "evidence",
            "capabilities",
            "tools",
            "execution_authority",
        ):
            self.assertNotIn(forbidden, fields)


if __name__ == "__main__":
    unittest.main()
