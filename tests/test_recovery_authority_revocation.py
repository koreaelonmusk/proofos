"""Recovery authority revocation adversarial tests."""

import base64
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofos.auditor_key_recovery import (
    AuditorKeyRecoverySigner,
    RecoveryPolicy,
    RecoveryPolicyError,
    verify_recovery,
)
from proofos.auditor_key_rotation import KEY_TRANSITION_GENESIS
from proofos.keys import encode_public_key
from proofos.recovery_authority_revocation import (
    REVOCATION_GENESIS,
    RecoveryAuthorityRevocationContinuityError,
    RecoveryAuthorityRevocationSignatureInvalid,
    RecoveryAuthorityRevocationSigner,
    parse_revocation_registry,
    revoked_for_auditor_generation,
    verify_revocation,
    verify_revocation_registry,
)

T0 = 1_801_100_000.0
AUDITOR = "external-auditor-v1"


class RecoveryAuthorityRevocationTests(unittest.TestCase):
    def setUp(self):
        self.a = Ed25519PrivateKey.generate()
        self.b = Ed25519PrivateKey.generate()
        self.c = Ed25519PrivateKey.generate()
        self.policy = RecoveryPolicy(
            "auditor-recovery-v1",
            (
                ("a", encode_public_key(self.a.public_key())),
                ("b", encode_public_key(self.b.public_key())),
                ("c", encode_public_key(self.c.public_key())),
            ),
            2,
        )
        self.revocation = RecoveryAuthorityRevocationSigner.sign(
            revocation_generation=1,
            policy=self.policy,
            authority_id="a",
            effective_from_auditor_generation=2,
            incident_id="INC-REV-001",
            authority_private_keys={"b": self.b, "c": self.c},
            previous_revocation_digest=REVOCATION_GENESIS,
            issued_at=T0 + 1,
        )

    def recovery(self, generation, approvals):
        old = Ed25519PrivateKey.generate()
        replacement = Ed25519PrivateKey.generate()
        return AuditorKeyRecoverySigner.sign(
            auditor_id=AUDITOR,
            generation=generation,
            compromised_public_key=encode_public_key(old.public_key()),
            replacement_private_key=replacement,
            previous_history_digest=KEY_TRANSITION_GENESIS,
            incident_id=f"INC-REC-{generation}",
            policy=self.policy,
            authority_private_keys=approvals,
            issued_at=T0 + 10 + generation,
        )

    def test_round_trip_and_registry_verify(self):
        parsed = parse_revocation_registry([self.revocation.to_dict()])
        effective = verify_revocation_registry(
            policy=self.policy,
            revocations=parsed,
            expected_generation=1,
            expected_head_digest=parsed[0].revocation_digest(),
        )
        self.assertEqual(effective, {"a": 2})

    def test_revoked_authority_cannot_approve_own_revocation(self):
        with self.assertRaises(RecoveryPolicyError):
            RecoveryAuthorityRevocationSigner.sign(
                revocation_generation=1,
                policy=self.policy,
                authority_id="a",
                effective_from_auditor_generation=2,
                incident_id="INC-REV-SELF",
                authority_private_keys={"a": self.a, "b": self.b},
                issued_at=T0 + 1,
            )

    def test_revocation_requires_non_target_threshold(self):
        with self.assertRaises(RecoveryPolicyError):
            RecoveryAuthorityRevocationSigner.sign(
                revocation_generation=1,
                policy=self.policy,
                authority_id="a",
                effective_from_auditor_generation=2,
                incident_id="INC-REV-LOW",
                authority_private_keys={"b": self.b},
                issued_at=T0 + 1,
            )

    def test_revocation_signature_tampering_is_rejected(self):
        approvals = list(self.revocation.approvals)
        raw = bytearray(base64.b64decode(approvals[0].signature))
        raw[0] ^= 1
        approvals[0] = replace(
            approvals[0],
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        forged = replace(self.revocation, approvals=tuple(approvals))
        with self.assertRaises(RecoveryAuthorityRevocationSignatureInvalid):
            verify_revocation(
                forged,
                policy=self.policy,
                expected_policy_digest=self.policy.digest(),
            )

    def test_stale_registry_prefix_is_rejected(self):
        with self.assertRaises(RecoveryAuthorityRevocationContinuityError):
            verify_revocation_registry(
                policy=self.policy,
                revocations=(),
                expected_generation=1,
                expected_head_digest=self.revocation.revocation_digest(),
            )

    def test_duplicate_authority_revocation_is_rejected(self):
        second = RecoveryAuthorityRevocationSigner.sign(
            revocation_generation=2,
            policy=self.policy,
            authority_id="a",
            effective_from_auditor_generation=3,
            incident_id="INC-REV-DUP",
            authority_private_keys={"b": self.b, "c": self.c},
            previous_revocation_digest=self.revocation.revocation_digest(),
            issued_at=T0 + 2,
        )
        with self.assertRaises(RecoveryAuthorityRevocationContinuityError):
            verify_revocation_registry(
                policy=self.policy,
                revocations=(self.revocation, second),
                expected_generation=2,
                expected_head_digest=second.revocation_digest(),
            )

    def test_revocation_is_not_retroactive(self):
        effective = {"a": 2}
        recovery = self.recovery(1, {"a": self.a, "b": self.b})
        verify_recovery(
            recovery,
            policy=self.policy,
            expected_policy_digest=self.policy.digest(),
            revoked_authorities=effective,
        )

    def test_revocation_blocks_approval_at_effective_generation(self):
        effective = {"a": 2}
        recovery = self.recovery(2, {"a": self.a, "b": self.b})
        with self.assertRaisesRegex(RecoveryPolicyError, "revoked"):
            verify_recovery(
                recovery,
                policy=self.policy,
                expected_policy_digest=self.policy.digest(),
                revoked_authorities=effective,
            )

    def test_future_revocation_set_is_generation_scoped(self):
        effective = {"a": 3}
        self.assertEqual(
            revoked_for_auditor_generation(effective, 2),
            frozenset(),
        )
        self.assertEqual(
            revoked_for_auditor_generation(effective, 3),
            frozenset({"a"}),
        )

    def test_revocation_carries_no_completion_or_execution_authority(self):
        fields = set(self.revocation.__dataclass_fields__)
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
