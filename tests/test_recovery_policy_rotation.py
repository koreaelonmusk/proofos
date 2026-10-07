"""Recovery-policy continuity adversarial tests."""

import base64
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofos.auditor_key_recovery import RecoveryPolicy, RecoveryPolicyError
from proofos.keys import encode_public_key
from proofos.recovery_policy_rotation import (
    RECOVERY_POLICY_TRANSITION_GENESIS,
    RecoveryPolicyContinuityError,
    RecoveryPolicyTransition,
    RecoveryPolicyTransitionSignatureInvalid,
    RecoveryPolicyTransitionSigner,
    parse_recovery_policy_history,
    verify_policy_transition,
    verify_recovery_policy_chain,
)

T0 = 1_801_000_000.0


class RecoveryPolicyContinuityTests(unittest.TestCase):
    def setUp(self):
        self.a1 = Ed25519PrivateKey.generate()
        self.a2 = Ed25519PrivateKey.generate()
        self.a3 = Ed25519PrivateKey.generate()
        self.b1 = Ed25519PrivateKey.generate()
        self.b2 = Ed25519PrivateKey.generate()
        self.b3 = Ed25519PrivateKey.generate()
        self.c1 = Ed25519PrivateKey.generate()
        self.c2 = Ed25519PrivateKey.generate()
        self.c3 = Ed25519PrivateKey.generate()

        self.p1 = RecoveryPolicy(
            "recovery-policy-v1",
            (
                ("a", encode_public_key(self.a1.public_key())),
                ("b", encode_public_key(self.a2.public_key())),
                ("c", encode_public_key(self.a3.public_key())),
            ),
            2,
        )
        self.p2 = RecoveryPolicy(
            "recovery-policy-v2",
            (
                ("d", encode_public_key(self.b1.public_key())),
                ("e", encode_public_key(self.b2.public_key())),
                ("f", encode_public_key(self.b3.public_key())),
            ),
            2,
        )
        self.p3 = RecoveryPolicy(
            "recovery-policy-v3",
            (
                ("g", encode_public_key(self.c1.public_key())),
                ("h", encode_public_key(self.c2.public_key())),
                ("i", encode_public_key(self.c3.public_key())),
            ),
            2,
        )
        self.t1 = RecoveryPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=self.p1,
            next_policy=self.p2,
            previous_authority_private_keys={"a": self.a1, "b": self.a2},
            next_authority_private_keys={"d": self.b1, "e": self.b2},
            previous_transition_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
            issued_at=T0 + 1,
        )
        self.t2 = RecoveryPolicyTransitionSigner.sign(
            generation=2,
            previous_policy=self.p2,
            next_policy=self.p3,
            previous_authority_private_keys={"d": self.b1, "f": self.b3},
            next_authority_private_keys={"g": self.c1, "i": self.c3},
            previous_transition_digest=self.t1.transition_digest(),
            issued_at=T0 + 2,
        )

    def test_round_trip_and_complete_chain_verify(self):
        parsed1 = RecoveryPolicyTransition.from_dict(self.t1.to_dict())
        parsed2 = RecoveryPolicyTransition.from_dict(self.t2.to_dict())
        final = verify_recovery_policy_chain(
            initial_policy=self.p1,
            transitions=(parsed1, parsed2),
            expected_generation=2,
            expected_head_digest=parsed2.transition_digest(),
        )
        self.assertEqual(final.digest(), self.p3.digest())

    def test_old_policy_threshold_is_required(self):
        with self.assertRaises(RecoveryPolicyError):
            RecoveryPolicyTransitionSigner.sign(
                generation=1,
                previous_policy=self.p1,
                next_policy=self.p2,
                previous_authority_private_keys={"a": self.a1},
                next_authority_private_keys={"d": self.b1, "e": self.b2},
                issued_at=T0 + 1,
            )

    def test_new_policy_threshold_is_required(self):
        with self.assertRaises(RecoveryPolicyError):
            RecoveryPolicyTransitionSigner.sign(
                generation=1,
                previous_policy=self.p1,
                next_policy=self.p2,
                previous_authority_private_keys={"a": self.a1, "b": self.a2},
                next_authority_private_keys={"d": self.b1},
                issued_at=T0 + 1,
            )

    def test_previous_approval_tampering_is_rejected(self):
        approvals = list(self.t1.previous_approvals)
        raw = bytearray(base64.b64decode(approvals[0].signature))
        raw[0] ^= 1
        approvals[0] = replace(
            approvals[0],
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        forged = replace(self.t1, previous_approvals=tuple(approvals))
        with self.assertRaises(RecoveryPolicyTransitionSignatureInvalid):
            verify_policy_transition(forged)

    def test_next_approval_tampering_is_rejected(self):
        approvals = list(self.t1.next_approvals)
        raw = bytearray(base64.b64decode(approvals[0].signature))
        raw[-1] ^= 1
        approvals[0] = replace(
            approvals[0],
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        forged = replace(self.t1, next_approvals=tuple(approvals))
        with self.assertRaises(RecoveryPolicyTransitionSignatureInvalid):
            verify_policy_transition(forged)

    def test_stale_policy_prefix_is_rejected_by_pinned_head(self):
        with self.assertRaises(RecoveryPolicyContinuityError):
            verify_recovery_policy_chain(
                initial_policy=self.p1,
                transitions=(self.t1,),
                expected_generation=2,
                expected_head_digest=self.t2.transition_digest(),
            )

    def test_policy_substitution_is_rejected(self):
        with self.assertRaises(RecoveryPolicyContinuityError):
            verify_recovery_policy_chain(
                initial_policy=self.p2,
                transitions=(self.t1,),
                expected_generation=1,
                expected_head_digest=self.t1.transition_digest(),
            )

    def test_generation_gap_is_rejected(self):
        skipped = RecoveryPolicyTransitionSigner.sign(
            generation=3,
            previous_policy=self.p2,
            next_policy=self.p3,
            previous_authority_private_keys={"d": self.b1, "e": self.b2},
            next_authority_private_keys={"g": self.c1, "h": self.c2},
            previous_transition_digest=self.t1.transition_digest(),
            issued_at=T0 + 2,
        )
        with self.assertRaises(RecoveryPolicyContinuityError):
            verify_recovery_policy_chain(
                initial_policy=self.p1,
                transitions=(self.t1, skipped),
                expected_generation=2,
                expected_head_digest=skipped.transition_digest(),
            )

    def test_unknown_authority_field_is_rejected(self):
        raw = self.t1.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(Exception):
            parse_recovery_policy_history([raw])

    def test_transition_carries_no_completion_or_execution_authority(self):
        fields = set(RecoveryPolicyTransition.__dataclass_fields__)
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
