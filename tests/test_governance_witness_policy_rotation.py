"""Governance witness policy continuity adversarial tests."""

import base64
import unittest
from dataclasses import replace

from proofos.governance_witness import GovernanceAttestationSigner
from proofos.governance_witness_policy_rotation import (
    GOVERNANCE_WITNESS_POLICY_GENESIS,
    GovernanceWitnessPolicyContinuityError,
    GovernanceWitnessPolicySignatureInvalid,
    GovernanceWitnessPolicyTransition,
    GovernanceWitnessPolicyTransitionSigner,
    policy_for_governance_generation,
    verify_governance_witness_policy_chain,
    verify_policy_transition,
)
from proofos.witness_quorum import WitnessQuorumPolicy, WitnessQuorumPolicyError

T0 = 1_801_300_000.0


class GovernanceWitnessPolicyContinuityTests(unittest.TestCase):
    def setUp(self):
        self.old = {
            "a": GovernanceAttestationSigner.generate("a"),
            "b": GovernanceAttestationSigner.generate("b"),
            "c": GovernanceAttestationSigner.generate("c"),
        }
        self.new = {
            "d": GovernanceAttestationSigner.generate("d"),
            "e": GovernanceAttestationSigner.generate("e"),
            "f": GovernanceAttestationSigner.generate("f"),
        }
        self.third = {
            "g": GovernanceAttestationSigner.generate("g"),
            "h": GovernanceAttestationSigner.generate("h"),
            "i": GovernanceAttestationSigner.generate("i"),
        }
        self.p1 = WitnessQuorumPolicy(
            "governance-policy-v1",
            tuple((wid, signer.public_key_b64()) for wid, signer in self.old.items()),
            2,
        )
        self.p2 = WitnessQuorumPolicy(
            "governance-policy-v2",
            tuple((wid, signer.public_key_b64()) for wid, signer in self.new.items()),
            2,
        )
        self.p3 = WitnessQuorumPolicy(
            "governance-policy-v3",
            tuple((wid, signer.public_key_b64()) for wid, signer in self.third.items()),
            2,
        )
        self.t1 = GovernanceWitnessPolicyTransitionSigner.sign(
            generation=1,
            previous_policy=self.p1,
            next_policy=self.p2,
            previous_private_keys={
                "a": self.old["a"]._key,
                "b": self.old["b"]._key,
            },
            next_private_keys={
                "d": self.new["d"]._key,
                "e": self.new["e"]._key,
            },
            effective_from_governance_generation=2,
            issued_at=T0 + 1,
        )
        self.t2 = GovernanceWitnessPolicyTransitionSigner.sign(
            generation=2,
            previous_policy=self.p2,
            next_policy=self.p3,
            previous_private_keys={
                "d": self.new["d"]._key,
                "f": self.new["f"]._key,
            },
            next_private_keys={
                "g": self.third["g"]._key,
                "h": self.third["h"]._key,
            },
            effective_from_governance_generation=4,
            previous_transition_digest=self.t1.transition_digest(),
            issued_at=T0 + 2,
        )

    def test_complete_policy_chain_verifies(self):
        current, history = verify_governance_witness_policy_chain(
            initial_policy=self.p1,
            transitions=(self.t1, self.t2),
            expected_generation=2,
            expected_head_digest=self.t2.transition_digest(),
        )
        self.assertEqual(current.digest(), self.p3.digest())
        self.assertEqual(tuple(p.digest() for p in history), (
            self.p1.digest(), self.p2.digest(), self.p3.digest()
        ))

    def test_previous_policy_threshold_is_required(self):
        with self.assertRaises(WitnessQuorumPolicyError):
            GovernanceWitnessPolicyTransitionSigner.sign(
                generation=1,
                previous_policy=self.p1,
                next_policy=self.p2,
                previous_private_keys={"a": self.old["a"]._key},
                next_private_keys={
                    "d": self.new["d"]._key,
                    "e": self.new["e"]._key,
                },
                effective_from_governance_generation=2,
            )

    def test_next_policy_threshold_is_required(self):
        with self.assertRaises(WitnessQuorumPolicyError):
            GovernanceWitnessPolicyTransitionSigner.sign(
                generation=1,
                previous_policy=self.p1,
                next_policy=self.p2,
                previous_private_keys={
                    "a": self.old["a"]._key,
                    "b": self.old["b"]._key,
                },
                next_private_keys={"d": self.new["d"]._key},
                effective_from_governance_generation=2,
            )

    def test_previous_approval_tampering_is_rejected(self):
        approvals = list(self.t1.previous_approvals)
        raw = bytearray(base64.b64decode(approvals[0].signature))
        raw[0] ^= 1
        approvals[0] = replace(
            approvals[0],
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(GovernanceWitnessPolicySignatureInvalid):
            verify_policy_transition(
                replace(self.t1, previous_approvals=tuple(approvals))
            )

    def test_next_approval_tampering_is_rejected(self):
        approvals = list(self.t1.next_approvals)
        raw = bytearray(base64.b64decode(approvals[0].signature))
        raw[-1] ^= 1
        approvals[0] = replace(
            approvals[0],
            signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(GovernanceWitnessPolicySignatureInvalid):
            verify_policy_transition(replace(self.t1, next_approvals=tuple(approvals)))

    def test_stale_valid_prefix_is_rejected(self):
        with self.assertRaisesRegex(
            GovernanceWitnessPolicyContinuityError, "rollback|truncation"
        ):
            verify_governance_witness_policy_chain(
                initial_policy=self.p1,
                transitions=(self.t1,),
                expected_generation=2,
                expected_head_digest=self.t2.transition_digest(),
            )

    def test_initial_policy_substitution_is_rejected(self):
        with self.assertRaises(GovernanceWitnessPolicyContinuityError):
            verify_governance_witness_policy_chain(
                initial_policy=self.p2,
                transitions=(self.t1,),
                expected_generation=1,
                expected_head_digest=self.t1.transition_digest(),
            )

    def test_effective_governance_generations_must_increase(self):
        bad = GovernanceWitnessPolicyTransitionSigner.sign(
            generation=2,
            previous_policy=self.p2,
            next_policy=self.p3,
            previous_private_keys={
                "d": self.new["d"]._key,
                "e": self.new["e"]._key,
            },
            next_private_keys={
                "g": self.third["g"]._key,
                "h": self.third["h"]._key,
            },
            effective_from_governance_generation=2,
            previous_transition_digest=self.t1.transition_digest(),
            issued_at=T0 + 2,
        )
        with self.assertRaisesRegex(
            GovernanceWitnessPolicyContinuityError, "effective generations"
        ):
            verify_governance_witness_policy_chain(
                initial_policy=self.p1,
                transitions=(self.t1, bad),
                expected_generation=2,
                expected_head_digest=bad.transition_digest(),
            )

    def test_policy_selection_respects_effective_governance_generation(self):
        transitions = (self.t1, self.t2)
        self.assertEqual(
            policy_for_governance_generation(self.p1, transitions, 1).digest(),
            self.p1.digest(),
        )
        self.assertEqual(
            policy_for_governance_generation(self.p1, transitions, 2).digest(),
            self.p2.digest(),
        )
        self.assertEqual(
            policy_for_governance_generation(self.p1, transitions, 3).digest(),
            self.p2.digest(),
        )
        self.assertEqual(
            policy_for_governance_generation(self.p1, transitions, 4).digest(),
            self.p3.digest(),
        )

    def test_transition_carries_no_completion_or_execution_authority(self):
        fields = set(GovernanceWitnessPolicyTransition.__dataclass_fields__)
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
