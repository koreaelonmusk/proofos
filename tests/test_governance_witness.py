"""Cross-witness governance snapshot adversarial tests."""

import unittest
from dataclasses import replace

from proofos.auditor_key_rotation import KEY_TRANSITION_GENESIS
from proofos.governance_witness import (
    GOVERNANCE_GENESIS,
    GOVERNANCE_SNAPSHOT_VERSION,
    GovernanceAttestationSigner,
    GovernanceBindingError,
    GovernanceQuorumState,
    GovernanceSnapshot,
    GovernanceWitnessBundle,
    MalformedGovernanceSnapshot,
    verify_governance_bundle,
)
from proofos.recovery_authority_revocation import REVOCATION_GENESIS
from proofos.recovery_policy_rotation import RECOVERY_POLICY_TRANSITION_GENESIS
from proofos.witness_quorum import WitnessQuorumPolicy

T0 = 1_801_200_000.0


class GovernanceWitnessTests(unittest.TestCase):
    def setUp(self):
        self.signers = {
            "a": GovernanceAttestationSigner.generate("a"),
            "b": GovernanceAttestationSigner.generate("b"),
            "c": GovernanceAttestationSigner.generate("c"),
        }
        self.policy = WitnessQuorumPolicy(
            "governance-witness-v1",
            tuple(
                (wid, signer.public_key_b64())
                for wid, signer in self.signers.items()
            ),
            2,
        )
        self.snapshot = GovernanceSnapshot(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            governance_generation=1,
            previous_snapshot_digest=GOVERNANCE_GENESIS,
            auditor_history_generation=0,
            auditor_history_digest=KEY_TRANSITION_GENESIS,
            recovery_policy_generation=0,
            recovery_policy_digest="0" * 64,
            recovery_policy_history_digest=RECOVERY_POLICY_TRANSITION_GENESIS,
            revocation_generation=0,
            revocation_head_digest=REVOCATION_GENESIS,
            issued_at=T0 + 1,
        )

    def bundle(self, witness_ids=("a", "b")):
        attestations = tuple(
            self.signers[wid].sign(self.snapshot, observed_at=T0 + 2)
            for wid in witness_ids
        )
        return GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=self.snapshot,
            policy=self.policy,
            attestations=attestations,
        )

    def verify(self, bundle):
        return verify_governance_bundle(
            bundle,
            expected_policy_digest=self.policy.digest(),
            expected_governance_generation=1,
            expected_governance_head_digest=self.snapshot.snapshot_digest(),
        )

    def test_two_of_three_reaches_governance_quorum(self):
        result = self.verify(self.bundle())
        self.assertEqual(result.state, GovernanceQuorumState.QUORUM)
        self.assertEqual(result.counted_witnesses, ("a", "b"))

    def test_one_of_three_is_insufficient(self):
        result = self.verify(self.bundle(("a",)))
        self.assertEqual(result.state, GovernanceQuorumState.INSUFFICIENT)

    def test_forged_external_snapshot_head_is_rejected(self):
        with self.assertRaises(GovernanceBindingError):
            verify_governance_bundle(
                self.bundle(),
                expected_policy_digest=self.policy.digest(),
                expected_governance_generation=1,
                expected_governance_head_digest="f" * 64,
            )

    def test_stale_governance_generation_is_rejected(self):
        with self.assertRaises(GovernanceBindingError):
            verify_governance_bundle(
                self.bundle(),
                expected_policy_digest=self.policy.digest(),
                expected_governance_generation=2,
                expected_governance_head_digest=self.snapshot.snapshot_digest(),
            )

    def test_policy_substitution_is_rejected(self):
        with self.assertRaises(GovernanceBindingError):
            verify_governance_bundle(
                self.bundle(),
                expected_policy_digest="e" * 64,
                expected_governance_generation=1,
                expected_governance_head_digest=self.snapshot.snapshot_digest(),
            )

    def test_cross_witness_governance_split_view_is_explicit(self):
        other = replace(
            self.snapshot,
            auditor_history_generation=1,
            auditor_history_digest="d" * 64,
        )
        bundle = GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=self.snapshot,
            policy=self.policy,
            attestations=(
                self.signers["a"].sign(self.snapshot, observed_at=T0 + 2),
                self.signers["b"].sign(other, observed_at=T0 + 2),
            ),
        )
        result = self.verify(bundle)
        self.assertEqual(result.state, GovernanceQuorumState.SPLIT_VIEW)

    def test_unknown_authority_field_is_rejected(self):
        raw = self.bundle().to_dict()
        raw["snapshot"]["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedGovernanceSnapshot):
            GovernanceWitnessBundle.from_dict(raw)

    def test_governance_snapshot_carries_no_execution_authority(self):
        fields = set(GovernanceSnapshot.__dataclass_fields__)
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
