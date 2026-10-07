"""Cross-witness governance snapshot adversarial tests."""

import base64
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
    parse_governance_history,
    verify_governance_bundle,
    verify_governance_history,
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

    def test_exported_verifier_rejects_unsupported_materialized_versions(self):
        cases = (
            replace(self.bundle(), version="proofos.governance-snapshot.v2"),
            replace(
                self.bundle(),
                snapshot=replace(
                    self.snapshot,
                    version="proofos.governance-snapshot.v2",
                ),
            ),
            replace(
                self.bundle(),
                attestations=(
                    replace(
                        self.bundle().attestations[0],
                        version="proofos.governance-attestation.v2",
                    ),
                    self.bundle().attestations[1],
                ),
            ),
        )
        for candidate in cases:
            with self.subTest(version=candidate.version):
                with self.assertRaises(GovernanceBindingError):
                    verify_governance_bundle(
                        candidate,
                        expected_policy_digest=self.policy.digest(),
                        expected_governance_generation=1,
                        expected_governance_head_digest=(
                            candidate.snapshot.snapshot_digest()
                        ),
                    )

    def test_exported_verifier_revalidates_directly_materialized_snapshot_fields(self):
        malformed_snapshots = (
            replace(self.snapshot, auditor_history_generation=-1),
            replace(self.snapshot, recovery_policy_generation=-1),
            replace(self.snapshot, revocation_generation=-1),
            replace(self.snapshot, auditor_history_digest="not-a-digest"),
            replace(self.snapshot, issued_at=float("inf")),
        )
        for snapshot in malformed_snapshots:
            bundle = replace(self.bundle(), snapshot=snapshot)
            with self.subTest(snapshot=snapshot):
                with self.assertRaises(GovernanceBindingError):
                    verify_governance_bundle(
                        bundle,
                        expected_policy_digest=self.policy.digest(),
                        expected_governance_generation=snapshot.governance_generation,
                        expected_governance_head_digest="0" * 64,
                    )

    def test_exported_verifier_rejects_malformed_materialized_object_graphs(self):
        malformed_bundles = (
            replace(self.bundle(), policy=None),
            replace(self.bundle(), snapshot=None),
            replace(self.bundle(), attestations=(object(),)),
        )
        for bundle in malformed_bundles:
            with self.subTest(bundle=bundle):
                with self.assertRaises(GovernanceBindingError):
                    verify_governance_bundle(
                        bundle,
                        expected_policy_digest=self.policy.digest(),
                        expected_governance_generation=1,
                        expected_governance_head_digest="0" * 64,
                    )

        with self.assertRaises(GovernanceBindingError):
            verify_governance_bundle(
                object(),
                expected_policy_digest=self.policy.digest(),
                expected_governance_generation=1,
                expected_governance_head_digest="0" * 64,
            )

    def test_structural_revalidation_preserves_integer_snapshot_timestamp(self):
        integer_snapshot = replace(self.snapshot, issued_at=100)
        bundle = GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=integer_snapshot,
            policy=self.policy,
            attestations=tuple(
                self.signers[wid].sign(integer_snapshot, observed_at=101)
                for wid in ("a", "b")
            ),
        )
        result = verify_governance_bundle(
            bundle,
            expected_policy_digest=self.policy.digest(),
            expected_governance_generation=1,
            expected_governance_head_digest=integer_snapshot.snapshot_digest(),
        )
        self.assertEqual(result.state, GovernanceQuorumState.QUORUM)
        self.assertEqual(result.snapshot_digest, integer_snapshot.snapshot_digest())

    def test_validly_signed_attestation_cannot_predate_snapshot(self):
        attestation = self.signers["a"].sign(
            self.snapshot,
            observed_at=T0 + 2,
        )
        impossible = replace(attestation, observed_at=T0)
        impossible = replace(
            impossible,
            signature=base64.b64encode(
                self.signers["a"]._key.sign(impossible.signing_bytes())
            ).decode("ascii"),
        )
        bundle = GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=self.snapshot,
            policy=self.policy,
            attestations=(
                impossible,
                self.signers["b"].sign(self.snapshot, observed_at=T0 + 2),
            ),
        )
        with self.assertRaisesRegex(GovernanceBindingError, "predates"):
            self.verify(bundle)

    def second_bundle(self):
        second = replace(
            self.snapshot,
            governance_generation=2,
            previous_snapshot_digest=self.snapshot.snapshot_digest(),
            auditor_history_generation=1,
            auditor_history_digest="d" * 64,
            issued_at=T0 + 3,
        )
        return GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=second,
            policy=self.policy,
            attestations=tuple(
                self.signers[wid].sign(second, observed_at=T0 + 4)
                for wid in ("a", "b")
            ),
        )

    def test_two_generation_governance_history_verifies(self):
        second = self.second_bundle()
        result = verify_governance_history(
            (self.bundle(), second),
            expected_policy_digest=self.policy.digest(),
            expected_governance_generation=2,
            expected_governance_head_digest=second.snapshot.snapshot_digest(),
        )
        self.assertEqual(result.state, GovernanceQuorumState.QUORUM)
        self.assertEqual(result.snapshot_digest, second.snapshot.snapshot_digest())

    def test_governance_history_rejects_broken_previous_digest(self):
        second = self.second_bundle()
        broken_snapshot = replace(
            second.snapshot,
            previous_snapshot_digest="f" * 64,
        )
        broken = GovernanceWitnessBundle(
            version=GOVERNANCE_SNAPSHOT_VERSION,
            snapshot=broken_snapshot,
            policy=self.policy,
            attestations=tuple(
                self.signers[wid].sign(broken_snapshot, observed_at=T0 + 4)
                for wid in ("a", "b")
            ),
        )
        with self.assertRaisesRegex(GovernanceBindingError, "previous snapshot"):
            verify_governance_history(
                (self.bundle(), broken),
                expected_policy_digest=self.policy.digest(),
                expected_governance_generation=2,
                expected_governance_head_digest=broken_snapshot.snapshot_digest(),
            )

    def test_governance_history_rejects_stale_valid_prefix(self):
        second = self.second_bundle()
        with self.assertRaisesRegex(GovernanceBindingError, "rollback|truncation"):
            verify_governance_history(
                (self.bundle(),),
                expected_policy_digest=self.policy.digest(),
                expected_governance_generation=2,
                expected_governance_head_digest=second.snapshot.snapshot_digest(),
            )

    def test_governance_history_parser_preserves_legacy_object_and_array(self):
        first = self.bundle()
        second = self.second_bundle()
        legacy = parse_governance_history(first.to_dict())
        history = parse_governance_history([first.to_dict(), second.to_dict()])
        self.assertEqual(len(legacy), 1)
        self.assertEqual(len(history), 2)
        self.assertEqual(
            history[-1].snapshot.snapshot_digest(),
            second.snapshot.snapshot_digest(),
        )

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
