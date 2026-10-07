"""Auditor signing-key continuity adversarial tests."""

import base64
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofos.auditor_key_rotation import (
    AUDITOR_KEY_TRANSITION_VERSION,
    KEY_TRANSITION_GENESIS,
    AuditorKeyContinuityError,
    AuditorKeyTransition,
    AuditorKeyTransitionSignatureInvalid,
    AuditorKeyTransitionSigner,
    MalformedAuditorKeyTransition,
    verify_transition,
    verify_transition_chain,
)
from proofos.keys import encode_public_key

AUDITOR = "external-auditor-v1"
T0 = 1_800_800_000.0


class AuditorKeyRotationTests(unittest.TestCase):
    def setUp(self):
        self.k1 = Ed25519PrivateKey.generate()
        self.k2 = Ed25519PrivateKey.generate()
        self.k3 = Ed25519PrivateKey.generate()
        self.p1 = encode_public_key(self.k1.public_key())
        self.p2 = encode_public_key(self.k2.public_key())
        self.p3 = encode_public_key(self.k3.public_key())

        self.t1 = AuditorKeyTransitionSigner.sign(
            auditor_id=AUDITOR,
            generation=1,
            previous_private_key=self.k1,
            next_private_key=self.k2,
            previous_transition_digest=KEY_TRANSITION_GENESIS,
            issued_at=T0 + 1,
        )
        self.t2 = AuditorKeyTransitionSigner.sign(
            auditor_id=AUDITOR,
            generation=2,
            previous_private_key=self.k2,
            next_private_key=self.k3,
            previous_transition_digest=self.t1.transition_digest(),
            issued_at=T0 + 2,
        )

    def test_round_trip_and_complete_chain_verify(self):
        parsed1 = AuditorKeyTransition.from_dict(self.t1.to_dict())
        parsed2 = AuditorKeyTransition.from_dict(self.t2.to_dict())

        final = verify_transition_chain(
            auditor_id=AUDITOR,
            initial_public_key=self.p1,
            transitions=(parsed1, parsed2),
            expected_generation=2,
            expected_head_digest=parsed2.transition_digest(),
        )
        self.assertEqual(final, self.p3)
        self.assertEqual(parsed1.version, AUDITOR_KEY_TRANSITION_VERSION)

    def test_previous_key_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.t1.previous_key_signature))
        raw[0] ^= 1
        forged = replace(
            self.t1,
            previous_key_signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(AuditorKeyTransitionSignatureInvalid):
            verify_transition(forged)

    def test_next_key_possession_signature_tampering_is_rejected(self):
        raw = bytearray(base64.b64decode(self.t1.next_key_signature))
        raw[-1] ^= 1
        forged = replace(
            self.t1,
            next_key_signature=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        with self.assertRaises(AuditorKeyTransitionSignatureInvalid):
            verify_transition(forged)

    def test_generation_gap_is_rejected(self):
        skipped = AuditorKeyTransitionSigner.sign(
            auditor_id=AUDITOR,
            generation=3,
            previous_private_key=self.k2,
            next_private_key=self.k3,
            previous_transition_digest=self.t1.transition_digest(),
            issued_at=T0 + 2,
        )
        with self.assertRaises(AuditorKeyContinuityError):
            verify_transition_chain(
                auditor_id=AUDITOR,
                initial_public_key=self.p1,
                transitions=(self.t1, skipped),
                expected_generation=2,
                expected_head_digest=skipped.transition_digest(),
            )

    def test_previous_transition_digest_break_is_rejected(self):
        broken = AuditorKeyTransitionSigner.sign(
            auditor_id=AUDITOR,
            generation=2,
            previous_private_key=self.k2,
            next_private_key=self.k3,
            previous_transition_digest="f" * 64,
            issued_at=T0 + 2,
        )
        with self.assertRaises(AuditorKeyContinuityError):
            verify_transition_chain(
                auditor_id=AUDITOR,
                initial_public_key=self.p1,
                transitions=(self.t1, broken),
                expected_generation=2,
                expected_head_digest=broken.transition_digest(),
            )

    def test_auditor_identity_substitution_is_rejected(self):
        other = AuditorKeyTransitionSigner.sign(
            auditor_id="attacker-auditor",
            generation=1,
            previous_private_key=self.k1,
            next_private_key=self.k2,
            previous_transition_digest=KEY_TRANSITION_GENESIS,
            issued_at=T0 + 1,
        )
        with self.assertRaises(AuditorKeyContinuityError):
            verify_transition_chain(
                auditor_id=AUDITOR,
                initial_public_key=self.p1,
                transitions=(other,),
                expected_generation=1,
                expected_head_digest=other.transition_digest(),
            )

    def test_chain_cannot_substitute_untrusted_previous_key(self):
        attacker = Ed25519PrivateKey.generate()
        successor = Ed25519PrivateKey.generate()
        forged = AuditorKeyTransitionSigner.sign(
            auditor_id=AUDITOR,
            generation=1,
            previous_private_key=attacker,
            next_private_key=successor,
            previous_transition_digest=KEY_TRANSITION_GENESIS,
            issued_at=T0 + 1,
        )
        with self.assertRaises(AuditorKeyContinuityError):
            verify_transition_chain(
                auditor_id=AUDITOR,
                initial_public_key=self.p1,
                transitions=(forged,),
                expected_generation=1,
                expected_head_digest=forged.transition_digest(),
            )

    def test_stale_valid_prefix_is_rejected_by_pinned_head(self):
        with self.assertRaises(AuditorKeyContinuityError):
            verify_transition_chain(
                auditor_id=AUDITOR,
                initial_public_key=self.p1,
                transitions=(self.t1,),
                expected_generation=2,
                expected_head_digest=self.t2.transition_digest(),
            )

    def test_boolean_generation_is_rejected_by_signer(self):
        with self.assertRaises(ValueError):
            AuditorKeyTransitionSigner.sign(
                auditor_id=AUDITOR,
                generation=True,
                previous_private_key=self.k1,
                next_private_key=self.k2,
                previous_transition_digest=KEY_TRANSITION_GENESIS,
                issued_at=T0 + 1,
            )

    def test_noncanonical_signature_encoding_is_rejected(self):
        encoded = self.t1.previous_key_signature
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        index = alphabet.index(encoded[-3])
        alternate = alphabet[(index & 0b110000) | ((index + 1) & 0b001111)]
        self.assertNotEqual(alternate, encoded[-3])
        noncanonical = encoded[:-3] + alternate + "=="
        self.assertEqual(
            base64.b64decode(noncanonical, validate=True),
            base64.b64decode(encoded, validate=True),
        )
        forged = replace(self.t1, previous_key_signature=noncanonical)
        with self.assertRaises(AuditorKeyTransitionSignatureInvalid):
            verify_transition(forged)
    def test_unknown_field_is_rejected(self):
        raw = self.t1.to_dict()
        raw["verdict"] = "VERIFIED"
        with self.assertRaises(MalformedAuditorKeyTransition):
            AuditorKeyTransition.from_dict(raw)

    def test_same_key_rotation_is_rejected(self):
        with self.assertRaises(ValueError):
            AuditorKeyTransitionSigner.sign(
                auditor_id=AUDITOR,
                generation=1,
                previous_private_key=self.k1,
                next_private_key=self.k1,
                previous_transition_digest=KEY_TRANSITION_GENESIS,
                issued_at=T0 + 1,
            )

    def test_materialized_unsupported_version_is_rejected(self):
        future = replace(self.t1, version="proofos.auditor-key-transition.v2")
        with self.assertRaises(AuditorKeyContinuityError):
            verify_transition(future)

    def test_transition_carries_no_completion_or_execution_authority(self):
        fields = set(AuditorKeyTransition.__dataclass_fields__)
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
