import unittest

from proofos.verifier import (
    Evidence,
    EvidenceSource,
    FailureClass,
    VerificationStatus,
    verify_completion,
)

OBSERVED = EvidenceSource.OBSERVED
EXECUTOR = EvidenceSource.EXECUTOR
MODEL = EvidenceSource.MODEL

REQUIRED = ("tests", "runtime")


def observed(kind, value="observed-signal", valid=True):
    return Evidence(kind, value, OBSERVED, valid)


class VerificationContractTests(unittest.TestCase):
    def test_verified_with_complete_valid_observed_evidence(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                observed("tests", "unit-suite: 553/553"),
                observed("runtime", "healthcheck: 200; behavior observed"),
            ),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertEqual(result.missing, ())
        self.assertEqual(result.failure, FailureClass.NONE)

    def test_abstain_when_runtime_evidence_missing(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(observed("tests", "unit-suite: 553/553"),),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))
        self.assertEqual(result.failure, FailureClass.EVIDENCE_MISSING)

    def test_abstain_when_runtime_evidence_invalid(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                observed("tests", "unit-suite: 553/553"),
                observed("runtime", "tampered payload", valid=False),
            ),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))
        self.assertEqual(result.failure, FailureClass.EVIDENCE_INVALID)

    def test_abstain_on_empty_claim(self):
        result = verify_completion(
            claim=" ",
            evidence=(observed("tests"), observed("runtime")),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.MALFORMED_INPUT)

    def test_abstain_without_declared_requirements(self):
        result = verify_completion(claim="Done", evidence=(), required_kinds=())
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_MISSING)


class ProvenanceTests(unittest.TestCase):
    """Self-reported and model-generated assertions are never evidence."""

    def test_abstain_when_evidence_is_executor_self_report(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                observed("tests", "unit-suite: 553/553"),
                Evidence("runtime", "I checked it myself, it works", EXECUTOR),
            ),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))
        self.assertEqual(result.failure, FailureClass.EVIDENCE_UNTRUSTED)

    def test_abstain_when_evidence_is_model_generated(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                Evidence("tests", "I am confident tests pass", MODEL),
                Evidence("runtime", "I am confident runtime is healthy", MODEL),
            ),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, REQUIRED)
        self.assertEqual(result.failure, FailureClass.EVIDENCE_UNTRUSTED)


class AnomalyTests(unittest.TestCase):
    """Any anomaly must resolve to ABSTAIN, never to VERIFIED."""

    def test_abstain_on_conflicting_evidence_for_same_kind(self):
        # A valid observation and a tampered one for the same kind must not be
        # resolved in favour of the claim.
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                observed("tests", "unit-suite: 553/553"),
                observed("runtime", "healthcheck: 200"),
                observed("runtime", "TAMPERED", valid=False),
            ),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))

    def test_abstain_on_empty_evidence_value(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(observed("tests", "ok"), observed("runtime", "   ")),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))

    def test_abstain_on_malformed_evidence_item(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=("not-an-evidence-object",),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.MALFORMED_INPUT)

    def test_abstain_on_non_string_claim(self):
        result = verify_completion(
            claim=None,
            evidence=(observed("tests"), observed("runtime")),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.MALFORMED_INPUT)

    def test_verifier_exception_abstains_rather_than_raising(self):
        class Exploding:
            def __iter__(self):
                raise RuntimeError("collector exploded")

        result = verify_completion(
            claim="Production fix completed",
            evidence=Exploding(),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.failure, FailureClass.VERIFIER_FAILURE)

    def test_duplicate_valid_evidence_still_verifies(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                observed("tests", "run 1"),
                observed("tests", "run 2"),
                observed("runtime", "healthcheck: 200"),
            ),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_unknown_evidence_kind_cannot_satisfy_a_requirement(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(observed("tests", "ok"), observed("vibes", "looks good")),
            required_kinds=REQUIRED,
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))


if __name__ == "__main__":
    unittest.main()
