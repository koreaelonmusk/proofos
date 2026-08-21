import unittest

from proofos.verifier import Evidence, VerificationStatus, verify_completion


class VerificationContractTests(unittest.TestCase):
    def test_verified_with_complete_valid_evidence(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                Evidence("tests", "unit-suite: 553/553", True),
                Evidence("runtime", "healthcheck: 200; behavior observed", True),
            ),
            required_kinds=("tests", "runtime"),
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertEqual(result.missing, ())

    def test_abstain_when_runtime_evidence_missing(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(Evidence("tests", "unit-suite: 553/553", True),),
            required_kinds=("tests", "runtime"),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))

    def test_abstain_when_runtime_evidence_invalid(self):
        result = verify_completion(
            claim="Production fix completed",
            evidence=(
                Evidence("tests", "unit-suite: 553/553", True),
                Evidence("runtime", "worker self-report only", False),
            ),
            required_kinds=("tests", "runtime"),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)
        self.assertEqual(result.missing, ("runtime",))

    def test_abstain_on_empty_claim(self):
        result = verify_completion(
            claim=" ",
            evidence=(
                Evidence("tests", "passed", True),
                Evidence("runtime", "observed", True),
            ),
            required_kinds=("tests", "runtime"),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)

    def test_abstain_without_declared_requirements(self):
        result = verify_completion(
            claim="Done",
            evidence=(),
            required_kinds=(),
        )
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)


if __name__ == "__main__":
    unittest.main()
