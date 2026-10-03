from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_extropy_jev0_provenance.py"

spec = importlib.util.spec_from_file_location("verify_extropy_jev0_provenance", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ExtropyJev0ProvenanceVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = b"jev0-binary"
        self.policy = b'{"schema_version":1}\n'
        self.capabilities = {
            "schema_version": 1,
            "runtime_ready": True,
            "process_backend": "posix",
        }
        canonical = json.dumps(
            self.capabilities,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.provenance = {
            "schema": module.PROVENANCE_SCHEMA,
            "executableSha256": hashlib.sha256(self.executable).hexdigest(),
            "policySha256": hashlib.sha256(self.policy).hexdigest(),
            "capabilitiesSha256": hashlib.sha256(canonical).hexdigest(),
        }

    def payload(self):
        return {
            "schema": module.REPORT_SCHEMA,
            "kind": module.REPORT_KIND,
            "workId": "work-1",
            "runId": "run-1",
            "mode": "armed",
            "executedCount": 1,
            "blockedCount": 0,
            "records": [
                {
                    "capabilityId": "tool/mcp/extropy-local/run_npm_script",
                    "executor": "tool-broker",
                    "workCapabilities": ["EXECUTE"],
                    "status": "EXECUTED",
                    "reason": "executed",
                    "executed": True,
                    "verified": False,
                    "jev0Execution": dict(self.provenance),
                }
            ],
        }

    def verify(self, payload):
        return module.verify_execution_report(
            payload,
            executable_bytes=self.executable,
            policy_bytes=self.policy,
            capabilities=self.capabilities,
        )

    def test_rederives_all_constituent_hashes(self):
        result = self.verify(self.payload())
        self.assertTrue(result["valid"])
        self.assertEqual(len(result["verified_records"]), 1)
        self.assertEqual(
            result["verified_records"][0]["executableSha256"],
            self.provenance["executableSha256"],
        )

    def test_rejects_truncated_execution_report_envelope(self):
        payload = {
            "records": [
                {
                    "executed": True,
                    "jev0Execution": dict(self.provenance),
                }
            ],
        }
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "envelope schema drifted",
        ):
            self.verify(payload)

    def test_rejects_report_identity_mismatch(self):
        payload = self.payload()
        payload["kind"] = "synthetic.report"
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "identity is invalid",
        ):
            self.verify(payload)

    def test_rejects_inconsistent_counts(self):
        payload = self.payload()
        payload["executedCount"] = 0
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "executedCount does not match executed records",
        ):
            self.verify(payload)

    def test_rejects_boolean_capabilities_schema_version(self):
        payload = self.payload()
        capabilities = dict(self.capabilities)
        capabilities["schema_version"] = True
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "unsupported jev0 capabilities schema",
        ):
            module.verify_execution_report(
                payload,
                executable_bytes=self.executable,
                policy_bytes=self.policy,
                capabilities=capabilities,
            )

    def test_rejects_schema_drift(self):
        payload = self.payload()
        payload["records"][0]["jev0Execution"]["unexpected"] = True
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "schema drifted",
        ):
            self.verify(payload)

    def test_rejects_non_executed_record(self):
        payload = self.payload()
        payload["records"][0]["executed"] = False
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "non-executed capability",
        ):
            self.verify(payload)

    def test_rejects_executable_mismatch(self):
        payload = self.payload()
        payload["records"][0]["jev0Execution"]["executableSha256"] = "0" * 64
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "executable SHA-256 mismatch",
        ):
            self.verify(payload)

    def test_rejects_policy_mismatch(self):
        payload = self.payload()
        payload["records"][0]["jev0Execution"]["policySha256"] = "0" * 64
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "policy SHA-256 mismatch",
        ):
            self.verify(payload)

    def test_rejects_capabilities_mismatch(self):
        payload = self.payload()
        payload["records"][0]["jev0Execution"]["capabilitiesSha256"] = "0" * 64
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "capabilities SHA-256 mismatch",
        ):
            self.verify(payload)

    def test_rejects_missing_provenance(self):
        payload = self.payload()
        del payload["records"][0]["jev0Execution"]
        with self.assertRaisesRegex(
            module.ExtropyJev0ProvenanceError,
            "contains no jev0 provenance",
        ):
            self.verify(payload)


if __name__ == "__main__":
    unittest.main()
