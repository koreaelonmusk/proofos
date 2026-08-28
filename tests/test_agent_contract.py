import unittest

from google.adk.tools import FunctionTool

from proofos.verifier import VerificationStatus
from proofos.ledger import EvidenceLedger
from proofos_agent import agent as agent_module
from proofos_agent.verification_tool import build_verification_tool
from proofos_agent import scenario
from tests.test_probe import send_json, serving


def tool_parameter_names(tool) -> list[str]:
    declaration = FunctionTool(tool)._get_declaration()
    dumped = declaration.model_dump(exclude_none=True)
    schema = dumped.get("parameters_json_schema") or dumped.get("parameters")
    return sorted((schema.get("properties") or {}).keys())


class ToolTrustBoundaryTests(unittest.TestCase):
    """The model must not be able to assert that evidence exists."""

    def setUp(self):
        self.ledger = EvidenceLedger()
        self.tool = build_verification_tool(self.ledger)

    def test_tool_exposes_no_model_controlled_evidence_parameters(self):
        params = tool_parameter_names(self.tool)
        self.assertEqual(params, ["claim", "task_id"])

    def test_tool_schema_has_no_boolean_evidence_flags(self):
        declaration = FunctionTool(self.tool)._get_declaration()
        dumped = declaration.model_dump(exclude_none=True)
        schema = dumped.get("parameters_json_schema") or dumped.get("parameters")
        for name, spec in (schema.get("properties") or {}).items():
            self.assertNotIn(
                "bool",
                str(spec).lower(),
                msg=f"parameter {name!r} lets the model assert evidence state",
            )

    def test_agent_declares_required_gemini_model_and_tool(self):
        self.assertTrue(agent_module.MODEL.startswith("gemini-3"))
        agent = agent_module.build_verifier_agent(self.ledger)
        self.assertEqual(agent.model, agent_module.MODEL)
        self.assertEqual(len(agent.tools), 1)

    def test_unknown_task_id_abstains(self):
        result = self.tool(
            task_id="does-not-exist", claim="All done"
        )
        self.assertEqual(result["status"], VerificationStatus.ABSTAIN.value)

    def test_tool_abstains_while_runtime_evidence_is_only_self_reported(self):
        scenario.seed_incomplete_evidence(self.ledger)
        result = self.tool(
            task_id=scenario.TASK_ID, claim=scenario.WORKER_CLAIM
        )
        self.assertEqual(result["status"], VerificationStatus.ABSTAIN.value)
        self.assertEqual(result["missing"], ["runtime"])

    def test_tool_verifies_after_recovery_collects_runtime_evidence(self):
        scenario.seed_incomplete_evidence(self.ledger)
        # Recovery performs a real HTTP probe against a real server.
        with serving(lambda h: send_json(h, 200, {"status": "ok"})) as url:
            scenario.collect_runtime_evidence(self.ledger, url, timeout=5)
        result = self.tool(
            task_id=scenario.TASK_ID, claim=scenario.WORKER_CLAIM
        )
        self.assertEqual(result["status"], VerificationStatus.VERIFIED.value)
        self.assertEqual(result["missing"], [])


if __name__ == "__main__":
    unittest.main()
