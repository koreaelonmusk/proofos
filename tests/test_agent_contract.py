import unittest

from google.adk.tools import FunctionTool

from proofos.verifier import VerificationStatus
from proofos_agent import agent as agent_module
from proofos_agent import scenario


def tool_parameter_names() -> list[str]:
    declaration = FunctionTool(agent_module.verify_task_completion)._get_declaration()
    dumped = declaration.model_dump(exclude_none=True)
    schema = dumped.get("parameters_json_schema") or dumped.get("parameters")
    return sorted((schema.get("properties") or {}).keys())


class ToolTrustBoundaryTests(unittest.TestCase):
    """The model must not be able to assert that evidence exists."""

    def setUp(self):
        agent_module.LEDGER.reset()

    def test_tool_exposes_no_model_controlled_evidence_parameters(self):
        params = tool_parameter_names()
        self.assertEqual(params, ["claim", "task_id"])

    def test_tool_schema_has_no_boolean_evidence_flags(self):
        declaration = FunctionTool(agent_module.verify_task_completion)._get_declaration()
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
        self.assertEqual(agent_module.root_agent.model, agent_module.MODEL)
        self.assertEqual(len(agent_module.root_agent.tools), 1)

    def test_unknown_task_id_abstains(self):
        result = agent_module.verify_task_completion(
            task_id="does-not-exist", claim="All done"
        )
        self.assertEqual(result["status"], VerificationStatus.ABSTAIN.value)

    def test_tool_abstains_while_runtime_evidence_is_only_self_reported(self):
        scenario.seed_incomplete_evidence(agent_module.LEDGER)
        result = agent_module.verify_task_completion(
            task_id=scenario.TASK_ID, claim=scenario.WORKER_CLAIM
        )
        self.assertEqual(result["status"], VerificationStatus.ABSTAIN.value)
        self.assertEqual(result["missing"], ["runtime"])

    def test_tool_verifies_after_recovery_collects_runtime_evidence(self):
        scenario.seed_incomplete_evidence(agent_module.LEDGER)
        scenario.collect_runtime_evidence(agent_module.LEDGER)
        result = agent_module.verify_task_completion(
            task_id=scenario.TASK_ID, claim=scenario.WORKER_CLAIM
        )
        self.assertEqual(result["status"], VerificationStatus.VERIFIED.value)
        self.assertEqual(result["missing"], [])


if __name__ == "__main__":
    unittest.main()
