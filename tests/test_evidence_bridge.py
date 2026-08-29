"""The wall between translating a submission and encoding it as evidence.

P7 established that an adapter is not a judge. P8 adds the next wall: an adapter
is not an evidence encoder either. Translation lives in ``proofos.adapters`` /
``proofos.adapter`` and holds no verifier type; encoding lives here, in
``proofos.evidence_bridge``, and it is the only place a neutral submission
becomes ``Evidence``. The provenance it writes is fixed by the code -- always
EXECUTOR, never OBSERVED, never chosen by the caller or the payload.

These tests hold that wall structurally (against the modules' own source) and
behaviourally (the loudest self-certifying payload still abstains, while an
independent observation on the ordinary trusted path verifies).
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import unittest

from proofos.adapters import AdapterEnvelope, HttpAdapter, PythonAdapter
from proofos.evidence_bridge import evidence_from_envelope
from proofos.verifier import (
    Evidence,
    EvidenceSource,
    Requirement,
    VerificationStatus,
    verify_completion,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
BRIDGE_SRC = ROOT / "proofos" / "evidence_bridge.py"
ADAPTERS_SRC = ROOT / "proofos" / "adapters.py"
ADAPTER_SRC = ROOT / "proofos" / "adapter.py"

NOW = 1_700_000_000.0
KIND = "task_outcome"
REQ = Requirement(KIND, max_age_seconds=900)

# As loud as a self-certifying framework gets: it declares success, trust, and
# observed provenance. After encoding it must still be EXECUTOR evidence.
LOUD = {"verified": True, "trusted": True, "source": "OBSERVED",
        "authority": "verifier", "confidence": 1.0}


def envelope(claim="Task complete.", extra=None, tool_results=()):
    return PythonAdapter("acme-runner", framework="plain-python").normalize(
        actor_id="deploy-agent", task_id="DEPLOY-9", claim=claim,
        execution_id="exec_1", at=NOW, tool_results=tool_results, extra=extra or {})


def _identifiers(path: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def _imported(path: pathlib.Path) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    return imported


class A_AdaptersDoesNotEncodeEvidenceTests(unittest.TestCase):
    """A: adapters.py no longer imports Evidence / EvidenceSource."""

    def test_adapters_imports_no_verifier_evidence_types(self):
        imported = _imported(ADAPTERS_SRC)
        self.assertNotIn("Evidence", imported)
        self.assertNotIn("EvidenceSource", imported)


class B_AsEvidenceIsGoneTests(unittest.TestCase):
    """B: the envelope-level as_evidence encoder has been removed, no wrapper."""

    def test_adapter_envelope_has_no_as_evidence(self):
        self.assertFalse(hasattr(AdapterEnvelope, "as_evidence"))

    def test_adapters_source_does_not_define_as_evidence(self):
        self.assertNotIn("as_evidence", _identifiers(ADAPTERS_SRC))


class C_ProvenanceIsNotAnInputTests(unittest.TestCase):
    """C: the bridge takes no caller-selected provenance."""

    def test_signature_is_only_envelope_and_kind(self):
        params = list(inspect.signature(evidence_from_envelope).parameters)
        self.assertEqual(params, ["envelope", "kind"])

    def test_no_provenance_shaped_parameter_exists(self):
        params = set(inspect.signature(evidence_from_envelope).parameters)
        for forbidden in ("source", "trusted", "observed", "verified", "provenance", "collector"):
            self.assertNotIn(forbidden, params)


class D_BridgeNeverEmitsObservedTests(unittest.TestCase):
    """D: no path in the bridge reaches OBSERVED -- structurally and behaviourally."""

    def test_the_bridge_source_never_names_observed(self):
        self.assertNotIn("OBSERVED", _identifiers(BRIDGE_SRC))

    def test_every_record_is_executor_for_any_payload(self):
        env = envelope(extra=LOUD, tool_results=[
            {"tool": "http_get", "payload": {"status": 200, "verified": True}, "at": NOW}])
        sources = {e.source for e in evidence_from_envelope(env, KIND)}
        self.assertEqual(sources, {EvidenceSource.EXECUTOR})
        self.assertNotIn(EvidenceSource.OBSERVED, sources)


class E_BridgeDoesNotVerifyTests(unittest.TestCase):
    """E: the bridge encodes; it does not decide, trust, or grant."""

    def test_bridge_imports_no_verification_authority(self):
        imported = _imported(BRIDGE_SRC)
        for forbidden in ("verify_completion", "VerificationResult", "VerificationStatus",
                          "EvidenceLedger", "ObservationGrant", ".ledger", ".capabilities",
                          ".ingestion", ".registry", ".attestation", ".collector_registry"):
            self.assertNotIn(forbidden, imported, f"bridge imports {forbidden}")

    def test_bridge_names_no_verdict_or_grant_verb(self):
        used = _identifiers(BRIDGE_SRC)
        for forbidden in ("verify_completion", "verify", "trust", "grant", "accept",
                          "certify", "VerificationResult"):
            self.assertNotIn(forbidden, used)


class F_VerifiedFieldHasNoAuthorityTests(unittest.TestCase):
    """F: "verified": true does not change the encoded provenance."""

    def test_verified_true_still_yields_executor(self):
        plain = [e.source for e in evidence_from_envelope(envelope(), KIND)]
        loud = [e.source for e in evidence_from_envelope(envelope(extra={"verified": True}), KIND)]
        self.assertEqual(plain, loud)
        self.assertEqual(set(loud), {EvidenceSource.EXECUTOR})


class G_ObservedFieldHasNoAuthorityTests(unittest.TestCase):
    """G: "source": "OBSERVED" in the payload does not change the provenance."""

    def test_source_observed_string_still_yields_executor(self):
        env = envelope(extra={"source": "OBSERVED"})
        for e in evidence_from_envelope(env, KIND):
            self.assertIs(e.source, EvidenceSource.EXECUTOR)
            self.assertIsNot(e.source, EvidenceSource.OBSERVED)


class EncodingBehaviourIsPreservedTests(unittest.TestCase):
    """The extracted encoding reproduces the old as_evidence behaviour exactly."""

    def test_the_claim_becomes_one_executor_record_attributed_to_the_actor(self):
        records = evidence_from_envelope(envelope(), KIND)
        self.assertEqual(records[0].kind, KIND)
        self.assertEqual(records[0].value, "Task complete.")
        self.assertIs(records[0].source, EvidenceSource.EXECUTOR)
        self.assertEqual(records[0].collector, "deploy-agent")

    def test_each_tool_result_adds_an_executor_record_attributed_to_the_actor(self):
        env = envelope(tool_results=[{"tool": "http_get", "payload": {"status": 200}, "at": NOW}])
        records = evidence_from_envelope(env, KIND)
        self.assertEqual(len(records), 2)
        self.assertIs(records[1].source, EvidenceSource.EXECUTOR)
        self.assertEqual(records[1].collector, "deploy-agent")
        self.assertIn("http_get", records[1].value)

    def test_encoding_is_deterministic(self):
        a = evidence_from_envelope(envelope(), KIND)
        b = evidence_from_envelope(envelope(), KIND)
        self.assertEqual([e.content_hash for e in a], [e.content_hash for e in b])


class GoldenTrustSeparationTests(unittest.TestCase):
    """Same claim, two provenance paths, two answers -- the difference is the path."""

    def test_untrusted_route_abstains(self):
        # submission → adapter → bridge → EXECUTOR evidence → verifier → ABSTAIN
        env = envelope(extra=LOUD)
        result = verify_completion("Task complete.", evidence_from_envelope(env, KIND), [REQ], now=NOW)
        self.assertEqual(result.status, VerificationStatus.ABSTAIN)

    def test_trusted_route_verifies(self):
        # independent collector → OBSERVED evidence → verifier → VERIFIED
        observed = Evidence(kind=KIND, value="observed independently",
                            source=EvidenceSource.OBSERVED, collected_at=NOW,
                            collector="independent-collector")
        result = verify_completion("Task complete.", [observed], [REQ], now=NOW)
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_the_difference_is_provenance_not_wording(self):
        # Identical claim string down both routes; only the trust path differs.
        claim = "Task complete."
        untrusted = verify_completion(
            claim, evidence_from_envelope(envelope(claim=claim, extra=LOUD), KIND), [REQ], now=NOW)
        trusted = verify_completion(
            claim, [Evidence(kind=KIND, value=claim, source=EvidenceSource.OBSERVED,
                             collected_at=NOW, collector="independent-collector")], [REQ], now=NOW)
        self.assertEqual(untrusted.status, VerificationStatus.ABSTAIN)
        self.assertEqual(trusted.status, VerificationStatus.VERIFIED)


class TheTwoAdapterModulesStayDistinctTests(unittest.TestCase):
    """P7's neutral adapter never grew an encoder; the wall is one-directional."""

    def test_proofos_adapter_still_encodes_no_evidence(self):
        # The singular P7 adapter imports nothing from the core and holds no encoder.
        imported = _imported(ADAPTER_SRC)
        self.assertNotIn("Evidence", imported)
        self.assertNotIn("EvidenceSource", imported)
        self.assertNotIn("evidence_from_envelope", _identifiers(ADAPTER_SRC))


if __name__ == "__main__":
    unittest.main()
