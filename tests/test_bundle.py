"""A proof bundle is a record of a decision. It is not a decision.

Two properties get most of the attention here. The first is that this module
cannot create evidence -- ``Evidence`` is not imported and not constructed, so
the serializer has no route to a provenance no matter what a file says. The
second is that export fails closed on anything that must not travel: a bundle is
made to be sent to people, and redacting a secret would leave a file that still
asserts a verdict while no longer carrying what the verdict rested on.
"""

from __future__ import annotations

import ast
import json
import pathlib
import unittest

from proofos import Evidence, EvidenceLedger, EvidenceSource, ProofOS, Requirement
from proofos.bundle import (
    BUNDLE_KIND,
    BUNDLE_SCHEMA,
    MAX_VALUE,
    BundleError,
    BundleIntegrityError,
    EvidenceRecord,
    ProofBundle,
    SensitiveContentError,
    export_bundle,
    inspect,
    load_bundle,
    refuse_sensitive_content,
    render_inspection,
)

MODULE = pathlib.Path(__file__).resolve().parent.parent / "proofos" / "bundle.py"
NOW = 1_700_000_000.0
KIND = "service_health"
CLAIM = "Deployment complete."
COLLECTOR = "proofos-collector"


def observed_ledger(value: str = "GET /health -> 200", at: float = NOW - 10,
                    collector: str = COLLECTOR) -> EvidenceLedger:
    """A ledger holding one genuine observation, written through a grant."""
    ledger = EvidenceLedger()
    ledger.open_task("DEPLOY-9", (Requirement(KIND, max_age_seconds=900),))
    grant = ledger.grant_observation(collector, (KIND,))
    ledger.seal()
    ledger.record("DEPLOY-9", Evidence(kind=KIND, value=value,
                                       source=EvidenceSource.OBSERVED,
                                       collected_at=at, collector=collector),
                  grant)
    return ledger


def self_reported_ledger() -> EvidenceLedger:
    ledger = EvidenceLedger()
    ledger.open_task("DEPLOY-9", (Requirement(KIND, max_age_seconds=900),))
    ledger.seal()
    ledger.record("DEPLOY-9", Evidence(kind=KIND, value="I checked, it is up.",
                                       source=EvidenceSource.EXECUTOR,
                                       collected_at=NOW - 10,
                                       collector="deploy-agent"))
    return ledger


def bundle_from(ledger: EvidenceLedger, *, created_at: float = NOW + 1,
                **overrides):
    decision = ProofOS().verify_recorded(ledger, "DEPLOY-9", CLAIM, now=NOW)
    kwargs = dict(
        claim=CLAIM,
        requirements=ledger.requirements("DEPLOY-9"),
        evidence=ledger.evidence("DEPLOY-9"),
        task_id="DEPLOY-9",
        verification_time=NOW,
        created_at=created_at,
        actor_id="deploy-agent",
        policy_id="strict-v1",
        recorded_verdict=str(decision.status),
        recorded_reason=str(decision.reason),
    )
    kwargs.update(overrides)
    return export_bundle(**kwargs)


def mutate(bundle: ProofBundle, **changes) -> dict:
    """Edit a serialized bundle without touching its digest."""
    raw = json.loads(bundle.to_json())
    raw.update(changes)
    return raw


class SerializationWorksTests(unittest.TestCase):
    def test_a_decision_round_trips_unchanged(self):
        bundle = bundle_from(observed_ledger())
        self.assertEqual(load_bundle(bundle.to_json()), bundle)

    def test_the_bundle_names_itself_and_its_schema(self):
        bundle = bundle_from(observed_ledger())
        self.assertEqual(bundle.schema_version, BUNDLE_SCHEMA)
        self.assertEqual(bundle.bundle_kind, BUNDLE_KIND)
        self.assertTrue(bundle.bundle_id.startswith("pb_"))

    def test_the_records_survive_intact(self):
        bundle = bundle_from(observed_ledger())
        record = bundle.evidence[0]
        self.assertEqual(record.kind, KIND)
        self.assertEqual(record.source, "OBSERVED")
        self.assertEqual(record.collector, COLLECTOR)
        self.assertTrue(record.intact)

    def test_the_requirement_horizon_travels_with_it(self):
        bundle = bundle_from(observed_ledger())
        self.assertEqual(bundle.requirements[0].kind, KIND)
        self.assertEqual(bundle.requirements[0].max_age_seconds, 900)

    def test_a_bundle_with_no_requirements_is_refused(self):
        with self.assertRaises(BundleError):
            export_bundle(claim=CLAIM, requirements=(), evidence=(),
                          task_id="DEPLOY-9", verification_time=NOW,
                          created_at=NOW)


class ThisModuleCannotCreateEvidenceTests(unittest.TestCase):
    """The wall, checked as a structure rather than promised in a docstring."""

    def test_it_never_imports_or_constructs_evidence(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        for forbidden in ("Evidence", "EvidenceSource", "EvidenceLedger",
                          "ObservationGrant", "verify_completion", "ProofOS",
                          ".verifier", ".ledger", ".api", ".capabilities",
                          ".ingestion"):
            self.assertNotIn(forbidden, imported,
                             f"bundle.py imports {forbidden}")

    def test_loading_yields_inert_records_not_evidence(self):
        record = load_bundle(bundle_from(observed_ledger()).to_json()).evidence[0]
        self.assertIsInstance(record, EvidenceRecord)
        for forbidden in ("as_evidence", "record", "grant", "verify"):
            self.assertFalse(hasattr(record, forbidden))
        # `source` here is a string describing what was recorded, not a
        # provenance the kernel would honour.
        self.assertIsInstance(record.source, str)

    def test_it_performs_no_io_and_reads_no_clock(self):
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("time.time", "datetime", "os.environ", "open(",
                          "pathlib", "urllib", "socket", "subprocess"):
            self.assertNotIn(forbidden, source)

    def test_no_exported_name_decides_anything(self):
        import proofos.bundle as module

        for name in module.__all__:
            self.assertNotIn(name.lower(), {"verify", "verified", "abstain",
                                            "decide", "verdict"})


class IntegrityTests(unittest.TestCase):
    def test_the_digest_covers_the_payload_and_excludes_itself(self):
        bundle = bundle_from(observed_ledger())
        self.assertNotIn("digest", bundle.payload())
        self.assertEqual(bundle.digest, bundle.compute_digest())
        self.assertTrue(bundle.intact)

    def test_a_mutated_protected_field_breaks_integrity(self):
        bundle = bundle_from(observed_ledger())
        for field, value in (("claim", "Something else entirely."),
                             ("task_id", "OTHER-TASK"),
                             ("verification_time", NOW + 5),
                             ("recorded_verdict", "ABSTAIN"),
                             ("recorded_reason", "EVIDENCE_MISSING")):
            with self.subTest(field=field):
                tampered = load_bundle(mutate(bundle, **{field: value}))
                self.assertFalse(tampered.intact)
                with self.assertRaises(BundleIntegrityError):
                    tampered.require_intact()

    def test_a_mutated_evidence_record_breaks_integrity(self):
        bundle = bundle_from(observed_ledger())
        raw = json.loads(bundle.to_json())
        raw["evidence"][0]["source"] = "OBSERVED"
        raw["evidence"][0]["collector"] = "someone-else"
        with self.assertRaises(BundleIntegrityError):
            load_bundle(raw).require_intact()

    def test_a_broken_bundle_is_never_repaired_by_recomputing(self):
        # The tempting shortcut, refused. Recomputing a digest over tampered
        # bytes proves only that the digest can be made to agree with anything.
        bundle = bundle_from(observed_ledger())
        tampered = load_bundle(mutate(bundle, claim="Anything I like."))
        self.assertNotEqual(tampered.digest, tampered.compute_digest())
        with self.assertRaises(BundleIntegrityError):
            tampered.require_intact()
        self.assertNotEqual(tampered.digest, tampered.compute_digest())

    def test_an_evidence_record_that_lies_about_its_own_digest_is_refused(self):
        ledger = observed_ledger()
        broken = Evidence(kind=KIND, value="GET /health -> 200",
                          source=EvidenceSource.OBSERVED, collected_at=NOW,
                          collector=COLLECTOR, content_hash="0" * 64)
        with self.assertRaises(BundleError):
            export_bundle(claim=CLAIM,
                          requirements=ledger.requirements("DEPLOY-9"),
                          evidence=(broken,), task_id="DEPLOY-9",
                          verification_time=NOW, created_at=NOW)


class CanonicalizationTests(unittest.TestCase):
    def test_the_same_decision_exports_byte_identically(self):
        one = bundle_from(observed_ledger()).to_json()
        two = bundle_from(observed_ledger()).to_json()
        self.assertEqual(one, two)

    def test_the_digest_follows_the_content_not_the_creation_moment(self):
        early = bundle_from(observed_ledger(), created_at=NOW + 1)
        late = bundle_from(observed_ledger(), created_at=NOW + 9_999)
        self.assertNotEqual(early.digest, late.digest)
        self.assertNotEqual(early.bundle_id, late.bundle_id)

    def test_key_order_in_the_input_does_not_change_the_digest(self):
        bundle = bundle_from(observed_ledger())
        raw = json.loads(bundle.to_json())
        shuffled = dict(reversed(list(raw.items())))
        self.assertEqual(load_bundle(shuffled).digest, bundle.digest)
        self.assertTrue(load_bundle(shuffled).intact)

    def test_evidence_order_is_preserved_not_sorted(self):
        # Order is what the run did. A serializer that sorts it is editing the
        # record, even when the sort looks tidier.
        ledger = EvidenceLedger()
        ledger.open_task("DEPLOY-9", (Requirement(KIND),))
        ledger.seal()
        for value in ("third", "first", "second"):
            ledger.record("DEPLOY-9", Evidence(
                kind=KIND, value=value, source=EvidenceSource.EXECUTOR,
                collected_at=NOW, collector="deploy-agent"))
        bundle = bundle_from(ledger)
        self.assertEqual([e.value for e in bundle.evidence],
                         ["third", "first", "second"])


class ContentSafetyTests(unittest.TestCase):
    """Export refuses. It does not redact, truncate, or quietly drop."""

    SECRETS = [
        ("private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"),
        ("bearer", "Authorization: Bearer ya29.a0AfB_abcdefghijklmnop"),
        ("aws key", "used AKIAIOSFODNN7EXAMPLE to read the bucket"),
        ("openai key", "sk-abcdefghijklmnopqrstuvwxyz012345"),
        ("github token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        ("slack token", "xoxb-11111111-2222222222-abcdefghijkl"),
        ("google key", "AIzaSyA1234567890abcdefghijklmnopqrstuv"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"),
        ("signed url", "https://storage/o/x?X-Goog-Signature=deadbeefdeadbeef1234"),
        ("inline secret", "client_secret=hunter2hunter2"),
        ("cookie", "Set-Cookie: session=abc123"),
        ("embedded image", "data:image/png;base64,iVBORw0KGgo="),
        ("windows home", r"read C:\Users\alice\proof.json"),
        ("unix home", "read /home/alice/proof.json"),
        ("machine temp", "wrote /tmp/proofos-run-1234/out.json"),
    ]

    def test_export_fails_closed_on_anything_that_must_not_travel(self):
        for label, value in self.SECRETS:
            with self.subTest(case=label):
                with self.assertRaises(SensitiveContentError):
                    bundle_from(observed_ledger(value=value))

    def test_a_secret_anywhere_in_the_payload_is_caught(self):
        # Not only evidence values. A credential pasted into a collector name is
        # still a credential.
        with self.assertRaises(SensitiveContentError):
            bundle_from(observed_ledger(),
                        claim="deployed with sk-abcdefghijklmnopqrstuvwxyz012345")

    def test_ordinary_evidence_is_not_flagged(self):
        # A scanner that fires on real evidence gets switched off, and a scanner
        # that is off protects nothing.
        for value in ("GET https://svc-abc.a.run.app/health -> 200 in 41ms",
                      "sha256:9f2a3b4c5d6e7f80", "revision svc-00009-f2s ready",
                      "3 of 3 checks passed; latency p99 210ms",
                      "artifact digest 90927444630edb45"):
            with self.subTest(value=value):
                bundle = bundle_from(observed_ledger(value=value))
                refuse_sensitive_content(bundle)

    def test_an_unbounded_value_is_refused_rather_than_truncated(self):
        # Truncating would change what the verdict rested on and leave the
        # verdict in place, which is the failure mode worth avoiding.
        with self.assertRaises(BundleError) as caught:
            bundle_from(observed_ledger(value="x" * (MAX_VALUE + 1)))
        self.assertIn("longer than", str(caught.exception))

    def test_there_is_no_field_for_a_prompt_or_a_transcript(self):
        # Handled structurally rather than by scanning: a shape with nowhere to
        # put a transcript cannot leak one by accident.
        raw = json.loads(bundle_from(observed_ledger()).to_json())
        for forbidden in ("prompt", "prompts", "reasoning", "transcript",
                          "messages", "completion", "screenshot"):
            self.assertNotIn(forbidden, raw)


class TheWireIsValidatedTests(unittest.TestCase):
    def test_an_unknown_field_is_refused_rather_than_ignored(self):
        # A field the parser drops silently is a field somebody can hide meaning
        # in. This is also what stops a bundle asking for authority: there is no
        # grants field, and one that arrived would be doing something.
        bundle = bundle_from(observed_ledger())
        for extra in ("grants", "capabilities", "trusted_collectors",
                      "policy_override", "observation_grant"):
            with self.subTest(field=extra):
                with self.assertRaises(BundleError) as caught:
                    load_bundle(mutate(bundle, **{extra: ["anything"]}))
                self.assertIn("unexpected", str(caught.exception))

    def test_a_missing_field_is_refused(self):
        raw = json.loads(bundle_from(observed_ledger()).to_json())
        raw.pop("recorded_verdict")
        with self.assertRaises(BundleError):
            load_bundle(raw)

    def test_a_foreign_schema_is_refused(self):
        bundle = bundle_from(observed_ledger())
        with self.assertRaises(BundleError):
            load_bundle(mutate(bundle, schema_version=99))
        with self.assertRaises(BundleError):
            load_bundle(mutate(bundle, bundle_kind="something.else.v1"))

    def test_malformed_input_is_refused(self):
        for payload in ("not json", "[]", "3", '{"schema_version": 1}'):
            with self.subTest(payload=payload):
                with self.assertRaises(BundleError):
                    load_bundle(payload)

    def test_a_malformed_record_is_refused(self):
        bundle = bundle_from(observed_ledger())
        raw = json.loads(bundle.to_json())
        for change in ({"valid": "yes"}, {"collected_at": "soon"},
                       {"kind": ""}, {"content_hash": None}):
            with self.subTest(change=change):
                broken = json.loads(bundle.to_json())
                broken["evidence"][0].update(change)
                with self.assertRaises(BundleError):
                    load_bundle(broken)
        raw["evidence"][0]["surprise"] = 1
        with self.assertRaises(BundleError):
            load_bundle(raw)

    def test_a_non_finite_timestamp_is_refused(self):
        with self.assertRaises(BundleError):
            bundle_from(observed_ledger(), created_at=float("inf"))


class InspectionHasNoAuthorityTests(unittest.TestCase):
    def test_inspection_reports_facts_and_decides_nothing(self):
        facts = inspect(bundle_from(observed_ledger()))
        self.assertEqual(facts["integrity"], "intact")
        self.assertEqual(facts["evidence_count"], 1)
        self.assertEqual(facts["requirement_count"], 1)
        self.assertEqual(facts["recorded_verdict"], "VERIFIED")
        self.assertEqual(facts["sensitive_content"], "clean")
        for forbidden in ("verdict", "status", "verified"):
            self.assertNotIn(forbidden, facts)

    def test_inspection_of_a_self_certifying_bundle_still_only_reports(self):
        # It says what the file claims. It does not agree with it.
        bundle = bundle_from(self_reported_ledger(), recorded_verdict="VERIFIED",
                             recorded_reason="NONE")
        facts = inspect(bundle)
        self.assertEqual(facts["recorded_verdict"], "VERIFIED")
        self.assertEqual(facts["integrity"], "intact")

    def test_inspection_says_when_integrity_is_broken(self):
        bundle = bundle_from(observed_ledger())
        tampered = load_bundle(mutate(bundle, claim="Anything."))
        self.assertEqual(inspect(tampered)["integrity"], "BROKEN")

    def test_the_rendering_carries_the_disclaimer(self):
        text = render_inspection(bundle_from(observed_ledger()))
        self.assertIn("recorded_verdict is what the original run concluded",
                      text)
        self.assertIn("not evidence of anything", text)


if __name__ == "__main__":
    unittest.main()
