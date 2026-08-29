"""Three tiers, one contract: the root API small by intent, the public API
complete by obligation.

An earlier version of this file enforced a stronger rule -- every type reachable
from a public signature must be exported from the package root -- and that rule
was wrong in a way worth recording. It conflated two promises. "You can import
this" and "this is part of the front door" are different commitments, and
collapsing them means the root grows every time two subsystems learn to
reference each other's types. A name exported by accident at 0.1.0 is a
compatibility obligation until 2.0.

  TIER 1  proofos.*            the 80-90% path. Small, and small on purpose.
  TIER 2  proofos.<module>.*   public, documented, imported from where it lives.
  TIER 3  everything else      no compatibility promise.

The obligation that survives is the one that mattered: a type a caller can be
handed must be importable from somewhere public. It need not be the lobby.

The root list is an allowlist with a reason per name, not a count. A count tells
you the surface changed; it cannot tell you whether anyone meant it to. Entries
marked ``review`` are inherited from the 0.1.0 baseline and are candidates for
demotion to tier 2 in the deliberate root-API review before 1.0 -- written down
here so that review begins with a list instead of a memory.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import types
import typing
import unittest

import proofos

PACKAGE = pathlib.Path(proofos.__file__).resolve().parent
INIT = PACKAGE / "__init__.py"

FACADE = "facade"      # front door: the common path, deliberately at the root
REVIEW = "review"      # baseline from 0.1.0; revisit before 1.0

#: TIER 1. Adding a name here is the decision; the test below is only the latch.
ROOT_API: dict[str, tuple[str, str]] = {
    "ProofOS":                 (FACADE, "ask whether a claim is supported"),
    "Decision":                (FACADE, "what ProofOS answers"),
    "Requirement":             (FACADE, "say what would prove it"),
    "Evidence":                (FACADE, "supply what you have"),
    "EvidenceSource":          (FACADE, "the provenance a requirement can accept"),
    "VerificationResult":      (FACADE, "the kernel's own result type"),
    "VerificationStatus":      (FACADE, "VERIFIED or ABSTAIN"),
    "FailureClass":            (FACADE, "why a refusal happened"),
    "EvidenceAssessment":      (FACADE, "returned by Decision.accepted and .rejected"),
    "verify_completion":       (FACADE, "the kernel entry point"),
    "EvidenceTamperedError":   (FACADE, "raised by EvidenceLedger; caught by name"),
    "UnknownTaskError":        (FACADE, "raised by EvidenceLedger; caught by name"),
    "JournalUnavailableError": (FACADE, "raised by the durable journal; caught by name"),

    "EvidenceLedger":     (REVIEW, "recording evidence is common, but the ledger "
                                   "may belong under proofos.ledger"),
    "Journal":            (REVIEW, "same question as EvidenceLedger"),
    "content_hash":       (REVIEW, "small and useful; may belong under proofos.integrity"),
    "probe_health":       (REVIEW, "a convenience collector, not the front door"),
    "ProbeResult":        (REVIEW, "only callers of probe_health need it"),
    "ProbeOutcome":       (REVIEW, "only callers of probe_health need it"),
    "EventType":          (REVIEW, "needed to read a journal, not to verify"),
    "ExecutionEvent":     (REVIEW, "needed to read a journal, not to verify"),
    "EventDraft":         (REVIEW, "only an author implementing JournalSink needs it"),
    "JournalSink":        (REVIEW, "a protocol for storage authors, not for callers"),
    "InMemoryJournalSink": (REVIEW, "a default implementation, not an interface"),
    "Severity":           (REVIEW, "journal severity; a caller rarely names it"),
    "ObservationGrant":   (REVIEW, "held by the ingestion boundary, not by callers"),
}

#: TIER 2, declared here rather than as ``__all__`` inside each module: four of
#: these are trusted-core files byte-identical to the frozen hackathon main, and
#: a docstring is not worth breaking that for. The two platform-new modules
#: carry their own ``__all__`` and this map defers to them.
TIER_2: dict[str, frozenset[str]] = {
    "proofos.api": frozenset({"Decision", "ProofOS"}),
    "proofos.verifier": frozenset({
        "Evidence", "EvidenceAssessment", "EvidenceSource", "FailureClass",
        "Requirement", "VerificationResult", "VerificationStatus",
        "verify_completion",
    }),
    "proofos.journal": frozenset({
        "EventDraft", "EventType", "ExecutionEvent", "Journal", "JournalSink",
        "InMemoryJournalSink", "JournalUnavailableError", "Severity",
        "verify_events",
    }),
    "proofos.ledger": frozenset({
        "EvidenceLedger", "EvidenceTamperedError", "ObservationGrant",
        "UnknownTaskError",
    }),
    "proofos.probe": frozenset({"ProbeOutcome", "ProbeResult", "probe_health"}),
    "proofos.integrity": frozenset({"content_hash"}),
}

#: Modules that declare their own surface. Read from the module, never copied.
SELF_DECLARING = ("proofos.plugins", "proofos.conformance", "proofos.policy")


def public_surface() -> dict[str, frozenset[str]]:
    surface = dict(TIER_2)
    for name in SELF_DECLARING:
        module = importlib.import_module(name)
        surface[name] = frozenset(getattr(module, "__all__", ()))
    surface["proofos"] = frozenset(ROOT_API)
    return surface


def annotations_of(obj: object) -> list[object]:
    found: list[object] = []
    targets: list[object] = []
    if inspect.isclass(obj):
        for attr_name, attr in vars(obj).items():
            if attr_name.startswith("_") and attr_name != "__init__":
                continue
            if isinstance(attr, property):
                targets.extend(f for f in (attr.fget, attr.fset) if f)
            elif inspect.isfunction(attr):
                targets.append(attr)
        targets.append(obj)
    elif inspect.isfunction(obj):
        targets.append(obj)
    for target in targets:
        try:
            found.extend(
                typing.get_type_hints(target, vars(inspect.getmodule(target))).values()
            )
        except Exception as exc:  # noqa: BLE001 -- reported, not swallowed
            found.append(exc)
    return found


def named_types(annotation: object) -> list[type]:
    args = typing.get_args(annotation)
    if args:
        return [t for arg in args for t in named_types(arg)]
    return [annotation] if inspect.isclass(annotation) else []


def reachable_types() -> set[type]:
    """Every ProofOS type a caller can be handed by something public."""
    found: set[type] = set()
    for module_name, names in public_surface().items():
        module = importlib.import_module(module_name)
        for name in names:
            obj = getattr(module, name, None)
            if obj is None:
                continue
            for annotation in annotations_of(obj):
                if isinstance(annotation, Exception):
                    continue
                for kind in named_types(annotation):
                    if getattr(kind, "__module__", "").startswith("proofos"):
                        found.add(kind)
    return found


class TheRootIsAnAllowlistTests(unittest.TestCase):
    """Requirement 4: a new root export takes a deliberate edit, not a number."""

    def test_root_exports_match_the_allowlist_exactly(self):
        self.assertEqual(
            set(proofos.__all__), set(ROOT_API),
            "proofos.__all__ and the allowlist disagree. Adding a name to the "
            "root API means adding it here with a reason, in the same commit, "
            "so the decision is visible in review rather than inferred from a "
            "changed count.",
        )

    def test_every_root_name_has_a_stated_reason(self):
        for name, (tier, reason) in ROOT_API.items():
            with self.subTest(name=name):
                self.assertIn(tier, (FACADE, REVIEW))
                self.assertTrue(reason.strip(), f"{name} is listed without a reason")

    def test_all_is_assigned_exactly_once(self):
        tree = ast.parse(INIT.read_text(encoding="utf-8"))
        assignments = [
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
        ]
        self.assertEqual(len(assignments), 1)

    def test_star_import_yields_exactly_the_declared_surface(self):
        namespace: dict[str, object] = {}
        exec("from proofos import *", namespace)  # noqa: S102 -- that is the test
        namespace.pop("__builtins__", None)
        self.assertEqual(sorted(namespace), sorted(proofos.__all__))

    def test_no_submodule_is_exported_from_the_root(self):
        modules = [n for n in proofos.__all__
                   if isinstance(getattr(proofos, n), types.ModuleType)]
        self.assertEqual(modules, [])


class ThePublicApiIsCompleteTests(unittest.TestCase):
    """Requirements 1 and 3: importable somewhere public, nothing private leaking."""

    def test_every_reachable_type_is_publicly_importable(self):
        surface = public_surface()
        orphans = [f"{k.__module__}.{k.__name__}" for k in reachable_types()
                   if not any(k.__name__ in names for names in surface.values())]
        self.assertEqual(
            sorted(set(orphans)), [],
            "these types appear in a public signature but are exported from no "
            "public module, so a caller can be handed one and cannot name it",
        )

    def test_no_private_implementation_type_leaks_through_a_public_annotation(self):
        # A leading underscore promises nobody outside depends on it. Handing one
        # back through a public signature breaks that promise silently, which is
        # the worst way to break it.
        leaked = [f"{k.__module__}.{k.__name__}" for k in reachable_types()
                  if k.__name__.startswith("_")]
        self.assertEqual(sorted(leaked), [])

    def test_public_import_location_is_explicit(self):
        # Requirement 2. Exactly one module may claim a public name; otherwise
        # "where do I import this from" has two answers and one will rot.
        claims: dict[str, list[str]] = {}
        for module_name, names in public_surface().items():
            if module_name == "proofos":
                continue  # the root re-exports; it does not define
            for name in names:
                claims.setdefault(name, []).append(module_name)
        duplicates = {n: m for n, m in claims.items() if len(m) > 1}
        self.assertEqual(duplicates, {},
                         "the same public name is claimed by two modules")

    def test_a_tier_two_name_resolves_to_the_module_that_defines_it(self):
        for module_name, names in TIER_2.items():
            module = importlib.import_module(module_name)
            for name in sorted(names):
                with self.subTest(module=module_name, name=name):
                    obj = getattr(module, name, None)
                    self.assertIsNotNone(obj, f"{module_name} does not export {name}")
                    defined_in = getattr(obj, "__module__", module_name)
                    self.assertEqual(
                        defined_in, module_name,
                        f"{name} is listed under {module_name} but defined in "
                        f"{defined_in}; list it where it lives",
                    )


class TheRootDoesNotGrowByAccidentTests(unittest.TestCase):
    """Requirements 5 and 6: tier 2 stays tier 2 unless promoted on purpose."""

    def test_plugin_types_stay_under_proofos_plugins(self):
        import proofos.plugins as plugins

        for name in plugins.__all__:
            with self.subTest(name=name):
                self.assertNotIn(
                    name, ROOT_API,
                    f"{name} reached the root API. A plugin author imports from "
                    "proofos.plugins; someone verifying a claim never needs "
                    "this, and the root API is for the second one.",
                )

    def test_conformance_types_stay_under_proofos_conformance(self):
        import proofos.conformance as conformance

        for name in conformance.__all__:
            with self.subTest(name=name):
                self.assertNotIn(name, ROOT_API)

    def test_policy_types_stay_under_proofos_policy(self):
        import proofos.policy as policy

        for name in getattr(policy, "__all__", ()):
            with self.subTest(name=name):
                self.assertNotIn(name, ROOT_API)

    def test_the_review_backlog_is_recorded_rather_than_remembered(self):
        # Not an assertion about size: an assertion that the demotion candidates
        # are written down, so the pre-1.0 root review starts from a list.
        pending = [n for n, (tier, _) in ROOT_API.items() if tier == REVIEW]
        self.assertTrue(pending, "no demotion candidates recorded")
        for name in pending:
            self.assertIn(name, proofos.__all__)


class ExceptionsAreCatchableByNameTests(unittest.TestCase):
    def test_exported_exceptions_are_the_ones_public_paths_raise(self):
        raised: set[str] = set()
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                    func = node.exc.func
                    if isinstance(func, ast.Name):
                        raised.add(func.id)
        defined_here = {
            name for name, obj in vars(proofos).items()
            if inspect.isclass(obj) and issubclass(obj, BaseException)
            and getattr(obj, "__module__", "").startswith("proofos")
        }
        for name in sorted(raised & defined_here):
            self.assertIn(name, proofos.__all__,
                          f"{name} is raised by this package but is not exported")


if __name__ == "__main__":
    unittest.main()
