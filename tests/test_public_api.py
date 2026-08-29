"""The public surface is a promise, so it is checked rather than described.

Two defects motivated this file, both of which a reviewer reading the source
would have had to notice by eye:

``__init__.py`` assigned ``__all__`` twice. Python kept the second one, the
first became dead text, and the difference between them silently removed three
exception types that callers are expected to catch by name.

``Decision.accepted`` returns ``EvidenceAssessment`` objects that were not
exported. Code could receive one and had no supported way to name it -- an API
nobody can write a type annotation against.

Neither is caught by "does it import". Both are caught here.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import types
import typing
import unittest

import proofos

PACKAGE = pathlib.Path(proofos.__file__).resolve().parent
INIT = PACKAGE / "__init__.py"


def exported() -> dict[str, object]:
    return {name: getattr(proofos, name) for name in proofos.__all__}


def annotations_of(obj: object) -> list[object]:
    """Every annotation reachable from one exported name.

    Classes contribute their public methods, properties and dataclass fields;
    functions contribute their own signature. Anything that cannot be resolved
    is returned as the exception, so a broken annotation fails loudly instead of
    being skipped into silence.
    """
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
            hints = typing.get_type_hints(target, vars(inspect.getmodule(target)))
        except Exception as exc:  # noqa: BLE001 -- reported, not swallowed
            found.append(exc)
            continue
        found.extend(hints.values())
    return found


def named_types(annotation: object) -> list[type]:
    """Flatten a possibly-generic annotation into the concrete classes it names."""
    args = typing.get_args(annotation)
    if args:
        out: list[type] = []
        for arg in args:
            out.extend(named_types(arg))
        return out
    return [annotation] if inspect.isclass(annotation) else []


class TheSurfaceIsDeclaredOnceTests(unittest.TestCase):
    def test_all_is_assigned_exactly_once(self):
        # The defect this file exists for. A second assignment is not a merge
        # artefact you notice -- it is a working file that quietly means
        # something other than what it appears to say.
        tree = ast.parse(INIT.read_text(encoding="utf-8"))
        assignments = [
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets)
        ]
        self.assertEqual(len(assignments), 1,
                         f"__init__.py assigns __all__ {len(assignments)} times; "
                         "the last one wins and the others are dead text")

    def test_no_name_is_listed_twice(self):
        self.assertEqual(len(proofos.__all__), len(set(proofos.__all__)))

    def test_every_exported_name_exists(self):
        missing = [n for n in proofos.__all__ if not hasattr(proofos, n)]
        self.assertEqual(missing, [], f"__all__ names nothing importable: {missing}")

    def test_star_import_yields_exactly_the_declared_surface(self):
        namespace: dict[str, object] = {}
        exec("from proofos import *", namespace)  # noqa: S102 -- that is the test
        namespace.pop("__builtins__", None)
        self.assertEqual(sorted(namespace), sorted(proofos.__all__))


class TheSurfaceIsClosedTests(unittest.TestCase):
    """A type you can be handed is a type you must be able to name."""

    def test_every_type_reachable_from_an_export_is_itself_exported(self):
        surface = set(proofos.__all__)
        unreachable: list[str] = []
        for name, obj in exported().items():
            for annotation in annotations_of(obj):
                if isinstance(annotation, Exception):
                    self.fail(f"{name}: annotation could not be resolved: {annotation!r}")
                for kind in named_types(annotation):
                    module = getattr(kind, "__module__", "")
                    if not module.startswith("proofos"):
                        continue
                    if kind.__name__ not in surface:
                        unreachable.append(f"{name} -> {kind.__name__} ({module})")
        self.assertEqual(
            sorted(set(unreachable)), [],
            "these types appear in an exported signature but cannot be imported "
            "from proofos, so no caller can annotate against them",
        )

    def test_exported_exceptions_are_the_ones_public_paths_raise(self):
        # An error a caller is told to catch must be catchable by name. Matching
        # on message text is what people do when the class is not exported, and
        # message text is not an interface.
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


class TheSurfaceStaysSmallTests(unittest.TestCase):
    def test_no_submodule_is_exported(self):
        # Exporting a module exports everything inside it, forever.
        modules = [n for n in proofos.__all__
                   if isinstance(getattr(proofos, n), types.ModuleType)]
        self.assertEqual(modules, [])

    def test_the_surface_has_not_grown_without_a_decision(self):
        # Not a frozen list for its own sake: this is the number a reviewer
        # agreed to. Changing it should be a line in a diff someone reads.
        self.assertEqual(
            len(proofos.__all__), 26,
            "the public surface changed size; update this number in the same "
            "commit that changes __all__, so the growth is visible in review",
        )


if __name__ == "__main__":
    unittest.main()
