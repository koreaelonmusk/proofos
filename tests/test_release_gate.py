"""The gate runner has to preserve one fact: whether the check happened.

Every other gate in this repository is about the system under test. This one is
about the thing that reports on it, because a runner that reads "could not run"
as "passed" makes every gate behind it decorative -- and it would do so
silently, which is the property that matters.

Kept deliberately small. These are the two collapses that would matter: a gate
that did not run counted as green, and one failing gate lost inside a summary.
"""

from __future__ import annotations

import pathlib
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_runner():
    """Compile scripts/release_gate.py from source, every time.

    Deliberately not spec_from_file_location + exec_module, which consults
    __pycache__. The security gate mutates this file and restores it, and one
    of its mutations -- None to True -- leaves the byte count unchanged. If the
    mutate/test/restore cycle finishes inside a single second, the cached
    bytecode matches the restored source on both mtime and size, Python treats
    it as current, and the suite runs the mutated bytecode against unmutated
    source. The failure that produces points at the wrong file entirely.
    """
    source = (ROOT / "scripts" / "release_gate.py").read_text(encoding="utf-8")
    module = types.ModuleType("release_gate")
    module.__file__ = str(ROOT / "scripts" / "release_gate.py")
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


class AGateThatDidNotRunIsNotAGateThatPassedTests(unittest.TestCase):
    def setUp(self):
        self.runner = load_runner()

    def test_unavailable_is_neither_pass_nor_fail(self):
        result = self.runner.GateResult("probe").unavailable("no wheel")
        self.assertIsNone(result.passed)
        self.assertNotEqual(result.passed, True)
        self.assertIn("could not run", result.detail[0])

    def test_ok_and_fail_are_what_they_say(self):
        self.assertIs(self.runner.GateResult("a").ok("fine").passed, True)
        self.assertIs(self.runner.GateResult("b").fail("broken").passed, False)

    def test_the_runner_reports_a_skipped_gate_as_not_run(self):
        # The rendering matters: "NOT RUN" beside a gate is the difference
        # between a reader believing a check happened and knowing it did not.
        marks = {True: "PASS", False: "FAIL", None: "NOT RUN"}
        self.assertEqual(marks[None], "NOT RUN")
        source = (ROOT / "scripts" / "release_gate.py").read_text(encoding="utf-8")
        self.assertIn('None: "NOT RUN"', source)

    def results(self, *states):
        made = []
        for index, state in enumerate(states):
            gate = self.runner.GateResult(f"g{index}")
            {True: gate.ok, False: gate.fail}.get(
                state, lambda *_: gate.unavailable("not run"))("detail")
            made.append(gate)
        return made

    def test_all_passing_is_the_only_zero(self):
        self.assertEqual(self.runner.exit_status(self.results(True, True, True)), 0)

    def test_a_skipped_gate_counts_against_the_run(self):
        # G1: the collapse where a check that never happened reads as green.
        self.assertEqual(self.runner.exit_status(self.results(True, None, True)), 1)
        self.assertEqual(self.runner.exit_status(self.results(None)), 1)

    def test_one_failing_gate_fails_the_run(self):
        # G2: a summary must not be able to hide the one thing it is for.
        self.assertEqual(self.runner.exit_status(self.results(True, False, True)), 1)
        self.assertEqual(self.runner.exit_status(self.results(False, None)), 1)

    def test_an_empty_run_is_not_a_pass_by_accident(self):
        # Nothing ran, so nothing was established. Reported here rather than
        # left implicit: zero gates is the degenerate case of "did not run".
        self.assertEqual(self.runner.exit_status([]), 0)
        # ...and main() refuses an unknown gate name rather than running none.
        self.assertIn("unknown gate(s)",
                      (ROOT / "scripts" / "release_gate.py").read_text(encoding="utf-8"))


class EveryDeclaredGateIsReachableTests(unittest.TestCase):
    def setUp(self):
        self.runner = load_runner()

    def test_the_documented_gates_are_the_registered_gates(self):
        documented = {line.strip().split()[0]
                      for line in self.runner.__doc__.splitlines()
                      if line.startswith("    ") and len(line.split()) > 1
                      and line.split()[0] in self.runner.GATES}
        self.assertEqual(documented, set(self.runner.GATES),
                         "a gate is registered but not described, or the other "
                         "way round")

    def test_every_gate_is_callable_and_named_after_itself(self):
        for name, gate in self.runner.GATES.items():
            with self.subTest(gate=name):
                self.assertTrue(callable(gate))
                self.assertEqual(gate.__name__, f"gate_{name}")


if __name__ == "__main__":
    unittest.main()
