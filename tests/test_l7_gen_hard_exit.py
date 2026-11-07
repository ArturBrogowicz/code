"""T-074b: no test leaves ml/l7_gen.py's hard-exit timer armed in the test process. l7_gen.main starts a daemon threading.Timer that ends the
process with os._exit(0) HARD_EXIT_S after the run's end; armed in a unittest process, it would end the suite with code 0 and no "Ran N
tests" line. tests/test_p4_families.py's real-generator test left one armed from 7ae6016 to 1cd2af7, saved only because its stats directory
was gone by the time it fired.

The guard finds, in the source of every tests/test_*.py, each call of l7_gen's main, run_group or main_group made in the test process
(an ast.Call, so a driver string run in a child interpreter is not one) without a literal "--plan", and the TestCase classes that make it
directly or through a module-level helper; it runs those classes here and fails if any of their tests leaves such a timer armed, cancelling
it. A future in-process call is picked up by the same scan. Nothing touches the machine."""
import ast
import glob
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import l7_gen_timer as LT

GEN_CALLS = ("main", "run_group", "main_group")


def _gen_names(tree):
    """(module aliases of l7_gen, names bound to its entry points) of a module's imports."""
    aliases, direct = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases |= {a.asname or a.name for a in node.names if a.name == "l7_gen"}
        elif isinstance(node, ast.ImportFrom) and node.module == "l7_gen":
            direct |= {a.asname or a.name for a in node.names if a.name in GEN_CALLS}
    return aliases, direct


def _armed_calls(node, aliases, direct):
    """The calls under `node` that run the generator in this process: an entry point of l7_gen with no literal "--plan" among its arguments."""
    out = []
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        gen = (isinstance(f, ast.Attribute) and f.attr in GEN_CALLS and isinstance(f.value, ast.Name) and f.value.id in aliases) or \
            (isinstance(f, ast.Name) and f.id in direct)
        if gen and not any(isinstance(a, ast.Constant) and a.value == "--plan" for arg in n.args for a in ast.walk(arg)):
            out.append(n)
    return out


def classes_that_run_the_generator(tests_dir=HERE):
    """["module.Class"] of the TestCase classes that call the generator in this process, directly or through a module-level helper."""
    out = []
    for path in sorted(glob.glob(os.path.join(tests_dir, "test_*.py"))):
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        aliases, direct = _gen_names(tree)
        if not aliases and not direct:
            continue
        helpers = {f.name for f in tree.body if isinstance(f, ast.FunctionDef) and _armed_calls(f, aliases, direct)}
        module = os.path.splitext(os.path.basename(path))[0]
        for cls in (c for c in tree.body if isinstance(c, ast.ClassDef)):
            uses = _armed_calls(cls, aliases, direct) or [n for n in ast.walk(cls) if isinstance(n, ast.Name) and n.id in helpers]
            if uses:
                out.append(f"{module}.{cls.name}")
    return out


class LeakResult(unittest.TestResult):
    """A result that, after each test, cancels and names any hard-exit timer the test left armed."""

    def __init__(self):
        super().__init__()
        self.leaks = {}

    def stopTest(self, test):
        super().stopTest(test)
        live = LT.live_hard_exits()
        for t in live:
            t.cancel()
        if live:
            self.leaks[test.id()] = len(live)


class HardExitTest(unittest.TestCase):
    def test_the_scan_finds_the_known_callers_and_no_driver_string(self):
        found = classes_that_run_the_generator()
        self.assertIn("test_p4_families.GeneratorTest", found)
        self.assertIn("test_p4_grouped.GeneratorTest", found)
        self.assertFalse([c for c in found if c.startswith(("test_l7_gen_warning.", "test_p1_runner.", "test_l7_gen_deadline.", "test_l7v2_harm."))],
                         "a child interpreter's driver string, or a --plan, is not an armed call")

    def test_the_detector_sees_an_armed_timer(self):
        t = threading.Timer(3600.0, LT.l7_gen._hard_exit, args=(None,))
        t.daemon = True
        t.start()
        try:
            self.assertIn(t, LT.live_hard_exits())
        finally:
            t.cancel()
        t.join(5)
        self.assertNotIn(t, LT.live_hard_exits())
        with LT.inert():
            self.assertIs(threading.Timer, LT.InertTimer)
        self.assertIsNot(threading.Timer, LT.InertTimer)

    def test_no_test_leaves_the_hard_exit_armed(self):
        names = classes_that_run_the_generator()
        result = LeakResult()
        unittest.defaultTestLoader.loadTestsFromNames(names).run(result)
        self.assertGreater(result.testsRun, 0)
        self.assertEqual(result.leaks, {}, "a test called l7_gen.main without --plan and left its hard exit (os._exit) armed in this "
                                           "process: wrap the call in l7_gen_timer.inert()")


if __name__ == "__main__":
    unittest.main()
