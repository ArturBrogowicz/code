"""Static checks of capture_testbed_dataset.py (no root, no import).

The capture builds the testbed as soon as it is imported, so it is parsed with `ast`.
"""
import ast
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CaptureScriptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "capture_testbed_dataset.py"), encoding="utf-8") as fh:
            cls.tree = ast.parse(fh.read())

    def test_no_session_specific_paths(self):
        # Review D12: the attack scripts were written to another session's tmpfs
        # scratchpad, which is gone after a reboot.
        strings = [n.value for n in ast.walk(self.tree)
                   if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertEqual([s for s in strings if "claude-" in s or "scratchpad" in s], [])

    def test_scripts_go_to_a_private_temporary_directory(self):
        calls = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == "mkdtemp"]
        self.assertTrue(calls, "SCR should come from tempfile.mkdtemp()")


if __name__ == "__main__":
    unittest.main()
