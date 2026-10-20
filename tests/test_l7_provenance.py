"""Unit tests for the git provenance of the L7 runners (audit G-14). Offline: a throw-away git
repository, no namespaces, no traffic. The suite's runners already refuse a dirty tree and
record commit, branch and dirty; capture_l7, eval_l7 and smoke_l7 recorded the commit only."""
import argparse
import ast
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import capture_l7
import eval_l7

import l7_dataset

RUNNERS = ("capture_l7.py", "eval_l7.py", "smoke_l7.py")


def git(repo, *args):
    subprocess.run(["git", "-C", repo, "-c", "user.email=t@example.org", "-c", "user.name=t",
                    *args], check=True, capture_output=True)


class TempRepoCase(unittest.TestCase):
    """A repository with one commit on branch `main` and one tracked file."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = tmp.name
        git(self.repo, "init", "-q")
        git(self.repo, "symbolic-ref", "HEAD", "refs/heads/main")
        self.tracked = os.path.join(self.repo, "tracked.txt")
        self.write(self.tracked, "one\n")
        git(self.repo, "add", "tracked.txt")
        git(self.repo, "commit", "-q", "-m", "first")
        self.head = subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"], check=True,
                                   capture_output=True, text=True).stdout.strip()

    @staticmethod
    def write(path, text):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


class GitStateTest(TempRepoCase):
    def test_clean_tree(self):
        self.assertEqual(capture_l7.git_state(self.repo),
                         {"commit": self.head, "branch": "main", "dirty": False,
                          "dirty_files": []})

    def test_a_modified_tracked_file_is_dirty_and_named(self):
        self.write(self.tracked, "two\n")
        state = capture_l7.git_state(self.repo)
        self.assertTrue(state["dirty"])
        self.assertEqual(state["dirty_files"], [" M tracked.txt"])
        self.assertEqual(state["commit"], self.head)

    def test_an_untracked_file_does_not_make_the_tree_dirty(self):
        self.write(os.path.join(self.repo, "notes.txt"), "scratch\n")
        self.assertFalse(capture_l7.git_state(self.repo)["dirty"])

    def test_only_the_first_fifty_dirty_files_are_listed(self):
        for i in range(60):
            path = os.path.join(self.repo, f"f{i:02d}.txt")
            self.write(path, "x\n")
            git(self.repo, "add", os.path.basename(path))
        git(self.repo, "commit", "-q", "-m", "many")
        for i in range(60):
            self.write(os.path.join(self.repo, f"f{i:02d}.txt"), "y\n")
        state = capture_l7.git_state(self.repo)
        self.assertEqual(len(state["dirty_files"]), 50)

    def test_outside_a_checkout_everything_is_empty(self):
        with tempfile.TemporaryDirectory() as plain, \
                mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": os.path.dirname(plain)}):
            self.assertEqual(capture_l7.git_state(plain),
                             {"commit": None, "branch": None, "dirty": None, "dirty_files": []})
            self.assertIsNone(capture_l7.git_commit(plain))

    def test_git_commit_is_the_head(self):
        self.assertEqual(capture_l7.git_commit(self.repo), self.head)


class RequireCleanTreeTest(TempRepoCase):
    def test_a_clean_tree_passes_and_returns_the_state(self):
        state = capture_l7.require_clean_tree(False, self.repo)
        self.assertEqual((state["commit"], state["dirty"]), (self.head, False))

    def test_a_dirty_tree_is_refused_with_the_files_and_the_way_out(self):
        self.write(self.tracked, "two\n")
        with self.assertRaises(SystemExit) as cm:
            capture_l7.require_clean_tree(False, self.repo)
        msg = str(cm.exception)
        self.assertIn("tracked.txt", msg)
        self.assertIn("--allow-dirty", msg)

    def test_allow_dirty_records_the_dirt_instead_of_refusing(self):
        self.write(self.tracked, "two\n")
        state = capture_l7.require_clean_tree(True, self.repo)
        self.assertTrue(state["dirty"])
        self.assertEqual(state["dirty_files"], [" M tracked.txt"])

    def test_a_directory_that_is_not_a_checkout_is_not_refused(self):
        with tempfile.TemporaryDirectory() as plain, \
                mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": os.path.dirname(plain)}):
            self.assertIsNone(capture_l7.require_clean_tree(False, plain)["dirty"])


class ReportTest(unittest.TestCase):
    def build(self, **kw):
        with tempfile.TemporaryDirectory() as d:
            for name in ("ban_events.jsonl", "l7_record.jsonl"):
                open(os.path.join(d, name), "w", encoding="utf-8").close()
            pkg = os.path.join(d, "pkg")
            os.makedirs(pkg)
            with open(os.path.join(pkg, "config.json"), "w", encoding="utf-8") as fh:
                fh.write("{}")
            ip_map = {"10.0.1.5": {"class": "benign", "kind": "browser_page"}}
            m = l7_dataset.make_manifest(seed=1, duration_s=60.0, ip_map=ip_map, schedule=[],
                                         provenance={}, notes="")
            args = argparse.Namespace(soak=False, duration=60.0, seed=1)
            return eval_l7.build_report(d, m, 0.0, pkg, args, **kw)

    def test_the_report_records_the_state_it_is_given(self):
        state = {"commit": "abc", "branch": "x", "dirty": True, "dirty_files": [" M a.py"]}
        rep = self.build(git=state)
        self.assertEqual(rep["git"], state)
        self.assertEqual(rep["git_commit"], "abc")

    def test_without_a_state_it_reads_the_checkout(self):
        rep = self.build()
        self.assertEqual(set(rep["git"]), {"commit", "branch", "dirty", "dirty_files"})
        self.assertEqual(rep["git_commit"], rep["git"]["commit"])


class RunnerWiringTest(unittest.TestCase):
    """The three runners must ask for a clean tree before they touch the testbed, and offer
    --allow-dirty. Parsed, not run: they need root and a VM."""

    SIDE_EFFECTS = ("create_host_bridge", "build_topology", "makedirs")

    @staticmethod
    def calls_in_main(name):
        """[(line, called name)] of every call in the runner's main(): `f(...)` gives "f",
        `module.f(...)` gives "f"."""
        with open(os.path.join(REPO, "ml", name), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        out = []
        for c in ast.walk(main):
            if isinstance(c, ast.Call):
                f = c.func
                out.append((c.lineno, f.attr if isinstance(f, ast.Attribute)
                            else getattr(f, "id", "")))
        return sorted(out)

    def test_every_runner_calls_require_clean_tree_in_main_once(self):
        for name in RUNNERS:
            calls = [a for _, a in self.calls_in_main(name) if a == "require_clean_tree"]
            self.assertEqual(len(calls), 1, name)

    def test_the_check_comes_before_anything_touches_the_testbed(self):
        for name in RUNNERS:
            calls = self.calls_in_main(name)
            check = next(line for line, a in calls if a == "require_clean_tree")
            effects = [line for line, a in calls if a in self.SIDE_EFFECTS]
            self.assertTrue(effects, f"{name}: no side effect found, the test is stale")
            self.assertLess(check, min(effects), name)

    def test_every_runner_lists_allow_dirty(self):
        for name in RUNNERS:
            res = subprocess.run([sys.executable, os.path.join(REPO, "ml", name), "--help"],
                                 capture_output=True, text=True, check=False)
            self.assertEqual(res.returncode, 0, f"{name}: {res.stderr}")
            self.assertIn("--allow-dirty", res.stdout, name)


if __name__ == "__main__":
    unittest.main()
