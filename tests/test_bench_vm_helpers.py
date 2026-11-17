"""The VM step helpers in bench/vm/ (bench/vm/README.md), checked without running a step.

Each script must parse (`bash -n`). vm_step.sh's `--print` mode and its usage error run nothing: they are
run here as the calling user, with S pointing at a temporary directory, and the directory must stay empty.
The worktree is the checkout the script lies in, so a copy under another tree prints that tree. Nothing
runs as root, no snapshot is taken (s3_snapshot.sh deletes the directory it is given) and no command is
executed through vm_step.sh.
"""
import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM = os.path.join(REPO, "bench", "vm")
SCRIPTS = ("vm_step.sh", "s3_snapshot.sh", "s3_compare.sh")
BASH = shutil.which("bash")


@unittest.skipIf(BASH is None, "bash is not installed")
class VmHelpersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vm_step_test_")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.s = os.path.join(self.tmp, "scratch")
        os.mkdir(self.s)

    def run_vm_step(self, script, *args):
        env = dict(os.environ, S=self.s)
        return subprocess.run([BASH, script, *args], cwd=self.tmp, env=env, capture_output=True, text=True,
                              timeout=30, check=False)

    def test_every_script_parses(self):
        for name in SCRIPTS:
            with self.subTest(name=name):
                done = subprocess.run([BASH, "-n", os.path.join(VM, name)], capture_output=True, text=True,
                                      timeout=30, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)

    def test_no_script_names_a_worktree(self):
        for name in SCRIPTS:
            with open(os.path.join(VM, name), encoding="utf-8") as fh:
                text = fh.read()
            with self.subTest(name=name):
                self.assertNotIn("/home/", text)
                self.assertNotIn("audit-must-do-2-5", text)

    def test_print_shows_the_plan_and_runs_nothing(self):
        done = self.run_vm_step(os.path.join(VM, "vm_step.sh"), "--print", "t1", "--", "echo", "hello")
        self.assertEqual(done.returncode, 0, done.stderr)
        lines = done.stdout.splitlines()
        s = self.s
        snap = os.path.join(VM, "s3_snapshot.sh")
        self.assertEqual(lines[0], f"cd {os.path.realpath(REPO)}")
        self.assertEqual(lines[1], f"test ! -e {s}/t1_output.txt")
        self.assertEqual(lines[2], f"bash {os.path.realpath(snap)} {s}/t1_before; free -m > {s}/t1_free_before.txt")
        self.assertEqual(lines[4], f"echo hello 2>&1 | tee {s}/t1_output.txt")
        self.assertIn(f"bash {os.path.realpath(VM)}/s3_compare.sh {s}/t1_before {s}/t1_after", lines[5])
        self.assertEqual(len(lines), 6)
        self.assertEqual(os.listdir(self.s), [])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["scratch"])

    def test_the_worktree_is_the_checkout_the_script_lies_in(self):
        tree = os.path.join(self.tmp, "other tree")
        os.makedirs(os.path.join(tree, "bench", "vm"))
        for name in SCRIPTS:
            shutil.copy(os.path.join(VM, name), os.path.join(tree, "bench", "vm", name))
        done = self.run_vm_step(os.path.join(tree, "bench", "vm", "vm_step.sh"), "--print", "t2", "--", "true")
        self.assertEqual(done.returncode, 0, done.stderr)
        lines = done.stdout.splitlines()
        self.assertEqual(lines[0], f"cd {os.path.realpath(tree)}")
        self.assertIn(f"bash {os.path.realpath(tree)}/bench/vm/s3_snapshot.sh {self.s}/t2_before", lines[2])
        self.assertEqual(os.listdir(self.s), [])

    def test_s_defaults_to_the_old_scratch_directory(self):
        env = {k: v for k, v in os.environ.items() if k != "S"}
        done = subprocess.run([BASH, os.path.join(VM, "vm_step.sh"), "--print", "t3", "--", "true"], cwd=self.tmp,
                              env=env, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.splitlines()[1], "test ! -e /var/tmp/hg1c_scratch/t3_output.txt")

    def test_a_malformed_call_is_refused_before_anything_runs(self):
        for args in ((), ("t4",), ("t4", "--"), ("t4", "echo", "hello"), ("--print", "t4", "--")):
            with self.subTest(args=args):
                done = self.run_vm_step(os.path.join(VM, "vm_step.sh"), *args)
                self.assertEqual(done.returncode, 64)
                self.assertTrue(done.stdout.startswith("usage: vm_step.sh"), done.stdout)
        self.assertEqual(os.listdir(self.s), [])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["scratch"])


if __name__ == "__main__":
    unittest.main()
