"""eval/publish_campaign.py on run-contract directories (bench/calibrate.py's drift step, bench/executor.py's runs): each one
is copied as it is, its provenance is read from what its runs record, a recorded drift verdict is judged again from the
published runs beside the recorded one, a cut step stays without a verdict, and the publisher starts without matplotlib.
The drift directories are made on the simulated host (bench/sim_host.py) against the frozen record under bench/calibration/,
in a temporary directory; nothing here needs root, a namespace or the network."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibrate as K
import calibration as CAL
import executor as X
import publish_campaign as PUB
import sim_host as S

RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")
FAMILY = "cheap_static_flood"


def make_drift(out):
    """One drift check on the simulated host, the legit probe and one attack run, as `calibrate.py drift` writes it."""
    cal = CAL.load(RECORD)
    host = S.SimHost(server=S.SyntheticServer(cal, (30, 45, 30), capacity_cpu=1.1), tag=S.origin_tag(cal))
    with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(io.StringIO()):
        return K.drift_step(K.Runner(host), cal, RECORD, out, [FAMILY], None, lambda m: None)


def publish(repo, *argv):
    """main() as the command line runs it, with results/ under `repo`; returns what it printed."""
    out = io.StringIO()
    with mock.patch.object(PUB, "REPO", repo), mock.patch.object(sys, "argv", ["publish_campaign.py", *argv]), \
            contextlib.redirect_stdout(out):
        PUB.main()
    return out.getvalue()


def read(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class RunContractPublishTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.tmp.name
        cls.whole = os.path.join(root, "src", "drift_whole")
        cls.recorded = make_drift(cls.whole)
        attack = os.path.join("drift", f"attack_{FAMILY}")
        # a run the tool kept aside after a failure: no DONE
        shutil.copytree(os.path.join(cls.whole, attack, "U"), os.path.join(cls.whole, attack, "U.failed1"))
        os.remove(os.path.join(cls.whole, attack, "U.failed1", "DONE"))
        # a step cut by a host reset during its attack run: no drift.json, no run.json and an empty plan.json there
        cls.cut = os.path.join(root, "src", "drift_cut")
        shutil.copytree(cls.whole, cls.cut)
        shutil.rmtree(os.path.join(cls.cut, attack, "U.failed1"))
        for name in ("drift/drift.json", f"{attack}/U/run.json", f"{attack}/U/DONE"):
            os.remove(os.path.join(cls.cut, name))
        open(os.path.join(cls.cut, attack, "U", "plan.json"), "w").close()
        # a step stopped by a run the executor could not carry out: FAILED instead of run.json
        cls.failed = os.path.join(root, "src", "drift_failed")
        shutil.copytree(cls.cut, cls.failed)
        with open(os.path.join(cls.failed, attack, "U", "FAILED"), "w", encoding="utf-8") as fh:
            fh.write("SetupFailed: the origin exited with 1 (see gunicorn.log)\n")
        # a recorded verdict that the runs do not reproduce
        cls.tampered = os.path.join(root, "src", "drift_tampered")
        shutil.copytree(cls.whole, cls.tampered)
        verdict = read(os.path.join(cls.tampered, "drift", "drift.json"))
        verdict["ok"] = not verdict["ok"]
        verdict["legit"]["Q"] -= 1.0
        with open(os.path.join(cls.tampered, "drift", "drift.json"), "w", encoding="utf-8") as fh:
            json.dump(verdict, fh)
        cls.readme = os.path.join(root, "README.md")
        with open(cls.readme, "w", encoding="utf-8") as fh:
            fh.write("# what this is\n")
        cls.steps = os.path.join(root, "steps")
        os.makedirs(os.path.join(cls.steps, "before"))
        with open(os.path.join(cls.steps, "before", "uptime.txt"), "w", encoding="utf-8") as fh:
            fh.write("up 1 h\n")
        cls.repo = os.path.join(root, "repo")
        os.makedirs(os.path.join(cls.repo, "results"))
        cls.said = publish(cls.repo, cls.whole, cls.cut, cls.failed, cls.tampered, "--name", "drift-demo",
                           "--with", cls.readme, "--with", cls.steps)
        cls.dst = os.path.join(cls.repo, "results", "drift-demo")
        cls.drift = {a["dir"]: a for a in read(os.path.join(cls.dst, "analysis", "drift.json"))["attempts"]}
        cls.runs = read(os.path.join(cls.dst, "analysis", "runs.json"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_source_and_every_further_path_is_copied_as_it_is(self):
        for src in (self.whole, self.cut, self.failed, self.tampered, self.steps):
            self.assertEqual(PUB.tree_hashes(os.path.join(self.dst, os.path.basename(src))), PUB.tree_hashes(src), src)
        with open(self.readme, "rb") as a, open(os.path.join(self.dst, "README.md"), "rb") as b:
            self.assertEqual(a.read(), b.read())
        self.assertEqual(os.path.getsize(os.path.join(self.dst, "drift_cut", "drift", f"attack_{FAMILY}", "U", "plan.json")), 0)

    def test_the_checksums_cover_every_published_file(self):
        with open(os.path.join(self.dst, "SHA256SUMS"), encoding="utf-8") as fh:
            listed = dict(reversed(line.rstrip("\n").split("  ", 1)) for line in fh)
        self.assertEqual(listed, PUB.tree_hashes(self.dst))
        self.assertIn("analysis/drift.json", listed)
        self.assertIn("steps/before/uptime.txt", listed)

    def test_a_recorded_verdict_is_judged_again_from_the_published_runs_and_agrees(self):
        a = self.drift["drift_whole"]
        self.assertTrue(a["agree"], a["differences"])
        self.assertEqual(a["recorded"], read(os.path.join(self.whole, "drift", "drift.json")))
        self.assertEqual((a["judged"]["ok"], a["judged"]["reasons"]), (self.recorded["ok"], self.recorded["reasons"]))
        self.assertEqual(a["judged"]["attacks"][FAMILY]["level"], self.recorded["attacks"][FAMILY]["level"])
        self.assertEqual(a["not_compared"], ["created_utc", "waits", "smoke"])
        self.assertIn("drift_whole: recorded ok=", self.said)
        self.assertIn("the two agree apart from created_utc, waits, smoke", self.said)

    def test_a_cut_step_has_no_verdict_and_its_complete_runs_are_descriptive_only(self):
        a = self.drift["drift_cut"]
        self.assertIsNone(a["recorded"])
        self.assertIsNone(a["judged"])
        self.assertTrue(a["verdict"].startswith("no verdict"))
        self.assertEqual(sorted(a["descriptive_not_a_verdict"]), ["legit"])
        self.assertEqual(a["descriptive_not_a_verdict"]["legit"], self.recorded["legit"])
        self.assertIn("drift_cut: no verdict", self.said)
        with open(os.path.join(self.dst, "analysis", "summary.md"), encoding="utf-8") as fh:
            self.assertIn("| drift_cut | no verdict", fh.read())

    def test_a_recorded_verdict_the_runs_do_not_reproduce_is_named_with_its_fields(self):
        a = self.drift["drift_tampered"]
        self.assertFalse(a["agree"])
        self.assertEqual(a["differences"], ["ok", "legit.Q"])
        self.assertEqual(a["judged"]["ok"], self.recorded["ok"])
        self.assertIn("drift_tampered: recorded ok=", self.said)
        self.assertIn("they DIFFER in ok, legit.Q", self.said)

    def test_the_provenance_is_what_the_runs_record(self):
        runs = {r["dir"]: r for r in self.runs["runs"]}
        whole = self.runs["sources"]["drift_whole"]
        self.assertEqual(whole["states"], {"complete": 2, "ended without DONE": 1})
        self.assertEqual(whole["dirty"], [False])
        self.assertEqual(len(whole["commits"]), 1)
        self.assertEqual(whole["calibration_sha256"], [CAL.load(RECORD)["sha256"]])
        self.assertEqual(self.runs["sources"]["drift_cut"]["states"], {"complete": 1, "cut before run.json": 1})
        aside = runs[f"drift_whole/drift/attack_{FAMILY}/U.failed1"]
        self.assertEqual((aside["state"], aside["kind"], aside["level"]), ("ended without DONE", "U", 2.0))
        cut = runs[f"drift_cut/drift/attack_{FAMILY}/U"]
        self.assertEqual(cut["files_missing_or_unreadable"]["run.json"], "absent")
        self.assertTrue(cut["files_missing_or_unreadable"]["plan.json"].startswith("unreadable (0 bytes"))
        failed = runs[f"drift_failed/drift/attack_{FAMILY}/U"]
        self.assertEqual((failed["state"], failed["failed"]),
                         ("failed before run.json", "SetupFailed: the origin exited with 1 (see gunicorn.log)"))
        self.assertTrue(self.drift["drift_failed"]["verdict"].startswith("no verdict"))
        legit = runs["drift_whole/drift/legit/C"]
        self.assertEqual(legit["host"]["cpus"], 8)
        self.assertEqual((legit["executor_ok"], legit["role"]), (True, "control"))

    def test_an_existing_entry_is_kept_unless_forced(self):
        with self.assertRaises(SystemExit) as stop:
            publish(self.repo, self.whole, "--name", "drift-demo")
        self.assertIn("exists", str(stop.exception))


class RunContractRefusalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.src = os.path.join(cls.tmp.name, "drift_one")
        make_drift(cls.src)
        cls.repo = os.path.join(cls.tmp.name, "repo")
        os.makedirs(os.path.join(cls.repo, "results"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def refused(self, *argv):
        with self.assertRaises(SystemExit) as stop:
            publish(self.repo, *argv)
        return str(stop.exception)

    def test_a_record_with_another_hash_is_refused(self):
        said = self.refused(self.src, "--name", "x", "--calibration", CAL.PLACEHOLDER)
        self.assertIn("the runs name the frozen", said)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "results", "x")))

    def test_names_that_would_collide_are_refused(self):
        other = os.path.join(self.tmp.name, "elsewhere", "drift_one")
        shutil.copytree(self.src, other)
        self.assertIn("collide", self.refused(self.src, other, "--name", "x"))
        analysis = os.path.join(self.tmp.name, "analysis")
        os.makedirs(analysis, exist_ok=True)
        self.assertIn("collide", self.refused(self.src, "--name", "x", "--with", analysis))

    def test_symbolic_links_are_refused(self):
        linked = os.path.join(self.tmp.name, "linked")
        shutil.copytree(self.src, linked)
        os.symlink(os.path.join(self.src, "drift", "drift.json"), os.path.join(linked, "drift", "elsewhere.json"))
        self.assertIn("symbolic links", self.refused(linked, "--name", "x"))

    def test_several_directories_need_a_name_and_further_paths_need_run_contract_sources(self):
        self.assertIn("--name", self.refused(self.src, self.src))
        suite = os.path.join(self.tmp.name, "suite")
        os.makedirs(os.path.join(suite, "xdp", "run1"))
        with open(os.path.join(suite, "xdp", "run1", "provenance.json"), "w", encoding="utf-8") as fh:
            json.dump({"mode": {"label": "xdp"}}, fh)
        self.assertIn("not both", self.refused(suite, self.src, "--name", "x"))
        self.assertIn("for run-contract directories", self.refused(suite, "--name", "x", "--with", self.src))

    def test_the_size_limit_holds(self):
        with mock.patch.object(PUB, "MAX_BYTES", 1000):
            self.assertIn("too large", self.refused(self.src, "--name", "big"))
        self.assertFalse(os.path.exists(os.path.join(self.repo, "results", "big")))

    def test_a_run_contract_directory_is_published_without_matplotlib(self):
        blocked = {"matplotlib": None, "matplotlib.pyplot": None, "plot_campaign": None}
        with mock.patch.dict(sys.modules, blocked):
            said = publish(self.repo, self.src, "--name", "no-mpl")
        self.assertIn("published", said)


class WithoutMatplotlibTest(unittest.TestCase):
    def test_the_publisher_imports_without_matplotlib(self):
        code = ("import sys; sys.modules['matplotlib'] = None; sys.path.insert(0, sys.argv[1]); "
                "import publish_campaign; print('plot_campaign' in sys.modules)")
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run([sys.executable, "-c", code, os.path.join(REPO, "eval")], cwd=tmp,
                                  capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual((done.returncode, done.stdout.strip()), (0, "False"), done.stderr)

    def test_a_suite_campaign_without_matplotlib_gets_its_tables_and_says_that_its_figures_are_missing(self):
        try:
            from test_campaign_analysis import make_run
        except ImportError:                     # without pandas the suite's tables cannot be made either
            self.skipTest("needs pandas")
        with tempfile.TemporaryDirectory() as tmp:
            campaign, repo = os.path.join(tmp, "campaign"), os.path.join(tmp, "repo")
            os.makedirs(os.path.join(repo, "results"))
            for seed in (1, 2):
                make_run(campaign, "xdp", f"run{seed}", seed, [1] * 10)
            with mock.patch.dict(sys.modules, {"matplotlib": None, "matplotlib.pyplot": None, "plot_campaign": None}):
                said = publish(repo, campaign, "--name", "demo")
            published = os.path.join(repo, "results", "demo")
            self.assertTrue(os.path.isdir(os.path.join(published, "analysis")))
            self.assertFalse(os.path.exists(os.path.join(published, "analysis", "figures")))
            self.assertIn("[!] no figures", said)


if __name__ == "__main__":
    unittest.main()
