"""Packets and crash safety (docs/RECALIBRATION_2026-11_DESIGN.md 6.2 and K6; T-092 finding 2): --stop-after for the calibration's
steps, the drift check and a gate campaign, files synced before they replace the old ones, and an empty or unreadable DONE, block.json
or campaign.json after a host reset read as what it is. On the simulated host only."""
import contextlib
import io
import json
import os
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
import calibration as C
import calibration_fixtures as CF
import executor as X
import gate_campaign as GC
import hostcheck as HC
import sim_host as S
import test_gate_campaign as TG


def cli(main, *argv, host=None):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv), host=host)
    return code, out.getvalue(), err.getvalue()


def run_dirs(root):
    """Every run directory under `root` (it holds a plan.json), relative, with its seed."""
    out = []
    for d, _, files in sorted(os.walk(root)):
        if "plan.json" in files:
            with open(os.path.join(d, "plan.json"), encoding="utf-8") as fh:
                out.append((os.path.relpath(d, root), json.load(fh)["seed"]))
    return sorted(out)


class WriteTest(unittest.TestCase):
    def test_a_record_is_synced_renamed_and_its_directory_synced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a", "DONE")
            for write in (X.write_json, HC._write_json):
                with self.subTest(write=write.__module__), mock.patch.object(os, "fsync", wraps=os.fsync) as fsync:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    write(path, {"ok": True})
                    self.assertEqual(fsync.call_count, 2, "the file and its directory")
                    with open(path, encoding="utf-8") as fh:
                        self.assertEqual(json.load(fh), {"ok": True})
                    self.assertFalse(os.path.exists(path + ".tmp"))


class StopAfterCalibrationTest(unittest.TestCase):
    """--stop-after on a drift check of schema 2: it stops between runs, exits 4, and the same command resumes to the runs an
    uninterrupted check makes."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cal = CF.frozen_v2()
        self.path = os.path.join(self.tmp.name, "v2.json")
        C.dump(self.cal, self.path)

    def host(self):
        return S.SimHost(server=S.SyntheticServer(self.cal, (30, 45, 30), capacity_cpu=1.1), tag=S.origin_tag(self.cal),
                         origin_costs=dict(self.cal["route_costs_ms"]))

    def test_a_stop_and_a_resume_give_the_runs_of_an_uninterrupted_check(self):
        whole, split = os.path.join(self.tmp.name, "whole"), os.path.join(self.tmp.name, "split")
        code, _, _ = cli(K.main, "drift", "--calibration", self.path, "--out", whole, host=self.host())
        self.assertIn(code, (K.EXIT_OK, K.EXIT_INVALID))
        code, _, err = cli(K.main, "drift", "--calibration", self.path, "--out", split, "--stop-after", "5", host=self.host())
        self.assertEqual(code, K.EXIT_PAUSED)
        self.assertIn("paused: the packet's time budget of 5 min is used (--stop-after); the same command resumes it", err)
        self.assertFalse(os.path.exists(os.path.join(split, "drift", "drift.json")))
        made = run_dirs(os.path.join(split, "drift"))
        self.assertTrue(0 < len(made) < 6, made)
        code, _, _ = cli(K.main, "drift", "--calibration", self.path, "--out", split, host=self.host())
        self.assertIn(code, (K.EXIT_OK, K.EXIT_INVALID))
        self.assertEqual(run_dirs(os.path.join(split, "drift")), run_dirs(os.path.join(whole, "drift")))
        a, b = (K.read_json(os.path.join(d, "drift", "drift.json")) for d in (whole, split))
        self.assertEqual([[r["legit"]["run"], *[x["run"] for x in r["attacks"].values()]] for r in a["rounds"]],
                         [[r["legit"]["run"], *[x["run"] for x in r["attacks"].values()]] for r in b["rounds"]])
        self.assertEqual(a["check"], b["check"], "the same runs on the same model")

    def test_every_run_command_takes_it(self):
        for argv in (["origin"], ["capacity"], ["ladder", "--family", "cheap_static_flood"], ["reference"],
                     ["drift", "--calibration", self.path]):
            with self.subTest(step=argv[0]), mock.patch.object(K, "_dispatch", return_value=0) as dispatch:
                self.assertEqual(K.main([*argv, "--out", self.tmp.name, "--stop-after", "85"]), 0)
                self.assertEqual(dispatch.call_args.args[0].stop_after, 85.0)

    def test_an_empty_done_is_read_as_absent_and_the_run_made_again(self):
        out = os.path.join(self.tmp.name, "d")
        cli(K.main, "drift", "--calibration", self.path, "--out", out, host=self.host())
        done = os.path.join(out, "drift", "r2", "legit", "C", GC.DONE)
        open(done, "w").close()                                       # a reset in the half minute after it was written
        os.remove(os.path.join(out, "drift", "drift.json"))
        with mock.patch.object(K.X, "execute", wraps=X.execute) as spy:
            code, stdout, err = cli(K.main, "drift", "--calibration", self.path, "--out", out, host=self.host())
        self.assertIn(code, (K.EXIT_OK, K.EXIT_INVALID), err)
        self.assertEqual([c.args[0].out for c in spy.call_args_list], [os.path.dirname(done)])
        self.assertIn(f"{done} cannot be read (0 bytes, JSONDecodeError): read as absent, the run is made again", stdout)
        self.assertTrue(K.read_json(done)["ok"])


class StopAfterHostCheckTest(unittest.TestCase):
    def test_a_host_invalid_run_is_not_made_again_once_the_budget_is_used(self):
        """The remake after a speed hold is a run like any other: it does not start after --stop-after; the resume makes it."""
        with tempfile.TemporaryDirectory() as tmp:
            costs = dict(C.load(C.PLACEHOLDER)["route_costs_ms"])
            app = [(1000, 1874, 60.0, "server")]
            host = S.SimHost(origin_costs=costs, other_load=lambda t: app if t < S.BASE_EPOCH + 15 else [])
            check = HC.HostCheck(host, HC.SpeedBracket(C.PLACEHOLDER, costs, "x"), os.path.join(tmp, "m"), "2", 0.1)
            runner = K.Runner(host, check=check, stop_after_min=3.0)
            self.addCleanup(runner.close)
            ctl = K.SC.load(K.spec_path(K.CONTROL_SPEC))
            plan = X.plan_population(K.P.draw(ctl.seed_namespace, 11, 20.0, ctl.benign_identities, None, K.P.Timeline(8.0, 0.0, 0.0),
                                              ctl.per_profile), "probe", "C", 11, os.path.join(tmp, "a", "C"), C.load(C.PLACEHOLDER),
                                     C.PLACEHOLDER, K.P.Timeline(8.0, 0.0, 0.0), settings={"readiness_timeout_s": 5.0})
            with self.assertRaisesRegex(GC.Paused, "budget of 3 min"):
                runner.run(plan, lambda m: None)
            self.assertTrue(os.path.isdir(plan.out + ".hostinvalid1"))
            self.assertFalse(os.path.exists(plan.out))


class StopAfterCampaignTest(TG.CampaignCase):
    def test_a_paused_campaign_resumes_to_the_runs_of_an_uninterrupted_one_and_the_budget_is_no_part_of_its_fingerprint(self):
        whole = self.run_campaign(out="whole")
        with self.assertRaisesRegex(GC.Paused, "paused: the packet's time budget of 1 min is used"):
            self.run_campaign(out="split", stop_after_min=1.0)
        state = K.read_json(os.path.join(self.tmp.name, "split", GC.CAMPAIGN))
        self.assertEqual(state["state"], "paused")
        self.assertNotIn("stop_after_min", state["fingerprint"])
        resumed = self.run_campaign(out="split", stop_after_min=600.0)
        self.assertEqual(resumed["state"], "complete")
        self.assertEqual(self.dirs("split"), self.dirs("whole"))
        self.assertEqual(run_dirs(os.path.join(self.tmp.name, "split")), run_dirs(os.path.join(self.tmp.name, "whole")))
        self.assertEqual(whole["gate"], resumed["gate"])

    def test_the_command_exits_4_when_it_pauses(self):
        code, _, err = cli(GC.main, "run", TG.SPEC, "--calibration", self.cal_path, "--out", self.path(), "--blocks", "3", "--no-warmup",
                           "--rho", str(TG.RHO), "--timeline", "6,6,6", "--simulate", "pass", "--stop-after", "0.5")
        self.assertEqual((code, GC.EXIT_PAUSED), (4, 4))
        self.assertIn("paused", err)

    def test_an_empty_done_and_an_empty_block_json_are_made_again_on_resume(self):
        self.run_campaign()
        for name in (os.path.join("b02_a1", "U", GC.DONE), os.path.join("b02_a1", "block.json")):
            open(self.path(name), "w").close()
        with mock.patch.object(GC.X, "execute", wraps=X.execute) as spy:
            again = self.run_campaign()
        self.assertEqual(again["state"], "complete")
        self.assertEqual([c.args[0].out for c in spy.call_args_list], [self.path("b02_a1", "U")])
        self.assertTrue(any("block.json cannot be read (0 bytes" in m for m in self.say), self.say)
        self.assertTrue(any("DONE cannot be read (0 bytes" in m for m in self.say), self.say)
        self.assertTrue(self.json("b02_a1", "block.json")["complete"])

    def test_an_empty_campaign_json_refuses_with_exit_2_and_no_traceback(self):
        self.run_campaign()
        open(self.path(GC.CAMPAIGN), "w").close()
        code, _, err = cli(GC.main, "run", TG.SPEC, "--calibration", self.cal_path, "--out", self.path(), "--blocks", "3", "--no-warmup",
                           "--rho", str(TG.RHO), "--timeline", "6,6,6", "--simulate", "pass")
        self.assertEqual(code, GC.EXIT_STOPPED)
        self.assertIn("campaign.json cannot be read (0 bytes, JSONDecodeError", err)
        self.assertIn("set the directory aside", err)
        self.assertNotIn("Traceback", err)
        code, _, err = cli(GC.main, "status", self.path())
        self.assertEqual(code, GC.EXIT_STOPPED)


if __name__ == "__main__":
    unittest.main()
