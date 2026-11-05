"""Offline tests for the load-model cells of eval/run_campaign.py (EXP-C,
docs/EXPC_ATTACKER_SETTING_DESIGN.md): parsing of --loads, the plan, the per-run environment, what is
recorded in campaign.json, and the unchanged default.

Nothing is run: --dry-run only prints the plan, and the checks that look at the machine (pgrep, the
binaries) are replaced.
"""
import argparse
import contextlib
import io
import os
import random
import sys
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "eval"))
with mock.patch("atexit.register"), mock.patch("signal.signal"):
    import test_distributed_suite as S
import loadtools as LT
import run_campaign as RC

MODES = ["xdp", "iptables", "nginxlimits", "unprotected"]


def old_build_plan(modes, runs, order_seed, seed_base):
    """The plan as the runner built it before the load cells existed."""
    rng = random.Random(order_seed)
    plan = []
    for block in range(1, runs + 1):
        order = list(modes)
        rng.shuffle(order)
        plan += [{"block": block, "mode": m, "profile_seed": seed_base + block,
                  "dir": f"{m}/run{block}"} for m in order]
    return plan


def args(**kw):
    base = {"modes": ",".join(MODES), "runs": 3, "scenarios": "4", "operating_point": "knee",
            "attack_duration": 30.0, "seed_base": 0, "order_seed": 0}
    return argparse.Namespace(**{**base, **kw})


def dry_run(*argv):
    out = io.StringIO()
    with mock.patch.object(sys, "argv", ["run_campaign.py", "--dry-run", "--out", "/tmp/x", *argv]), \
            mock.patch.object(RC, "check_loads"), contextlib.redirect_stdout(out):
        RC.main()
    return out.getvalue()


class ParseLoadsTest(unittest.TestCase):
    def test_cells(self):
        cells = RC.parse_loads("wrk, loadgen:50 ,k6:62.5,loadgen:100")
        self.assertEqual([c["spec"] for c in cells], ["wrk", "loadgen:50", "k6:62.5", "loadgen:100"])
        self.assertEqual([c["suffix"] for c in cells], ["", "@loadgen50", "@k662.5", "@loadgen100"])
        self.assertEqual([c["rate"] for c in cells], [0.0, 50.0, 62.5, 100.0])

    def test_a_cell_that_makes_no_sense_is_refused(self):
        for text in ("", " , ", "vegeta:100", "wrk2", "wrk:100", "loadgen", "loadgen:", "loadgen:0",
                     "loadgen:-3", "loadgen:fast", "loadgen:nan", "loadgen:inf",
                     "loadgen:100,loadgen:100", "loadgen:100,loadgen:1e2"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                RC.parse_loads(text)

    def test_the_tools_and_the_label_suffix_are_the_suites(self):
        self.assertEqual(RC.LOAD_TOOLS, S.FLOOD_TOOLS)
        self.assertEqual(RC.LOAD_TOOLS, LT.FLOOD_TOOLS)
        for spec in ("wrk", "loadgen:100", "k6:62.5", "loadgen:1000"):
            cell = RC.parse_loads(spec)[0]
            with mock.patch.object(S, "FLOOD_TOOL", cell["tool"]), \
                    mock.patch.object(S, "FLOOD_RATE", cell["rate"]):
                self.assertEqual(S._flood_suffix(), cell["suffix"], spec)


class PlanTest(unittest.TestCase):
    def test_without_loads_the_plan_is_exactly_what_it_was(self):
        for modes, runs, order_seed, seed_base in ((MODES, 3, 0, 0), (MODES, 10, 7, 100),
                                                   (["xdp", "unprotected"], 1, 5, 0), (MODES[:3], 4, 2, 9)):
            expected = old_build_plan(modes, runs, order_seed, seed_base)
            self.assertEqual(RC.build_plan(modes, runs, order_seed, seed_base), expected)
            self.assertEqual(RC.build_plan(modes, runs, order_seed, seed_base, loads=None), expected)
            self.assertTrue(all("load" not in item for item in expected))

    def test_with_loads_every_block_runs_every_mode_and_load_once(self):
        loads = RC.parse_loads("wrk,loadgen:50,loadgen:100,loadgen:200")
        modes = ["unprotected", "nginxlimits", "xdp"]
        plan = RC.build_plan(modes, 2, 0, 0, loads)
        self.assertEqual(len(plan), 2 * 3 * 4)
        for block in (1, 2):
            items = [i for i in plan if i["block"] == block]
            self.assertEqual(sorted((i["mode"], i["load"]) for i in items),
                             sorted((m, c["spec"]) for m in modes for c in loads))
            self.assertEqual({i["profile_seed"] for i in items}, {block})   # every cell of a block is paired
        dirs = [i["dir"] for i in plan]
        self.assertEqual(len(set(dirs)), len(dirs))
        self.assertIn("unprotected/run1", dirs)                  # the closed-loop cell keeps its old name
        self.assertIn("xdp@loadgen100/run2", dirs)
        self.assertEqual(plan, RC.build_plan(modes, 2, 0, 0, loads))      # deterministic
        self.assertNotEqual([i["dir"] for i in plan], [i["dir"] for i in RC.build_plan(modes, 2, 1, 0, loads)])

    def test_the_settings_record_the_loads_only_when_they_are_not_the_default(self):
        self.assertNotIn("loads", RC.make_settings(args(), {}))
        self.assertNotIn("loads", RC.make_settings(args(), {}, None))
        loads = RC.parse_loads("wrk,loadgen:100")
        self.assertEqual(RC.make_settings(args(), {}, loads)["loads"], ["wrk", "loadgen:100"])
        # a campaign recorded before the cells existed has exactly these keys, so it still resumes
        self.assertEqual(set(RC.make_settings(args(), {})),
                         {"modes", "runs", "scenarios", "operating_point", "attack_duration",
                          "seed_base", "order_seed", "set"})


class RunEnvTest(unittest.TestCase):
    def item(self, **kw):
        return {"block": 1, "mode": "unprotected", "profile_seed": 1, "dir": "unprotected/run1", **kw}

    def test_a_default_run_has_no_flood_variables_even_if_the_caller_has_some(self):
        with mock.patch.dict(os.environ, {"FLOOD_TOOL": "k6", "FLOOD_RATE": "9"}):
            env = RC.run_env(args(), {}, self.item(), "/r")
        self.assertNotIn("FLOOD_TOOL", env)
        self.assertNotIn("FLOOD_RATE", env)

    def test_a_cell_sets_the_tool_and_the_rate(self):
        env = RC.run_env(args(), {}, self.item(load="loadgen:62.5"), "/r")
        self.assertEqual((env["FLOOD_TOOL"], env["FLOOD_RATE"]), ("loadgen", "62.5"))
        self.assertEqual(env["MITIGATION_MODE"], "none")
        closed = RC.run_env(args(), {}, self.item(load="wrk"), "/r")
        self.assertEqual(closed["FLOOD_TOOL"], "wrk")
        self.assertNotIn("FLOOD_RATE", closed)

    def test_the_flood_variables_are_cleared_settable_and_listed(self):
        for name in ("FLOOD_TOOL", "FLOOD_RATE"):
            self.assertIn(name, RC.EVAL_VARS)
            self.assertIn(name, RC.SETTABLE)


class CommandLineTest(unittest.TestCase):
    def test_the_default_dry_run_shows_no_flood_and_names_the_modes(self):
        text = dry_run("--modes", "xdp,unprotected", "--runs", "2", "--operating-point", "knee")
        self.assertNotIn("FLOOD", text)
        self.assertNotIn("loads", text)
        self.assertIn("block  1 ", text)

    def test_loads_wrk_alone_is_the_default_plan(self):
        argv = ["--modes", "xdp,unprotected", "--runs", "3", "--operating-point", "knee"]
        self.assertEqual(dry_run(*argv, "--loads", "wrk"), dry_run(*argv))

    def test_the_dry_run_of_an_exp_c_campaign(self):
        text = dry_run("--modes", "unprotected,xdp", "--runs", "2", "--operating-point", "knee",
                       "--loads", "wrk,loadgen:50,loadgen:100")
        self.assertIn('"loads": ["wrk", "loadgen:50", "loadgen:100"]', text)
        runs = [ln for ln in text.splitlines() if ln.startswith("  block")]
        self.assertEqual(len(runs), 2 * 2 * 3)
        self.assertEqual(sum("'FLOOD_TOOL': 'loadgen'" in ln for ln in runs), 2 * 2 * 2)
        self.assertEqual(sum("'FLOOD_RATE': '100'" in ln for ln in runs), 2 * 2)
        self.assertTrue(any(ln.split()[2] == "xdp@loadgen100" for ln in runs))

    def test_loads_and_a_set_flood_variable_do_not_go_together(self):
        with mock.patch.object(sys, "argv", ["run_campaign.py", "--dry-run", "--loads", "loadgen:50",
                                             "--set", "FLOOD_RATE=100"]), \
                mock.patch.object(RC, "check_loads"), self.assertRaises(SystemExit) as cm:
            RC.main()
        self.assertIn("do not combine", str(cm.exception))

    def test_a_single_load_model_can_be_set_for_every_run(self):
        with mock.patch.object(sys, "argv", ["run_campaign.py", "--dry-run", "--out", "/tmp/x",
                                             "--modes", "xdp", "--runs", "1", "--set", "FLOOD_TOOL=loadgen",
                                             "--set", "FLOOD_RATE=100"]), \
                mock.patch.object(RC, "check_loads") as check, contextlib.redirect_stdout(io.StringIO()) as out:
            RC.main()
        self.assertIn("'FLOOD_TOOL': 'loadgen'", out.getvalue())
        check.assert_called_once()
        for bad in (["FLOOD_TOOL=loadgen"], ["FLOOD_TOOL=wrk", "FLOOD_RATE=5"], ["FLOOD_RATE=5"],
                    ["FLOOD_TOOL=vegeta", "FLOOD_RATE=5"]):
            sets = [x for pair in (("--set", s) for s in bad) for x in pair]
            with self.subTest(bad=bad), mock.patch.object(sys, "argv", ["run_campaign.py", "--dry-run", *sets]), \
                    mock.patch.object(RC, "check_loads"), self.assertRaises(SystemExit):
                RC.main()

    def test_bad_cells_stop_the_runner_before_anything_starts(self):
        for loads in ("vegeta:100", "loadgen", "wrk:5"):
            with self.subTest(loads=loads), mock.patch.object(sys, "argv", ["run_campaign.py", "--dry-run",
                                                                          "--loads", loads]), \
                    mock.patch.object(RC, "check_loads"), self.assertRaises(SystemExit):
                RC.main()


class VerifiedToolsOnlyTest(unittest.TestCase):
    def test_wrk_needs_no_check(self):
        with mock.patch.object(LT, "load_manifest") as load:
            RC.check_loads(RC.parse_loads("wrk"))
        load.assert_not_called()

    def test_a_tool_the_verification_did_not_clear_stops_the_runner(self):
        with mock.patch.object(LT, "load_manifest", return_value={"tools": {}}), \
                mock.patch.object(LT, "resolve_tool", side_effect=LT.ToolError("vegeta has status 'smoke-tested', "
                                                                               "not 'verified'")), \
                self.assertRaises(SystemExit) as cm:
            RC.check_loads(RC.parse_loads("loadgen:100"))
        self.assertIn("not 'verified'", str(cm.exception))

    def test_verified_tools_pass_and_each_is_checked_once(self):
        with mock.patch.object(LT, "load_manifest", return_value={"tools": {}}), \
                mock.patch.object(LT, "resolve_tool") as resolve:
            RC.check_loads(RC.parse_loads("wrk,loadgen:50,loadgen:100,k6:50"))
        self.assertEqual(sorted(c.args[1] for c in resolve.call_args_list), ["k6", "loadgen"])


class LeftoversTest(unittest.TestCase):
    def test_a_generator_left_behind_contaminates_the_next_run(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            out = "4242\n" if argv[:3] == ["pgrep", "-x", "k6"] or argv[-1] == "bench/loadgen.py" else ""
            return mock.Mock(stdout=out)

        with mock.patch.object(RC.subprocess, "run", side_effect=fake_run):
            found = RC.leftovers()
        self.assertIn(["pgrep", "-f", "bench/loadgen.py"], calls)
        self.assertIn(["pgrep", "-x", "k6"], calls)
        self.assertIn(["pgrep", "-x", "wrk"], calls)
        self.assertIn("process 'bench/loadgen.py' pid 4242", found)
        self.assertIn("process k6 pid 4242", found)


if __name__ == "__main__":
    unittest.main()
