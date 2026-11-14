"""The paired check of the two probe contexts before R1's hold (bench/vm/paired_check.py; re-calibration pre-registration 5.3, P-1).

Hermetic: probes are scripted stand-ins; nothing is timed, no sandbox or sudo is started, and every file is in a temporary directory.
One test starts a short-lived shell to prove that a probe's whole session is stopped on a timeout.
"""
import json
import os
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench", "vm"))
import paired_check as P

A_COSTS = {"C0": 0.0055, "C1": 5.06, "C2": 2.64, "C3": 42.4, "C5": 230.3}
BOOT = "3e99b2cc-13f7-4112-ae52-9d03631f0e3e"


def reported(cpu, ctx):
    return {"cpus": [int(cpu)], "repeats": 21, "clock": "thread_time"} if ctx == "A" else {"clock": "thread_time"}


def records(off_b=0.0, per_cpu=None, drop=None, bad=None):
    """The 8 planned probe records, B's C3 and C5 `off_b` (or per_cpu[cpu]) above A's."""
    out = []
    for i, cpu, ctx in P.plan():
        off = (per_cpu or {}).get(cpu, off_b) if ctx == "B" else 0.0
        costs = dict(A_COSTS, C3=A_COSTS["C3"] * (1 + off), C5=A_COSTS["C5"] * (1 + off))
        if bad == i:
            costs = None
        out.append({"i": i, "cpu": cpu, "ctx": ctx, "costs_ms": costs, "reported": reported(cpu, ctx),
                    "error": None if costs else "exit 1: boom"})
    if drop is not None:
        del out[drop]
    return out


def probe_output(cmd, off_b=0.0):
    """What the probe `cmd` prints: HS1's probe line for A, an origin-session line for B."""
    if cmd[0] == "sudo":
        costs = dict(A_COSTS, C3=A_COSTS["C3"] * (1 + off_b), C5=A_COSTS["C5"] * (1 + off_b))
        return json.dumps({"costs_ms": costs, "batch": {}, "clock": "thread_time"}) + "\n"
    cpu = cmd[cmd.index("-c") + 1]
    return json.dumps({"costs_ms": A_COSTS, "cpus": [int(cpu)], "repeats": int(cmd[-1]), "clock": "thread_time"}) + "\n"


def write_probes(d, recs, extra=""):
    with open(os.path.join(d, "probes.jsonl"), "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in recs)
        fh.write(extra)


class PlanTest(unittest.TestCase):
    def test_the_pre_registered_constants(self):
        self.assertEqual(P.LIMIT, 0.05)
        self.assertEqual(P.ROUTES, ("C3", "C5"))
        self.assertEqual(P.CPUS, ("0", "1"))
        self.assertEqual(P.ORDER, ("A", "B", "B", "A"))
        self.assertEqual(P.REPEATS, 21)
        self.assertEqual(P.CLOCK, "thread_time")
        self.assertEqual(P.MIN_UPTIME_S, 1800.0)
        self.assertEqual((P.EXIT_GO, P.EXIT_USAGE, P.EXIT_UNREADABLE, P.EXIT_STOP), (0, 2, 3, 6))

    def test_cpu_0_then_cpu_1_each_in_the_order_a_b_b_a(self):
        self.assertEqual([(cpu, ctx) for _, cpu, ctx in P.plan()],
                         [("0", "A"), ("0", "B"), ("0", "B"), ("0", "A"), ("1", "A"), ("1", "B"), ("1", "B"), ("1", "A")])
        self.assertEqual([i for i, _, _ in P.plan()], list(range(8)))

    def test_context_a_is_hs1s_probe_in_the_sandbox(self):
        cmd = P.command("A", "1", "/home/artur/agent_workspace/host/x", 903, root="/T")
        self.assertEqual(cmd[0], P.SBX)
        self.assertEqual(cmd[1], "/home/artur/agent_workspace/host/x")
        self.assertEqual(cmd[2:5], ["taskset", "-c", "1"])
        self.assertEqual(cmd[5:8], [P.HS1_PY, "-I", "-B"])
        self.assertEqual(cmd[8:], ["/T/bench/vm/hs1_probe.py", "903", "21"])
        self.assertNotIn("sudo", cmd)

    def test_context_b_is_the_holds_probe_as_root(self):
        cmd = P.command("B", "0", "/ignored", 901, root="/T")
        self.assertEqual(cmd[:6], ["sudo", "env", "PYTHONDONTWRITEBYTECODE=1", "taskset", "-c", "0"])
        self.assertEqual(cmd[6:8], [P.TREE_PY, "-B"])
        self.assertEqual(cmd[8:], ["/T/bench/calibrate.py", "origin-session", "--repeats", "21", "--calibration",
                                   "/T/bench/calibration/placeholder.json"])

    def test_an_unknown_context_is_refused(self):
        with self.assertRaises(ValueError):
            P.command("C", "0", "/x", 1)


class ParseTest(unittest.TestCase):
    def test_the_last_line_with_costs(self):
        out = "noise\n" + json.dumps({"costs_ms": {"C3": 1}}) + "\n" + json.dumps({"costs_ms": {"C3": "2.5", "C5": 3}}) + "\n"
        self.assertEqual(P.parse_costs(out), {"C3": 2.5, "C5": 3.0})

    def test_nothing_readable(self):
        self.assertIsNone(P.parse_costs(""))
        self.assertIsNone(P.parse_costs("Traceback\n{\"x\": 1}\n[1, 2]\n"))
        self.assertIsNone(P.parse_costs(None))
        self.assertIsNone(P.parse_costs(json.dumps({"costs_ms": {"C3": "fast"}})))


class JudgeTest(unittest.TestCase):
    def test_equal_contexts_go_on(self):
        v = P.judge(records(0.0))
        self.assertTrue(v["ok"])
        self.assertEqual(v["exit"], P.EXIT_GO)
        self.assertAlmostEqual(v["D"], 0.0, places=12)

    def test_the_limit_is_inclusive(self):
        # binary-exact costs, so D equals the limit exactly: 1.0625 / 1.0 - 1 = 0.0625
        recs = records(0.0)
        for r in recs:
            r["costs_ms"].update(C3=1.0625 if r["ctx"] == "B" else 1.0, C5=1.0625 if r["ctx"] == "B" else 1.0)
        old = P.LIMIT
        try:
            P.LIMIT = 0.0625
            self.assertEqual(P.judge(recs)["D"], 0.0625)
            self.assertTrue(P.judge(recs)["ok"])
            recs[1]["costs_ms"]["C3"] = 1.0625 + 2 ** -20
            self.assertFalse(P.judge(recs)["ok"])
        finally:
            P.LIMIT = old
        self.assertTrue(P.judge(records(-0.049))["ok"])

    def test_beyond_the_limit_stops_in_either_direction(self):
        for off in (0.051, -0.051, 0.2):
            v = P.judge(records(off))
            self.assertFalse(v["ok"], off)
            self.assertEqual(v["exit"], P.EXIT_STOP)
            self.assertIn("R1 stops before the hold", v["reasons"][0])

    def test_d_is_the_mean_over_cpus_and_routes(self):
        v = P.judge(records(per_cpu={"0": 0.08, "1": 0.0}))
        self.assertAlmostEqual(v["D"], 0.04, places=12)
        self.assertTrue(v["ok"])
        self.assertAlmostEqual(v["per_cpu"]["0"]["off"]["C5"], 0.08, places=12)
        v = P.judge(records(per_cpu={"0": 0.08, "1": 0.03}))
        self.assertAlmostEqual(v["D"], 0.055, places=12)
        self.assertFalse(v["ok"])

    def test_an_unreadable_probe_stops(self):
        v = P.judge(records(0.0, bad=5))
        self.assertFalse(v["ok"])
        self.assertEqual(v["exit"], P.EXIT_UNREADABLE)
        self.assertIn("probe 5 (CPU 1, B) could not be read", v["reasons"][0])
        self.assertIsNone(v["D"])

    def test_a_missing_or_reordered_probe_stops(self):
        self.assertEqual(P.judge(records(0.0, drop=7))["exit"], P.EXIT_UNREADABLE)
        recs = records(0.0)
        recs[1], recs[3] = recs[3], recs[1]
        self.assertEqual(P.judge(recs)["exit"], P.EXIT_UNREADABLE)

    def test_a_route_missing_zero_or_not_finite_stops(self):
        for route, value in (("C5", None), ("C3", 0.0), ("C3", float("nan")), ("C5", float("inf")), ("C3", True)):
            recs = records(0.0)
            if value is None:
                del recs[2]["costs_ms"][route]
            else:
                recs[2]["costs_ms"][route] = value
            self.assertEqual(P.judge(recs)["exit"], P.EXIT_UNREADABLE, (route, value))

    def test_hs1s_probe_must_report_its_cpu_repeats_and_clock(self):
        for field, value in (("cpus", [1]), ("cpus", [0, 1]), ("repeats", 7), ("clock", "perf_counter")):
            recs = records(0.0)
            recs[0]["reported"][field] = value
            self.assertEqual(P.judge(recs)["exit"], P.EXIT_UNREADABLE, (field, value))
        recs = records(0.0)
        recs[0]["reported"] = None
        self.assertEqual(P.judge(recs)["exit"], P.EXIT_UNREADABLE)
        recs = records(0.0)
        recs[1]["reported"]["clock"] = "process_time"     # B reports no repeats or CPUs, but its clock is checked
        self.assertEqual(P.judge(recs)["exit"], P.EXIT_UNREADABLE)

    def test_problems_from_reading_the_file_stop(self):
        v = P.judge(records(0.0), problems=["probes.jsonl line 9 is not JSON (a torn write?)"])
        self.assertEqual(v["exit"], P.EXIT_UNREADABLE)
        self.assertIn("torn", v["reasons"][0])

    def test_each_contexts_d_against_hs1s_medians_is_reported_not_judged(self):
        med = {"medians_ms": {cpu: {r: {"median_ms": A_COSTS[r] / 1.02} for r in P.ROUTES} for cpu in P.CPUS}}
        v = P.judge(records(0.03), med)
        self.assertAlmostEqual(v["d_vs_hs1_medians"]["A"], 0.02, places=9)
        self.assertAlmostEqual(v["d_vs_hs1_medians"]["B"], 1.02 * 1.03 - 1, places=9)
        self.assertTrue(v["ok"])


class RunTest(unittest.TestCase):
    def test_run_records_every_probe_in_order_and_judges(self):
        calls = []

        def runner(cmd):
            calls.append(cmd)
            return 0, probe_output(cmd, off_b=0.01), ""

        with tempfile.TemporaryDirectory() as d:
            recs = P.run(d, runner=runner, now=lambda: "T")
            self.assertEqual(len(calls), 8)
            self.assertEqual([c[0] == "sudo" for c in calls], [False, True, True, False] * 2)
            back, problems = P.read_records(d)
            self.assertEqual(problems, [])
            self.assertEqual(back, json.loads(json.dumps(recs)))
            v = P.judge(back)
            self.assertAlmostEqual(v["D"], 0.01, places=12)
            self.assertTrue(v["ok"])

    def test_a_failing_or_timed_out_probe_is_recorded_unreadable(self):
        def runner(cmd):
            if cmd[0] == "sudo":
                return None, "", "TimeoutExpired: no result within 600 s; the probe's session was stopped"
            return 1, "", "no origin"

        with tempfile.TemporaryDirectory() as d:
            recs = P.run(d, runner=runner, now=lambda: "T")
            self.assertTrue(all(r["costs_ms"] is None for r in recs))
            self.assertIn("TimeoutExpired", recs[1]["error"])
            self.assertEqual(recs[0]["error"], "no origin")
            self.assertEqual(P.judge(recs)["exit"], P.EXIT_UNREADABLE)

    def test_a_timed_out_probe_loses_its_whole_session(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "child.pid")
            cmd = ["bash", "-c", f"sleep 60 & echo $! > {pidfile}; wait"]
            t0 = time.monotonic()
            rc, _out, err = P.run_probe(cmd, timeout=1.0)
            self.assertIsNone(rc)
            self.assertIn("TimeoutExpired", err)
            self.assertLess(time.monotonic() - t0, 15)
            with open(pidfile, encoding="ascii") as fh:
                child = int(fh.read())
            for _ in range(50):
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                self.fail("the probe's background child survived the timeout")

    def test_a_probe_that_cannot_start(self):
        rc, _out, err = P.run_probe(["/nonexistent/probe"], timeout=5)
        self.assertIsNone(rc)
        self.assertIn("FileNotFoundError", err)


class MainTest(unittest.TestCase):
    def main(self, argv, uptime=4000.0, ran=None):
        return P.main(argv, read_uptime=lambda: uptime, read_boot=lambda: BOOT,
                      do_run=(ran.append if ran is not None else lambda d: None))

    def test_an_out_dir_outside_the_workspace_or_already_used_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            ran = []
            self.assertEqual(self.main(["run", d], ran=ran), P.EXIT_USAGE)
            old = P.WORKSPACE
            try:
                P.WORKSPACE = d
                used = os.path.join(d, "used")
                os.makedirs(used)
                with open(os.path.join(used, "probes.jsonl"), "w", encoding="utf-8") as fh:
                    fh.write("{}\n")
                self.assertEqual(self.main(["run", used], ran=ran), P.EXIT_USAGE)
                with open(os.path.join(used, "probes.jsonl"), encoding="utf-8") as fh:
                    self.assertEqual(fh.read(), "{}\n")
            finally:
                P.WORKSPACE = old
            self.assertEqual(ran, [])

    def test_a_young_boot_is_refused_before_any_probe(self):
        with tempfile.TemporaryDirectory() as d:
            old = P.WORKSPACE
            try:
                P.WORKSPACE = d
                ran = []
                self.assertEqual(self.main(["run", os.path.join(d, "x")], uptime=1799.0, ran=ran), P.EXIT_USAGE)
                self.assertEqual(ran, [])
            finally:
                P.WORKSPACE = old

    def test_bad_medians_are_refused_before_any_probe(self):
        with tempfile.TemporaryDirectory() as d:
            old = P.WORKSPACE
            try:
                P.WORKSPACE = d
                ran = []
                bad = os.path.join(d, "bad.json")
                with open(bad, "w", encoding="utf-8") as fh:
                    json.dump({"medians_ms": {"0": {"C3": {"median_ms": 42.0}}}}, fh)
                for medians in (os.path.join(d, "missing.json"), bad):
                    self.assertEqual(self.main(["run", os.path.join(d, "x"), "--medians", medians], ran=ran), P.EXIT_USAGE)
                self.assertEqual(ran, [])
            finally:
                P.WORKSPACE = old

    def test_judge_writes_paired_json_with_the_boot_and_the_time(self):
        with tempfile.TemporaryDirectory() as d:
            write_probes(d, records(0.06))
            self.assertEqual(self.main(["judge", d]), P.EXIT_STOP)
            with open(os.path.join(d, "paired.json"), encoding="utf-8") as fh:
                v = json.load(fh)
            self.assertFalse(v["ok"])
            self.assertEqual(v["schema"], "paired-check/1")
            self.assertEqual(v["boot_id"], BOOT)
            self.assertRegex(v["judged_utc"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z$")

    def test_a_torn_line_gives_a_written_stop_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            write_probes(d, records(0.0)[:7], extra='{"i": 7, "cpu": "1", "ct')
            self.assertEqual(self.main(["judge", d]), P.EXIT_UNREADABLE)
            with open(os.path.join(d, "paired.json"), encoding="utf-8") as fh:
                v = json.load(fh)
            self.assertTrue(any("torn" in r for r in v["reasons"]))

    def test_run_then_judge_in_one_call(self):
        with tempfile.TemporaryDirectory() as d:
            old = P.WORKSPACE
            try:
                P.WORKSPACE = d
                out = os.path.join(d, "check")
                ran = []

                def fake_run(path):
                    ran.append(path)
                    os.makedirs(path)
                    write_probes(path, records(0.02))

                rc = P.main(["run", out], read_uptime=lambda: 4000.0, read_boot=lambda: BOOT, do_run=fake_run)
                self.assertEqual(rc, P.EXIT_GO)
                self.assertEqual(ran, [os.path.realpath(out)])
                with open(os.path.join(out, "paired.json"), encoding="utf-8") as fh:
                    self.assertEqual(json.load(fh)["uptime_s_at_start"], 4000.0)
            finally:
                P.WORKSPACE = old


if __name__ == "__main__":
    unittest.main()
