"""Host validity per run (bench/hostcheck.py; docs/RECALIBRATION_2026-11_DESIGN.md 5.1 and 7): the rules on fixtures and on the
simulated host, and the signature of every function that decides a run's host validity, none of which may read a Q, a p95 or a harm.
Nothing here needs root, a namespace or the real host."""
import contextlib
import datetime
import gzip
import inspect
import io
import os
import re
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
import harm_gate as H
import hostcheck as HC
import population as P
import scenario as SC
import sim_host as S

TEMPLATE = C.load(C.PLACEHOLDER)
COSTS = dict(TEMPLATE["route_costs_ms"])
FORBIDDEN = ("q", "p95", "harm", "metrics", "dq", "dl")


def probe(c3_0, c5_0, c3_1, c5_1, base=COSTS):
    """A probe pair whose C3 and C5 are these fractions off `base` on CPU 0 and CPU 1; the other routes as `base`."""
    return {"cpus": {"0": {**base, "C3": base["C3"] * (1 + c3_0), "C5": base["C5"] * (1 + c5_0)},
                     "1": {**base, "C3": base["C3"] * (1 + c3_1), "C5": base["C5"] * (1 + c5_1)}}}


def judging_functions():
    """Every function of bench/hostcheck.py that decides a run's host validity, or gives a figure such a decision reads."""
    return [HC.speed_deviation, HC.speed_verdict, HC.judge_speed, HC.pooled_legit_slip_p99, HC.rule_slip, HC.rule_clock,
            HC.rule_pause, HC.other_cpu, HC.rule_other_cpu, HC.rule_evidence, HC.is_testbed, HC.judge_host, HC.HostCheck.judge]


class SignatureTest(unittest.TestCase):
    def test_nothing_that_judges_host_validity_takes_or_reads_a_q_a_p95_or_a_harm(self):
        for fn in judging_functions():
            with self.subTest(fn=fn.__name__):
                names = [n.lower() for n in inspect.signature(fn).parameters]
                self.assertFalse([n for n in names if n in FORBIDDEN or "p95" in n or "harm" in n], names)
                body = inspect.getsource(fn).split('"""')[-1]          # the code after the docstring
                for word in (r'\["Q"\]', r"'Q'", r"p95", r"\bharm\b", r"run_metrics", r"\bmetrics\b"):
                    self.assertIsNone(re.search(word, body), f"{fn.__name__} reads {word}")


class SpeedTest(unittest.TestCase):
    def test_the_constants_of_h1(self):
        self.assertEqual((HC.SPEED_DEV, HC.SPEED_ROUTES, HC.SPEED_CPUS, HC.SPEED_REPEATS), (0.10, ("C3", "C5"), ("0", "1"), 21))

    def test_d_is_the_mean_over_the_cpus_of_the_mean_of_c3_and_c5(self):
        self.assertAlmostEqual(HC.speed_deviation(probe(0.10, 0.20, -0.10, 0.0), COSTS), (0.15 + -0.05) / 2, delta=1e-12)
        other = probe(0.0, 0.0, 0.0, 0.0)
        other["cpus"]["0"]["C1"] = 99.0                                   # the other routes do not count
        self.assertEqual(HC.speed_deviation(other, COSTS), 0.0)
        self.assertIsNone(HC.speed_deviation({"cpus": {"0": COSTS, "1": None}}, COSTS), "an unreadable CPU says nothing")
        self.assertIsNone(HC.speed_deviation({"cpus": {"0": COSTS}}, COSTS))

    def test_ten_percent_at_either_end_is_inside_and_more_is_not(self):
        self.assertEqual(HC.speed_verdict(0.10, -0.10), [])
        self.assertEqual(len(HC.speed_verdict(0.10 + 1e-9, 0.0)), 1)
        self.assertEqual(len(HC.speed_verdict(0.0, -0.10 - 1e-9)), 1)
        self.assertIn("could not be read", HC.speed_verdict(None, 0.0)[0])
        r = HC.judge_speed(probe(0.0, 0.0, 0.0, 0.0), probe(0.3, 0.3, 0.3, 0.3), COSTS)
        self.assertEqual((r["ok"], r["d_before"]), (False, 0.0))
        self.assertAlmostEqual(r["d_after"], 0.3, delta=1e-12)
        self.assertEqual(r["reasons"], ["H1: speed after the run +30.0% from the reference costs (limit 10%)"])

    def test_the_probe_is_a_session_of_the_origin_step_pinned_and_with_the_records_knobs(self):
        self.assertEqual(HC.probe_command("1", "/x/cal.json", "/py"),
                         ["taskset", "-c", "1", "/py", os.path.join(REPO, "bench", "calibrate.py"), "origin-session", "--repeats", "21",
                          "--calibration", "/x/cal.json"])
        self.assertEqual(K.ORIGIN_REPEATS, HC.SPEED_REPEATS)


class BracketTest(unittest.TestCase):
    """The bracket around runs of the calibrator on the simulated host."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        ctl = SC.load(K.spec_path(K.CONTROL_SPEC))
        self.plan = lambda name="a": X.plan_population(P.draw(ctl.seed_namespace, 11, 20.0, ctl.benign_identities, None,
                                                               P.Timeline(8.0, 0.0, 0.0), ctl.per_profile),
                                                       "probe", "C", 11, os.path.join(self.tmp.name, name, "C"), TEMPLATE,
                                                       C.PLACEHOLDER, P.Timeline(8.0, 0.0, 0.0),
                                                       settings={"readiness_timeout_s": 5.0})

    def runner(self, host):
        return K.Runner(host, speed=HC.SpeedBracket(C.PLACEHOLDER, COSTS, "the test's costs"))

    def test_the_probes_run_on_cpus_0_and_1_before_the_stack_and_after_the_teardown(self):
        host = S.SimHost(origin_costs=COSTS)
        self.runner(host).run(self.plan(), lambda m: None)
        probes = [i for i, c in enumerate(host.commands) if "origin-session" in c[2]]
        self.assertEqual([host.commands[i][2][:3] for i in probes], [("taskset", "-c", "0"), ("taskset", "-c", "1")] * 2)
        for i in probes:
            self.assertEqual(host.commands[i][2][3:], tuple(HC.probe_command("0", C.PLACEHOLDER)[3:]))
        first_prim = next(i for i, c in enumerate(host.commands) if c[0] == "prim")
        last_teardown = max(i for i, c in enumerate(host.commands) if c[2][:3] in (("ip", "netns", "del"), ("ip", "link", "del")))
        self.assertLess(probes[1], first_prim, "the first pair before the topology is built")
        self.assertGreater(probes[2], last_teardown, "the second after the teardown")
        gate = next(i for i, c in enumerate(host.commands) if "timer-probe" in c[2])
        self.assertLess(gate, probes[0], "after the environment gate")

    def test_run_json_and_done_keep_both_probes_d_and_the_in_run_index(self):
        host = S.SimHost(origin_costs=COSTS)
        plan = self.plan()
        done = self.runner(host).run(plan, lambda m: None)
        run = K.read_json(os.path.join(plan.out, "run.json"))
        for record in (done["speed"], run["speed"]):
            self.assertEqual(sorted(record), ["after", "before", "d_after", "d_before", "in_run", "limit", "ok", "reasons", "reference",
                                              "reference_costs_ms", "window"])
            self.assertEqual((record["d_before"], record["d_after"], record["ok"]), (0.0, 0.0, True))
            self.assertEqual(sorted(record["before"]["cpus"]), ["0", "1"])
            self.assertGreater(record["in_run"]["origin_cpu_s"], 0)
            self.assertIsNotNone(record["in_run"]["index"])
            self.assertLessEqual(record["window"]["t_start"], record["window"]["t_end"])
        self.assertEqual(K.read_json(os.path.join(plan.out, "environment.json"))["speed_before"], run["speed"]["before"])

    def test_a_host_that_slows_down_during_a_run_is_host_invalid_by_its_after_probe(self):
        host = S.SimHost(origin_costs=COSTS)
        host.origin_slow = lambda t: 0.3 if any(p.role == "origin" for p in host.procs.values()) else 0.0     # from the stack's start on
        said = []
        done = self.runner(host).run(self.plan(), said.append)
        self.assertEqual((done["speed"]["d_before"], done["speed"]["ok"]), (0.0, False))
        self.assertAlmostEqual(done["speed"]["d_after"], 0.3, delta=1e-9)
        self.assertEqual(done["speed"]["reasons"], ["H1: speed after the run +30.0% from the reference costs (limit 10%)"])
        self.assertTrue(any("HOST-INVALID: H1: speed after the run" in m for m in said), said)
        self.assertTrue(done["ok"], "H1 says nothing about the executor's soundness")

    def test_a_runner_without_a_bracket_probes_nothing(self):
        host = S.SimHost(origin_costs=COSTS)
        done = K.Runner(host).run(self.plan(), lambda m: None)
        self.assertNotIn("speed", done)
        self.assertFalse([c for c in host.commands if "origin-session" in c[2]])

    def cli(self, *args, host=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = K.main(list(args), host=host)
        return code, out.getvalue(), err.getvalue()

    def test_the_steps_bracket_their_runs_against_the_sessions_origin_and_need_it(self):
        out = os.path.join(self.tmp.name, "s")
        code, _, err = self.cli("capacity", "--out", out, "--levels", "80,160", "--step-s", "10", "--repeats", "1", "--simulate")
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("no origin step", err)
        self.assertEqual(self.cli("origin", "--out", out, "--simulate")[0], K.EXIT_OK)
        origin = K.read_json(os.path.join(out, "origin", "origin.json"))
        self.cli("capacity", "--out", out, "--levels", "80,160,240,320,400,480", "--step-s", "10", "--repeats", "1", "--simulate",
                 "--sim-capacity-cpu", "1.1")
        done = GC.read_done(os.path.join(out, "capacity", "r1", "C"))
        self.assertEqual(done["speed"]["reference_costs_ms"], origin["route_costs_ms"])
        self.assertEqual(done["speed"]["reference"], "the session's origin step (origin/origin.json)")
        self.assertTrue(done["speed"]["ok"], done["speed"])

    def test_the_drift_step_brackets_against_the_frozen_records_costs(self):
        frozen = os.path.join(self.tmp.name, "frozen.json")
        C.dump(CF.frozen_v2(), frozen)
        with mock.patch.object(K, "drift_step", return_value={"ok": True}) as step:
            code = self.cli("drift", "--calibration", frozen, "--out", os.path.join(self.tmp.name, "d"), "--simulate")[0]
        self.assertEqual(code, K.EXIT_OK)
        runner = step.call_args.args[0]
        self.assertEqual(runner.speed.reference_costs, CF.frozen_v2()["route_costs_ms"])
        self.assertEqual(runner.speed.cal_path, frozen)
        self.assertIn("the frozen record", runner.speed.source)


# --- K4: the monitors and the rules H3-H7 ---------------------------------------------------------------------------------------------

T0 = datetime.datetime(2026, 11, 13, 10, 0, 0, tzinfo=datetime.UTC).timestamp()
DRIFT = os.path.join(REPO, "results", "2026-11-11_harm-drift-check")


def at(seconds):
    return T0 + seconds


def mpstat_text(times, date="2026-11-13", ampm=False):
    def clock(t):
        d = datetime.datetime.fromtimestamp(t, datetime.UTC)
        return d.strftime("%I:%M:%S %p") if ampm else d.strftime("%H:%M:%S")
    out = [f"Linux 7.0.0-42-generic (h) \t{date} \t_x86_64_\t(8 CPU)", ""]
    for t in times:
        out += [f"{clock(t)}  CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle",
                f"{clock(t)}  all    1.00    0.00    1.00    0.00    0.00    0.00    0.00    0.00    0.00   98.00",
                f"{clock(t)}    0    1.00    0.00    1.00    0.00    0.00    0.00    0.00    0.00    0.00   98.00", ""]
    return "\n".join(out) + "\n"


def pidstat_text(samples):
    """samples: [(end time, [(uid, pid, %CPU, command)])], 10 s each."""
    out = ["Linux 7.0.0-42-generic (h) \t2026-11-13 \t_x86_64_\t(8 CPU)", ""]
    for t, rows in samples:
        clock = datetime.datetime.fromtimestamp(t - 10, datetime.UTC).strftime("%H:%M:%S")
        end = datetime.datetime.fromtimestamp(t, datetime.UTC).strftime("%H:%M:%S")
        out.append(f"{clock}   UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command")
        out += [f"{end}  {uid:>4}  {pid:>8}    {pct:.2f}    0.00    0.00    0.00    {pct:.2f}     2  {cmd}" for uid, pid, pct, cmd in rows]
        out.append("")
    return "\n".join(out) + "\n"


def chrony_text(samples):
    """samples: [(time, System time offset, leap, [(state, offset)])]."""
    out = []
    for t, offset, leap, sources in samples:
        out.append(datetime.datetime.fromtimestamp(t, datetime.UTC).isoformat(timespec="seconds").replace("+00:00", "Z"))
        out.append(f"B97DBE7B,185.125.190.123,3,{t:.3f},{offset:.9f},0.0,0.0,1.0,0.0,0.1,0.04,0.002,64.0,{leap}")
        out += [f"^,{state},10.0.0.{i},2,6,377,22,{off:.9f},{off:.9f},0.010" for i, (state, off) in enumerate(sources)]
    return "\n".join(out) + "\n"


class ParserTest(unittest.TestCase):
    def test_mpstat_in_iso_and_in_the_twelve_hour_form_of_ap7(self):
        times = [at(k * 5) for k in range(4)]
        self.assertEqual(HC.parse_mpstat(mpstat_text(times)), times)
        self.assertEqual(HC.parse_mpstat(mpstat_text(times, date="11/13/2026", ampm=True)), times)
        late = [at(-15), at(-10)]                                    # 09:59:45 and 09:59:50, then past midnight is a new day
        self.assertEqual(HC.parse_mpstat(mpstat_text(late)), late)
        self.assertEqual(HC.parse_mpstat(mpstat_text(times) + "\x00" * 50), times, "a reset's NUL tail is read past")

    def test_the_day_turns_when_the_clock_goes_back(self):
        midnight = datetime.datetime(2026, 11, 14, tzinfo=datetime.UTC).timestamp()
        times = [midnight - 5, midnight, midnight + 5]
        self.assertEqual(HC.parse_mpstat(mpstat_text(times)), times)

    def test_pidstat_with_full_command_lines_and_an_empty_interval(self):
        got = HC.parse_pidstat(pidstat_text([(at(10), [(0, 7, 12.5, "/repo/venv/bin/python /repo/bench/loadgen.py --rate 3")]),
                                             (at(20), [])]))
        self.assertEqual([s["t"] for s in got], [at(10), at(20)])
        self.assertEqual(got[0]["rows"], [{"uid": 0, "pid": 7, "cpu_pct": 12.5, "command": "/repo/venv/bin/python /repo/bench/loadgen.py --rate 3"}])
        self.assertEqual(got[1]["rows"], [])

    def test_chrony_samples_with_tracking_and_sources(self):
        got = HC.parse_chrony(chrony_text([(at(0), 0.002, "Normal", [("*", 0.001), ("-", -13836.6)])]))
        self.assertEqual(got, [{"t": at(0), "tracking": {"system_time_s": 0.002, "leap": "Normal"},
                                "sources": [{"state": "*", "name": "10.0.0.0", "offset_s": 0.001},
                                            {"state": "-", "name": "10.0.0.1", "offset_s": -13836.6}]}])

    def test_the_journal(self):
        text = "2026-11-13T10:00:05.123456+00:00 h kernel: clocksource: Long readout interval\nnot a line\n"
        self.assertEqual(HC.parse_journal(text), [(at(5.123456), "h kernel: clocksource: Long readout interval")])


class RuleTest(unittest.TestCase):
    def test_h3_the_pooled_slip_at_most_the_records_100_ms(self):
        self.assertTrue(HC.rule_slip(0.1, 0.1)["ok"])
        self.assertFalse(HC.rule_slip(0.1 + 1e-9, 0.1)["ok"])
        self.assertFalse(HC.rule_slip(None, 0.1)["ok"])
        self.assertEqual(TEMPLATE["validity"]["slip_pooled_s"], 0.1)

    def test_h3_does_not_judge_a_staged_capacity_run_and_judges_every_other(self):
        """D-099 1 (2026-11-14, pre-data; T-105 F1): a staged capacity run keeps H1 and H4-H7, and its slip is recorded, not judged."""
        speed = {"reasons": []}
        cover = {"mpstat": [at(k * 5) for k in range(-1, 22)], "pidstat": [{"t": at(k * 10), "rows": []} for k in range(1, 11)],
                 "chrony": [{"t": at(k * 30), "tracking": {"system_time_s": 0.0, "leap": "Normal"}, "sources": []} for k in range(4)],
                 "journal": []}
        staged = HC.judge_host(speed, 0.291, 0.1, cover, {}, at(0), at(100), staged=True)
        self.assertTrue(staged["ok"], staged["reasons"])
        self.assertEqual(staged["rules"]["H3"], {"ok": True, "reasons": [], "exempt": HC.H3_EXEMPT})
        self.assertEqual(staged["slip_p99_s"], 0.291)
        self.assertEqual(sorted(staged["rules"]), ["H1", "H3", "H4", "H5", "H6", "H7"])
        other = HC.judge_host(speed, 0.291, 0.1, cover, {}, at(0), at(100))
        self.assertEqual(other["reasons"], ["H3: pooled legit slip p99 291 ms above 100 ms"])
        late = HC.judge_host(speed, 0.291, 0.1, {**cover, "mpstat": [at(0), at(60)]}, {}, at(0), at(100), staged=True)
        self.assertFalse(late["ok"], "the other rules still judge it")
        self.assertEqual(HC.STAGED_SCENARIO, "capacity")
        plan = K.capacity_plan(TEMPLATE, C.PLACEHOLDER, 0, "/tmp/x/capacity/r1/C", [80.0, 160.0], 10.0)
        self.assertEqual(plan.scenario, HC.STAGED_SCENARIO, "the calibrator's staged runs are the ones exempt")

    def test_h4_the_clock(self):
        quiet = [(at(k * 30), 0.0999, "Normal", [("*", 1.0), ("+", -1.0), ("-", 5000.0)]) for k in range(-1, 5)]
        self.assertTrue(HC.rule_clock(HC.parse_chrony(chrony_text(quiet)), [], at(0), at(100))["ok"])
        for bad, said in (((at(30), 0.1, "Normal", []), "system clock was +0.100 s off"),
                          ((at(30), 0.0, "Not synchronised", []), "not synchronised"),
                          ((at(30), 0.0, "Normal", [("*", -1.0 - 1e-6)]), "read -1.000 s"),
                          ((at(30), 0.0, "Normal", [("+", 13836.6)]), "read +13836.600 s")):
            with self.subTest(said=said):
                r = HC.rule_clock(HC.parse_chrony(chrony_text([*quiet, bad])), [], at(0), at(100))
                self.assertFalse(r["ok"])
                self.assertIn(said, r["reasons"][0])
        far = [(at(200), 5.0, "Normal", [])]
        self.assertTrue(HC.rule_clock(HC.parse_chrony(chrony_text(far)), [], at(0), at(100))["ok"], "beyond one interval of the run")
        for line, ok in (("chronyd[1]: Forward time jump detected!", False), ("chronyd[1]: Can't synchronise: no majority", False),
                         ("kernel: clocksource: Long readout interval", False), ("chronyd[1]: Selected source 10.0.0.1", True)):
            with self.subTest(line=line):
                self.assertIs(HC.rule_clock([], [(at(50), line)], at(0), at(100))["ok"], ok)
        self.assertTrue(HC.rule_clock([], [(at(101), "kernel: Long readout interval")], at(0), at(100))["ok"], "after the run")

    def test_h5_no_gap_above_10_s(self):
        """D-099 2 (2026-11-14, pre-data): the line is 10 s (was 6 s), the monitors at real-time priority."""
        self.assertTrue(HC.rule_pause([at(k * 5) for k in range(-1, 22)], at(0), at(100))["ok"])
        self.assertTrue(HC.rule_pause([at(0), at(10), at(20)], at(1), at(19))["ok"], "10 s is not above 10 s")
        self.assertTrue(HC.rule_pause([at(0), at(9), at(18)], at(1), at(17))["ok"], "AP-7's longest gaps under load, 9 s")
        r = HC.rule_pause([at(0), at(10.6), at(20)], at(1), at(19))
        self.assertEqual(r["reasons"], ["H5: no mpstat sample for 11 s from 2026-11-13T10:00:00+00:00"])
        self.assertFalse(HC.rule_pause([at(-5), at(30), at(35)], at(0), at(20))["ok"], "a pause across the start")
        self.assertTrue(HC.rule_pause([at(-100), at(-50), at(0), at(5), at(10)], at(1), at(9))["ok"], "gaps before the window")

    def test_h6_five_percent_on_average_and_fifty_in_any_sample(self):
        def run(pcts):
            text = pidstat_text([(at(10 * (k + 1)), [(1000, 1874, p, "/home/u/.claude/remote/srv/x/server --serve")])
                                 for k, p in enumerate(pcts)])
            return HC.rule_other_cpu(HC.parse_pidstat(text), at(0), at(10 * len(pcts) - 10))
        self.assertTrue(run([5.0, 5.0, 5.0])["ok"])
        self.assertFalse(run([5.0, 5.0, 5.01])["ok"])
        self.assertTrue(run([0.0, 0.0, 15.0])["ok"], "the mean is 5")
        self.assertEqual(len(run([50.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])["reasons"]), 0)
        r = run([50.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
        self.assertTrue(any("50.1 % of a CPU in the sample" in x for x in r["reasons"]), r)
        testbed = pidstat_text([(at(10), [(0, 9, 300.0, "nginx: worker process"), (0, 10, 99.0, "[kworker/0:1-events]")])])
        self.assertTrue(HC.rule_other_cpu(HC.parse_pidstat(testbed), at(0), at(5))["ok"])

    def test_h7_dead_monitors_and_records_that_do_not_cover_the_run_fail_closed(self):
        cover = {"mpstat": [at(k * 5) for k in range(21)], "pidstat": [at(k * 10) for k in range(1, 11)],
                 "chrony": [at(k * 30) for k in range(4)], "journal": []}
        self.assertTrue(HC.rule_evidence(cover, {"mpstat": True}, at(0), at(100))["ok"])
        self.assertEqual(HC.rule_evidence(cover, {"pidstat": False}, at(0), at(100))["reasons"], ["H7: the monitor pidstat had died"])
        for name in ("mpstat", "pidstat", "chrony", "journal"):
            with self.subTest(missing=name):
                self.assertFalse(HC.rule_evidence({**cover, name: None}, {}, at(0), at(100))["ok"])
        self.assertFalse(HC.rule_evidence({**cover, "mpstat": [at(k * 5) for k in range(10)]}, {}, at(0), at(100))["ok"],
                         "a record that ends 55 s before the run does")

    def test_h7_needs_each_monitors_first_sample_within_an_interval_and_the_slack_of_the_start(self):
        """T-105 F6: a sample from before the window (an earlier run's) does not cover its start; one at or after the start, no later
        than one interval plus COVER_SLACK_S (5 s) after it, does."""
        self.assertEqual(HC.COVER_SLACK_S, 5.0)
        t0, t1 = at(0), at(150)
        silent = {"mpstat": [t0 - 3 + 5 * i for i in range(33)], "pidstat": [t0 - 600, t1], "chrony": [t0 - 600, t1 - 5], "journal": []}
        r = HC.rule_evidence(silent, {}, t0, t1)
        self.assertEqual(r["reasons"], ["H7: the pidstat record has no sample in the first 15 s of the run (from 2026-11-13T10:00:00+00:00)",
                                        "H7: the chrony record has no sample in the first 35 s of the run (from 2026-11-13T10:00:00+00:00)"])
        cover = {"mpstat": [t0 + 10 - 1e-6, *[t0 + 10 + 5 * i for i in range(30)]], "pidstat": [t0 + 15, *[t0 + 15 + 10 * i for i in range(14)]],
                 "chrony": [t0 + 35, t0 + 65, t0 + 95, t0 + 125], "journal": []}
        self.assertTrue(HC.rule_evidence(cover, {}, t0, t1)["ok"], "at the bound")
        for name, every in (("mpstat", 5.0), ("pidstat", 10.0), ("chrony", 30.0)):
            with self.subTest(late=name):
                late = {**cover, name: [t for t in cover[name] if t > t0 + every + HC.COVER_SLACK_S]}
                self.assertFalse(HC.rule_evidence(late, {}, t0, t1)["ok"])
        v = HC.judge_host({"reasons": []}, 0.01, 0.1, {**silent, "pidstat": [{"t": t0 - 600, "rows": []}, {"t": t1, "rows": []}],
                                                       "chrony": [{"t": t0 - 600, "tracking": {"system_time_s": 0.0, "leap": "Normal"},
                                                                   "sources": []}, {"t": t1 - 5, "tracking": {"system_time_s": 0.0,
                                                                                                             "leap": "Normal"}, "sources": []}]},
                          {"mpstat": True, "pidstat": True, "chrony": True, "journal": True}, t0, t1)
        self.assertFalse(v["ok"], "T-105's demonstration (D): two monitors silent for 145 s of a 150-s window")
        t1 = at(12.5)                                   # a smoke test's window, shorter than the chrony sampler's interval
        short = {"mpstat": [at(-3), at(2), at(7), at(12)], "pidstat": [at(-7.5), at(2.5), at(12.5)], "journal": []}
        self.assertTrue(HC.rule_evidence({**short, "chrony": [at(-17.5)]}, {}, t0, t1)["ok"], "one interval before its end")
        self.assertEqual(HC.rule_evidence({**short, "chrony": [at(-20.0)]}, {}, t0, t1)["reasons"],
                         ["H7: the chrony record does not cover the run (2026-11-13T10:00:00+00:00 to 2026-11-13T10:00:12+00:00)"])
        self.assertEqual(HC.rule_evidence({**short, "chrony": [at(-23.0)]}, {}, t0, t1)["reasons"],
                         ["H7: the chrony record has no sample in the last 35 s before the end of this short run (2026-11-13T10:00:12+00:00)"])


class ClassifyTest(unittest.TestCase):
    def test_the_apps_server_sshd_and_the_agents_are_not_the_testbed(self):
        for command, uid in (("server", 1000), ("/home/artur/.claude/remote/srv/4c11/server --serve --socket x", 1000),
                             ("sshd-session: artur@notty", 1000), ("sshd-session", 1000), ("2.1.321-c6c6b56", 1000),
                             ("python", 1000), ("/usr/bin/python3 -m unittest discover -s tests", 1000), ("tail", 1000),
                             ("systemd-journald", 0), ("(udev-worker)", 0), ("snapd", 0)):
            with self.subTest(command=command):
                self.assertFalse(HC.is_testbed(command, uid))

    def test_the_testbed_is_nginx_gunicorn_the_engines_the_tools_the_monitors_and_kernel_threads(self):
        for command, uid in (("nginx: worker process", 65534), ("nginx", 65534), ("python", 0),
                             ("/repo/venv/bin/python /repo/venv/bin/gunicorn --chdir bench origin:app", 0),
                             ("/repo/venv/bin/python -m gunicorn --version", 0), ("gunicorn: worker [origin:app]", 0),
                             ("/repo/venv/bin/python /repo/bench/loadgen.py --url http://10.0.0.1/", 0),
                             ("/repo/venv/bin/python bench/calibrate.py drift --calibration x", 0),
                             ("/repo/venv/bin/python /repo/bench/calibrate.py origin-session --repeats 21", 0),
                             ("/repo/venv/bin/python /repo/bench/loadtool_validate.py timer-probe", 0),
                             ("/repo/venv/bin/python /repo/bench/hostcheck.py chrony-sampler --every 30", 0),
                             ("/repo/venv/bin/python control_plane.py", 0), ("ip netns exec hg_0 x", 0), ("tc qdisc show", 0),
                             ("taskset -c 7 x", 0), ("sudo ./venv/bin/python bench/gate_campaign.py run", 0), ("mpstat -P ALL 5", 0),
                             ("pidstat -u -l 10", 0), ("journalctl -f", 0), ("stdbuf -oL mpstat -P ALL 5", 0), ("kworker/2:2H-kblockd", 0), ("ksoftirqd/1", 0),
                             ("migration/0", 0), ("rcu_preempt", 0), ("[kworker/0:0-events]", 0), ("kcompactd0", 0), ("jbd2/dm-0-8", 0)):
            with self.subTest(command=command):
                self.assertTrue(HC.is_testbed(command, uid))


AFTER_PAIR_S = 15.0         # the speed bracket's time (design 6.1: about 15 s a run), all of it put after DONE: it over-reaches


def window(run_dir):
    """The window the runner judges (from its first speed probe's start to its second's end), on a published run that had no speed
    bracket: from when its environment gate passed (environment.json; the first probe starts then, before the stack) to its DONE plus
    the after-probe pair, which the runner makes after the teardown (T-105 F2: a window that ends at DONE is narrower than the
    runner's)."""
    def ts(x):
        return datetime.datetime.fromisoformat(x).timestamp()
    return (ts(K.read_json(os.path.join(run_dir, "environment.json"))["checked_utc"]),
            ts(K.read_json(os.path.join(run_dir, "DONE"))["finished_utc"]) + AFTER_PAIR_S)


RUNS = ("legit/C", "attack_cheap_static_flood/U", "attack_costly_export_flood/U", "attack_costly_search_flood/U")


class PublishedMonitorsTest(unittest.TestCase):
    """The rules on the records of real steps, which ran before H1 and without a journal record, so the test reads H3 to H6 (H4 where
    chrony was recorded). AP-7's are published with the drift check (results/2026-11-11_harm-drift-check/ap7_monitors); AP-5's are
    tests/fixtures/ap5_monitors, gzip copies (NUL tail removed) of the orchestrator's tasks/T-081/ap5/mpstat.txt (sha256 7eeeff14...)
    and pidstat.txt (972eff3c...), taken with `pidstat -u 10` and `mpstat -P ALL 5` as AP-7's."""

    @classmethod
    def setUpClass(cls):
        def read(path):
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        mon = os.path.join(DRIFT, "ap7_monitors")
        cls.ap7 = {"mpstat": HC.parse_mpstat(read(os.path.join(mon, "mpstat.txt"))),
                   "pidstat": HC.parse_pidstat(read(os.path.join(mon, "pidstat.txt"))),
                   "chrony": HC.parse_chrony(read(os.path.join(mon, "chrony.txt")))}
        fix = os.path.join(HERE, "fixtures", "ap5_monitors")
        with gzip.open(os.path.join(fix, "mpstat.txt.gz"), "rt", encoding="utf-8") as a, \
                gzip.open(os.path.join(fix, "pidstat.txt.gz"), "rt", encoding="utf-8") as b:
            cls.ap5 = {"mpstat": HC.parse_mpstat(a.read()), "pidstat": HC.parse_pidstat(b.read())}

    def rules(self, records, run_dir):
        t0, t1 = window(run_dir)
        out = {"H3": HC.rule_slip(HC.pooled_legit_slip_p99(run_dir), 0.1), "H5": HC.rule_pause(records["mpstat"], t0, t1),
               "H6": HC.rule_other_cpu(records["pidstat"], t0, t1)}
        if "chrony" in records:
            out["H4"] = HC.rule_clock(records["chrony"], [], t0, t1)
        return out

    def test_ap7_the_runs_inside_the_compaction_are_host_invalid_by_h6(self):
        """C-129: the session compacted by hand from 18:44:51 to 18:47:10Z; the app's server and sshd used 40-60 % of a CPU."""
        for run in RUNS[:2]:
            with self.subTest(run=run):
                r = self.rules(self.ap7, os.path.join(DRIFT, "drift_20261111c_q1", "drift", run))
                self.assertFalse(r["H6"]["ok"])
                self.assertTrue(any("server" in x for x in r["H6"]["reasons"]), r["H6"])
        for run in RUNS[2:]:
            with self.subTest(run=run):
                self.assertTrue(self.rules(self.ap7, os.path.join(DRIFT, "drift_20261111c_q1", "drift", run))["H6"]["ok"])

    def test_ap7_the_runs_of_the_second_attempt_are_valid(self):
        """Over the runner's window (T-105 F2) and with H5's line at 10 s (D-099 2): AP-7's mpstat, under the testbed's load, had 21
        gaps of 7-9 s in 38 min."""
        self.assertEqual(window(os.path.join(DRIFT, "drift_20261111c_q1.second", "drift", RUNS[1]))[1]
                         - datetime.datetime.fromisoformat(K.read_json(os.path.join(DRIFT, "drift_20261111c_q1.second", "drift", RUNS[1],
                                                                                    "DONE"))["finished_utc"]).timestamp(), AFTER_PAIR_S)
        for run in RUNS:
            with self.subTest(run=run):
                r = self.rules(self.ap7, os.path.join(DRIFT, "drift_20261111c_q1.second", "drift", run))
                self.assertEqual({k: v["ok"] for k, v in r.items()}, {"H3": True, "H4": True, "H5": True, "H6": True}, r)

    def test_ap5_the_quiet_runs_are_valid(self):
        for run in RUNS:
            with self.subTest(run=run):
                r = self.rules(self.ap5, os.path.join(DRIFT, "drift_20261108_q1", "drift", run))
                self.assertEqual({k: v["ok"] for k, v in r.items()}, {"H3": True, "H5": True, "H6": True}, r)


class HostCheckOnSimTest(unittest.TestCase):
    """The runner's host check on the simulated host (K4): its monitors, the verdict, a host-invalid run set aside and made again, the
    pause and the resume."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        ctl = SC.load(K.spec_path(K.CONTROL_SPEC))
        self.plan = lambda name="a": X.plan_population(P.draw(ctl.seed_namespace, 11, 20.0, ctl.benign_identities, None,
                                                               P.Timeline(8.0, 0.0, 0.0), ctl.per_profile),
                                                       "probe", "C", 11, os.path.join(self.tmp.name, name, "C"), TEMPLATE,
                                                       C.PLACEHOLDER, P.Timeline(8.0, 0.0, 0.0),
                                                       settings={"readiness_timeout_s": 5.0})

    def runner(self, host, n=1):
        check = HC.HostCheck(host, HC.SpeedBracket(C.PLACEHOLDER, COSTS, "the test's costs"),
                             os.path.join(self.tmp.name, "monitors", str(n)), "2", 0.1)
        runner = K.Runner(host, check=check)
        self.addCleanup(runner.close)
        return runner

    def test_a_quiet_host_gives_a_valid_run_and_the_monitors_records_are_kept(self):
        host = S.SimHost(origin_costs=COSTS)
        done = self.runner(host).run(self.plan(), lambda m: None)
        self.assertTrue(done["host"]["ok"], done["host"]["reasons"])
        self.assertEqual(sorted(done["host"]["rules"]), ["H1", "H3", "H4", "H5", "H6", "H7"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp.name, "monitors", "1"))),
                         ["chrony.txt", "journal.txt", "mpstat.txt", "pidstat.txt"])
        started = [c[2] for c in host.commands if c[0] == "popen" and c[2][:3] == ("taskset", "-c", "2")]
        self.assertEqual([a[3:] for a in started], [tuple(argv) for argv in HC.monitor_commands().values()],
                         "four monitors on the executor's CPU")
        self.assertEqual([a[3:6] == HC.REALTIME for a in started], [True, True, True, False],
                         "mpstat, pidstat and the chrony sampler at real-time priority, still pinned (D-099 2)")

    def test_load_of_another_process_makes_the_run_host_invalid_and_it_is_made_again_after_a_hold(self):
        app = [(1000, 1874, 60.0, "/home/artur/.claude/remote/srv/x/server --serve")]
        host = S.SimHost(origin_costs=COSTS, other_load=lambda t: app if t < S.BASE_EPOCH + 200 else [])
        said = []
        plan = self.plan()
        done = self.runner(host).run(plan, said.append)
        self.assertTrue(done["host"]["ok"])
        aside = plan.out + ".hostinvalid1"
        self.assertTrue(os.path.isdir(aside))
        with open(os.path.join(aside, "HOSTINVALID"), encoding="utf-8") as fh:
            self.assertIn("H6:", fh.read())
        self.assertFalse(K.read_json(os.path.join(aside, "DONE"))["host"]["ok"])
        hold = K.read_json(os.path.join(aside, "HOLD.json"))
        self.assertEqual((hold["held"], len(hold["pairs"])), (True, 2))
        self.assertGreaterEqual(host.sleeps.count(HC.HOLD_EVERY_S), 1)
        self.assertEqual(K.read_json(os.path.join(plan.out, "plan.json"))["seed"], K.read_json(os.path.join(aside, "plan.json"))["seed"])
        self.assertTrue(any("host-invalid" in m and "1 in a row, 1 in this packet" in m for m in said), said)
        self.assertFalse(os.path.exists(plan.out + ".failed1"), "it used none of the tries")

    def test_a_dead_monitor_voids_the_run(self):
        host = S.SimHost(origin_costs=COSTS, monitor_dies=("pidstat", 3.0))
        with self.assertRaises(HC.HostUnfit):
            self.runner(host).run(self.plan(), lambda m: None)
        reasons = K.read_json(os.path.join(self.tmp.name, "a", "C.hostinvalid1", "DONE"))["host"]["reasons"]
        self.assertIn("H7: the monitor pidstat had died", reasons)

    def test_three_in_a_row_pause_the_packet_and_the_same_command_resumes_it(self):
        app = [(1000, 1874, 60.0, "server")]
        host = S.SimHost(origin_costs=COSTS, other_load=lambda t: app)
        plan = self.plan()
        with self.assertRaisesRegex(HC.HostUnfit, r"paused: host unfit \(3 host-invalid runs in a row, 3 in this packet"):
            self.runner(host).run(plan, lambda m: None)
        self.assertEqual(sorted(n for n in os.listdir(os.path.dirname(plan.out)) if "hostinvalid" in n),
                         ["C.hostinvalid1", "C.hostinvalid2", "C.hostinvalid3"])
        self.assertFalse(os.path.exists(os.path.join(plan.out, "DONE")))
        done = self.runner(S.SimHost(origin_costs=COSTS), n=2).run(plan, lambda m: None)
        self.assertTrue(done["host"]["ok"])
        self.assertTrue(os.path.isdir(plan.out + ".hostinvalid3"), "every set-aside run stays")

    def test_the_fourth_host_invalid_run_of_a_packet_pauses_it(self):
        host = S.SimHost(origin_costs=COSTS)
        runner = self.runner(host)
        verdicts = iter([False, True, False, True, False, True, False])
        real = HC.HostCheck.judge

        def scripted(check, run_dir, speed, **kw):
            v = real(check, run_dir, speed, **kw)
            ok = next(verdicts)
            return v if ok else {**v, "ok": False, "reasons": ["H6: scripted"]}
        with mock.patch.object(HC.HostCheck, "judge", scripted), \
                mock.patch.object(HC, "speed_hold", return_value={"held": True, "pairs": [], "waited_s": 0.0}):
            for name in ("a", "b", "c"):
                self.assertTrue(runner.run(self.plan(name), lambda m: None)["host"]["ok"])
            with self.assertRaisesRegex(HC.HostUnfit, "1 host-invalid runs in a row, 4 in this packet"):
                runner.run(self.plan("d"), lambda m: None)

    def test_the_runner_exempts_its_staged_capacity_runs_from_h3_and_no_other(self):
        """D-099 1 (2026-11-14, pre-data; T-105 F1): with a pooled legit slip p99 of 291 ms (hg2_3's capacity run r3), the staged run
        of the capacity step is valid and a legit probe, as a reference's or a confirmation's, is host-invalid by H3."""
        with mock.patch.object(HC, "pooled_legit_slip_p99", return_value=0.291):
            staged = K.capacity_plan(TEMPLATE, C.PLACEHOLDER, 0, os.path.join(self.tmp.name, "capacity", "r1", "C"), [80.0, 160.0],
                                     10.0, settings={"readiness_timeout_s": 5.0})
            done = self.runner(S.SimHost(origin_costs=COSTS)).run(staged, lambda m: None)
            self.assertTrue(done["host"]["ok"], done["host"]["reasons"])
            self.assertEqual((done["host"]["rules"]["H3"]["exempt"], done["host"]["slip_p99_s"]), (HC.H3_EXEMPT, 0.291))
            plan = self.plan()
            with self.assertRaises(HC.HostUnfit):
                self.runner(S.SimHost(origin_costs=COSTS), n=2).run(plan, lambda m: None)
        reasons = K.read_json(os.path.join(plan.out + ".hostinvalid1", "DONE"))["host"]["reasons"]
        self.assertEqual(reasons, ["H3: pooled legit slip p99 291 ms above 100 ms"])

    def test_a_hold_that_finds_no_two_good_pairs_in_30_minutes_pauses(self):
        host = S.SimHost(origin_costs=COSTS, other_load=lambda t: [(1000, 1, 60.0, "server")] if t < S.BASE_EPOCH + 50 else [])
        host.origin_slow = lambda t: 0.2 if t > 40 else 0.0
        with self.assertRaisesRegex(HC.HostUnfit, "did not find two probe pairs in a row within 10% in 30 min"):
            self.runner(host).run(self.plan(), lambda m: None)

    def test_the_speed_hold(self):
        host = S.SimHost(origin_costs=COSTS)
        host.origin_slow = lambda t: 0.3 if t < 400 else 0.0
        r = HC.speed_hold(host, C.PLACEHOLDER, COSTS)
        self.assertTrue(r["held"])
        self.assertEqual([round(p["d"], 3) for p in r["pairs"]], [0.3, 0.3, 0.0, 0.0])
        r = HC.speed_hold(S.SimHost(origin_costs=COSTS), C.PLACEHOLDER, COSTS, lo=-0.05, hi=0.12, agree=0.05, max_min=45)
        self.assertEqual((r["held"], len(r["pairs"])), (True, 2))
        slow = S.SimHost(origin_costs=COSTS)
        slow.origin_slow = lambda t: 0.3
        r = HC.speed_hold(slow, C.PLACEHOLDER, COSTS)
        self.assertEqual((r["held"], len(r["pairs"])), (False, 7), "a pair at 0, 5, ... 30 min: at most 30 min")

    def test_the_command_line_exits_5_paused_host_unfit(self):
        out = os.path.join(self.tmp.name, "s")
        K.write_json(os.path.join(out, "origin", "origin.json"), {"route_costs_ms": COSTS, "estimator": K.origin_estimator()})
        host = S.SimHost(origin_costs=COSTS, other_load=lambda t: [(1000, 1, 60.0, "server")],
                         server=S.SyntheticServer(TEMPLATE, (30, 45, 30), capacity_cpu=1.1), tag="placeholder")
        err = io.StringIO()
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = K.main(["capacity", "--out", out, "--levels", "80,160", "--step-s", "10", "--repeats", "1"], host=host)
        self.assertEqual(code, K.EXIT_HOST_UNFIT)
        self.assertEqual(K.EXIT_HOST_UNFIT, 5)
        self.assertIn("HostUnfit: paused: host unfit", err.getvalue())
        self.assertEqual(host.alive(), [], "the monitors are stopped")

    def test_a_host_invalid_run_of_a_drift_check_never_enters_its_sample(self):
        cal = CF.frozen_v2()
        path = os.path.join(self.tmp.name, "v2.json")
        C.dump(cal, path)
        app = [(1000, 1874, 60.0, "server")]
        host = S.SimHost(server=S.SyntheticServer(cal, (30, 45, 30), capacity_cpu=1.1), tag=S.origin_tag(cal),
                         origin_costs=dict(cal["route_costs_ms"]), other_load=lambda t: app if t < S.BASE_EPOCH + 100 else [])
        check = HC.HostCheck(host, HC.SpeedBracket(path, cal["route_costs_ms"], "the record"), os.path.join(self.tmp.name, "m"), "2", 0.1)
        runner = K.Runner(host, check=check)
        self.addCleanup(runner.close)
        out = os.path.join(self.tmp.name, "drift")
        with mock.patch.object(K.H, "read_run", wraps=H.read_run) as read:
            result = K.drift_step(runner, cal, path, out, None, None, lambda m: None)
        self.assertTrue(os.path.isdir(os.path.join(out, "drift", "r1", "legit", "C.hostinvalid1")))
        self.assertEqual(len(read.call_args_list), 6)
        self.assertFalse([c for c in read.call_args_list if "hostinvalid" in c.args[0]])
        self.assertEqual(result["rounds"][0]["legit"]["run"], os.path.join("drift", "r1", "legit", "C"))

    def test_the_counting_constants(self):
        self.assertEqual((HC.INVALID_IN_A_ROW, HC.INVALID_IN_PACKET, HC.HOLD_EVERY_S, HC.HOLD_MAX_MIN), (3, 4, 300.0, 30.0))
        self.assertEqual((HC.MPSTAT_GAP_S, HC.OTHER_CPU_MEAN_PCT, HC.OTHER_CPU_PEAK_PCT, HC.CLOCK_OFFSET_S, HC.SOURCE_OFFSET_S),
                         (10.0, 5.0, 50.0, 0.1, 1.0))
        self.assertEqual(HC.REALTIME, ("chrt", "--fifo", "1"))
        self.assertEqual(HC.monitor_commands("/py")["pidstat"], ["chrt", "--fifo", "1", "stdbuf", "-oL", "pidstat", "-u", "-l", "10"])
        self.assertEqual(HC.monitor_commands("/py")["mpstat"], ["chrt", "--fifo", "1", "stdbuf", "-oL", "mpstat", "-P", "ALL", "5"])
        self.assertEqual(HC.monitor_commands("/py")["chrony"], ["chrt", "--fifo", "1", "/py", os.path.join(REPO, "bench", "hostcheck.py"),
                                                                "chrony-sampler", "--every", "30"])
        self.assertEqual(HC.monitor_commands("/py")["journal"][:3], ["stdbuf", "-oL", "journalctl"], "the follower is not real-time")


if __name__ == "__main__":
    unittest.main()
