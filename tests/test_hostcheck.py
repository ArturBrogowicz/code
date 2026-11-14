"""Host validity per run (bench/hostcheck.py; docs/RECALIBRATION_2026-11_DESIGN.md 5.1 and 7): the rules on fixtures and on the
simulated host, and the signature of every function that decides a run's host validity, none of which may read a Q, a p95 or a harm.
Nothing here needs root, a namespace or the real host."""
import contextlib
import inspect
import io
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
    return [HC.speed_deviation, HC.speed_verdict, HC.judge_speed]


class SignatureTest(unittest.TestCase):
    def test_nothing_that_judges_host_validity_takes_or_reads_a_q_a_p95_or_a_harm(self):
        for fn in judging_functions():
            with self.subTest(fn=fn.__name__):
                names = [n.lower() for n in inspect.signature(fn).parameters]
                self.assertFalse([n for n in names if n in FORBIDDEN or "p95" in n or "harm" in n], names)
                body = inspect.getsource(fn).split('"""')[-1]          # the code after the docstring
                for word in ('["Q"]', "'Q'", "p95", "harm", "run_metrics"):
                    self.assertNotIn(word, body, f"{fn.__name__} reads {word}")


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

if __name__ == "__main__":
    unittest.main()
