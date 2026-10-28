"""The calibration runner (bench/calibrate.py): the arithmetic of each step on hand-made numbers, the stop rules, the record it
freezes, and the steps run on the simulated host against a server of a known capacity, so that the capacity and the knee they
find can be compared with what the model says they are. Nothing here needs root or a namespace; what the real host will say is
for the steps of docs/HG1C_DESIGN.md 10."""
import contextlib
import copy
import io
import json
import math
import os
import shutil
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
import population as P
import scenario as SC
import sim_host as S

TEMPLATE = C.load(C.PLACEHOLDER)
SPEC_SEARCH = os.path.join(REPO, "bench", "scenarios", "costly_search_sub_threshold.json")


def metrics(q=100.0, p95=0.05, by_class=None):
    """The part of a run's metrics that the calibrator reads."""
    classes = by_class if by_class is not None else {"C0": {"Q": 100.0, "ok": 10, "n": 10}}
    return {"Q": q, "p95_s": p95, "by_class": classes}


class CapacityOfTest(unittest.TestCase):
    LEVELS = K.capacity_levels()

    def rows(self, healthy_to, saturated_from=None, repeats=3):
        """Q per repeat and level: 100 up to level `healthy_to` (an index), 90 after, 40 from `saturated_from`."""
        q = [100.0 if k <= healthy_to else 90.0 for k in range(10)]
        if saturated_from is not None:
            q = [40.0 if k >= saturated_from else x for k, x in enumerate(q)]
        return [list(q) for _ in range(repeats)]

    def test_the_levels_are_fifty_times_one_point_three_to_the_k(self):
        self.assertEqual(len(self.LEVELS), 10)
        self.assertEqual((self.LEVELS[0], self.LEVELS[-1]), (50.0, 530.2))
        for a, b in zip(self.LEVELS, self.LEVELS[1:], strict=False):
            self.assertAlmostEqual(b / a, 1.3, delta=0.01)

    def test_c_slo_is_the_last_level_before_the_first_unhealthy_one_and_c_sat_the_lowest_saturated(self):
        r = K.capacity_of(self.LEVELS, self.rows(4, saturated_from=8))
        self.assertEqual((r["c_slo_rps"], r["c_sat_rps"], r["first_unhealthy_rps"]), (self.LEVELS[4], self.LEVELS[8], self.LEVELS[5]))

    def test_one_repeat_below_ninety_nine_is_enough_to_end_the_healthy_range(self):
        q = self.rows(9)
        q[1][3] = 98.99
        self.assertEqual(K.capacity_of(self.LEVELS, [row[:] for row in q] if False else self.with_saturation(q))["c_slo_rps"],
                         self.LEVELS[2])

    def with_saturation(self, q):
        return [[40.0 if k == 9 else x for k, x in enumerate(row)] for row in q]

    def test_ninety_nine_exactly_is_healthy(self):
        q = self.with_saturation(self.rows(9))
        q[0][3] = 99.0
        self.assertEqual(K.capacity_of(self.LEVELS, q)["c_slo_rps"], self.LEVELS[8])

    def test_saturation_needs_two_repeats_and_fifty_exactly_is_not_below(self):
        q = self.rows(4, saturated_from=9)
        q[0][8] = 30.0                                   # one repeat: not enough
        q[1][7] = 50.0                                   # not below fifty
        q[2][7] = 49.9
        self.assertEqual(K.capacity_of(self.LEVELS, q)["c_sat_rps"], self.LEVELS[9])
        q[1][8] = 49.9                                   # now two at level 8
        self.assertEqual(K.capacity_of(self.LEVELS, q)["c_sat_rps"], self.LEVELS[8])

    def test_a_level_that_is_healthy_again_after_the_first_failure_changes_nothing(self):
        q = self.rows(4, saturated_from=8)
        for row in q:
            row[6] = 100.0
        self.assertEqual(K.capacity_of(self.LEVELS, q)["c_slo_rps"], self.LEVELS[4])

    def test_c_sat_exceeds_c_slo_whatever_the_rows(self):
        for healthy_to in range(9):
            r = K.capacity_of(self.LEVELS, self.rows(healthy_to, saturated_from=healthy_to + 1))
            self.assertGreater(r["c_sat_rps"], r["c_slo_rps"])
            C.validate(K.draft_record(TEMPLATE, None, r))

    def test_a_first_level_that_is_already_unhealthy_stops_the_calibration(self):
        q = self.rows(-1, saturated_from=5)
        with self.assertRaisesRegex(K.CalibrationStop, "first level, 50 req/s, is already below 99 %"):
            K.capacity_of(self.LEVELS, q)

    def test_a_server_that_never_fails_in_the_range_stops_it_and_says_to_extend_the_range(self):
        with self.assertRaisesRegex(K.CalibrationStop, "capacity is above the range of the probe"):
            K.capacity_of(self.LEVELS, self.rows(9))

    def test_a_server_that_is_never_saturated_stops_it(self):
        with self.assertRaisesRegex(K.CalibrationStop, "no level up to 530.2 req/s brings Q below 50 %"):
            K.capacity_of(self.LEVELS, self.rows(4))

    def test_the_windows_are_the_middle_of_each_step(self):
        self.assertEqual(K.step_windows(3), [(5.0, 17.0), (25.0, 37.0), (45.0, 57.0)])
        self.assertEqual(K.step_windows(2, 10.0, (1.0, 8.0)), [(1.0, 8.0), (11.0, 18.0)])


class StackCostTest(unittest.TestCase):
    """The server CPU per request through the whole stack, from the telemetry of a staged run."""

    @staticmethod
    def steps(*counts):
        return [{"by_profile": {"perfect": {"n": n // 2}, "broadband": {"n": n - n // 2}}} for n in counts]

    @staticmethod
    def telemetry(rows):
        return [{"t_rel": str(t), "origin_cpu_pct": str(o), "nginx_cpu_pct": str(n)} for t, o, n in rows]

    def test_the_cpu_seconds_of_the_window_over_its_requests(self):
        # step 0 is read over 1.8 + 5 .. 1.8 + 17 = 6.8 .. 18.8 s of the telemetry: 12 s; origin at 50 % = 6 CPU-s, nginx at 10 % = 1.2
        rows = self.telemetry([(t, 50.0, 10.0) for t in range(20)])
        out = K.stack_cost(rows, self.steps(2400), 20.0, 1.8)
        self.assertEqual(out[0]["requests"], 2400)
        self.assertAlmostEqual(out[0]["origin_ms_per_request"], 6.0 * 1000 / 2400)
        self.assertAlmostEqual(out[0]["nginx_ms_per_request"], 1.2 * 1000 / 2400)

    def test_a_step_is_read_over_its_own_window(self):
        rows = self.telemetry([(t, 10.0 if t < 22 else 80.0, 0.0) for t in range(45)])
        out = K.stack_cost(rows, self.steps(1000, 1000), 20.0, 1.8)
        self.assertLess(out[0]["origin_ms_per_request"], out[1]["origin_ms_per_request"] / 4)

    def test_the_telemetry_counts_from_the_launch_and_the_axis_begins_the_start_up_later(self):
        rows = self.telemetry([(t, 10.0 if t < 7 else 90.0, 0.0) for t in range(20)])
        out = K.stack_cost(rows, self.steps(1200), 20.0, 1.8)             # read over 6.8 .. 18.8 s: only the busy rows
        self.assertAlmostEqual(out[0]["origin_ms_per_request"], 0.9 * 12 * 1000 / 1200)

    def test_a_step_with_no_readings_or_no_requests_is_none(self):
        rows = self.telemetry([(t, 10.0, 10.0) for t in range(20)])
        self.assertEqual(K.stack_cost(rows, self.steps(0), 20.0, 1.8), [None])
        self.assertEqual(K.stack_cost([], self.steps(100), 20.0, 1.8), [None])
        rows[8]["origin_cpu_pct"] = ""
        self.assertEqual(K.stack_cost(rows, self.steps(100), 20.0, 1.8)[0]["requests"], 100, "unreadable cells are left out")

    def test_the_repeats_are_combined_by_the_median_per_step(self):
        a = [{"requests": 10, "origin_ms_per_request": 1.0, "nginx_ms_per_request": 0.1}, None]
        b = [{"requests": 10, "origin_ms_per_request": 6.0, "nginx_ms_per_request": 0.3}, None]
        c = [{"requests": 10, "origin_ms_per_request": 2.0, "nginx_ms_per_request": 0.2}, None]
        out = K.combine_stack_cost([a, b, c])
        self.assertEqual(out[0]["origin_ms_per_request"], 2.0)
        self.assertIsNone(out[1])

    def test_the_capacity_step_records_it_next_to_the_capacity(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        host = S.SimHost(server=S.SyntheticServer(TEMPLATE, (30, 45, 30), capacity_cpu=1.1))
        result = K.capacity_step(K.Runner(host), TEMPLATE, C.PLACEHOLDER, tmp.name, [80.0, 160.0, 240.0, 320.0, 400.0, 480.0], 10.0, 2,
                                 lambda m: None)
        self.assertEqual(len(result["stack_cost"]), 6)
        first = result["stack_cost"][0]
        self.assertGreater(first["origin_ms_per_request"], 0.0)
        self.assertEqual(first["requests"], K.read_json(os.path.join(tmp.name, "capacity", "capacity.json"))["stack_cost"][0]["requests"])

    def test_the_capacity_step_reads_each_repeat_from_the_start_up_delay_of_its_plan(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        host = S.SimHost(server=S.SyntheticServer(TEMPLATE, (30, 45, 30), capacity_cpu=1.1))
        real, delays = K.stack_cost, []

        def spy(rows, steps, step_s, delay):
            delays.append(delay)
            return real(rows, steps, step_s, delay)
        with mock.patch.object(K, "stack_cost", spy):
            K.capacity_step(K.Runner(host), TEMPLATE, C.PLACEHOLDER, tmp.name, [80.0, 160.0, 240.0, 320.0, 400.0, 480.0], 10.0, 2,
                            lambda m: None)
        self.assertEqual(delays, [X.SETTINGS["startup_delay_legit_s"]] * 2)
        with mock.patch.object(K, "stack_cost", spy):
            K.capacity_step(K.Runner(host, settings={"startup_delay_legit_s": 3.3}), TEMPLATE, C.PLACEHOLDER, os.path.join(tmp.name, "again"),
                            [80.0, 160.0, 240.0, 320.0, 400.0, 480.0], 10.0, 2, lambda m: None)
        self.assertEqual(delays[2:], [3.3, 3.3], "the plan's own setting, which a smoke test can override")


class StagedLimitsTest(unittest.TestCase):
    """The probe reads each step over 5 to 17 s of its 20 s, so a group that begins up to 3 s from its plan, or spread over 3 s, is read
    all the same: a staged plan is judged at that tolerance and not at a block's 0.5 s (docs/HG1C_DESIGN.md 8 and departure 24)."""

    OUT = "/var/tmp/ddos_campaigns/example/capacity/r1/C"

    def test_the_limits_are_the_skew_the_window_leaves_on_either_side(self):
        self.assertEqual(K.staged_limits(20.0), {"t0_spread_limit_s": 3.0, "t0_range_limit_s": 3.0, "group_start_limit_s": 3.0})
        self.assertEqual(K.staged_limits(30.0), {"t0_spread_limit_s": 5.0, "t0_range_limit_s": 5.0, "group_start_limit_s": 5.0})
        self.assertEqual(K.staged_limits(18.0)["group_start_limit_s"], 1.0)

    def test_a_step_the_window_does_not_fit_in_is_judged_as_a_block(self):
        for step in (17.0, 17.4, 17.5, 10.0):
            with self.subTest(step_s=step):
                self.assertEqual(K.staged_limits(step), {})

    def test_the_plan_of_a_repeat_carries_them_and_the_caller_can_override_them(self):
        plan = K.capacity_plan(TEMPLATE, C.PLACEHOLDER, 0, self.OUT, [50.0, 65.0], 20.0)
        for key in ("t0_spread_limit_s", "t0_range_limit_s", "group_start_limit_s"):
            self.assertEqual(plan.settings[key], 3.0, key)
        for key in ("attack_start_limit_s", "straggler_tail_s", "straggler_share"):
            self.assertEqual(plan.settings[key], X.SETTINGS[key], f"{key} is not touched")
        over = K.capacity_plan(TEMPLATE, C.PLACEHOLDER, 0, self.OUT, [50.0, 65.0], 20.0, settings={"group_start_limit_s": 0.7})
        self.assertEqual((over.settings["group_start_limit_s"], over.settings["t0_spread_limit_s"]), (0.7, 3.0))
        short = K.capacity_plan(TEMPLATE, C.PLACEHOLDER, 0, self.OUT, [50.0, 65.0], 10.0)
        self.assertEqual(short.settings["t0_spread_limit_s"], X.SETTINGS["t0_spread_limit_s"])

    @staticmethod
    def skewed_host(**kw):
        """Groups that begin late and spread, as the first staged runs on the VM did (2026-10-28): from the second step on 0.5 s late,
        and the streams of a step spread over 1.6 s, so that no 0.5 s pack of them is a majority."""
        return S.SimHost(startup_s=lambda sid, index, kind: S.LEGIT_STARTUP_S + (0.0 if sid.startswith("S00-") else 0.5)
                         + 1.6 * ((index % 10) / 9), **kw)

    def test_such_a_run_is_sound_at_the_probes_limits_and_not_at_a_blocks(self):
        levels = [50.0, 100.0, 150.0]
        with tempfile.TemporaryDirectory() as tmp:
            probe = K.capacity_plan(TEMPLATE, C.PLACEHOLDER, 0, os.path.join(tmp, "probe", "C"), levels, 20.0,
                                    settings={"readiness_timeout_s": 5.0})
            result = X.execute(probe, self.skewed_host())
            self.assertTrue(result.ok, result.reasons)
            ctl = SC.load(K.spec_path(K.CONTROL_SPEC))
            pop = P.staged(ctl.seed_namespace, K.SEEDS["capacity"], levels, 20.0, ctl.benign_identities, ctl.per_profile)
            block = X.plan_population(pop, "capacity", "C", K.SEEDS["capacity"], os.path.join(tmp, "block", "C"), TEMPLATE,
                                      C.PLACEHOLDER, pop.timeline, settings={"readiness_timeout_s": 5.0})
            result = X.execute(block, self.skewed_host())
            self.assertFalse(result.ok)
            text = "; ".join(result.reasons)
            self.assertIn("outside the pack", text)
            self.assertIn("from their start (limit 0.5 s)", text)

    def test_the_capacity_step_completes_on_a_host_that_starts_its_groups_like_that(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = self.skewed_host(server=S.SyntheticServer(TEMPLATE, (30, 45, 30), capacity_cpu=1.1))
            result = K.capacity_step(K.Runner(host), TEMPLATE, C.PLACEHOLDER, tmp, [80.0, 160.0, 240.0, 320.0, 400.0, 480.0], 20.0, 2,
                                     lambda m: None)
            self.assertIn("c_slo_rps", result)
            self.assertFalse(any(name.endswith(".failed1") for name in os.listdir(os.path.join(tmp, "capacity", "r1"))),
                             "no run had to be made again")


class OriginTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def sessions(self, factors):
        return [{"C0": 0.05 * f, "C3": 30.0 * f} for f in factors]

    def test_the_spread_is_per_route_against_the_median(self):
        spread = K.origin_spread(self.sessions([0.95, 1.0, 1.05]))
        self.assertAlmostEqual(spread["C3"], 0.1)
        self.assertAlmostEqual(spread["C0"], 0.1)

    def test_the_cost_is_the_median_of_the_medians(self):
        self.assertEqual(K.combine_origin([{"C0": 1.0}, {"C0": 5.0}, {"C0": 2.0}]), {"C0": 2.0})

    def step(self, noise, **faults):
        host = S.SimHost(origin_costs=dict(TEMPLATE["route_costs_ms"]), origin_noise=noise, faults=faults)
        say = []
        result = K.origin_step(host, TEMPLATE, C.PLACEHOLDER, self.tmp.name, say.append)
        return host, result, say

    def test_three_sessions_each_a_process_on_cpu_zero_and_their_median_are_the_step(self):
        host, result, _ = self.step((0.0, 0.01, -0.01))
        commands = [c for c in host.commands if "origin-session" in c[2]]
        self.assertEqual(len(commands), 3)
        for _, _, argv in commands:
            self.assertEqual(argv[:3], ("taskset", "-c", "0"))
            self.assertIn("--calibration", argv)
            self.assertEqual(argv[argv.index("--repeats") + 1], "21")
        self.assertEqual(result["route_costs_ms"], TEMPLATE["route_costs_ms"])
        self.assertEqual(len(result["rounds"]), 1)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "origin", "origin.json")))

    def test_sessions_that_disagree_by_more_than_ten_percent_are_made_again_and_only_the_second_round_counts(self):
        host, result, say = self.step((-0.1, 0.05, 0.2, 0.0, 0.01, -0.01))
        self.assertEqual(len(result["rounds"]), 2)
        self.assertEqual(sum("origin-session" in c[2] for c in host.commands), 6)
        self.assertEqual(result["route_costs_ms"], TEMPLATE["route_costs_ms"], "the second round's median")
        self.assertTrue(any("round 1" in m for m in say) and any("round 2" in m for m in say))

    def test_a_host_that_disagrees_with_itself_twice_cannot_be_calibrated(self):
        with self.assertRaisesRegex(K.CalibrationStop, "not stable enough"):
            self.step((-0.1, 0.0, 0.2))

    def test_eight_percent_is_within_the_limit_and_twelve_is_not(self):
        _, result, _ = self.step((-0.04, 0.0, 0.04))
        self.assertEqual(len(result["rounds"]), 1)
        _, result, _ = self.step((-0.06, 0.0, 0.06, -0.04, 0.0, 0.04))
        self.assertEqual(len(result["rounds"]), 2)

    def test_the_spread_and_the_median_are_of_the_sessions_not_of_the_largest(self):
        self.assertAlmostEqual(K.origin_spread(self.sessions([1.0, 1.0, 1.3]))["C3"], 0.3)
        self.assertEqual(K.combine_origin(self.sessions([1.0, 1.0, 1.3]))["C3"], 30.0)

    def test_a_session_that_gives_nothing_readable_stops_it(self):
        with self.assertRaisesRegex(K.CalibrationStop, "gave nothing readable"):
            self.step((0.0,), origin_session_fails=None)

    def test_one_real_session_times_every_route(self):
        costs = K.origin_session(TEMPLATE, repeats=3)
        self.assertEqual(sorted(costs), ["C0", "C1", "C2", "C3", "C5"])
        self.assertTrue(all(v > 0 for v in costs.values()))
        self.assertGreater(costs["C5"], costs["C0"])


class HarmTest(unittest.TestCase):
    CONTROLS = (metrics(100.0, 0.05), metrics(99.0, 0.07))

    def test_the_figures_are_normalised_by_the_floors(self):
        h, parts = K.harm(self.CONTROLS, metrics(80.0, 0.06), 10.0, 1.0)
        self.assertAlmostEqual(parts["dQ"], (99.5 - 80.0) / 10.0)
        self.assertAlmostEqual(parts["dL"], math.log2(0.06 / 0.06))
        self.assertEqual(h, parts["dQ"])

    def test_latency_alone_can_be_the_harm(self):
        h, parts = K.harm(self.CONTROLS, metrics(99.5, 0.24), 10.0, 1.0)
        self.assertAlmostEqual(parts["dL"], 2.0)
        self.assertAlmostEqual(h, 2.0)

    def test_either_figure_reaching_its_floor_is_harm_one(self):
        self.assertAlmostEqual(K.harm(self.CONTROLS, metrics(89.5, 0.06), 10.0, 1.0)[0], 1.0)
        self.assertAlmostEqual(K.harm(self.CONTROLS, metrics(99.5, 0.12), 10.0, 1.0)[0], 1.0)

    def test_the_controls_count_by_their_mean_not_their_middle(self):
        controls = [metrics(100.0, 0.05), metrics(100.0, 0.05), metrics(94.0, 0.05)]
        self.assertAlmostEqual(K.harm(controls, metrics(90.0, 0.05), 10.0, 1.0)[1]["dQ"], 0.8)

    def test_the_latency_floor_is_the_gates(self):
        h, parts = K.harm(self.CONTROLS, metrics(99.5, 0.24), 10.0, 2.0)
        self.assertAlmostEqual(parts["dL"], 1.0)
        self.assertAlmostEqual(h, 1.0)

    def test_a_run_better_than_the_controls_has_negative_harm(self):
        self.assertLess(K.harm(self.CONTROLS, metrics(100.0, 0.03), 10.0, 1.0)[0], 0)

    def test_a_figure_that_cannot_be_taken_is_left_out(self):
        h, parts = K.harm(self.CONTROLS, metrics(50.0, None), 10.0, 1.0)
        self.assertEqual(set(parts), {"dQ"})
        self.assertAlmostEqual(h, 4.95)
        self.assertEqual(K.harm(self.CONTROLS, metrics(None, None), 10.0, 1.0), (None, {}))

    def test_the_floors_are_the_gates(self):
        h, _ = K.harm(self.CONTROLS, metrics(80.0, 0.06), 20.0, 1.0)
        self.assertAlmostEqual(h, 0.975)


def loose_cal(control_q_min):
    """A frozen record whose gate accepts controls down to `control_q_min`, so that they can differ by more than a point."""
    cal = copy.deepcopy(CF.placeholder())
    cal["gate"]["control_q_min"] = control_q_min
    return CF.frozen(cal)


class SessionTest(unittest.TestCase):
    CAL = CF.frozen()
    LOOSE = loose_cal(90.0)

    def healthy(self, q=100.0):
        return {"Q": q, "p95_s": 0.05, "by_class": {"C0": {"Q": 100.0, "ok": 10, "n": 10}, "C3": {"Q": 99.0, "ok": 99, "n": 100}}}

    def test_healthy_controls_within_two_points_make_a_valid_session(self):
        self.assertEqual(K.session_problems([self.healthy(100.0), self.healthy(99.5), self.healthy(99.1)], self.CAL), [])

    def test_two_points_apart_is_valid_and_more_is_not(self):
        self.assertEqual(K.session_problems([self.healthy(100.0), self.healthy(98.0)], self.LOOSE), [])
        reasons = K.session_problems([self.healthy(100.0), self.healthy(97.5)], self.LOOSE)
        self.assertEqual(len(reasons), 1)
        self.assertIn("differ by 2.5 pp, over 2", reasons[0])
        self.assertEqual(K.session_problems([self.healthy(100.0), self.healthy(99.0)], self.CAL), [])

    def test_an_unhealthy_control_is_named(self):
        bad = {**self.healthy(), "Q": 90.0}
        reasons = K.session_problems([self.healthy(), bad, self.healthy()], self.CAL)
        self.assertTrue(any(r.startswith("control 2: Q(C) is 90.00 %") for r in reasons), reasons)

    def test_a_starved_class_makes_a_control_unhealthy(self):
        starved = self.healthy()
        starved["by_class"] = {"C3": {"Q": 60.0, "ok": 60, "n": 100}}
        reasons = K.session_problems([self.healthy(), starved], self.CAL)
        self.assertTrue(any("class C3" in r for r in reasons), reasons)

    def test_a_session_needs_two_controls(self):
        self.assertEqual(K.session_problems([self.healthy()], self.CAL), ["fewer than two controls: the session has no reference"])
        self.assertEqual(len(K.session_problems([], self.CAL)), 1)


class LadderTest(unittest.TestCase):
    CAL = CF.frozen()
    LOOSE = loose_cal(90.0)
    SCN = SC.load(SPEC_SEARCH)

    def test_a_session_of_seven_levels_is_fourteen_attack_runs_and_four_controls(self):
        seq = K.ladder_sequence([0.125, 0.25, 0.5, 1, 2, 4, 8], "x")
        self.assertEqual(sum(r[0] == "U" for r in seq), 14)
        self.assertEqual(sum(r[0] == "C" for r in seq), 4)
        self.assertEqual(len(seq), 18, "the design's 18 runs a family")

    def test_every_level_is_made_twice_and_a_control_follows_every_fourth_attack_run_and_the_last(self):
        seq = K.ladder_sequence([1, 2, 4, 8, 16], "y")
        attacks = [r for r in seq if r[0] == "U"]
        self.assertEqual(sorted((r[1], r[2]) for r in attacks), sorted((lv, rep) for lv in (1, 2, 4, 8, 16) for rep in (1, 2)))
        kinds = "".join(r[0] for r in seq)
        self.assertEqual(kinds, "UUUUCUUUUCUUC")
        self.assertEqual([r[2] for r in seq if r[0] == "C"], [1, 2, 3], "the controls are numbered")

    def test_the_order_is_drawn_from_the_seed_and_can_be_drawn_again(self):
        levels = [0.125, 0.25, 0.5, 1, 2, 4, 8]
        self.assertEqual(K.ladder_sequence(levels, "a"), K.ladder_sequence(levels, "a"))
        self.assertNotEqual(K.ladder_sequence(levels, "a"), K.ladder_sequence(levels, "b"))
        self.assertNotEqual([r for r in K.ladder_sequence(levels, "a") if r[0] == "U"],
                            sorted((r for r in K.ladder_sequence(levels, "a") if r[0] == "U"), key=lambda r: (r[1], r[2])))

    def entries(self, harms, controls=(100.0, 99.5, 99.0, 100.0), p95=0.05):
        rows = [{"kind": "C", "level": None, "repeat": i + 1, "metrics": metrics(q, p95, {"C0": {"Q": 100.0, "ok": 1, "n": 1}})}
                for i, q in enumerate(controls)]
        mean_q = sum(controls) / len(controls)
        for level, repeats in harms.items():
            for rep, h in enumerate(repeats, 1):
                rows.append({"kind": "U", "level": level, "repeat": rep, "metrics": metrics(mean_q - 10.0 * h, p95)})
        return rows

    def test_the_knee_is_the_lowest_level_whose_repeats_all_reach_the_floor(self):
        r = K.analyse_ladder(self.entries({0.5: [0.1, 0.2], 1: [0.9, 1.4], 2: [1.5, 2.0], 4: [3.0, 4.0]}), self.CAL)
        self.assertTrue(r["valid"])
        self.assertEqual(r["knee"]["level"], 2)
        self.assertEqual(r["knee"]["passing"], [2, 4])
        self.assertTrue(r["knee"]["monotone"])

    def test_a_level_where_one_repeat_falls_short_is_not_the_knee(self):
        r = K.analyse_ladder(self.entries({1: [0.9, 1.4], 2: [1.5, 2.0], 4: [3.0, 4.0]}), self.CAL)
        self.assertEqual(r["knee"]["level"], 2)
        r = K.analyse_ladder(self.entries({1: [1.0, 1.4], 2: [0.99, 2.0], 4: [3.0, 4.0]}), self.CAL)
        self.assertEqual(r["knee"]["level"], 1, "exactly the floor counts")

    def test_nothing_reaching_the_floor_is_a_finding_and_not_a_reason_to_tune(self):
        r = K.analyse_ladder(self.entries({1: [0.1, 0.1], 2: [0.2, 0.3], 4: [0.5, 0.6]}), self.CAL)
        self.assertIsNone(r["knee"]["level"])
        self.assertEqual(r["knee"]["why"], C.CANNOT_HARM)
        self.assertTrue(r["valid"])

    def test_the_harm_is_taken_against_the_sessions_controls_together(self):
        r = K.analyse_ladder(self.entries({2: [1.0, 1.0]}, controls=(100.0, 99.0)), self.CAL)
        self.assertAlmostEqual(r["levels"][0]["repeats"][0]["harm"], 1.0)
        self.assertEqual(r["controls"], [{"Q": 100.0, "p95_s": 0.05}, {"Q": 99.0, "p95_s": 0.05}])

    def test_a_session_whose_controls_disagree_is_not_valid_and_says_so(self):
        r = K.analyse_ladder(self.entries({2: [2.0, 2.0]}, controls=(100.0, 100.0, 96.0, 100.0)), self.LOOSE)
        self.assertFalse(r["valid"])
        self.assertTrue(any("differ by 4.0 pp" in x for x in r["reasons"]))

    def test_a_run_with_no_figure_cannot_make_a_level_pass(self):
        rows = self.entries({2: [2.0]})
        rows.append({"kind": "U", "level": 2, "repeat": 2, "metrics": metrics(None, None)})
        self.assertIsNone(K.analyse_ladder(rows, self.CAL)["knee"]["level"])

    def test_a_ladder_the_generator_can_carry_is_run_whole(self):
        usable, left = K.runnable_levels(self.SCN, self.CAL)
        self.assertEqual((usable, left), ([0.125, 0.25, 0.5, 1, 2, 4, 8], {}))

    def test_a_ladder_ends_below_the_first_level_the_generator_cannot_carry(self):
        flood = SC.load(os.path.join(REPO, "bench", "scenarios", "cheap_static_flood.json"))
        usable, left = K.runnable_levels(flood, self.CAL)
        self.assertEqual(usable, [0.125, 0.25, 0.5, 1, 2, 4])
        self.assertEqual(list(left), [8])
        self.assertIn("in flight", left[8][0])
        self.assertEqual(K.level_flags(flood, self.CAL, 4), [])

    def flags_for(self, **attack):
        kinds = {"share": 0.1, "max_stream_rate": 100.0, "inflight": 100.0, "cap": 5000}
        kinds.update(attack)
        plan = {"generator": {"cpu_share_limit": 0.7, "ceiling_rps": 5000, "kinds": {"attack": kinds}}}
        with mock.patch.object(K.SC, "plan", return_value=plan):
            return K.level_flags(self.SCN, self.CAL, 1)

    def test_each_limit_of_the_generator_flags_a_level_and_at_the_limit_only_the_cap_does(self):
        self.assertEqual(self.flags_for(), [])
        self.assertEqual(self.flags_for(share=0.7), [], "the share may be at its limit")
        self.assertIn("needs 71% of its CPUs", self.flags_for(share=0.71)[0])
        self.assertEqual(self.flags_for(max_stream_rate=5000), [])
        self.assertIn("plans 5001 req/s", self.flags_for(max_stream_rate=5001)[0])
        self.assertEqual(self.flags_for(inflight=4999), [])
        self.assertIn("5000 requests could be in flight", self.flags_for(inflight=5000)[0])
        self.assertEqual(len(self.flags_for(share=0.9, max_stream_rate=6000, inflight=6000)), 3)

    def test_nothing_above_a_flagged_level_is_tried_even_if_it_would_pass(self):
        with mock.patch.object(K, "level_flags", lambda scn, cal, level: ["too much"] if level == 1 else []):
            usable, left = K.runnable_levels(self.SCN, self.CAL)
        self.assertEqual(usable, [0.125, 0.25, 0.5])
        self.assertEqual(sorted(left), [1, 2, 4, 8])

    def test_the_scenario_of_a_level_has_that_level(self):
        self.assertEqual(K.ladder_scenario("costly_export_flood", 4).intensity["level"], 4)
        self.assertEqual(K.ladder_scenario("costly_export_flood").family, "costly_export_flood")

    def test_every_family_has_a_spec_that_names_it(self):
        for family, spec in K.FAMILY_SPECS.items():
            self.assertEqual(SC.load(K.spec_path(spec)).family, family)
        self.assertEqual(set(K.FAMILY_SPECS), set(P.ATTACK_FAMILIES))


class ReferenceTest(unittest.TestCase):
    def test_the_reference_is_the_median_of_the_probes_and_one_run_a_family(self):
        legit = [{"Q": 99.0, "p95_s": 0.05}, {"Q": 100.0, "p95_s": 0.09}, {"Q": 100.0, "p95_s": 0.04}]
        ref = K.reference_of(92.8, legit, {"b": {"level": 2.0, "Q": 70.0, "p95_s": 0.2}, "a": {"level": 4.0, "Q": 40.0, "p95_s": 0.4}})
        self.assertEqual(ref, {"rho_rps": 92.8, "q_pct": 100.0, "p95_s": 0.05,
                               "attack": {"a": {"level": 4.0, "q_pct": 40.0, "p95_s": 0.4},
                                          "b": {"level": 2.0, "q_pct": 70.0, "p95_s": 0.2}}})

    def test_the_reference_is_a_valid_drift_reference(self):
        ref = K.reference_of(90.0, [{"Q": 100.0, "p95_s": 0.05}], {"costly_search_flood": {"level": 2.0, "Q": 70.0, "p95_s": 0.2}})
        C.freeze(copy.deepcopy(TEMPLATE), host=CF.SAMPLE_HOST, drift_reference=ref)

    def frozen(self):
        cal = copy.deepcopy(TEMPLATE)
        ref = {"rho_rps": 90.0, "q_pct": 100.0, "p95_s": 0.050,
               "attack": {"costly_search_flood": {"level": 2.0, "q_pct": 70.0, "p95_s": 0.2}}}
        return C.freeze(cal, host=CF.SAMPLE_HOST, drift_reference=ref)

    def test_a_probe_within_two_points_and_a_quarter_is_not_drift(self):
        cal = self.frozen()
        r = K.drift_check(cal, {"Q": 98.0, "p95_s": 0.0625}, {"costly_search_flood": {"Q": 72.0, "p95_s": 0.25}})
        self.assertEqual(r, {"ok": True, "reasons": []})

    def test_beyond_them_it_is_and_the_reason_names_the_probe(self):
        cal = self.frozen()
        r = K.drift_check(cal, {"Q": 97.9, "p95_s": 0.0626}, {"costly_search_flood": {"Q": 72.1, "p95_s": 0.2501}})
        self.assertFalse(r["ok"])
        self.assertEqual(len(r["reasons"]), 4)
        self.assertTrue(r["reasons"][0].startswith("legit probe: Q 97.9"))
        self.assertTrue(any(x.startswith("costly_search_flood: p95") for x in r["reasons"]))


ORIGIN = {"route_costs_ms": {"C0": 0.06, "C1": 3.3, "C2": 2.2, "C3": 31.0, "C5": 155.0}, "template_sha256": TEMPLATE["sha256"]}
CAPACITY = {"c_slo_rps": 150.0, "c_sat_rps": 300.0, "template_sha256": TEMPLATE["sha256"]}
ENV = {"facts": {"uname": "Linux testbed 7.0.0-38-generic x86_64", "cpus": 8, "mem_mib": 9426, "python": "3.14.4",
                 "nginx": "nginx version: nginx/1.28.3", "gunicorn": "gunicorn (version 26.2.0)"},
       "provenance": {"files": {"origin.py": "a" * 64, "loadgen.py": "b" * 64}, "nginx_source_sha256": "c" * 64},
       "stack": {"origin": {"nofile_soft_hard": [[524288, 524288]]}}}


class RecordTest(unittest.TestCase):

    def test_the_draft_is_the_template_with_what_is_measured_and_is_still_a_placeholder(self):
        draft = K.draft_record(TEMPLATE, ORIGIN, CAPACITY, {"costly_search_flood": 2.0})
        self.assertEqual(draft["status"], "placeholder")
        self.assertEqual(draft["route_costs_ms"], ORIGIN["route_costs_ms"])
        self.assertEqual(draft["capacity"], {"c_slo_rps": 150.0, "c_sat_rps": 300.0})
        self.assertEqual(draft["knees"], {"costly_search_flood": 2.0})
        for key in ("mix", "slo_ms", "gate", "validity", "knobs", "judged_profiles"):
            self.assertEqual(draft[key], TEMPLATE[key], key)
        self.assertEqual(C.rho_rps(draft), 75.0)
        self.assertNotIn("sha256", draft)
        C.validate(draft)

    def test_a_draft_of_a_frozen_template_is_a_placeholder_again_without_its_hash(self):
        frozen = CF.frozen()
        draft = K.draft_record(frozen, None, None, None)
        self.assertEqual(draft["status"], "placeholder")
        self.assertNotIn("sha256", draft)
        self.assertEqual(frozen["status"], "frozen")
        C.validate(draft)

    def test_nothing_is_changed_in_the_template(self):
        before = copy.deepcopy(TEMPLATE)
        K.draft_record(TEMPLATE, ORIGIN, CAPACITY, {"a": 1.0})
        self.assertEqual(TEMPLATE, before)

    def test_what_a_step_ran_under_is_the_template_and_the_measured_costs_and_capacity(self):
        under = K.under_of(TEMPLATE, ORIGIN, CAPACITY)
        self.assertEqual(under["template_sha256"], TEMPLATE["sha256"])
        self.assertEqual(under["capacity"], {"c_slo_rps": 150.0, "c_sat_rps": 300.0})
        other = K.under_of(TEMPLATE, {"route_costs_ms": {**ORIGIN["route_costs_ms"], "C3": 32.0}}, CAPACITY)
        self.assertNotEqual(under, other)

    def test_the_host_is_what_the_environment_of_a_run_recorded(self):
        host = K.host_of(ENV)
        self.assertEqual(host["gunicorn"], {"version": "26.2.0", "workers": 2, "threads": 8, "nofile": 524288})
        self.assertEqual(host["nginx"], {"version": "1.28.3", "conf_sha256": "c" * 64})
        self.assertEqual((host["origin_sha256"], host["loadgen_sha256"], host["origin_seed"]), ("a" * 64, "b" * 64, 1))
        self.assertEqual(host["pins"], P.PIN_PLAN)
        C.freeze(copy.deepcopy(TEMPLATE), host=host, drift_reference=CF.SAMPLE_DRIFT)

    def test_a_limit_that_is_not_a_number_or_a_missing_stack_record_stops_it(self):
        env = copy.deepcopy(ENV)
        env["stack"]["origin"]["nofile_soft_hard"] = [["unlimited", "unlimited"]]
        with self.assertRaisesRegex(K.CalibrationStop, "open-file limit"):
            K.host_of(env)
        del env["stack"]
        with self.assertRaisesRegex(K.CalibrationStop, "open-file limit"):
            K.host_of(env)

    def test_a_version_is_read_from_the_tools_own_words(self):
        env = copy.deepcopy(ENV)
        env["facts"]["nginx"] = "nothing"
        with self.assertRaisesRegex(K.CalibrationStop, "no version number"):
            K.host_of(env)


class ProbeTest(unittest.TestCase):
    def test_a_legit_probe_is_read_from_ten_seconds_in(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        server = S.SyntheticServer(TEMPLATE, (0.0, 5.0, 1.0), {"C": {"fail_p": 1.0}})     # every request of the first 5 s fails
        host = S.SimHost(server=server)
        plan = K.probe_plan(TEMPLATE, C.PLACEHOLDER, "probe", 31, os.path.join(tmp.name, "block", "C"), {"readiness_timeout_s": 5.0})
        K.Runner(host).run(plan, lambda m: None)
        run = H.read_run(plan.out)
        self.assertEqual(K.probe_metrics(run, TEMPLATE)["Q"], 100.0)
        whole = H.run_metrics(run, TEMPLATE, {"baseline_s": 120.0, "attack_s": 1.0, "recovery_s": 1.0}, window=(0.0, 120.0))
        self.assertLess(whole["Q"], 100.0, "the first seconds do fail: the window is what leaves them out")

    def test_a_probe_is_120_seconds_of_the_benign_load_at_rho(self):
        plan = K.probe_plan(TEMPLATE, C.PLACEHOLDER, "probe", 31, "/var/tmp/ddos_campaigns/example/C")
        self.assertEqual(plan.timeline["total_s"], 120.0)
        self.assertEqual(plan.kind, "C")
        self.assertAlmostEqual(sum(s.rate for s in plan.streams), C.rho_rps(TEMPLATE), delta=0.5)
        self.assertEqual({s.kind for s in plan.streams}, {"legit"})


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        ctl = SC.load(K.spec_path(K.CONTROL_SPEC))
        self.cal = TEMPLATE
        self.plan = lambda name="a": X.plan_population(P.draw(ctl.seed_namespace, 11, 20.0, ctl.benign_identities, None,
                                                               P.Timeline(8.0, 0.0, 0.0), ctl.per_profile),
                                                       "probe", "C", 11, os.path.join(self.tmp.name, name, "C"), self.cal,
                                                       C.PLACEHOLDER, P.Timeline(8.0, 0.0, 0.0),
                                                       settings={"readiness_timeout_s": 5.0})

    def test_a_run_is_made_once_and_remembered(self):
        host = S.SimHost()
        runner = K.Runner(host)
        plan = self.plan()
        record = runner.run(plan, lambda m: None)
        self.assertTrue(record["ok"])
        with mock.patch.object(K.X, "execute") as execute:
            self.assertEqual(K.Runner(S.SimHost()).run(plan, lambda m: None), record)
        execute.assert_not_called()

    def test_the_first_run_of_a_process_waits_for_the_full_gate_and_the_next_for_the_timer(self):
        runner = K.Runner(S.SimHost())
        with mock.patch.object(K.X, "execute", wraps=X.execute) as spy:
            runner.run(self.plan("a"), lambda m: None)
            runner.run(self.plan("b"), lambda m: None)
        self.assertEqual([c.args[2] for c in spy.call_args_list], ["full", "timer"])

    def test_an_unsound_run_is_made_again_and_the_first_is_kept_beside_it(self):
        started = []

        def startup(sid, index, kind):
            started.append(sid)
            return S.LEGIT_STARTUP_S + (2.8 if len(started) == 3 else 0.0)       # only the first run's third stream is late, beyond the range limit
        runner = K.Runner(S.SimHost(startup_s=startup))
        plan = self.plan()
        record = runner.run(plan, lambda m: None)
        self.assertTrue(record["ok"])
        self.assertTrue(os.path.isdir(plan.out + ".failed1"), "the unsound attempt is evidence")
        self.assertTrue(os.path.exists(os.path.join(plan.out, "run.json")))

    def test_the_second_attempt_of_the_first_run_does_not_wait_for_the_full_gate_again(self):
        started = []

        def startup(sid, index, kind):
            started.append(sid)
            return S.LEGIT_STARTUP_S + (2.8 if len(started) == 3 else 0.0)
        runner = K.Runner(S.SimHost(startup_s=startup))
        with mock.patch.object(K.X, "execute", wraps=X.execute) as spy:
            runner.run(self.plan(), lambda m: None)
        self.assertEqual([c.args[2] for c in spy.call_args_list], ["full", "timer"])

    def test_a_run_unsound_in_every_attempt_stops_the_calibration(self):
        runner = K.Runner(S.SimHost(startup_s=lambda sid, index, kind: S.LEGIT_STARTUP_S + (2.8 if index == 3 else 0.0)))
        with self.assertRaisesRegex(K.CalibrationStop, "not sound in 2 attempts"):
            runner.run(self.plan(), lambda m: None)

    def test_a_run_that_fails_in_its_timeline_is_made_again(self):
        runner = K.Runner(S.SimHost(faults={"stream_dies": 1}))
        self.assertTrue(runner.run(self.plan(), lambda m: None)["ok"])

    def test_a_refusal_of_the_executor_is_not_retried(self):
        runner = K.Runner(S.SimHost(root=False))
        with self.assertRaises(X.PreflightRefused):
            runner.run(self.plan(), lambda m: None)

    def test_an_unfinished_run_of_an_earlier_call_is_removed_and_made_again(self):
        plan = self.plan()
        os.makedirs(plan.out)
        with open(os.path.join(plan.out, "FAILED"), "w", encoding="utf-8") as fh:
            fh.write("interrupted\n")
        self.assertTrue(K.Runner(S.SimHost()).run(plan, lambda m: None)["ok"])
        self.assertFalse(os.path.exists(os.path.join(plan.out, "FAILED")))
        self.assertFalse(os.path.exists(plan.out + ".failed0"))


# --- the steps on a server of a known capacity ------------------------------------------------------

CAPACITY_CPU = 1.1                  # CPU-seconds a second: the simulated server's capacity


def failing(u):
    return 0.0 if u <= 1.0 else 1.0 - 1.0 / u


class SimulatedCalibrationTest(unittest.TestCase):
    """The whole calibration on the simulated host, once: the origin, the capacity, the three screenings, the reference, the freeze
    and a drift check. The server fails the share of requests that does not fit its capacity, so the capacity, the knee and the
    harms have values that the model gives and that these tests compute from it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = os.path.join(cls.tmp.name, "session")
        cls.say = []
        cls.template = copy.deepcopy(TEMPLATE)
        cls.host = S.SimHost(server=S.SyntheticServer(cls.template, (30, 45, 30), capacity_cpu=CAPACITY_CPU), tag="placeholder",
                             origin_costs=dict(cls.template["route_costs_ms"]), origin_noise=(0.0, 0.01, -0.01))
        cls.runner = K.Runner(cls.host)
        cls.origin = K.origin_step(cls.host, cls.template, C.PLACEHOLDER, cls.out, cls.say.append)
        cls.capacity = K.capacity_step(cls.runner, cls.template, C.PLACEHOLDER, cls.out, say=cls.say.append)
        cls.draft, cls.under = K.session_draft(cls.out, cls.template)
        cls.ladders = {f: K.ladder_step(cls.runner, cls.draft, C.PLACEHOLDER, f, cls.out, cls.under, say=cls.say.append)
                       for f in sorted(K.FAMILY_SPECS)}
        knees = {f: ladder["knee"]["level"] for f, ladder in cls.ladders.items()}
        cls.reference = K.reference_step(cls.runner, K.draft_record(cls.template, cls.origin, cls.capacity, knees), C.PLACEHOLDER,
                                         knees, cls.out, cls.under, say=cls.say.append)
        env_path = os.path.join(cls.out, "capacity", "r1", "C", "environment.json")
        cls.frozen = K.freeze_step(cls.out, cls.template, K.read_json(env_path), "2026-10-24T12:00:00Z")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    # what the model says
    @staticmethod
    def mean_cost_of_the_legit_mix():
        ctl = SC.load(K.spec_path(K.CONTROL_SPEC))
        pop = P.draw(ctl.seed_namespace, 11, 100.0, ctl.benign_identities, None, P.Timeline(20.0, 0.0, 0.0), ctl.per_profile)
        cost = TEMPLATE["route_costs_ms"]
        return sum(s.rate * cost[s.route_class] for s in pop.streams) / sum(s.rate for s in pop.streams) / 1000.0

    def expected_q(self, level):
        return 100.0 * (1.0 - failing(level * self.mean_cost_of_the_legit_mix() / CAPACITY_CPU))

    def test_the_capacity_found_is_the_one_the_model_has(self):
        levels = K.capacity_levels()
        healthy = [k for k, lv in enumerate(levels) if self.expected_q(lv) >= K.HEALTHY_Q]
        saturated = [k for k, lv in enumerate(levels) if self.expected_q(lv) < K.SATURATED_Q]
        for lv in levels:                                                 # the model is not borderline anywhere that matters
            if self.expected_q(lv) < 100.0:
                self.assertGreater(abs(self.expected_q(lv) - K.HEALTHY_Q), 1.5, lv)
            self.assertGreater(abs(self.expected_q(lv) - K.SATURATED_Q), 3.0, lv)
        self.assertEqual(self.capacity["c_slo_rps"], levels[healthy[-1]])
        self.assertEqual(self.capacity["c_sat_rps"], levels[saturated[0]])

    def test_the_measured_q_follows_the_model_level_by_level(self):
        for row in self.capacity["q_pct"]:
            for lv, q in zip(self.capacity["levels_rps"], row, strict=True):
                self.assertAlmostEqual(q, self.expected_q(lv), delta=4.0, msg=lv)

    def test_the_repeats_of_a_step_are_not_the_same_run(self):
        rows = self.capacity["q_pct"]
        self.assertEqual(len({tuple(r) for r in rows}), 3)

    def test_every_screening_found_the_knee_the_model_has(self):
        spare = C.spare_capacity(self.draft)
        rho_cpu = C.rho_rps(self.draft) * self.mean_cost_of_the_legit_mix()
        for family, ladder in self.ladders.items():
            with self.subTest(family=family):
                self.assertTrue(ladder["valid"], ladder["reasons"])
                predicted = {}
                for row in ladder["levels"]:
                    u = (rho_cpu + row["level"] * spare) / CAPACITY_CPU
                    predicted[row["level"]] = 100.0 * failing(u) / TEMPLATE["gate"]["floor_pp"]
                    for r in row["repeats"]:
                        self.assertAlmostEqual(r["harm"], predicted[row["level"]], delta=0.45, msg=row["level"])
                for lv, h in predicted.items():
                    self.assertGreater(abs(h - 1.0), 0.5, f"the model is borderline at level {lv}")
                self.assertEqual(ladder["knee"]["level"], min(lv for lv, h in predicted.items() if h >= 1.0))

    def test_the_generator_limits_cut_the_ladder_of_the_cheap_flood_and_no_other(self):
        self.assertEqual(self.ladders["cheap_static_flood"]["levels_run"], [0.125, 0.25, 0.5, 1, 2, 4])
        self.assertEqual(list(self.ladders["cheap_static_flood"]["levels_left_out"]), ["8"])
        self.assertEqual(self.ladders["costly_search_flood"]["levels_run"], [0.125, 0.25, 0.5, 1, 2, 4, 8])
        self.assertEqual(self.ladders["costly_export_flood"]["levels_left_out"], {})

    def test_each_family_is_screened_on_its_own_draw_from_the_calibrations_seeds(self):
        seeds = {f: ladder["seed"] for f, ladder in self.ladders.items()}
        self.assertEqual(len(set(seeds.values())), 3)
        for seed in seeds.values():
            P.check_seed("calib", seed)
            self.assertNotIn(seed, range(1, 11), "the gate's blocks use 1-10")

    def test_a_screening_has_the_designs_eighteen_runs_and_four_controls(self):
        ladder = self.ladders["costly_search_flood"]
        self.assertEqual(len(ladder["sequence"]), 18)
        self.assertEqual(len(ladder["controls"]), 4)
        self.assertEqual(len(os.listdir(os.path.join(self.out, "ladder_costly_search_flood"))), 19)

    def test_the_session_is_a_directory_of_runs_the_gate_can_read(self):
        run = H.read_run(os.path.join(self.out, "ladder_costly_search_flood", "01_" + self.leading(), "U" if self.is_attack() else "C"))
        self.assertIn(run["role"], ("attack", "control"))

    def leading(self):
        label = min(d for d in os.listdir(os.path.join(self.out, "ladder_costly_search_flood")) if d.startswith("01_"))
        return label[3:]

    def is_attack(self):
        return self.leading().startswith("L")

    def test_the_reference_is_at_rho_and_at_the_knees(self):
        ref = self.reference["reference"]
        self.assertEqual(ref["rho_rps"], C.rho_rps(self.draft))
        self.assertGreaterEqual(ref["q_pct"], 99.0)
        self.assertEqual(sorted(ref["attack"]), sorted(K.FAMILY_SPECS))
        for family, a in ref["attack"].items():
            self.assertEqual(a["level"], self.ladders[family]["knee"]["level"])
            self.assertLess(a["q_pct"], ref["q_pct"] - 10.0)

    def test_the_record_is_frozen_complete_and_accepted_by_the_loader(self):
        f = self.frozen
        self.assertEqual(f["status"], "frozen")
        self.assertEqual(f["created_utc"], "2026-10-24T12:00:00Z")
        self.assertEqual(f["capacity"], {"c_slo_rps": self.capacity["c_slo_rps"], "c_sat_rps": self.capacity["c_sat_rps"]})
        self.assertEqual(f["route_costs_ms"], self.origin["route_costs_ms"])
        self.assertEqual(f["knees"], {fam: ladder["knee"]["level"] for fam, ladder in self.ladders.items()})
        self.assertEqual(f["drift_reference"], self.reference["reference"])
        path = os.path.join(self.tmp.name, "frozen.json")
        C.dump(f, path)
        self.assertEqual(C.load(path), f)
        self.assertEqual(f["host"]["gunicorn"]["nofile"], 524288)
        self.assertEqual(f["host"]["nginx"]["version"], "1.28.3")

    def test_the_gate_of_the_frozen_record_can_run_a_campaign_on_the_same_server(self):
        cal = copy.deepcopy(self.frozen)
        cal["gate"]["min_blocks"] = 3
        cal = C.freeze(cal, host=cal["host"], drift_reference=cal["drift_reference"])
        scn = SC.load(SPEC_SEARCH)
        t = (6.0, 6.0, 6.0)
        host = S.SimHost(server=S.SyntheticServer(cal, t, capacity_cpu=CAPACITY_CPU), tag=S.origin_tag(cal))
        path = os.path.join(self.tmp.name, "frozen3.json")
        C.dump(cal, path)
        state = GC.run_campaign(scn, cal, path, GC.sha256_of(SPEC_SEARCH), os.path.join(self.tmp.name, "camp"), host,
                                GC.Options(blocks=3, warmup=False, timeline=t, simulate="pass", rho=C.rho_rps(cal)), say=lambda m: None)
        self.assertEqual(state["gate"]["verdict"], "PASS", state["gate"])

    def test_the_drift_check_passes_on_the_same_server_and_fails_on_a_slower_one(self):
        path = os.path.join(self.tmp.name, "drift_cal.json")
        C.dump(self.frozen, path)
        say = []
        same = S.SimHost(server=S.SyntheticServer(self.frozen, (30, 45, 30), capacity_cpu=CAPACITY_CPU), tag=S.origin_tag(self.frozen))
        ok = K.drift_step(K.Runner(same), self.frozen, path, os.path.join(self.tmp.name, "d1"), None, None, say.append)
        self.assertTrue(ok["ok"], ok["reasons"])
        slow = S.SimHost(server=S.SyntheticServer(self.frozen, (30, 45, 30), capacity_cpu=CAPACITY_CPU * 0.25),
                         tag=S.origin_tag(self.frozen))
        bad = K.drift_step(K.Runner(slow), self.frozen, path, os.path.join(self.tmp.name, "d2"), None, None, say.append)
        self.assertFalse(bad["ok"])
        self.assertTrue(bad["reasons"][0].startswith("legit probe: Q"), bad["reasons"])
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "d2", "drift", "drift.json")))

    def cli(self, *args, host=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = K.main(list(args), host=host)
        return code, out.getvalue(), err.getvalue()

    def test_the_drift_command_exits_zero_on_the_same_server_and_three_on_another(self):
        path = os.path.join(self.tmp.name, "cli_cal.json")
        C.dump(self.frozen, path)
        code, out, err = self.cli("drift", "--calibration", path, "--out", os.path.join(self.tmp.name, "c1"), "--simulate",
                                  "--sim-capacity-cpu", str(CAPACITY_CPU))
        self.assertEqual((code, err), (K.EXIT_OK, ""), out)
        self.assertIn("within the frozen reference", out)
        code, out, _ = self.cli("drift", "--calibration", path, "--out", os.path.join(self.tmp.name, "c2"), "--simulate",
                                "--sim-capacity-cpu", str(CAPACITY_CPU * 0.25))
        self.assertEqual(code, K.EXIT_INVALID)
        self.assertIn("OUT of it", out)
        self.assertIn("drift check 1 of 2 failed; making it once more", out)
        self.assertIn("drift check 2 of 2 failed; it stops here", out)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "c2.second", "drift", "drift.json")))

    def test_a_drift_check_that_fails_is_made_once_more_after_the_gate_and_can_then_pass(self):
        path = os.path.join(self.tmp.name, "cli_cal2.json")
        C.dump(self.frozen, path)
        server = S.SyntheticServer(self.frozen, (30, 45, 30), capacity_cpu=CAPACITY_CPU * 0.25)

        def recover(host):                          # the first attempt takes about 250 s of the host's time; then the server is well again
            if host.t > 260.0:
                server.capacity_cpu = CAPACITY_CPU
        host = S.SimHost(server=server, tag=S.origin_tag(self.frozen), on_sleep=recover)
        with mock.patch.object(K.Runner, "__init__", autospec=True, side_effect=K.Runner.__init__) as made:
            code, out, _ = self.cli("drift", "--calibration", path, "--out", os.path.join(self.tmp.name, "c3"), host=host)
        self.assertEqual(code, K.EXIT_OK, out)
        self.assertIn("drift check 1 of 2 failed; making it once more", out)
        self.assertEqual(made.call_count, 2, "a new runner for the second attempt, which waits for the full gate again")
        self.assertFalse(K.read_json(os.path.join(self.tmp.name, "c3", "drift", "drift.json"))["ok"])
        self.assertTrue(K.read_json(os.path.join(self.tmp.name, "c3.second", "drift", "drift.json"))["ok"])

    def test_a_screening_whose_controls_are_unhealthy_is_invalid_and_exits_three(self):
        dest = self.copy_session()                      # not the session itself: this overwrites a screening
        shutil.rmtree(os.path.join(dest, "ladder_costly_search_flood"))
        code, out, _ = self.cli("ladder", "--out", dest, "--family", "costly_search_flood", "--levels", "1,2", "--simulate",
                                "--sim-capacity-cpu", str(CAPACITY_CPU * 0.2))
        self.assertEqual(code, K.EXIT_INVALID)
        self.assertIn("session NOT valid", out)
        ladder = K.read_json(os.path.join(dest, "ladder_costly_search_flood", "ladder.json"))
        self.assertFalse(ladder["valid"])
        self.assertTrue(ladder["smoke"])
        self.assertTrue(ladder["reasons"])

    def test_a_drift_check_needs_a_frozen_record(self):
        with self.assertRaisesRegex(K.CalibrationStop, "needs a frozen calibration"):
            K.drift_step(K.Runner(S.SimHost()), self.template, C.PLACEHOLDER, self.tmp.name)

    def test_a_drift_check_for_a_family_without_a_reference_stops(self):
        cal = copy.deepcopy(self.frozen)
        with self.assertRaisesRegex(K.CalibrationStop, "no attack reference for nothing"):
            K.drift_step(K.Runner(S.SimHost(server=S.SyntheticServer(cal, (30, 45, 30), capacity_cpu=CAPACITY_CPU),
                                            tag=S.origin_tag(cal))), cal, C.PLACEHOLDER, os.path.join(self.tmp.name, "d3"),
                         ["nothing"], None, lambda m: None)

    # --- the freeze refuses what it should ------------------------------------------------------

    def copy_session(self):
        dest = os.path.join(self.tmp.name, f"copy{len(os.listdir(self.tmp.name))}")
        os.makedirs(dest)
        for name in ("origin", "capacity"):
            shutil.copytree(os.path.join(self.out, name, ), os.path.join(dest, name), ignore=shutil.ignore_patterns("r[23]"))
        for family in K.FAMILY_SPECS:
            os.makedirs(os.path.join(dest, f"ladder_{family}"))
            shutil.copy(os.path.join(self.out, f"ladder_{family}", "ladder.json"), os.path.join(dest, f"ladder_{family}"))
        os.makedirs(os.path.join(dest, "reference"))
        shutil.copy(os.path.join(self.out, "reference", "reference.json"), os.path.join(dest, "reference"))
        return dest

    def edit(self, dest, *parts, change):
        path = os.path.join(dest, *parts)
        data = K.read_json(path)
        change(data)
        K.write_json(path, data)

    def freeze(self, dest, template=None):
        env = K.read_json(os.path.join(dest, "capacity", "r1", "C", "environment.json"))
        return K.freeze_step(dest, template or self.template, env)

    def test_a_copy_of_the_session_freezes_the_same(self):
        dest = self.copy_session()
        self.assertEqual({**self.freeze(dest), "created_utc": 0}, {**self.frozen, "created_utc": 0} | {"sha256": self.freeze(dest)["sha256"]})

    def test_a_smoke_step_cannot_be_frozen(self):
        dest = self.copy_session()
        self.edit(dest, "capacity", "capacity.json", change=lambda d: d.update(smoke=True))
        with self.assertRaisesRegex(K.CalibrationStop, "capacity is a smoke test"):
            self.freeze(dest)

    def test_a_screening_that_is_not_valid_cannot_be_frozen(self):
        dest = self.copy_session()
        self.edit(dest, "ladder_costly_search_flood", "ladder.json", change=lambda d: d.update(valid=False, reasons=["x"]))
        with self.assertRaisesRegex(K.CalibrationStop, "screening of costly_search_flood is not valid"):
            self.freeze(dest)

    def test_steps_made_under_other_numbers_cannot_be_frozen_together(self):
        dest = self.copy_session()
        self.edit(dest, "origin", "origin.json", change=lambda d: d["route_costs_ms"].update(C3=99.0))
        with self.assertRaisesRegex(K.CalibrationStop, "ladder .* was made under other measured costs"):
            self.freeze(dest)

    def test_a_template_other_than_the_one_measured_under_cannot_be_used(self):
        dest = self.copy_session()
        other = copy.deepcopy(self.template)
        other["gate"]["floor_pp"] = 12.0
        other["sha256"] = C.digest(other)
        with self.assertRaisesRegex(K.CalibrationStop, "made under another template"):
            self.freeze(dest, other)

    def test_a_reference_that_is_not_at_the_knees_cannot_be_frozen(self):
        dest = self.copy_session()
        self.edit(dest, "reference", "reference.json", change=lambda d: d["reference"]["attack"].pop("costly_search_flood"))
        with self.assertRaisesRegex(K.CalibrationStop, "not at the knees"):
            self.freeze(dest)

    def test_a_reference_at_another_rho_cannot_be_frozen(self):
        dest = self.copy_session()
        self.edit(dest, "reference", "reference.json", change=lambda d: d["reference"].update(rho_rps=50.0))
        with self.assertRaisesRegex(K.CalibrationStop, "reference was taken at rho 50"):
            self.freeze(dest)


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def cli(self, *args, host=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(X.signal, "signal"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = K.main(list(args), host=host)
        return code, out.getvalue(), err.getvalue()

    def test_plan_prints_the_steps_and_their_time(self):
        code, out, _ = self.cli("plan")
        self.assertEqual(code, K.EXIT_OK)
        self.assertIn("3 capacity + 54 screening + 6 reference = 63", out)
        self.assertIn("2.6 h", out)
        for word in ("origin", "capacity", "ladder", "knee", "reference", "freeze", "drift"):
            self.assertIn(word, out)

    def test_the_session_steps_run_in_order_on_the_simulated_host(self):
        out = os.path.join(self.tmp.name, "s")
        sim = ("--simulate", "--sim-capacity-cpu", str(CAPACITY_CPU))
        self.assertEqual(self.cli("origin", "--out", out, *sim)[0], K.EXIT_OK)
        code, text, err = self.cli("capacity", "--out", out, "--levels", "80,160,240,320,400,480", "--step-s", "10", "--repeats", "3", *sim)
        self.assertEqual((code, err), (K.EXIT_OK, ""), text)
        self.assertIn("capacity: C_slo", text)
        self.assertTrue(K.read_json(os.path.join(out, "capacity", "capacity.json"))["smoke"])

    def test_a_ladder_before_the_capacity_is_refused_and_says_which_step_is_missing(self):
        code, _, err = self.cli("ladder", "--out", os.path.join(self.tmp.name, "empty"), "--family", "costly_search_flood", "--simulate")
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("no origin step", err)

    def test_a_reference_before_the_screenings_is_refused(self):
        out = os.path.join(self.tmp.name, "s")
        sim = ("--simulate", "--sim-capacity-cpu", str(CAPACITY_CPU))
        self.cli("origin", "--out", out, *sim)
        self.cli("capacity", "--out", out, "--levels", "80,160,240,320,400,480", "--step-s", "10", *sim)
        code, _, err = self.cli("reference", "--out", out, *sim)
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("a smoke test", err)

    def test_a_capacity_that_stopped_leaves_its_runs_and_a_record_that_says_why(self):
        out = os.path.join(self.tmp.name, "s")
        sim = ("--simulate", "--sim-capacity-cpu", str(CAPACITY_CPU))
        self.cli("origin", "--out", out, *sim)
        code, _, err = self.cli("capacity", "--out", out, "--levels", "80,160,240,280", "--step-s", "10", *sim)
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("no level up to 280 req/s brings Q below 50 %", err)
        record = K.read_json(os.path.join(out, "capacity", "capacity.json"))
        self.assertIn("not saturated", record["stopped"])
        self.assertTrue(os.path.exists(os.path.join(out, "capacity", "r1", "C", "run.json")))
        with self.assertRaisesRegex(K.CalibrationStop, "capacity step stopped"):
            K.session_draft(out, TEMPLATE)

    def test_a_freeze_of_an_empty_directory_is_refused(self):
        code, _, err = self.cli("freeze", "--dir", self.tmp.name, "--out", os.path.join(self.tmp.name, "x.json"))
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("run `capacity` first", err)

    def test_a_ladder_family_must_be_one_of_the_three(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            K.main(["ladder", "--out", self.tmp.name, "--family", "nothing"])
        self.assertEqual(ctx.exception.code, 2)

    def test_a_refusal_of_the_executor_exits_two(self):
        code, _, err = self.cli("capacity", "--out", os.path.join(self.tmp.name, "r"), host=S.SimHost(root=False))
        self.assertEqual(code, K.EXIT_STOPPED)
        self.assertIn("PreflightRefused", err)

    def test_levels_are_positive_numbers(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            K.main(["capacity", "--out", self.tmp.name, "--levels", "a,b"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            K.main(["capacity", "--out", self.tmp.name, "--levels", "10,-5"])
        self.assertEqual(K._levels_arg("10, 20.5"), [10.0, 20.5])

    def test_origin_session_prints_one_json_object(self):
        code, out, _ = self.cli("origin-session", "--repeats", "3")
        self.assertEqual(code, K.EXIT_OK)
        self.assertEqual(sorted(json.loads(out)), ["C0", "C1", "C2", "C3", "C5"])


if __name__ == "__main__":
    unittest.main()
