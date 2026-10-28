"""The executor's run half (docs/HG1C_DESIGN.md 6), on the simulated host of bench/sim_host.py: nothing here needs root, creates
a namespace or starts a server. What cannot be tested this way is listed in docs/HG1C_DESIGN.md 9 and is what S1-S4 are for."""
import contextlib
import copy
import csv
import dataclasses
import gzip
import io
import itertools
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "eval"))
import calibration as C
import calibration_fixtures as CF
import executor as X
import harm_gate as H
import population as P
import run_campaign
import scenario as SC
import sim_host as F

SPEC = os.path.join(REPO, "bench", "scenarios", "costly_search_sub_threshold.json")
SHORT = (10.0, 10.0, 10.0)                # baseline, attack, recovery: virtual time is free, events are not


def stream_of(proc):
    """The id of the stream that a simulated engine process runs."""
    return os.path.basename(os.path.dirname(proc.argv[proc.argv.index("--summary") + 1]))


def bare_settings(**changes):
    return {"readiness_timeout_s": 5.0, **changes}


def teardown_cost(argv):
    """Seconds the commands of a teardown take in the model, each kind its own, so that a time in the log is told from another."""
    if argv[:3] == ["ip", "netns", "pids"]:
        return 0.2
    if argv[:3] == ["ip", "netns", "del"]:
        return 0.5
    if argv[:3] == ["ip", "link", "del"]:
        return 0.1
    return 0.3 if argv[:1] == ["ps"] else 0.0


class RunCase(unittest.TestCase):
    """A scratch directory, and plans made the way the tests of the plan half make them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scn = SC.load(SPEC)
        self.cal = C.load(C.PLACEHOLDER)

    def plan(self, kind="C", name=None, cal=None, path=None, settings=None, **kw):
        out = os.path.join(self.tmp.name, name or kind)
        kw.setdefault("timeline", SHORT)
        kw.setdefault("rho", 20.0)
        return X.plan_run(self.scn, cal or self.cal, kind, 1, out, path or C.PLACEHOLDER, "sha",
                          settings=bare_settings(**(settings or {})), **kw)

    def go(self, kind="C", host=None, plan_args=None, **kw):
        host = host or F.SimHost()
        plan = self.plan(kind, **(plan_args or {}))
        return plan, host, X.execute(plan, host, **kw)

    def read(self, plan, name):
        with open(os.path.join(plan.out, name), encoding="utf-8") as fh:
            return fh.read()

    def run_json(self, plan):
        return json.loads(self.read(plan, "run.json"))

    def failed(self, plan):
        return self.read(plan, "FAILED")

    def assertTestbedEmpty(self, host):
        self.assertEqual(host.testbed(), {"namespaces": [], "links": [], "processes": []})


class ContractTest(RunCase):
    """What a good run leaves behind, and that the harm gate can read it."""

    def test_a_control_run_is_sound_and_leaves_the_run_contract(self):
        plan, host, result = self.go("C")
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(result.reasons, [])
        self.assertEqual(result.setup_retries, 0)
        run = H.read_run(plan.out)
        self.assertEqual(run["role"], "control")
        self.assertEqual(sum(s["kind"] == "legit" for s in run["streams"]), 29)
        self.assertEqual(run["executor"]["ok"], True)
        for name in ("run.json", "plan.json", "environment.json", "executor.log", "server.csv", "server_requests.csv",
                     "nginx.conf", "nginx_access.log.gz", "gunicorn.log"):
            self.assertTrue(os.path.exists(os.path.join(plan.out, name)), name)
        self.assertFalse(os.path.exists(os.path.join(plan.out, "FAILED")))
        self.assertFalse(os.path.exists(os.path.join(plan.out, "nginx_access.log")), "the log is kept compressed")
        self.assertTestbedEmpty(host)

    def test_the_harm_gate_measures_the_run(self):
        plan, _, _ = self.go("C")
        run = H.read_run(plan.out)
        timeline = {"baseline_s": 10.0, "attack_s": 10.0, "recovery_s": 10.0}
        m = H.run_metrics(run, self.cal, timeline)
        self.assertGreater(m["requests"], 20)
        self.assertEqual(m["Q"], 100.0)

    def test_streams_are_listed_with_what_the_gate_requires(self):
        plan, _, _ = self.go("C")
        for s in self.run_json(plan)["streams"]:
            self.assertEqual(sorted(s), sorted(H.STREAM_KEYS))
            self.assertTrue(os.path.exists(os.path.join(plan.out, s["summary"])))
            self.assertTrue(os.path.exists(os.path.join(plan.out, s["records"])))
            self.assertIn(s["netem"], C.LINK_PROFILES)

    def test_the_run_says_what_it_was_and_what_it_overrode(self):
        plan, _, _ = self.go("C")
        meta = self.run_json(plan)
        self.assertEqual((meta["role"], meta["scenario"], meta["seed"]), ("control", "costly_search_sub_threshold", 1))
        self.assertEqual(meta["overrides"], {"rho_rps": 20.0, "timeline_s": [10.0, 10.0, 10.0]})
        self.assertEqual(meta["calibration_sha256"], plan.calibration_sha256)
        self.assertEqual(meta["plan_sha256"], plan.plan_sha256)
        self.assertEqual(meta["executor"]["estimator"], "exit-minus-consistent-wall")

    def test_the_legit_streams_are_the_same_in_the_control_and_the_attack_run(self):
        a = self.plan("C", name="blk/C")
        b = self.plan("U", name="blk/U")
        self.assertEqual(a.plan_sha256, b.plan_sha256)

    def test_the_environment_is_recorded(self):
        plan, _, _ = self.go("C")
        env = json.loads(self.read(plan, "environment.json"))
        self.assertEqual(env["git"]["commit"], "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(env["git"]["dirty"], False)
        self.assertEqual(env["gate"]["met"], True)
        self.assertEqual(env["timer_legit"]["p99_ms"], 1.0)
        self.assertEqual(env["facts"]["nginx"], "nginx version: nginx/1.28.3")
        self.assertEqual(env["calibration_sha256"], plan.calibration_sha256)
        self.assertEqual(env["nofile_soft"], 524288)

    def test_the_event_log_tells_the_run_in_order(self):
        plan, _, _ = self.go("C")
        lines = self.read(plan, "executor.log").splitlines()
        order = [next(i for i, line in enumerate(lines) if key in line)
                 for key in ("preflight and environment passed", "topology:", "stack ready", "launched 29 legit streams",
                             "timeline over", "run.json written", "teardown complete")]
        self.assertEqual(order, sorted(order))
        self.assertNotIn("KILL", "\n".join(lines), "a run that ends well needs no KILL")

    def test_telemetry_is_one_row_a_second_with_the_cpu_of_the_server_processes(self):
        plan, _, _ = self.go("C")
        with open(os.path.join(plan.out, "server.csv"), encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertGreater(len(rows), 25)
        ticks = [float(r["t_rel"]) for r in rows]
        self.assertEqual(ticks[:3], [0.0, 1.0, 2.0])
        later = rows[5]
        self.assertEqual(float(later["origin_cpu_pct"]), 50.0)
        self.assertEqual(float(later["nginx_cpu_pct"]), 40.0)
        self.assertEqual(float(later["cpu6_busy_pct"]), 10.0)
        self.assertEqual(later["listen_overflows"], "0")

    def test_server_requests_are_counted_by_the_client_class_of_the_address(self):
        plan, _, _ = self.go("U")
        with open(os.path.join(plan.out, "server_requests.csv"), encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        classes = {r["Client_Class"] for r in rows}
        self.assertEqual(classes, {"legit", "attack"})
        control, _, _ = self.go("C", plan_args={"name": "ctl/C"})
        with open(os.path.join(control.out, "server_requests.csv"), encoding="utf-8", newline="") as fh:
            self.assertEqual({r["Client_Class"] for r in csv.DictReader(fh)}, {"legit"})

    def test_the_nginx_log_is_compressed_and_complete(self):
        plan, _, _ = self.go("C")
        with gzip.open(os.path.join(plan.out, "nginx_access.log.gz"), "rt", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        self.assertGreater(len(lines), 100)
        self.assertEqual(json.loads(lines[0])["request_uri"], "/static/1")

    def test_the_suite_is_never_imported_by_a_run_on_a_scripted_host(self):
        with mock.patch.object(X.RealHost, "suite", side_effect=AssertionError("the suite was imported")):
            self.go("C")


class TimelineTest(RunCase):
    def test_the_attack_streams_are_launched_so_that_their_loops_start_at_the_end_of_the_baseline(self):
        plan, host, result = self.go("U")
        self.assertTrue(result.ok, result.reasons)
        legit = host.launch_times["L-poisson-C0-perfect-0"]
        attack = host.launch_times["A-costly_search_flood-perfect-0"]
        self.assertAlmostEqual(attack - legit, X.launch_attack_after(plan), delta=0.011)
        self.assertAlmostEqual(X.launch_attack_after(plan), 10.0 + 2.9 - 0.15)

    def test_the_attack_streams_sit_at_the_baseline_on_the_runs_axis(self):
        plan, _, _ = self.go("U")
        run = self.run_json(plan)
        offsets = {s["kind"]: s["offset_s"] for s in run["streams"]}
        # the simulated engines start as S4 and S1b measured them (2.8 s and 0.14 s), the settings are 2.9 s and 0.15 s: 0.07 s apart
        self.assertAlmostEqual(offsets["attack"], 10.0, delta=0.1)
        self.assertAlmostEqual(offsets["legit"], 0.0, delta=0.1)
        self.assertLess(abs(run["executor"]["attack_start_error_s"]), 0.1)
        self.assertAlmostEqual(run["executor"]["launch_attack_after_s"], 12.75)

    def test_a_control_run_launches_no_attack_stream(self):
        plan, host, _ = self.go("C")
        self.assertFalse([sid for sid in host.launch_times if sid.startswith("A-")])
        self.assertIsNone(self.run_json(plan)["executor"]["launch_attack_after_s"])

    def test_the_offsets_are_from_the_median_legit_start_whatever_the_streams_took_to_start(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: F.LEGIT_STARTUP_S + 0.01 * index if kind == "legit" else F.ATTACK_STARTUP_S)
        plan, _, result = self.go("U", host)
        self.assertTrue(result.ok, result.reasons)
        legit = [s["offset_s"] for s in self.run_json(plan)["streams"] if s["kind"] == "legit"]
        self.assertAlmostEqual(sorted(legit)[len(legit) // 2], 0.0, delta=0.01)
        self.assertAlmostEqual(max(legit) - min(legit), 0.28, delta=0.01)

    def late_host(self, late):
        """A host in which the legit streams at the places `late` among those launched together begin 0.8 s after the others (or, if
        `late` is a dict, by the seconds it gives)."""
        delays = late if isinstance(late, dict) else dict.fromkeys(late, 0.8)
        return F.SimHost(startup_s=lambda sid, index, kind: F.LEGIT_STARTUP_S + delays.get(index, 0.0))

    def test_a_stream_that_starts_late_is_a_straggler_the_run_tolerates_and_places_by_its_own_offset(self):
        plan, _, result = self.go("C", self.late_host({7}))
        self.assertTrue(result.ok, result.reasons)
        run = self.run_json(plan)
        (straggler,) = run["executor"]["stragglers"]
        self.assertAlmostEqual(straggler["from_pack_s"], 0.8, delta=0.02)
        self.assertAlmostEqual(straggler["offset_s"], 0.8, delta=0.02)
        self.assertEqual(straggler["tail_s"], 0.0)
        self.assertLess(run["executor"]["t0_spread_legit_s"], 0.1, "the pack")
        self.assertAlmostEqual(run["executor"]["t0_range_legit_s"], 0.8, delta=0.07, msg="all the legit starts")
        self.assertAlmostEqual(max(s["offset_s"] for s in run["streams"]), 0.8, delta=0.02, msg="it is placed where it began")
        self.assertIn("1 legit stream(s) began outside the pack of the others, by up to 0.8", self.read(plan, "executor.log"))
        self.assertIn(straggler["id"], self.read(plan, "executor.log"))

    def test_the_log_counts_the_stragglers_and_names_the_largest_distance(self):
        plan, _, result = self.go("C", self.late_host({7: 0.8, 8: 1.2}))
        self.assertTrue(result.ok, result.reasons)
        ids = [s["id"] for s in self.run_json(plan)["executor"]["stragglers"]]
        self.assertEqual(len(ids), 2)
        self.assertIn("2 legit stream(s) began outside the pack of the others, by up to 1.2", self.read(plan, "executor.log"))
        self.assertIn(", ".join(ids), self.read(plan, "executor.log"))

    def test_a_run_without_a_straggler_says_none_and_does_not_mention_it(self):
        plan, _, result = self.go("C")
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(self.run_json(plan)["executor"]["stragglers"], [])
        self.assertNotIn("outside the pack", self.read(plan, "executor.log"))

    def test_as_many_stragglers_as_the_share_allows_are_tolerated(self):
        plan, _, result = self.go("C", self.late_host({7, 8}))
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(len(self.run_json(plan)["executor"]["stragglers"]), 2)

    def test_a_third_of_the_streams_beginning_late_is_a_run_the_pack_still_holds(self):
        plan, _, result = self.go("C", self.late_host(set(range(7, 17))))             # 10 of 29, 0.8 s late
        self.assertTrue(result.ok, result.reasons)
        run = self.run_json(plan)
        self.assertEqual(len(run["executor"]["stragglers"]), 10)
        self.assertIn("10 legit stream(s) began outside the pack of the others, by up to 0.8", self.read(plan, "executor.log"))
        self.assertEqual(sorted(round(s["offset_s"], 1) for s in run["streams"])[-10:], [0.8] * 10)

    def test_without_a_majority_in_one_place_the_run_is_unsound(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: F.LEGIT_STARTUP_S + (0.0, 0.8, 1.6)[index % 3])      # 10, 10 and 9 streams
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        self.assertEqual([r for r in result.reasons if "apart" in r],
                         ["the legit streams began 1.60 s apart (limit 0.5 s; 19 of 29 are outside the pack, at most 14 may be)"])
        self.assertEqual(len(self.run_json(plan)["executor"]["stragglers"]), 19)

    def test_a_stream_beginning_further_than_the_range_limit_from_the_others_is_placed_and_the_run_is_unsound(self):
        plan, _, result = self.go("C", self.late_host({7: 2.8}))
        self.assertFalse(result.ok)
        self.assertEqual([r for r in result.reasons if "apart" in r],
                         ["the legit streams began 2.80 s apart, further than the 2.5 s within which a straggler may begin"])
        run = H.read_run(plan.out)
        self.assertEqual(len(run["executor"]["stragglers"]), 1)
        self.assertAlmostEqual(max(s["offset_s"] for s in run["streams"]), 2.8, delta=0.02)

    def test_more_stragglers_than_the_share_allows_make_the_run_unsound_and_they_are_still_placed(self):
        plan, _, result = self.go("C", self.late_host({7, 8, 9}), plan_args={"settings": {"straggler_share": 0.1}})
        self.assertFalse(result.ok)
        self.assertEqual([r for r in result.reasons if "apart" in r],
                         ["the legit streams began 0.80 s apart (limit 0.5 s; 3 of 29 are outside the pack, at most 2 may be)"])
        run = H.read_run(plan.out)
        self.assertEqual(run["executor"]["ok"], False)
        self.assertEqual(len(run["executor"]["stragglers"]), 3)
        self.assertEqual(sorted(round(s["offset_s"], 1) for s in run["streams"])[-3:], [0.8, 0.8, 0.8])

    def test_an_attack_that_starts_off_the_end_of_the_baseline_makes_the_run_unsound(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: X.SETTINGS["startup_delay_legit_s"] if kind == "legit"
                         else X.SETTINGS["startup_delay_attack_s"] + 1.0)
        plan, _, result = self.go("U", host)
        self.assertFalse(result.ok)
        self.assertTrue(any("the attack began +1.00 s" in r for r in result.reasons), result.reasons)
        self.assertAlmostEqual(self.run_json(plan)["executor"]["attack_start_error_s"], 1.0, delta=0.01)

    def test_a_common_delay_between_the_loop_and_the_exit_cancels(self):
        slow = F.SimHost(exit_delay_s=0.9)
        plan, _, result = self.go("U", slow)
        self.assertTrue(result.ok, result.reasons)
        self.assertLess(abs(self.run_json(plan)["executor"]["attack_start_error_s"]), 0.1)

    def test_an_exit_delay_that_grows_with_the_requests_is_taken_off_when_it_is_known(self):
        per = 3e-3                             # the attack streams have tens of requests more than the legit ones: 3 ms each
        host = F.SimHost(exit_delay_per_request_s=per)
        plan, _, uncorrected = self.go("U", host, plan_args={"rho": 20.0, "name": "raw/U"})
        err_raw = self.run_json(plan)["executor"]["attack_start_error_s"]
        host = F.SimHost(exit_delay_per_request_s=per)
        plan, _, corrected = self.go("U", host, plan_args={"name": "fixed/U", "settings": {"exit_delay_per_request_s": per}})
        err_fixed = self.run_json(plan)["executor"]["attack_start_error_s"]
        self.assertTrue(uncorrected.ok and corrected.ok)
        self.assertGreater(abs(err_raw), 0.2)
        self.assertLess(abs(err_fixed), 0.1)

    def test_telemetry_is_sampled_over_the_whole_timeline_and_the_attack_launch_does_not_skip_a_tick(self):
        plan, _, _ = self.go("U")
        with open(os.path.join(plan.out, "server.csv"), encoding="utf-8", newline="") as fh:
            ticks = [float(r["t_rel"]) for r in csv.DictReader(fh)]
        gaps = [b - a for a, b in itertools.pairwise(ticks)]
        self.assertLess(max(gaps), 1.01)
        self.assertGreater(ticks[-1], 30.0)

    def test_a_stream_that_dies_early_ends_the_run_and_the_testbed_is_taken_down(self):
        host = F.SimHost(faults={"stream_dies": 1})
        plan = self.plan("C")
        with self.assertRaises(X.RunFailed) as ctx:
            X.execute(plan, host)
        self.assertIn("no legit stream left an output", str(ctx.exception))
        self.assertIn("exited with 2", str(ctx.exception))
        self.assertIn("Traceback", str(ctx.exception))
        self.assertIn("RunFailed", self.failed(plan))
        self.assertFalse(os.path.exists(os.path.join(plan.out, "run.json")))
        self.assertTestbedEmpty(host)
        self.assertLess(host.t, 15.0, "the run was cut short, not left to run its length")

    def test_a_stream_that_has_sent_its_last_request_exits_and_is_not_dead(self):
        host = F.SimHost()
        plan, _, result = self.go("C", host)
        self.assertTrue(result.ok, result.reasons)
        streams = [p for p in host.procs.values() if p.role == "stream"]
        early = [p for p in streams if host.launch_times[stream_of(p)] + 1.8 + 30.0 - (p.exit_time - F.BASE_EPOCH) > X.EARLY_SLACK_S]
        self.assertEqual(len(streams), 29)
        self.assertGreaterEqual(len(early), 3, "streams of a few tenths of a request per second are gone long before the run is over")
        self.assertFalse(any("before its end" in r for r in result.reasons))
        self.assertEqual(len(H.read_run(plan.out)["streams"]), 29)
        self.assertGreater(host.t, 31.0, "the run went on to its last stream")

    def lowest(self, plan):
        """The legit stream of the fewest requests: it exits long before the end of the run (a single request is due half way)."""
        stream = min((s for s in plan.streams if s.kind == "legit"), key=lambda s: s.rate)
        self.assertLessEqual(round(stream.rate * stream.duration_s), 5, "its last request is due well before the end")
        return stream.id

    def test_a_stream_that_exits_with_an_error_before_its_end_ends_the_run_even_with_its_output(self):
        plan = self.plan("C")
        stream = self.lowest(plan)
        host = F.SimHost(nonzero=lambda sid: sid == stream)
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        said = [r for r in result.reasons if r.startswith(f"stream {stream} exited with 3 at T+")]
        self.assertEqual(len(said), 1, result.reasons)
        self.assertIn("s before its end", said[0])
        self.assertNotIn("leaving no output", said[0], "it left its output")
        self.assertLess(host.t, 29.0, "the run was cut short")
        self.assertTestbedEmpty(host)

    def test_a_stream_that_exits_zero_before_its_end_leaving_no_output_ends_the_run(self):
        plan = self.plan("C")
        stream = self.lowest(plan)
        host = F.SimHost(silent=lambda sid: sid == stream)
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        said = [r for r in result.reasons if r.startswith(f"stream {stream} exited with 0 at T+")]
        self.assertEqual(len(said), 1, result.reasons)
        self.assertTrue(said[0].endswith("s before its end, leaving no output"), said[0])
        self.assertLess(host.t, 29.0, "the run was cut short")
        self.assertTestbedEmpty(host)

    def test_a_stream_that_exits_with_an_error_within_the_slack_of_its_end_does_not_end_the_run(self):
        base = F.SimHost()
        self.go("C", base, plan_args={"name": "base/C"})
        # the executor looks once a second from the launch: it sees an exit at the first look at or after it
        seen = {stream_of(p): math.ceil(p.exit_time - F.BASE_EPOCH - base.launch_times[stream_of(p)]) for p in base.procs.values()
                if p.role == "stream"}
        end = X.SETTINGS["startup_delay_legit_s"] + 30.0                 # where the executor puts a legit stream's end: its start-up and its duration
        near = sorted(sid for sid, look in seen.items() if end - X.EARLY_SLACK_S <= look < end)
        self.assertTrue(near, f"some stream is first seen to have exited within {X.EARLY_SLACK_S:g} s of its end: {sorted(seen.values())}")
        host = F.SimHost(nonzero=lambda sid: sid == near[0])
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        self.assertEqual([r for r in result.reasons if "before its end" in r], [], "it is within the slack of its end")
        self.assertTrue(any(f"stream {near[0]} exited with 3" in r for r in result.reasons), result.reasons)
        self.assertEqual(len(H.read_run(plan.out)["streams"]), 29)
        self.assertGreater(host.t, 31.0)

    def test_a_stream_that_leaves_no_output_is_left_out_and_the_run_is_unsound(self):
        host = F.SimHost(faults={"stream_silent": 1})
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        self.assertTrue(any("left no output" in r for r in result.reasons), result.reasons)
        self.assertEqual(len(H.read_run(plan.out)["streams"]), 28)

    def test_a_stream_that_exits_non_zero_makes_the_run_unsound_even_with_its_output(self):
        host = F.SimHost(faults={"stream_nonzero": 1})
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        self.assertTrue(any("exited with 3" in r for r in result.reasons), result.reasons)
        self.assertEqual(len(H.read_run(plan.out)["streams"]), 29, "its output is kept: it is the gate's to weigh")

    def test_a_stream_that_never_ends_is_cut_off_at_the_deadline(self):
        host = F.SimHost(faults={"stream_hangs": 1})
        _, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        self.assertTrue(any("still running" in r for r in result.reasons), result.reasons)
        self.assertTestbedEmpty(host)

    def test_the_deadline_is_the_start_up_the_timeline_the_drain_and_the_waits_after_the_launch(self):
        host = F.SimHost(faults={"stream_hangs": 1})
        plan, _, result = self.go("C", host)
        s = plan.settings
        deadline = s["startup_delay_legit_s"] + plan.timeline["total_s"] + X.DRAIN_S + s["term_grace_s"] + 10.0
        said = [r for r in result.reasons if "still running" in r]
        self.assertEqual(len(said), 1, result.reasons)
        gave_up = int(said[0].split("still running ")[1].split(" s after the launch")[0])
        # the executor looks once a tick and gives up at the first look after the deadline; the reason rounds that to a second
        self.assertGreaterEqual(gave_up, round(deadline), said)
        self.assertLessEqual(gave_up, deadline + X.TICK_S + 0.5, said)

    def test_ctrl_c_during_the_timeline_takes_the_testbed_down_and_says_so(self):
        def interrupt(host):
            if host.t > 20.0:
                raise KeyboardInterrupt("signal 15")
        host = F.SimHost(on_sleep=interrupt)
        plan = self.plan("C")
        with self.assertRaises(KeyboardInterrupt):
            X.execute(plan, host)
        self.assertIn("KeyboardInterrupt", self.failed(plan))
        self.assertTestbedEmpty(host)
        self.assertFalse(os.path.exists(os.path.join(plan.out, "run.json")))
        self.assertTrue(host.ran("ip", "netns", "del"))
        self.assertEqual(host.unshielded, [], "the namespaces were deleted inside the shield, out of reach of a second Ctrl-C")


class RefusalTest(RunCase):
    """The checks before anything is built: refusals leave the machine as they found it."""

    def assertNothingBuilt(self, host):
        self.assertEqual(host.prims, [])
        self.assertEqual(host.kinds()["popen"], 0)
        self.assertEqual(host.ran("ip", "netns", "del"), [])
        self.assertEqual(host.ran("kill"), [])

    def refused(self, host, error=X.PreflightRefused, name=None, **kw):
        plan = self.plan("C", name=name)
        with self.assertRaises(error) as ctx:
            X.execute(plan, host, **kw)
        self.assertIn(error.__name__, self.failed(plan))
        self.assertNothingBuilt(host)
        return plan, str(ctx.exception)

    def test_it_needs_root(self):
        _, why = self.refused(F.SimHost(root=False))
        self.assertIn("needs root", why)

    def test_it_needs_the_venv(self):
        _, why = self.refused(F.SimHost(python_exists=False))
        self.assertIn("venv", why)

    def test_it_needs_enough_descriptors(self):
        _, why = self.refused(F.SimHost(nofile=(1024, 1024)))
        self.assertIn("1024", why)

    def test_a_dirty_tree_is_refused_and_allowed_when_asked_and_then_recorded(self):
        _, why = self.refused(F.SimHost(dirty=True), name="dirty/C")
        self.assertIn("uncommitted", why)
        self.assertIn("bench/executor.py", why)
        plan, _, result = self.go("C", F.SimHost(dirty=True), allow_dirty=True, plan_args={"name": "ok/C"})
        self.assertTrue(result.ok)
        env = json.loads(self.read(plan, "environment.json"))
        self.assertEqual((env["git"]["dirty"], env["allow_dirty"]), (True, True))
        self.assertEqual(env["git"]["dirty_files"], [" M bench/executor.py"])

    def test_an_earlier_testbed_is_refused_not_destroyed(self):
        host = F.SimHost(preexisting=["legit_3", "server_ns"])
        _, why = self.refused(host)
        self.assertIn("netem legit_3", why.replace("netns", "netem"))
        self.assertIn("legit_3", why)
        self.assertEqual(sorted(host.namespaces), ["legit_3", "server_ns"], "somebody else's namespaces are theirs")

    def test_a_process_of_an_earlier_run_is_refused_whatever_it_is_called(self):
        host = F.SimHost()
        host.spawn(["/usr/sbin/nginx", "-c", "x.conf"], "", "nginx", "nginx")
        _, why = self.refused(host)
        self.assertIn("process nginx", why)

    def test_clean_takes_down_an_earlier_testbeds_namespaces_and_the_run_goes_on(self):
        host = F.SimHost(preexisting=["legit_3", "bot_1"])
        host.links.update({"vo_legit_3", "ddos_br0"})
        _, _, result = self.go("C", host, clean=True)
        self.assertTrue(result.ok, result.reasons)
        self.assertTestbedEmpty(host)
        self.assertTrue(host.ran("ip", "netns", "del", "legit_3"))

    def test_clean_does_not_kill_a_process_outside_the_namespaces(self):
        host = F.SimHost(preexisting=["legit_3"])
        stray = host.spawn(["/usr/sbin/nginx"], "", "nginx", "nginx")
        plan = self.plan("C")
        with self.assertRaises(X.PreflightRefused):
            X.execute(plan, host, clean=True)
        self.assertIsNone(stray.returncode)
        self.assertEqual(host.ran("kill"), [], "nothing was signalled: the stray is reported, not killed")

    def test_a_directory_that_holds_something_is_not_used(self):
        plan = self.plan("C")
        os.makedirs(plan.out)
        keep = os.path.join(plan.out, "earlier.txt")
        with open(keep, "w", encoding="utf-8") as fh:
            fh.write("a result")
        host = F.SimHost()
        with self.assertRaises(X.PreflightRefused):
            X.execute(plan, host)
        self.assertEqual(os.listdir(plan.out), ["earlier.txt"])
        self.assertNothingBuilt(host)

    def test_a_timer_that_wakes_late_on_the_legit_cpu_is_refused(self):
        _, why = self.refused(F.SimHost(timer_p99_ms=25.0), error=X.EnvironmentRefused)
        self.assertIn("p99 25.0 ms", why)
        self.assertIn("CPU 6", why)

    def test_a_timer_just_under_the_limit_is_accepted_and_one_at_it_is_not(self):
        _, _, result = self.go("C", F.SimHost(timer_p99_ms=9.99))
        self.assertTrue(result.ok)
        self.refused(F.SimHost(timer_p99_ms=10.0), error=X.EnvironmentRefused, name="edge/C")

    def test_the_full_gate_waits_for_uptime_and_load_and_then_refuses(self):
        host = F.SimHost(uptime_s=60.0)
        _, why = self.refused(host, error=X.EnvironmentRefused, wait_gate_min=1.0)
        self.assertIn("not quiet enough", why)
        self.assertGreaterEqual(host.t, 60.0, "it waited as long as it was told to")
        host = F.SimHost(load1=1.5)
        _, why = self.refused(host, error=X.EnvironmentRefused, name="load/C", wait_gate_min=0.5)
        self.assertIn("load 1.50", why)

    def test_between_the_runs_of_a_campaign_the_load_a_run_left_is_recorded_not_waited_for(self):
        host = F.SimHost(load1=2.5, uptime_s=60.0)
        plan, _, result = self.go("C", host, gate="timer")
        self.assertTrue(result.ok)
        self.assertLess(host.sleeps[0], 20, "it did not wait for the gate")
        env = json.loads(self.read(plan, "environment.json"))
        self.assertEqual((env["gate_mode"], env["gate"]["met"], env["gate"]["load1"]), ("timer", None, 2.5))

    def test_the_timer_still_gates_between_the_runs_of_a_campaign(self):
        self.refused(F.SimHost(timer_p99_ms=40.0), error=X.EnvironmentRefused, gate="timer")


class TimerLimitTest(RunCase):
    """The limit for the timer on the legit CPU is the calibration's validity.timer_p99_ms, or a smoke test's; the run records
    which, and the limit it used."""

    def limited(self, ms):
        cal = copy.deepcopy(self.cal)
        cal["validity"]["timer_p99_ms"] = ms
        return cal

    def refused(self, host, name, **kw):
        plan = self.plan("C", name=name, **kw)
        with self.assertRaises(X.EnvironmentRefused) as ctx:
            X.execute(plan, host)
        self.assertEqual(host.prims, [], "nothing was built")
        return plan, str(ctx.exception)

    def environment(self, plan):
        return json.loads(self.read(plan, "environment.json"))

    def test_the_limit_is_the_calibrations_not_a_constant_of_the_code(self):
        plan, _, result = self.go("C", F.SimHost(timer_p99_ms=15.0), plan_args={"cal": self.limited(20.0), "name": "high/C"})
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(self.environment(plan)["timer_limit_ms"], 20.0)
        _, why = self.refused(F.SimHost(timer_p99_ms=7.0), "low/C", cal=self.limited(5.0))
        self.assertIn("p99 7.0 ms", why)
        self.assertIn("needs below 5 ms", why)

    def test_the_refusal_names_the_limit_and_does_not_blame_a_smoke_test_that_did_not_set_it(self):
        _, why = self.refused(F.SimHost(timer_p99_ms=15.0), "default/C")
        self.assertIn(f"needs below {self.cal['validity']['timer_p99_ms']:g} ms", why)
        self.assertNotIn("--timer-limit-ms", why)

    def test_the_limit_the_calibration_gives_is_recorded_and_is_not_an_override(self):
        plan, _, _ = self.go("C", plan_args={"name": "own/C"})
        env = self.environment(plan)
        self.assertEqual((env["timer_limit_ms"], env["timer_limit_is_override"]), (self.cal["validity"]["timer_p99_ms"], False))
        self.assertEqual(sorted(self.run_json(plan)["overrides"]), ["rho_rps", "timeline_s"],
                         "the run was a smoke test in other ways, which says nothing of its limit")

    def test_a_smoke_test_can_raise_it_and_the_run_says_so_everywhere(self):
        host = F.SimHost(timer_p99_ms=15.0)
        self.refused(host, "refused/C")
        plan, _, result = self.go("C", F.SimHost(timer_p99_ms=15.0), plan_args={"name": "raised/C", "timer_limit_ms": 50.0})
        self.assertTrue(result.ok, result.reasons)
        env = self.environment(plan)
        self.assertEqual((env["timer_limit_ms"], env["timer_limit_is_override"]), (50.0, True))
        self.assertEqual(env["timer_legit"]["p99_ms"], 15.0, "the timer is measured and recorded as it was")
        self.assertEqual(self.run_json(plan)["overrides"]["timer_limit_ms"], 50.0)
        self.assertEqual(json.loads(self.read(plan, "plan.json"))["overrides"]["timer_limit_ms"], 50.0)
        self.assertEqual(H.read_run(plan.out)["overrides"]["timer_limit_ms"], 50.0)

    def test_a_limit_a_smoke_test_set_still_refuses_what_is_above_it_and_says_who_set_it(self):
        _, why = self.refused(F.SimHost(timer_p99_ms=60.0), "above/C", timer_limit_ms=50.0)
        self.assertIn("p99 60.0 ms", why)
        self.assertIn("needs below 50 ms", why)
        self.assertIn("set by --timer-limit-ms for a smoke test", why)

    def test_a_smoke_test_can_also_make_it_stricter(self):
        self.refused(F.SimHost(timer_p99_ms=3.0), "strict/C", timer_limit_ms=2.0)

    def test_just_under_the_limit_is_accepted_and_one_at_it_is_not_whoever_set_it(self):
        _, _, result = self.go("C", F.SimHost(timer_p99_ms=49.99), plan_args={"name": "under/C", "timer_limit_ms": 50.0})
        self.assertTrue(result.ok)
        self.refused(F.SimHost(timer_p99_ms=50.0), "edge/C", timer_limit_ms=50.0)

    def test_between_the_runs_of_a_campaign_the_same_limit_gates_the_timer(self):
        _, _, result = self.go("C", F.SimHost(timer_p99_ms=40.0), gate="timer", plan_args={"name": "in/C", "timer_limit_ms": 50.0})
        self.assertTrue(result.ok)
        plan = self.plan("C", name="out/C", timer_limit_ms=50.0)
        with self.assertRaises(X.EnvironmentRefused):
            X.execute(plan, F.SimHost(timer_p99_ms=60.0), gate="timer")

    def test_a_refusal_for_the_timer_leaves_a_failed_file_and_no_run(self):
        plan, _ = self.refused(F.SimHost(timer_p99_ms=60.0), "failed/C", timer_limit_ms=50.0)
        self.assertIn("EnvironmentRefused", self.failed(plan))
        self.assertFalse(os.path.exists(os.path.join(plan.out, "run.json")))


class SetupTest(RunCase):
    def build(self, faults, expect=X.SetupFailed, **kw):
        host = F.SimHost(faults=faults)
        plan = self.plan("C", **kw)
        with self.assertRaises(expect) as ctx:
            X.execute(plan, host)
        return plan, host, str(ctx.exception)

    def test_a_missing_address_is_found_the_testbed_rebuilt_and_the_run_goes_on(self):
        host = F.SimHost(faults={"missing_address": 1})
        plan, _, result = self.go("C", host)
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(result.setup_retries, 1)
        self.assertEqual(self.run_json(plan)["executor"]["setup_retries"], 1)
        self.assertEqual(sum(p[0] == "bridge" for p in host.prims), 2, "the topology was built twice")
        log = self.read(plan, "executor.log")
        self.assertIn("setup failed: topology:", log)
        self.assertIn("retrying the setup (1 of 2)", log)
        self.assertTestbedEmpty(host)

    def test_the_failed_attempt_leaves_nothing_in_the_run_directory(self):
        host = F.SimHost(faults={"nginx_fails": 1})
        plan, _, result = self.go("C", host)
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(result.setup_retries, 1)
        self.assertEqual(self.read(plan, "gunicorn.log").count("Booting worker"), 1, "only the second attempt's origin is in the log")

    def test_a_fault_that_stays_stops_after_two_retries(self):
        plan, host, why = self.build({"missing_address": None})
        self.assertIn("addresses", why)
        self.assertEqual(sum(p[0] == "bridge" for p in host.prims), 3)
        self.assertIn("SetupFailed", self.failed(plan))
        self.assertFalse(os.path.exists(os.path.join(plan.out, "run.json")))
        self.assertTestbedEmpty(host)

    def test_two_namespaces_with_the_same_mac_are_found(self):
        _, _, why = self.build({"duplicate_mac": None})
        self.assertIn("MAC", why)
        self.assertIn("also", why)

    def test_a_server_without_its_address_is_found(self):
        _, _, why = self.build({"server_address_missing": None})
        self.assertIn("no 10.0.0.1 on veth_server", why)

    def test_an_nginx_configuration_that_is_not_the_plans_is_refused(self):
        plan = dataclasses.replace(self.plan("C"), nginx_conf="worker_processes 1;\n")
        host = F.SimHost()
        with self.assertRaises(X.SetupFailed) as ctx:
            X.execute(plan, host)
        self.assertIn("no text with that hash", str(ctx.exception))
        self.assertEqual(host.kinds()["popen"], 0, "nothing was started from a configuration nobody vouched for")

    def test_a_link_without_its_netem_is_found(self):
        _, _, why = self.build({"no_netem": None})
        self.assertIn("no netem", why)

    def test_a_namespace_that_cannot_reach_the_server_is_found(self):
        _, _, why = self.build({"ping_fails": None})
        self.assertIn("no answer from 10.0.0.1", why)

    def test_connectivity_is_tried_from_the_namespace_and_from_its_last_alias(self):
        plan, host, _ = self.go("U")
        pings = host.ran("ping")
        for ns in plan.namespaces:
            from_ns = [c for c in pings if c[1] == ns.name]
            self.assertEqual(len(from_ns), 2, ns.name)
            self.assertIn(ns.addresses[-1], from_ns[1][2])

    def test_each_ping_asks_for_three_packets_a_fifth_of_a_second_apart_and_waits_three_seconds(self):
        plan, host, _ = self.go("C")
        ns = plan.namespaces[0]
        own, alias = [c[2] for c in host.ran("ping") if c[1] == ns.name]
        self.assertEqual(own, ("ping", "-c", "3", "-i", "0.2", "-W", "3", X.SERVER_IP))
        self.assertEqual(alias, ("ping", "-c", "3", "-i", "0.2", "-W", "3", "-I", ns.addresses[-1], X.SERVER_IP))

    def test_a_ping_command_is_given_longer_than_its_packets_and_its_wait_take(self):
        self.assertEqual((X.PING_COUNT, X.PING_INTERVAL_S, X.PING_WAIT_S), (3, 0.2, 3.0))
        self.assertGreater(X.PING_RUN_S, (X.PING_COUNT - 1) * X.PING_INTERVAL_S + X.PING_WAIT_S + 5.0)
        seen = []
        real = F.SimHost.run

        def spy(host, argv, ns="", stdin="", env=None, timeout=None):
            if argv[0] == "ping":
                seen.append(timeout)
            return real(host, argv, ns, stdin, env, timeout)
        with mock.patch.object(F.SimHost, "run", spy):
            self.go("C")
        self.assertEqual(set(seen), {X.PING_RUN_S})
        self.assertEqual(len(seen), 8)

    def test_a_namespace_whose_first_packets_are_lost_still_answers(self):
        _, host, _ = self.go("C", F.SimHost(ping_drops=lambda ns, source, k: k < 2))
        self.assertEqual(len(host.ran("ping")), 8)
        self.assertTestbedEmpty(host)

    def test_a_namespace_every_packet_of_which_is_lost_is_found_with_the_source_that_failed(self):
        host = F.SimHost(ping_drops=lambda ns, source, k: ns == "hg_3_mobile_bad")
        _, _, why = self.build_with(host)
        self.assertIn("hg_3_mobile_bad: no answer from 10.0.0.1", why)
        self.assertEqual(why.count("no answer"), 2, "from its own address and from its alias")
        self.assertNotIn("hg_0_perfect: no answer", why)

    def test_an_alias_that_cannot_reach_the_server_is_told_apart_from_the_namespace(self):
        plan = self.plan("C")
        alias = plan.namespaces[1].addresses[-1]
        host = F.SimHost(ping_drops=lambda ns, source, k: source == alias)
        _, _, why = self.build_with(host, plan)
        self.assertIn(f"{plan.namespaces[1].name}: no answer from 10.0.0.1 to {alias}", why)
        self.assertEqual(why.count("no answer"), 1)

    def test_one_packet_of_three_lost_in_every_ping_is_no_failure_but_a_ping_of_one_would_have_failed(self):
        drops = lambda ns, source, k: k == 0
        _, host, _ = self.go("C", F.SimHost(ping_drops=drops))
        self.assertTestbedEmpty(host)
        one = F.SimHost(ping_drops=drops)
        self.assertEqual(one.run(["ping", "-c", "1"], ns="hg_0_perfect").code, 1, "the sim: a single lost packet is a failed ping")
        self.assertEqual(one.run(["ping", "-c", "3"], ns="hg_0_perfect").code, 0)
        self.assertEqual(one.run(["ping"], ns="hg_0_perfect").code, 1, "without -c the simulated ping sends one packet")

    def build_with(self, host, plan=None):
        plan = plan or self.plan("C")
        with self.assertRaises(X.SetupFailed) as ctx:
            X.execute(plan, host)
        return plan, host, str(ctx.exception)

    def test_nginx_that_does_not_start_is_reported_with_what_it_said(self):
        _, _, why = self.build({"nginx_fails": None})
        self.assertIn("exited 1: nginx: [emerg] bind() to 0.0.0.0:80 failed", why)

    def test_a_start_that_fails_says_the_last_three_lines_of_what_it_printed(self):
        class Chatty(F.SimHost):
            def _daemon_start(self, a, ns, cpus=None):
                return 1, "\n".join(f"nginx: [emerg] line {k}" for k in range(5))
        _, _, why = self.build_with(Chatty())
        self.assertIn("exited 1: nginx: [emerg] line 2 | nginx: [emerg] line 3 | nginx: [emerg] line 4", why)
        self.assertNotIn("line 1", why)

    def test_nginx_is_started_with_no_pipe_for_its_daemon_to_hold(self):
        """S3: run to completion with its output captured, the call came back only at its timeout, three times."""
        plan, host, result = self.go("C")
        self.assertTrue(result.ok, result.reasons)
        started = [c for c in host.commands if c[2][:1] == ("taskset",) and "nginx" in c[2]]
        self.assertEqual([(c[0], c[1]) for c in started], [("popen", "server_ns")], "like the origin, not run to completion")
        self.assertLess(host.t, X.RealHost.COMMAND_TIMEOUT_S, "no call waited out its timeout")
        self.assertRegex(self.read(plan, "executor.log"), r"started Nginx \(its launcher returned after 0\.\d+ s\)")
        self.assertEqual(self.read(plan, "nginx_start.log"), "")

    def test_nginx_that_does_not_return_is_given_up_after_the_wait_and_taken_down(self):
        _, host, why = self.build({"nginx_foreground": None})
        self.assertIn("did not return within 10 s: Nginx is not daemonising, or it hangs", why)
        self.assertIn("nginx -c", why)
        self.assertEqual(sum(p[0] == "bridge" for p in host.prims), 3, "a failed start is retried like any other")
        self.assertGreaterEqual(host.t, 3 * X.DAEMON_FORK_WAIT_S)
        self.assertTestbedEmpty(host)

    def test_a_start_that_fails_keeps_the_last_attempts_files_and_only_those(self):
        plan, host, _ = self.build({"nginx_fails": None})
        for name in ("nginx.conf", "nginx_start.log", "gunicorn.log", "nginx_access.log", "nginx_error.log",
                     "plan.json", "environment.json", "executor.log", "FAILED"):
            self.assertTrue(os.path.exists(os.path.join(plan.out, name)), name)
        self.assertEqual(self.read(plan, "nginx_start.log").count("emerg"), 1, "the last attempt's message, not three")
        self.assertEqual(self.read(plan, "gunicorn.log").count("Booting worker"), 1, "the last attempt's origin, not three")
        self.assertFalse(os.path.exists(os.path.join(plan.out, "run.json")))
        self.assertEqual(self.read(plan, "executor.log").count("retrying the setup"), 2)
        self.assertTestbedEmpty(host)

    def test_a_start_that_a_retry_cures_leaves_only_the_second_attempts_files(self):
        plan, _, result = self.go("C", F.SimHost(faults={"nginx_fails": 1}))
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(self.read(plan, "nginx_start.log"), "", "the first attempt's message went with its files")

    def test_an_origin_that_exits_before_it_answers_is_reported(self):
        _, _, why = self.build({"origin_dies": None})
        self.assertIn("the origin exited with 1", why)

    def test_a_stack_that_is_never_ready_is_given_up_after_the_timeout(self):
        _, host, why = self.build({"not_ready": None})
        self.assertIn("did not answer 200", why)
        self.assertGreaterEqual(host.t, 5.0 * 3, "three attempts of the readiness timeout")
        self.assertLess(host.t, 5.0 * 3 + 30.0, "and no more than that")

    def test_a_route_that_answers_with_the_wrong_class_is_reported(self):
        _, _, why = self.build({"wrong_class": None})
        self.assertIn("route class 'C1', not C3", why)

    def test_an_origin_under_another_calibration_is_reported(self):
        _, _, why = self.build({"wrong_tag": None})
        self.assertIn("calibration", why)

    def test_the_origins_calibration_tag_is_the_frozen_records_hash(self):
        frozen = CF.frozen()
        tag = f"frozen:{frozen['sha256'][:8]}"
        _, _, result = self.go("C", F.SimHost(tag=tag), plan_args={"cal": frozen, "name": "f/C"})
        self.assertTrue(result.ok, result.reasons)
        host = F.SimHost(tag="placeholder")
        with self.assertRaises(X.SetupFailed) as ctx:
            X.execute(self.plan("C", cal=frozen, name="g/C"), host)
        self.assertIn(tag, str(ctx.exception))

    def test_the_setup_is_topology_then_origin_then_nginx_then_readiness_then_the_streams(self):
        plan, host, _ = self.go("C")

        def first(match):
            return next(i for i, (kind, _, argv) in enumerate(host.commands) if match(kind, argv))
        last_prim = max(i for i, c in enumerate(host.commands) if c[0] == "prim")
        origin = first(lambda kind, argv: kind == "popen" and "gunicorn" in argv)
        nginx = first(lambda kind, argv: kind == "popen" and argv[:1] == ("taskset",) and "nginx" in argv)
        ready = first(lambda kind, argv: kind == "run" and argv[:1] == ("curl",))
        stream = first(lambda kind, argv: kind == "popen" and "bench/loadgen.py" in " ".join(argv))
        self.assertLess(last_prim, origin)
        self.assertLess(origin, nginx)
        self.assertLess(nginx, ready)
        self.assertLess(ready, stream)
        warm = [c for c in host.commands if c[0] == "run" and c[2][:1] == ("curl",) and "-w" in c[2]]
        self.assertGreaterEqual(len(warm), 1 + 5 * plan.settings["warmup_requests"], "the probe, then the warm-up of each route")

    def test_the_streams_run_in_their_namespaces_with_their_own_pins_and_the_cleaned_environment(self):
        plan, host, _ = self.go("U")
        by_ns = {c[1] for c in host.commands if c[0] == "popen" and "bench/loadgen.py" in " ".join(c[2])}
        self.assertEqual(by_ns, {ns.name for ns in plan.namespaces})


class TeardownTest(RunCase):
    def test_a_origin_that_ignores_term_is_killed_after_the_grace(self):
        host = F.SimHost(faults={"stubborn_origin": 1})
        plan, _, result = self.go("C", host)
        self.assertTrue(result.ok)
        self.assertIn("KILL pid", self.read(plan, "executor.log"))
        self.assertTestbedEmpty(host)

    def test_a_process_of_a_namespace_that_ignores_term_is_killed_after_the_grace(self):
        host = F.SimHost(faults={"stubborn_nginx": None})
        plan, _, result = self.go("C", host)
        self.assertTrue(result.ok)
        log = self.read(plan, "executor.log")
        self.assertIn("processes of the namespaces that ignored TERM", log)
        self.assertEqual(len(host.ran("kill", "-KILL")), 1)
        self.assertEqual(len(host.ran("kill", "-TERM")), 1)
        self.assertTestbedEmpty(host)

    def test_a_process_that_survives_the_teardown_is_a_leftover_error_and_the_run_is_kept(self):
        host = F.SimHost(faults={"leftover_nginx_after_teardown": None})
        plan = self.plan("C")
        with self.assertRaises(X.LeftoverError) as ctx:
            X.execute(plan, host)
        self.assertIn("process nginx", str(ctx.exception))
        self.assertIn("LeftoverError", self.failed(plan))
        self.assertTrue(os.path.exists(os.path.join(plan.out, "run.json")), "the run itself finished and is kept")

    def test_nothing_is_ever_killed_by_pattern(self):
        runs = [{}, {"faults": {"stubborn_origin": 1}}, {"faults": {"missing_address": 1}}, {"faults": {"stream_dies": 1}}]
        for i, kw in enumerate(runs):
            host = F.SimHost(**kw)
            plan = self.plan("C", name=f"k{i}/C")
            with self.subTest(kw=kw), mock.patch("builtins.print"):
                try:
                    X.execute(plan, host)
                except X.RunFailed:
                    pass
            for _, _, argv in host.commands:
                self.assertNotIn(argv[0], ("pkill", "killall", "fuser"), argv)
                if argv[0] == "kill":
                    self.assertRegex(argv[1], r"^-(TERM|KILL)$")
                    self.assertTrue(all(a.isdigit() for a in argv[2:]), argv)
                self.assertNotEqual(argv[0], "pgrep", "processes are read from the process table, not found by pattern")
                if argv[0] == "ps":
                    self.assertEqual(argv[1:], ("-eo", "pid=,ppid=,args="))

    def test_the_teardown_logs_the_time_of_each_step(self):
        """S3's teardown took 12.6 s and the log did not say where."""
        plan, _, result = self.go("C", F.SimHost(run_cost_s=teardown_cost))
        self.assertTrue(result.ok, result.reasons)
        text = self.read(plan, "executor.log")
        namespaces = [ns.name for ns in plan.namespaces] + [X.SERVER_NS]
        links = [X.outer_veth(ns.name) for ns in plan.namespaces] + [X.SERVER_VETH_HOST_END, X.BRIDGE]
        self.assertIn("teardown: 2 process(es) in 5 namespace(s): listed in 1.00 s, ended in 0.10 s", text)
        self.assertIn("teardown: namespaces deleted: " + ", ".join(f"{n} 0.50 s" for n in namespaces), text)
        self.assertIn("teardown: links deleted: " + ", ".join(f"{n} 0.10 s" for n in links), text)
        self.assertIn("teardown complete: no namespace, link or process of the testbed is left (leftover check 0.30 s; 4.5 s in all)", text)
        order = [text.index(k) for k in ("teardown: 2 process", "teardown: namespaces deleted", "teardown: links deleted", "teardown complete")]
        self.assertEqual(order, sorted(order))

    def test_what_stopping_the_run_s_own_processes_took_is_logged_once(self):
        plan, _, _ = self.go("C")
        self.assertEqual(self.read(plan, "executor.log").count("stopped 1 process(es) of this run in 0.00 s"), 1,
                         "the origin, after the timeline; the stop in the `finally` finds nothing to stop and says nothing")
        plan, _, _ = self.go("C", F.SimHost(faults={"stubborn_origin": 1}), plan_args={"name": "stubborn/C"})
        text = self.read(plan, "executor.log")
        self.assertIn("stopped 1 process(es) of this run in 2.00 s", text)
        self.assertLess(text.index("KILL pid"), text.index("stopped 1 process(es)"))

    def test_destroy_says_nothing_without_a_log_and_the_time_of_each_step_with_one(self):
        quiet = F.SimHost(preexisting=["legit_3"])
        X.destroy(quiet, ["legit_3"], ["vo_legit_3"], 2.0)
        self.assertEqual(quiet.namespaces, {})
        said = []
        loud = F.SimHost(preexisting=["legit_3"], run_cost_s=teardown_cost)
        X.destroy(loud, ["legit_3"], ["vo_legit_3"], 2.0, said.append)
        self.assertEqual(said, ["teardown: 0 process(es) in 1 namespace(s): listed in 0.20 s, ended in 0.00 s",
                                "teardown: namespaces deleted: legit_3 0.50 s", "teardown: links deleted: vo_legit_3 0.10 s"])

    def test_a_process_that_ignores_term_is_told_in_the_time_it_cost(self):
        plan, _, _ = self.go("C", F.SimHost(faults={"stubborn_nginx": None}), plan_args={"name": "stubborn_nginx/C"})
        text = self.read(plan, "executor.log")
        self.assertRegex(text, r"teardown: 2 process\(es\) in 5 namespace\(s\): listed in 0\.00 s, ended in 2\.\d\d s")

    def test_the_namespaces_processes_are_found_by_namespace(self):
        plan, host, _ = self.go("C")
        asked = {c[2][3] for c in host.ran("ip", "netns", "pids")}
        self.assertEqual(asked, {ns.name for ns in plan.namespaces} | {"server_ns"})

    def test_a_failed_run_is_taken_down_as_a_finished_one_is(self):
        for faults in ({"stream_dies": 1}, {"nginx_fails": None}, {"stream_hangs": 1}):
            with self.subTest(faults=faults):
                host = F.SimHost(faults=faults)
                try:
                    X.execute(self.plan("C", name=f"{min(faults)}/C"), host)
                except X.RunFailed:
                    pass
                self.assertTestbedEmpty(host)


class StagedRunTest(RunCase):
    """A load that steps up in one run, as the capacity probe's does (docs/HG1C_DESIGN.md 8)."""
    LEVELS = (20.0, 40.0, 80.0)
    STEP = 6.0

    def staged_plan(self, name="s", settings=None):
        pop = P.staged("calib", 1, self.LEVELS, self.STEP)
        return X.plan_population(pop, "capacity", "C", 1, os.path.join(self.tmp.name, name, "C"), self.cal, C.PLACEHOLDER,
                                 pop.timeline, settings=bare_settings(**(settings or {})))

    def step_of(self, sid):
        return int(sid[1:3])

    def go_staged(self, host=None, **kw):
        host = host or F.SimHost()
        plan = self.staged_plan(**kw)
        return plan, host, X.execute(plan, host)

    def test_every_step_is_launched_when_it_is_due_and_the_run_is_sound(self):
        plan, host, result = self.go_staged()
        self.assertTrue(result.ok, result.reasons)
        first = min(host.launch_times.values())
        for sid, t in host.launch_times.items():
            self.assertAlmostEqual(t - first, self.step_of(sid) * self.STEP, delta=0.011, msg=sid)
        self.assertEqual(len(host.launch_times), 3 * 29)
        self.assertEqual(self.read(plan, "executor.log").count("launched 29 legit streams"), 3)
        self.assertEqual(self.run_json(plan)["started_utc"], X._utc(F.BASE_EPOCH + first), "the run began with its first step")
        self.assertTestbedEmpty(host)

    def test_the_streams_are_placed_at_their_step_on_the_runs_axis(self):
        plan, _, _ = self.go_staged()
        run = H.read_run(plan.out)
        for s in run["streams"]:                         # the model's start-up grows 2 ms with each stream it has started
            self.assertAlmostEqual(s["offset_s"], self.step_of(s["id"]) * self.STEP, delta=0.2, msg=s["id"])
        self.assertEqual(self.run_json(plan)["executor"]["launch_attack_after_s"], None)

    def test_a_window_reads_one_step_and_the_gate_sees_the_load_of_each(self):
        server = F.SyntheticServer(self.cal, (self.STEP, 0.0, 0.0))
        plan, _, result = self.go_staged(host=F.SimHost(server=server))
        self.assertTrue(result.ok, result.reasons)
        run = H.read_run(plan.out)
        timeline = {"baseline_s": 18.0, "attack_s": 0.1, "recovery_s": 0.1}
        counts = [H.run_metrics(run, self.cal, timeline, window=(k * self.STEP + 1, k * self.STEP + 5))["requests"]
                  for k in range(3)]
        self.assertAlmostEqual(counts[1] / counts[0], 2.0, delta=0.5)
        self.assertAlmostEqual(counts[2] / counts[0], 4.0, delta=1.0)

    def test_a_step_that_starts_late_makes_the_run_unsound_and_is_placed_where_it_began(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + (0.8 if sid.startswith("S01-") else 0.0))
        plan, _, result = self.go_staged(host=host)
        self.assertFalse(result.ok)
        self.assertEqual(len(result.reasons), 1, result.reasons)
        self.assertIn("the legit streams that start at 6 s began +0.80 s from their start", result.reasons[0])
        late = [s["offset_s"] for s in H.read_run(plan.out)["streams"] if s["id"].startswith("S01-")]
        self.assertAlmostEqual(sum(late) / len(late), 6.8, delta=0.06)

    def test_a_step_whose_streams_start_apart_is_unsound_in_its_own_words(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + (0.08 * (index % 30) if sid.startswith("S02-") else 0.0))
        _, _, result = self.go_staged(host=host)
        self.assertFalse(result.ok)
        self.assertTrue(any("the legit streams that start at 12 s began" in r and "s apart" in r for r in result.reasons), result.reasons)

    def test_the_first_step_defines_the_axis_not_the_whole_run(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + (0.3 if sid.startswith("S00-") else 0.0))
        plan, _, result = self.go_staged(host=host)
        self.assertTrue(result.ok, result.reasons)
        offsets = {self.step_of(s["id"]): s["offset_s"] for s in H.read_run(plan.out)["streams"]}
        self.assertAlmostEqual(offsets[1], 6.0 - 0.3, delta=0.06)

    def test_a_stream_of_a_later_step_that_dies_ends_the_run_with_the_earlier_steps_kept(self):
        host = F.SimHost(dies=lambda sid: sid.startswith("S01-"))
        plan, _, result = self.go_staged(host=host)
        self.assertFalse(result.ok)
        self.assertTrue(any("exited with 2" in r for r in result.reasons), result.reasons)
        kept = {self.step_of(s["id"]) for s in H.read_run(plan.out)["streams"]}
        self.assertEqual(kept, {0}, "step 0 had finished; step 1 died and step 2 was never launched")
        self.assertTestbedEmpty(host)
        self.assertLess(host.t, 3 * self.STEP + 2.0 + 10.0)

    def test_a_step_after_a_gap_is_launched_when_it_is_due_and_the_run_waits_for_it(self):
        pop = P.staged("calib", 1, self.LEVELS[:2], self.STEP)
        late = tuple(dataclasses.replace(s, start_s=30.0) if s.id.startswith("S01-") else s for s in pop.streams)
        pop = dataclasses.replace(pop, streams=late, timeline=P.Timeline(36.0, 0.0, 0.0))
        plan = X.plan_population(pop, "capacity", "C", 1, os.path.join(self.tmp.name, "gap", "C"), self.cal, C.PLACEHOLDER,
                                 pop.timeline, settings=bare_settings())
        host = F.SimHost()
        result = X.execute(plan, host)
        self.assertTrue(result.ok, result.reasons)
        first = min(host.launch_times.values())
        self.assertAlmostEqual(max(host.launch_times.values()) - first, 30.0, delta=0.011)
        self.assertEqual(len(host.launch_times), 2 * 29, "the streams of the later step were launched, though none was running")

    def test_the_axis_begins_where_the_first_legit_group_does_whatever_its_start(self):
        plan = self.staged_plan()
        shifted = dataclasses.replace(plan, streams=tuple(dataclasses.replace(s, start_s=s.start_s + 10.0) for s in plan.streams))
        found = {s.id: (100.0 + s.start_s + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0) for s in shifted.streams}
        al = X.alignment(shifted, found)
        self.assertEqual(al["reasons"], [])
        self.assertAlmostEqual(al["zero"], 100.0)
        first = [off for sid, off in al["offsets"].items() if sid.startswith("S00-")]
        self.assertAlmostEqual(first[0], 10.0, msg="its streams are placed 10 s into the run")

    def test_alignment_groups_the_streams_by_their_start(self):
        plan = self.staged_plan()
        found = {}
        for s in plan.streams:
            t0 = 100.0 + s.start_s + (0.2 if s.start_s == 12.0 else 0.0)
            found[s.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0)
        al = X.alignment(plan, found)
        self.assertEqual(al["reasons"], [])
        self.assertAlmostEqual(al["zero"], 100.0)
        self.assertAlmostEqual(al["t0_spread_legit_s"], 0.0, places=9)
        by_step = {self.step_of(sid): off for sid, off in al["offsets"].items()}
        self.assertAlmostEqual(by_step[2], 12.2)
        found = {k: (t + (0.6 if k.startswith("S01-") else 0.0), w, n) for k, (t, w, n) in found.items()}
        al = X.alignment(plan, found)
        self.assertEqual(len(al["reasons"]), 1)
        self.assertIn("began +0.60 s from their start", al["reasons"][0])


class ProcessTableTest(RunCase):
    """What counts as a testbed's process: by what it runs, never by a word anywhere in its command line."""

    def test_what_a_process_runs(self):
        for argv, program in (
                (["nginx:", "master", "process", "/usr/sbin/nginx"], "nginx"),
                (["/usr/sbin/nginx", "-c", "x.conf"], "nginx"),
                (["/v/bin/python", "bench/loadgen.py", "--url", "http://10.0.0.1/"], "loadgen.py"),
                (["python3", "-u", "bench/loadgen.py"], "loadgen.py"),
                (["python", "-m", "gunicorn", "--workers", "2", "origin:app"], "gunicorn"),
                (["python", "-W", "ignore", "-m", "gunicorn", "origin:app"], "gunicorn"),
                (["python", "-X", "dev", "bench/loadgen.py"], "loadgen.py"),
                (["python", "-u", "-W", "error", "/v/bin/gunicorn"], "gunicorn"),
                (["python", "/v/bin/gunicorn", "origin:app"], "gunicorn"),
                (["gunicorn:", "worker", "[origin:app]"], "gunicorn"),
                (["python", "ml/control_plane.py"], "control_plane.py"),
                (["wrk", "-t2", "-c100"], "wrk"),
                (["k6", "run", "x.js"], "k6"),
                (["vim", "bench/loadgen.py"], "vim"),
                (["tail", "-f", "/var/log/nginx/error.log"], "tail"),
                (["sudo", "./venv/bin/python", "bench/executor.py", "run"], "sudo"),
                (["python", "bench/executor.py", "run", "--out", "/var/tmp/gunicorn/nginx/loadgen.py"], "executor.py"),
                (["python3"], "python3")):
            with self.subTest(argv=argv):
                self.assertEqual(X.program_of(argv), program)

    def test_the_programs_of_a_testbed_are_found_and_the_look_of_a_command_line_is_not_enough(self):
        host = F.SimHost()
        host.table_extra = [(901, 1, "nginx: master process /usr/sbin/nginx"), (902, 1, "python -m gunicorn origin:app"),
                            (903, 1, "/v/bin/python bench/loadgen.py --url http://10.0.0.1/"), (904, 1, "wrk -t2 -c10 http://x"),
                            (905, 1, "k6 run s.js"), (906, 1, "hping3 -S 10.0.0.1"),
                            (910, 1, "vim bench/loadgen.py"), (911, 1, "tail -f /var/log/nginx/error.log"),
                            (912, 1, "less gunicorn.log"), (913, 1, "bash -c cd /home/x/gunicorn && ls"),
                            (914, 1, "[kworker/0:1-events]")]
        self.assertEqual(X.process_leftovers(host), ["process nginx pid 901", "process gunicorn pid 902",
                                                     "process loadgen.py pid 903", "process wrk pid 904",
                                                     "process k6 pid 905", "process hping3 pid 906"])

    def test_the_executors_own_command_line_and_its_parents_are_never_a_leftover(self):
        host = F.SimHost()
        self.assertEqual(X.process_leftovers(host), [], "the model's executor has gunicorn, nginx and loadgen.py in its arguments")
        host.table_extra = [(4000, 1, "nginx: master process")]       # the parent, replaced: whatever it runs, it is above us
        self.assertEqual(X.process_leftovers(host), [])
        host.table_extra = [(4001, 4242, "nginx: master process")]     # a child of the executor is not above it
        self.assertEqual(X.process_leftovers(host), ["process nginx pid 4001"])

    def test_a_table_that_cannot_be_read_is_not_a_clean_machine(self):
        host = F.SimHost(faults={"table_unreadable": None})
        with self.assertRaises(X.TableUnreadable) as ctx:
            X.leftovers(host)
        self.assertIn("ps -eo", str(ctx.exception))
        plan = self.plan("C")
        with self.assertRaises(X.TableUnreadable):
            X.execute(plan, host)
        self.assertIn("TableUnreadable", self.failed(plan))
        self.assertEqual(host.prims, [])

    def test_a_listing_of_namespaces_or_links_that_cannot_run_is_not_a_clean_machine(self):
        host = F.SimHost()
        original = host.run
        host.run = lambda argv, *a, **k: X.Result(1, "", "RTNETLINK answers: Operation not permitted") \
            if list(argv[:2]) in (["ip", "netns"], ["ip", "-br"]) else original(argv, *a, **k)
        with self.assertRaises(X.TableUnreadable):
            X.leftovers(host)

    def test_a_teardown_that_cannot_look_is_a_failure(self):
        host = F.SimHost()
        plan = self.plan("C")
        original = host.run

        def unreadable_at_the_end(argv, *a, **k):
            if list(argv[:1]) == ["ps"] and host.t > 20.0:
                return X.Result(1, "", "ps: gone")
            return original(argv, *a, **k)
        host.run = unreadable_at_the_end
        with self.assertRaises(X.TableUnreadable):
            X.execute(plan, host)
        self.assertTrue(os.path.exists(os.path.join(plan.out, "run.json")))


class ProvenanceTest(RunCase):
    def test_the_files_the_result_depends_on_are_hashed(self):
        plan, _, _ = self.go("U")
        prov = json.loads(self.read(plan, "environment.json"))["provenance"]
        for name, digest in prov["files"].items():
            self.assertEqual(digest, X.sha256_file(os.path.join(REPO, "bench", name)), name)
        self.assertEqual(sorted(prov["files"]), sorted(X.PROVENANCE_FILES))
        self.assertEqual(prov["nginx_source_sha256"], X.sha256_file(X.NGINX_CONF))
        self.assertEqual(prov["nginx_rendered_sha256"], plan.nginx_conf_sha256)
        self.assertNotEqual(prov["nginx_source_sha256"], prov["nginx_rendered_sha256"], "two log paths differ")
        self.assertTrue(prov["engine_is_pinned"])
        self.assertEqual(prov["engine_pinned_sha256"], prov["files"]["loadgen.py"])

    def test_the_stack_as_started_is_read_back(self):
        plan, _, _ = self.go("C", F.SimHost(nofile=(524288, 524288)))
        stack = json.loads(self.read(plan, "environment.json"))["stack"]
        self.assertEqual(stack["origin"], {"processes": 1, "cpus_allowed": ["0-1"], "nofile_soft_hard": [[524288, 524288]]})
        self.assertEqual(stack["nginx"], {"processes": 2, "cpus_allowed": ["0-1"], "nofile_soft_hard": [[524288, 524288]]})

    def test_a_stack_that_never_came_up_has_no_stack_record_but_still_has_its_provenance(self):
        host = F.SimHost(faults={"nginx_fails": None})
        plan = self.plan("C")
        with self.assertRaises(X.SetupFailed):
            X.execute(plan, host)
        env = json.loads(self.read(plan, "environment.json"))
        self.assertNotIn("stack", env)
        self.assertIn("provenance", env)

    def test_an_engine_that_is_not_the_one_the_manifest_pins_is_said_not_to_be(self):
        plan = self.plan("C")
        manifest = X.LT.load_manifest()
        manifest["tools"]["loadgen"]["sha256"] = "0" * 64
        with mock.patch.object(X.LT, "load_manifest", return_value=manifest):
            prov = X.provenance(plan)
        self.assertFalse(prov["engine_is_pinned"])
        self.assertEqual(prov["engine_pinned_sha256"], "0" * 64)

    def test_the_limit_rows_are_read_by_name(self):
        text = ("Limit                     Soft Limit           Hard Limit           Units     \n"
                "Max open files            1024                 524288               files     \n"
                "Max locked memory         unlimited            unlimited            bytes     \n")
        self.assertEqual(X._limit(text, "Max open files"), [1024, 524288])
        self.assertEqual(X._limit(text, "Max locked memory"), ["unlimited", "unlimited"])
        self.assertIsNone(X._limit(text, "Max stack size"))


class PackTest(unittest.TestCase):
    """The most streams that began within the limit of one another: the rest are the stragglers."""

    def test_the_pack_is_the_most_streams_within_the_limit_of_one_another(self):
        pack, out = X.pack_of({"a": 0.0, "b": 0.1, "c": 0.2, "d": 5.0, "e": 9.0}, 0.5)
        self.assertEqual((pack, out), (["a", "b", "c"], ["d", "e"]))

    def test_the_limit_is_inclusive(self):
        self.assertEqual(X.pack_of({"a": 1.0, "b": 1.5}, 0.5), (["a", "b"], []))
        pack, out = X.pack_of({"a": 1.0, "b": 1.51}, 0.5)
        self.assertEqual(len(pack), 1)
        self.assertEqual(len(out), 1)

    def test_streams_on_both_sides_of_the_pack_are_outside_it(self):
        times = {"early": -3.0, **{f"p{i}": 0.01 * i for i in range(5)}, "late": 4.0}
        self.assertEqual(X.pack_of(times, 0.5), ([f"p{i}" for i in range(5)], ["early", "late"]))

    def test_of_two_packs_of_one_size_the_one_nearer_the_median_is_taken(self):
        pack, out = X.pack_of({"a": 0.0, "b": 0.1, "c": 2.0, "d": 2.1, "e": 4.0}, 0.5)
        self.assertEqual((pack, out), (["c", "d"], ["a", "b", "e"]))

    def test_streams_that_began_together_are_a_pack_and_ties_go_by_id(self):
        self.assertEqual(X.pack_of({"b": 1.0, "a": 1.0, "c": 1.0}, 0.0), (["a", "b", "c"], []))
        self.assertEqual(X.pack_of({"only": 7.0}, 0.5), (["only"], []))

    def test_the_pack_and_the_rest_are_in_the_order_of_their_starts(self):
        pack, out = X.pack_of({"z": 0.0, "y": 0.2, "x": -9.0, "w": 9.0, "v": 0.1}, 0.5)
        self.assertEqual((pack, out), (["z", "v", "y"], ["x", "w"]))


class EstimatorTest(RunCase):
    """The clocks of the streams, from what they report (docs/HG1C_DESIGN.md 6.6)."""

    def found(self, plan, legit=0.0, attack=None, wall=40.0, intended=100):
        """What the streams would report if the legit ones began at `legit(stream)` and the attack ones at `attack(stream)`
        on the executor's clock."""
        out = {}
        for i, s in enumerate(plan.streams):
            t0 = (legit(i) if callable(legit) else legit) if s.kind == "legit" else \
                (attack(i) if callable(attack) else attack)
            out[s.id] = (t0 + wall - X.ENGINE_T0_OFFSET_S + plan.settings["exit_delay_per_request_s"] * intended, wall, intended)
        return out

    def test_the_estimate_is_the_exit_less_the_wall_time_plus_the_engines_zero(self):
        self.assertAlmostEqual(X.estimate_t0(100.0, 40.0), 60.05)

    def test_the_part_of_the_exit_delay_that_grows_with_the_requests_is_taken_off(self):
        self.assertAlmostEqual(X.estimate_t0(100.0, 40.0, intended=1000, per_request_s=0.0002), 60.05 - 0.2)
        self.assertAlmostEqual(X.estimate_t0(100.0, 40.0, intended=1000), 60.05)

    def test_offsets_are_from_the_median_legit_start(self):
        plan = self.plan("U")
        al = X.alignment(plan, self.found(plan, legit=lambda i: 100.0 + 0.001 * (i % 5), attack=110.0))
        legit = [al["offsets"][s.id] for s in plan.streams if s.kind == "legit"]
        self.assertEqual(sorted(legit)[len(legit) // 2], 0.0 if len(legit) % 2 else sorted(legit)[len(legit) // 2])
        self.assertAlmostEqual(al["zero"], 100.002, places=3)
        self.assertAlmostEqual(al["t0_spread_legit_s"], 0.004, places=6)
        self.assertEqual(al["reasons"], [])

    def test_the_run_is_unsound_when_the_legit_starts_are_further_apart_than_the_limit_and_no_straggler_is_allowed(self):
        plan = self.plan("C", settings={"straggler_share": 0.0})
        near = X.alignment(plan, self.found(plan, legit=lambda i: 100.0 + (0.5 if i == 3 else 0.0)))
        far = X.alignment(plan, self.found(plan, legit=lambda i: 100.0 + (0.51 if i == 3 else 0.0)))
        self.assertEqual(near["reasons"], [])
        self.assertEqual(len(far["reasons"]), 1)
        self.assertIn("apart", far["reasons"][0])

    def test_the_attack_start_error_is_against_the_end_of_the_baseline_on_the_legit_axis(self):
        plan = self.plan("U")
        base = plan.timeline["baseline_s"]
        for shift, sound in ((0.0, True), (0.49, True), (-0.49, True), (0.51, False), (-0.51, False)):
            with self.subTest(shift=shift):
                al = X.alignment(plan, self.found(plan, legit=100.0, attack=100.0 + base + shift))
                self.assertAlmostEqual(al["attack_start_error_s"], shift, places=6)
                self.assertEqual(al["reasons"] == [], sound)
                if not sound:
                    self.assertIn(f"{shift:+.2f} s", al["reasons"][0])

    def test_an_attack_run_with_no_attack_report_is_unsound_and_a_control_has_no_attack_error(self):
        plan = self.plan("U")
        found = {k: v for k, v in self.found(plan, legit=100.0, attack=110.0).items() if not k.startswith("A-")}
        al = X.alignment(plan, found)
        self.assertEqual(al["reasons"], ["no attack stream reported"])
        control = self.plan("C", name="ctl/C")
        al = X.alignment(control, self.found(control, legit=100.0))
        self.assertIsNone(al["attack_start_error_s"])
        self.assertEqual(al["reasons"], [])

    def test_with_several_attack_starts_the_worst_error_is_reported(self):
        plan = self.plan("U")
        base = plan.timeline["baseline_s"]
        attack = [x for x in plan.streams if x.kind == "attack"]
        streams = tuple(dataclasses.replace(x, start_s=base + 10.0) if x in attack[2:] else x for x in plan.streams)
        plan = dataclasses.replace(plan, streams=streams)
        found = {}
        for x in plan.streams:
            t0 = 100.0 + (0.0 if x.kind == "legit" else x.start_s + (0.1 if x.start_s == base else -0.4))
            found[x.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 100)
        al = X.alignment(plan, found)
        self.assertAlmostEqual(al["attack_start_error_s"], -0.4)
        self.assertEqual(al["reasons"], [])

    def test_no_legit_report_is_no_alignment(self):
        plan = self.plan("U")
        al = X.alignment(plan, {})
        self.assertEqual(al["reasons"], ["no legit stream reported"])
        self.assertEqual(al["offsets"], {})

    def test_a_delay_common_to_every_stream_cancels(self):
        plan = self.plan("U")
        a = X.alignment(plan, self.found(plan, legit=lambda i: 100.0 + 0.01 * (i % 3), attack=110.1))
        shifted = {k: (t + 0.7, w, n) for k, (t, w, n) in self.found(plan, legit=lambda i: 100.0 + 0.01 * (i % 3),
                                                                      attack=110.1).items()}
        b = X.alignment(plan, shifted)
        for sid, off in a["offsets"].items():
            self.assertAlmostEqual(off, b["offsets"][sid], places=9)
        self.assertAlmostEqual(a["attack_start_error_s"], b["attack_start_error_s"], places=9)

    def test_the_limits_are_the_plans_settings(self):
        plan = self.plan("C", settings={"t0_spread_limit_s": 0.05, "straggler_share": 0.0})
        al = X.alignment(plan, self.found(plan, legit=lambda i: 100.0 + (0.06 if i == 0 else 0.0)))
        self.assertEqual(len(al["reasons"]), 1)


class ConsistentWallTest(unittest.TestCase):
    """The wall time an engine reports, held to what its records allow (S1b: bench/loadgen.py reads the schedule's zero and, one
    statement later, its wall clock; a process descheduled in between reports too short a wall time)."""

    def test_a_wall_time_that_holds_the_records_stands(self):
        self.assertEqual(X.consistent_wall(40.0, 39.0), 40.0)
        self.assertEqual(X.consistent_wall(40.0, 39.9), 40.0)

    def test_the_wall_time_is_at_least_the_last_done_plus_the_engines_offset(self):
        self.assertAlmostEqual(X.consistent_wall(40.0, 39.96), 40.01)
        self.assertEqual(X.consistent_wall(40.0, 39.95), 40.0, "at the limit nothing changes")
        self.assertAlmostEqual(X.consistent_wall(27.29, 29.28), 29.33)

    def test_without_a_finished_request_the_wall_time_stands(self):
        self.assertEqual(X.consistent_wall(12.0, None), 12.0)

    def test_the_stream_of_s1b_run_1_that_began_two_seconds_before_the_rest_is_put_where_it_began(self):
        # the numbers of L-poisson-C3-broadband-1 in s1b_1: exit 29.500 s after the first launch, wall time 27.2925 s, last request
        # done 29.2767 s after its zero; the origin saw its first request at a zero of 0.206 s
        exit_s, wall, last = 29.500, 27.2925, 29.2767
        self.assertAlmostEqual(X.estimate_t0(exit_s, wall), 2.2575, places=4)
        self.assertAlmostEqual(X.estimate_t0(exit_s, X.consistent_wall(wall, last)), 0.2233, places=4)


class LastDoneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def records(self, done, header=F.RECORD_HEADER, name="records"):
        path = os.path.join(self.tmp.name, f"{name}.csv.gz")
        with gzip.open(path, "wt", newline="") as fh:
            fh.write(header)
            for i, t in enumerate(done):
                fh.write(f"{i},{i}.0,{i}.0,{t},200,100,,0,1\n")
        return path

    def test_it_is_the_largest_t_done_whatever_the_order(self):
        self.assertEqual(X.last_done(self.records(["3.5", "29.25", "7.0"])), 29.25)

    def test_requests_that_never_finished_are_not_counted(self):
        self.assertEqual(X.last_done(self.records(["3.5", "nan", "inf", "-inf", "9.5", "nan"])), 9.5)

    def test_no_finished_request_is_none(self):
        self.assertIsNone(X.last_done(self.records([])))
        self.assertIsNone(X.last_done(self.records(["nan", "nan"])))

    def test_what_cannot_be_read_raises_one_of_the_unreadable_errors(self):
        path = self.records(["1.0"])
        with open(path, "rb") as fh:
            whole = fh.read()
        broken = {"missing": os.path.join(self.tmp.name, "nothing.csv.gz"),
                  "not gzip": self.write_bytes(b"this is not a gzip file"),
                  "cut off": self.write_bytes(whole[: len(whole) // 2]),
                  "empty": self.empty(),
                  "no t_done column": self.records(["1.0"], header="i,t_intended,t_sent\n", name="no_column"),
                  "a short row": self.short_row(),
                  "not a number": self.records(["fast"], name="not_a_number")}
        for name, bad in broken.items():
            with self.subTest(name), self.assertRaises(X.RECORDS_UNREADABLE):
                X.last_done(bad)

    def test_the_first_send_is_the_first_finite_t_sent_and_a_file_that_cannot_be_read_has_none(self):
        path = os.path.join(self.tmp.name, "sent.csv.gz")
        with gzip.open(path, "wt", newline="") as fh:
            fh.write(F.RECORD_HEADER + "0,1.0,nan,nan,0,0,dropped,0,0\n1,2.0,2.5,2.6,200,1,,0,1\n2,3.0,3.5,3.6,200,1,,0,1\n")
        self.assertEqual(X._first_sent(path), 2.5)
        with open(path, "rb") as fh:
            whole = fh.read()
        self.assertIsNone(X._first_sent(self.write_bytes(whole[: len(whole) // 2])), "a file cut short: EOFError, not an exception")
        self.assertIsNone(X._first_sent(self.write_bytes(b"this is not a gzip file")))
        self.assertIsNone(X._first_sent(os.path.join(self.tmp.name, "nothing.csv.gz")))
        self.assertIsNone(X._first_sent(self.empty()))

    def empty(self):
        path = os.path.join(self.tmp.name, "empty.csv.gz")
        gzip.open(path, "wt").close()
        return path

    def write_bytes(self, data):
        path = os.path.join(self.tmp.name, f"{len(data)}.csv.gz")
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def short_row(self):
        path = os.path.join(self.tmp.name, "short.csv.gz")
        with gzip.open(path, "wt", newline="") as fh:
            fh.write(F.RECORD_HEADER + "0,1.0\n")
        return path


class LeftOutputTest(RunCase):
    def test_an_engine_has_left_its_output_when_it_left_its_summary_and_its_records(self):
        stream = self.plan("C").streams[0]
        os.makedirs(stream.workdir)
        self.assertFalse(X.left_output(stream))
        with open(stream.summary, "w", encoding="utf-8") as fh:
            fh.write("{}")
        self.assertFalse(X.left_output(stream), "the records are missing")
        with open(stream.records, "wb") as fh:
            fh.write(b"")
        self.assertTrue(X.left_output(stream))
        os.remove(stream.summary)
        self.assertFalse(X.left_output(stream), "the summary is missing")


class CollectTest(RunCase):
    """collect() on files like the engines leave, with their exit times given: what the executor makes of them."""

    def leave(self, plan, stall=None, zero=None, last=None, exit_delay=0.02, nan_done=(), skip_records=(), tail=None):
        """Every stream of `plan` as an engine leaves it. Stream i began at `zero(i)` on the executor's clock, its last request was
        done `last(i)` s later, its loop ended `tail(i)` s after that and it exited `exit_delay` s after; `stall(i)` is how long it was
        descheduled between reading the schedule's zero and its wall clock, which makes its wall time that much short. Returns the
        processes."""
        stall, zero, tail = stall or (lambda i: 0.0), zero or (lambda i: 100.0), tail or (lambda i: 0.0)
        last = last or (lambda i: 25.0 + 0.5 * (i % 5))
        procs = {}
        for i, st in enumerate(plan.streams):
            os.makedirs(st.workdir, exist_ok=True)
            done = last(i)
            with open(st.summary, "w", encoding="utf-8") as fh:
                json.dump({"wall_s": done + X.ENGINE_T0_OFFSET_S + tail(i) - stall(i), "intended": 3}, fh)
            if i not in skip_records:
                with gzip.open(st.records, "wt", newline="") as fh:
                    fh.write(F.RECORD_HEADER)
                    for k, t in enumerate((0.5, 1.5, done)):
                        shown = "nan" if i in nan_done else format(t if t == done else t + 0.01, ".6f")
                        fh.write(f"{k},{t:.6f},{t:.6f},{shown},200,100,,0,1\n")
            procs[st.id] = types.SimpleNamespace(poll=lambda: 0, exit_time=zero(i) + done + tail(i) + exit_delay)
        return procs

    def collect(self, plan, procs):
        return X.collect(plan, procs, {"legit": 100.0}, [])

    def test_streams_whose_wall_times_hold_their_records_are_placed_together_and_left_alone(self):
        plan = self.plan("C")
        block, _, zero = self.collect(plan, self.leave(plan))
        self.assertTrue(block["ok"], block["reasons"])
        self.assertEqual(set(block["wall_gap_s"].values()), {0.0})
        self.assertEqual(set(block["wall_gap_s"]), {s.id for s in plan.streams})
        self.assertAlmostEqual(zero, 100.02 - 3 * X.SETTINGS["exit_delay_per_request_s"], places=6)
        self.assertLess(block["t0_spread_legit_s"], 1e-9)
        self.assertEqual(block["estimator"], "exit-minus-consistent-wall")

    def test_an_engine_that_was_descheduled_is_put_where_its_loop_began_and_the_gap_is_recorded(self):
        plan = self.plan("C")
        block, rows, _ = self.collect(plan, self.leave(plan, stall=lambda i: 2.0 if i == 3 else 0.0))
        stalled = plan.streams[3].id
        self.assertTrue(block["ok"], block["reasons"])
        self.assertAlmostEqual(block["wall_gap_s"][stalled], 2.0, places=4)
        self.assertEqual({v for k, v in block["wall_gap_s"].items() if k != stalled}, {0.0})
        self.assertEqual({r["id"]: r["offset_s"] for r in rows}[stalled], 0.0)
        self.assertLess(block["t0_spread_legit_s"], 1e-9)

    def test_an_engine_that_really_began_early_is_a_straggler_placed_where_it_began(self):
        plan = self.plan("C")
        block, rows, _ = self.collect(plan, self.leave(plan, stall=lambda i: 2.0 if i == 3 else 0.0,
                                                        zero=lambda i: 98.0 if i == 3 else 100.0))
        self.assertTrue(block["ok"], block["reasons"])
        self.assertEqual(block["stragglers"], [{"id": plan.streams[3].id, "offset_s": -2.0, "from_pack_s": -2.0, "tail_s": 0.0}])
        self.assertAlmostEqual({r["id"]: r["offset_s"] for r in rows}[plan.streams[3].id], -2.0, places=4)
        self.assertLess(block["t0_spread_legit_s"], 1e-9, "the pack")
        self.assertAlmostEqual(block["t0_range_legit_s"], 2.0, places=4, msg="all the legit starts")

    def test_more_early_engines_than_the_share_allows_make_the_run_unsound(self):
        plan = self.plan("C", settings={"straggler_share": 0.1})
        early = {3, 4, 5}
        block, rows, _ = self.collect(plan, self.leave(plan, zero=lambda i: 98.0 if i in early else 100.0))
        self.assertFalse(block["ok"])
        self.assertEqual(block["reasons"], ["the legit streams began 2.00 s apart (limit 0.5 s; 3 of 29 are outside the pack, at most 2 may be)"])
        self.assertEqual([s["id"] for s in block["stragglers"]], sorted(plan.streams[i].id for i in early))
        self.assertEqual({r["offset_s"] for r in rows if r["id"] in {s["id"] for s in block["stragglers"]}}, {-2.0})

    def test_an_early_engine_whose_loop_ended_long_after_its_last_request_cannot_be_placed(self):
        plan = self.plan("C")
        procs = self.leave(plan, zero=lambda i: 98.0 if i == 3 else 100.0, tail=lambda i: 0.8 if i == 3 else 0.0)
        block, _, _ = self.collect(plan, procs)
        self.assertFalse(block["ok"])
        self.assertEqual(block["reasons"], [(f"legit stream {plan.streams[3].id} began -2.00 s from the others and its loop ended 0.80 s "
                                             "after its last request, so where it began cannot be told (limit 0.1 s)")])
        self.assertEqual(block["stragglers"][0]["tail_s"], 0.8)

    def test_the_tail_a_straggler_may_have_is_the_settings(self):
        plan = self.plan("C")
        for tail, sound in ((0.09, True), (0.1, True), (0.11, False)):
            with self.subTest(tail=tail):
                block, _, _ = self.collect(plan, self.leave(plan, zero=lambda i: 98.0 if i == 3 else 100.0,
                                                            tail=lambda i, tail=tail: tail if i == 3 else 0.0))
                self.assertEqual(block["ok"], sound, block["reasons"])
        loose = self.plan("C", name="loose/C", settings={"straggler_tail_s": 1.0})
        block, _, _ = self.collect(loose, self.leave(loose, zero=lambda i: 98.0 if i == 3 else 100.0, tail=lambda i: 0.8 if i == 3 else 0.0))
        self.assertTrue(block["ok"], block["reasons"])

    def test_a_straggler_that_finished_no_request_has_nothing_to_place_and_is_tolerated(self):
        plan = self.plan("C")
        block, _, _ = self.collect(plan, self.leave(plan, zero=lambda i: 98.0 if i == 4 else 100.0, nan_done=(4,)))
        self.assertTrue(block["ok"], block["reasons"])
        self.assertEqual([(x["id"], x["tail_s"]) for x in block["stragglers"]], [(plan.streams[4].id, 0.0)])

    def test_a_long_tail_in_the_pack_is_no_matter(self):
        plan = self.plan("C")
        block, _, _ = self.collect(plan, self.leave(plan, tail=lambda i: 0.8 if i == 3 else 0.0))
        self.assertTrue(block["ok"], block["reasons"])
        self.assertEqual(block["stragglers"], [])

    def test_without_the_correction_the_stalled_stream_is_a_straggler_placed_two_seconds_late(self):
        plan = self.plan("C")
        procs = self.leave(plan, stall=lambda i: 2.0 if i == 3 else 0.0)
        with mock.patch.object(X, "consistent_wall", lambda wall, last: wall):
            block, rows, _ = self.collect(plan, procs)
        # the rule tolerates one straggler and cannot tell a stream that began late from one that only reported a short wall time
        self.assertTrue(block["ok"], block["reasons"])
        self.assertAlmostEqual(block["stragglers"][0]["from_pack_s"], 2.0, places=4)
        self.assertAlmostEqual({r["id"]: r["offset_s"] for r in rows}[plan.streams[3].id], 2.0, places=4, msg="where it was not")

    def test_the_correction_does_not_depend_on_when_the_last_request_was_done(self):
        plan = self.plan("C")
        block, rows, _ = self.collect(plan, self.leave(plan, last=lambda i: 3.0 + 4.0 * i, stall=lambda i: 1.0 if i % 2 else 0.0))
        self.assertTrue(block["ok"], block["reasons"])
        self.assertLess(block["t0_spread_legit_s"], 1e-9)
        self.assertEqual({r["offset_s"] for r in rows}, {0.0})

    def test_records_that_cannot_be_read_leave_the_stream_out_and_the_run_unsound(self):
        plan = self.plan("C")
        procs = self.leave(plan)
        with open(plan.streams[5].records, "wb") as fh:
            fh.write(b"not a gzip file")
        block, rows, _ = self.collect(plan, procs)
        self.assertFalse(block["ok"])
        self.assertIn(f"stream {plan.streams[5].id}: unreadable records", block["reasons"])
        self.assertNotIn(plan.streams[5].id, {r["id"] for r in rows})
        self.assertNotIn(plan.streams[5].id, block["wall_gap_s"])
        self.assertEqual(len(rows), 28)

    def test_records_in_which_no_request_finished_leave_the_wall_time_as_it_is(self):
        plan = self.plan("C")
        block, rows, _ = self.collect(plan, self.leave(plan, nan_done=(4,)))
        self.assertTrue(block["ok"], block["reasons"])
        self.assertEqual(block["wall_gap_s"][plan.streams[4].id], 0.0)
        self.assertEqual(len(rows), 29)

    def test_a_stream_without_records_is_left_out_as_one_without_output(self):
        plan = self.plan("C")
        procs = self.leave(plan, skip_records=(2,))
        block, _, _ = self.collect(plan, procs)
        self.assertFalse(block["ok"])
        self.assertTrue(any(f"stream {plan.streams[2].id} left no output" in r for r in block["reasons"]), block["reasons"])


class DescheduledEngineTest(RunCase):
    """A whole run on the simulated host in which one engine was descheduled between its two clock readings (S1b)."""

    def offset(self, plan, sid):
        return {s["id"]: s["offset_s"] for s in self.run_json(plan)["streams"]}[sid]

    def run_with(self, late=2.0, correct=True, name="C"):
        busiest = max((st for st in self.plan("C", name="look/C").streams if st.kind == "legit"), key=lambda st: st.rate).id
        host = F.SimHost(wall_late_s=lambda sid, index, kind: late if sid == busiest else 0.0)
        if correct:
            plan, _, result = self.go("C", host, plan_args={"name": name})
        else:
            with mock.patch.object(X, "consistent_wall", lambda wall, last: wall):
                plan, _, result = self.go("C", host, plan_args={"name": name})
        return plan, result, busiest

    def test_the_correction_keeps_the_run_sound_and_puts_the_stream_with_the_others(self):
        plan, result, busiest = self.run_with()
        self.assertTrue(result.ok, result.reasons)
        run = self.run_json(plan)
        base, _, _ = self.run_with(late=0.0, name="base/C")
        self.assertAlmostEqual(self.offset(plan, busiest), self.offset(base, busiest), places=6, msg="where it is without the stall")
        gap = run["executor"]["wall_gap_s"]
        self.assertAlmostEqual(gap[busiest], 2.0, places=3, msg="the engine's wall time was 2 s short, and the records say so")
        self.assertEqual(sum(v > 0.05 for v in gap.values()), 1)

    def test_the_run_log_says_which_wall_times_were_raised_and_by_how_much(self):
        plan, _, _ = self.run_with()
        self.assertIn("wall time of 1 stream(s) raised to what their records need, by up to 2.00 s", self.read(plan, "executor.log"))

    def test_the_log_counts_the_streams_and_names_the_largest_gap(self):
        plan0 = self.plan("C", name="look/C")
        busy = sorted((st for st in plan0.streams if st.kind == "legit"), key=lambda st: -st.rate)[:2]
        late = {busy[0].id: 3.0, busy[1].id: 2.0}
        host = F.SimHost(wall_late_s=lambda sid, index, kind: late.get(sid, 0.0))
        plan, _, _ = self.go("C", host)
        gaps = self.run_json(plan)["executor"]["wall_gap_s"]
        raised = sorted(v for v in gaps.values() if v > X.WALL_GAP_NOTE_S)
        self.assertEqual(len(raised), 2, gaps)
        self.assertLess(raised[0], raised[1] - 0.2, "the two gaps differ")
        self.assertIn(f"wall time of 2 stream(s) raised to what their records need, by up to {raised[1]:.2f} s", self.read(plan, "executor.log"))

    def test_the_log_mentions_a_gap_from_fifty_milliseconds_and_not_below(self):
        said = []
        for late in (0.03, 0.07):
            plan, _, _ = self.run_with(late=late, name=f"late{late}/C")
            said.append("raised to what their records need" in self.read(plan, "executor.log"))
        self.assertEqual(said, [False, True])

    def test_a_run_without_such_an_engine_does_not_mention_it(self):
        plan, _, _ = self.go("C")
        self.assertNotIn("raised to what their records need", self.read(plan, "executor.log"))

    def test_without_the_correction_the_stream_would_be_a_straggler_placed_two_seconds_late(self):
        plan, result, busiest = self.run_with(correct=False)
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual([s["id"] for s in self.run_json(plan)["executor"]["stragglers"]], [busiest])
        base, _, _ = self.run_with(late=0.0, name="base/C")
        self.assertAlmostEqual(self.offset(plan, busiest) - self.offset(base, busiest), 2.0, delta=0.01)    # the median start may move a rank


class StragglersAllowedTest(unittest.TestCase):
    def test_it_is_the_whole_number_in_the_share_of_the_group(self):
        for n, share, allowed in ((9, 0.1, 0), (10, 0.1, 1), (19, 0.1, 1), (20, 0.1, 2), (29, 0.1, 2), (30, 0.1, 3), (31, 0.1, 3),
                                  (29, 0.0, 0), (5, 0.5, 2), (29, 0.4, 11), (29, 0.48, 13)):
            with self.subTest(streams=n, share=share):
                self.assertEqual(X.stragglers_allowed(n, share), allowed)

    def test_it_is_never_half_of_the_group_or_more_whatever_the_share(self):
        """The pack is a majority: the group's zero is then the median of more than half of its streams and not of a tie."""
        for n, share, allowed in ((29, 0.5, 14), (29, 1.0, 14), (30, 0.5, 14), (30, 1.0, 14), (4, 0.5, 1), (4, 1.0, 1), (3, 0.5, 1),
                                  (3, 1.0, 1), (2, 0.5, 0), (2, 1.0, 0), (1, 1.0, 0), (0, 1.0, 0), (5, 1.0, 2), (6, 1.0, 2),
                                  (7, 1.0, 3)):
            with self.subTest(streams=n, share=share):
                self.assertEqual(X.stragglers_allowed(n, share), allowed)

    def test_a_product_a_hair_under_a_whole_number_counts_as_that_number(self):
        self.assertLess(0.29 * 100, 29)
        self.assertEqual(X.stragglers_allowed(100, 0.29), 29)
        self.assertLess(0.35 * 180, 63)
        self.assertEqual(X.stragglers_allowed(180, 0.35), 63)


class StragglerRuleTest(RunCase):
    """At most `straggler_share` of the legit streams of a group may begin outside the limit of the others (docs/HG1C_DESIGN.md 14)."""

    @staticmethod
    def trimmed(plan, n):
        """The plan with its first n legit streams only."""
        return dataclasses.replace(plan, streams=tuple(plan.streams[:n]))

    def found(self, plan, early=(), late=(), base=100.0):
        out = {}
        for i, st in enumerate(plan.streams):
            t0 = base + (-2.0 if i in early else 1.5 if i in late else 0.01 * (i % 3))
            out[st.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S + plan.settings["exit_delay_per_request_s"] * 100, 40.0, 100)
        return out

    def test_one_early_stream_of_29_is_a_straggler_and_the_run_is_sound(self):
        plan = self.plan("C")
        al = X.alignment(plan, self.found(plan, early={3}))
        self.assertEqual(al["reasons"], [])
        self.assertEqual([x["id"] for x in al["stragglers"]], [plan.streams[3].id])
        self.assertLess(al["t0_spread_legit_s"], 0.05, "the pack")
        self.assertAlmostEqual(al["t0_range_legit_s"], 2.02, places=6, msg="all the legit starts")
        self.assertAlmostEqual(al["offsets"][plan.streams[3].id], -2.0, delta=0.02)

    def test_the_number_allowed_is_the_floor_of_the_share_of_the_group(self):
        base = self.plan("C", settings={"straggler_share": 0.1})
        for n, allowed in ((9, 0), (10, 1), (19, 1), (20, 2), (29, 2)):
            plan = self.trimmed(base, n)
            for count in (allowed, allowed + 1):
                with self.subTest(streams=n, stragglers=count):
                    al = X.alignment(plan, self.found(plan, early=set(range(count))))
                    self.assertEqual(al["reasons"] == [], count <= allowed, al["reasons"])
                    self.assertEqual(len(al["stragglers"]), count)

    def test_the_share_is_the_plans_setting(self):
        for share, sound in ((0.0, False), (0.05, True), (0.1, True), (0.2, True)):
            plan = self.plan("C", name=f"s{share}/C", settings={"straggler_share": share})
            al = X.alignment(plan, self.found(plan, early={1, 2}))
            self.assertEqual(al["reasons"] == [], sound if share != 0.05 else False, (share, al["reasons"]))
        five = self.plan("C", name="five/C", settings={"straggler_share": 0.2})
        self.assertEqual(X.alignment(five, self.found(five, early={0, 1, 2, 3, 4}))["reasons"], [])
        self.assertEqual(len(X.alignment(five, self.found(five, early={0, 1, 2, 3, 4, 5}))["reasons"]), 1)

    def test_stragglers_on_both_sides_are_counted_together(self):
        plan = self.plan("C", settings={"straggler_share": 0.1, "t0_range_limit_s": 10.0})
        self.assertEqual(X.alignment(plan, self.found(plan, early={1}, late={2}))["reasons"], [])
        al = X.alignment(plan, self.found(plan, early={1}, late={2, 3}))
        self.assertEqual(len(al["reasons"]), 1)
        self.assertIn("3 of 29 are outside the pack, at most 2 may be", al["reasons"][0])
        self.assertEqual(sorted(round(x["from_pack_s"], 1) for x in al["stragglers"]), [-2.0, 1.5, 1.5])

    def test_the_reason_without_a_share_is_the_old_one(self):
        plan = self.plan("C", settings={"straggler_share": 0.0})
        al = X.alignment(plan, self.found(plan, late={4}))
        self.assertEqual(al["reasons"], ["the legit streams began 1.50 s apart (limit 0.5 s)"])

    def test_a_straggler_is_recorded_with_its_offset_its_distance_from_the_pack_and_its_tail(self):
        plan = self.plan("C")
        sid = plan.streams[3].id
        al = X.alignment(plan, self.found(plan, early={3}), {sid: 0.04, plan.streams[0].id: 0.9})
        (straggler,) = al["stragglers"]
        self.assertEqual(set(straggler), {"id", "offset_s", "from_pack_s", "tail_s"})
        self.assertEqual((straggler["id"], straggler["tail_s"]), (sid, 0.04))
        self.assertAlmostEqual(straggler["from_pack_s"], -2.01, delta=0.01)
        self.assertAlmostEqual(straggler["offset_s"], al["offsets"][sid], places=3)
        self.assertEqual(al["reasons"], [], "a long tail in the pack is no matter")

    def test_a_straggler_whose_loop_outlived_its_last_request_by_more_than_the_setting_cannot_be_placed(self):
        plan = self.plan("C")
        sid = plan.streams[3].id
        for tail, sound in ((0.0, True), (0.1, True), (0.1001, False), (5.0, False)):
            with self.subTest(tail=tail):
                al = X.alignment(plan, self.found(plan, early={3}), {sid: tail})
                self.assertEqual(al["reasons"] == [], sound, al["reasons"])
        al = X.alignment(plan, self.found(plan, early={3}), {sid: 0.5})
        self.assertEqual(len(al["reasons"]), 1)
        self.assertIn(f"legit stream {sid} began -2.01 s from the others and its loop ended 0.50 s after its last request", al["reasons"][0])

    def test_when_there_are_too_many_stragglers_the_tails_are_not_asked_about(self):
        plan = self.plan("C", settings={"straggler_share": 0.1})
        al = X.alignment(plan, self.found(plan, early={1, 2, 3}), {plan.streams[1].id: 5.0})
        self.assertEqual(len(al["reasons"]), 1)
        self.assertIn("apart", al["reasons"][0])

    def test_every_straggler_is_asked_about_its_tail_however_many_there_are(self):
        plan = self.plan("C")
        early = set(range(1, 11))
        al = X.alignment(plan, self.found(plan, early=early), {plan.streams[4].id: 0.5, plan.streams[5].id: 0.1})
        self.assertEqual(len(al["stragglers"]), 10)
        self.assertEqual(len(al["reasons"]), 1, al["reasons"])
        self.assertIn(f"legit stream {plan.streams[4].id} began", al["reasons"][0])
        self.assertIn("its loop ended 0.50 s after its last request", al["reasons"][0])

    def test_the_zero_is_the_median_of_the_pack_not_of_all_the_streams(self):
        plan = self.plan("C", settings={"t0_range_limit_s": 100.0})
        found = {}
        for i, st in enumerate(plan.streams):
            t0 = 90.0 if i < 2 else 100.0 + 0.01 * (i - 2)
            found[st.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S + plan.settings["exit_delay_per_request_s"] * 100, 40.0, 100)
        al = X.alignment(plan, found)
        self.assertEqual(al["reasons"], [])
        self.assertAlmostEqual(al["zero"], 100.13)                # the median of 27 pack streams; that of all 29 would be 100.12
        self.assertAlmostEqual(al["offsets"][plan.streams[0].id], -10.13)

    def test_a_group_that_starts_later_is_judged_by_its_pack(self):
        plan = self.staged_plan(t0_range_limit_s=100.0)
        step = {}
        for st in plan.streams:
            step.setdefault(st.start_s, []).append(st)
        found = {}
        for start, streams in step.items():
            for i, st in enumerate(streams):
                t0 = 100.0 + start + (0.2 if start == 12.0 else 0.0) + (3.0 if (start == 12.0 and i == 0) else 0.0)
                found[st.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0)
        al = X.alignment(plan, found)
        self.assertEqual(al["reasons"], [])
        self.assertEqual([x["id"] for x in al["stragglers"]], [step[12.0][0].id])
        self.assertAlmostEqual(al["offsets"][step[12.0][1].id], 12.2)
        self.assertAlmostEqual(al["offsets"][step[12.0][0].id], 15.2)
        late = {k: (t + 0.6, w, n) for k, (t, w, n) in found.items() if k.startswith("S02-")}
        al = X.alignment(plan, {**found, **late})
        self.assertEqual(len(al["reasons"]), 1)
        self.assertIn("began +0.80 s from their start", al["reasons"][0])

    def test_a_later_group_is_judged_by_the_median_of_its_pack_not_of_all_its_streams(self):
        plan = self.staged_plan(t0_range_limit_s=100.0)
        step = {}
        for st in plan.streams:
            step.setdefault(st.start_s, []).append(st)

        def found(shift):
            out = {}
            for start, streams in step.items():
                for i, st in enumerate(streams):
                    if start != 12.0:
                        off = 0.0
                    elif i < 27:
                        off = 0.3975 + 0.0075 * i + shift        # the pack: its median (the 14th of 27) is 0.495, the next one 0.5025
                    else:
                        off = 3.0                                # two late stragglers: the median of all 29 would be the 15th, 0.5025
                    out[st.id] = (100.0 + start + off + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0)
            return out
        al = X.alignment(plan, found(0.0))
        self.assertEqual(al["reasons"], [])
        self.assertEqual(len(al["stragglers"]), 2)
        al = X.alignment(plan, found(0.0075))
        self.assertEqual(len(al["reasons"]), 1)
        self.assertIn("began +0.50 s from their start (limit 0.5 s)", al["reasons"][0])

    def test_the_stragglers_are_listed_by_id_and_not_by_start(self):
        plan = self.plan("C", settings={"t0_range_limit_s": 10.0})
        found = self.found(plan)
        a, b = sorted(st.id for st in plan.streams[5:7])
        found[a] = (found[a][0] - 2.0, *found[a][1:])             # the smaller id began later than the larger one
        found[b] = (found[b][0] - 3.0, *found[b][1:])
        al = X.alignment(plan, found)
        self.assertEqual(al["reasons"], [])
        self.assertEqual([x["id"] for x in al["stragglers"]], [a, b])
        self.assertLess(al["stragglers"][1]["from_pack_s"], al["stragglers"][0]["from_pack_s"])

    def spread(self, plan, offsets, base=100.0):
        """`found` in which the stream at index i began offsets[i] s after the others (none: with them), whatever that is."""
        return {st.id: (base + offsets.get(i, 0.0) + 40.0 - X.ENGINE_T0_OFFSET_S + plan.settings["exit_delay_per_request_s"] * 100, 40.0, 100)
                for i, st in enumerate(plan.streams)}

    def test_up_to_a_minority_of_the_group_may_be_stragglers_by_default(self):
        plan = self.plan("C")
        al = X.alignment(plan, self.found(plan, early=set(range(14))))
        self.assertEqual(al["reasons"], [])
        self.assertEqual(len(al["stragglers"]), 14)

    def test_the_pack_has_to_be_a_majority_of_the_group(self):
        plan = self.plan("C", settings={"t0_range_limit_s": 100.0})
        apart = {i: 0.6 * (i - 13) for i in range(14, 29)}        # 15 streams, each further than the limit from every other one
        al = X.alignment(plan, self.spread(plan, apart))
        self.assertEqual(len(al["stragglers"]), 15)
        self.assertEqual(len(al["reasons"]), 1, al["reasons"])
        self.assertIn("15 of 29 are outside the pack, at most 14 may be", al["reasons"][0])
        fewer = {i: 0.6 * (i - 14) for i in range(15, 29)}
        al = X.alignment(plan, self.spread(plan, fewer))
        self.assertEqual((len(al["stragglers"]), al["reasons"]), (14, []))

    def test_half_of_a_group_is_not_a_majority(self):
        plan = self.plan("C", settings={"t0_range_limit_s": 100.0})
        four = self.trimmed(plan, 4)
        al = X.alignment(four, self.spread(four, {2: 0.6, 3: 1.2}))
        self.assertEqual(len(al["reasons"]), 1, al["reasons"])
        self.assertIn("2 of 4 are outside the pack, at most 1 may be", al["reasons"][0])
        three = self.trimmed(plan, 3)
        self.assertEqual(X.alignment(three, self.spread(three, {2: 0.6}))["reasons"], [])
        two = self.trimmed(plan, 2)
        self.assertEqual(X.alignment(two, self.spread(two, {1: 0.6}))["reasons"], ["the legit streams began 0.60 s apart (limit 0.5 s)"])

    def test_the_range_of_a_group_is_held_to_the_range_limit_and_its_stragglers_are_still_placed(self):
        plan = self.plan("C")
        for early, sound in ((2.4, True), (2.6, False)):
            with self.subTest(early=early):
                al = X.alignment(plan, self.spread(plan, {3: -early}))
                self.assertEqual(al["reasons"] == [], sound, al["reasons"])
                self.assertEqual([x["id"] for x in al["stragglers"]], [plan.streams[3].id])
                self.assertAlmostEqual(al["offsets"][plan.streams[3].id], -early, places=6)
        late = X.alignment(plan, self.spread(plan, {3: 2.6}))
        self.assertEqual(late["reasons"], ["the legit streams began 2.60 s apart, further than the 2.5 s within which a straggler may begin"])

    def test_a_range_exactly_at_the_limit_is_sound(self):
        plan = self.plan("C")
        found = self.spread(plan, {3: -2.0})
        wide = X.alignment(plan, found)["t0_range_legit_s"]
        at = self.plan("C", name="at/C", settings={"t0_range_limit_s": wide})
        self.assertEqual(X.alignment(at, found)["reasons"], [])
        below = self.plan("C", name="below/C", settings={"t0_range_limit_s": wide - 1e-9})
        self.assertEqual(len(X.alignment(below, found)["reasons"]), 1)

    def test_the_range_limit_is_the_plans_setting(self):
        loose = self.plan("C", name="loose/C", settings={"t0_range_limit_s": 3.0})
        self.assertEqual(X.alignment(loose, self.spread(loose, {3: -2.6}))["reasons"], [])
        tight = self.plan("C", name="tight/C", settings={"t0_range_limit_s": 1.0})
        al = X.alignment(tight, self.spread(tight, {3: -1.2}))
        self.assertEqual(len(al["reasons"]), 1, al["reasons"])
        self.assertIn("further than the 1 s within which a straggler may begin", al["reasons"][0])

    def test_a_group_can_break_both_limits_and_says_so_twice(self):
        plan = self.plan("C", settings={"straggler_share": 0.1})
        al = X.alignment(plan, self.spread(plan, {1: -2.6, 2: -2.6, 3: -2.6}))
        self.assertEqual(len(al["reasons"]), 2, al["reasons"])
        self.assertIn("3 of 29 are outside the pack, at most 2 may be", al["reasons"][0])
        self.assertIn("further than the 2.5 s", al["reasons"][1])

    def test_the_range_limit_is_judged_for_each_group_on_its_own(self):
        plan = self.staged_plan()
        step = {}
        for st in plan.streams:
            step.setdefault(st.start_s, []).append(st)
        found = {}
        for start, streams in step.items():
            for i, st in enumerate(streams):
                found[st.id] = (100.0 + start + (-2.6 if (start == 6.0 and i == 0) else 0.0) + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0)
        self.assertEqual(sorted(step), [0.0, 6.0, 12.0], "the group with the wide range is not the last one")
        al = X.alignment(plan, found)
        self.assertEqual(len(al["reasons"]), 1, al["reasons"])
        self.assertIn("the legit streams that start at 6 s began 2.60 s apart, further than the 2.5 s", al["reasons"][0])
        self.assertAlmostEqual(al["t0_range_legit_s"], 2.6)

    def staged_plan(self, **settings):
        pop = P.staged("calib", 1, (20.0, 40.0, 80.0), 6.0)
        return X.plan_population(pop, "capacity", "C", 1, os.path.join(self.tmp.name, "s", "C"), self.cal, C.PLACEHOLDER, pop.timeline,
                                 settings=bare_settings(**settings))

    def test_a_later_group_is_judged_by_the_group_limit_and_not_by_the_attacks(self):
        step = {}
        plan = self.staged_plan()
        for st in plan.streams:
            step.setdefault(st.start_s, []).append(st)
        found = {st.id: (100.0 + start + (0.8 if start == 12.0 else 0.0) + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0)
                 for start, streams in step.items() for st in streams}
        self.assertEqual(len(X.alignment(plan, found)["reasons"]), 1)
        self.assertIn("began +0.80 s from their start (limit 0.5 s)", X.alignment(plan, found)["reasons"][0])
        loose = self.staged_plan(group_start_limit_s=1.0)
        self.assertEqual(X.alignment(loose, found)["reasons"], [])
        attack_loose = self.staged_plan(attack_start_limit_s=5.0)
        self.assertEqual(len(X.alignment(attack_loose, found)["reasons"]), 1, "the attack's limit is not a group's")
        al = X.alignment(self.staged_plan(group_start_limit_s=0.7), found)
        self.assertIn("(limit 0.7 s)", al["reasons"][0])

    def test_a_later_group_exactly_at_the_group_limit_is_sound(self):
        step = {}
        base = self.staged_plan()
        for st in base.streams:
            step.setdefault(st.start_s, []).append(st)
        found = {st.id: (100.0 + start + (0.8 if start == 12.0 else 0.0) + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 0)
                 for start, streams in step.items() for st in streams}
        per = base.settings["exit_delay_per_request_s"]
        t0 = {sid: X.estimate_t0(*found[sid], per) for sid in found}          # the streams of a group share one
        error = t0[step[12.0][0].id] - (t0[step[0.0][0].id] + 12.0)           # as alignment() takes it
        self.assertEqual(X.alignment(self.staged_plan(group_start_limit_s=error), found)["reasons"], [])
        self.assertEqual(len(X.alignment(self.staged_plan(group_start_limit_s=error - 1e-9), found)["reasons"]), 1)

    def test_the_attack_is_judged_by_the_attack_limit_and_not_by_the_groups(self):
        base = self.plan("U")
        late = self.found(base)
        for st in base.streams:
            if st.kind == "attack":                                  # 0.8 s after the end of the baseline
                late[st.id] = (100.0 + base.timeline["baseline_s"] + 0.8 + 40.0 - X.ENGINE_T0_OFFSET_S
                               + base.settings["exit_delay_per_request_s"] * 100, 40.0, 100)
        al = X.alignment(base, late)
        self.assertEqual(len(al["reasons"]), 1, al["reasons"])
        self.assertIn("the attack began +0.79 s from the end of the baseline (limit 0.5 s)", al["reasons"][0])      # the pack's median is 0.01 s in
        self.assertEqual(X.alignment(self.plan("U", name="a/U", settings={"attack_start_limit_s": 1.0}), late)["reasons"], [])
        self.assertEqual(len(X.alignment(self.plan("U", name="g/U", settings={"group_start_limit_s": 5.0}), late)["reasons"]), 1,
                         "the group limit is not the attack's")

    def test_the_attack_is_not_judged_by_a_pack(self):
        plan = self.plan("U")
        base = plan.timeline["baseline_s"]
        found = self.found(plan)
        attack = [st for st in plan.streams if st.kind == "attack"]
        for i, st in enumerate(attack):
            t0 = 100.0 + base + (7.0 if i == 0 else 0.0)
            found[st.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S + plan.settings["exit_delay_per_request_s"] * 100, 40.0, 100)
        al = X.alignment(plan, found)
        self.assertEqual(al["reasons"], [], "the median of the attack's starts is what is judged")
        self.assertEqual(al["stragglers"], [])
        self.assertAlmostEqual(al["attack_start_error_s"], 0.0, delta=0.02)


class AccessLogTest(unittest.TestCase):
    @staticmethod
    def line(stamp="2026-10-24T08:00:10+00:00", ip="10.0.1.5", took=0.01, status=200):
        return json.dumps({"timestamp": stamp, "client_ip": ip, "request_time": took, "status": status})

    def zero(self, second=0):
        import datetime
        return datetime.datetime.fromisoformat("2026-10-24T08:00:00+00:00").timestamp() + second

    def test_a_request_is_put_where_it_arrived_not_where_it_ended(self):
        rows, bad = X.aggregate_access_log([self.line(took=0.0), self.line(took=3.0)], self.zero())
        self.assertEqual(bad, 0)
        self.assertEqual([(r[0], r[3]) for r in rows], [(7, 1), (10, 1)])

    def test_the_log_second_counts_as_its_middle(self):
        rows, _ = X.aggregate_access_log([self.line(took=0.4), self.line(took=0.6)], self.zero())
        self.assertEqual([(r[0], r[3]) for r in rows], [(9, 1), (10, 1)])

    def test_the_second_is_from_the_runs_zero(self):
        rows, _ = X.aggregate_access_log([self.line()], self.zero(4))
        self.assertEqual(rows[0][0], 6)

    def test_the_client_class_is_the_populations_address_prefix(self):
        lines = [self.line(ip="10.0.1.7"), self.line(ip="10.0.3.9"), self.line(ip="10.0.2.4"), self.line(ip="10.0.0.1"),
                 self.line(ip="::1")]
        rows, _ = X.aggregate_access_log(lines, self.zero())
        self.assertEqual({r[1]: r[3] for r in rows}, {"legit": 2, "attack": 1, "other": 2})

    def test_status_splits_the_cells_and_the_mean_and_largest_request_time_are_kept(self):
        rows, _ = X.aggregate_access_log([self.line(took=0.1), self.line(took=0.3), self.line(status=503, took=0.2)], self.zero())
        ok = next(r for r in rows if r[2] == 200)
        self.assertEqual((ok[3], round(ok[4], 6), ok[5]), (2, 0.2, 0.3))
        self.assertEqual(next(r for r in rows if r[2] == 503)[3], 1)

    def test_lines_that_cannot_be_read_are_counted_and_left_out(self):
        rows, bad = X.aggregate_access_log(["not json", "{}", self.line(ip="nonsense"), self.line(stamp="yesterday"), self.line()],
                                           self.zero())
        self.assertEqual(bad, 4)
        self.assertEqual(sum(r[3] for r in rows), 1)

    def test_it_agrees_with_the_suites_own_aggregate_on_the_arrival_second(self):
        sys.path.insert(0, REPO)
        with mock.patch("atexit.register"), mock.patch("signal.signal"):
            import test_distributed_suite as S
        lines = [self.line(took=t, ip="10.0.1.5") for t in (0.0, 0.2, 0.7, 1.4, 2.9)]
        theirs, _ = S.aggregate_access_log(lines)
        ours, _ = X.aggregate_access_log(lines, 0.0)
        self.assertEqual(sorted(r[0] for r in theirs), sorted(r[0] for r in ours))


class SamplerTest(RunCase):
    def sampler(self, host=None):
        host = host or F.SimHost()
        host.spawn(["gunicorn"], "server_ns", "gunicorn", "origin")
        host.spawn(["nginx:", "master process"], "server_ns", "nginx", "nginx")
        sampler = X.Sampler(host)
        sampler.attach()
        return host, sampler

    def test_attach_groups_the_server_namespaces_processes(self):
        _, sampler = self.sampler()
        self.assertEqual(sorted(sampler.pids.values()), ["nginx", "origin"])

    def test_the_first_row_has_the_load_and_the_next_have_the_rates(self):
        host, sampler = self.sampler()
        sampler.sample(0.0)
        host.sleep(1.0)
        sampler.sample(1.0)
        first, second = sampler.rows
        self.assertEqual(first["load1"], 0.05)
        self.assertNotIn("cpu_busy_pct", first)
        self.assertEqual(second["cpu_busy_pct"], 10.0)
        self.assertEqual(second["origin_cpu_pct"], 50.0)
        self.assertEqual(second["nginx_cpu_pct"], 20.0)
        self.assertEqual(second["steal_pct"], 0.0)

    def test_steal_is_a_share_of_all_the_cpus_time(self):
        host, sampler = self.sampler(F.SimHost(steal_share=0.03))
        sampler.sample(0.0)
        host.sleep(2.0)
        sampler.sample(2.0)
        self.assertAlmostEqual(sampler.rows[1]["steal_pct"], 3.0, delta=0.1)

    def test_a_read_that_fails_leaves_an_empty_cell_and_the_run_goes_on(self):
        host, sampler = self.sampler()
        original = host.read_text

        def flaky(path):
            if path == "/proc/loadavg" and host.t >= 1.0:
                raise OSError("gone")
            return original(path)
        host.read_text = flaky
        sampler.sample(0.0)
        host.sleep(1.0)
        sampler.sample(1.0)
        self.assertIsNone(sampler.rows[1]["load1"])
        path = os.path.join(self.tmp.name, "server.csv")
        sampler.write(path)
        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows[1]["load1"], "")
        self.assertEqual(rows[0]["load1"], "0.05")

    def test_a_process_that_appears_later_is_picked_up(self):
        host, sampler = self.sampler()
        for i in range(X.REATTACH_EVERY):
            host.sleep(1.0)
            sampler.sample(float(i))
        late = host.spawn(["nginx:", "worker process"], "server_ns", "nginx", "nginx")
        self.assertNotIn(late.pid, sampler.pids)
        sampler.sample(float(X.REATTACH_EVERY))
        self.assertEqual(sampler.pids.get(late.pid), "nginx")

    def test_the_listen_queue_counters_are_read_from_a_process_in_the_namespace(self):
        host, sampler = self.sampler()
        host.sleep(35.0)
        sampler.sample(35.0)
        self.assertEqual((sampler.rows[0]["listen_overflows"], sampler.rows[0]["listen_drops"]), (3, 3))
        self.assertEqual((sampler.rows[0]["tcp_inuse"], sampler.rows[0]["tcp_tw"]), (17, 5))


class RealHostTest(unittest.TestCase):
    """The parts of the real host that need neither root nor a namespace."""

    def test_cpu_lists(self):
        self.assertEqual(X.cpu_list("2"), {2})
        self.assertEqual(X.cpu_list("0-1"), {0, 1})
        self.assertEqual(X.cpu_list("3-5,7"), {3, 4, 5, 7})

    def test_a_command_comes_back_as_code_output_and_error(self):
        host = X.RealHost()
        self.assertEqual(host.run(["echo", "hi"]), X.Result(0, "hi\n", ""))
        self.assertEqual(host.run(["sh", "-c", "echo bad >&2; exit 3"]), X.Result(3, "", "bad\n"))

    def test_a_missing_command_is_a_code_not_an_exception(self):
        r = X.RealHost().run(["no-such-command-hg1c"])
        self.assertEqual(r.code, 127)

    def test_a_command_that_runs_too_long_is_cut_off(self):
        r = X.RealHost().run(["sleep", "5"], timeout=0.2)
        self.assertEqual((r.code, r.err), (-1, "timeout"))

    def test_input_is_fed_and_otherwise_stdin_is_closed(self):
        host = X.RealHost()
        self.assertEqual(host.run(["cat"], stdin="a\nb\n").out, "a\nb\n")
        self.assertEqual(host.run(["cat"]).out, "", "cat would otherwise wait for the terminal")

    def test_commands_get_the_cleaned_environment_with_the_callers_variables_added(self):
        with mock.patch.dict(os.environ, {"http_proxy": "http://proxy.invalid:3128", "KEEP_ME": "1"}):
            out = X.RealHost().run(["env"], env={"ORIGIN_SEED": "7"}).out.splitlines()
        self.assertNotIn("http_proxy=http://proxy.invalid:3128", out)
        self.assertIn("NO_PROXY=*", out)
        self.assertIn("ORIGIN_SEED=7", out)
        self.assertIn("KEEP_ME=1", out)

    def test_a_process_is_reaped_and_its_exit_is_stamped_by_its_own_watcher(self):
        host = X.RealHost()
        before = time.time()
        proc = host.popen(["sh", "-c", "exit 3"])
        deadline = time.time() + 10
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(proc.poll(), 3)
        self.assertGreaterEqual(proc.exit_time, before)
        self.assertLessEqual(proc.exit_time, time.time())

    def test_a_process_can_be_terminated_and_killed(self):
        host = X.RealHost()
        proc = host.popen(["sleep", "30"])
        self.assertIsNone(proc.poll())
        proc.terminate()
        deadline = time.time() + 10
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(proc.poll(), -signal.SIGTERM)
        proc.kill()                          # already gone: not an error

    def test_the_shield_ignores_the_signals_that_end_a_run_and_puts_the_handlers_back(self):
        sigs = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        before = {sig: signal.getsignal(sig) for sig in sigs}
        with X.RealHost().shielded():
            self.assertEqual({signal.getsignal(sig) for sig in sigs}, {signal.SIG_IGN})
            signal.raise_signal(signal.SIGINT)        # would be a KeyboardInterrupt outside
        self.assertEqual({sig: signal.getsignal(sig) for sig in sigs}, before)

    def test_the_shield_is_put_back_when_what_it_shields_fails(self):
        before = signal.getsignal(signal.SIGINT)
        with self.assertRaises(ZeroDivisionError), X.RealHost().shielded():
            raise ZeroDivisionError
        self.assertEqual(signal.getsignal(signal.SIGINT), before)

    def test_the_suite_is_imported_with_its_variables_cleared_and_its_hooks_taken_back(self):
        stub = mock.Mock(cleanup_all=lambda: None)
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        with mock.patch.dict(sys.modules, {"test_distributed_suite": stub}), \
                mock.patch.dict(os.environ, {"FLOOD_TOOL": "wrk", "OPERATING_POINT": "x"}), \
                mock.patch("atexit.unregister") as unregister, mock.patch("signal.signal") as setter:
            got = X.RealHost().suite()
            self.assertNotIn("FLOOD_TOOL", os.environ)
            self.assertNotIn("OPERATING_POINT", os.environ)
        self.assertIs(got, stub)
        unregister.assert_called_once_with(stub.cleanup_all)
        self.assertEqual({c.args for c in setter.call_args_list},
                         {(signal.SIGINT, before[signal.SIGINT]), (signal.SIGTERM, before[signal.SIGTERM])})

    def test_the_real_suite_leaves_no_atexit_hook_and_no_signal_handler_behind(self):
        code = (
            "import atexit, signal, subprocess, sys\n"
            "subprocess.run = lambda *a, **k: None          # if the suite's cleanup ever ran, it would do nothing\n"
            f"sys.path.insert(0, {os.path.join(REPO, 'bench')!r})\n"
            "import executor as X\n"
            "n, i, t = atexit._ncallbacks(), signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)\n"
            "suite = X.RealHost().suite()\n"
            "print(atexit._ncallbacks() - n, signal.getsignal(signal.SIGINT) is i, signal.getsignal(signal.SIGTERM) is t,\n"
            "      hasattr(suite, 'create_client_ns'), 'FLOOD_TOOL' in __import__('os').environ)\n")
        env = {k: v for k, v in os.environ.items() if k not in X.SUITE_ENV_VARS}
        env["FLOOD_TOOL"] = "wrk"
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60, check=False,
                             cwd=REPO, env={**env, "PYTHONPATH": ""})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split(), ["0", "True", "True", "True", "False"], out.stdout + out.stderr)

    def test_the_suite_env_vars_are_the_campaign_runners(self):
        self.assertEqual(X.SUITE_ENV_VARS, run_campaign.EVAL_VARS)


class SmokeTopologyTest(RunCase):
    def test_the_topology_is_built_verified_pinged_and_taken_down(self):
        plan = self.plan("C")
        host = F.SimHost()
        seconds = X.smoke_topology(plan, host)
        self.assertGreaterEqual(seconds, 0.0)
        self.assertEqual(sum(p[0] == "client_ns" for p in host.prims), 4)
        self.assertEqual(host.kinds()["popen"], 0, "no stack and no stream")
        self.assertTrue(host.ran("ping"))
        self.assertTestbedEmpty(host)

    def test_a_topology_that_fails_verification_is_still_taken_down(self):
        host = F.SimHost(faults={"duplicate_mac": None})
        with self.assertRaises(X.SetupFailed):
            X.smoke_topology(self.plan("C"), host)
        self.assertTestbedEmpty(host)

    def test_it_refuses_what_a_run_refuses(self):
        host = F.SimHost(preexisting=["legit_1"])
        with self.assertRaises(X.PreflightRefused):
            X.smoke_topology(self.plan("C"), host)
        self.assertEqual(sorted(host.namespaces), ["legit_1"])
        with self.assertRaises(X.PreflightRefused):
            X.smoke_topology(self.plan("C", name="x/C"), F.SimHost(root=False))


class ClockSummaryTest(unittest.TestCase):
    @staticmethod
    def row(error, intended=100, kind="legit", start=1.8, rss=30.0, launch=0.0, gap=0.0):
        """`error` is the corrected estimator's; the engine's wall time was `gap` shorter than its records allow, so the
        estimator without the correction was `gap` later."""
        began = launch + start
        return {"id": f"{kind}-{error}", "kind": kind, "rate": 10.0, "intended": intended, "launch_s": launch, "start_s": began,
                "exit_s": began + error + 31.0 - X.ENGINE_T0_OFFSET_S, "start_after_launch_s": start,
                "estimator_minus_truth_s": error, "raw_estimator_minus_truth_s": error + gap, "wall_s": 31.0 - gap,
                "last_done_s": 30.9, "wall_gap_s": gap, "cpu_s": 0.5, "rss_mib": rss}

    def test_the_bias_is_the_median_and_the_scatter_is_around_it(self):
        rows = [self.row(e) for e in (0.30, 0.31, 0.32, 0.33, 0.40)]
        s = X.clock_summary(rows, 6, 30.0)
        self.assertAlmostEqual(s["estimator_bias_s"], 0.32)
        self.assertAlmostEqual(s["estimator_error_s"]["max"], 0.08)
        self.assertAlmostEqual(s["estimator_error_s"]["p50"], 0.01)
        self.assertEqual((s["streams"], s["reported"]), (6, 5))

    def test_a_bias_common_to_all_streams_is_not_an_error(self):
        s = X.clock_summary([self.row(0.5), self.row(0.5), self.row(0.5)], 3, 30.0)
        self.assertAlmostEqual(s["estimator_bias_s"], 0.5)
        self.assertEqual(s["estimator_error_s"]["max"], 0.0)

    def test_the_start_up_and_its_spread_are_summarised(self):
        s = X.clock_summary([self.row(0.0, start=s) for s in (1.7, 1.8, 2.1)], 3, 30.0)
        self.assertEqual(s["start_after_launch_s"], {"min": 1.7, "median": 1.8, "max": 2.1, "spread": 2.1 - 1.7})

    def test_the_dependence_on_the_request_count_is_fitted(self):
        rows = [self.row(0.05 + 3e-5 * n, intended=n) for n in (100, 1000, 5000, 20000)]
        fit = X.clock_summary(rows, 4, 30.0)["exit_delay_fit"]
        self.assertAlmostEqual(fit["per_request_s"], 3e-5, places=9)
        self.assertAlmostEqual(fit["base_s"], 0.05, places=6)

    def test_no_fit_without_a_spread_of_request_counts(self):
        rows = [self.row(0.1, intended=100) for _ in range(4)]
        self.assertIsNone(X.clock_summary(rows, 4, 30.0)["exit_delay_fit"])
        self.assertIsNone(X.clock_summary(rows[:2], 2, 30.0)["exit_delay_fit"])

    def test_the_legit_spread_is_kept_apart_from_the_attack_streams(self):
        rows = [self.row(0.30), self.row(0.32), self.row(0.9, kind="attack", intended=5000)]
        s = X.clock_summary(rows, 3, 30.0)
        self.assertAlmostEqual(s["legit_error_spread_s"], 0.02)

    def test_memory_and_cpu_are_totalled(self):
        s = X.clock_summary([self.row(0.1, rss=30.0), self.row(0.1, rss=50.0)], 2, 30.0)
        self.assertEqual(s["rss_mib"], {"max": 50.0, "total": 80.0})
        self.assertAlmostEqual(s["cpu_s_total"], 1.0)

    def three(self):
        """Launched at 0.0, 0.1 and 0.2 s, began at 3.0, 3.1 and 3.5 s after the first launch; the estimator puts them at 3.0, 3.12, 3.4."""
        return [self.row(0.00, launch=0.0, start=3.0), self.row(0.02, launch=0.1, start=3.0), self.row(-0.10, launch=0.2, start=3.3)]

    def test_the_launches_are_spread_over_the_legit_streams(self):
        s = X.clock_summary(self.three(), 3, 30.0)
        self.assertEqual({k: round(v, 9) for k, v in s["legit_launch_s"].items()},
                         {"min": 0.0, "median": 0.1, "max": 0.2, "spread": 0.2})

    def test_the_true_starts_are_spread_over_the_legit_streams(self):
        s = X.clock_summary(self.three(), 3, 30.0)
        self.assertEqual({k: round(v, 9) for k, v in s["legit_true_start_s"].items()},
                         {"min": 3.0, "median": 3.1, "max": 3.5, "spread": 0.5})

    def test_the_estimated_starts_are_the_true_ones_plus_the_error(self):
        s = X.clock_summary(self.three(), 3, 30.0)
        self.assertEqual({k: round(v, 9) for k, v in s["legit_estimated_start_s"].items()},
                         {"min": 3.0, "median": 3.12, "max": 3.4, "spread": 0.4})

    def test_the_attack_streams_are_not_among_the_spread_legit_ones(self):
        rows = [*self.three(), self.row(0.5, kind="attack", intended=5000, launch=9.0, start=0.1)]
        s = X.clock_summary(rows, 4, 30.0)
        self.assertAlmostEqual(s["legit_launch_s"]["spread"], 0.2)
        self.assertAlmostEqual(s["legit_true_start_s"]["max"], 3.5)
        self.assertAlmostEqual(s["legit_estimated_start_s"]["max"], 3.4)

    def test_without_legit_streams_there_is_no_spread(self):
        s = X.clock_summary([self.row(0.1, kind="attack")], 1, 30.0)
        for key in ("legit_launch_s", "legit_true_start_s", "legit_estimated_start_s"):
            self.assertEqual(s[key], {"min": None, "median": None, "max": None, "spread": None})

    def early_starter(self):
        """Two streams that began at 2.0 and 2.1 s, and one that began at 0.2 s whose engine was descheduled for 2.0 s: its wall time
        was 2.0 s short, so without the correction it would be put at 2.22 s, in the pack."""
        return [self.row(0.02, start=2.0), self.row(0.03, start=2.1, gap=0.05), self.row(0.02, start=0.2, gap=2.0)]

    def test_the_correction_shows_the_early_stream_the_estimator_without_it_hides(self):
        s = X.clock_summary(self.early_starter(), 3, 30.0)
        self.assertAlmostEqual(s["legit_estimated_start_s"]["spread"], 2.13 - 0.22)
        self.assertAlmostEqual(s["legit_raw_estimated_start_s"]["spread"], 2.22 - 2.02)
        self.assertAlmostEqual(s["legit_estimated_start_s"]["min"], 0.22)
        self.assertAlmostEqual(s["legit_raw_estimated_start_s"]["min"], 2.02)

    def test_the_wall_gaps_are_summarised_over_all_streams(self):
        rows = [*self.early_starter(), self.row(0.1, kind="attack", gap=0.4)]
        s = X.clock_summary(rows, 4, 30.0)
        self.assertEqual({k: round(v, 9) for k, v in s["wall_gap_s"].items()}, {"min": 0.0, "median": 0.225, "max": 2.0, "spread": 2.0})

    def test_the_text_says_what_the_correction_did(self):
        text = X.clock_text(X.clock_summary(self.early_starter(), 3, 30.0), "/x")
        self.assertIn("the estimator puts them over 1.910 s (0.200 s without the wall-time correction)", text)
        self.assertIn("wall time raised to what the records need: median 0.050 s, max 2.000 s", text)

    def test_the_text_gives_the_spreads_and_the_limit_a_run_holds_them_to(self):
        text = X.clock_text(X.clock_summary(self.three(), 3, 30.0), "/x")
        self.assertIn("launched over 0.200 s", text)
        self.assertIn("loops began over 0.500 s (min 3.000, median 3.100, max 3.500 after the first launch)", text)
        self.assertIn("estimator puts them over 0.400 s (0.400 s without the wall-time correction), which a run holds to 0.5 s", text)
        with mock.patch.dict(X.SETTINGS, {"t0_spread_limit_s": 1.25}):
            self.assertIn("which a run holds to 1.25 s", X.clock_text(X.clock_summary(self.three(), 3, 30.0), "/x"))

    def test_nothing_reported_is_a_summary_of_nothing(self):
        s = X.clock_summary([], 29, 30.0)
        self.assertEqual((s["reported"], s["estimator_bias_s"], s["exit_delay_fit"]), (0, None, None))
        self.assertIn("0 of 29", X.clock_text(s, "/x"))


@contextlib.contextmanager
def few_streams(how_many=2):
    """Populations trimmed to a few streams of some rate, and every CPU pin set to a CPU this process may use: the probe on a small
    scale, with the real engine. The trimmed population hands out tuples, as the real one does."""
    mine = str(min(os.sched_getaffinity(0)))
    pins = dict.fromkeys(("server", "daemon", "legit", "attack"), mine)
    real = SC.population_of

    class Few:
        def __init__(self, pop):
            self.pop = pop

        def of_kind(self, kind):
            return tuple(s for s in self.pop.of_kind(kind) if s.rate >= 2.0)[:how_many]

    def small(*a, **k):
        pop, level = real(*a, **k)
        return Few(pop), level
    with mock.patch.object(SC, "population_of", small), mock.patch.object(P, "PIN_PLAN", pins):
        yield pins


class ClockProbeTest(RunCase):
    """The probe on loopback with the real engine and a few small streams: the pipeline, not the accuracy."""

    def probe(self, attack):
        out = os.path.join(self.tmp.name, "probe")
        with few_streams():
            return X.clock_probe(self.scn, self.cal, 1, 3.0, out, attack=attack), out

    def test_two_streams_on_loopback_give_a_reference_each(self):
        result, out = self.probe(False)
        self.assertEqual((result["streams"], result["reported"]), (2, 2), result)
        for row in result["rows"]:
            self.assertTrue(0.0 < row["start_after_launch_s"] < 10.0, row)
            self.assertLess(abs(row["estimator_minus_truth_s"]), 1.0, row)
            self.assertGreater(row["rss_mib"], 5.0)
        self.assertEqual({row["kind"] for row in result["rows"]}, {"legit"})
        self.assertTrue(os.path.exists(os.path.join(out, "clock_probe.json")))
        self.assertTrue(os.path.exists(os.path.join(out, "streams", result["rows"][0]["id"], "loadgen.records.csv.gz")))

    def test_every_stream_says_when_it_was_launched_began_and_exited_from_the_first_launch(self):
        result, out = self.probe(False)
        rows = result["rows"]
        self.assertEqual(min(row["launch_s"] for row in rows), 0.0)
        for row in rows:
            self.assertAlmostEqual(row["start_s"], row["launch_s"] + row["start_after_launch_s"], places=9)
            self.assertGreater(row["exit_s"], row["start_s"])
            # the estimator's row, rebuilt from the exit: exit less the wall time held to the records, plus the engine's offset,
            # is start + error; without the correction it is later by the gap
            self.assertAlmostEqual(row["exit_s"] - (row["wall_s"] + row["wall_gap_s"]) + X.ENGINE_T0_OFFSET_S,
                                   row["start_s"] + row["estimator_minus_truth_s"], places=6)
            self.assertAlmostEqual(row["exit_s"] - row["wall_s"] + X.ENGINE_T0_OFFSET_S,
                                   row["start_s"] + row["raw_estimator_minus_truth_s"], places=6)
            self.assertAlmostEqual(row["raw_estimator_minus_truth_s"] - row["estimator_minus_truth_s"], row["wall_gap_s"], places=6)
            self.assertGreaterEqual(row["wall_gap_s"], 0.0)
            self.assertAlmostEqual(row["wall_s"] + row["wall_gap_s"], max(row["wall_s"], row["last_done_s"] + X.ENGINE_T0_OFFSET_S), places=9)
        self.assertEqual(result["legit_launch_s"]["spread"], max(r["launch_s"] for r in rows) - min(r["launch_s"] for r in rows))
        self.assertEqual(result["legit_true_start_s"]["max"], max(r["start_s"] for r in rows))
        with open(os.path.join(out, "clock_probe.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["rows"], rows)

    def test_the_commands_are_built_before_the_first_stream_is_launched(self):
        calls, build, popen = [], X.LT.build_plan, X.RealHost.popen

        def traced_build(*args, **kwargs):
            calls.append("build")
            return build(*args, **kwargs)

        def traced_popen(host, *args, **kwargs):
            calls.append("launch")
            return popen(host, *args, **kwargs)
        with few_streams(), mock.patch.object(X.LT, "build_plan", traced_build), mock.patch.object(X.RealHost, "popen", traced_popen):
            X.clock_probe(self.scn, self.cal, 1, 1.0, os.path.join(self.tmp.name, "probe"), attack=False)
        self.assertEqual(calls, ["build", "build", "launch", "launch"])

    def test_with_attack_the_scenarios_attack_streams_are_run_too(self):
        result, _ = self.probe(True)
        self.assertEqual((result["streams"], result["reported"]), (4, 4), result)
        self.assertEqual(sorted(row["kind"] for row in result["rows"]), ["attack", "attack", "legit", "legit"])
        self.assertIsNotNone(result["exit_delay_fit"], "streams with different request counts give a fit")


class ProbeStreamsTest(RunCase):
    """The streams S1 runs, from the real populations of the shipped scenarios (a stand-in population once hid a type error here)."""

    def population(self, name, attack):
        scn = SC.load(os.path.join(REPO, "bench", "scenarios", name + ".json"))
        return SC.population_of(scn, self.cal, scn.first_seed, attack=attack)[0]

    def test_the_legit_streams_alone_are_the_29_of_the_population(self):
        streams = X.probe_streams(self.population("costly_search_sub_threshold", False), False)
        self.assertIsInstance(streams, list)
        self.assertEqual((len(streams), {s.kind for s in streams}), (29, {"legit"}))

    def test_with_the_attack_the_scenarios_attack_streams_follow_the_legit_ones(self):
        for name, attackers in (("costly_search_sub_threshold", 4), ("cheap_static_flood", 3), ("costly_export_sub_threshold", 4)):
            with self.subTest(scenario=name):
                streams = X.probe_streams(self.population(name, True), True)
                self.assertIsInstance(streams, list)
                self.assertEqual([s.kind for s in streams], ["legit"] * 29 + ["attack"] * attackers)

    def test_the_attack_streams_of_a_population_are_left_out_unless_asked_for(self):
        pop = self.population("costly_search_sub_threshold", True)
        self.assertEqual(len(pop.of_kind("attack")), 4)
        streams = X.probe_streams(pop, False)
        self.assertEqual((len(streams), {s.kind for s in streams}), (29, {"legit"}))

    def test_an_attack_is_not_asked_for_of_a_population_that_has_none(self):
        streams = X.probe_streams(self.population("benign_control", True), True)
        self.assertEqual({s.kind for s in streams}, {"legit"})

    def test_the_real_population_works_with_the_probe_end_to_end_up_to_the_engine_command(self):
        for s in X.probe_streams(self.population("cheap_static_flood", True), True):
            spec = X.dataclasses.replace(X.P.to_load_spec(s, "http://127.0.0.1:1/"), duration=1.0, local_addrs=(), allow_loopback=True)
            argv = X.LT.build_plan("loadgen", spec, os.path.join(self.tmp.name, s.id)).steps[0].argv
            self.assertIn("--allow-loopback", argv)
            self.assertEqual(argv[argv.index("-c") + 1], X.P.PIN_PLAN["legit" if s.kind == "legit" else "attack"])


class CommandLineTest(RunCase):
    def run_main(self, *args, host=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(X.signal, "signal") as handlers, contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = X.main(list(args), host=host)
        return code, handlers, out.getvalue(), err.getvalue()

    def base(self, kind="C", name=None):
        return ["run", SPEC, "--kind", kind, "--out", os.path.join(self.tmp.name, name or kind), "--rho", "20",
                "--timeline", "10,10,10", "--allow-dirty"]

    def test_a_sound_run_exits_zero_pins_itself_and_installs_its_signal_handlers(self):
        host = F.SimHost()
        code, handlers, shown, _ = self.run_main(*self.base(), host=host)
        self.assertEqual(code, X.EXIT_OK)
        self.assertEqual(host.pinned, P.PIN_PLAN["daemon"])
        self.assertEqual({c.args[0] for c in handlers.call_args_list}, {signal.SIGTERM, signal.SIGHUP})
        self.assertIn("sound", shown)

    def test_a_run_with_a_timer_limit_says_it_is_a_smoke_test_and_the_harm_gate_will_not_judge_it(self):
        host = F.SimHost(timer_p99_ms=15.0)
        code, _, shown, _ = self.run_main(*self.base("C", "raised/C"), "--timer-limit-ms", "50", host=host)
        self.assertEqual(code, X.EXIT_OK)
        self.assertRegex(shown, r"OVERRIDES \{[^}]*'timer_limit_ms': 50\.0[^}]*\}: a smoke test, not a result; "
                                r"the harm gate gives no verdict on it")
        code, _, shown, err = self.run_main(*self.base("C", "refused/C"), host=F.SimHost(timer_p99_ms=15.0))
        self.assertEqual(code, X.EXIT_FAILED)
        self.assertIn("EnvironmentRefused", err)
        self.assertIn("needs below 10 ms", err)

    def test_a_run_without_overrides_does_not_say_so(self):
        code, _, shown, _ = self.run_main("run", SPEC, "--kind", "C", "--out", os.path.join(self.tmp.name, "C"), "--allow-dirty",
                                          host=F.SimHost(server=F.SyntheticServer(self.cal, (105.0, 45.0, 45.0))))
        self.assertEqual(code, X.EXIT_OK)
        self.assertNotIn("OVERRIDES", shown)

    def test_the_signal_handler_ends_the_run_like_ctrl_c(self):
        _, handlers, _, _ = self.run_main(*self.base(), host=F.SimHost())
        handler = handlers.call_args_list[0].args[1]
        with self.assertRaises(KeyboardInterrupt):
            handler(signal.SIGTERM, None)

    def test_an_unsound_run_exits_three(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: F.LEGIT_STARTUP_S + (2.8 if index == 3 else 0.0))       # beyond the range limit
        code, _, shown, _ = self.run_main(*self.base(), host=host)
        self.assertEqual(code, X.EXIT_UNSOUND)
        self.assertIn("UNSOUND", shown)

    def test_a_refusal_exits_two_and_says_why_on_stderr(self):
        code, _, _, err = self.run_main(*self.base(), host=F.SimHost(root=False))
        self.assertEqual(code, X.EXIT_FAILED)
        self.assertIn("PreflightRefused", err)
        self.assertIn("needs root", err)

    def test_a_plan_that_cannot_be_made_exits_one(self):
        code, _, _, err = self.run_main("run", SPEC, "--kind", "U", "--out", os.path.join(self.tmp.name, "C"),
                                        host=F.SimHost())
        self.assertEqual(code, X.EXIT_USAGE)
        self.assertIn("called U", err)

    def test_a_bad_timeline_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            X.main(["plan", SPEC, "--kind", "C", "--timeline", "10,10"])
        self.assertEqual(ctx.exception.code, 2)

    def test_smoke_topology_builds_and_takes_down(self):
        host = F.SimHost()
        code, _, shown, _ = self.run_main("smoke-topology", SPEC, "--out", os.path.join(self.tmp.name, "C"), host=host)
        self.assertEqual(code, X.EXIT_OK)
        self.assertIn("nothing left", shown)
        self.assertTestbedEmpty(host)

    def test_clock_probe_pins_itself_runs_the_streams_and_prints_what_it_found(self):
        out = os.path.join(self.tmp.name, "probe")
        with few_streams() as pins, mock.patch.object(X.RealHost, "pin") as pin:
            code, _, shown, err = self.run_main("clock-probe", SPEC, "--duration", "3", "--out", out)
        self.assertEqual((code, err), (X.EXIT_OK, ""))
        pin.assert_called_once_with(pins["daemon"])
        self.assertIn("clock probe: 2 of 2 streams gave a reference (3 s each)", shown)
        self.assertIn("estimator bias", shown)
        self.assertRegex(shown, r"legit streams: launched over \d\.\d{3} s; loops began over \d\.\d{3} s \(min \d+\.\d{3}, "
                                r"median \d+\.\d{3}, max \d+\.\d{3} after the first launch\); the estimator puts them over "
                                r"\d\.\d{3} s \(\d\.\d{3} s without the wall-time correction\), which a run holds to 0\.5 s")
        self.assertRegex(shown, r"wall time raised to what the records need: median \d\.\d{3} s, max \d\.\d{3} s")
        self.assertTrue(os.path.exists(os.path.join(out, "clock_probe.json")))

    def test_clock_probe_with_attack_says_so_and_runs_the_attack_streams(self):
        out = os.path.join(self.tmp.name, "probe")
        with few_streams(), mock.patch.object(X.RealHost, "pin"):
            code, _, shown, _ = self.run_main("clock-probe", SPEC, "--duration", "3", "--attack", "--out", out)
        self.assertEqual(code, X.EXIT_OK)
        self.assertIn("4 of 4 streams gave a reference", shown)
        self.assertIn("error against requests:", shown)

    def test_a_run_prints_its_figures_by_link_for_the_first_real_records(self):
        host = F.SimHost(server=F.SyntheticServer(self.cal, (10.0, 10.0, 10.0)))
        code, _, shown, _ = self.run_main(*self.base(), host=host)
        self.assertEqual(code, X.EXIT_OK)
        self.assertIn("figures over 10-20 s, the judged links (perfect, broadband): Q 100.00 %", shown)
        for profile, judged, q in (("perfect", "judged", r"100\.0"), ("broadband", "judged", r"100\.0"),
                                   ("mobile_3g", "not judged", r"\d\d?\.\d"), ("mobile_bad", "not judged", r"\d\d?\.\d")):
            self.assertRegex(shown, rf"{profile}\s+{judged}\s+\d+ requests, Q {q} %")
        self.assertRegex(shown, r"p95 [1-9]\d* ms, slip p99 [1-9]\d* ms")

    def test_the_plan_prints_the_overrides_it_was_given(self):
        code, _, shown, _ = self.run_main("plan", SPEC, "--kind", "U", "--out", os.path.join(self.tmp.name, "U"), "--rho", "20",
                                          "--timeline", "10,10,10")
        self.assertEqual(code, X.EXIT_OK)
        self.assertIn("OVERRIDES", shown)
        self.assertIn("timeline_s", shown)

    def test_the_plan_subcommand_never_imports_the_suite(self):
        code = ("import sys\n"
                f"sys.path.insert(0, {os.path.join(REPO, 'bench')!r})\n"
                "import executor as X\n"
                f"X.main(['plan', {SPEC!r}, '--kind', 'C'])\n"
                "print('SUITE' if 'test_distributed_suite' in sys.modules else 'NO-SUITE')\n")
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.split()[-1], "NO-SUITE")


if __name__ == "__main__":
    unittest.main()
