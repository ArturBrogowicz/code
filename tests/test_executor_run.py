"""The executor's run half (docs/HG1C_DESIGN.md 6), on the simulated host of bench/sim_host.py: nothing here needs root, creates
a namespace or starts a server. What cannot be tested this way is listed in docs/HG1C_DESIGN.md 9 and is what S1-S4 are for."""
import contextlib
import csv
import dataclasses
import gzip
import io
import itertools
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
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


def bare_settings(**changes):
    return {"readiness_timeout_s": 5.0, **changes}


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
        self.assertEqual(meta["executor"]["estimator"], "exit-minus-wall")

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
        self.assertAlmostEqual(X.launch_attack_after(plan), 10.0 + 1.8 - 0.3)

    def test_the_attack_streams_sit_at_the_baseline_on_the_runs_axis(self):
        plan, _, _ = self.go("U")
        run = self.run_json(plan)
        offsets = {s["kind"]: s["offset_s"] for s in run["streams"]}
        self.assertAlmostEqual(offsets["attack"], 10.0, delta=0.06)
        self.assertAlmostEqual(offsets["legit"], 0.0, delta=0.06)
        self.assertLess(abs(run["executor"]["attack_start_error_s"]), 0.06)
        self.assertEqual(run["executor"]["launch_attack_after_s"], 11.5)

    def test_a_control_run_launches_no_attack_stream(self):
        plan, host, _ = self.go("C")
        self.assertFalse([sid for sid in host.launch_times if sid.startswith("A-")])
        self.assertIsNone(self.run_json(plan)["executor"]["launch_attack_after_s"])

    def test_the_offsets_are_from_the_median_legit_start_whatever_the_streams_took_to_start(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + 0.01 * index if kind == "legit" else 0.3)
        plan, _, result = self.go("U", host)
        self.assertTrue(result.ok, result.reasons)
        legit = [s["offset_s"] for s in self.run_json(plan)["streams"] if s["kind"] == "legit"]
        self.assertAlmostEqual(sorted(legit)[len(legit) // 2], 0.0, delta=0.01)
        self.assertAlmostEqual(max(legit) - min(legit), 0.28, delta=0.01)

    def test_a_stream_that_starts_late_makes_the_run_unsound_and_is_still_placed(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + (0.8 if index == 7 else 0.0))
        plan, _, result = self.go("C", host)
        self.assertFalse(result.ok)
        self.assertTrue(any("apart" in r for r in result.reasons), result.reasons)
        run = H.read_run(plan.out)
        self.assertEqual(run["executor"]["ok"], False)
        late = max(s["offset_s"] for s in run["streams"])
        self.assertAlmostEqual(late, 0.8, delta=0.02)

    def test_an_attack_that_starts_off_the_end_of_the_baseline_makes_the_run_unsound(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 if kind == "legit" else 1.3)
        plan, _, result = self.go("U", host)
        self.assertFalse(result.ok)
        self.assertTrue(any("the attack began +1.00 s" in r for r in result.reasons), result.reasons)
        self.assertAlmostEqual(self.run_json(plan)["executor"]["attack_start_error_s"], 1.0, delta=0.01)

    def test_a_common_delay_between_the_loop_and_the_exit_cancels(self):
        slow = F.SimHost(exit_delay_s=0.9)
        plan, _, result = self.go("U", slow)
        self.assertTrue(result.ok, result.reasons)
        self.assertLess(abs(self.run_json(plan)["executor"]["attack_start_error_s"]), 0.06)

    def test_an_exit_delay_that_grows_with_the_requests_is_taken_off_when_it_is_known(self):
        per = 5e-3                             # the attack streams have tens of requests more than the legit ones: 5 ms each
        host = F.SimHost(exit_delay_per_request_s=per)
        plan, _, uncorrected = self.go("U", host, plan_args={"rho": 20.0, "name": "raw/U"})
        err_raw = self.run_json(plan)["executor"]["attack_start_error_s"]
        host = F.SimHost(exit_delay_per_request_s=per)
        plan, _, corrected = self.go("U", host, plan_args={"name": "fixed/U", "settings": {"exit_delay_per_request_s": per}})
        err_fixed = self.run_json(plan)["executor"]["attack_start_error_s"]
        self.assertTrue(uncorrected.ok and corrected.ok)
        self.assertGreater(abs(err_raw), 0.1)
        self.assertLess(abs(err_fixed), 0.06)

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

    def test_nginx_that_does_not_start_is_reported_with_what_it_said(self):
        _, _, why = self.build({"nginx_fails": None})
        self.assertIn("emerg", why)

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
        nginx = first(lambda kind, argv: kind == "run" and argv[:1] == ("taskset",) and "nginx" in argv)
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
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + (0.02 * (index % 30) if sid.startswith("S02-") else 0.0))
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
        found = {s.id: (100.0 + s.start_s + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 100) for s in shifted.streams}
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
            found[s.id] = (t0 + 40.0 - X.ENGINE_T0_OFFSET_S, 40.0, 100)
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


class EstimatorTest(RunCase):
    """The clocks of the streams, from what they report (docs/HG1C_DESIGN.md 6.6)."""

    def found(self, plan, legit=0.0, attack=None, wall=40.0, intended=100):
        """What the streams would report if the legit ones began at `legit(stream)` and the attack ones at `attack(stream)`
        on the executor's clock."""
        out = {}
        for i, s in enumerate(plan.streams):
            t0 = (legit(i) if callable(legit) else legit) if s.kind == "legit" else \
                (attack(i) if callable(attack) else attack)
            out[s.id] = (t0 + wall - X.ENGINE_T0_OFFSET_S, wall, intended)
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

    def test_the_run_is_unsound_when_the_legit_starts_are_further_apart_than_the_limit(self):
        plan = self.plan("C")
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
        plan = self.plan("C", settings={"t0_spread_limit_s": 0.05})
        al = X.alignment(plan, self.found(plan, legit=lambda i: 100.0 + (0.06 if i == 0 else 0.0)))
        self.assertEqual(len(al["reasons"]), 1)


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
    def row(error, intended=100, kind="legit", start=1.8, rss=30.0):
        return {"id": f"{kind}-{error}", "kind": kind, "rate": 10.0, "intended": intended, "start_after_launch_s": start,
                "estimator_minus_truth_s": error, "wall_s": 31.0, "cpu_s": 0.5, "rss_mib": rss}

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

    def test_nothing_reported_is_a_summary_of_nothing(self):
        s = X.clock_summary([], 29, 30.0)
        self.assertEqual((s["reported"], s["estimator_bias_s"], s["exit_delay_fit"]), (0, None, None))
        self.assertIn("0 of 29", X.clock_text(s, "/x"))


class ClockProbeTest(RunCase):
    """The probe on loopback with the real engine and two small streams: the pipeline, not the accuracy."""

    def test_two_streams_on_loopback_give_a_reference_each(self):
        mine = min(os.sched_getaffinity(0))
        pins = {"server": str(mine), "daemon": str(mine), "legit": str(mine), "attack": str(mine)}
        real = SC.population_of

        class Few:
            def __init__(self, pop):
                self.pop = pop

            def of_kind(self, kind):
                return [s for s in self.pop.of_kind(kind) if s.rate >= 2.0][:2]

        def small(*a, **k):
            pop, level = real(*a, **k)
            return Few(pop), level
        out = os.path.join(self.tmp.name, "probe")
        with mock.patch.object(SC, "population_of", small), mock.patch.object(P, "PIN_PLAN", pins):
            result = X.clock_probe(self.scn, self.cal, 1, 3.0, out)
        self.assertEqual((result["streams"], result["reported"]), (2, 2), result)
        for row in result["rows"]:
            self.assertTrue(0.0 < row["start_after_launch_s"] < 10.0, row)
            self.assertLess(abs(row["estimator_minus_truth_s"]), 1.0, row)
            self.assertGreater(row["rss_mib"], 5.0)
        self.assertTrue(os.path.exists(os.path.join(out, "clock_probe.json")))
        self.assertTrue(os.path.exists(os.path.join(out, "streams", result["rows"][0]["id"], "loadgen.records.csv.gz")))


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

    def test_the_signal_handler_ends_the_run_like_ctrl_c(self):
        _, handlers, _, _ = self.run_main(*self.base(), host=F.SimHost())
        handler = handlers.call_args_list[0].args[1]
        with self.assertRaises(KeyboardInterrupt):
            handler(signal.SIGTERM, None)

    def test_an_unsound_run_exits_three(self):
        host = F.SimHost(startup_s=lambda sid, index, kind: 1.8 + (0.8 if index == 3 else 0.0))
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
