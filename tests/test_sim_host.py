"""The simulated host and its synthetic server (bench/sim_host.py): the model that stands in for the machine in the executor's and
the campaign's tests and in `gate_campaign.py --simulate`. The server is not a model of any server: it makes a harm of a known
size, so the tests check that it does, where it should, and that the harm gate reads what it writes."""
import csv
import gzip
import json
import os
import sys
import tempfile
import unittest

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "eval"))
import calibration as C
import calibration_fixtures as CF
import executor as X
import harm_gate as H
import origin as O
import scenario as SC
import sim_host as S

SPEC = os.path.join(REPO, "bench", "scenarios", "costly_search_sub_threshold.json")
TIMELINE = (10.0, 10.0, 10.0)
CAL = CF.placeholder_with_knees()


class StreamIdTest(unittest.TestCase):
    def test_legit_and_attack_ids(self):
        self.assertEqual(S.parse_stream_id("L-poisson-C0-broadband-1"), ("legit", "C0", "broadband"))
        self.assertEqual(S.parse_stream_id("L-pulse-C3-mobile_3g-2"), ("legit", "C3", "mobile_3g"))
        self.assertEqual(S.parse_stream_id("A-costly_search_flood-perfect-0"), ("attack", "C3", "perfect"))
        self.assertEqual(S.parse_stream_id("A-cheap_static_flood-mobile_bad-3"), ("attack", "C1", "mobile_bad"))

    def test_every_stream_of_a_real_plan_parses_to_a_route_and_a_link_the_model_knows(self):
        scn = SC.load(SPEC)
        plan = X.plan_run(scn, CAL, "U", 1, "/var/tmp/ddos_campaigns/example/U", C.PLACEHOLDER)
        for s in plan.streams:
            kind, route, profile = S.parse_stream_id(s.id)
            with self.subTest(stream=s.id):
                self.assertEqual((kind, route, profile), (s.kind, s.route_class, s.netem))
                self.assertIn(profile, S.LINKS)
                self.assertIn(route, O.CLASSES)


class SyntheticServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, run="C", sid="L-constant-C1-perfect-0", rate=20.0, duration=30.0, effects=None, seed=5, identities=3, wall=30.5):
        workdir = os.path.join(self.tmp.name, "block", run, "streams", sid)          # the parent's name is part of the draw
        os.makedirs(workdir, exist_ok=True)
        opts = {"--rate": str(rate), "--duration": str(duration), "--process": "constant", "--seed": str(seed),
                "--summary": os.path.join(workdir, "loadgen.summary.json"),
                "--records": os.path.join(workdir, "loadgen.records.csv.gz")}
        n = S.SyntheticServer(CAL, TIMELINE, effects).write(sid, opts, wall, identities)
        with gzip.open(opts["--records"], "rt", newline="") as fh:
            rows = list(csv.DictReader(fh))
        with open(opts["--summary"], encoding="utf-8") as fh:
            return n, rows, json.load(fh)

    @staticmethod
    def column(rows, name):
        return np.array([float(r[name]) for r in rows])

    def mean_latency(self, rows):
        return float(np.mean(self.column(rows, "t_done") - self.column(rows, "t_sent")))

    def test_without_an_effect_every_request_succeeds_where_it_was_scheduled(self):
        n, rows, summary = self.write()
        self.assertEqual((n, len(rows)), (600, 600))
        self.assertEqual({r["status"] for r in rows}, {"200"})
        self.assertEqual({r["err"] for r in rows}, {""})
        t_int, t_sent = self.column(rows, "t_intended"), self.column(rows, "t_sent")
        self.assertTrue(np.all(t_sent > t_int))
        self.assertLess(float(np.max(t_sent - t_int)), 0.01)
        self.assertEqual((summary["intended"], summary["completed"], summary["dropped"]), (600, 600, 0))
        self.assertEqual(summary["wall_s"], 30.5)
        self.assertEqual(summary["errors"], {})
        self.assertEqual({r["ident"] for r in rows}, {"0", "1", "2"})

    def test_an_effect_fails_requests_inside_the_attack_window_only(self):
        n, rows, summary = self.write(run="U", effects={"U": {"fail_p": 1.0}})
        t_int = self.column(rows, "t_intended")
        failed = np.array([r["err"] == "timeout" for r in rows])
        inside = (t_int >= 10.0) & (t_int < 20.0)
        self.assertTrue(np.all(failed[inside]))
        self.assertFalse(np.any(failed[~inside]))
        self.assertEqual(summary["errors"], {"timeout": int(inside.sum())})
        self.assertEqual(summary["completed"], n - int(inside.sum()))
        done, sent = self.column(rows, "t_done"), self.column(rows, "t_sent")
        self.assertTrue(np.allclose((done - sent)[failed], S.TIMEOUT_S))
        self.assertEqual({r["status"] for r, f in zip(rows, failed, strict=True) if f}, {"0"})

    def test_the_loop_lasts_until_the_last_request_is_done_a_timeout_included(self):
        _, rows, summary = self.write(run="U", effects={"U": {"fail_p": 1.0}}, wall=25.0)
        last = float(np.max(self.column(rows, "t_done")))
        self.assertGreater(last, 29.9, "the requests sent at the end of the window time out ten seconds later")
        self.assertAlmostEqual(summary["wall_s"], last + X.ENGINE_T0_OFFSET_S, places=5, msg="the records hold six decimals")

    def test_a_wall_time_that_holds_the_last_request_is_left_as_given(self):
        _, rows, summary = self.write(wall=31.7)
        self.assertEqual(summary["wall_s"], 31.7)
        self.assertLess(float(np.max(self.column(rows, "t_done"))) + X.ENGINE_T0_OFFSET_S, 31.7)

    def test_an_effect_of_a_given_share_fails_about_that_share(self):
        _, rows, _ = self.write(run="U", rate=200.0, effects={"U": {"fail_p": 0.3}})
        t_int = self.column(rows, "t_intended")
        inside = (t_int >= 10.0) & (t_int < 20.0)
        share = np.mean([r["err"] == "timeout" for r, i in zip(rows, inside, strict=True) if i])
        self.assertAlmostEqual(float(share), 0.3, delta=0.05)

    def test_a_slowdown_multiplies_the_service_time_inside_the_window_only(self):
        _, rows, _ = self.write(run="U", rate=100.0, effects={"U": {"slow": 3.0}})
        t_int, latency = self.column(rows, "t_intended"), self.column(rows, "t_done") - self.column(rows, "t_sent")
        inside = (t_int >= 10.0) & (t_int < 20.0)
        self.assertAlmostEqual(float(np.mean(latency[inside]) / np.mean(latency[~inside])), 3.0, delta=0.5)

    def test_an_effect_is_for_the_run_it_names(self):
        _, rows, _ = self.write(run="C", effects={"U": {"fail_p": 1.0}})
        self.assertEqual({r["err"] for r in rows}, {""})

    def test_an_effect_does_not_touch_an_attack_stream(self):
        n, _, summary = self.write(run="U", sid="A-costly_search_flood-perfect-0", rate=100.0, effects={"U": {"fail_p": 1.0}})
        self.assertEqual(summary["errors"], {})
        self.assertEqual(summary["intended"], n)

    def test_the_slip_of_the_generator_is_the_effects_to_set(self):
        _, _, summary = self.write(run="U", effects={"U": {"slip": 0.2}})
        self.assertGreater(summary["slip_s"]["p99"], 0.1)
        _, _, quiet = self.write(run="C")
        self.assertLess(quiet["slip_s"]["p99"], 0.01)

    def test_the_link_adds_its_delay(self):
        _, perfect, _ = self.write(sid="L-constant-C1-perfect-0", rate=100.0)
        _, mobile, _ = self.write(sid="L-constant-C1-mobile_3g-1", rate=100.0)
        self.assertGreater(self.mean_latency(mobile) - self.mean_latency(perfect), 0.1)

    def test_a_route_costs_what_the_calibration_says(self):
        _, cheap, _ = self.write(sid="L-constant-C0-perfect-0", rate=100.0)
        _, dear, _ = self.write(sid="L-constant-C5-perfect-0", rate=100.0)
        self.assertAlmostEqual(self.mean_latency(dear) / self.mean_latency(cheap),
                               CAL["route_costs_ms"]["C5"] / CAL["route_costs_ms"]["C0"], delta=40)
        self.assertGreater(self.mean_latency(dear), 0.1)

    def test_the_same_run_and_stream_give_the_same_records_and_another_run_does_not(self):
        _, a, _ = self.write(run="C")
        _, b, _ = self.write(run="C")
        _, c, _ = self.write(run="Cp")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual([r["t_intended"] for r in a], [r["t_intended"] for r in c], "the same clients in both")

    def test_the_stream_seed_changes_the_schedule_of_a_random_process(self):
        workdir = os.path.join(self.tmp.name, "block", "C", "streams", "L-poisson-C1-perfect-0")
        os.makedirs(workdir)
        times = []
        for seed in (1, 2):
            opts = {"--rate": "20", "--duration": "10", "--process": "poisson", "--seed": str(seed),
                    "--summary": os.path.join(workdir, f"s{seed}.json"), "--records": os.path.join(workdir, f"r{seed}.csv.gz")}
            S.SyntheticServer(CAL, TIMELINE).write("L-poisson-C1-perfect-0", opts, 10.5, 1)
            with gzip.open(opts["--records"], "rt", newline="") as fh:
                times.append([r["t_intended"] for r in csv.DictReader(fh)])
        self.assertNotEqual(times[0], times[1])

    def test_an_attack_streams_records_are_cut_short_and_its_summary_is_not(self):
        n, rows, summary = self.write(run="U", sid="A-costly_search_flood-perfect-0", rate=100.0, duration=30.0)
        self.assertEqual(len(rows), S.ATTACK_RECORDS)
        self.assertEqual((n, summary["intended"], summary["sent"]), (3000, 3000, 3000))


class MeasuredTest(unittest.TestCase):
    """The simulated machine is the one that S1 and S1b measured, and the executor's settings are chosen to match it."""

    def test_the_exit_delay_per_request_is_the_settings(self):
        self.assertEqual(S.EXIT_DELAY_PER_REQUEST_S, X.SETTINGS["exit_delay_per_request_s"])

    def test_the_start_ups_are_within_what_the_settings_cover(self):
        self.assertAlmostEqual(S.LEGIT_STARTUP_S, X.SETTINGS["startup_delay_legit_s"], delta=0.15)
        self.assertAlmostEqual(S.ATTACK_STARTUP_S, X.SETTINGS["startup_delay_attack_s"], delta=0.05)
        self.assertLess(S.LEGIT_STARTUP_S, X.SETTINGS["startup_delay_legit_s"], "the settings cover the slowest of S1b's, 2.55 s, and S4's 2.8 s")


class StreamExitTest(unittest.TestCase):
    """When a simulated engine exits and what its summary says about its wall time."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def start(self, host, run="C", sid="L-constant-C1-perfect-0", rate=20.0, duration=30.0):
        workdir = os.path.join(self.tmp.name, "block", run, "streams", sid)
        os.makedirs(workdir)
        argv = ["python", "bench/loadgen.py", "--rate", str(rate), "--duration", str(duration), "--process", "constant", "--seed", "1",
                "--summary", os.path.join(workdir, "loadgen.summary.json"),
                "--records", os.path.join(workdir, "loadgen.records.csv.gz")]
        return host.popen(argv), os.path.join(workdir, "loadgen.summary.json")

    @staticmethod
    def wall(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)["wall_s"]

    LAST = (600 - 0.5) * 30.0 / 600                  # the last of 600 requests in 30 s is due then, after the schedule's zero
    START = S.LEGIT_STARTUP_S                        # an engine's loop begins this long after its launch (the first of its batch)

    def exit_at(self, wall, requests):
        """When an engine exits, after the launch: its loop begins, lasts `wall`, and it takes its exit delay, a little more for each request."""
        return self.START + wall + 0.04 + S.EXIT_DELAY_PER_REQUEST_S * requests

    def test_an_engine_reports_the_wall_time_of_its_loop_which_ends_with_its_last_request(self):
        host = S.SimHost()
        proc, summary = self.start(host)
        host.sleep(40.0)
        self.assertEqual(proc.returncode, 0)
        self.assertAlmostEqual(self.wall(summary), self.LAST + 0.011 + X.ENGINE_T0_OFFSET_S)
        self.assertAlmostEqual(proc.exit_time - S.BASE_EPOCH, self.exit_at(self.wall(summary), 600), places=5)

    def test_an_engine_descheduled_between_its_two_clock_readings_reports_that_much_less(self):
        host = S.SimHost(wall_late_s=lambda sid, index, kind: 2.0)
        proc, summary = self.start(host)
        host.sleep(40.0)
        self.assertAlmostEqual(self.wall(summary), self.LAST + 0.011 + X.ENGINE_T0_OFFSET_S - 2.0)
        self.assertAlmostEqual(proc.exit_time - S.BASE_EPOCH, self.exit_at(self.LAST + 0.011 + X.ENGINE_T0_OFFSET_S, 600), places=5,
                               msg="it still exits when its loop did")

    def test_the_hook_is_asked_for_the_stream_its_place_among_those_launched_together_and_its_kind(self):
        asked = []
        host = S.SimHost(wall_late_s=lambda sid, index, kind: asked.append((sid, index, kind)) or 0.0)
        self.start(host, sid="L-constant-C1-perfect-0")
        self.start(host, sid="L-constant-C2-perfect-0")
        self.assertEqual(asked, [("L-constant-C1-perfect-0", 0, "legit"), ("L-constant-C2-perfect-0", 1, "legit")])

    def test_a_stream_of_few_requests_is_gone_long_before_its_duration_is_over(self):
        host = S.SimHost()
        proc, summary = self.start(host, rate=0.07)                  # two requests in 30 s: the last is due at 22.5 s
        host.sleep(23.0)
        self.assertIsNone(proc.returncode)
        host.sleep(3.0)
        self.assertEqual(proc.returncode, 0)
        self.assertAlmostEqual(self.wall(summary), 22.5 + 0.011 + X.ENGINE_T0_OFFSET_S)
        self.assertAlmostEqual(proc.exit_time - S.BASE_EPOCH, self.exit_at(22.5 + 0.011 + 0.05, 2), places=5)

    def test_with_a_server_the_engine_exits_when_the_last_request_of_its_records_is_answered(self):
        host = S.SimHost(server=S.SyntheticServer(CAL, TIMELINE, {}))
        proc, summary = self.start(host, rate=3.0)
        host.sleep(40.0)
        with gzip.open(os.path.join(os.path.dirname(summary), "loadgen.records.csv.gz"), "rt", newline="") as fh:
            rows = list(csv.DictReader(fh))
        last = max(float(r["t_done"]) for r in rows)
        self.assertAlmostEqual(self.wall(summary), last + X.ENGINE_T0_OFFSET_S, places=5)
        self.assertAlmostEqual(proc.exit_time - S.BASE_EPOCH, self.exit_at(last + 0.05, len(rows)), places=5)

    def test_a_silent_engine_ends_with_its_last_send_and_leaves_nothing(self):
        host = S.SimHost(silent=lambda sid: True)
        proc, summary = self.start(host)
        host.sleep(40.0)
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(os.path.exists(summary))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(summary), "loadgen.records.csv.gz")))
        self.assertAlmostEqual(proc.exit_time - S.BASE_EPOCH, self.exit_at(0.05 + self.LAST, 600), places=5)

    def test_an_engine_can_exit_non_zero_and_keep_its_files(self):
        host = S.SimHost(nonzero=lambda sid: True)
        proc, summary = self.start(host)
        host.sleep(40.0)
        self.assertEqual(proc.returncode, 3)
        self.assertTrue(os.path.exists(summary))

    def test_the_part_of_the_exit_delay_that_grows_with_the_requests_is_added_per_request(self):
        plain, slow = S.SimHost(exit_delay_per_request_s=0.0), S.SimHost(exit_delay_per_request_s=0.001)
        a, _ = self.start(plain, run="A")
        b, _ = self.start(slow, run="B")
        plain.sleep(40.0)
        slow.sleep(40.0)
        self.assertAlmostEqual(b.exit_time - a.exit_time, 0.001 * 600, places=5)

    def test_when_every_engine_of_a_run_dies_the_streams_of_another_run_live(self):
        host = S.SimHost(faults={"engines_die": 1})
        first, _ = self.start(host, run="C", sid="L-constant-C1-perfect-0")
        second, _ = self.start(host, run="C", sid="L-constant-C2-perfect-0")
        other, _ = self.start(host, run="Cp", sid="L-constant-C1-perfect-0")
        host.sleep(10.0)
        self.assertEqual((first.returncode, second.returncode, other.returncode), (2, 2, None))

    def test_an_engine_whose_last_requests_time_out_outlives_its_duration_and_exits_when_the_last_is_done(self):
        late = (20.0, 10.0, 10.0)                       # the window of the effect ends with the run: its timeouts end ten seconds later
        host = S.SimHost(server=S.SyntheticServer(CAL, late, {"U": {"fail_p": 1.0}}))
        proc, summary = self.start(host, run="U")
        host.sleep(35.0)
        self.assertIsNone(proc.returncode, "its requests time out until 40 s")
        host.sleep(15.0)
        self.assertEqual(proc.returncode, 0)
        wall = self.wall(summary)
        self.assertGreater(wall, 39.9)
        with gzip.open(os.path.join(os.path.dirname(summary), "loadgen.records.csv.gz"), "rt", newline="") as fh:
            requests = len(list(csv.DictReader(fh)))
        self.assertAlmostEqual(proc.exit_time - S.BASE_EPOCH, self.exit_at(wall, requests), places=5)

    def test_a_signal_ends_an_engine_that_is_waiting_for_its_requests(self):
        late = (20.0, 10.0, 10.0)
        host = S.SimHost(server=S.SyntheticServer(CAL, late, {"U": {"fail_p": 1.0}}))
        proc, _ = self.start(host, run="U")
        host.sleep(35.0)
        proc.terminate()
        self.assertEqual(proc.returncode, -15)
        host.sleep(15.0)
        self.assertEqual(proc.returncode, -15, "its late exit does not overwrite how it ended")


class LoadModelTest(unittest.TestCase):
    """A server with a capacity: what fits is served, what does not fit fails, and a full server is slow."""
    COST_C1 = CAL["route_costs_ms"]["C1"] / 1000          # 3 ms: 100 requests/s offer 0.3 CPU-s/s

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    @staticmethod
    def stream(kind="legit", begin=0.0, duration=30.0, rate=100.0, route="C1"):
        return {"kind": kind, "begin": begin, "end": begin + duration, "rate": rate, "route": route}

    def server(self, capacity_cpu):
        return S.SyntheticServer(CAL, TIMELINE, capacity_cpu=capacity_cpu)

    def write(self, capacity_cpu, own, others, run="C", sid="L-constant-C1-perfect-0", seed=5):
        workdir = os.path.join(self.tmp.name, "block", run, "streams", sid)
        os.makedirs(workdir, exist_ok=True)
        opts = {"--rate": str(own["rate"]), "--duration": str(own["end"] - own["begin"]), "--process": "constant",
                "--seed": str(seed), "--summary": os.path.join(workdir, "loadgen.summary.json"),
                "--records": os.path.join(workdir, "loadgen.records.csv.gz")}
        self.server(capacity_cpu).write(sid, opts, 30.5, 1, others, own["begin"])
        with gzip.open(opts["--records"], "rt", newline="") as fh:
            rows = list(csv.DictReader(fh))
        return {k: np.array([float(r[k]) if k != "err" else r[k] == "timeout" for r in rows])
                for k in ("t_intended", "t_sent", "t_done", "status", "err")}

    def test_utilisation_is_the_load_of_the_streams_that_are_running_over_the_capacity(self):
        own = self.stream()
        extra = self.stream(begin=10.0, duration=10.0, rate=200.0)
        server = self.server(0.6)
        times = np.array([0.0, 9.9, 10.0, 19.9, 20.0, 29.9])
        u = server.utilisation(times, 0.0, [own, extra])
        self.assertTrue(np.allclose(u, [0.5, 0.5, 1.5, 1.5, 0.5, 0.5]), u)

    def test_the_axis_starts_where_the_first_legit_stream_began(self):
        first, late = self.stream(begin=100.0), self.stream(begin=110.0, duration=10.0, rate=200.0)
        u = self.server(0.6).utilisation(np.array([0.0, 5.0]), 110.0, [first, late])
        self.assertTrue(np.allclose(u, [1.5, 1.5]), "the late stream's own time 0 is 10 s into the run")

    def test_an_attack_adds_its_cost_while_it_runs_and_a_step_only_its_own(self):
        legit = self.stream()
        attack = self.stream(kind="attack", begin=10.0, duration=10.0, rate=10.0, route="C3")      # 10 x 30 ms = 0.3 CPU-s/s
        u = self.server(0.6).utilisation(np.array([5.0, 15.0, 25.0]), 0.0, [legit, attack])
        self.assertTrue(np.allclose(u, [0.5, 1.0, 0.5]), u)
        step0, step1 = self.stream(duration=6.0), self.stream(begin=6.0, duration=6.0, rate=200.0)
        u = self.server(0.6).utilisation(np.array([3.0, 9.0]), 0.0, [step0, step1])
        self.assertTrue(np.allclose(u, [0.5, 1.0]), "the steps do not add up: one ends where the next begins")

    def test_below_the_capacity_nothing_fails_and_nothing_is_slow(self):
        own = self.stream()
        loaded = self.write(0.6, own, [own])
        idle = self.write(1e9, own, [own], run="Cp")
        self.assertFalse(loaded["err"].any())
        lat = lambda r: float(np.mean(r["t_done"] - r["t_sent"]))
        self.assertAlmostEqual(lat(loaded), lat(idle), delta=0.002)

    def test_over_the_capacity_the_share_that_does_not_fit_fails(self):
        own = self.stream(rate=200.0)                       # 0.6 CPU-s/s on a server that does 0.3: u = 2
        r = self.write(0.3, own, [own])
        self.assertAlmostEqual(float(r["err"].mean()), 0.5, delta=0.04)

    def test_a_server_over_its_capacity_is_slower_by_the_load_over_the_capacity(self):
        own = self.stream(rate=300.0)                       # u = 3
        full = self.write(0.3, own, [own])
        idle = self.write(1e9, own, [own], run="Cp")
        ok = ~full["err"]
        slow = float(np.mean((full["t_done"] - full["t_sent"])[ok]))
        quick = float(np.mean(idle["t_done"] - idle["t_sent"]))
        self.assertAlmostEqual(slow / quick, 3.0, delta=0.4)

    def test_the_harm_is_where_the_attack_is(self):
        own = self.stream(rate=100.0)
        attack = self.stream(kind="attack", begin=10.0, duration=10.0, rate=40.0, route="C3")      # +1.2 CPU-s/s on 0.4: u = 4
        r = self.write(0.4, own, [own, attack])
        inside = (r["t_intended"] >= 10.0) & (r["t_intended"] < 20.0)
        self.assertFalse(r["err"][~inside].any(), "outside the attack the server has room")
        self.assertGreater(float(r["err"][inside].mean()), 0.5)

    def test_an_attack_stream_is_not_itself_hurt(self):
        attack = self.stream(kind="attack", rate=40.0, route="C3")
        r = self.write(0.1, attack, [self.stream(), attack], run="U", sid="A-costly_search_flood-perfect-0")
        self.assertFalse(r["err"].any())

    def test_a_run_that_has_no_capacity_model_uses_its_effects(self):
        server = S.SyntheticServer(CAL, TIMELINE, {"U": {"fail_p": 1.0}})
        self.assertIsNone(server.capacity_cpu)


class DaemonTest(unittest.TestCase):
    """Nginx daemonises. Run to completion with its output captured, its daemon keeps the pipes and the call returns at its timeout,
    as the one in S3 did three times; started like the suite starts it, with no pipe, the launcher returns once the daemon has forked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conf = os.path.join(self.tmp.name, "nginx.conf")
        with open(self.conf, "w", encoding="utf-8") as fh:
            fh.write("http { access_log /x/nginx_access.log json_ml_format; }\n")
        self.argv = ["taskset", "-c", "0-1", "nginx", "-c", self.conf]

    @staticmethod
    def daemons(host):
        return [p for p in host.alive("server_ns") if p.role == "nginx"]

    def test_a_captured_call_returns_at_its_timeout_with_the_daemon_up(self):
        host = S.SimHost()
        r = host.run(self.argv, ns="server_ns")
        self.assertEqual((r.code, r.out, r.err), (-1, "", "timeout"))
        self.assertEqual(host.t, X.RealHost.COMMAND_TIMEOUT_S)
        self.assertEqual([p.cpus for p in self.daemons(host)], ["0-1", "0-1"])

    def test_the_timeout_is_the_callers(self):
        host = S.SimHost()
        host.run(self.argv, ns="server_ns", timeout=7.0)
        self.assertEqual(host.t, 7.0)
        host.run(["ip", "link"], ns="")
        host.run(self.argv, ns="server_ns")
        self.assertEqual(host.t, 7.0 + X.RealHost.COMMAND_TIMEOUT_S, "a call without a timeout is not given the last call's")

    def test_without_the_model_the_call_returns_at_once(self):
        host = S.SimHost(daemon_holds_pipes=False)
        r = host.run(self.argv, ns="server_ns")
        self.assertEqual((r.code, host.t, len(self.daemons(host))), (0, 0.0, 2))

    def test_started_with_no_pipe_the_launcher_returns_after_the_fork_and_the_daemon_stays(self):
        host = S.SimHost()
        launcher = host.popen(self.argv, ns="server_ns")
        self.assertEqual((host.t, launcher.poll(), len(self.daemons(host))), (0.0, None, 2))
        host.sleep(S.NGINX_FORK_S / 2)
        self.assertIsNone(launcher.poll())
        host.sleep(S.NGINX_FORK_S / 2)
        self.assertEqual((launcher.poll(), len(self.daemons(host))), (0, 2))

    def test_a_start_that_fails_returns_1_at_once_with_the_message_on_stderr_and_no_daemon(self):
        host = S.SimHost(faults={"nginx_fails": None})
        path = os.path.join(self.tmp.name, "nginx_start.log")
        with open(path, "ab") as err:
            launcher = host.popen(self.argv, ns="server_ns", stderr=err)
        self.assertEqual((launcher.poll(), self.daemons(host)), (1, []))
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "nginx: [emerg] bind() to 0.0.0.0:80 failed\n")
        r = host.run(self.argv, ns="server_ns")
        self.assertEqual((r.code, r.err, host.t), (1, "nginx: [emerg] bind() to 0.0.0.0:80 failed", 0.0))

    def test_nginx_that_does_not_daemonise_never_returns(self):
        host = S.SimHost(faults={"nginx_foreground": None})
        launcher = host.popen(self.argv, ns="server_ns")
        host.sleep(600.0)
        self.assertIsNone(launcher.poll())

    def test_the_launcher_is_taken_for_nginx_by_what_it_runs_not_by_a_word_in_a_path(self):
        host = S.SimHost()
        conf = os.path.join(self.tmp.name, "gunicorn", "nginx.conf")
        os.makedirs(os.path.dirname(conf))
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("http { access_log /x/a.log json_ml_format; }\n")
        launcher = host.popen(["taskset", "-c", "0-1", "nginx", "-c", conf], ns="server_ns")
        self.assertEqual(launcher.role, "launcher")
        self.assertEqual(len(self.daemons(host)), 2)


class DaemonModelTest(unittest.TestCase):
    """The mitigation daemon of the protected arms (control_plane.py, HG4 G13) as the model plays it: what it needs to start, when it
    is ready, what it attaches, whom it bans and when, and how each signal ends it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run = os.path.join(self.tmp.name, "b01_a1", "M_xdp")
        os.makedirs(self.run)
        self.events = os.path.join(self.run, "ban_events.jsonl")
        self.log = os.path.join(self.run, "daemon.log")

    @staticmethod
    def host(server_ns=True, **kw):
        host = S.SimHost(**kw)
        host.prim("bridge")
        if server_ns:
            host.prim("server_ns")
        return host

    def start(self, host, cwd=S.REPO, ns=X.SERVER_NS, env=None):
        env = {"MITIGATION_BACKEND": "xdp", "BAN_EVENTS": self.events, "XDP_GRU": "0"} if env is None else env
        with open(self.log, "ab") as fh:
            return host.popen(["taskset", "-c", "2", "/repo/venv/bin/python", "-u", os.path.join(S.REPO, "control_plane.py")],
                              ns=ns, env=env, stdout=fh, stderr=fh, cwd=cwd)

    def stream(self, host, sid, rate, addresses, run=None):
        """An engine process of `run` (default: this test's run) as the executor launches one, with its source addresses."""
        work = os.path.join(run or self.run, "streams", sid)
        os.makedirs(work, exist_ok=True)
        argv = ["prlimit", "--nofile=100", "--", "taskset", "-c", "6", "/repo/venv/bin/python", "bench/loadgen.py", "--rate", str(rate),
                "--duration", "20", "--process", "constant", "--seed", "1", "--summary", f"{work}/loadgen.summary.json",
                "--records", f"{work}/loadgen.records.csv.gz"]
        for ip in addresses:
            argv += ["--local-addr", ip]
        return host.popen(argv, ns="hg_0_perfect")

    def events_of(self, kind=None):
        if not os.path.exists(self.events):
            return []
        with open(self.events, encoding="utf-8") as fh:
            return [e for e in map(json.loads, fh) if kind is None or e["kind"] == kind]

    def said(self):
        with open(self.log, encoding="utf-8") as fh:
            return fh.read()

    @staticmethod
    def xdp(host, ns=X.SERVER_NS):
        return json.loads(host.run(["ip", "-j", "link", "show", "veth_server"], ns=ns).out)[0].get("xdp")

    @staticmethod
    def loaded(host):
        progs = json.loads(host.run(["bpftool", "-j", "prog", "show"]).out)
        maps = json.loads(host.run(["bpftool", "-j", "map", "show"]).out)
        return [p["id"] for p in progs], sorted({m["name"] for m in maps})

    def ready(self, host, **kw):
        daemon = self.start(host, **kw)
        host.sleep(S.DAEMON_STARTUP_S + 0.01)
        return daemon

    def test_it_is_ready_after_its_start_up_with_xdp_attached_its_start_event_written_and_its_line_said(self):
        host = self.host()
        daemon = self.start(host)
        host.sleep(S.DAEMON_STARTUP_S - 0.01)
        self.assertEqual((self.xdp(host), self.events_of(), self.loaded(host)[0]), (None, [], []))
        self.assertNotIn(S.DAEMON_LINES["listening"], self.said())
        host.sleep(0.02)
        self.assertIsNone(daemon.poll())
        prog = self.xdp(host)["prog"]
        self.assertEqual(prog["name"], S.XDP_PROG_NAME)
        (start,) = self.events_of()
        self.assertEqual((start["kind"], start["pid"], start["backend"], start["xdp_gru"], start["gru_only"], start["l7_shadow"]),
                         ("start", daemon.pid, "xdp", False, False, False))
        self.assertEqual(start["t_wall"], S.BASE_EPOCH + S.DAEMON_STARTUP_S, "written when it became ready")
        self.assertTrue(self.said().rstrip().endswith(S.DAEMON_LINES["listening"]))
        self.assertEqual(self.loaded(host), ([prog["id"]], sorted(S.DAEMON_MAPS)))

    def test_it_needs_the_checkout_as_its_working_directory(self):
        host = self.host()
        daemon = self.start(host, cwd="/")
        host.sleep(1.0)
        self.assertEqual(daemon.poll(), 1)
        self.assertIn("FileNotFoundError", self.said())
        self.assertEqual((self.xdp(host), self.events_of(), self.loaded(host)[0]), (None, [], []))

    def test_it_cannot_attach_outside_the_server_namespace(self):
        host = self.host(server_ns=False)
        daemon = self.start(host)
        host.sleep(S.DAEMON_STARTUP_S + 1.0)
        self.assertEqual(daemon.poll(), 1)
        self.assertIn("No such device", self.said())

    def test_sigint_runs_its_finally_which_detaches_xdp_and_ends_it_with_0(self):
        host = self.host()
        daemon = self.ready(host)
        daemon.interrupt()
        self.assertIsNone(daemon.poll(), "the finally takes a moment")
        host.sleep(S.DAEMON_STOP_S + 0.01)
        self.assertEqual(daemon.poll(), 0)
        self.assertEqual((self.xdp(host), self.loaded(host)[0]), (None, []))
        self.assertIn(S.DAEMON_LINES["detached"], self.said())

    def test_term_and_kill_end_it_at_once_and_leave_the_program_attached_until_the_namespace_goes(self):
        for stop, code in ((lambda p: p.terminate(), -15), (lambda p: p.kill(), -9)):
            with self.subTest(code=code):
                host = self.host()
                daemon = self.ready(host)
                stop(daemon)
                self.assertEqual(daemon.poll(), code)
                self.assertIsNotNone(self.xdp(host), "nothing ran its finally")
                self.assertEqual(len(self.loaded(host)[0]), 1, "attached, the program stays loaded")
                host.run(["ip", "netns", "del", X.SERVER_NS])
                self.assertEqual(self.loaded(host), ([], []))

    def test_xdp_off_detaches_the_program(self):
        host = self.host()
        daemon = self.ready(host)
        daemon.kill()
        self.assertEqual(host.run(["ip", "link", "set", "dev", "veth_server", "xdp", "off"], ns=X.SERVER_NS).code, 0)
        self.assertEqual((self.xdp(host), self.loaded(host)[0]), (None, []))

    def test_a_daemon_that_ignores_sigint_ends_only_on_kill(self):
        host = self.host(faults={"daemon_ignores_int": 1})
        daemon = self.ready(host)
        daemon.interrupt()
        host.sleep(5.0)
        self.assertIsNone(daemon.poll())
        daemon.kill()
        self.assertEqual(daemon.poll(), -9)
        self.assertIsNotNone(self.xdp(host))

    def test_a_pinned_program_outlives_the_daemon_and_the_namespace(self):
        host = self.host(faults={"xdp_leftover": None})
        daemon = self.ready(host)
        prog = self.xdp(host)["prog"]["id"]
        daemon.kill()
        host.run(["ip", "netns", "del", X.SERVER_NS])
        self.assertEqual(self.loaded(host), ([prog], sorted(S.DAEMON_MAPS)))

    def test_each_source_above_the_rule_is_banned_after_the_delay_and_a_source_below_it_never(self):
        host = self.host()
        self.ready(host)
        began = host.t
        self.stream(host, "A-cheap_static_flood-perfect-0", 300.0, ["10.0.2.1", "10.0.2.2", "10.0.2.3"])
        self.stream(host, "A-costly_search_flood-perfect-1", 30.0, ["10.0.2.4", "10.0.2.5", "10.0.2.6"])
        host.sleep(10.0)
        bans = self.events_of("ban")
        self.assertEqual(sorted(e["ip"] for e in bans), ["10.0.2.1", "10.0.2.2", "10.0.2.3"])
        loop_start = began + S.ATTACK_STARTUP_S
        for e in bans:
            self.assertEqual((e["engine"], e["enforced"], e["value"]), ("l7_rate", True, 100.0))
            self.assertAlmostEqual(e["t_wall"] - S.BASE_EPOCH, loop_start + X.ENGINE_T0_OFFSET_S + S.DAEMON_BAN_DELAY_S, delta=0.01)
        self.assertEqual(sorted(host.bans[self.run]), ["10.0.2.1", "10.0.2.2", "10.0.2.3"])

    def test_a_stream_of_another_run_or_one_before_the_daemon_is_ready_is_not_banned(self):
        host = self.host()
        other = os.path.join(self.tmp.name, "b01_a1", "U")
        self.start(host)
        self.stream(host, "A-cheap_static_flood-perfect-0", 300.0, ["10.0.2.1"])           # its ban is due before the daemon is ready
        host.sleep(S.DAEMON_STARTUP_S + 0.5)
        self.stream(host, "A-cheap_static_flood-perfect-0", 300.0, ["10.0.2.9"], run=other)
        host.sleep(10.0)
        self.assertEqual(self.events_of("ban"), [])

    def test_the_fault_daemon_bans_benign_bans_the_first_source_of_one_legit_stream(self):
        host = self.host(faults={"daemon_bans_benign": 1})
        self.ready(host)
        self.stream(host, "L-poisson-C1-perfect-0", 2.0, ["10.0.1.20", "10.0.1.21"])
        self.stream(host, "L-poisson-C2-perfect-0", 2.0, ["10.0.1.30"])
        host.sleep(10.0)
        self.assertEqual([e["ip"] for e in self.events_of("ban")], ["10.0.1.20"])

    def test_a_daemon_that_dies_runs_its_finally_and_its_bans_are_lifted(self):
        host = self.host(faults={"daemon_dies": 1})
        daemon = self.ready(host)
        self.stream(host, "A-cheap_static_flood-perfect-0", 300.0, ["10.0.2.1"])
        host.sleep(S.DAEMON_DIES_AFTER_S + 0.1)
        self.assertEqual(daemon.poll(), 1)
        self.assertIn("UnicodeDecodeError", self.said())
        self.assertIsNone(self.xdp(host))
        self.assertAlmostEqual(host.bans[self.run]["10.0.2.1"][1], S.DAEMON_STARTUP_S + S.DAEMON_DIES_AFTER_S, delta=0.001)

    def test_without_ban_events_or_without_xdp_nothing_is_recorded_or_enforced(self):
        host = self.host(faults={"daemon_no_events": 1})
        self.ready(host)
        self.assertEqual(self.events_of(), [])
        host = self.host()
        self.ready(host, env={"MITIGATION_BACKEND": "xdp"})
        self.assertEqual(os.listdir(self.run), ["daemon.log"], "without BAN_EVENTS the model writes no file")
        host = self.host(faults={"xdp_not_attached": 1})
        self.ready(host)
        self.assertIsNone(self.xdp(host))
        self.assertIn(S.DAEMON_LINES["listening"], self.said())
        self.stream(host, "A-cheap_static_flood-perfect-0", 300.0, ["10.0.2.1"])
        host.sleep(5.0)
        self.assertEqual([e["enforced"] for e in self.events_of("ban")], [False])
        self.assertNotIn(self.run, host.bans)

    def test_the_start_event_says_what_the_environment_asked_for(self):
        host = self.host()
        self.ready(host, env={"MITIGATION_BACKEND": "iptables", "BAN_EVENTS": self.events, "GRU_ONLY": "1"})
        (start,) = self.events_of("start")
        self.assertEqual((start["backend"], start["gru_only"], start["xdp_gru"]), ("iptables", True, True))

    def test_bpftool_can_fail(self):
        host = self.host(faults={"bpftool_fails": 1})
        self.assertEqual(host.run(["bpftool", "-j", "prog", "show"]).code, 255)


class MitigatedServerTest(unittest.TestCase):
    """What the synthetic server does with the bans of a protected run: a banned source's requests time out while its ban holds, a
    banned attack source costs nothing, and U's harm lasts until every attack source is banned."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, run, sid="L-constant-C1-perfect-0", rate=20.0, effects=None, others=(), bans=None, local=()):
        workdir = os.path.join(self.tmp.name, "block", run, "streams", sid)
        os.makedirs(workdir, exist_ok=True)
        opts = {"--rate": str(rate), "--duration": "30", "--process": "constant", "--seed": "5",
                "--summary": os.path.join(workdir, "loadgen.summary.json"),
                "--records": os.path.join(workdir, "loadgen.records.csv.gz")}
        S.SyntheticServer(CAL, TIMELINE, effects).write(sid, opts, 30.5, max(1, len(local)), others, 0.0, bans=bans, local=local)
        with gzip.open(opts["--records"], "rt", newline="") as fh:
            rows = list(csv.DictReader(fh))
        return np.array([float(r["t_sent"]) for r in rows]), np.array([r["err"] == "timeout" for r in rows])

    def test_a_banned_sources_requests_time_out_while_its_ban_holds(self):
        zero = X.ENGINE_T0_OFFSET_S
        sent, failed = self.write("M_xdp", local=("10.0.1.5", "10.0.1.6"), bans={"10.0.1.5": [zero + 5.0, zero + 8.0]})
        first = np.arange(len(sent)) % 2 == 0
        inside = (sent >= 5.0) & (sent < 8.0)
        self.assertTrue(np.all(failed[first & inside]))
        self.assertFalse(np.any(failed[~(first & inside)]))

    def test_an_m_run_is_harmed_as_u_until_every_attack_source_is_banned(self):
        attack = [{"kind": "attack", "begin": 10.0, "end": 20.0, "rate": 100.0, "route": "C1", "addresses": ("10.0.2.1", "10.0.2.2")}]
        bans = {"10.0.2.1": [12.0, None], "10.0.2.2": [14.0, None]}
        sent, failed = self.write("M_xdp", effects={"U": {"fail_p": 1.0}}, others=attack, bans=bans)
        window = (sent >= 10.0) & (sent < 20.0)
        self.assertTrue(np.all(failed[window & (sent < 13.9)]))
        self.assertFalse(np.any(failed[window & (sent > 14.0)]))
        _, unbanned = self.write("M_limits", effects={"U": {"fail_p": 1.0}}, others=attack)
        self.assertTrue(np.all(unbanned[window]), "with no ban the run is harmed as U")
        _, named = self.write("M_xdp", effects={"U": {"fail_p": 1.0}, "M_xdp": {}}, others=attack)
        self.assertFalse(np.any(named), "an effect named for the run is taken as it is")

    def test_requests_to_a_banned_source_fill_the_engines_cap_and_it_drops_the_rest(self):
        workdir = os.path.join(self.tmp.name, "block", "M_xdp", "streams", "A-cheap_static_flood-perfect-0")
        os.makedirs(workdir)
        opts = {"--rate": "300", "--duration": "30", "--process": "constant", "--seed": "5", "--timeout": "10",
                "--summary": os.path.join(workdir, "loadgen.summary.json"), "--records": os.path.join(workdir, "loadgen.records.csv.gz")}
        zero = X.ENGINE_T0_OFFSET_S
        S.SyntheticServer(CAL, TIMELINE).write("A-cheap_static_flood-perfect-0", opts, 30.5, 1, (), 0.0,
                                               bans={"10.0.2.1": [zero + 5.0, None]}, local=("10.0.2.1",), max_inflight=500)
        with gzip.open(opts["--records"], "rt", newline="") as fh:
            rows = list(csv.DictReader(fh))
        with open(opts["--summary"], encoding="utf-8") as fh:
            summary = json.load(fh)
        dropped = [float(r["t_intended"]) for r in rows if r["err"] == "dropped"]
        self.assertEqual(len(rows), 9000, "with bans the attack stream's records are all written")
        self.assertAlmostEqual(min(dropped), 5.0 + 500 / 300, delta=0.05)
        self.assertTrue(all(r["t_sent"] == "nan" for r in rows if r["err"] == "dropped"))
        sent = [(float(r["t_sent"]), float(r["t_done"])) for r in rows if r["err"] != "dropped"]
        self.assertLessEqual(max(sum(1 for s, d in sent if s <= t < d) for t in np.arange(0.0, 30.0, 0.25)), 500)
        self.assertEqual((summary["intended"], summary["sent"], summary["dropped"]), (9000, 9000 - len(dropped), len(dropped)))
        self.assertTrue(summary["flags"]["dropped"] and summary["flags"]["sent_short"])

    def test_a_banned_attack_source_costs_the_server_nothing(self):
        server = S.SyntheticServer(CAL, TIMELINE, capacity_cpu=1.0)
        others = [{"kind": "legit", "begin": 0.0, "end": 30.0, "rate": 10.0, "route": "C1", "addresses": ("10.0.1.5",)},
                  {"kind": "attack", "begin": 10.0, "end": 20.0, "rate": 1000.0, "route": "C1", "addresses": ("10.0.2.1", "10.0.2.2")}]
        times = np.array([5.0, 11.0, 13.0, 16.0])
        u = server.utilisation(times, 0.0, others, {"10.0.2.1": [12.0, None], "10.0.2.2": [15.0, None]})
        cost = CAL["route_costs_ms"]["C1"] / 1000.0
        self.assertTrue(np.allclose(u, [10 * cost, 1010 * cost, 510 * cost, 10 * cost]))


class SimulatedRunTest(unittest.TestCase):
    """A run through the executor on the simulated host, read by the harm gate."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scn = SC.load(SPEC)

    def run_kind(self, kind, effects):
        host = S.SimHost(server=S.SyntheticServer(CAL, TIMELINE, effects))
        plan = X.plan_run(self.scn, CAL, kind, 1, os.path.join(self.tmp.name, "block", kind), C.PLACEHOLDER, "x",
                          settings={"readiness_timeout_s": 5.0}, rho=40.0, timeline=TIMELINE)
        result = X.execute(plan, host)
        self.assertTrue(result.ok, result.reasons)
        return H.run_metrics(H.read_run(plan.out), CAL, dict(zip(("baseline_s", "attack_s", "recovery_s"), TIMELINE, strict=True)))

    def test_the_control_is_healthy_and_the_attack_run_loses_about_the_effects_share(self):
        effects = {"U": {"fail_p": 0.3}}
        control, attack = self.run_kind("C", effects), self.run_kind("U", effects)
        self.assertGreaterEqual(control["Q"], CAL["gate"]["control_q_min"])
        self.assertAlmostEqual(control["Q"] - attack["Q"], 30.0, delta=7.0)

    def test_the_placebo_is_a_control(self):
        effects = {"U": {"fail_p": 0.3}}
        self.assertGreaterEqual(self.run_kind("Cp", effects)["Q"], CAL["gate"]["control_q_min"])


class FaultScheduleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scn = SC.load(SPEC)

    def plan(self, name):
        return X.plan_run(self.scn, CAL, "C", 1, os.path.join(self.tmp.name, name, "C"), C.PLACEHOLDER, "x",
                          settings={"readiness_timeout_s": 5.0}, rho=40.0, timeline=TIMELINE)

    def test_a_fault_is_armed_when_the_topology_of_its_run_is_built(self):
        host = S.SimHost(fault_schedule={2: {"stream_dies": 1}})
        self.assertTrue(X.execute(self.plan("first"), host).ok)
        self.assertEqual(host.topologies, 1)
        with self.assertRaises(X.RunFailed):
            X.execute(self.plan("second"), host)
        self.assertEqual(host.topologies, 2)
        self.assertTrue(X.execute(self.plan("third"), host).ok, "the fault fired once")
        self.assertEqual(host.testbed(), {"namespaces": [], "links": [], "processes": []})

    def test_a_retried_setup_builds_another_topology(self):
        host = S.SimHost(faults={"missing_address": 1})
        result = X.execute(self.plan("retry"), host)
        self.assertEqual((result.setup_retries, host.topologies), (1, 2))


class ClockTest(unittest.TestCase):
    def test_events_run_in_time_order_and_the_clock_stops_at_the_end_of_the_sleep(self):
        host = S.SimHost()
        seen = []
        host.schedule(3.0, lambda: seen.append(("b", host.t)))
        host.schedule(1.0, lambda: seen.append(("a", host.t)))
        host.schedule(9.0, lambda: seen.append(("late", host.t)))
        host.sleep(5.0)
        self.assertEqual(seen, [("a", 1.0), ("b", 3.0)])
        self.assertEqual((host.t, host.monotonic(), host.time()), (5.0, 5.0, S.BASE_EPOCH + 5.0))
        host.sleep(5.0)
        self.assertEqual(seen[-1], ("late", 9.0))

    def test_a_command_the_model_does_not_know_is_not_found(self):
        r = S.SimHost().run(["rm", "-rf", "/"])
        self.assertEqual(r.code, 127)

    def test_a_process_the_model_does_not_know_is_refused(self):
        with self.assertRaises(AssertionError):
            S.SimHost().popen(["sleep", "5"])

    def test_the_effect_presets_name_the_run_they_hit(self):
        self.assertEqual(sorted(S.EFFECT_PRESETS), ["fail", "latency", "pass", "small"])
        self.assertEqual(S.EFFECT_PRESETS["fail"], {})
        self.assertTrue(all(set(e) <= {"U"} for e in S.EFFECT_PRESETS.values()))


if __name__ == "__main__":
    unittest.main()
