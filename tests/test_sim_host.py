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
import executor as X
import harm_gate as H
import origin as O
import scenario as SC
import sim_host as S

SPEC = os.path.join(REPO, "bench", "scenarios", "costly_search_sub_threshold.json")
TIMELINE = (10.0, 10.0, 10.0)
CAL = C.load(C.PLACEHOLDER)


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

    def write(self, run="C", sid="L-constant-C1-perfect-0", rate=20.0, duration=30.0, effects=None, seed=5, identities=3):
        workdir = os.path.join(self.tmp.name, run, "streams", sid)
        os.makedirs(workdir, exist_ok=True)
        opts = {"--rate": str(rate), "--duration": str(duration), "--process": "constant", "--seed": str(seed),
                "--summary": os.path.join(workdir, "loadgen.summary.json"),
                "--records": os.path.join(workdir, "loadgen.records.csv.gz")}
        n = S.SyntheticServer(CAL, TIMELINE, effects).write(sid, opts, 30.5, identities)
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
        workdir = os.path.join(self.tmp.name, "C", "streams", "L-poisson-C1-perfect-0")
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


class SimulatedRunTest(unittest.TestCase):
    """A run through the executor on the simulated host, read by the harm gate."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scn = SC.load(SPEC)

    def run_kind(self, kind, effects):
        host = S.SimHost(server=S.SyntheticServer(CAL, TIMELINE, effects))
        plan = X.plan_run(self.scn, CAL, kind, 1, os.path.join(self.tmp.name, kind), C.PLACEHOLDER, "x",
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
