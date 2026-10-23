"""Offline tests for bench/origin.py, the cost-calibrated origin of the harm benchmark
(docs/BENCHMARK_HARM_DESIGN.md 5, docs/HG1B_MINIMAL_DESIGN.md 5.1).

The origin is called as a WSGI app, in process: no socket is opened and nothing is timed against a real
clock (the clock is injected where cost is measured). The data sets are small, so that the module runs
in a couple of seconds.
"""
import contextlib
import dataclasses
import io
import json
import math
import os
import statistics
import sys
import tempfile
import threading
import unittest
from typing import ClassVar

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import origin as O

FAST = O.CostKnobs(rows_total=2000, page_rows=40, page_burn=50, api_burn=200, search_rows=1000,
                   export_rows=300, export_burn=100)
URLS = {"C0": "/static/3", "C1": "/page/9", "C2": "/api/item/21", "C3": "/search?q=alpha",
        "C5": "/export?r=4"}


def call(app, method, url):
    path, _, qs = url.partition("?")
    got = {}

    def start_response(status, headers):
        got["status"], got["headers"] = status, dict(headers)

    body = b"".join(app({"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs}, start_response))
    return got["status"], got["headers"], body


class StepClock:
    """A clock that moves by `step` seconds each time it is read: every timed call lasts exactly one step."""

    def __init__(self, step):
        self.step, self.t = step, 0.0

    def __call__(self):
        self.t += self.step
        return self.t


class RoutesTest(unittest.TestCase):
    def setUp(self):
        self.o = O.Origin(FAST, data_seed=1)
        self.addCleanup(self.o.close)

    def test_every_route_answers_and_names_its_class(self):
        self.assertEqual(set(URLS), set(O.CLASSES))
        for klass, url in URLS.items():
            with self.subTest(route=klass):
                status, headers, body = call(self.o, "GET", url)
                self.assertEqual(status, "200 OK")
                self.assertEqual(headers["X-Route-Class"], klass)
                self.assertGreater(len(body), 0)
                self.assertEqual(headers["Content-Length"], str(len(body)))

    def test_the_route_table_is_the_documented_one(self):
        self.assertEqual([k for k, _ in O.ROUTES], list(O.CLASSES))
        self.assertEqual(set(O.SAMPLE_URLS), set(O.CLASSES))

    def test_repeated_requests_are_byte_identical_across_instances(self):
        other = O.Origin(FAST, data_seed=1)
        self.addCleanup(other.close)
        for klass, url in URLS.items():
            with self.subTest(route=klass):
                first, again, elsewhere = call(self.o, "GET", url), call(self.o, "GET", url), call(other, "GET", url)
                self.assertEqual(first[2], again[2])
                self.assertEqual(first[2], elsewhere[2])
                self.assertEqual(first[1]["X-Work"], elsewhere[1]["X-Work"])

    def test_the_data_seed_changes_the_bytes(self):
        other = O.Origin(FAST, data_seed=2)
        self.addCleanup(other.close)
        for klass, url in URLS.items():
            with self.subTest(route=klass):
                self.assertNotEqual(call(self.o, "GET", url)[2], call(other, "GET", url)[2])

    def test_methods_paths_and_parameters(self):
        status, headers, _ = call(self.o, "POST", "/export")
        self.assertEqual((status, headers["Allow"]), ("405 Method Not Allowed", "GET, HEAD"))
        self.assertEqual(call(self.o, "PUT", "/page/1")[0], "405 Method Not Allowed")
        for url in ("/nope", "/api/item/abc", "/api/item/12345678901", "/static/x", "/page/", "/exports"):
            with self.subTest(url=url):
                self.assertEqual(call(self.o, "GET", url)[0], "404 Not Found")
        for url in ("/search", "/search?q=", "/search?q=" + "a" * 33, "/search?q=a;b", "/export?r=x",
                    "/export?other=1", "/export?r=1234567"):
            with self.subTest(url=url):
                self.assertEqual(call(self.o, "GET", url)[0], "400 Bad Request")

    def test_head_has_the_headers_and_no_body(self):
        for klass, url in URLS.items():
            with self.subTest(route=klass):
                get, head = call(self.o, "GET", url), call(self.o, "HEAD", url)
                self.assertEqual(head[0], "200 OK")
                self.assertEqual(head[2], b"")
                self.assertEqual(head[1]["Content-Length"], get[1]["Content-Length"])
                self.assertEqual(head[1]["X-Work"], get[1]["X-Work"])

    def test_headers_and_the_calibration_tag(self):
        _, headers, _ = call(self.o, "GET", URLS["C2"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Origin-Calibration"], "placeholder")
        frozen = O.Origin(FAST, tag="frozen:abcd1234")
        self.addCleanup(frozen.close)
        self.assertEqual(call(frozen, "GET", URLS["C2"])[1]["X-Origin-Calibration"], "frozen:abcd1234")

    def test_the_wsgi_contract(self):
        calls = []
        result = self.o({"REQUEST_METHOD": "GET", "PATH_INFO": "/static/1", "QUERY_STRING": ""},
                        lambda status, headers: calls.append((status, headers)))
        self.assertEqual(len(calls), 1)
        self.assertRegex(calls[0][0], r"^\d{3} ")
        self.assertTrue(all(isinstance(chunk, bytes) for chunk in result))


class WorkTest(unittest.TestCase):
    def work(self, knobs, klass, sigma=0.0):
        o = O.Origin(dataclasses.replace(knobs, spread_sigma=sigma), data_seed=1)
        self.addCleanup(o.close)
        return int(call(o, "GET", URLS[klass])[1]["X-Work"])

    def test_at_sigma_zero_the_work_is_what_the_knobs_say(self):
        k = FAST
        self.assertEqual(self.work(k, "C0"), k.static_bytes // 64)
        self.assertEqual(self.work(k, "C1"), k.page_rows + k.page_burn)
        self.assertEqual(self.work(k, "C2"), 1 + k.api_burn)
        self.assertEqual(self.work(k, "C3"), k.search_rows)
        self.assertEqual(self.work(k, "C5"), k.export_rows + k.export_burn)

    def test_work_grows_with_each_knob(self):
        for klass, knob in (("C0", "static_bytes"), ("C1", "page_rows"), ("C1", "page_burn"),
                            ("C2", "api_burn"), ("C3", "search_rows"), ("C5", "export_rows"),
                            ("C5", "export_burn")):
            with self.subTest(route=klass, knob=knob):
                base = getattr(FAST, knob)
                small = self.work(dataclasses.replace(FAST, **{knob: base}), klass)
                big = self.work(dataclasses.replace(FAST, **{knob: base * 2}), klass)
                self.assertGreater(big, small)

    def test_the_spread_is_deterministic_per_url_and_has_mean_one(self):
        self.assertEqual(O.spread_factor("/api/item/5", 1, 0.25), O.spread_factor("/api/item/5", 1, 0.25))
        self.assertNotEqual(O.spread_factor("/api/item/5", 1, 0.25), O.spread_factor("/api/item/6", 1, 0.25))
        self.assertNotEqual(O.spread_factor("/api/item/5", 1, 0.25), O.spread_factor("/api/item/5", 2, 0.25))
        factors = [O.spread_factor(f"/api/item/{i}", 1, 0.25) for i in range(4000)]
        self.assertAlmostEqual(statistics.fmean(factors), 1.0, delta=0.03)
        self.assertAlmostEqual(statistics.pstdev([math.log(f) for f in factors]), 0.25, delta=0.02)
        self.assertEqual(O.spread_factor("/x", 1, 0.0), 1.0)

    def test_the_spread_scales_the_work_of_a_url_the_same_way_every_time(self):
        o = O.Origin(FAST, data_seed=1)
        self.addCleanup(o.close)
        works = {call(o, "GET", f"/api/item/{i}")[1]["X-Work"] for i in (5, 5, 5)}
        self.assertEqual(len(works), 1)
        spread = {int(call(o, "GET", f"/api/item/{i}")[1]["X-Work"]) for i in range(40)}
        self.assertGreater(len(spread), 10)                      # different URLs, different work

    def test_the_export_takes_a_parameter_that_changes_only_its_work_factor(self):
        o = O.Origin(FAST, data_seed=1)
        self.addCleanup(o.close)
        a, b = call(o, "GET", "/export?r=1"), call(o, "GET", "/export?r=2")
        self.assertNotEqual(a[1]["X-Work"], b[1]["X-Work"])

    def test_no_sleep_unless_the_io_wait_is_on(self):
        def forbidden(_seconds):
            raise AssertionError("slept")

        o = O.Origin(FAST, data_seed=1, sleep=forbidden)
        self.addCleanup(o.close)
        for url in URLS.values():
            self.assertEqual(call(o, "GET", url)[0], "200 OK")
        slept = []
        waiting = O.Origin(dataclasses.replace(FAST, io_wait_ms=5.0), data_seed=1, sleep=slept.append)
        self.addCleanup(waiting.close)
        for url in URLS.values():
            call(waiting, "GET", url)
        self.assertEqual(slept, [0.005, 0.005])                  # C2 and C3 only


class DataTest(unittest.TestCase):
    def test_the_data_set_depends_on_the_seed_alone(self):
        a, b, c = O.Origin(FAST, 1), O.Origin(FAST, 1), O.Origin(FAST, 2)
        for o in (a, b, c):
            self.addCleanup(o.close)
        self.assertEqual(a.checksum(), b.checksum())
        self.assertNotEqual(a.checksum(), c.checksum())
        self.assertEqual(a._anchor.execute("SELECT count(*) FROM items").fetchone()[0], FAST.rows_total)

    def test_threads_get_the_bytes_a_single_thread_gets(self):
        o = O.Origin(FAST, data_seed=1)
        self.addCleanup(o.close)
        expected = {url: call(o, "GET", url)[2:] + (call(o, "GET", url)[1]["X-Work"],) for url in URLS.values()}
        failures = []

        def worker():
            try:
                for _ in range(3):
                    for url in URLS.values():
                        _, headers, body = call(o, "GET", url)
                        if (body, headers["X-Work"]) != (expected[url][0], expected[url][1]):
                            failures.append(url)
            except Exception as exc:                            # noqa: BLE001  any error is a failure here
                failures.append(repr(exc))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(failures, [])


class CalibrationTest(unittest.TestCase):
    FROZEN: ClassVar[dict] = {"C0": 2.0, "C1": 2.0, "C2": 2.0, "C3": 2.0, "C5": 2.0}

    def test_the_cost_of_a_route_is_what_the_clock_says_at_nominal_work(self):
        o = O.Origin(FAST, 1)
        self.addCleanup(o.close)
        measured = O.measure_unloaded(o, repeats=3, clock=StepClock(0.002))
        self.assertEqual(set(measured), set(O.CLASSES))
        for value in measured.values():
            self.assertAlmostEqual(value, 2.0, places=6)

    def test_the_self_check_tolerates_25_percent_and_names_the_routes_beyond(self):
        self.assertEqual(O.self_check({k: 2.4 for k in self.FROZEN}, self.FROZEN), [])
        self.assertEqual(O.self_check({k: 1.6 for k in self.FROZEN}, self.FROZEN), [])
        bad = O.self_check({**{k: 2.0 for k in self.FROZEN}, "C3": 2.6, "C5": None}, self.FROZEN)
        self.assertEqual([b["class"] for b in bad], ["C3", "C5"])
        self.assertAlmostEqual(bad[0]["off"], 0.3)

    def test_a_host_10_percent_off_starts_and_one_30_percent_off_refuses(self):
        app = O.make_app(FAST, frozen_costs_ms=self.FROZEN, clock=StepClock(0.0022), tag="frozen:12345678")
        self.addCleanup(app.close)
        self.assertEqual(call(app, "GET", URLS["C2"])[1]["X-Origin-Calibration"], "frozen:12345678")
        with self.assertRaisesRegex(O.CalibrationError, "C0: 2.6 ms against 2 ms frozen"):
            O.make_app(FAST, frozen_costs_ms=self.FROZEN, clock=StepClock(0.0026))

    def test_without_frozen_costs_there_is_no_check(self):
        app = O.make_app(FAST, clock=StepClock(99.0))            # absurd clock: nothing is compared
        self.addCleanup(app.close)
        self.assertEqual(call(app, "GET", URLS["C0"])[1]["X-Origin-Calibration"], "placeholder")

    def test_the_app_is_built_from_the_environment(self):
        knobs = json.dumps(dataclasses.asdict(FAST))
        app = O.app_from_env({"ORIGIN_KNOBS": knobs, "ORIGIN_SEED": "5"})
        self.addCleanup(app.close)
        self.assertEqual((app.data_seed, app.knobs.rows_total, app.tag), (5, FAST.rows_total, "placeholder"))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cal.json")
            cal = {"status": "frozen", "sha256": "ab" * 32, "route_costs_ms": self.FROZEN,
                   "knobs": dataclasses.asdict(FAST), "unknown_field": 1}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cal, fh)
            frozen = O.app_from_env({"ORIGIN_CALIBRATION": path}, clock=StepClock(0.002))
            self.addCleanup(frozen.close)
            self.assertEqual((frozen.tag, frozen.knobs.rows_total), ("frozen:abababab", FAST.rows_total))
            cal["status"] = "placeholder"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(cal, fh)
            placeholder = O.app_from_env({"ORIGIN_CALIBRATION": path, "ORIGIN_KNOBS": '{"rows_total": 500}'})
            self.addCleanup(placeholder.close)
            self.assertEqual((placeholder.tag, placeholder.knobs.rows_total), ("placeholder", 500))

    def test_importing_the_module_builds_nothing(self):
        self.assertNotIn("app", vars(O))
        self.assertFalse(hasattr(O, "nothing_of_the_kind"))       # the lazy __getattr__ knows only `app`

    def test_the_command_line(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(O.main(["--routes"]), 0)
        self.assertIn("C3  /search", out.getvalue())
        knobs = json.dumps(dataclasses.asdict(FAST))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(O.main(["--calibrate", "--knobs", knobs, "--repeats", "3"], clock=StepClock(0.002)), 0)
        self.assertAlmostEqual(json.loads(out.getvalue())["measured_ms"]["C3"], 2.0, places=6)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cal.json")
            for step, expected in ((0.0022, 0), (0.0030, 1)):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"route_costs_ms": self.FROZEN}, fh)
                out = io.StringIO()
                with self.subTest(step=step), contextlib.redirect_stdout(out):
                    self.assertEqual(O.main(["--check", path, "--knobs", knobs], clock=StepClock(step)), expected)


if __name__ == "__main__":
    unittest.main()
