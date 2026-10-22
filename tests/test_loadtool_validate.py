"""Offline tests for bench/loadtool_validate.py, the verification of the HTTP load generators.

* the test matrix and the analytic p99 of the stall test;
* every evaluator at and beyond the edge of its pass criterion, on synthetic results;
* the per-tool summary: verdicts, the V7 ceiling, the status the results suggest;
* the scripted origin S2 over loopback sockets (a handful of requests, well under a second each),
  its process lifecycle (SIGTERM writes the log) and, when nginx is installed, S1 as a real
  user-level Nginx on a free loopback port;
* the run and re-analysis flow with a fake environment: files, SHA256SUMS, README, errors.

No load tool is started and nothing leaves the machine; the only traffic is the few requests above
on 127.0.0.1.
"""
import asyncio
import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import loadtool_validate as V
import loadtools as LT


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def res(requests=1000, errors=0, non2xx=0, dropped=0, p50=None, p99=None, quantiles="exact",
        cpu=None):
    return {"tool": "t", "requests": requests, "responses": requests - errors,
            "ok2xx": requests - errors - non2xx, "non2xx": non2xx, "errors": errors,
            "status": {}, "latency": {"p50": p50, "p99": p99}, "quantiles": quantiles,
            "duration": 10.0, "dropped": dropped,
            "extra": {"children_cpu_s": cpu} if cpu else {}}


def job(test, tool="vegeta", rate=None, repeat=0, role="subject"):
    spec = V.TESTS[test]
    j = V.Job(test, tool, rate or spec["rates"][0], spec["duration"], repeat, spec["origin"],
              tuple(sorted(spec.get("s2", {}).items())), role=role)
    return j.as_dict()


class MatrixTest(unittest.TestCase):
    def test_the_matrix_has_the_jobs_the_design_lists(self):
        jobs = V.expand()
        per_test = {}
        for j in jobs:
            per_test[j.test] = per_test.get(j.test, 0) + 1
        self.assertEqual(per_test, {"V1": 3, "V2": 27, "V3": 3, "V4": 4, "V5": 3, "V6": 3, "V7": 15})
        self.assertEqual(len({j.key for j in jobs}), len(jobs))
        self.assertAlmostEqual(sum(j.duration for j in jobs) / 60, 18.2, places=1)

    def test_wrk_is_only_the_control_of_the_stall_test(self):
        wrk = [j for j in V.expand() if j.tool == "wrk"]
        self.assertEqual([(j.test, j.role) for j in wrk], [("V4", "control")])
        self.assertTrue(all(j.role == "subject" for j in V.expand() if j.tool != "wrk"))

    def test_filters_and_origins(self):
        jobs = V.expand(tools=["k6"], tests=["V4", "V7"])
        self.assertEqual({j.tool for j in jobs}, {"k6"})
        self.assertEqual({j.test for j in jobs}, {"V4", "V7"})
        v7 = [j for j in jobs if j.test == "V7"]
        self.assertEqual([j.rate for j in v7], [1000, 2000, 5000, 10000, 20000])
        self.assertEqual({j.cpus for j in v7}, {"4"})
        self.assertEqual({j.origin for j in v7}, {"s1"})
        v4 = next(j for j in jobs if j.test == "V4")
        self.assertEqual(dict(v4.s2), {"service_ms": 5.0, "jitter_ms": 5.0,
                                       "stall_after": 15.0, "stall_for": 3.0})

    def test_the_analytic_stall_quantile(self):
        self.assertAlmostEqual(V.analytic_stall_p99(500, 40, 3), 2.6)
        self.assertAlmostEqual(V.analytic_stall_p99(500, 40, 3, service=0.0075), 2.6075)
        self.assertAlmostEqual(V.analytic_stall_p99(500, 40, 3, q=0.95), 1.0)
        # too few requests in the stall to reach the quantile: the service time remains
        self.assertEqual(V.analytic_stall_p99(500, 400, 3, service=0.01), 0.01)


class EvaluatorTest(unittest.TestCase):
    def passes(self, j, r, o):
        return V.evaluate(j, r, o)["pass"]

    def test_v1_smoke(self):
        j, o = job("V1"), {"requests": 1000}
        self.assertTrue(self.passes(j, res(1000), o))
        self.assertTrue(self.passes(j, res(980), {"requests": 1020}))
        self.assertFalse(self.passes(j, res(979), o))                   # 2.1 % short
        self.assertFalse(self.passes(j, res(1000), {"requests": 1021}))
        self.assertFalse(self.passes(j, res(1000, errors=1), o))

    def test_v2_rate_accuracy_is_judged_at_the_origin(self):
        j = job("V2", rate=1000)                                        # 20 s: 20000 expected
        self.assertTrue(self.passes(j, res(20000), {"requests": 20200}))
        self.assertFalse(self.passes(j, res(20000), {"requests": 20201}))
        self.assertTrue(self.passes(j, res(19000), {"requests": 19800}))   # the tool's count is a note

    def test_v3_latency_tolerance_is_the_larger_of_1_ms_and_10_percent(self):
        j = job("V3")
        o = {"service_s": {"p50": 0.0075, "p99": 0.0200}}
        self.assertTrue(self.passes(j, res(p50=0.0084, p99=0.0219), o))   # 0.9 ms; 1.9 ms < 2 ms
        self.assertFalse(self.passes(j, res(p50=0.0086, p99=0.0200), o))  # 1.1 ms > 1 ms
        self.assertFalse(self.passes(j, res(p50=0.0075, p99=0.0225), o))   # 2.5 ms > 2 ms
        self.assertFalse(self.passes(j, res(p50=None, p99=0.02), o))

    def test_v4_subject_must_report_the_analytic_p99_and_keep_sending(self):
        j = job("V4")
        want = V.analytic_stall_p99(500, 40, 3, service=0.0075)
        o = {"arrivals_in_stall": 1500}
        self.assertTrue(self.passes(j, res(p99=want), o))
        self.assertTrue(self.passes(j, res(p99=want * 1.14), o))
        self.assertFalse(self.passes(j, res(p99=want * 1.16), o))
        self.assertFalse(self.passes(j, res(p99=0.012), o))               # CO: stall not reported
        self.assertFalse(self.passes(j, res(p99=want), {"arrivals_in_stall": 1000}))
        self.assertFalse(self.passes(j, res(p99=None), o))

    def test_v4_control_passes_by_failing_to_see_the_stall(self):
        j = job("V4", tool="wrk", role="control")
        o = {"arrivals_in_stall": None}
        self.assertTrue(self.passes(j, res(p99=0.012), o))
        self.assertTrue(self.passes(j, res(p99=0.26), o))
        self.assertFalse(self.passes(j, res(p99=0.27), o))                # saw too much of it
        e = V.evaluate(j, res(p99=0.012), o)
        self.assertEqual(e["role"], "control")

    def test_v5_arrivals_follow_the_rate_or_the_tool_reports_the_difference(self):
        j = job("V5")                                                     # 2000/s for 20 s
        self.assertTrue(self.passes(j, res(40000), {"arrivals": 40000}))
        self.assertTrue(self.passes(j, res(40000), {"arrivals": 39300}))
        self.assertFalse(self.passes(j, res(40000), {"arrivals": 39100}))
        self.assertTrue(self.passes(j, res(20000, dropped=19000), {"arrivals": 21000}))
        e = V.evaluate(j, res(20000, dropped=100), {"arrivals": 20000})
        self.assertFalse(e["pass"])
        self.assertIn("silent shortfall: 19900", e["notes"])

    def test_v6_status_accounting(self):
        j = job("V6")                                                     # 500/s, 20 s
        o = {"arrivals": 10000, "status": {"200": 9000, "503": 1000}}
        self.assertTrue(self.passes(j, res(10000, non2xx=1000), o))
        self.assertTrue(self.passes(j, res(10000, non2xx=1010), o))
        self.assertFalse(self.passes(j, res(10000, non2xx=1011), o))
        self.assertFalse(self.passes(j, res(10000, non2xx=0), o))         # 503s not counted
        self.assertFalse(self.passes(j, res(9890, non2xx=1000), o))       # requests off by 1.1 %

    def test_v7_step_and_cost(self):
        j = job("V7", rate=5000)                                          # 10 s: 50000
        cpu = {"user": 2.0, "system": 1.0}
        e = V.evaluate(j, res(50000, cpu=cpu), {"requests": 50000})
        self.assertTrue(e["pass"])
        self.assertAlmostEqual(e["metrics"]["cpu_per_1000"], 0.06)
        self.assertFalse(self.passes(j, res(50000, errors=3), {"requests": 50000}))
        self.assertFalse(self.passes(j, res(50000), {"requests": 49400}))

    def test_a_tool_that_raised_its_own_validity_flags_says_so(self):
        r = res(1000)
        r["extra"] = {"flags": {"slip": True, "cpu": False, "dropped": True}}
        e = V.evaluate(job("V1"), r, {"requests": 1000})
        self.assertIn("the tool's own validity flags: slip, dropped", e["notes"])
        self.assertTrue(e["pass"])                                        # a note, not a criterion
        self.assertEqual(V.evaluate(job("V1"), res(1000), {"requests": 1000})["notes"], [])

    def test_every_check_carries_what_it_compared(self):
        e = V.evaluate(job("V1"), res(1000), {"requests": 1000})
        for c in e["checks"]:
            self.assertEqual(set(c), {"name", "observed", "expected", "tolerance", "pass"})


def ev(test, tool, ok=True, rate=1000, role="subject", cpu=0.05, error=None):
    e = {"key": f"{test}/{tool}/r{rate}", "test": test, "tool": tool, "role": role,
         "rate": rate, "repeat": 0, "pass": ok, "checks": [], "notes": [],
         "metrics": {"cpu_per_1000": cpu}}
    if error:
        e["error"] = error
    return e


class SummaryTest(unittest.TestCase):
    def full(self, tool, fail=()):
        return [ev(t, tool, ok=t not in fail) for t in ("V1", "V2", "V3", "V4", "V5", "V6")]

    def test_a_tool_that_passes_everything_is_verified(self):
        s = V.summarise(self.full("vegeta"), {"vegeta": {"v0_ok": True}})["vegeta"]
        self.assertEqual(s["suggested_status"], "verified")
        self.assertEqual(s["restrictions"], [])
        self.assertEqual({v["verdict"] for v in s["tests"].values()}, {"pass"})

    def test_failing_v1_or_v2_makes_a_tool_unfit(self):
        for t in ("V1", "V2"):
            s = V.summarise(self.full("k6", fail=(t,)), {"k6": {"v0_ok": True}})["k6"]
            self.assertEqual(s["suggested_status"], "unfit", t)

    def test_failing_later_tests_restricts_what_the_tool_may_be_used_for(self):
        s = V.summarise(self.full("k6", fail=("V4", "V5")), {"k6": {"v0_ok": True}})["k6"]
        self.assertEqual(s["suggested_status"], "verified")
        self.assertEqual(s["restrictions"], ["no latency claims under stalls", "no overload claims"])

    def test_incomplete_and_error_cases(self):
        part = [ev("V1", "k6"), ev("V4", "k6")]
        self.assertEqual(V.summarise(part, {"k6": {"v0_ok": True}})["k6"]["suggested_status"],
                         "incomplete")
        self.assertEqual(V.summarise(self.full("k6"), {"k6": {"v0_ok": False}})["k6"]
                         ["suggested_status"], "error")
        bad = self.full("k6") + [ev("V7", "k6", error="boom")]
        self.assertEqual(V.summarise(bad, {"k6": {"v0_ok": True}})["k6"]["tests"]["V7"]["verdict"],
                         "error")

    def test_the_closed_loop_control_is_reported_as_one(self):
        s = V.summarise([ev("V4", "wrk", role="control")], {"wrk": {"v0_ok": True}})["wrk"]
        self.assertEqual(s["tests"]["V4"]["verdict"], "control ok")
        self.assertEqual(s["suggested_status"], "control")
        s = V.summarise([ev("V4", "wrk", ok=False, role="control")], {"wrk": {"v0_ok": True}})
        self.assertEqual(s["wrk"]["tests"]["V4"]["verdict"], "control NOT as expected")

    def test_v7_ceiling_is_the_highest_rate_with_no_failure_below_it(self):
        es = [ev("V7", "k6", ok=ok, rate=r, cpu=r / 1e5)
              for r, ok in ((1000, True), (2000, True), (5000, False), (10000, True))]
        t = V.summarise(es, {"k6": {"v0_ok": True}})["k6"]["tests"]["V7"]
        self.assertEqual(t["ceiling"], 2000)
        self.assertEqual(t["cpu_per_1000"]["10000"], 0.1)
        none = V.summarise([ev("V7", "k6", ok=False, rate=1000)], {})["k6"]["tests"]["V7"]
        self.assertIsNone(none["ceiling"])

    def test_the_summary_of_an_s2_log(self):
        log = {"params": {"stall_after": 1.0, "stall_for": 0.5},
               "arrivals": [[0, 0.0], [1, 0.4], [2, 1.2], [3, 1.4], [4, 1.6], [5, 2.5]],
               "responses": [[0, 0.01, 200], [1, 0.42, 503], [2, 1.5, 200], [3, 1.5, 200]]}
        s = V.summarise_s2(log)
        self.assertEqual((s["arrivals"], s["responses"]), (6, 4))
        self.assertEqual(s["status"], {"200": 3, "503": 1})
        self.assertEqual(s["arrivals_in_stall"], 2)                       # 1.2 and 1.4
        self.assertEqual(s["arrivals_per_s"], [2, 3, 1])
        self.assertAlmostEqual(s["service_s"]["max"], 0.3)                # request 2: 1.5 - 1.2
        self.assertEqual((s["first_arrival_s"], s["last_arrival_s"]), (0.0, 2.5))
        none = V.summarise_s2({"params": {"stall_after": None, "stall_for": 0}, "arrivals": [],
                               "responses": []})
        self.assertEqual((none["arrivals"], none["arrivals_per_s"], none["arrivals_in_stall"]),
                         (0, [], None))


def get(sock, method="GET", close=False):
    extra = "Connection: close\r\n" if close else ""
    sock.sendall(f"{method} / HTTP/1.1\r\nHost: x\r\n{extra}\r\n".encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    length = int(re.search(rb"Content-Length: (\d+)", head).group(1))
    while method != "HEAD" and len(rest) < length:
        rest += sock.recv(4096)
    return int(head.split()[1]), head, rest


class RunningOrigin:
    """A ScriptedOrigin on an ephemeral loopback port, in a thread of its own."""

    def __init__(self, **kw):
        self.origin = V.ScriptedOrigin(**kw)

    def __enter__(self):
        self.loop = asyncio.new_event_loop()
        started = threading.Event()

        def target():
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(self.origin.start("127.0.0.1", 0))
            started.set()
            self.loop.run_forever()
            self.server.close()
            tasks = asyncio.all_tasks(self.loop)
            for t in tasks:
                t.cancel()
            self.loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        started.wait(5)
        self.port = self.origin.port
        return self

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)

    def __exit__(self, *exc):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


class ScriptedOriginTest(unittest.TestCase):
    def test_every_nth_request_gets_a_503_and_connections_are_kept_alive(self):
        with RunningOrigin(service_ms=1, jitter_ms=0, error_every=3) as o, o.connect() as s:
            codes = [get(s)[0] for _ in range(7)]
        self.assertEqual(codes, [200, 200, 503, 200, 200, 503, 200])
        log = o.origin
        self.assertEqual([r[2] for r in log.responses], codes)
        self.assertEqual([a[0] for a in log.arrivals], list(range(7)))

    def test_head_gets_no_body_and_close_is_honoured(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o:
            with o.connect() as s:
                code, head, body = get(s, "HEAD")
                self.assertEqual((code, body), (200, b""))
                self.assertIn(b"Content-Length: 3", head)
            with o.connect() as s:
                code, head, body = get(s, close=True)
                self.assertEqual((code, body), (200, b"ok\n"))
                self.assertIn(b"Connection: close", head)
                self.assertEqual(s.recv(10), b"")                         # the origin closed

    def test_service_time_is_what_was_asked_for(self):
        with RunningOrigin(service_ms=40, jitter_ms=0) as o, o.connect() as s:
            t0 = time.monotonic()
            get(s)
            took = time.monotonic() - t0
        self.assertGreaterEqual(took, 0.04)
        self.assertLess(took, 2.0)                  # this VM wakes sleepers late: no tight bound
        a, r = o.origin.arrivals[0], o.origin.responses[0]
        self.assertGreaterEqual(r[1] - a[1], 0.04)

    def test_the_stall_holds_exactly_the_responses_that_would_fall_inside_it(self):
        o = V.ScriptedOrigin(stall_after=1.0, stall_for=2.0)
        self.assertIsNone(o._stall_end(0.0))
        self.assertIsNone(o._stall_end(0.999))
        self.assertEqual(o._stall_end(1.0), 3.0)
        self.assertEqual(o._stall_end(2.5), 3.0)
        self.assertIsNone(o._stall_end(3.0))
        self.assertIsNone(V.ScriptedOrigin()._stall_end(1.0))

    def test_a_response_that_falls_inside_the_stall_is_held_to_its_end(self):
        # the window is wide and the second request is sent by the origin's own clock, so
        # that a late wake-up of this thread cannot move it out of the window
        with (RunningOrigin(service_ms=1, jitter_ms=0, stall_after=0.1, stall_for=1.4) as o,
              o.connect() as s):
            get(s)                                                        # t0; before the stall
            while o.origin.clock() - o.origin.t0 < 0.15:
                time.sleep(0.005)
            self.assertLess(o.origin.clock() - o.origin.t0, 1.0)          # still inside the window
            get(s)
        first, second = o.origin.responses
        self.assertLess(first[1], 0.1)
        self.assertGreaterEqual(second[1], 1.499)                         # held to 0.1 + 1.4

    def test_capacity_queues_requests_but_arrivals_are_logged_at_once(self):
        with RunningOrigin(service_ms=150, jitter_ms=0, capacity=1) as o:
            socks = [o.connect() for _ in range(3)]
            done = []
            threads = [threading.Thread(target=lambda s=s: done.append(get(s)[0])) for s in socks]
            for t in threads:
                t.start()
            time.sleep(0.1)
            seen = len(o.origin.arrivals)                                 # all three, before any reply
            for t in threads:
                t.join(5)
            for s in socks:
                s.close()
        self.assertEqual(seen, 3)
        self.assertEqual(done, [200, 200, 200])
        times = sorted(r[1] for r in o.origin.responses)
        self.assertGreaterEqual(times[2] - times[0], 0.28)                # served one at a time

    def test_jitter_is_a_function_of_the_seed_and_the_request_number(self):
        a, b = V.ScriptedOrigin(seed=3), V.ScriptedOrigin(seed=3)
        self.assertEqual(a._u[:50], b._u[:50])
        self.assertNotEqual(a._u[:50], V.ScriptedOrigin(seed=4)._u[:50])

    def test_dump_round_trips_through_gzip(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o, o.connect() as s:
            get(s)
            get(s)
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("log.json", "log.json.gz"):
                path = os.path.join(tmp, name)
                o.origin.dump(path)
                opener = gzip.open if name.endswith("gz") else open
                with opener(path, "rt") as f:
                    log = json.load(f)
                self.assertEqual(V.summarise_s2(log)["arrivals"], 2)
                self.assertEqual(log["params"]["service_ms"], 1)


class ProcessTest(unittest.TestCase):
    def test_s2_as_a_process_writes_its_log_at_sigterm(self):
        port = free_port()
        with tempfile.TemporaryDirectory() as tmp:
            s2 = V.S2Process(tmp, {"service_ms": 1.0, "jitter_ms": 0.0, "error_every": 2},
                             port=port, cpus="0")
            with s2:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                    codes = [get(s)[0] for _ in range(4)]
                summary = s2.finish()
            self.assertEqual(codes, [200, 503, 200, 503])
            self.assertEqual((summary["arrivals"], summary["status"]),
                             (4, {"200": 2, "503": 2}))
            self.assertTrue(os.path.exists(os.path.join(tmp, "s2.log.json.gz")))
            self.assertFalse(V.port_in_use(port))

    def test_a_port_that_is_taken_is_an_infrastructure_error(self):
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", 0))
            busy.listen()
            port = busy.getsockname()[1]
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(V.InfraError):
                V.S2Process(tmp, {}, port=port, cpus="0").__enter__()
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(V.InfraError):
                V.Nginx(tmp, port=port, cpus="0").__enter__()

    def test_the_nginx_config_and_command(self):
        n = V.Nginx("/w", port=18081)
        conf = n.config()
        for text in ("daemon off;", "listen 127.0.0.1:18081 backlog=4096;", "stub_status;",
                     'return 200 "ok\\n";', "access_log off;", "pid /w/s1/nginx.pid;"):
            self.assertIn(text, conf)
        self.assertEqual(n.command()[:5], ["taskset", "-c", "0-1", "nginx", "-p"])
        s2 = V.S2Process("/w", {"b": 1, "a": 2}).command()
        self.assertEqual(s2[:3], ["taskset", "-c", "2-3"])
        self.assertIn("serve-s2", s2)
        self.assertEqual(s2[-1], '{"a": 2, "b": 1}')

    @unittest.skipUnless(shutil.which("nginx") and shutil.which("taskset"),
                         "needs nginx and taskset")
    def test_s1_as_a_real_nginx_counts_the_requests_that_arrived(self):
        port = free_port()
        with tempfile.TemporaryDirectory() as tmp:
            with V.Nginx(tmp, port=port, cpus="0") as n:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                    for _ in range(5):
                        code, _, body = get(s)
                        self.assertEqual((code, body), (200, b"ok\n"))
                summary = n.finish()
            self.assertEqual(summary["requests"], 5)
            self.assertFalse(V.port_in_use(port))


def fake_summary(j):
    """What a well-behaved origin would have seen for job j (a dict)."""
    n = j["rate"] * j["duration"]
    if j["origin"] == "s1":
        return {"kind": "s1", "requests": n}
    s2 = j["s2"]
    out = {"kind": "s2", "arrivals": n, "responses": n, "status": {"200": n},
           "service_s": {"p50": 0.0075, "p99": 0.0099}, "arrivals_in_stall": None}
    if "stall_for" in s2:
        out["arrivals_in_stall"] = j["rate"] * s2["stall_for"]
    if "error_every" in s2:
        out["status"] = {"200": n * 0.9, "503": n * 0.1}
    return out


def fake_result(j):
    n = j["rate"] * j["duration"]
    r = res(n, p50=0.0078, p99=0.0102, quantiles="exact", cpu={"user": 0.4, "system": 0.1})
    r["tool"] = j["tool"]
    if j["test"] == "V4":
        r["latency"]["p99"] = 0.012 if j["role"] == "control" else 2.6
    if j["test"] == "V6":
        r["non2xx"] = n * 0.1
    return r


class FakeOrigin:
    def __init__(self, j):
        self.summary = fake_summary(j)
        self.url = "http://127.0.0.1:1/"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def finish(self):
        return self.summary


class FakeEnv:
    def __init__(self, fail_tools=(), infra_on=None):
        self.fail_tools, self.infra_on, self.launched = fail_tools, infra_on, []

    def origin(self, j, workdir):
        if j.key == self.infra_on:
            raise V.InfraError("port taken")
        return FakeOrigin(j.as_dict())

    def launch(self, j, url, workdir):
        self.launched.append(j.key)
        if j.tool in self.fail_tools:
            raise LT.ToolError("boom")
        r = fake_result(j.as_dict())
        cpu = r["extra"].pop("children_cpu_s")
        os.makedirs(workdir, exist_ok=True)
        with open(os.path.join(workdir, "vegeta.bin"), "wb") as f:                # raw output
            f.write(b"raw")
        return LT.ToolResult(j.tool, r["requests"], r["responses"], r["ok2xx"], r["non2xx"],
                             r["errors"], {}, r["latency"], r["quantiles"], 10.0, 0, {}), \
            {"ok": True, "children_cpu_s": cpu}


TOOLS_INFO = {t: {"v0_ok": True, "status": "smoke-tested", "sha256": "0" * 64,
                  "pinned_version": "v1", "version_output": "v1"}
              for t in ("vegeta", "k6", "loadgen", "wrk")}


class FlowTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self._tmp.name, "results")
        os.makedirs(self.out)
        self.addCleanup(self._tmp.cleanup)

    def run_all(self, env=None, **kw):
        env = env or FakeEnv()
        evals = V.run_all(env, V.expand(), self.out, TOOLS_INFO, **kw)
        V.finalize(self.out, evals, TOOLS_INFO, {"git_commit": "abc", "uname": "u"})
        return env, evals

    def silently(self, fn, *a, **kw):
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(*a, **kw)

    def test_a_perfect_environment_verifies_every_tool(self):
        _, evals = self.silently(self.run_all)
        self.assertEqual(len(evals), 58)
        self.assertTrue(all(e["pass"] for e in evals), [e["key"] for e in evals if not e["pass"]])
        s = read(self.out, "results.json")["summary"]
        self.assertEqual(s["vegeta"]["suggested_status"], "verified")
        self.assertEqual(s["k6"]["suggested_status"], "verified")
        self.assertEqual(s["loadgen"]["suggested_status"], "verified")
        self.assertEqual(s["wrk"]["suggested_status"], "control")
        self.assertEqual(s["k6"]["tests"]["V7"]["ceiling"], 20000)

    def test_the_results_directory_is_laid_out_like_a_campaign(self):
        self.silently(self.run_all)
        for name in ("README.md", "results.json", "SHA256SUMS"):
            self.assertTrue(os.path.isfile(os.path.join(self.out, name)), name)
        d = os.path.join(self.out, "V4", "vegeta", "r500_0")
        self.assertEqual(sorted(os.listdir(d)), ["job.json", "origin.json", "tool_result.json"])
        self.assertEqual(read(d, "job.json")["s2"]["stall_for"], 3.0)
        self.assertEqual(read(d, "tool_result.json")["extra"]["children_cpu_s"]["user"], 0.4)
        listed = {}
        with open(os.path.join(self.out, "SHA256SUMS")) as f:
            for line in f:
                digest, _, rel = line.rstrip("\n").partition("  ")
                listed[rel] = digest
        found = {os.path.relpath(os.path.join(d, f), self.out)
                 for d, _, files in os.walk(self.out) for f in files} - {"SHA256SUMS"}
        self.assertEqual(set(listed), found)
        for rel, digest in listed.items():
            with open(os.path.join(self.out, rel), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, rel)

    def test_raw_tool_output_is_dropped_unless_asked_for(self):
        self.silently(self.run_all, keep_raw=False)
        self.assertFalse(os.path.exists(os.path.join(self.out, "V1", "vegeta", "r100_0",
                                                     "vegeta.bin")))

    def test_raw_tool_output_is_kept_on_request(self):
        self.silently(self.run_all, keep_raw=True)
        self.assertTrue(os.path.exists(os.path.join(self.out, "V1", "vegeta", "r100_0",
                                                    "vegeta.bin")))

    def test_the_timer_probe_is_in_the_results_and_warns_when_it_should(self):
        t = V.timer_lateness(samples=20, interval=0.002)
        self.assertEqual((t["samples"], t["interval_s"]), (20, 0.002))
        self.assertTrue(0 <= t["p50_ms"] <= t["p99_ms"] <= t["max_ms"])
        evals = []
        slow = {"interval_s": 0.01, "samples": 200, "p50_ms": 12.0, "p99_ms": 300.0, "max_ms": 389.0}
        fine = {**slow, "p50_ms": 0.1, "p99_ms": 0.5, "max_ms": 1.0}
        V.finalize(self.out, evals, {}, {"timer": slow, "timer_after": fine})
        with open(os.path.join(self.out, "README.md")) as f:
            text = f.read()
        self.assertIn("lateness before the run (sleep 10 ms, 200 samples): p50 12.0 ms, "
                      "p99 300.0 ms, max 389.0 ms. **above the limit: schedules will slip**", text)
        self.assertIn("lateness after the run (sleep 10 ms, 200 samples): p50 0.1 ms, "
                      "p99 0.5 ms, max 1.0 ms.\n", text)

    def test_the_evaluations_are_listed_in_a_fixed_order(self):
        self.silently(self.run_all)
        jobs = read(self.out, "results.json")["jobs"]
        order = [(e["test"], e["tool"], e["rate"], e["repeat"]) for e in jobs]
        self.assertEqual(order, sorted(order))
        self.assertEqual([e["key"] for e in jobs[:3]],
                         ["V1/k6/r100_0", "V1/loadgen/r100_0", "V1/vegeta/r100_0"])

    def test_the_readme_has_the_verdicts_and_the_checks(self):
        self.silently(self.run_all)
        with open(os.path.join(self.out, "README.md")) as f:
            text = f.read()
        self.assertIn("| vegeta | yes |", text)
        self.assertIn("verified", text)
        self.assertIn("control ok", text)
        self.assertIn("reported p99 against the analytic value", text)
        self.assertIn("## V7: ceiling and cost", text)
        self.assertIn("`abc`", text)

    def test_a_tool_that_fails_is_a_result_and_the_others_still_run(self):
        _env, evals = self.silently(self.run_all, FakeEnv(fail_tools=("k6",)))
        errors = [e for e in evals if "error" in e]
        self.assertEqual({e["tool"] for e in errors}, {"k6"})
        self.assertEqual(len(errors), len([j for j in V.expand() if j.tool == "k6"]))
        s = read(self.out, "results.json")["summary"]
        self.assertEqual(s["k6"]["suggested_status"], "error")
        self.assertEqual(s["vegeta"]["suggested_status"], "verified")
        self.assertTrue(os.path.exists(os.path.join(self.out, "V1", "k6", "r100_0", "error.json")))

    def test_stop_on_error_stops_at_the_first_one(self):
        _env, evals = self.silently(self.run_all, FakeEnv(fail_tools=("k6",)), stop_on_error=True)
        self.assertEqual(evals[-1]["tool"], "k6")
        self.assertEqual(sum("error" in e for e in evals), 1)
        self.assertLess(len(evals), 58)

    def test_a_tool_whose_v0_failed_is_not_run(self):
        env = FakeEnv()
        info = {**TOOLS_INFO, "k6": {**TOOLS_INFO["k6"], "v0_ok": False}}
        evals = self.silently(V.run_all, env, V.expand(), self.out, info)
        self.assertFalse([k for k in env.launched if "/k6/" in k])
        self.assertTrue(all("not run" in e["error"] for e in evals if e["tool"] == "k6"))

    def test_an_infrastructure_error_stops_everything(self):
        with self.assertRaises(V.InfraError):
            self.silently(V.run_all, FakeEnv(infra_on="V3/vegeta/r500_0"), V.expand(), self.out,
                          TOOLS_INFO)

    def test_reanalysis_from_the_files_gives_the_same_verdicts(self):
        self.silently(self.run_all, FakeEnv(fail_tools=("k6",)))
        before = read(self.out, "results.json")
        rc = self.silently(V.main, ["reanalyse", self.out])
        self.assertEqual(rc, 0)
        after = read(self.out, "results.json")
        self.assertEqual(before["jobs"], after["jobs"])
        self.assertEqual(before["summary"], after["summary"])

    def test_reanalysis_picks_up_a_changed_criterion_and_a_changed_file(self):
        self.silently(self.run_all)
        path = os.path.join(self.out, "V1", "vegeta", "r100_0", "origin.json")
        o = read(os.path.dirname(path), "origin.json")
        o["requests"] = 900
        with open(path, "w") as f:
            json.dump(o, f)
        self.silently(V.main, ["reanalyse", self.out])
        s = read(self.out, "results.json")["summary"]
        self.assertEqual(s["vegeta"]["tests"]["V1"]["verdict"], "fail")
        self.assertEqual(s["vegeta"]["suggested_status"], "unfit")


def read(directory, name):
    with open(os.path.join(directory, name)) as f:
        return json.load(f)


class CliTest(unittest.TestCase):
    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = V.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_plan_prints_every_command_and_starts_nothing(self):
        rc, out, _ = self.call("plan", "--tools", "vegeta,wrk", "--tests", "V4")
        self.assertEqual(rc, 0)
        self.assertIn("V4/vegeta/r500_0: origin s2 subject", out)
        self.assertIn("V4/wrk/r500_0: origin s2 control", out)
        self.assertIn("serve-s2", out)
        self.assertIn("vegeta attack -rate=500/1s -duration=40s", out)
        self.assertIn("-redirects=-1", out)
        self.assertIn("/usr/bin/wrk -t2 -c50 -d40s", out)
        self.assertTrue(out.strip().endswith("2 jobs, 1.3 minutes of load"))

    def test_run_needs_yes(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o")
            rc, _, err = self.call("run", "--out", out, "--tests", "V1")
            self.assertEqual(rc, 2)
            self.assertIn("--yes", err)
            self.assertFalse(os.path.exists(out))

    def test_run_never_overwrites_a_results_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "keep"), "w") as f:
                f.write("x")
            rc, _, err = self.call("run", "--out", tmp, "--tests", "V1", "--yes")
            self.assertEqual(rc, 2)
            self.assertIn("never overwritten", err)
            self.assertEqual(os.listdir(tmp), ["keep"])

    def test_unknown_tools_and_tests_are_refused(self):
        for argv in (["plan", "--tools", "ab"], ["plan", "--tests", "V9"]):
            with self.assertRaises(SystemExit):
                self.call(*argv)

    def test_tools_info_checks_hash_and_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = b"#!/bin/sh\necho 'Version: v12.13.0'\n"
            path = os.path.join(tmp, "vegeta-12.13.0", "vegeta")
            os.makedirs(os.path.dirname(path))
            with open(path, "wb") as f:
                f.write(script)
            os.chmod(path, 0o755)
            m = {"schema": 1, "tools": {"vegeta": {
                "kind": "external", "version": "v12.13.0", "path": "vegeta-12.13.0/vegeta",
                "sha256": hashlib.sha256(script).hexdigest(), "status": "smoke-tested"}}}
            info = V.RealEnv(m, tmp).tools_info(["vegeta"])["vegeta"]
            self.assertTrue(info["v0_ok"])
            self.assertEqual(info["version_output"], "Version: v12.13.0")
            m["tools"]["vegeta"]["version"] = "v13"
            self.assertFalse(V.RealEnv(m, tmp).tools_info(["vegeta"])["vegeta"]["v0_ok"])
            m["tools"]["vegeta"]["sha256"] = "0" * 64
            info = V.RealEnv(m, tmp).tools_info(["vegeta"])["vegeta"]
            self.assertFalse(info["v0_ok"])
            self.assertIn("binary changed", info["error"])


if __name__ == "__main__":
    unittest.main()
