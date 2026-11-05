"""Tests for bench/loadgen.py, the in-repo open-loop engine.

* the schedules: counts, spacing, determinism, the pulse windows and the ramp's rate;
* the HTTP reader on bytes fed to a StreamReader: Content-Length, chunked with trailers, HEAD, 204,
  until-EOF, back-to-back responses, a short body;
* the summary on hand-filled records: latency from the intended time against from the actual
  send, slip, and every validity flag at its limit;
* the engine against local servers on 127.0.0.1 (tens of requests, runs of well under two
  seconds): counts, intended-time latency across a stall, drops at the in-flight cap, timeouts and
  refused connections, source-address binding, keep-alive pools and stale connections, and the
  command line (scope refusal, --plan, --strict, the summary and records files).

The time-based checks use margins that survive this VM's late wake-ups (sleepers are sometimes woken
hundreds of milliseconds late); none asserts that the generator was punctual, only what it counted.
"""
import asyncio
import contextlib
import gzip
import io
import itertools
import json
import math
import os
import sys
import tempfile
import threading
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import loadgen as G
import loadtools as LT
from test_loadtool_validate import RunningOrigin, free_port


class ServerThread:
    """A raw asyncio server on an ephemeral loopback port; `handler(reader, writer, log)`."""

    def __init__(self, handler):
        self.handler = handler
        self.log = {"conns": 0, "peers": [], "requests": 0}

    def __enter__(self):
        self.loop = asyncio.new_event_loop()
        started = threading.Event()

        async def wrap(reader, writer):
            self.log["conns"] += 1
            self.log["peers"].append(writer.get_extra_info("peername")[0])
            try:
                await self.handler(reader, writer, self.log)
            except (asyncio.IncompleteReadError, ConnectionError):
                pass
            finally:
                writer.close()

        def target():
            asyncio.set_event_loop(self.loop)
            self.server = self.loop.run_until_complete(asyncio.start_server(wrap, "127.0.0.1", 0))
            self.port = self.server.sockets[0].getsockname()[1]
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
        self.url = f"http://127.0.0.1:{self.port}/"
        return self

    def __exit__(self, *exc):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


async def answer_ok(reader, writer, log):
    """Keep-alive, immediate 200."""
    while True:
        await reader.readuntil(b"\r\n\r\n")
        log["requests"] += 1
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()


async def answer_once_then_close(reader, writer, log):
    """Says keep-alive, then closes the socket: the client's pooled connection goes stale."""
    await reader.readuntil(b"\r\n\r\n")
    log["requests"] += 1
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
    await writer.drain()


async def never_answer(reader, writer, log):
    await reader.readuntil(b"\r\n\r\n")
    log["requests"] += 1
    await asyncio.sleep(30)


def config(url, **kw):
    kw.setdefault("allow_loopback", True)
    return G.Config(url=url, **kw)


def exchanges(cfg, n):
    """n requests one after the other through one engine's pool (no schedule involved)."""
    async def go():
        eng = G.Engine(cfg, sched=[0.0] * n)
        eng.t0 = asyncio.get_running_loop().time()
        out = [await eng._exchange(eng.idents[0], eng.requests[0][0]) for _ in range(n)]
        for ident in eng.idents:
            while ident.pool:
                ident.pool.pop()[1].close()
        return out
    return asyncio.run(go())


def run(cfg):
    eng = G.Engine(cfg)
    timing = asyncio.run(eng.run())
    return eng, G.summarise(eng, timing)


class ScheduleTest(unittest.TestCase):
    def test_constant(self):
        s = G.schedule("constant", 100, 2)
        self.assertEqual(len(s), 200)
        self.assertEqual(s[0], 0.0)
        self.assertAlmostEqual(s[1], 0.01)
        self.assertLess(s[-1], 2)
        self.assertEqual(len(G.schedule("constant", 12.5, 4)), 50)

    def test_poisson_is_seeded_and_has_the_right_rate(self):
        a, b = G.schedule("poisson", 1000, 10, seed=5), G.schedule("poisson", 1000, 10, seed=5)
        self.assertEqual(a, b)
        self.assertNotEqual(a, G.schedule("poisson", 1000, 10, seed=6))
        self.assertAlmostEqual(len(a), 10000, delta=300)                 # 3 sigma = 300
        self.assertEqual(a, sorted(a))
        self.assertLess(a[-1], 10)
        gaps = [y - x for x, y in itertools.pairwise(a)]
        self.assertAlmostEqual(sum(gaps) / len(gaps), 0.001, delta=0.00005)

    def test_pulse_sends_only_in_the_on_windows(self):
        s = G.schedule("pulse", 100, 3, period=1.0, duty=0.25)
        self.assertEqual(len(s), 300)
        for t in s:
            self.assertLess(t % 1.0, 0.25 + 1e-9, t)
        self.assertAlmostEqual(s[1] - s[0], 0.25 / 100)                  # 400 requests/s while on

    def test_pulse_that_is_cut_by_the_end_of_the_run(self):
        s = G.schedule("pulse", 100, 1.1, period=1.0, duty=0.5)
        self.assertTrue(all(t < 1.1 for t in s))
        self.assertEqual(len(s), 100 + 20)                               # the second window has 0.1 s

    def test_ramp(self):
        s = G.schedule("ramp", 0, 10, ramp_to=200)
        self.assertEqual(len(s), 1000)                                   # mean rate 100 for 10 s
        self.assertEqual(s, sorted(s))
        self.assertLess(s[-1], 10)
        first, last = sum(t < 2 for t in s), sum(t >= 8 for t in s)
        self.assertEqual(first, 40)                                      # N(2) = 10 x 4
        self.assertEqual(last, 360)                                      # N(10) - N(8)
        a = 200 / (2 * 10)                                               # N(t) = a t^2
        for k, t in enumerate(s):
            self.assertAlmostEqual(a * t * t, k, places=6)

    def test_ramp_down_and_flat(self):
        down = G.schedule("ramp", 200, 10, ramp_to=0)
        self.assertEqual(len(down), 1000)
        self.assertEqual(down, sorted(down))
        self.assertGreater(sum(t < 2 for t in down), 350)
        self.assertEqual(G.schedule("ramp", 50, 4, ramp_to=50), G.schedule("constant", 50, 4))
        self.assertEqual(G.schedule("ramp", 50, 4), G.schedule("constant", 50, 4))

    def test_bad_arguments(self):
        for args in (("constant", 0, 1), ("constant", 1, 0), ("burst", 1, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                G.schedule(*args)
        with self.assertRaises(ValueError):
            G.schedule("pulse", 10, 1, duty=0)
        with self.assertRaises(ValueError):
            G.schedule("ramp", 10, 1, ramp_to=-1)
        with self.assertRaises(ValueError):
            G.schedule("ramp", 0, 1, ramp_to=0)


class HttpTest(unittest.TestCase):
    def feed(self, data, method="GET", eof=True, reads=1):
        async def go():
            reader = asyncio.StreamReader()
            reader.feed_data(data)
            if eof:
                reader.feed_eof()
            return [await G.read_response(reader, method) for _ in range(reads)]
        return asyncio.run(go())

    def test_request_bytes(self):
        self.assertEqual(G.build_request("GET", "10.0.0.1", 80, "/x"),
                         b"GET /x HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: loadgen/1\r\n"
                         b"Accept: */*\r\n\r\n")
        req = G.build_request("HEAD", "10.0.0.1", 8080, "/", ("X-A: b",))
        self.assertIn(b"Host: 10.0.0.1:8080\r\n", req)
        self.assertTrue(req.endswith(b"X-A: b\r\n\r\n"))

    def test_head_parsing(self):
        self.assertEqual(G.parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 5"), (200, 5, False, False))
        self.assertEqual(G.parse_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked"),
                         (200, None, True, False))
        self.assertEqual(G.parse_head(b"HTTP/1.1 503 X\r\ncontent-length: 3\r\nCONNECTION: Close"),
                         (503, 3, False, True))
        self.assertEqual(G.parse_head(b"HTTP/1.0 200 OK"), (200, None, False, True))
        self.assertEqual(G.parse_head(b"HTTP/1.0 200 OK\r\nConnection: keep-alive")[3], False)
        for bad in (b"garbage", b"HTTP/1.1 abc OK", b"HTTP/2 200", b"",
                    b"HTTP/1.1 200 OK\r\nContent-Length: x"):
            with self.subTest(bad=bad), self.assertRaises(G.ProtocolError):
                G.parse_head(bad)

    def test_content_length_body(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        self.assertEqual(self.feed(head + b"hello"), [(200, len(head) + 5, True)])

    def test_two_responses_back_to_back_keep_their_framing(self):
        a = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        b = b"HTTP/1.1 404 NF\r\nContent-Length: 3\r\n\r\nnot"
        got = self.feed(a + b, reads=2)
        self.assertEqual([g[0] for g in got], [200, 404])
        self.assertEqual(got[1][1], len(b))

    def test_head_and_204_have_no_body_whatever_the_header_says(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n"
        self.assertEqual(self.feed(head, "HEAD"), [(200, len(head), True)])
        h204 = b"HTTP/1.1 204 No Content\r\nContent-Length: 7\r\n\r\n"
        self.assertEqual(self.feed(h204), [(204, len(h204), True)])

    def test_chunked_body_with_extension_and_trailers(self):
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        body = b"5;ext=1\r\nhello\r\n3\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n"
        self.assertEqual(self.feed(head + body), [(200, len(head) + 8, True)])
        nxt = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"
        got = self.feed(head + body + nxt, reads=2)                      # the trailer was consumed
        self.assertEqual(got[1][0], 200)

    def test_bad_chunk_size(self):
        head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        with self.assertRaises(G.ProtocolError):
            self.feed(head + b"zz\r\nabc\r\n")

    def test_body_until_eof_means_close(self):
        head = b"HTTP/1.0 200 OK\r\n\r\n"
        self.assertEqual(self.feed(head + b"abcdef"), [(200, len(head) + 6, False)])

    def test_connection_close_is_not_keep_alive(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        self.assertEqual(self.feed(head), [(200, len(head), False)])

    def test_a_short_body_is_an_incomplete_read(self):
        with self.assertRaises(asyncio.IncompleteReadError):
            self.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
        with self.assertRaises(asyncio.IncompleteReadError):
            self.feed(b"HTTP/1.1 200 OK\r\nContent-")

    def test_error_classes(self):
        import errno
        self.assertEqual(G.classify(TimeoutError()), G.TIMEOUT)
        self.assertEqual(G.classify(OSError(errno.EMFILE, "x")), G.FD)
        self.assertEqual(G.classify(OSError(errno.EADDRNOTAVAIL, "x")), G.PORT)
        self.assertEqual(G.classify(ConnectionRefusedError(), connecting=True), G.CONNECT)
        self.assertEqual(G.classify(ConnectionResetError()), G.RESET)
        self.assertEqual(G.classify(BrokenPipeError()), G.RESET)
        self.assertEqual(G.classify(asyncio.IncompleteReadError(b"", 5)), G.RESET)
        self.assertEqual(G.classify(G.ProtocolError("x")), G.PROTOCOL)
        self.assertEqual(G.classify(asyncio.LimitOverrunError("x", 1)), G.PROTOCOL)
        self.assertEqual(G.classify(RuntimeError()), G.OTHER)


def hand_engine(rows, **kw):
    """An Engine whose records are filled by hand: rows of (intended, sent, done, status, err)."""
    cfg = config("http://127.0.0.1:1/", rate=10, duration=10, **kw)
    eng = G.Engine(cfg, sched=[r[0] for r in rows])
    for i, (_, sent, done, status, err) in enumerate(rows):
        eng.t_sent[i], eng.t_done[i], eng.status[i], eng.err[i] = sent, done, status, err
    return eng


TIMING = {"wall_s": 10.0, "cpu_s": 1.0, "spin_s": 0.0}


class SummaryTest(unittest.TestCase):
    def test_latency_is_from_the_intended_time_and_service_from_the_send(self):
        nan = math.nan
        eng = hand_engine([(0.0, 0.0, 0.010, 200, 0),
                           (1.0, 1.4, 1.410, 200, 0),            # sent 0.4 s late, 10 ms service
                           (2.0, 2.0, 2.020, 503, 0),
                           (3.0, nan, nan, 0, G.DROPPED)])
        s = G.summarise(eng, TIMING)
        self.assertEqual((s["intended"], s["sent"], s["dropped"], s["completed"]), (4, 3, 1, 3))
        self.assertEqual(s["status"], {"200": 2, "503": 1})
        self.assertEqual(s["errors"], {"dropped": 1})
        self.assertAlmostEqual(s["latency_s"]["max"], 0.410)
        self.assertAlmostEqual(s["service_s"]["max"], 0.020)
        self.assertAlmostEqual(s["slip_s"]["max"], 0.4)
        self.assertAlmostEqual(s["latency_2xx_s"]["max"], 0.410)
        self.assertEqual(s["per_second"]["intended"][:4], [1, 1, 1, 1])
        self.assertEqual(s["per_second"]["completed"][:3], [1, 1, 1])

    def test_failed_requests_count_in_the_latency_and_not_as_completed(self):
        eng = hand_engine([(0.0, 0.0, 0.2, 0, G.TIMEOUT), (1.0, 1.0, 1.001, 200, 0)])
        s = G.summarise(eng, TIMING)
        self.assertEqual((s["sent"], s["completed"]), (2, 1))
        self.assertEqual(s["errors"], {"timeout": 1})
        self.assertAlmostEqual(s["latency_s"]["max"], 0.2)

    def test_each_flag_trips_at_its_limit(self):
        ok = [(i / 10, i / 10 + 0.001, i / 10 + 0.002, 200, 0) for i in range(100)]
        s = G.summarise(hand_engine(ok), TIMING)
        self.assertTrue(s["valid"], s["flags"])
        late = [(t, t + 0.06, d + 0.06, c, e) for t, _, d, c, e in ok]
        self.assertTrue(G.summarise(hand_engine(late), TIMING)["flags"]["slip"])
        short = ok[:98] + [(9.8, math.nan, math.nan, 0, G.DROPPED), (9.9, math.nan, math.nan, 0, G.DROPPED)]
        s = G.summarise(hand_engine(short), TIMING)
        self.assertTrue(s["flags"]["sent_short"])
        self.assertTrue(s["flags"]["dropped"])
        one = ok[:99] + [(9.9, math.nan, math.nan, 0, G.DROPPED)]          # 99 of 100: at the limit
        s = G.summarise(hand_engine(one), TIMING)
        self.assertFalse(s["flags"]["sent_short"])
        self.assertTrue(s["flags"]["dropped"])
        s = G.summarise(hand_engine(ok), {"wall_s": 10.0, "cpu_s": 7.5, "spin_s": 0.0})
        self.assertTrue(s["flags"]["cpu"])                                 # 75 % of a core
        s = G.summarise(hand_engine(ok), {"wall_s": 10.0, "cpu_s": 7.5, "spin_s": 1.0})
        self.assertFalse(s["flags"]["cpu"])                                # 65 % once the spin is out
        bad = ok[:90] + [(9.0 + i / 100, 9.0 + i / 100, 9.1, 0, G.FD) for i in range(5)] \
            + [(9.5 + i / 100, 9.5 + i / 100, 9.6, 0, G.PORT) for i in range(5)]
        s = G.summarise(hand_engine(bad), TIMING)
        self.assertTrue(s["flags"]["descriptors"] and s["flags"]["ports"])
        self.assertFalse(s["valid"])

    def test_the_summary_is_json(self):
        s = G.summarise(hand_engine([(0.0, 0.0, 0.01, 200, 0)]), TIMING)
        self.assertEqual(json.loads(json.dumps(s))["tool"], "loadgen")


class EngineTest(unittest.TestCase):
    def test_a_steady_run_sends_everything_and_reads_every_answer(self):
        with RunningOrigin(service_ms=5, jitter_ms=0) as o:
            _eng, s = run(config(f"http://127.0.0.1:{o.port}/", rate=100, duration=0.5))
        self.assertEqual((s["intended"], s["sent"], s["dropped"], s["completed"]), (50, 50, 0, 50))
        self.assertEqual(s["status"], {"200": 50})
        self.assertEqual(s["errors"], {})
        self.assertGreaterEqual(s["latency_s"]["min"], 0.005)
        self.assertEqual(len(o.origin.arrivals), 50)
        self.assertEqual(s["per_second"]["intended"][0], 50)

    def test_latency_across_a_stall_is_counted_from_the_intended_time(self):
        # 100 requests/s for 1.2 s; the origin holds every response written in [0.2, 0.7) after
        # its first request. The ~50 requests intended in that window wait up to 0.5 s each,
        # and a generator that sent the next one only after the previous answer would show ~5 ms.
        with RunningOrigin(service_ms=2, jitter_ms=0, stall_after=0.2, stall_for=0.5) as o:
            _eng, s = run(config(f"http://127.0.0.1:{o.port}/", rate=100, duration=1.2))
        self.assertEqual((s["sent"], s["dropped"], s["completed"]), (120, 0, 120))
        self.assertGreaterEqual(s["latency_s"]["max"], 0.45)
        self.assertGreaterEqual(s["latency_s"]["p99"], 0.3)
        self.assertLess(s["latency_s"]["p50"], 0.4)
        self.assertEqual(len(o.origin.arrivals), 120)                     # all of them got there

    def test_requests_beyond_the_inflight_cap_are_dropped_and_flagged(self):
        with RunningOrigin(service_ms=150, jitter_ms=0) as o:
            _eng, s = run(config(f"http://127.0.0.1:{o.port}/", rate=50, duration=0.6,
                                max_inflight=1))
        self.assertEqual(s["intended"], 30)
        self.assertEqual(s["sent"] + s["dropped"], 30)
        self.assertGreater(s["dropped"], 10)
        self.assertEqual(s["errors"]["dropped"], s["dropped"])
        self.assertTrue(s["flags"]["dropped"])
        self.assertFalse(s["valid"])
        self.assertEqual(len(o.origin.arrivals), s["sent"])               # what was dropped never left

    def test_timeouts_are_errors_with_the_timeout_as_their_latency(self):
        with ServerThread(never_answer) as srv:
            _eng, s = run(config(srv.url, rate=20, duration=0.3, timeout=0.2))
        self.assertEqual(s["errors"], {"timeout": 6})
        self.assertEqual((s["sent"], s["completed"]), (6, 0))
        self.assertGreaterEqual(s["latency_s"]["min"], 0.2)

    def test_a_refused_connection_is_a_connect_error(self):
        port = free_port()
        _eng, s = run(config(f"http://127.0.0.1:{port}/", rate=20, duration=0.3, timeout=1))
        self.assertEqual(s["errors"], {"connect": 6})
        self.assertEqual(s["completed"], 0)

    def test_each_identity_binds_its_source_address(self):
        with ServerThread(answer_ok) as srv:
            _eng, s = run(config(srv.url, rate=40, duration=0.5,
                                local_addrs=("127.0.0.2", "127.0.0.3")))
        self.assertEqual(s["completed"], 20)
        self.assertEqual(set(srv.log["peers"]), {"127.0.0.2", "127.0.0.3"})
        self.assertEqual(s["identities"], ["127.0.0.2", "127.0.0.3"])

    def test_the_pool_keeps_idle_connections_and_pool_zero_keeps_none(self):
        # sequential exchanges, so that late wake-ups (which make the scheduler send bursts)
        # cannot change how many connections are needed
        with ServerThread(answer_ok) as srv:
            got = exchanges(config(srv.url, rate=1, duration=1, pool=100), 10)
        self.assertEqual([r for _, _, r in got], [0] + [1] * 9)
        self.assertEqual(srv.log["conns"], 1)
        with ServerThread(answer_ok) as srv:
            got = exchanges(config(srv.url, rate=1, duration=1, pool=0), 10)
        self.assertEqual([r for _, _, r in got], [0] * 10)
        self.assertEqual(srv.log["conns"], 10)

    def test_the_pool_is_capped_per_identity(self):
        async def go(cfg):
            eng = G.Engine(cfg, sched=[0.0] * 5)
            eng.t0 = asyncio.get_running_loop().time()
            await asyncio.gather(*[eng._exchange(eng.idents[0], eng.requests[0][0])
                                   for _ in range(5)])                   # five at once
            kept = len(eng.idents[0].pool)
            for ident in eng.idents:
                while ident.pool:
                    ident.pool.pop()[1].close()
            return kept
        with ServerThread(answer_ok) as srv:
            self.assertEqual(asyncio.run(go(config(srv.url, rate=1, duration=1, pool=2))), 2)
            self.assertEqual(srv.log["conns"], 5)

    def test_a_connection_the_server_closed_is_retried_once_on_a_new_one(self):
        with ServerThread(answer_once_then_close) as srv:
            got = exchanges(config(srv.url, rate=1, duration=1), 10)
        self.assertEqual([s for s, _, _ in got], [200] * 10)
        self.assertEqual([r for _, _, r in got], [0] * 10)               # the retry was on a new one
        self.assertEqual(srv.log["requests"], 10)

    def test_paths_and_headers_reach_the_server(self):
        seen = []

        async def record(reader, writer, log):
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                seen.append(head)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()

        with ServerThread(record) as srv:
            run(config(srv.url, rate=20, duration=0.4, paths=("/a", "/b?x=1"),
                       headers=("X-Test: yes",)))
        lines = {h.split(b"\r\n")[0] for h in seen}
        self.assertEqual(lines, {b"GET /a HTTP/1.1", b"GET /b?x=1 HTTP/1.1"})
        self.assertTrue(all(b"X-Test: yes\r\n" in h for h in seen))

    def test_the_run_is_reproducible_from_the_seed(self):
        a = G.Engine(config("http://127.0.0.1:1/", rate=50, duration=2, process="poisson", seed=9,
                            paths=("/a", "/b", "/c")))
        b = G.Engine(config("http://127.0.0.1:1/", rate=50, duration=2, process="poisson", seed=9,
                            paths=("/a", "/b", "/c")))
        self.assertEqual((a.sched, a.choice), (b.sched, b.choice))

    def test_spinning_is_accounted_apart_from_load(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o:
            _eng, s = run(config(f"http://127.0.0.1:{o.port}/", rate=50, duration=0.4, spin_ms=50))
        self.assertEqual(s["completed"], 20)
        self.assertGreater(s["cpu"]["spin_s"], 0.1)
        self.assertEqual(s["spin_ms"], 50)

    def test_head_requests_work(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o:
            _eng, s = run(config(f"http://127.0.0.1:{o.port}/", rate=20, duration=0.3,
                                method="HEAD"))
        self.assertEqual(s["status"], {"200": 6})

    def test_the_scope_lock_applies_to_the_engine_itself(self):
        for url in ("http://8.8.8.8/", "http://example.com/", "http://127.0.0.1:1/"):
            with self.assertRaises(LT.ScopeError):
                G.Engine(G.Config(url=url, rate=1, duration=1))
        with self.assertRaises(LT.ScopeError):
            G.Engine(G.Config(url="http://10.0.0.1/", rate=1, duration=1,
                              local_addrs=("192.168.1.1",)))
        with self.assertRaises(ValueError):
            G.Engine(G.Config(url="http://10.0.0.1/", rate=1, duration=1, method="POST"))
        G.Engine(G.Config(url="http://10.0.0.1/", rate=1, duration=1))


class CliTest(unittest.TestCase):
    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = G.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_version_and_plan_send_nothing(self):
        self.assertEqual(self.call("--version"), (0, "loadgen 1\n", ""))
        rc, out, _ = self.call("--url", "http://10.0.0.1/", "--rate", "10", "--duration", "2",
                               "--plan")
        self.assertEqual(rc, 0)
        self.assertIn("constant: 20 requests over 2 s", out)
        self.assertIn("per second: [10, 10, 0]", out)

    def test_refusals_return_2_before_anything_is_sent(self):
        for url in ("http://8.8.8.8/", "http://example.com/", "http://127.0.0.1:1/"):
            rc, out, err = self.call("--url", url, "--rate", "10", "--duration", "1")
            self.assertEqual((rc, out), (2, ""), url)
            self.assertIn("refusing", err)
        rc, _, err = self.call("--url", "http://10.0.0.1/", "--rate", "10", "--duration", "1",
                               "--header", "no colon")
        self.assertEqual(rc, 2)
        with self.assertRaises(SystemExit):
            self.call("--url", "http://10.0.0.1/")

    def test_summary_and_records_files(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o, tempfile.TemporaryDirectory() as tmp:
            summary, records = os.path.join(tmp, "s.json"), os.path.join(tmp, "r.csv.gz")
            rc, out, _ = self.call("--url", f"http://127.0.0.1:{o.port}/", "--allow-loopback",
                                   "--rate", "50", "--duration", "0.4", "--summary", summary,
                                   "--records", records)
            self.assertEqual((rc, out), (0, ""))
            with open(summary) as f:
                s = json.load(f)
            self.assertEqual((s["intended"], s["completed"], s["version"]), (20, 20, "1"))
            with gzip.open(records, "rt") as f:
                lines = f.read().splitlines()
            self.assertEqual(lines[0], "i,t_intended,t_sent,t_done,status,bytes,err,ident,reused")
            self.assertEqual(len(lines), 21)
            self.assertEqual(lines[1].split(",")[4], "200")

    def test_the_summary_goes_to_stdout_without_a_file(self):
        with RunningOrigin(service_ms=1, jitter_ms=0) as o:
            rc, out, _ = self.call("--url", f"http://127.0.0.1:{o.port}/", "--allow-loopback",
                                   "--rate", "20", "--duration", "0.3")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["completed"], 6)

    def test_strict_turns_a_flag_into_status_3(self):
        with RunningOrigin(service_ms=150, jitter_ms=0) as o:
            args = ["--url", f"http://127.0.0.1:{o.port}/", "--allow-loopback", "--rate", "50",
                    "--duration", "0.4", "--max-inflight", "1"]
            self.assertEqual(self.call(*args)[0], 0)
            self.assertEqual(self.call(*args, "--strict")[0], 3)


if __name__ == "__main__":
    unittest.main()
