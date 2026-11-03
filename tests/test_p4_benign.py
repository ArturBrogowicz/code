"""P4 part 2b: the benign population on profile R, its upload kinds and the halving rule (ml/p4_traffic.py,
ml/l7_benign.py upload_plan, ml/l7_gen.py PacedBody / benign_uploader / benign_slow_uploader; docs/P4_SLOW_DESIGN.md
§4.2). Offline: nothing is sent; the generator runs against a fake sender and a fake clock."""
import collections
import contextlib
import ipaddress
import os
import random
import socket
import sys
import threading
import time
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "eval")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import harm_gate as HG
import l7_benign
import l7_gen
import l7_pools
import p4_outcome
import p4_traffic as P

import slow_pc


class Clock:
    """time.time / time.monotonic / time.sleep on one virtual clock."""

    def __init__(self, t=1000.0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)


class UploadPlanTest(unittest.TestCase):
    def test_the_draws_are_the_p5_uploaders(self):
        params = {"think_s": [4.0, 10.0], "body_bytes": [200, 60000]}
        rng, plan = random.Random(7), l7_benign.upload_plan(params, 120.0, random.Random(7))
        legacy = [(rng.randint(200, 60000), rng.uniform(4.0, 10.0)) for _ in plan]   # the P5 loop's draw order
        self.assertEqual(plan, legacy)
        self.assertGreaterEqual(sum(t for _b, t in plan), 120.0)
        self.assertLess(sum(t for _b, t in plan[:-1]), 120.0)
        self.assertEqual(l7_benign.upload_plan({}, 60.0, random.Random(3)),
                         l7_benign.upload_plan(dict(l7_benign.UPLOAD_DEFAULTS), 60.0, random.Random(3)))

    def test_p4_bodies_go_up_to_2_mb(self):
        spec = {s["kind"]: s for s in P.BENIGN}
        for kind in ("uploader", "slow_uploader"):
            self.assertEqual(spec[kind]["params"]["body_bytes"], [200, 2_000_000])
            sizes = [b for b, _t in l7_benign.upload_plan(spec[kind]["params"], 3000.0, random.Random(1))]
            self.assertLessEqual(max(sizes), 2_000_000)
            self.assertGreater(max(sizes), 1_500_000)


class PacedBodyTest(unittest.TestCase):
    def test_it_leaves_at_the_rate_a_piece_at_a_time(self):
        c = Clock()
        body = l7_gen.PacedBody(10_000, 2000, clock=c.now, sleep=c.sleep)
        self.assertEqual(len(body), 10_000)
        t0, pieces = c.t, []
        while chunk := body.read(8192):
            pieces.append(len(chunk))
            self.assertLessEqual(sum(pieces), 2000 * (c.t - t0) + 1e-6, "never ahead of the rate")
        self.assertEqual(sum(pieces), 10_000)
        self.assertTrue(all(p <= l7_gen.PacedBody.CHUNK for p in pieces))
        self.assertAlmostEqual(c.t - t0, 10_000 / 2000, places=6)
        self.assertEqual(body.read(), b"")

    def test_requests_sends_it_with_a_content_length_not_chunked(self):
        import requests
        prep = requests.Request("POST", "http://10.0.0.1/upload", data=l7_gen.PacedBody(4321, 2000)).prepare()
        self.assertEqual(prep.headers.get("Content-Length"), "4321")
        self.assertNotIn("Transfer-Encoding", prep.headers)
        plain = requests.Request("POST", "http://10.0.0.1/upload", data=b"x" * 4321).prepare()
        self.assertEqual(sorted(prep.headers.items()), sorted(plain.headers.items()), "the same request head")

    def test_it_stops_at_its_deadline(self):
        c = Clock()
        body = l7_gen.PacedBody(10_000, 2000, clock=c.now, sleep=c.sleep, deadline=c.t + 1.0, wall=c.now)
        got = 0
        with self.assertRaises(l7_gen.UploadDeadline):
            while chunk := body.read(8192):
                got += len(chunk)
        self.assertAlmostEqual(c.t, 1001.0 - 1000.0 + 1000.0)                # at the deadline, not after it
        self.assertLessEqual(got, 2000)
        self.assertEqual(len(l7_gen.PacedBody(5, 2000, clock=c.now, sleep=c.sleep, deadline=c.t + 9, wall=c.now).read()), 5)

    def test_a_rate_is_required(self):
        with self.assertRaises(ValueError):
            l7_gen.PacedBody(10, 0)


class UploaderGeneratorTest(unittest.TestCase):
    def run_kind(self, kind, params, dur=60.0, seed=5):
        c, posts = Clock(), []

        def one_shot(method, url, data=None, **kw):
            posts.append((method, url, data, kw))
            c.sleep(0.5 if not isinstance(data, l7_gen.PacedBody) else len(data) / data.rate)

        with mock.patch.object(l7_gen, "_one_shot", one_shot), mock.patch("time.time", c.now), \
                mock.patch("time.sleep", c.sleep):
            l7_gen.resolve("benign", kind)("10.0.0.1", 80, params, dur, random.Random(seed))
        return posts

    def test_the_uploader_posts_its_plan_in_order(self):
        params = dict(P._UPLOAD)
        posts = self.run_kind("uploader", params)
        plan = l7_benign.upload_plan(params, 60.0, random.Random(5))
        self.assertGreater(len(posts), 2)
        self.assertEqual([len(d) for _m, _u, d, _k in posts], [b for b, _t in plan[:len(posts)]])
        self.assertTrue(all(isinstance(d, bytes) for _m, _u, d, _k in posts))
        self.assertEqual({(m, u) for m, u, _d, _k in posts}, {("post", "http://10.0.0.1:80/upload")})

    def test_the_slow_uploader_is_the_uploader_paced(self):
        spec = {s["kind"]: s for s in P.BENIGN}
        posts = self.run_kind("slow_uploader", spec["slow_uploader"]["params"], dur=3000.0)
        plan = l7_benign.upload_plan(spec["slow_uploader"]["params"], 3000.0, random.Random(5))
        self.assertTrue(all(isinstance(d, l7_gen.PacedBody) and d.rate == 2000 for _m, _u, d, _k in posts))
        self.assertEqual([len(d) for _m, _u, d, _k in posts], [b for b, _t in plan[:len(posts)]])
        self.assertEqual({k["timeout"] for _m, _u, _d, k in posts}, {15})

    def test_a_think_time_ends_at_the_deadline(self):
        c, spent = Clock(), []

        def one_shot(method, url, data=None, **kw):
            spent.append(c.t)

        with mock.patch.object(l7_gen, "_one_shot", one_shot), mock.patch("time.time", c.now), \
                mock.patch("time.sleep", c.sleep):
            l7_gen.resolve("benign", "uploader")("10.0.0.1", 80, {"think_s": [500.0, 500.0], "body_bytes": [10, 10]},
                                                 60.0, random.Random(5))
        self.assertEqual((spent, c.t), ([1000.0], 1060.0))

    def test_a_slow_uploader_without_a_rate_is_refused(self):
        with self.assertRaises(SystemExit):
            self.run_kind("slow_uploader", dict(P._UPLOAD))


class RealClockTest(unittest.TestCase):
    """Review T-047 P-01, on the real generator and the real clock. Nearly every run of P4 would otherwise be invalid: the
    deadline bounded only the START of an upload, and a 24 kB body took 12 s and then the 15-s read timeout on a 1.5-s generator.
    These tests do not bound the call by wall time: a sleep in this very path has been measured returning 30 s late on this VM,
    cause not established. What they show holds however late a wake-up is."""

    DUR = 1.5
    RATE = 2000
    GUARD_S = 120.0

    def setUp(self):
        self.closed = threading.Event()
        self.received = 0
        self.srv = socket.socket()
        self.addCleanup(self.srv.close)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.conns = []
        threading.Thread(target=self.sink, daemon=True).start()

    def tearDown(self):
        for conn in self.conns:
            conn.close()

    def sink(self):
        with contextlib.suppress(OSError):
            conn, _addr = self.srv.accept()
            self.conns.append(conn)
            while chunk := conn.recv(65536):
                self.received += len(chunk)
            self.closed.set()

    def test_a_paced_body_stops_at_the_deadline_and_closes(self):
        t0 = time.monotonic()
        l7_gen.resolve("benign", "slow_uploader")("127.0.0.1", self.srv.getsockname()[1],
                                                  {"think_s": [4.0, 4.0], "path": "/upload", "body_bytes": [24_000, 24_000],
                                                   "rate_Bps": self.RATE}, self.DUR, random.Random(1))
        self.assertGreaterEqual(time.monotonic() - t0, self.DUR - 0.1)
        self.assertTrue(self.closed.wait(self.GUARD_S), "the upload itself stopped: its connection was closed")
        head = 400                                          # the request head the sink counts too
        self.assertLessEqual(self.received, self.RATE * self.DUR + l7_gen.PacedBody.CHUNK + head)

    def test_an_upload_waiting_for_its_answer_does_not_hold_the_generator(self):
        answered = threading.Event()
        self.addCleanup(answered.set)

        def never_answered(method, url, **kw):
            answered.wait()

        with mock.patch.object(l7_gen, "_one_shot", never_answered):
            generator = threading.Thread(target=l7_gen.resolve("benign", "uploader"), daemon=True,
                                         args=("127.0.0.1", 80, {"think_s": [4.0, 4.0], "body_bytes": [200, 200]},
                                               self.DUR, random.Random(1)))
            generator.start()
            generator.join(self.GUARD_S)
            self.assertFalse(generator.is_alive(), "the generator ended with the upload still in flight")
            self.assertFalse(answered.is_set())


class PopulationTest(unittest.TestCase):
    def test_the_mix_of_section_4_2(self):
        plan = P.build_plan(3101, "eval")
        kinds = collections.Counter(e["kind_or_family"] for e in plan["entities"])
        self.assertEqual(kinds, {"tpcw_browsing": 40, "cgnat_browsers": 2, "search_user": 10, "api_bulk": 1,
                                 "crawler_polite": 1, "uploader": 4, "slow_uploader": 2})
        users = sorted(e["params"]["users"] for e in plan["entities"] if e["kind_or_family"] == "cgnat_browsers")
        self.assertEqual(users, [12, 24])
        self.assertEqual(P.BENIGN_ENTITIES, 60)
        self.assertTrue(all(e["role"] == "benign" for e in plan["entities"]))
        self.assertTrue(all(e["schedule"] == {"start_s": 0.0, "stop_s": 270.0, "phase": None}
                            for e in plan["entities"]))

    def test_labels_for_the_scorers(self):
        plan = P.build_plan(3101, "eval")
        labels = collections.Counter(P.roles(plan["entities"]).values())
        self.assertEqual(labels, {"tpcw_browsing": 40, "cgnat": 2, "search_user": 10, "api_bulk": 1,
                                  "crawler_polite": 1, "uploader": 4, "slow_uploader": 2})
        self.assertNotIn("attack", labels)

    def test_addresses_are_the_l7_pools_scheme(self):
        plan = P.build_plan(3102, "eval")
        addrs = [e["address"] for e in plan["entities"]]
        self.assertEqual(len(set(addrs)), len(addrs))
        pool = l7_pools.draw_pool(P.VERSION, 3102, P.POOL_SIZE)
        self.assertEqual(addrs, [pool[e["index"]] for e in plan["entities"]])
        for a in addrs:
            ip = ipaddress.ip_address(a)
            self.assertIn(ip, l7_pools.POOL_NET)
            self.assertFalse(any(ip in n for n in l7_pools.LEGACY_NETS))
        self.assertNotEqual(addrs, [e["address"] for e in P.build_plan(3103, "eval")["entities"]])
        self.assertEqual(plan, P.build_plan(3102, "eval"))

    def test_netem_is_balanced_and_the_slow_uploaders_have_their_link(self):
        plan = P.build_plan(4001, "val")
        slow = [e for e in plan["entities"] if e["kind_or_family"] == "slow_uploader"]
        self.assertEqual({e["netem"] for e in slow}, {P.NETEM_SLOW})
        rest = collections.Counter(e["netem"] for e in plan["entities"] if e["kind_or_family"] != "slow_uploader")
        self.assertEqual(set(rest), set(l7_pools.NETEM_PROFILES))
        self.assertLessEqual(max(rest.values()) - min(rest.values()), 1)
        self.assertEqual(P.NETEM_SLOW_ARGV[-2:], ("rate", "16kbit"))

    def test_the_two_upload_kinds_differ_only_in_pace_and_link(self):
        spec = {s["kind"]: s for s in P.BENIGN}
        up, slow = spec["uploader"], spec["slow_uploader"]
        self.assertEqual({k: v for k, v in slow["params"].items() if k != "rate_Bps"}, up["params"])
        self.assertEqual(slow["params"]["rate_Bps"] * 8, 16_000)
        self.assertEqual(slow["ports"], up["ports"])

    def test_seeds_and_timeline_are_the_pre_registered_ones(self):
        self.assertEqual(P.TIMELINE, p4_outcome.TIMELINE)
        self.assertEqual(P.SEEDS["eval"], p4_outcome.BLOCK_SEEDS)
        self.assertEqual(P.SEEDS["val"], slow_pc.VALIDATION_SEEDS)
        self.assertEqual(P.SEEDS["pilot"], tuple(range(9101, 9107)))
        with self.assertRaises(P.PlanError):
            P.build_plan(3101, "val")
        with self.assertRaises(P.PlanError):
            P.build_plan(9201, "pilot")


class HalvingTest(unittest.TestCase):
    def test_halving_drops_browser_devices_only_and_shifts_nothing(self):
        full = P.build_plan(9101, "pilot")
        half = P.build_plan(9101, "pilot", halvings=1)
        self.assertEqual([P.browser_devices(h) for h in range(4)], [40, 20, 10, 5])
        count = collections.Counter(e["kind_or_family"] for e in half["entities"])
        self.assertEqual(count["tpcw_browsing"], 20)
        self.assertEqual(count["cgnat_browsers"], 2, "the CGNAT pools are never removed")
        self.assertEqual(len(half["entities"]), 40)
        by_id = {e["entity_id"]: e for e in full["entities"]}
        for e in half["entities"]:
            f = by_id[e["entity_id"]]
            self.assertEqual({k: e[k] for k in ("address", "params", "client_seed", "port")},
                             {k: f[k] for k in ("address", "params", "client_seed", "port")})
        with self.assertRaises(P.PlanError):
            P.browser_devices(-1)

    def test_the_rule_reads_the_two_pilot_controls(self):
        cal = {"gate": {"control_q_min": 99.0}, "slo_ms": {"C1": 300, "C0": 100}}

        def control(q, c0_q=100.0):
            return {"Q": q, "by_class": {"C1": {"Q": q, "ok": 1, "n": 1}, "C0": {"Q": c0_q, "ok": 1, "n": 1}}}

        healthy = HG.control_health(control(99.5), cal)
        self.assertFalse(P.halve([healthy, healthy]))
        self.assertTrue(P.halve([healthy, HG.control_health(control(98.9), cal)]))
        self.assertTrue(P.halve([HG.control_health(control(99.6, c0_q=94.0), cal), healthy]))
        with self.assertRaises(P.PlanError):
            P.halve([healthy])

    def test_the_rule_does_not_fire_on_one_slow_export(self):
        # D-050: P4's control health judges a class of at least 20 requests; this class holds one.
        cal = {"gate": {"control_q_min": 99.0}, "slo_ms": {"C5": 3000}}
        one = {"Q": 99.5, "by_class": {"C5": {"Q": 0.0, "ok": 0, "n": 1}}}
        self.assertTrue(HG.control_health(one, cal))
        self.assertFalse(P.halve([p4_outcome.control_health(one, cal)[0], []]))


if __name__ == "__main__":
    unittest.main()
