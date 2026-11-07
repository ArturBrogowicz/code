"""P4 part 2b: the two slow families at the frozen scale of docs/P4_SLOW_DESIGN.md §5 on the in-repo generators
(ml/p4_traffic.py FAMILIES, loris_schedule, post_schedule; ml/l7_gen.py slow_schedule, run_slow_schedule, --plan).
Offline: no socket is opened; the generator runs against fake connections on a fake clock."""
import collections
import contextlib
import errno
import io
import itertools
import json
import os
import random
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7_gen
import l7_pools
import p4_traffic as P


class Clock:
    def __init__(self, t=5000.0):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)


class FakeSock:
    def __init__(self, net, head):
        self.net, self.head, self.sent, self.closed = net, head, [], False

    def sendall(self, data):
        if self in self.net.fail_next:
            self.net.fail_next.discard(self)
            raise ConnectionResetError("closed by the server")
        self.sent.append((round(self.net.clock.t - self.net.t0, 3), data))

    def close(self):
        self.closed = True


class FakeNet:
    """_open_sockets(host, port, n, head) on fake connections; `refuse` opens that fail."""

    def __init__(self, clock):
        self.clock, self.t0, self.socks, self.fail_next, self.refuse = clock, clock.t, [], set(), 0

    def open(self, host, port, n, head, errors=None):
        if self.refuse:
            self.refuse -= 1
            return []
        out = [FakeSock(self, head) for _ in range(n)]
        self.socks += out
        return out


def run(sched, dur, net=None, before=None):
    clock = Clock()
    net = net or FakeNet(clock)
    net.clock, net.t0 = clock, clock.t
    if before:
        before(net)
    with mock.patch.object(l7_gen, "_open_sockets", net.open), mock.patch("time.time", clock.now), \
            mock.patch("time.sleep", clock.sleep):
        stats = l7_gen.run_slow_schedule("10.0.0.1", 80, sched, dur)
    return net, stats


class FrozenScaleTest(unittest.TestCase):
    def test_the_parameters_of_section_5(self):
        lo, po = P.FAMILIES["loris"], P.FAMILIES["post"]
        self.assertEqual((lo["family"], lo["levels"], lo["ports"]), ("slowloris", (100, 175, 250, 300, 400, 500), [80]))   # D-073 (1)
        self.assertEqual(lo["params"], {"conns": 6, "header_every_s": [10.0, 40.0], "line_max_bytes": 32})
        self.assertEqual((po["family"], po["levels"], po["ports"]), ("slowpost", (5, 10, 20, 40), [80]))
        self.assertEqual(po["params"], {"conns": 1, "byte_every_s": [5.0, 30.0], "chunk_bytes": [1, 16],
                                        "content_length": [100_000, 1_000_000], "path": "/upload"})
        self.assertEqual(po["draws"], {"conns": ["int", 1, 2]})
        self.assertEqual(P.POOL_SIZE, 60 + 500 + 40)
        self.assertEqual((P.FAMILY_BASE, P.ALWAYS_RUN), ({"loris": 60, "post": 560}, 3))

    def test_the_top_of_both_ladders_in_one_plan(self):
        plan = P.build_plan(3101, "eval", loris=500, post=40)
        fam = collections.Counter(e["kind_or_family"] for e in plan["entities"] if e["role"] == "attack")
        self.assertEqual(fam, {"slowloris": 500, "slowpost": 40})
        loris = [e for e in plan["entities"] if e["kind_or_family"] == "slowloris"]
        post = [e for e in plan["entities"] if e["kind_or_family"] == "slowpost"]
        self.assertEqual({e["params"]["conns"] for e in loris}, {6})
        self.assertEqual({e["params"]["conns"] for e in post}, {1, 2})
        self.assertEqual(sum(e["params"]["conns"] for e in loris), 3000)          # 3,000 planned at the top level (D-073 (1))
        self.assertLessEqual(sum(e["params"]["conns"] for e in post), 80)
        self.assertTrue(all(e["p4_role"] == "attack" and e["port"] == 80 and e["params"]["port"] == 80
                            for e in loris + post))
        self.assertTrue(all(e["schedule"]["start_s"] == 30.0 and e["schedule"]["stop_s"] == 240.0 for e in loris + post))
        self.assertEqual({e["schedule"]["phase"] for e in loris}, {"loris"})
        addrs = [e["address"] for e in plan["entities"]]
        self.assertEqual(len(set(addrs)), len(addrs))
        netem = collections.Counter(e["netem"] for e in loris + post)
        self.assertEqual(set(netem), set(l7_pools.NETEM_PROFILES))
        self.assertLessEqual(max(netem.values()) - min(netem.values()), 1)

    def test_only_the_number_of_sources_moves(self):
        top = {e["entity_id"]: e for e in P.build_plan(9101, "pilot", loris=500, post=40)["entities"]}
        knee = P.build_plan(9101, "pilot", loris=175, post=10)["entities"]
        for e in knee:
            self.assertEqual({k: e[k] for k in ("address", "params", "client_seed")},
                             {k: top[e["entity_id"]][k] for k in ("address", "params", "client_seed")})
        benign = [e for e in knee if e["role"] == "benign"]
        self.assertEqual(benign, [e for e in P.build_plan(9101, "pilot")["entities"] if e["role"] == "benign"])
        with self.assertRaises(P.PlanError):
            P.build_plan(9101, "pilot", loris=501)
        with self.assertRaises(P.PlanError):
            P.build_plan(9101, "pilot", post=-1)


class ScheduleTest(unittest.TestCase):
    def test_slowloris_lines_every_10_to_40_s_of_at_most_32_bytes(self):
        params = dict(P.FAMILIES["loris"]["params"])
        slots = P.loris_schedule(params, 210.0, random.Random(11))
        self.assertEqual(len(slots), 6)
        for slot in slots:
            times = [0.0] + [t for t, _l in slot["lines"]]
            gaps = [b - a for a, b in itertools.pairwise(times)]
            self.assertTrue(all(10.0 - 1e-3 <= g <= 40.0 + 1e-3 for g in gaps), gaps)
            self.assertTrue(all(len(line) <= 32 and line.endswith("\r\n") and ": " in line for _t, line in slot["lines"]))
            self.assertLess(times[-1], 210.0)
            self.assertGreaterEqual(len(slot["lines"]), 210 // 40)
        self.assertEqual(slots, P.loris_schedule(params, 210.0, random.Random(11)))
        self.assertNotEqual(slots, P.loris_schedule(params, 210.0, random.Random(12)))

    def test_slow_post_chunks_of_1_to_16_bytes_every_5_to_30_s(self):
        params = dict(P.FAMILIES["post"]["params"], conns=2)
        slots = P.post_schedule(params, 210.0, random.Random(3))
        self.assertEqual(len(slots), 2)
        for slot in slots:
            self.assertEqual(len(slot["content_lengths"]), P.CONTENT_LENGTHS_PER_SLOT)
            self.assertTrue(all(100_000 <= n <= 1_000_000 for n in slot["content_lengths"]))
            times = [0.0] + [t for t, _n in slot["chunks"]]
            self.assertTrue(all(5.0 - 1e-3 <= b - a <= 30.0 + 1e-3 for a, b in itertools.pairwise(times)))
            self.assertTrue(all(1 <= n <= 16 for _t, n in slot["chunks"]))
            self.assertLess(sum(n for _t, n in slot["chunks"]), min(slot["content_lengths"]), "never completes")

    def test_plan_prints_the_schedule_the_generator_runs(self):
        params = dict(P.FAMILIES["loris"]["params"], port=80)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            l7_gen.main(["--role", "attack", "--family", "slowloris", "--host", "10.0.0.1", "--duration", "210",
                         "--seed", "77", "--params", json.dumps(params), "--plan"])
        printed = json.loads(out.getvalue())
        want = l7_gen.slow_schedule("slowloris", "10.0.0.1", params, 210.0, random.Random(77))
        self.assertEqual(printed["schedule"], json.loads(json.dumps(want)))
        self.assertTrue(printed["schedule"]["head"].startswith("GET /?r="))
        post = dict(P.FAMILIES["post"]["params"], conns=2, port=80)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            l7_gen.main(["--role", "attack", "--family", "slowpost", "--host", "10.0.0.1", "--duration", "210",
                         "--seed", "5", "--params", json.dumps(post), "--plan"])
        self.assertEqual(len(json.loads(out.getvalue())["schedule"]["slots"]), 2)

    def test_only_a_range_of_gaps_selects_the_p4_pacing(self):
        self.assertTrue(l7_gen.paced("slowloris", P.FAMILIES["loris"]["params"]))
        self.assertTrue(l7_gen.paced("slowpost", P.FAMILIES["post"]["params"]))
        self.assertFalse(l7_gen.paced("slowloris", {"conns": 6, "header_every_s": 3}))
        self.assertFalse(l7_gen.paced("slowpost", {"conns": 6, "byte_every_s": 3, "body_bytes": 60000}))
        self.assertFalse(l7_gen.paced("slowread", {"read_every_s": [1, 2]}))


class GeneratorTest(unittest.TestCase):
    def test_slowloris_sends_each_line_on_its_connection_at_its_time(self):
        sched = l7_gen.slow_schedule("slowloris", "10.0.0.1", dict(P.FAMILIES["loris"]["params"]), 210.0,
                                     random.Random(9))
        net, stats = run(sched, 210.0)
        self.assertEqual((stats["opened"], stats["reopened"], stats["failed_opens"]), (6, 0, 0))
        for sock, slot in zip(net.socks, sched["slots"], strict=True):
            self.assertEqual(sock.head, sched["head"].encode())
            self.assertEqual(sock.sent, [(t, line.encode()) for t, line in slot["lines"]])
            self.assertTrue(sock.closed, "closed at the end")

    def test_a_closed_connection_is_reopened_and_carries_on(self):
        sched = l7_gen.slow_schedule("slowloris", "10.0.0.1", dict(P.FAMILIES["loris"]["params"]), 210.0,
                                     random.Random(9))
        clock = Clock()
        net = FakeNet(clock)
        first = {}

        def arm(n):
            orig = n.open

            def open_and_mark(host, port, k, head, errors=None):
                got = orig(host, port, k, head, errors)
                if not first and got:
                    first["s"] = got[0]
                    n.fail_next.add(got[0])                   # the first connection's first line finds it closed
                return got
            n.open = open_and_mark
        net, stats = run(sched, 210.0, net, arm)
        self.assertEqual((stats["opened"], stats["reopened"]), (6, 1))
        lines0 = sched["slots"][0]["lines"]
        replacement = net.socks[6]
        self.assertEqual(replacement.head, sched["head"].encode())
        self.assertEqual(first["s"].sent, [])
        self.assertEqual(replacement.sent, [(t, line.encode()) for t, line in lines0[1:]],
                         "the re-opened connection takes the slot's next lines")

    def test_an_open_that_fails_is_tried_again_at_the_next_event(self):
        sched = l7_gen.slow_schedule("slowloris", "10.0.0.1", dict(P.FAMILIES["loris"]["params"], conns=1), 210.0,
                                     random.Random(4))

        def refuse(n):
            n.refuse = 2                                      # at the start, and at the first line
        net, stats = run(sched, 210.0, before=refuse)
        self.assertEqual((stats["failed_opens"], stats["opened"]), (2, 1))
        lines = sched["slots"][0]["lines"]
        self.assertEqual(net.socks[0].sent, [(t, line.encode()) for t, line in lines[1:]])

    def test_slow_post_declares_its_content_length_and_dribbles_its_chunks(self):
        params = dict(P.FAMILIES["post"]["params"], conns=2)
        sched = l7_gen.slow_schedule("slowpost", "10.0.0.1", params, 210.0, random.Random(21))
        net, stats = run(sched, 210.0)
        self.assertEqual(stats["opened"], 2)
        for sock, slot in zip(net.socks, sched["slots"], strict=True):
            head = sock.head.decode()
            self.assertTrue(head.startswith("POST /upload HTTP/1.1\r\n"))
            self.assertIn(f"Content-Length: {slot['content_lengths'][0]}\r\n\r\n", head)
            self.assertEqual([(t, len(d)) for t, d in sock.sent], [(t, n) for t, n in slot["chunks"]])
        self.assertEqual(stats["sent_bytes"], sum(n for s in sched["slots"] for _t, n in s["chunks"]))

    def test_a_complete_body_reopens_with_the_next_content_length(self):
        sched = {"family": "slowpost", "head": "POST /upload HTTP/1.1\r\nContent-Length: {n}\r\n\r\n",
                 "slots": [{"content_lengths": [20, 30], "chunks": [[5.0, 16], [10.0, 16], [15.0, 16]]}]}
        net, stats = run(sched, 60.0)
        self.assertEqual((stats["opened"], stats["reopened"]), (1, 1))
        self.assertEqual([len(d) for _t, d in net.socks[0].sent], [16, 4])
        self.assertIn(b"Content-Length: 30", net.socks[1].head)
        self.assertEqual([len(d) for _t, d in net.socks[1].sent], [16])

    def test_the_generator_states_what_it_opened(self):
        # The real generator, in the sandbox: its source address is not on this machine, so every open fails for a local
        # reason, and that must reach the runner (review T-047 P-06: the stats were dropped).
        params = dict(P.FAMILIES["loris"]["params"], conns=2, port=80)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(l7_gen, "SOURCE", None):
            path = os.path.join(tmp, "stats.json")
            rc = l7_gen.main(["--role", "attack", "--family", "slowloris", "--host", "10.0.0.1", "--duration", "0.2",
                              "--seed", "7", "--params", json.dumps(params), "--source", "10.0.16.5", "--stats", path])
            with open(path, encoding="utf-8") as fh:
                stats = json.load(fh)
        self.assertEqual((rc, stats["opened"], stats["failed_opens"], stats["local_errors"]), (0, 0, 2, 2))

    def test_a_refused_open_is_not_a_local_error(self):
        def refused(_host, _port, _n, _head, errors=None):
            errors.append(ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
            return []
        sched = {"family": "slowloris", "head": "GET / HTTP/1.1\r\n", "slots": [{"lines": []}]}
        with mock.patch.object(l7_gen, "_open_sockets", refused):
            stats = l7_gen.run_slow_schedule("10.0.0.1", 80, sched, 0.1)
        self.assertEqual((stats["failed_opens"], stats["local_errors"]), (1, 0))

    def test_the_attack_functions_take_the_p4_pacing(self):
        calls = []
        with mock.patch.object(l7_gen, "run_slow_schedule", lambda h, p, s, d: calls.append((h, p, s["family"], d))):
            l7_gen.attack_slowloris("10.0.0.1", 80, dict(P.FAMILIES["loris"]["params"]), 210.0, random.Random(1))
            l7_gen.attack_slowpost("10.0.0.1", 80, dict(P.FAMILIES["post"]["params"]), 210.0, random.Random(1))
        self.assertEqual(calls, [("10.0.0.1", 80, "slowloris", 210.0), ("10.0.0.1", 80, "slowpost", 210.0)])


if __name__ == "__main__":
    unittest.main()
