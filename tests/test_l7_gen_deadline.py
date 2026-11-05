"""A generator's deadline (ml/l7_gen.py; ml/p1_prereg_3.json generator; review T-050 T050-03, -04, -16), on the real generator, every kind, as
real processes, on a sink on loopback: one that answers, one that accepts and never answers, and one whose accept queue is full, where a SYN is dropped as
an XDP ban drops it. The scope lock is widened in the child's process only; nothing leaves the sandbox. Offline: no VM, no nginx."""
import csv
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "eval"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7_bots
import l7_gen as L
import l7_pools as LP
import p1_traffic as PT
import p4_runner as P4
import p4_traffic

DURATION = 2.0
# The child runs main() with the scope lock on loopback and the slow kinds' fixed port 80 on the sink's; it prints when main begins, so that a
# loaded machine's interpreter start is not counted against the generator.
DRIVER = """
import ipaddress, os, sys, time
sys.path.insert(0, os.path.join(os.getcwd(), "ml"))
import l7_gen
sink = int(sys.argv[1])
l7_gen.TESTBED_NET = ipaddress.ip_network("127.0.0.0/8")
real = l7_gen._open_sockets
l7_gen._open_sockets = lambda host, port, *a, **k: real(host, sink, *a, **k)
print(time.time(), flush=True)
sys.exit(l7_gen.main(sys.argv[2:]))
"""


def table():
    """{name: (role, params)} for every kind and family of the generator but the SYN flood, which needs hping3 (its own test below)."""
    specs = {}
    for pop in LP.POPULATIONS.values():
        for s in pop["benign"]:
            specs.setdefault(("benign", s["kind"]), dict(s.get("params", {})))
        for s in pop["attack"]:
            specs.setdefault(("attack", s["family"]), dict(s.get("params", {})))
    for s in p4_traffic.BENIGN:
        specs.setdefault(("benign", s["kind"]), dict(s.get("params", {})))
    block = PT.build_block(9001, "pilot", {"C2": 1.0, "C3a": 1.0, "C3b": 2}, gate_seeds=(0,), benign_specs=[s for s in LP.POPULATIONS["l7v2"]["benign"] if not s.get("gate")])
    for rows in block["attack"].values():
        for e in rows:
            specs[("attack", e["kind_or_family"])] = dict(e["params"])
    specs[("benign", "downloader")] = {"think_s": [20.0, 22.0], "path": "/download/large"}    # T050-03: a last think time far past the end
    specs[("benign", "slow_uploader")] = {"rate_Bps": 2000, "think_s": [1.0, 2.0], "body_bytes": [100000, 100000], "path": "/upload"}
    out = {}
    for (role, name), params in specs.items():
        if name == "volumetric_flood":
            continue
        if "first_visit_s" in params:
            params["first_visit_s"] = [0.0, 0.0]
        out[f"{role}:{name}"] = (role, name, params)
    loris, post = p4_traffic.FAMILIES["loris"], p4_traffic.FAMILIES["post"]
    out["attack:slowloris_paced"] = ("attack", loris["family"], dict(loris["params"]))
    out["attack:slowpost_paced"] = ("attack", post["family"], dict(post["params"]))
    missing = (set(L.BENIGN) | set(L.ATTACK)) - {name for _r, name, _p in out.values()} - {"volumetric_flood"}
    for name in sorted(missing):
        role = "benign" if name in L.BENIGN else "attack"
        out[f"{role}:{name}"] = (role, name, {"rps": 2.0} if role == "attack" else {})
    return out


class AnsweringSink:
    """Answers every request at once, with an empty 200."""

    def __enter__(self):
        self.srv = socket.create_server(("127.0.0.1", 0), backlog=512)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def _accept(self):
        while True:
            try:
                conn = self.srv.accept()[0]
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn):
        with conn:
            try:
                while conn.recv(65536):
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass

    def __exit__(self, *a):
        self.srv.close()


class SilentSink:
    """Accepts, and never answers: what a request on a dropped path looks like after its connection."""

    def __enter__(self):
        self.srv = socket.create_server(("127.0.0.1", 0), backlog=512)
        self.port = self.srv.getsockname()[1]
        self.held = []
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def _accept(self):
        while True:
            try:
                self.held.append(self.srv.accept()[0])
            except OSError:
                return

    def __exit__(self, *a):
        self.srv.close()
        for c in self.held:
            c.close()


class DroppingSink:
    """A full accept queue: no new connection is taken, and a SYN is dropped, as an XDP ban drops it."""

    def __enter__(self):
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(0)
        self.port = self.srv.getsockname()[1]
        self.fill = []
        for _ in range(4):
            c = socket.socket()
            c.setblocking(False)
            c.connect_ex(("127.0.0.1", self.port))
            self.fill.append(c)
        time.sleep(0.05)
        return self

    def __exit__(self, *a):
        for c in self.fill:
            c.close()
        self.srv.close()


def run_all(sink, out, only=None):
    """Every kind at once on `sink`, or those named: {name: {"after_end": seconds past its end at which it exited, "code", "records"}}."""
    procs = {}
    for name, (role, kind, params) in table().items():
        if only is not None and name not in only:
            continue
        stem = name.replace(":", "_").replace("@", "_")
        argv = [sys.executable, "-c", DRIVER, str(sink.port), "--role", role, "--kind" if role == "benign" else "--family", kind,
                "--host", "127.0.0.1", "--port", str(sink.port), "--duration", str(DURATION), "--seed", "7", "--source", "127.0.0.1",
                "--params", json.dumps(params)]
        records = None
        if role == "benign" and kind in L.l7_benign.KINDS + L.l7_benign.L7V2_KINDS:
            records = os.path.join(out, stem + ".csv")
            argv += ["--records", records]
        if role == "attack":
            argv += ["--stats", os.path.join(out, stem + ".json")]
        procs[name] = (subprocess.Popen(argv, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True), records)
    got, lock = {}, threading.Lock()

    def wait(name, proc, records):
        begun = float(proc.stdout.readline())
        proc.wait(timeout=120)
        ended = time.time()
        with lock:
            got[name] = {"after_end": ended - begun - DURATION, "code": proc.returncode, "records": records, "stderr": proc.stderr.read()[-300:]}

    threads = [threading.Thread(target=wait, args=(n, p, r)) for n, (p, r) in procs.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return got


class DeadlineTest(unittest.TestCase):
    def check(self, sink_type, bound):
        with tempfile.TemporaryDirectory() as out, sink_type() as sink:
            got = run_all(sink, out)
            self.assertGreater(len(got), 30)
            late = [n for n, r in got.items() if r["after_end"] > bound]
            if late:           # a stalled machine is not a generator's overshoot: one of 97 s was seen, on one vCPU's share of the kinds. Alone, a defect stays late.
                print(f"late, run again alone: { {n: round(got[n]['after_end'], 1) for n in late} }", file=sys.stderr)
                got.update(run_all(sink, out, late))
            for name, row in sorted(got.items()):
                with self.subTest(name):
                    self.assertEqual(row["code"], 0, row["stderr"])
                    self.assertLessEqual(row["after_end"], bound, name)
            self.rows = {n: self.read_rows(r["records"]) for n, r in got.items() if r["records"]}

    @staticmethod
    def read_rows(path):
        with open(path, encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))

    def test_on_an_answering_sink_every_kind_ends_at_its_end(self):
        """A healthy run: every think time and pause is cut (T050-03, the downloader above all), and a recording kind has its rows."""
        self.check(AnsweringSink, 3.0)
        self.assertTrue(any(self.rows.values()))
        for rows in self.rows.values():
            for r in rows:
                self.assertEqual(r["err"], "", r)

    def test_on_a_silent_sink_every_kind_ends_within_the_drain(self):
        """T050-04: every request hangs after its connection. A device abandons its view, and its hung requests have their rows."""
        self.check(SilentSink, L.DRAIN_S + 3.0)
        errs = [r["err"] for rows in self.rows.values() for r in rows]
        self.assertTrue(errs and set(errs) <= {"timeout", "conn", "error"}, set(errs))

    def test_on_a_dropping_sink_every_kind_ends_within_the_drain(self):
        """T050-04: a SYN dropped, as an XDP ban drops it."""
        self.check(DroppingSink, L.DRAIN_S + 3.0)


class HardExitTest(unittest.TestCase):
    """What no kind's own care can bound: the process exits at its end + HARD_EXIT_S, code 0, with what it wrote."""

    def test_a_stuck_kind_is_ended(self):
        driver = ("import ipaddress, os, sys, time\nsys.path.insert(0, os.path.join(os.getcwd(), 'ml'))\nimport l7_gen\n"
                  "l7_gen.TESTBED_NET = ipaddress.ip_network('127.0.0.0/8')\n"
                  "def stuck(host, port, params, dur, rng):\n"
                  "    l7_gen.LIVE_STATS = {'opened': 5}\n"
                  "    time.sleep(10000)\n"
                  "l7_gen.ATTACK['slowread'] = stuck\n"
                  "print(time.time(), flush=True)\nsys.exit(l7_gen.main(sys.argv[1:]))\n")
        with tempfile.TemporaryDirectory() as out:
            stats = os.path.join(out, "s.json")
            for _attempt in range(2):          # a stalled machine gets one more try, as above
                proc = subprocess.Popen([sys.executable, "-c", driver, "--role", "attack", "--family", "slowread", "--host", "127.0.0.1",
                                         "--duration", "0.2", "--stats", stats, "--params", "{}"], cwd=REPO, stdout=subprocess.PIPE, text=True)
                begun = float(proc.stdout.readline())
                self.assertEqual(proc.wait(timeout=120), 0)
                after = time.time() - begun - 0.2
                proc.stdout.close()
                if after <= L.HARD_EXIT_S + 2.0:
                    break
            self.assertGreaterEqual(after, L.HARD_EXIT_S - 0.5)
            self.assertLessEqual(after, L.HARD_EXIT_S + 2.0)
            with open(stats, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), {"opened": 5})


class ConstantsTest(unittest.TestCase):
    def test_the_bound_is_the_record_s_and_inside_the_run_s_grace(self):
        g = PT.prereg_3()["generator"]
        self.assertEqual((L.DRAIN_S, L.HARD_EXIT_S), (g["drain_s"], g["hard_exit_s"]))
        self.assertLess(L.DRAIN_S, L.HARD_EXIT_S)
        self.assertLess(L.HARD_EXIT_S, P4.STOP_GRACE_S)

    def test_every_bot_family_is_in_the_table(self):
        self.assertTrue({f"attack:{f}" for f in l7_bots.FAMILIES} <= set(table()))


class UnitTest(unittest.TestCase):
    def test_a_cut_think_time_keeps_its_draw(self):
        class Rng:
            drawn = 0

            def uniform(self, lo, hi):
                self.drawn += 1
                return hi

        rng = Rng()
        slept = []
        with mock.patch.object(L.time, "sleep", slept.append), mock.patch.object(L.time, "time", lambda: 100.0):
            L._cut(rng.uniform(1.0, 22.0), 103.0)
            L._cut(rng.uniform(1.0, 2.0), 90.0)
        self.assertEqual((slept, rng.drawn), ([3.0, 0.0], 2))

    def test_a_request_s_timeout(self):
        with mock.patch.object(L.time, "time", lambda: 100.0):
            self.assertEqual(L._timeout(10.0, 200.0), 10.0)
            self.assertEqual(L._timeout(10.0, 98.0), 3.0)
            self.assertEqual(L._timeout(10.0, 50.0), 0.05)

    def test_the_syn_flood_ends_at_the_generator_s_end(self):
        slept = []
        fake = mock.Mock()
        with mock.patch.object(L.subprocess, "Popen", return_value=fake), mock.patch.object(L.time, "sleep", slept.append):
            L.attack_volumetric_flood("10.0.0.1", 80, {"dur_s": 60.0}, 2.0, None)
        self.assertEqual(slept, [2.0])
        fake.terminate.assert_called_once()

    def test_a_late_slow_schedule_stops_at_the_end(self):
        """A server that does not answer costs an open 4 s: events already due must not run on past the end."""
        now = [1000.0]

        def opens(_h, _p, _n, _head, errors=None):
            now[0] += 4.0
            errors.append(OSError())
            return []

        sched = {"family": "slowloris", "head": "GET / HTTP/1.1\r\n", "slots": [{"lines": [(0.1 * k, "x") for k in range(100)]} for _ in range(3)]}
        with mock.patch.object(L, "_open_sockets", opens), mock.patch.object(L.time, "time", lambda: now[0]), \
                mock.patch.object(L.time, "sleep", lambda s: None):
            L.run_slow_schedule("10.0.0.1", 80, sched, 5.0)
        self.assertLessEqual(now[0] - 1000.0, 5.0 + 4.0)


if __name__ == "__main__":
    unittest.main()
