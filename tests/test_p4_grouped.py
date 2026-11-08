"""D-075 (2026-11-07T08:33Z; memory, R-023): P4's Slowloris sources run grouped, one generator process per client namespace and a thread per
source, each source's seeded schedule, address and statistics unchanged; every other generator, P1's included, runs as before (T-074).
Offline: the generator runs against fake sockets, or against addresses this machine does not have; the runner on the fake host."""
import contextlib
import io
import json
import os
import random
import sys
import tempfile
import threading
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7_gen
import p4_fake_host as F
import p4_runner as R
import p4_traffic as P
from l7_gen_timer import inert

ADDRS = ("10.0.16.5", "10.0.16.9", "10.0.17.2")


def source(i, addr, conns=2):
    return {"entity_id": f"p4:9101:{60 + i}", "source": addr, "port": 80, "seed": 1000 + i,
            "params": dict(P.FAMILIES["loris"]["params"], conns=conns, port=80)}


LOG, LOCK = [], threading.Lock()


class RecordingSocket:
    """A socket that records, per process, what its owner bound, connected and sent (in LOG); every connect succeeds."""

    def __init__(self, *_a):
        self.entry = {"thread": threading.current_thread().name, "bound": None, "to": None, "sent": []}
        with LOCK:
            LOG.append(self.entry)

    def settimeout(self, _t):
        pass

    def bind(self, addr):
        self.entry["bound"] = addr

    def connect(self, addr):
        self.entry["to"] = addr

    def sendall(self, data):
        self.entry["sent"].append(data)

    def close(self):
        pass


def recorded(argv):
    LOG.clear()
    with mock.patch.object(l7_gen.socket, "socket", RecordingSocket), mock.patch.object(l7_gen, "SOURCE", None), \
            mock.patch.object(l7_gen, "LIVE_STATS", None), inert():
        rc = l7_gen.main(argv)
    return rc, [{k: v for k, v in e.items() if k != "thread"} for e in LOG], list(LOG)


class GeneratorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sources = [dict(source(i, a), stats=os.path.join(self.tmp.name, f"s{i}.json")) for i, a in enumerate(ADDRS)]

    def alone(self, s, stats=None):
        return ["--role", "attack", "--family", "slowloris", "--host", "10.0.0.1", "--port", str(s["port"]), "--duration", "0.3",
                "--seed", str(s["seed"]), "--params", json.dumps(s["params"]), "--source", s["source"]] + (["--stats", stats] if stats else [])

    def group(self, sources=None, duration="0.3"):
        return ["--role", "attack", "--family", "slowloris", "--host", "10.0.0.1", "--duration", duration,
                "--group", json.dumps({"sources": self.sources if sources is None else sources})]

    def test_each_source_plans_the_schedule_of_a_generator_of_its_own(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(l7_gen.main([*self.group(duration="210"), "--plan"]), 0)
        planned = json.loads(out.getvalue())["group"]
        for s, p in zip(self.sources, planned, strict=True):
            argv = self.alone(s)
            argv[argv.index("--duration") + 1] = "210"
            with contextlib.redirect_stdout(io.StringIO()) as one:
                l7_gen.main([*argv, "--plan"])
            self.assertEqual(p["schedule"], json.loads(one.getvalue())["schedule"])
            self.assertEqual(p["schedule"], l7_gen.slow_schedule("slowloris", "10.0.0.1", s["params"], 210.0, random.Random(s["seed"])))

    def test_each_source_sends_from_its_own_address_what_its_own_generator_sends(self):
        rc, group, raw = recorded(self.group())
        self.assertEqual(rc, 0)
        self.assertEqual({e["thread"] for e in raw}, {s["entity_id"] for s in self.sources}, "a thread per source")
        for s in self.sources:
            mine = [e for e in group if e["bound"] == (s["source"], 0)]
            rc1, alone, _raw = recorded(self.alone(s, stats=os.path.join(self.tmp.name, "alone.json")))
            self.assertEqual(rc1, 0)
            self.assertEqual(mine, alone)
            self.assertEqual(len(mine), 2)
            with open(s["stats"], encoding="utf-8") as fh, open(os.path.join(self.tmp.name, "alone.json"), encoding="utf-8") as fh1:
                self.assertEqual(json.load(fh), json.load(fh1))

    def test_a_group_of_addresses_this_machine_lacks_states_it_per_source(self):
        # As tests/test_p4_families.py's generator of its own: every open fails for a local reason, and each source's file says so.
        with mock.patch.object(l7_gen, "SOURCE", None), inert():
            self.assertEqual(l7_gen.main(self.group(duration="0.2")), 0)
        for s in self.sources:
            with open(s["stats"], encoding="utf-8") as fh:
                stats = json.load(fh)
            self.assertEqual((stats["opened"], stats["failed_opens"], stats["local_errors"]), (0, 2, 2), s["source"])

    def test_a_source_that_raised_writes_no_stats_and_the_group_exits_1(self):
        real = l7_gen.ATTACK["slowloris"]

        def flaky(host, port, params, dur, rng):
            if l7_gen._source() == ADDRS[1]:
                raise OSError("boom")
            return real(host, port, params, dur, rng)
        with mock.patch.dict(l7_gen.ATTACK, {"slowloris": flaky}), contextlib.redirect_stderr(io.StringIO()) as err:
            rc, _group, _raw = recorded(self.group())
        self.assertEqual(rc, 1)
        self.assertIn(f"{self.sources[1]['entity_id']} ({ADDRS[1]})", err.getvalue())
        self.assertEqual([os.path.exists(s["stats"]) for s in self.sources], [True, False, True])

    def test_what_a_group_refuses(self):
        bad = [[*self.group(), "--source", "10.0.16.1"], [*self.group(), "--stats", "x.json"],
               ["--role", "attack", "--family", "slowpost", "--host", "10.0.0.1", "--duration", "1", "--group",
                json.dumps({"sources": self.sources})],
               self.group([dict(self.sources[0], params={"conns": 2, "header_every_s": 3})]),
               self.group([dict(self.sources[0], source="192.168.1.5")]),
               self.group([self.sources[0], dict(self.sources[1], source=ADDRS[0])]),
               self.group([]),
               ["--role", "attack", "--family", "slowloris", "--host", "8.8.8.8", "--duration", "1", "--group",
                json.dumps({"sources": self.sources})]]
        for argv in bad:
            with self.assertRaises(SystemExit, msg=argv[-1][:80]), contextlib.redirect_stdout(io.StringIO()), inert():
                l7_gen.main(argv)

    def test_a_generator_of_its_own_sends_what_it_sent(self):
        """A pin of P1's and post's path that holds on the parent too: each slot bound to --source, its head sent, its stats written."""
        s = self.sources[0]
        path = os.path.join(self.tmp.name, "alone.json")
        rc, alone, raw = recorded(self.alone(s, stats=path))
        head = l7_gen.slow_schedule("slowloris", "10.0.0.1", s["params"], 0.3, random.Random(s["seed"]))["head"].encode()
        self.assertEqual(rc, 0)
        self.assertEqual(alone, [{"bound": (s["source"], 0), "to": ("10.0.0.1", 80), "sent": [head]}] * 2)
        self.assertEqual({e["thread"] for e in raw}, {threading.main_thread().name})
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), {"opened": 2, "reopened": 0, "sent_bytes": 0, "failed_opens": 0, "local_errors": 0})

    def test_a_generator_of_its_own_keeps_its_globals(self):
        """P1's path (ml/l7_gen.py without --group): its address is SOURCE and its live stats LIVE_STATS, and no thread-local is set."""
        s = self.sources[0]
        seen = {}
        real = l7_gen.run_slow_schedule

        def spy(*a):
            out = real(*a)
            seen.update(source=l7_gen._source(), live=l7_gen.LIVE_STATS is out, local=vars(l7_gen._LOCAL).copy())
            return out
        with mock.patch.object(l7_gen, "run_slow_schedule", spy), mock.patch.object(l7_gen.socket, "socket", RecordingSocket), \
                mock.patch.object(l7_gen, "SOURCE", None), mock.patch.object(l7_gen, "LIVE_STATS", None), inert():
            self.assertEqual(l7_gen.main(self.alone(s)), 0)
        self.assertEqual(seen, {"source": s["source"], "live": True, "local": {}})


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def run_of(self, arm="U_loris", loris=100, post=0, phase="campaign", seed=3101):
        kw = {"thresholds": (5, 256, 2)} if phase == "campaign" else {}
        families = ("loris", "post") if post else ("loris",)
        block = R.plan_block(phase, seed, self.root, sources={"loris": loris, "post": post}, families=families, **kw)
        return next(r for r in block["runs"] if r["arm"] == arm)

    def test_the_sources_of_a_namespace_are_one_generator(self):
        self.assertEqual(R.GROUPED_FAMILIES, l7_gen.GROUP_FAMILIES)
        run = self.run_of()
        attack = [x for x in run["launches"] if x["role"] == "attack"]
        loris = {e["entity_id"]: e for e in run["entities"] if e["role"] == "attack"}
        self.assertEqual(len(loris), 100)
        self.assertEqual(sorted(i for x in attack for i in x["entities"]), sorted(loris))
        for x in attack:
            argv = x["argv"]
            group = json.loads(argv[argv.index("--group") + 1])["sources"]
            self.assertLessEqual(len(group), R.MAX_ALIASES)
            self.assertEqual(x["entity_id"], f"group:{x['ns']}")
            self.assertNotIn("--source", argv)
            self.assertEqual(argv[argv.index("--family") + 1], "slowloris")
            self.assertEqual(float(argv[argv.index("--duration") + 1]), 210.0)
            for g in group:
                e = loris[g["entity_id"]]
                self.assertEqual((g["source"], g["port"], g["seed"], g["params"], g["stats"], e["namespace"]),
                                 (e["address"], e["port"], e["client_seed"], e["params"], R.stats_path(run["out"], e), x["ns"]))
        self.assertEqual(len(attack), len({e["namespace"] for e in loris.values()}))
        benign = [x for x in run["launches"] if x["role"] == "benign"]
        self.assertEqual(len(benign), 60)
        for x in benign:
            e = next(e for e in run["entities"] if e["entity_id"] == x["entity_id"])
            self.assertEqual(x["argv"], R.gen_argv(e, run["out"], R.PYTHON, cpus=x["argv"][2]), "one per entity, as before")
        starts = [x["start_s"] for x in run["launches"]]
        self.assertEqual(starts, sorted(starts))

    def test_slow_post_and_the_controls_are_not_grouped(self):
        post = self.run_of("U_post", post=10)
        self.assertEqual(sum(1 for x in post["launches"] if x["role"] == "attack"), 10)
        self.assertTrue(all("--source" in x["argv"] and "--group" not in x["argv"] for x in post["launches"]))
        self.assertTrue(all("--group" not in x["argv"] for x in self.run_of("C")["launches"]))

    def test_a_grouped_run_is_valid_and_its_sources_are_counted(self):
        run = self.run_of()
        self.assertEqual(R.execute_run(F.FakeHost(modelled_attackers=3), run)["reasons"], [])
        with open(os.path.join(run["out"], "run.json"), encoding="utf-8") as fh:
            attack = json.load(fh)["attack"]
        groups = sum(1 for x in run["launches"] if x["role"] == "attack")
        self.assertEqual((attack["planned"], attack["generators"], attack["processes"], attack["opened"], attack["no_stats"]),
                         (600, 100, groups, 600, 0))
        self.assertEqual(len(os.listdir(os.path.join(run["out"], "attack_stats"))), 100)

    def test_a_source_that_fails_names_its_group(self):
        run = self.run_of()
        bad = next(e for e in run["entities"] if e["role"] == "attack")
        res = R.execute_run(F.FakeHost(modelled_attackers=1, gen_fails={bad["address"]}), run)
        self.assertTrue(any(r.startswith(f"group:{bad['namespace']} exited with code 3") for r in res["reasons"]), res["reasons"])
        self.assertTrue(any("1 of 100 attack generators left no stats" in r for r in res["reasons"]), res["reasons"])

    def test_p1s_helpers_are_unchanged(self):
        """P1 calls gen_argv and namespaces (eval/p1_runner.py): one generator per entity, from its own address."""
        run = self.run_of("U_post", post=5)
        e = next(e for e in run["entities"] if e["role"] == "attack")
        self.assertEqual(R.gen_argv(e, "/o", "/py", cpus="3-5"),
                         ["taskset", "-c", "3-5", "/py", R.GEN, "--role", "attack", "--host", R.SERVER_IP, "--port", str(e["port"]),
                          "--duration", "210.0", "--seed", str(e["client_seed"]), "--params", json.dumps(e["params"], sort_keys=True),
                          "--source", e["address"], "--family", "slowpost", "--stats", R.stats_path("/o", e)])
        self.assertEqual([len(n["addresses"]) for n in R.namespaces([dict(x) for x in run["entities"]])],
                         [len(n["addresses"]) for n in run["namespaces"]])


if __name__ == "__main__":
    unittest.main()
