"""The P4 runner (eval/p4_runner.py; docs/P4_SLOW_DESIGN.md §4.3, §8, §10, §13), offline: plans as data, and whole
blocks executed on the fake host of tests/p4_fake_host.py, whose outputs go through eval/p4_validation.py and
eval/p4_outcome.py unchanged. Nothing touches the machine."""
import contextlib
import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_fake_host as F
import p4_outcome as OUT
import p4_runner as R
import p4_traffic as PT
import p4_validation as V

import l7_backend
import slow_pc

CAL = l7_backend.load_record()[0]
KNEE = {"loris": 100, "post": 5}
POINT = (5, 256, 2)


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def index(root):
    with open(os.path.join(root, "index.jsonl"), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.block = R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=POINT)
        self.runs = {r["arm"]: r for r in self.block["runs"]}

    def test_the_eight_arms_in_a_seeded_order(self):
        self.assertEqual(sorted(self.block["order"]), sorted(OUT.ARMS))
        self.assertEqual(self.block["order"], R.plan_block("campaign", 3101, "/x", sources=KNEE,
                                                           thresholds=POINT)["order"])
        orders = {tuple(R.plan_block("campaign", s, "/r", sources=KNEE, thresholds=POINT)["order"])
                  for s in OUT.BLOCK_SEEDS}
        self.assertGreater(len(orders), 1)
        self.assertEqual(self.block["dir"], "/r/campaign/b3101_a1")

    def test_nginx_and_the_daemon_per_arm(self):
        for arm, run in self.runs.items():
            conf = run["nginx"]["conf"]
            d = run["daemon"]
            if arm in ("C", "Cp") or arm.startswith("U_"):
                self.assertEqual((conf, d), ("nginx_profile_r.conf", None), arm)
                continue
            self.assertEqual(conf, "nginx_profile_r_limits.conf", arm)
            env = d["env"]
            self.assertEqual({k: env[k] for k in ("XDP_GRU", "GRU_ONLY", "L7_SHADOW", "MITIGATION_BACKEND",
                                                  "SLOW_PC_KILL_FILE")},
                             {"XDP_GRU": "0", "GRU_ONLY": "0", "L7_SHADOW": "0", "MITIGATION_BACKEND": "xdp",
                              "SLOW_PC_KILL_FILE": "/run/l7v2/kill"})
            self.assertEqual(env["BAN_EVENTS"], f"/r/campaign/b3101_a1/{arm}/ban_events.jsonl")
            self.assertEqual(d["argv"][:3], ["taskset", "-c", "2"])
            self.assertEqual(d["argv"][-1], os.path.join(REPO, "control_plane.py"))
            if arm.startswith("M_def_"):
                self.assertEqual((env["HEURISTIC_PROFILE"], env["SLOW_PC"]), ("default", "0"))
                self.assertNotIn("SLOW_PC_RECORD", env)
            else:
                self.assertEqual({k: env[k] for k in ("HEURISTIC_PROFILE", "SLOW_PC", "SLOW_PC_ENFORCE", "SLOW_PC_T",
                                                      "SLOW_PC_F", "SLOW_PC_K")},
                                 {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "1",
                                  "SLOW_PC_T": "5", "SLOW_PC_F": "256", "SLOW_PC_K": "2"})
                self.assertEqual(env["SLOW_PC_RECORD"], f"/r/campaign/b3101_a1/{arm}/slow_pc.jsonl.gz")
                self.assertTrue(run["enforcing"])

    def test_the_stack_on_cpus_0_1_and_its_provenance(self):
        for run in self.runs.values():
            g = run["gunicorn"]
            self.assertEqual(g["argv"][:3], ["taskset", "-c", "0-1"])
            self.assertEqual(g["argv"][-5:], ["gunicorn", "-c", os.path.join(REPO, "gunicorn_profile_r.py"),
                                              "--chdir", REPO])
            self.assertEqual(g["env"], {"L7_CALIBRATION": R.PLACEHOLDER})
            self.assertEqual(run["nginx"]["start"][:3], ["taskset", "-c", "0-1"])
            files = run["provenance"]["files_sha256"]
            self.assertEqual(files, {n: sha(os.path.join(REPO, n)) for n in ("nginx_profile_r.conf",
                                                                             "nginx_profile_r_limits.conf",
                                                                             "gunicorn_profile_r.py")})
            self.assertEqual(run["provenance"]["calibration"]["sha256"], sha(R.PLACEHOLDER))
            self.assertEqual(run["timeline"], {"baseline_s": 30, "attack_s": 210, "recovery_s": 30})

    def test_the_population_of_each_run(self):
        count = {arm: (sum(e["role"] == "benign" for e in r["entities"]),
                       sum(e["role"] == "attack" for e in r["entities"])) for arm, r in self.runs.items()}
        self.assertEqual(count["C"], (60, 0))
        self.assertEqual(count["Cp"], (60, 0))
        self.assertEqual(count["U_loris"], (60, 100))
        self.assertEqual(count["M_pc_post"], (60, 5))
        loris = self.runs["U_loris"]
        self.assertEqual(loris["roles"], PT.roles(loris["entities"]))
        self.assertEqual(sorted(set(loris["roles"].values()) - {"attack"}),
                         ["api_bulk", "cgnat", "crawler_polite", "search_user", "slow_uploader", "tpcw_browsing",
                          "uploader"])
        for x in loris["launches"]:
            argv = x["argv"]
            self.assertEqual(argv[:3], ["taskset", "-c", "3-7"])
            self.assertEqual(argv[argv.index("--host") + 1], "10.0.0.1")
            e = next(e for e in loris["entities"] if e["entity_id"] == x["entity_id"])
            self.assertEqual(argv[argv.index("--source") + 1], e["address"])
            self.assertEqual(x["start_s"], 30.0 if e["role"] == "attack" else 0.0)
            self.assertEqual(float(argv[argv.index("--duration") + 1]), 210.0 if e["role"] == "attack" else 270.0)
            recorded = e["kind_or_family"] in ("tpcw_browsing", "cgnat_browsers", "search_user", "api_bulk",
                                               "crawler_polite")
            self.assertEqual("--records" in argv, recorded, e["kind_or_family"])
        slow = [n for n in loris["namespaces"] if n["profile"] == PT.NETEM_SLOW]
        self.assertEqual(len(slow), 1)
        self.assertEqual(len(slow[0]["addresses"]), 2)
        self.assertTrue(all(len(n["addresses"]) <= R.MAX_ALIASES for n in loris["namespaces"]))
        self.assertEqual(sum(len(n["addresses"]) for n in loris["namespaces"]), 160)

    def test_validation_and_ladder_runs(self):
        val = R.plan_block("validation", 4001, "/r", sources=KNEE)
        self.assertEqual(sorted(val["order"]), sorted(slow_pc.VALIDATION_RUNS))
        for run in val["runs"]:
            self.assertEqual(run["nginx"]["conf"], "nginx_profile_r.conf")
            env = run["daemon"]["env"]
            self.assertEqual((env["HEURISTIC_PROFILE"], env["SLOW_PC"], env["SLOW_PC_ENFORCE"]), ("tolerant", "1", "0"))
            self.assertIn("SLOW_PC_RECORD", env)
            self.assertFalse(run["enforcing"])
        lad = R.plan_block("ladder", 9102, "/r", sources={"loris": 0, "post": 20}, family="post", label="l20r1")
        self.assertEqual(sorted(lad["order"]), ["C", "U_post"])
        self.assertEqual(lad["dir"], "/r/ladder/b9102_a1_l20r1")
        u = next(r for r in lad["runs"] if r["arm"] == "U_post")
        self.assertEqual(sum(e["role"] == "attack" for e in u["entities"]), 20)
        self.assertTrue(all(r["daemon"] is None for r in lad["runs"]))

    def test_what_judges_data_is_refused_unless_frozen(self):
        bad = [lambda: R.plan_block("campaign", 3101, "/r", sources=KNEE),                     # no thresholds
               lambda: R.plan_block("campaign", 3101, "/r", sources=KNEE, thresholds=(7, 64, 2)),
               lambda: R.plan_block("campaign", 3101, "/r", sources={"loris": 120, "post": 5}, thresholds=POINT),
               lambda: R.plan_block("campaign", 4001, "/r", sources=KNEE, thresholds=POINT),
               lambda: R.plan_block("validation", 4001, "/r", sources=KNEE, thresholds=POINT),
               lambda: R.plan_block("validation", 3101, "/r", sources=KNEE),
               lambda: R.plan_block("ladder", 9101, "/r", sources=KNEE),                       # no family
               lambda: R.plan_block("ladder", 9101, "/r", sources={"loris": 99}, family="loris"),
               lambda: R.plan_block("smoke", 3101, "/r", sources=KNEE),
               lambda: R.plan_block("smoke", 9101, "/r", arms=["M_pc_loris"])]
        for make in bad:
            with self.assertRaises((R.PlanError, PT.PlanError)):
                make()

    def test_plan_prints_and_touches_nothing(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = R.main(["--phase", "campaign", "--seed", "3101", "--loris", "100", "--post", "5",
                         "--thresholds", "5,256,2", "--root", "/nonexistent/p4", "--plan"])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("P4 campaign block 3101 attempt 1", text)
        self.assertIn("run M_pc_loris: nginx nginx_profile_r_limits.conf, daemon pc", text)
        self.assertIn("SLOW_PC_ENFORCE=1", text)
        self.assertFalse(os.path.exists("/nonexistent/p4"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(R.main(["--phase", "campaign", "--seed", "3101", "--plan"]), 2)

    def test_stub_status_is_parsed(self):
        self.assertEqual(R.parse_stub_status(F.STUB.format(a=7, n=11, r=40, w=5)),
                         {"active": 7, "accepts": 11, "handled": 11, "requests": 40, "reading": 0, "writing": 2,
                          "waiting": 5})
        self.assertIsNone(R.parse_stub_status("502 Bad Gateway"))


class ExecuteTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def block(self, phase, seed, **kw):
        kw.setdefault("sources", KNEE)
        return R.plan_block(phase, seed, self.root, **kw)

    def test_validation_runs_feed_p4_validation_unchanged(self):
        manifests = []
        for seed in slow_pc.VALIDATION_SEEDS:
            host = F.FakeHost(poll_every_s=5.0, modelled_attackers=4)
            res = R.run_block(host, self.block("validation", seed))
            self.assertTrue(all(r["ok"] for _a, r in res), res)
            bdir = os.path.join(self.root, "validation", f"b{seed}_a1")
            manifests += [os.path.join(bdir, arm, "slow_pc_manifest.json") for arm in slow_pc.VALIDATION_RUNS]
        with open(manifests[0], encoding="utf-8") as fh:
            m = json.load(fh)
        self.assertEqual((m["record"], m["daemon"]), ("slow_pc.jsonl.gz", {"HEURISTIC_PROFILE": "tolerant",
                                                                           "SLOW_PC": "1", "SLOW_PC_ENFORCE": "0"}))
        out = os.path.join(self.root, "selection.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = V.main([*manifests, "--json", out])
        with open(out, encoding="utf-8") as fh:
            sel = json.load(fh)
        self.assertIn(rc, (0, 2))
        self.assertEqual(len(sel["outcomes"]), len(slow_pc.GRID))
        self.assertEqual(sorted((r["seed"], r["arm"]) for r in sel["runs"]),
                         sorted((s, a) for s in slow_pc.VALIDATION_SEEDS for a in slow_pc.VALIDATION_RUNS))
        point = next(o for o in sel["outcomes"] if (o["T"], o["F"], o["K"]) == POINT)
        self.assertEqual(point["attack_addresses"], 2 * (4 + 4))       # 4 modelled sources per family and seed
        self.assertEqual(point["slow_uploader_closed"], 0)
        self.assertGreater(point["benign_connections"], 0)

    def test_a_campaign_block_feeds_p4_outcome_unchanged(self):
        host = F.FakeHost(modelled_attackers=6)
        res = R.run_block(host, self.block("campaign", 3101, thresholds=POINT))
        self.assertEqual([a for a, _r in res], R.plan_block("campaign", 3101, "/x", sources=KNEE,
                                                            thresholds=POINT)["order"])
        self.assertTrue(all(r["ok"] for _a, r in res), [(a, r["reasons"]) for a, r in res if not r["ok"]])
        runs_path = os.path.join(self.root, "runs.jsonl")
        R.summarize_root(self.root, CAL, runs_path)
        with open(runs_path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        by = {r["arm"]: r for r in records}
        self.assertEqual(sorted(by), sorted(OUT.ARMS))
        self.assertTrue(all(len(r["q_per_s"]) == 270 and r["level_window"] == [120.0, 240.0] for r in records))
        self.assertGreater(by["C"]["Q"], by["U_loris"]["Q"])
        self.assertEqual(set(by["M_pc_loris"]["banned"].values()), {"attack"})
        self.assertEqual(by["M_def_loris"]["banned"], {})
        self.assertGreater(by["M_pc_loris"]["q_level"], by["U_loris"]["q_level"])
        out = os.path.join(self.root, "verdict.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(OUT.main([runs_path, "--json", out]), 0)
        with open(out, encoding="utf-8") as fh:
            verdict = json.load(fh)
        self.assertEqual(verdict["M7"], "invalid (1 of 10 valid)")    # one block of the ten (D-035, V-02)
        self.assertEqual(verdict["families"]["loris"]["harm"]["valid_blocks"], 1)
        self.assertEqual(verdict["bans_by_arm"]["M_pc_loris"], {"attack": 6})
        idx = index(self.root)
        self.assertEqual([(x["arm"], x["valid"]) for x in idx], [(a, True) for a, _r in res])

    def test_what_a_run_writes(self):
        host = F.FakeHost(modelled_attackers=2)
        R.run_block(host, self.block("campaign", 3102, thresholds=POINT, arms=None))
        run = os.path.join(self.root, "campaign", "b3102_a1", "M_pc_post")
        for name in ("plan.json", "run.json", "manifest.json", "slow_pc_manifest.json", "slow_pc.jsonl.gz",
                     "ban_events.jsonl", "daemon.log", "gunicorn.log", "stub_status.jsonl"):
            self.assertTrue(os.path.isfile(os.path.join(run, name)), name)
        with open(os.path.join(run, "run.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual((meta["role"], meta["class"], meta["thresholds"]), ("mitigated", "post", list(POINT)))
        with open(os.path.join(run, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        self.assertGreater(man["timeline"]["t0_wall"], F.BASE_EPOCH)
        self.assertEqual(set(man["ip_map"]), set(man["roles"]))
        with gzip.open(os.path.join(run, "slow_pc.jsonl.gz"), "rt", encoding="utf-8") as fh:
            first = json.loads(fh.readline())
        self.assertTrue(first["enforce"])
        with open(os.path.join(run, "stub_status.jsonl"), encoding="utf-8") as fh:
            stub = [json.loads(line) for line in fh]
        self.assertGreaterEqual(len(stub), 270)
        self.assertIn("waiting", stub[0])
        self.assertTrue(host.ran("ip", "netns", "del", "server_ns"))
        moved = [c[1] for c in host.ran("mv", "-f")]
        self.assertIn(("mv", "-f", "/var/log/nginx/l7_capture.log", os.path.join(run, "access.log")), moved)
        slow_ns = [c for c in host.commands if c[1][:2] == ("tc", "qdisc")]
        self.assertTrue(slow_ns and all(c[1] == PT.NETEM_SLOW_ARGV for c in slow_ns))

    def test_every_attempt_is_indexed_with_its_reasons(self):
        host = F.FakeHost(kill_file=True, modelled_attackers=1)
        res = dict(R.run_block(host, self.block("campaign", 3103, thresholds=POINT)))
        for arm in OUT.ARMS:
            self.assertEqual(res[arm]["ok"], not arm.startswith("M_pc_"), arm)
        self.assertIn("the kill file /run/l7v2/kill exists", res["M_pc_loris"]["reasons"][0])
        idx = index(self.root)
        self.assertEqual(len(idx), 8)
        self.assertEqual({x["arm"] for x in idx if not x["valid"]}, {"M_pc_loris", "M_pc_post"})
        with self.assertRaises(R.PlanError):
            R.run_block(F.FakeHost(), self.block("campaign", 3103, thresholds=POINT))
        R.run_block(F.FakeHost(modelled_attackers=1), self.block("campaign", 3103, thresholds=POINT, attempt=2))
        self.assertEqual(len(index(self.root)), 16)
        self.assertEqual({x["attempt"] for x in index(self.root)}, {1, 2})

    def one_run(self, name, phase="validation", seed=4002, arm="C", **kw):
        kw.setdefault("sources", KNEE)
        block = R.plan_block(phase, seed, os.path.join(self.root, name), **kw)
        return next(r for r in block["runs"] if r["arm"] == arm)

    def test_failures_make_a_run_invalid_and_the_testbed_is_taken_down(self):
        cases = {
            "daemon dies": (F.FakeHost(daemon_dies_at=100.0, modelled_attackers=1), "the daemon exited"),
            "stack": (F.FakeHost(stack_ready=False), "did not answer"),
            "leftovers": (F.FakeHost(netns=["server_ns"]), "leftover namespaces"),
            "not root": (F.FakeHost(root=False), "not root"),
            "topology": (F.FakeHost(fail_prim="client_ns"), "the runner failed: OSError"),
        }
        for name, (host, why) in cases.items():
            res = R.execute_run(host, self.one_run(name.replace(" ", "_")))
            self.assertFalse(res["ok"], name)
            self.assertTrue(any(why in r for r in res["reasons"]), (name, res["reasons"]))
            if name in ("leftovers", "not root"):
                self.assertFalse(host.ran("ip", "netns", "del"), name)
            else:
                self.assertTrue(host.ran("ip", "netns", "del", "server_ns"), name)
        res = R.execute_run(F.FakeHost(kill_appears_at=100.0, modelled_attackers=1),
                            self.one_run("kill_mid", "campaign", 3104, "M_pc_loris", thresholds=POINT))
        self.assertTrue(any("the kill file appeared at 100 s" in r for r in res["reasons"]), res["reasons"])
        run = self.one_run("gen_fails")
        bad = next(e["address"] for e in run["entities"] if e["kind_or_family"] == "uploader")
        res = R.execute_run(F.FakeHost(gen_fails=[bad], modelled_attackers=1), run)
        self.assertTrue(any("exited with code 3" in r for r in res["reasons"]), res["reasons"])

    def test_the_rule_must_poll_at_least_every_10_s(self):
        """D-035 (V-08): an M_pc (or validation) run whose rule logged no poll for more than 10 s is invalid."""
        self.assertEqual(R.SLOW_PC_POLL_GAP_S, 10.0)
        for every, ok in ((5.0, True), (9.5, True), (10.5, False), (15.0, False)):
            run = self.one_run(f"poll_{every}", "campaign", 3105, "M_pc_post", thresholds=POINT)
            res = R.execute_run(F.FakeHost(poll_every_s=every, modelled_attackers=1), run)
            silent = [r for r in res["reasons"] if "logged no poll" in r]
            self.assertEqual(not silent, ok, (every, res["reasons"]))
        res = R.execute_run(F.FakeHost(daemon_dies_at=150.0, modelled_attackers=1),
                            self.one_run("dies", "validation", 4001, "C"))
        self.assertTrue(any("logged no poll" in r for r in res["reasons"]), res["reasons"])
        res = R.execute_run(F.FakeHost(poll_every_s=30.0), self.one_run("no_rule", "campaign", 3105, "M_def_post",
                                                                        thresholds=POINT))
        self.assertFalse(any("logged no poll" in r for r in res["reasons"]), "M_def runs no rule")


if __name__ == "__main__":
    unittest.main()
