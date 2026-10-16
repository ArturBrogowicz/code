"""Unit tests for ml/eval_l7.py analysis (Phase P5). Offline: synthetic events, no VM."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import eval_l7

import l7_dataset


def manifest_with(benign, attackers, schedule, duration=400.0):
    ip_map = l7_dataset.build_ip_map(benign, attackers)
    return l7_dataset.make_manifest(seed=1, duration_s=duration, ip_map=ip_map,
                                    schedule=schedule, provenance={"t0_wall": 0})


class AnalyseTest(unittest.TestCase):
    def setUp(self):
        self.benign = [{"ip": "10.0.1.1", "profile": "perfect", "kind": "keepalive"},
                       {"ip": "10.0.1.2", "profile": "mobile_bad", "kind": "curl_oneshot"}]
        self.attackers = [
            {"ip": "10.0.2.1", "family": "subthreshold_flood", "held_out": False, "params": {}},
            {"ip": "10.0.2.2", "family": "credstuff", "held_out": True, "params": {}},
            {"ip": "10.0.2.3", "family": "slowloris", "held_out": False, "params": {}}]
        self.schedule = [{"ip": "10.0.2.1", "family": "subthreshold_flood", "held_out": False,
                          "mechanism": "rate", "start_s": 10.0, "stop_s": 70.0, "params": {}},
                         {"ip": "10.0.2.2", "family": "credstuff", "held_out": True,
                          "mechanism": "rate", "start_s": 20.0, "stop_s": 80.0, "params": {}},
                         {"ip": "10.0.2.3", "family": "slowloris", "held_out": False,
                          "mechanism": "conns", "start_s": 5.0, "stop_s": 60.0, "params": {}}]
        self.m = manifest_with(self.benign, self.attackers, self.schedule)
        self.t0 = 1000.0

    def test_marginal_value_pattern(self):
        # The point of P5: the sub-threshold flood is NOT banned by a deterministic engine
        # but the L7 GRU would-bans it; slowloris is the SlowConn path's, not the GRU's.
        events = [
            # subthreshold_flood: GRU would-bans at +12s, no deterministic ban
            {"kind": "l7_would_ban", "ip": "10.0.2.1", "t_poll": self.t0 + 22.0},
            # credstuff (held-out): GRU would-bans at +15s
            {"kind": "l7_would_ban", "ip": "10.0.2.2", "t_poll": self.t0 + 35.0},
            # slowloris: deterministic SlowConn bans it; GRU does not
            {"kind": "ban", "ip": "10.0.2.3", "engine": "l4_slowconn", "t_wall": self.t0 + 9.0},
            {"kind": "l7_gru_poll", "windows": 40, "over": 30, "would_bans": 2, "gated_age": 3,
             "suppressed_polls": 4},
            {"kind": "suppress_on", "t_wall": self.t0 + 100},
        ]
        a = eval_l7.analyse(events, self.m, self.t0)
        fam = a["by_family"]
        self.assertEqual(fam["subthreshold_flood"]["det_banned"], 0)
        self.assertEqual(fam["subthreshold_flood"]["would_banned"], 1)
        self.assertEqual(fam["subthreshold_flood"]["median_ttd_would_s"], 12.0)   # 22 - 10
        self.assertEqual(fam["credstuff"]["would_banned"], 1)
        self.assertEqual(fam["credstuff"]["median_ttd_would_s"], 15.0)            # 35 - 20
        self.assertEqual(fam["slowloris"]["det_banned"], 1)
        self.assertEqual(fam["slowloris"]["det_engines"], ["l4_slowconn"])
        self.assertEqual(fam["slowloris"]["would_banned"], 0)                      # GRU misses it (R1)
        self.assertEqual(a["gru_totals"]["windows"], 40)
        self.assertEqual(a["suppress_on_events"], 1)
        # P5b: the per-IP sets the verdict compares (§7.2)
        self.assertEqual(a["would_ban_ips"], ["10.0.2.1", "10.0.2.2"])
        self.assertEqual(a["det_banned_ips"], {"10.0.2.3": "l4_slowconn"})

    def test_benign_would_ban_is_fp(self):
        events = [{"kind": "l7_would_ban", "ip": "10.0.1.1", "t_poll": self.t0 + 50.0},
                  {"kind": "l7_would_ban", "ip": "10.0.1.1", "t_poll": self.t0 + 55.0}]
        a = eval_l7.analyse(events, self.m, self.t0)
        self.assertEqual(a["benign_would_ban_count"], 2)
        self.assertEqual(a["benign_would_ban_ips"], {"10.0.1.1": 2})
        self.assertEqual(a["benign_ips_total"], 2)

    def test_threshold_sweep_separates_flood_from_benign(self):
        d = tempfile.mkdtemp(prefix="l7rec_")
        self.addCleanup(__import__("shutil").rmtree, d, True)
        rec = os.path.join(d, "l7_record.jsonl")
        with open(rec, "w", encoding="utf-8") as fh:
            # attacker 10.0.2.1 at ~25 rps; benign 10.0.1.1 at ~2 rps
            fh.writelines(json.dumps({"rx": self.t0 + i * 0.04,
                                     "obj": U.obj(ip="10.0.2.1", msec=self.t0 + i * 0.04)}) + "\n" for i in range(120))
            fh.writelines(json.dumps({"rx": self.t0 + i * 0.5,
                                     "obj": U.obj(ip="10.0.1.1", msec=self.t0 + i * 0.5)}) + "\n" for i in range(10))
        sweep = eval_l7.threshold_sweep(rec, self.m, self.t0)
        self.assertEqual(sweep["deployed_l7_rate_ban_rps"], 50)
        at20 = next(r for r in sweep["sweep"] if r["rps_threshold"] == 20)
        self.assertEqual(at20["attacker_ips_caught"], 1)      # ~25 rps > 20
        self.assertEqual(at20["benign_ips_flagged"], 0)       # ~2 rps < 20
        at50 = next(r for r in sweep["sweep"] if r["rps_threshold"] == 50)
        self.assertEqual(at50["attacker_ips_caught"], 0)      # 25 < 50: the deployed rule misses it


class FakeSuite:
    """Stands in for test_distributed_suite: records run() calls, starts nothing."""
    PYTHON_VENV = "/venv/bin/python"
    SERVER_IP = "10.0.0.1"

    def __init__(self):
        self.calls = []

    def run(self, cmd, ns=None, bg=False, timeout=None):
        self.calls.append((ns, list(cmd)))

        class P:
            def poll(self):
                return 0
        return P()


class RunCaptureTest(unittest.TestCase):
    def test_run_capture_needs_no_module_global(self):
        # The P5 run A crash: gen_cmd read capture_l7's module-global S, which only
        # capture_l7.main() sets. Reused from eval_l7, it must take S as a parameter.
        import argparse

        import capture_l7
        self.assertFalse(hasattr(capture_l7, "S"))       # nobody set the global
        args = argparse.Namespace(duration=1.2)
        runner = eval_l7.EvalRunner(args, tempfile.mkdtemp(prefix="l7ev_"), "/pkg")
        fake = FakeSuite()
        benign = [{"ip": "10.0.1.1", "kind": "keepalive", "port": 443, "params": {}, "seed": 1}]
        attackers = [{"ip": "10.0.2.1", "family": "scraper", "port": 443,
                      "params": {"rps": 25}, "seed": 2}]
        schedule = [{"ip": "10.0.2.1", "start_s": 0.0, "stop_s": 1.0}]
        _t0, launched = runner.run_capture(fake, benign, attackers, schedule)
        self.assertEqual(launched, ["scraper"])
        nss = [ns for ns, _ in fake.calls]
        self.assertEqual(nss, ["b_10_0_1_1", "a_10_0_2_1"])
        cmd = fake.calls[0][1]
        self.assertEqual(cmd[0], FakeSuite.PYTHON_VENV)
        self.assertIn("--kind", cmd)
        self.assertEqual(cmd[cmd.index("--host") + 1], FakeSuite.SERVER_IP)
        self.assertIn("--family", fake.calls[1][1])


class PlanTest(unittest.TestCase):
    def test_soak_filters_to_flood_only(self):
        import argparse

        import capture_l7
        args = argparse.Namespace(seed=1, benign=6, duration=600.0,
                                  no_held_out=False, no_flood=False)
        _benign, attackers, _schedule, _ = capture_l7.build_plan(args)
        keep = [a for a in attackers if a["family"] == "volumetric_flood"]
        self.assertEqual(len(keep), 1)


class SelectAttacksTest(unittest.TestCase):
    """P5c.1 (§7.3.2): select_attacks is pure, so the filtering is unit-tested."""

    def setUp(self):
        import capture_l7
        args = type("A", (), {"seed": 1, "benign": 12, "duration": 600.0,
                              "no_held_out": False, "no_flood": False, "mix": "overlap"})()
        _b, self.attackers, self.schedule, _ = capture_l7.build_plan(args)
        self.assertTrue(any(a["family"] == "volumetric_flood" for a in self.attackers))
        self.assertTrue(any(a["family"] != "volumetric_flood" for a in self.attackers))

    def test_default_keeps_everything(self):
        a, s = eval_l7.select_attacks(self.attackers, self.schedule)
        self.assertEqual(a, self.attackers)
        self.assertEqual(s, self.schedule)

    def test_soak_keeps_only_the_flood(self):
        a, s = eval_l7.select_attacks(self.attackers, self.schedule, soak=True)
        self.assertEqual([x["family"] for x in a], ["volumetric_flood"])
        self.assertEqual(len(s), 1)

    def test_benign_only_drops_all_attacks(self):
        a, s = eval_l7.select_attacks(self.attackers, self.schedule, benign_only=True)
        self.assertEqual((a, s), ([], []))

    def test_benign_only_wins_over_soak(self):
        self.assertEqual(eval_l7.select_attacks(self.attackers, self.schedule,
                                                soak=True, benign_only=True), ([], []))

    def test_benign_only_manifest_validates_and_analyses(self):
        # With no attackers the dataset manifest must still validate, and analyse() must
        # report benign FPs with an empty by_family (the P5c.1 shape).
        benign = [{"ip": "10.0.1.1", "profile": "perfect", "kind": "browser_page"},
                  {"ip": "10.0.1.2", "profile": "perfect", "kind": "cgnat_browsers"}]
        ip_map = l7_dataset.build_ip_map(benign, [])
        m = l7_dataset.make_manifest(seed=1, duration_s=300.0, ip_map=ip_map,
                                     schedule=[], provenance={"t0_wall": 0})
        l7_dataset.validate_manifest(m)                       # does not raise
        t0 = 1000.0
        events = [{"kind": "l7_would_ban", "ip": "10.0.1.1", "t_poll": t0 + 5.0},
                  {"kind": "ban", "ip": "10.0.1.2", "engine": "l4_slowconn", "t_wall": t0 + 3.0}]
        a = eval_l7.analyse(events, m, t0)
        self.assertEqual(a["by_family"], {})
        self.assertEqual(a["benign_would_ban_count"], 1)
        self.assertEqual(a["det_banned_ips"], {"10.0.1.2": "l4_slowconn"})


if __name__ == "__main__":
    unittest.main()
