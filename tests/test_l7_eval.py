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


class PlanTest(unittest.TestCase):
    def test_soak_filters_to_flood_only(self):
        import argparse

        import capture_l7
        args = argparse.Namespace(seed=1, benign=6, duration=600.0,
                                  no_held_out=False, no_flood=False)
        _benign, attackers, _schedule, _ = capture_l7.build_plan(args)
        keep = [a for a in attackers if a["family"] == "volumetric_flood"]
        self.assertEqual(len(keep), 1)


if __name__ == "__main__":
    unittest.main()
