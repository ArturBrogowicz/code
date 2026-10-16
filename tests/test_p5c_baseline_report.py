"""Unit tests for ml/p5c_baseline_report.py (P5c.1, docs/L7_GRU_DESIGN.md §7.3.2), on a
synthetic benign-only run directory. Offline."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
from test_l7_baselines import write_recording

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import l7_traffic
import p5c_baseline_report as R

import l7_dataset


class BaselineReportTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="p5c1_")
        self.addCleanup(shutil.rmtree, self.d, True)
        benign, _, _, _ = l7_traffic.build_plan(1, 12, 120.0, benign_mix="overlap",
                                                launch_inadmissible=True)
        ip_map = l7_dataset.build_ip_map(benign, [])
        m = l7_dataset.make_manifest(seed=1, duration_s=120.0, ip_map=ip_map, schedule=[],
                                     provenance={"t0_wall": 1000.0})
        l7_dataset.write_dataset_manifest(os.path.join(self.d, "manifest.json"), m)
        with open(os.path.join(self.d, "summary.json"), "w", encoding="utf-8") as fh:
            json.dump({"t0_wall": 1000.0,
                       "analysis": {"benign_would_ban_ips": {"10.0.1.15": 2}}}, fh)
        events = [{"t_wall": 1012.0, "kind": "ban", "ip": "10.0.1.15", "engine": "l7_rate",
                   "value": 61.0, "threshold": 50, "error_ratio": 0.0},
                  {"t_wall": 1030.0, "kind": "ban", "ip": "10.0.1.17", "engine": "l4_slowconn",
                   "value": 72, "threshold": 8, "bytes": 0},
                  {"t_wall": 1031.0, "kind": "ban", "ip": "10.0.1.17", "engine": "l7_rate",
                   "value": 55.0}]                              # only the first ban counts
        with open(os.path.join(self.d, "ban_events.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in events)
        objs = ([U.obj(ip="10.0.1.15", ua="b", msec=1001.0 + i * 0.01) for i in range(61)]
                + [U.obj(ip="10.0.1.17", ua=f"u{i % 3}", msec=1002.0 + i * 0.1) for i in range(40)]
                + [U.obj(ip="10.0.1.18", ua="x", msec=1003.0, lreq="REJECTED")])
        objs[-1]["lconn"] = "REJECTED"
        write_recording(os.path.join(self.d, "l7_record.jsonl"), objs)
        self.rep = R.build(self.d)
        self.rows = {r["ip"]: r for r in self.rep["rows"]}

    def test_rows_specs_and_bans(self):
        self.assertEqual(self.rep["benign_ips"], 20)
        self.assertEqual(self.rep["det_banned_benign"], 2)
        self.assertEqual(self.rows["10.0.1.15"]["spec"], {"level": 60})
        self.assertEqual(self.rows["10.0.1.17"]["spec"], {"level": 30, "users": 12})
        self.assertEqual(self.rows["10.0.1.17"]["det_ban"]["engine"], "l4_slowconn")
        self.assertEqual(self.rows["10.0.1.17"]["det_ban"]["t_rel_s"], 30.0)
        self.assertEqual(self.rows["10.0.1.15"]["profile"]["peak_1s"], 61)
        self.assertEqual(self.rows["10.0.1.17"]["distinct_uas"], 3)
        self.assertEqual(self.rows["10.0.1.18"]["limit_req_rejected"], 1)
        self.assertEqual(self.rows["10.0.1.18"]["limit_conn_rejected"], 1)
        self.assertEqual(self.rows["10.0.1.15"]["gru_would_bans"], 2)
        self.assertIn("l7_rate", self.rows["10.0.1.15"]["gate_trips"])

    def test_gate_vs_live(self):
        c = self.rep["gate_vs_live"]
        self.assertEqual(c["predicted_ban_and_banned"], ["10.0.1.15", "10.0.1.17"])
        self.assertEqual(c["predicted_ban_not_banned"], ["10.0.1.16", "10.0.1.18"])
        self.assertEqual(c["predicted_ok_but_banned"], [])

    def test_unloaded_timing_changes_only_server_timing(self):
        item = ("record", U.obj(rt=0.5, urt="0.4", msec=1001.0))
        out = R.unloaded_timing(item)
        self.assertEqual((out[1]["rt"], out[1]["urt"]), (0.001, "0.001"))
        self.assertEqual({k: v for k, v in out[1].items() if k not in ("rt", "urt")},
                         {k: v for k, v in item[1].items() if k not in ("rt", "urt")})
        self.assertEqual(item[1]["rt"], 0.5)                       # input not mutated
        self.assertEqual(R.unloaded_timing(("poll", 1.0, False, ())), ("poll", 1.0, False, ()))

    def test_timing_counterfactual_runs_both_replays(self):
        pkg = tempfile.mkdtemp(prefix="p5c1pkg_")
        self.addCleanup(shutil.rmtree, pkg, True)
        U.tiny_package(pkg)
        cf = R.timing_counterfactual(os.path.join(self.d, "l7_record.jsonl"), pkg)
        self.assertEqual(set(cf), {"as_recorded", "unloaded_timing"})
        self.assertEqual(cf["as_recorded"]["windows"], cf["unloaded_timing"]["windows"])

    def test_markdown(self):
        md = R.to_markdown(self.rep)
        self.assertIn("2 of 20 benign IPs banned", md)
        self.assertIn("**l4_slowconn** @ 30.0 s", md)


if __name__ == "__main__":
    unittest.main()
