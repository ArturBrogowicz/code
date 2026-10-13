"""Tests for the campaign analysis (eval/campaign.py, eval/analyze_campaign.py).

Needs the venv (pandas, numpy, scipy):  venv/bin/python -m unittest discover -s tests -v

* A small synthetic campaign with known answers.
* Determinism: analysing twice gives byte-identical files.
* Reference test: the EXP-2a campaign published in results/ must reproduce the numbers of
  docs/REPORT_ADDENDUM_EXP0_EXP1.md §J.
"""
import csv
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
try:
    import campaign as C
    from analyze_campaign import analyse
    HAVE_STACK = True
except ImportError:                      # system python without pandas: skip these tests
    HAVE_STACK = False

EXP2A = os.path.join(REPO, "results", "2026-10-12_exp2a-knee_prototype")
SCEN = "Distributed HTTP Flood"


def _write_csv(path, header, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def make_run(root, mode, run, seed, oks, attack_start=1000.0, fp=()):
    """One synthetic run: `oks` = OK flags of the 'during' requests; plus one 'before'
    request and one 'after' request, both successful."""
    d = os.path.join(root, mode, run)
    os.makedirs(d)
    with open(os.path.join(d, "provenance.json"), "w") as fh:
        json.dump({"schema": 1, "status": "completed", "git": {"commit": "a" * 40},
                   "mode": {"label": mode}, "operating_point": {"name": "knee"},
                   "settings": {"PROFILE_SEED": seed, "ATTACK_DURATION": 0}}, fh)
    raw = [["t", SCEN, "before", "perfect", "200", "10.0", 1, "10.0.1.1", f"{attack_start - 2:.3f}"]]
    for i, ok in enumerate(oks):        # one request every 0.5 s after the attack start
        raw.append(["t", SCEN, "during", "perfect" if i % 2 else "broadband",
                    "200" if ok else "000", f"{100 + i:.1f}" if ok else "10000.0", int(ok),
                    "10.0.1.2", f"{attack_start + 0.5 * i:.3f}"])
    raw.append(["t", SCEN, "after", "perfect", "200", "5.0", 1, "10.0.1.1", f"{attack_start + 30:.3f}"])
    _write_csv(os.path.join(d, "availability_raw.csv"),
               ["Timestamp", "Scenario", "Period", "Profile", "HTTP_Code", "Latency_ms", "OK",
                "Client_IP", "T_Start"], raw)
    _write_csv(os.path.join(d, "metrics.csv"), ["Timestamp", "Scenario", "Phase", "CPU_Nginx_Pct", "PPS_Rx"],
               [["t", SCEN, "Phase 1: Baseline", "1.0", "10"],
                ["t", SCEN, "Phase 2: Pre-Mitigation", "40.0", "1000"],
                ["t", SCEN, "Phase 3: Post-Mitigation", "20.0", "3000"]])
    daemon = mode != "unprotected"
    ttm = {"10.0.2.1": 0.5, "10.0.2.2": 1.5} if daemon else {}
    eng = {"10.0.2.1": "l7_rate", "10.0.2.2": "l4_syn"} if daemon else {}
    _write_csv(os.path.join(d, "scenario_results.csv"),
               ["Scenario", "Data_Scenario", "Mode", "Attack_Start", "Attack_End", "Exposure_s", "Bots",
                "TTM_Exact_By_Bot", "Engine_By_Bot", "FP_Source", "FP_IPs"],
               [[SCEN, SCEN, mode, attack_start, attack_start + 5, 5.0, 2, json.dumps(ttm),
                 json.dumps(eng), "ban events" if daemon else "no daemon", json.dumps(list(fp))]])
    with open(os.path.join(d, "ban_events.jsonl"), "w") as fh:
        if daemon:
            fh.write(json.dumps({"t_wall": attack_start - 20, "kind": "start"}) + "\n")


@unittest.skipUnless(HAVE_STACK, "needs pandas/numpy (run with venv/bin/python)")
class SyntheticCampaignTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        make_run(self.root, "xdp", "run1", 1, [1] * 10)
        make_run(self.root, "xdp", "run2", 2, [1] * 9 + [0], fp=["10.0.1.3"])
        make_run(self.root, "unprotected", "run1", 1, [1] * 5 + [0] * 5)
        make_run(self.root, "unprotected", "run2", 2, [1] * 7 + [0] * 3)
        self.data = C.load(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_availability_pooled_per_run_and_ci(self):
        av = C.availability(self.data["raw"]).set_index(["mode", "period"])
        x, u = av.loc[("xdp", "during")], av.loc[("unprotected", "during")]
        self.assertEqual((x.n, x.ok, x.per_run_pct), (20, 19, "100/90"))
        self.assertAlmostEqual(x.success_pct, 95.0)
        self.assertEqual((u.n, u.per_run_pct), (20, "50/70"))
        self.assertTrue(90.0 <= x.ci_lo <= x.success_pct <= x.ci_hi <= 100.0)
        self.assertAlmostEqual(av.loc[("xdp", "before")].success_pct, 100.0)
        self.assertEqual(list(C.availability(self.data["raw"])["mode"][:3]), ["xdp"] * 3)  # mode order

    def test_delta_is_paired_by_profile_seed(self):
        dl = C.delta_vs_reference(self.data["raw"], self.data["runs"]).iloc[0]
        self.assertEqual(dl["mode"], "xdp")
        self.assertAlmostEqual(dl.delta_pp, 35.0)
        self.assertIn("paired", dl.method)
        self.assertTrue(20.0 - 1e-9 <= dl.ci_lo <= dl.ci_hi <= 50.0 + 1e-9)   # block diffs 50, 20
        self.assertLess(dl.fisher_p, 0.05)

    def test_delta_falls_back_to_independent_runs_without_shared_seeds(self):
        runs = self.data["runs"].copy()
        runs.loc[runs["mode"] == "unprotected", "profile_seed"] = None
        self.assertEqual(C.delta_vs_reference(self.data["raw"], runs).iloc[0].method,
                         "independent runs")

    def test_window_uses_request_start_relative_to_attack(self):
        w = C.window(self.data["raw"], 2.0).set_index(["mode", "profile"])
        # requests start every 0.5 s from the attack start -> 4 per run in [0, 2) s
        self.assertEqual(w.loc[("xdp", "ALL")].n, 8)
        self.assertAlmostEqual(w.loc[("unprotected", "ALL")].success_pct, 100.0)

    def test_latency_counts_only_served_requests(self):
        lat = C.latency(self.data["raw"]).set_index(["mode", "profile"])
        self.assertEqual(lat.loc[("xdp", "ALL")].n, 19)
        self.assertLess(lat.loc[("unprotected", "ALL")].p95_ms, 200)       # timeouts excluded

    def test_detection_and_false_positives(self):
        det = C.detection(self.data["scenarios"]).set_index("mode")
        self.assertEqual((det.loc["xdp"].banned, det.loc["xdp"].bots), (4, 4))
        self.assertAlmostEqual(det.loc["xdp"].ttm_median_s, 1.0)
        self.assertEqual(det.loc["xdp"].engines, "l4_syn:2, l7_rate:2")
        self.assertEqual((det.loc["xdp"].fp_count, det.loc["xdp"].fp_ips), (1, "10.0.1.3"))
        self.assertEqual(det.loc["unprotected"].fp_source, "no daemon")

    def test_server_means_exclude_the_baseline(self):
        srv = C.server(self.data["metrics"]).set_index("mode")
        self.assertAlmostEqual(srv.loc["xdp"].CPU_Nginx_Pct, 30.0)
        self.assertAlmostEqual(srv.loc["xdp"].PPS_Rx, 2000.0)

    def test_analysis_is_deterministic(self):
        a, b = os.path.join(self.root, "a"), os.path.join(self.root, "b")
        analyse(self.root, a)
        analyse(self.root, b)
        for name in sorted(os.listdir(a)):
            with open(os.path.join(a, name), "rb") as fa, open(os.path.join(b, name), "rb") as fb:
                self.assertEqual(fa.read(), fb.read(), name)


@unittest.skipUnless(HAVE_STACK and os.path.isdir(EXP2A), "needs the venv and results/ EXP-2a data")
class Exp2aReferenceTest(unittest.TestCase):
    """The published EXP-2a campaign must reproduce addendum §J (headline numbers as
    published; time-to-mitigate and the 0-10 s window as corrected in §J.5)."""

    @classmethod
    def setUpClass(cls):
        cls.data = C.load(EXP2A)

    def test_availability_during_the_flood(self):
        av = C.availability(self.data["raw"])
        d = av[av.period == "during"].set_index("mode")
        expected = {"xdp": (68, 100.0, "100/100/100"), "iptables": (72, 100.0, "100/100/100"),
                    "nginxlimits": (113, 52.2, "53/53/51"), "unprotected": (208, 89.9, "89/87/93")}
        for mode, (n, pct, per_run) in expected.items():
            self.assertEqual(d.loc[mode].n, n, mode)
            self.assertAlmostEqual(d.loc[mode].success_pct, pct, delta=0.05, msg=mode)
            self.assertEqual(d.loc[mode].per_run_pct, per_run, mode)

    def test_fisher_vs_unprotected(self):
        dl = C.delta_vs_reference(self.data["raw"], self.data["runs"]).set_index("mode")
        self.assertAlmostEqual(dl.loc["xdp"].fisher_p, 0.00295, delta=0.00005)
        self.assertAlmostEqual(dl.loc["nginxlimits"].fisher_p / 1.21e-13, 1.0, delta=0.01)

    def test_perfect_client_latency(self):
        lat = C.latency(self.data["raw"])
        p = lat[lat.profile == "perfect"].set_index("mode")
        expected = {"xdp": (1, 147), "iptables": (2, 418), "nginxlimits": (3837, 4613),
                    "unprotected": (1102, 6395)}
        for mode, (p50, p95) in expected.items():
            self.assertEqual((round(p.loc[mode].p50_ms), round(p.loc[mode].p95_ms)), (p50, p95), mode)

    def test_server_load(self):
        srv = C.server(self.data["metrics"]).set_index("mode")
        for mode, (nginx, pps) in {"xdp": (11, 10642), "iptables": (17, 12530),
                                   "nginxlimits": (98, 34160), "unprotected": (34, 3689)}.items():
            self.assertEqual(round(srv.loc[mode].CPU_Nginx_Pct), nginx, mode)
            self.assertEqual(round(srv.loc[mode].PPS_Rx), pps, mode)

    def test_detection_over_all_three_runs(self):
        det = C.detection(self.data["scenarios"]).set_index("mode")
        for mode, median in {"xdp": 0.22, "iptables": 0.31}.items():
            self.assertEqual((det.loc[mode].banned, det.loc[mode].bots), (30, 30), mode)
            self.assertAlmostEqual(det.loc[mode].ttm_median_s, median, delta=0.005, msg=mode)
            self.assertEqual((det.loc[mode].gru_bans, det.loc[mode].fp_count), (0, 0), mode)

    def test_equal_exposure_window_over_all_three_runs(self):
        w = C.window(self.data["raw"], 10.0)
        p = w[w.profile == "perfect"].set_index("mode")
        for mode, (n, pct) in {"xdp": (95, 100.0), "iptables": (96, 100.0),
                               "nginxlimits": (22, 13.6), "unprotected": (73, 97.3)}.items():
            self.assertEqual(p.loc[mode].n, n, mode)
            self.assertAlmostEqual(p.loc[mode].success_pct, pct, delta=0.05, msg=mode)


if __name__ == "__main__":
    unittest.main()
