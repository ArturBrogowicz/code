"""Reference tests for the prototype campaigns of 2026-10-12 published in results/.

Needs the venv (pandas, numpy):  venv/bin/python -m unittest discover -s tests -v

Each class pins the numbers that the campaign's README quotes, recomputed from the published
per-run files with eval/campaign.py. A campaign is not edited after publication, so a failure
here means the code changed (or the data was touched), not the number.
"""
import collections
import glob
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "eval"))
import ban_events

try:
    import campaign as C
    HAVE_STACK = True
except ImportError:                      # system python without pandas: skip these tests
    HAVE_STACK = False

EXP1 = os.path.join(REPO, "results", "2026-10-12_exp1-default-4modes_prototype")
HTTP, YOYO, UDP = "Distributed HTTP Flood", "Distributed Yo-Yo", "Distributed UDP Flood"


def bans_of(campaign_dir):
    """Every ban event of a campaign."""
    out = []
    for path in sorted(glob.glob(os.path.join(campaign_dir, "*", "run*", "ban_events.jsonl"))):
        out += [e for e in ban_events.read_events(path) if e["kind"] == "ban"]
    return out


def harness_fp_lines(campaign_dir):
    """Number of 'False Positives: n BANNED' lines of the harness console, per mode (modes
    without such a line are left out)."""
    out = collections.Counter()
    for path in glob.glob(os.path.join(campaign_dir, "*", "run*", "console.log")):
        with open(path, encoding="utf-8") as fh:
            out[path.split(os.sep)[-3]] += sum(1 for ln in fh if "False Positives:" in ln and "BANNED" in ln)
    return {mode: n for mode, n in out.items() if n}


@unittest.skipUnless(HAVE_STACK and os.path.isdir(EXP1), "needs the venv and results/ EXP-1 data")
class Exp1DefaultPointTest(unittest.TestCase):
    """README of 2026-10-12_exp1-default-4modes_prototype (addendum §C-§I)."""

    @classmethod
    def setUpClass(cls):
        cls.data = C.load(EXP1)
        cls.raw = cls.data["raw"]

    def test_four_modes_three_runs_ten_scenarios(self):
        runs = self.data["runs"]
        self.assertEqual(sorted(runs["mode"].unique()), ["iptables", "nginxlimits", "unprotected", "xdp"])
        self.assertEqual(runs.groupby("mode").size().to_dict(), {m: 3 for m in runs["mode"].unique()})
        self.assertEqual(self.data["scenarios"].groupby("mode").size().to_dict(),
                         {"iptables": 30, "nginxlimits": 30, "unprotected": 30, "xdp": 30})

    def test_availability_is_100_percent_but_for_one_request(self):
        during = self.raw[self.raw.Period == "during"]
        got = {m: (len(g), int((g.OK == 0).sum())) for m, g in during.groupby("mode")}
        self.assertEqual(got, {"xdp": (2318, 0), "iptables": (2273, 0), "nginxlimits": (6665, 0),
                               "unprotected": (6107, 1)})
        av = C.availability(self.raw)
        not_full = [(r.scenario, r.mode, r.period, r.ok, r.n) for r in av.itertuples() if r.ok != r.n]
        self.assertEqual(not_full, [(UDP, "unprotected", "during", 554, 555)])

    def test_first_ten_seconds_are_100_percent_in_every_cell(self):
        w = C.window(self.raw, 10.0)
        w = w[w.profile == "ALL"]
        self.assertEqual(len(w), 40)
        self.assertEqual(w.success_pct.min(), 100.0)

    def test_perfect_client_latency_under_l7_floods(self):
        lat = C.latency(self.raw)
        p = lat[lat.profile == "perfect"]
        expected = {HTTP: {"xdp": (2, 115), "iptables": (3, 259), "nginxlimits": (27, 208),
                           "unprotected": (274, 605)},
                    YOYO: {"xdp": (2, 253), "iptables": (2, 263), "nginxlimits": (2, 107),
                           "unprotected": (2, 478)}}
        for scenario, modes in expected.items():
            for mode, want in modes.items():
                row = p[(p.scenario == scenario) & (p["mode"] == mode)].iloc[0]
                self.assertEqual((round(row.p50_ms), round(row.p95_ms)), want, (scenario, mode))

    def test_server_load_under_the_http_flood(self):
        srv = C.server(self.data["metrics"])
        srv = srv[srv.scenario == HTTP].set_index("mode")
        for mode, (nginx, pps) in {"xdp": (52, 5009), "iptables": (55, 7001),
                                   "nginxlimits": (434, 48652), "unprotected": (112, 1189)}.items():
            self.assertEqual((round(srv.loc[mode].CPU_Nginx_Pct), round(srv.loc[mode].PPS_Rx)),
                             (nginx, pps), mode)

    def test_prestack_drop_only_with_xdp(self):
        srv = C.server(self.data["metrics"])
        srv = srv[srv.scenario == UDP].set_index("mode")
        self.assertEqual((round(srv.loc["xdp"].PreStack_Dropped), round(srv.loc["xdp"].IP_InReceives)),
                         (1593332, 119339))
        for mode, ip_in in {"iptables": 1274762, "nginxlimits": 1618276, "unprotected": 1460575}.items():
            self.assertEqual((round(srv.loc[mode].PreStack_Dropped), round(srv.loc[mode].IP_InReceives)),
                             (0, ip_in), mode)

    def test_detection_in_the_two_daemon_modes(self):
        det = C.detection(self.data["scenarios"])
        x = det[det["mode"].isin(["xdp", "iptables"])]
        self.assertTrue((x.banned == x.bots).all())
        self.assertEqual((int(x.gru_bans.sum()), int(x.fp_count.sum())), (0, 0))
        for mode, (lo, hi, worst) in {"xdp": (0.542, 3.937, 10.316), "iptables": (0.445, 3.776, 4.084)}.items():
            t = x[x["mode"] == mode]
            self.assertAlmostEqual(t.ttm_median_s.min(), lo, delta=0.006, msg=mode)
            self.assertAlmostEqual(t.ttm_median_s.max(), hi, delta=0.006, msg=mode)
            self.assertAlmostEqual(t.ttm_max_s.max(), worst, delta=0.006, msg=mode)
        ack = x[x.scenario == "Distributed ACK Flood"].set_index("mode")
        self.assertAlmostEqual(ack.loc["xdp"].ttm_max_s, 10.316, delta=0.006)      # the F-45 stall
        self.assertAlmostEqual(ack.loc["iptables"].ttm_max_s, 1.091, delta=0.006)

    def test_ban_events_census(self):
        bans = bans_of(EXP1)
        self.assertEqual(len(bans), 300)
        self.assertEqual(dict(collections.Counter(b["engine"] for b in bans)),
                         {"l4_volumetric": 108, "l7_rate": 66, "l4_slowconn": 60, "l4_syn": 36,
                          "l4_lowsyn": 30})
        self.assertEqual(sorted({b["ip"] for b in bans}), [f"10.0.2.{i}" for i in range(1, 6)])

    def test_harness_result_and_ping_check_lines(self):
        results = self.data["scenarios"].groupby("mode").Result.value_counts().to_dict()
        self.assertEqual(results, {("iptables", "PASS"): 30, ("nginxlimits", "FAIL"): 30,
                                   ("unprotected", "FAIL"): 30, ("xdp", "PASS"): 28, ("xdp", "FAIL"): 2})
        self.assertEqual(harness_fp_lines(EXP1), {"xdp": 1, "nginxlimits": 1, "unprotected": 2})

    def test_exposure(self):
        exposure = self.data["scenarios"].groupby("mode").Exposure_s.mean().round(1).to_dict()
        self.assertEqual(exposure, {"iptables": 9.0, "nginxlimits": 28.3, "unprotected": 28.6, "xdp": 9.5})


if __name__ == "__main__":
    unittest.main()
