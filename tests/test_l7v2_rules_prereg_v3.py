"""The rule arms' re-registration under D-043 (ml/l7v2_rules_prereg_v3.json, before any capture): every value is pinned
here and cross-checked with its source (docs/L7V2_DESIGN.md section 10, ml/l7_baselines.py, control_plane.py, nginx.conf,
the model pre-registration and the verdict pre-registration's candidates). Offline and pure."""
import hashlib
import json
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_baselines
import l7_traffic
import l7v2_model_prereg as MPRE

PATH = os.path.join(REPO, "ml", "l7v2_rules_prereg_v3.json")
SHA256 = "411c59f15bc30da2ef2265fff265e80010e4a6dbfbcc09a98d6b324f2d66cef6"


def spec():
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


class RuleLevelPreregTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), SHA256)
        s = spec()
        self.assertEqual(s["format"], "l7v2-rules-prereg/3")
        self.assertTrue(s["label"].startswith("re-registered 2026-11-01 under D-043"))
        self.assertIn("before any capture", s["label"])

    def test_the_rules_own_level_is_kept(self):
        s = spec()
        self.assertEqual(s["level"]["key"], ["ip", "ua_h"])
        d = s["decision_points"]
        self.assertEqual(d["poll_s"], MPRE.load()["selection"]["policy_engine_poll_s"])
        self.assertIn("one row per (IP, UA) key and engine poll", d["rule"])
        self.assertIn("k consecutive rows of the key", d["policy"])
        self.assertEqual(s["statistic"]["lookback_s"], MPRE.load()["ingest"]["idle_timeout_s"])
        self.assertIn("own (IP, UA) path", s["r_star_live"])

    def test_e1_threshold_levels(self):
        t = spec()["threshold_levels"]
        self.assertEqual(t["multiples"], [0.8, 1.0, 1.2, 1.5, 2.0])
        self.assertEqual(t["quantiles"], [0.5, 0.75, 0.9, 0.95, 0.98, 0.99, 0.995])
        self.assertIn("per-key maximum over the benign (IP, UA) keys", t["quantile_rule"])
        self.assertIn("the maximum itself is the multiple 1.0", t["quantile_rule"])
        self.assertEqual(t["quantiles"], sorted(t["quantiles"]))
        self.assertEqual(t["quantiles"][0], 0.5, "from the median")

    def test_e1_absolute_grids_extend_below_1_req_s(self):
        a = spec()["arms"]
        thr, rates = a["sustained_rate"]["thresholds_rps"], a["token_bucket"]["rates"]
        self.assertEqual(thr, [0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1, 2, 5, 10, 15, 20, 25, 30, 40, 50])
        self.assertEqual(rates, [0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 20, 25, 30])
        self.assertEqual(spec()["columns"]["key"]["bucket_rates"], rates)
        self.assertLessEqual(set(l7_baselines.SUSTAIN_THRESHOLDS), set(thr))
        self.assertLessEqual(set(l7_baselines.BUCKET_RATES), set(rates))
        self.assertEqual(a["sustained_rate"]["windows_s"], list(l7_baselines.SUSTAIN_WINDOWS))
        self.assertEqual(a["token_bucket"]["bursts"], list(l7_baselines.BUCKET_BURSTS))
        self.assertEqual(a["cost_budget"]["windows_s"], [10, 60, 300])
        self.assertEqual(a["multiscale_rate"]["windows_s"], [1, 10, 60, 300])

    def test_e4_a_flagged_key_costs_every_user_behind_it(self):
        u = spec()["unit_rule"]
        self.assertIn("costs every benign user behind it", u)
        self.assertIn("D-031's per-key rule", u)
        self.assertIn("view-level keys", u)

    def test_the_age_only_arm(self):
        s = spec()["age_only"]
        self.assertEqual(s["column"], "key:age")
        self.assertEqual(s["auc_band"], MPRE.load()["baselines"]["age_only"]["auc_band"])
        self.assertIn("never R*", s["use"])

    def test_the_fixed_replays_restate_the_daemon_and_nginx(self):
        with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
            src = fh.read()
        s = spec()
        d, a = s["daemon"], s["arms"]
        for needle in (f"HEURISTIC_WINDOW = {d['window_s']}", f"HEURISTIC_MAX_RPS = {a['default_rules']['max_rps']}",
                       f"HEURISTIC_ERROR_RATIO = {d['error_ratio']}",
                       f"HEURISTIC_MIN_REQUESTS = {d['min_requests']}", f"BAN_TTL_SECONDS = {int(d['ban_ttl_s'])}",
                       f'"HEURISTIC_MAX_RPS": {a["tolerant_rules"]["max_rps"]}', f"rps > {d['error_min_rps']})"):
            self.assertIn(needle, src)
        self.assertEqual((a["nginx_limits"]["rate_rps"], a["nginx_limits"]["burst"]),
                         (l7_traffic.THRESHOLDS["nginx_limit_req_rps"], l7_traffic.THRESHOLDS["nginx_limit_req_burst"]))
        with open(os.path.join(REPO, "nginx.conf"), encoding="utf-8") as fh:
            conf = fh.read()
        self.assertTrue(re.search(r"limit_req_zone \$binary_remote_addr .*rate=30r/s", conf))
        self.assertIn("burst=100 nodelay", conf)


if __name__ == "__main__":
    unittest.main()
