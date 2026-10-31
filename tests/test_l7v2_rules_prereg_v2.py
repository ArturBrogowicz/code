"""The rule arms' re-registration at their own level (ml/l7v2_rules_prereg_v2.json; review finding T042-E08, before any
capture): every value is pinned here and cross-checked with its source (docs/L7V2_DESIGN.md section 10,
ml/l7_baselines.py, control_plane.py, nginx.conf, the model and verdict pre-registrations). Offline and pure."""
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
import l7v2_verdict_prereg as VPRE

PATH = os.path.join(REPO, "ml", "l7v2_rules_prereg_v2.json")
SHA256 = "6aa398f36be5d4e8d8e27cfc12684ea140537cc02808b6662eab8e4f96c3a096"


def spec():
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


class RuleLevelPreregTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), SHA256)
        s = spec()
        self.assertEqual(s["format"], "l7v2-rules-prereg/2")
        self.assertTrue(s["label"].startswith("re-registered 2026-10-31 under T042-E08"))
        self.assertIn("before any capture", s["label"])

    def test_the_rules_own_level(self):
        s = spec()
        self.assertEqual(s["level"]["key"], ["ip", "ua_h"])
        d = s["decision_points"]
        self.assertEqual(d["poll_s"], MPRE.load()["selection"]["policy_engine_poll_s"])
        self.assertIn("one row per (IP, UA) key and engine poll", d["rule"])
        self.assertIn("k consecutive rows of the key", d["policy"])
        self.assertEqual(s["statistic"]["lookback_s"], MPRE.load()["ingest"]["idle_timeout_s"])
        self.assertIn("no cap on the history", s["statistic"]["per_request"])
        self.assertIn("one unit of its entity", s["unit_rule"])
        self.assertIn("own (IP, UA) path", s["r_star_live"])

    def test_grids_restate_the_design_and_l7_baselines(self):
        a = spec()["arms"]
        self.assertEqual(list(a), ["sustained_rate", "token_bucket", "cost_budget", "multiscale_rate", "population",
                                   "default_rules", "tolerant_rules", "nginx_limits"])
        self.assertEqual(a["sustained_rate"]["windows_s"], list(l7_baselines.SUSTAIN_WINDOWS))
        self.assertEqual(a["sustained_rate"]["thresholds_rps"], list(l7_baselines.SUSTAIN_THRESHOLDS))
        self.assertEqual(a["token_bucket"]["rates"], list(l7_baselines.BUCKET_RATES))
        self.assertEqual(a["token_bucket"]["bursts"], list(l7_baselines.BUCKET_BURSTS))
        self.assertEqual(a["cost_budget"]["windows_s"], [10, 60, 300])
        self.assertEqual(a["multiscale_rate"]["windows_s"], [1, 10, 60, 300])
        self.assertEqual(spec()["tau_grid"], [0.8, 1.0, 1.2, 1.5, 2.0])
        self.assertTrue(set(VPRE.load()["best_rule"]["candidates"]) <= {k for k, v in a.items() if v["tuned"]})

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
