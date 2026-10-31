"""The L7 v2 model-side pre-registration (ml/l7v2_model_prereg.json), docs/L7V2_DESIGN.md sections 8, 10 and 13: every
frozen value is pinned here, so a change shows up as a failing test and must become a new file version. Offline and
pure."""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7v2_model_prereg as P
import p3_prereg

PREREG_SHA256 = "3eedd1d5e0ac69a0ae3d74f4574fbeff4d0cad79e691fc4e440d808009c73706"


class FrozenFileTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(P.PREREG_PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_SHA256)
        self.assertEqual(P.load()["format"], "l7v2-model-prereg/1")

    def test_keying_and_ingest(self):
        pre = P.load()
        self.assertEqual(pre["keying"]["key"], ["ip", "ua_h", "sid_h"])
        self.assertEqual(pre["keying"]["sid_fields"], ["sid_set", "sid"])
        self.assertEqual(pre["keying"]["absent"], ["", "-"])
        self.assertEqual(pre["keying"]["no_sid"], -1)
        self.assertFalse(pre["keying"]["sid_is_a_feature"])
        self.assertEqual(pre["ingest"]["hashed"], {"uri": "uri_h", "ua": "ua_h", "ref": "ref_h", "sid": "sid_h"})
        self.assertEqual(pre["ingest"]["idle_timeout_s"], 300.0)
        self.assertEqual(pre["site_map"], {"page": ["C1"], "asset": ["C0"], "costly": ["C3", "C5"],
                                           "source": "l7_webapp.route_class"})

    def test_request_level(self):
        rl = P.load()["request_level"]
        self.assertEqual(rl["nav_features"], ["is_page", "is_asset", "is_costly", "asset_refetch", "page_revisit",
                                              "ref_present", "ref_known", "log_page_gap"])
        self.assertEqual(rl["groups"], ["timing", "completion", "status", "method", "size", "connection", "uri",
                                        "ratelimit", "nav"])
        self.assertEqual((rl["seq_len"], rl["stride"], rl["min_events"], rl["page_gap_clip_s"]), (64, 3, 5, 3600.0))

    def test_views(self):
        v = P.load()["views"]
        self.assertEqual((v["max_views"], v["min_views"], v["dwell_clip_s"], v["count_clip"]), (32, 4, 3600.0, 10000))
        self.assertEqual(P.token_columns(), [
            "valid", "log_dwell", "log_n_req", "asset_share", "asset_refetch_share", "log_n_costly", "page_view",
            "page_revisit", "ref_present", "ref_known", "s2xx_share", "s3xx_share", "s4xx_share", "s5xx_share",
            "get_share", "post_share", "other_share", "new_conn_share"])
        self.assertEqual(v["summary"], {"per_column": ["mean", "std", "max"],
                                        "counts": ["n_views", "log_n_req_total", "log_span", "log_rate"]})

    def test_models(self):
        m = P.load()["models"]
        self.assertEqual(m["view_gru"], {"level": "view", "embed": 32, "hidden": 64, "layers": 2, "dropout": 0.2,
                                         "epochs": 25, "lr": 0.001, "batch": 128})
        self.assertEqual(m["request_gru"], {"level": "request", "hidden": 64, "layers": 2, "dropout": 0.2,
                                            "epochs": 25, "lr": 0.001, "batch": 128})
        self.assertEqual(m["hgb"], {"input": "token summaries", "max_iter": 200, "class_weight": "balanced",
                                    "early_stopping": False})
        self.assertEqual(m["lr"], {"input": "token summaries", "scaler": "standard", "max_iter": 3000,
                                   "class_weight": "balanced"})
        self.assertEqual(m["gru_shuffled"]["shuffle_seed"], 7)
        self.assertEqual((m["fit_seed"], m["threads_max"]), (0, 2))

    def test_the_d034_re_registrations(self):
        # T038-04 (one tuning rule), T038-05 (the shuffled variants' units), T038-06 (the engine's windows), each
        # re-registered 2026-10-31 under D-034 before any capture
        pre = P.load()
        m, s = pre["models"], pre["selection"]
        self.assertIn("fixed epochs", m["training"])
        self.assertIn("the last epoch's weights kept", m["training"])
        self.assertIn("class_weight 'balanced'", m["training"])
        self.assertTrue(m["training_label"].startswith("re-registered 2026-10-31 under D-034, before any capture"))
        self.assertIn("first valid token in place", m["gru_shuffled"]["pin_first"])
        self.assertIn("beside every gap", m["gru_shuffled"]["report"])
        self.assertIn("newest engine.max_new_windows_per_key_per_poll", s["policy_engine"])
        self.assertEqual(s["policy_engine_poll_s"], 1.0)
        self.assertTrue(s["policy_engine_label"].startswith("re-registered 2026-10-31 under D-034, before any capture"))

    def test_the_age_only_baseline_d034(self):
        b = P.load()["baselines"]["age_only"]
        self.assertTrue(b["label"].startswith("registered 2026-10-31 under D-034"))
        self.assertEqual(b["auc_band"], 0.15)
        self.assertIn("time since the key's first view", b["score"])
        self.assertIn("within 0.5 +- auc_band", b["reading"])
        self.assertIn("age-confounded", b["reading"])
        self.assertNotIn("age_only", P.ARMS, "a diagnostic, never a selected arm")

    def test_the_load_split_d034(self):
        ls = P.load()["load_split"]
        self.assertIn("descriptive, never a gate", ls["label"])
        self.assertIn("timeline.t0_wall", ls["phase_rule"])
        self.assertIn("inside and outside the attack phases", ls["benign"])
        self.assertIn("intensity multiplier", ls["recall_by_load"])
        self.assertIn("pipeline-invariance check", ls["why"])

    def test_the_epochs_and_sizes_match_the_p3_curves(self):
        lc = p3_prereg.load()["learning_curve"]
        m = P.load()["models"]["view_gru"]
        self.assertEqual((m["epochs"], m["hidden"], m["layers"]), (lc["epochs"], lc["hidden"], lc["layers"]))

    def test_probes(self):
        pr = P.load()["probes"]
        self.assertEqual(pr["gate_v2"], ["ua_swap", "uri_bijection_class", "sid_swap", "time_offset", "server_load"])
        self.assertEqual(pr["gate_p5c"], ["ua_swap", "uri_bijection", "time_offset", "server_load"])
        self.assertEqual((pr["exact_tol"], pr["flip_tol"], pr["load_factor"], pr["max_windows"]),
                         (1e-5, 0.05, 10.0, 2000))
        self.assertIn("approved with the design (D-V5, 2026-10-30)", pr["change"])

    def test_selection(self):
        s = P.selection()
        self.assertEqual(s["budget"], 0.01)
        self.assertEqual(s["ties"], ["fewer benign units flagged",
                                     "lower median time to decision of the caught attack entities", "grid order"])
        self.assertEqual(s["arms"], list(P.ARMS))

    def test_the_grids_and_budget_are_p3s(self):
        lc = p3_prereg.load()["learning_curve"]
        s = P.selection()
        self.assertEqual((s["theta_grid"], s["k_grid"], s["budget"]),
                         (lc["theta_grid"], lc["k_grid"], lc["benign_budget"]))

    def test_engine(self):
        e = P.load()["engine"]
        self.assertTrue(e["observe_only"])
        self.assertEqual((e["min_views"], e["max_records_per_key"], e["max_new_windows_per_key_per_poll"],
                          e["evict_every_s"], e["contamination_max"]), (4, 2048, 4, 5.0, 0.5))


class ConsistencyCheckTest(unittest.TestCase):
    def _load_altered(self, change):
        with open(P.PREREG_PATH, encoding="utf-8") as fh:
            pre = json.load(fh)
        pre = copy.deepcopy(pre)
        change(pre)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "prereg.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(pre, fh)
            return P.load(path)

    def test_refuses_the_random_uri_probe_in_the_v2_gate(self):
        def change(pre):
            pre["probes"]["gate_v2"] = ["ua_swap", "uri_bijection", "time_offset", "server_load"]
        with self.assertRaises(P.PreregError):
            self._load_altered(change)

    def test_refuses_server_timing_at_the_request_level(self):
        def change(pre):
            pre["request_level"]["groups"].append("server_timing")
        with self.assertRaises(P.PreregError):
            self._load_altered(change)

    def test_refuses_the_sid_as_a_feature(self):
        def change(pre):
            pre["keying"]["sid_is_a_feature"] = True
        with self.assertRaises(P.PreregError):
            self._load_altered(change)

    def test_refuses_an_unsorted_grid(self):
        def change(pre):
            pre["selection"]["k_grid"] = [3, 1, 2]
        with self.assertRaises(P.PreregError):
            self._load_altered(change)

    def test_refuses_another_format(self):
        def change(pre):
            pre["format"] = "l7v2-model-prereg/0"
        with self.assertRaises(P.PreregError):
            self._load_altered(change)


if __name__ == "__main__":
    unittest.main()
