"""The L7 v2 verdict pre-registration (ml/l7v2_verdict_prereg.json), docs/L7V2_DESIGN.md section 11 and section 13
item 4: every frozen value is pinned here, so a change shows up as a failing test and must become a new file version.
Offline and pure."""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.join(REPO, "eval"))
import l7v2_model_prereg
import l7v2_verdict_prereg as P
import p3_prereg
import run_level_stats

PREREG_SHA256 = "b92e56bd57f127d1adc459631e7bfbc4589f9c008991cddcc67fcab2154022a2"


class FrozenFileTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(P.PREREG_PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_SHA256)
        self.assertEqual(P.load()["format"], "l7v2-verdict-prereg/1")

    def test_the_ladder_and_its_order(self):
        pre = P.load()
        self.assertEqual([r["verdict"] for r in pre["ladder"]], ["V-D", "V-A", "V-B", "V-C", "inconclusive"])
        rungs = {r["verdict"]: r for r in pre["ladder"]}
        self.assertIn("U fails harm admission", rungs["V-D"]["when"])
        self.assertIn("no enforcing arm meets the budget on the evaluation seeds", rungs["V-D"]["when"])
        self.assertIn("no arm mitigates", rungs["V-D"]["when"])
        self.assertIn("beats every live baseline arm of the class on harm", rungs["V-A"]["when"])
        self.assertIn("the HGB and the shuffled-GRU on detection by >= 10 pp", rungs["V-A"]["when"])
        self.assertIn("the best learned arm beats R* on harm", rungs["V-B"]["when"])
        self.assertIn("equivalent to R* on harm", rungs["V-C"]["when"])
        self.assertIn("first rung that holds", pre["ladder_rule"])

    def test_effect_sizes(self):
        e = P.load()["effect_sizes"]
        self.assertEqual((e["harm_beats_pp"], e["harm_equivalence_pp"], e["detection_beats_pp"],
                          e["detection_equivalence_pp"]), (5.0, 5.0, 10.0, 10.0))
        self.assertIn("supported in the arm's favour", e["harm_beats"])
        self.assertIn("strictly inside", e["harm_equivalence"])
        self.assertIn("excludes 0", e["detection_beats"])

    def test_the_testing_order(self):
        pre = P.load()
        self.assertEqual(pre["testing_order"], ["harm_admission", "budget", "best_learned_vs_rstar", "gru_vs_hgb",
                                                "gru_vs_shuffled"])
        self.assertEqual(pre["family_wise_alpha"], 0.05)
        self.assertIn("fixed sequence", pre["testing_order_rule"])

    def test_the_live_set(self):
        live = P.load()["live_set"]
        self.assertEqual(live["shared"], ["C", "C'"])
        self.assertEqual(live["per_class"], {"C3b": ["U", "default_rules", "R*", "hgb", "view_gru"],
                                             "C2": ["U", "R*", "view_gru"], "C3a": ["U", "R*", "view_gru"]})
        self.assertEqual(live["runs_per_block"], 13)
        self.assertEqual(live["minimum_cut"]["runs_per_block"], 9)

    def test_r_star(self):
        b = P.load()["best_rule"]
        self.assertEqual(b["candidates"], ["sustained_rate", "token_bucket", "cost_budget", "multiscale_rate"])
        self.assertEqual(b["ties"], ["fewer benign units flagged", "lower median time to decision",
                                     "candidate order"])
        self.assertIn("validation captures only", b["data"])

    def test_units_and_statistics_restate_the_tools(self):
        pre = P.load()
        u, s = pre["units"], pre["statistics"]
        self.assertEqual(u["eval_seeds"], p3_prereg.load()["seeds"]["p1_live_eval"])
        self.assertEqual(u["min_blocks"], run_level_stats.MIN_BLOCKS)
        self.assertEqual(s["harm"]["level"], run_level_stats.LEVEL)
        self.assertEqual(s["harm"]["same_sign_share"], run_level_stats.SAME_SIGN_SHARE)
        self.assertEqual((s["power"]["power"], s["power"]["alpha"]), (run_level_stats.POWER, run_level_stats.ALPHA))
        self.assertEqual((s["detection"]["B"], s["detection"]["level"], s["detection"]["interval"],
                          s["detection"]["seed"]), (2000, 0.95, "percentile", 20261031))
        self.assertEqual(len(s["detection"]["stages"]), 2)

    def test_the_v_a_blocks_restate_their_sources(self):
        b = P.load()["blocks_on_v_a"]
        self.assertEqual(b["age_only"]["band"], l7v2_model_prereg.load()["baselines"]["age_only"]["auc_band"])
        self.assertIn("frozen calibration record", b["record"]["rule"])

    def test_open_choices_are_unresolved(self):
        pre = P.load()
        self.assertEqual([c["id"] for c in pre["open_choices"]], ["OC-1", "OC-2", "OC-3", "OC-4"])
        self.assertTrue(all(c["resolution"] is None for c in pre["open_choices"]))
        self.assertEqual(P.choice_options(), {"OC-1": ["eval_q", "validation", "gru"], "OC-2": ["replay", "live"],
                                              "OC-3": ["with_u", "detectors_only"],
                                              "OC-4": ["inconclusive", "v_c"]})
        self.assertEqual([r["id"] for r in pre["readings"]], [f"R-{i}" for i in range(1, 9)])


class ConsistencyTest(unittest.TestCase):
    def _load(self, mutate):
        pre = copy.deepcopy(P.load())
        mutate(pre)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(pre, fh)
            return P.load(path)

    def test_refuses_inconsistent_files(self):
        def reorder(p):
            p["ladder"][1], p["ladder"][2] = p["ladder"][2], p["ladder"][1]

        def drop_gru(p):
            p["live_set"]["per_class"]["C2"] = ["U", "R*"]

        def runs(p):
            p["live_set"]["runs_per_block"] = 12

        def steps(p):
            p["testing_order"] = p["testing_order"][::-1]

        def resolution(p):
            p["open_choices"][0]["resolution"] = "something else"

        def blocks(p):
            p["units"]["min_blocks"] = 8

        for mutate in (reorder, drop_gru, runs, steps, resolution, blocks):
            with self.subTest(mutate.__name__), self.assertRaises(P.PreregError):
                self._load(mutate)

    def test_a_resolved_choice_leaves_one_option(self):
        def resolve(p):
            p["open_choices"][1]["resolution"] = "replay"
        pre = self._load(resolve)
        self.assertEqual(P.choice_options(pre)["OC-2"], ["replay"])


if __name__ == "__main__":
    unittest.main()
