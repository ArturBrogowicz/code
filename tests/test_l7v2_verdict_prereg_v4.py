"""The verdict pre-registration re-registered by D-051, D-053 and D-054 (ml/l7v2_verdict_prereg_v4.json, before any capture): every
value is pinned here, so a change shows up as a failing test and must become a new file version. Offline and pure."""
import hashlib
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.join(REPO, "eval"))
import l7v2_model_prereg
import p3_prereg
import run_level_stats

PATH = os.path.join(REPO, "ml", "l7v2_verdict_prereg_v4.json")
SHA256 = "ed79a8e6064a300f0e0ea19b1cda87b9fdbb8c50987fe3775da88b2b19e8673a"


def pre():
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


class FrozenFileTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), SHA256)
        p = pre()
        self.assertEqual(p["format"], "l7v2-verdict-prereg/4")
        self.assertTrue(p["label"].startswith("re-registered 2026-11-03 under D-058"))
        self.assertIn("before any capture", p["label"])

    def test_d044_settles_every_choice(self):
        c = {x["id"]: x for x in pre()["choices"]}
        self.assertEqual({k: v["resolution"] for k, v in c.items()},
                         {"OC-1": "validation", "OC-2": "live", "OC-3": "with_u", "OC-4": "v_c"})
        self.assertEqual({v["decision"] for v in c.values()}, {"D-044"})
        self.assertIn("frozen in the selection before evaluation (ties: the GRU)", c["OC-1"]["options"]["validation"])
        self.assertIn("reported beside", c["OC-2"]["reported_beside"])
        self.assertIn("in its own M runs", c["OC-2"]["options"]["live"])
        self.assertNotIn("open_choices", pre())

    def test_d043_detection_entities(self):
        d = pre()["detection_entities"]["per_class"]
        self.assertEqual(d["C3b"], {"primary": ["C3b@M2"], "reported_separately": ["C3b@M1", "C3b@M3", "C3b@M2exp"]})
        self.assertEqual(d["C2"], {"primary": ["C2"], "reported_separately": []})
        self.assertEqual(d["C3a"], {"primary": ["C3a"], "reported_separately": []})
        self.assertEqual(set(d), set(pre()["classes"]))

    def test_the_ladder_and_its_order(self):
        p = pre()
        self.assertEqual([r["verdict"] for r in p["ladder"]], ["V-D", "V-A", "V-B", "V-C", "inconclusive"])
        rungs = {r["verdict"]: r for r in p["ladder"]}
        self.assertIn("U fails harm admission", rungs["V-D"]["when"])
        self.assertIn("no contender (R*, HGB, GRU) meets the budget on the evaluation seeds", rungs["V-D"]["when"])
        self.assertIn("admitted on latency alone and no live M's mean gain", rungs["V-D"]["when"])
        self.assertIn("meets the budget", rungs["V-B"]["when"])
        self.assertIn("and R* meets the budget", rungs["V-C"]["when"])
        self.assertIn("not when the best learned arm is the HGB while the GRU beats R* on harm", rungs["V-C"]["when"])
        self.assertIn("(D-058, T050-14)", rungs["inconclusive"]["when"])
        self.assertIn("inconclusive with the arm named (D-051)", rungs["inconclusive"]["when"])
        self.assertIn("beats every live baseline arm of the class on harm", rungs["V-A"]["when"])
        self.assertIn("the HGB and the shuffled-GRU on detection by >= 10 pp", rungs["V-A"]["when"])
        self.assertIn("the best learned arm beats R* on harm", rungs["V-B"]["when"])
        self.assertIn("or R* beats it on harm (OC-4: 'rules suffice or win')", rungs["V-C"]["when"])
        self.assertEqual(p["testing_order"], ["harm_admission", "budget", "mitigation", "v_a", "best_learned_vs_rstar",
                                              "gru_vs_hgb", "gru_vs_shuffled"])
        self.assertEqual(p["family_wise_alpha"], 0.05)

    def test_effect_sizes_live_set_and_r_star_are_unchanged(self):
        p = pre()
        e = p["effect_sizes"]
        self.assertEqual((e["harm_beats_pp"], e["harm_equivalence_pp"], e["detection_beats_pp"],
                          e["detection_equivalence_pp"]), (5.0, 5.0, 10.0, 10.0))
        self.assertEqual(p["live_set"]["per_class"], {"C3b": ["U", "default_rules", "R*", "hgb", "view_gru"],
                                                      "C2": ["U", "R*", "view_gru"], "C3a": ["U", "R*", "view_gru"]})
        self.assertEqual(p["live_set"]["runs_per_block"], 13)
        self.assertEqual(p["best_rule"]["candidates"], ["sustained_rate", "token_bucket", "cost_budget",
                                                        "multiscale_rate"])

    def test_units_and_statistics_restate_the_tools(self):
        p = pre()
        u, s = p["units"], p["statistics"]
        self.assertEqual(u["eval_seeds"], p3_prereg.load()["seeds"]["p1_live_eval"])
        self.assertEqual(u["min_blocks"], run_level_stats.MIN_BLOCKS)
        self.assertEqual(s["harm"]["level"], run_level_stats.LEVEL)
        self.assertEqual(s["harm"]["same_sign_share"], run_level_stats.SAME_SIGN_SHARE)
        self.assertEqual((s["detection"]["B"], s["detection"]["level"], s["detection"]["seed"]), (2000, 0.95, 20261031))
        self.assertEqual(p["blocks_on_v_a"]["age_only"]["band"],
                         l7v2_model_prereg.load()["baselines"]["age_only"]["auc_band"])

    def test_d051_the_new_rules(self):
        p = pre()
        self.assertEqual(p["arms"]["contenders"], ["R*", "hgb", "view_gru"])
        self.assertEqual((p["carriers"]["V-B"], p["carriers"]["V-C"]), ("the best learned arm", "R*"))
        self.assertEqual(p["latency_alone"]["min_mean_gain_pp"], 5.0)
        self.assertIn("every GRU contrast is computed and reported whatever the verdict", p["always_reported"]["rule"])
        readings = {r["id"]: r["text"] for r in p["readings"]}
        self.assertIn("no gate on the HGB", readings["R-3"])
        self.assertIn("at most 0.10 by the union bound", readings["R-9"])

    def test_d058_the_new_rules(self):
        p = pre()
        self.assertIn("every contrast reported", p["hgb_led_v_c"]["rule"])
        self.assertIn("invalid (k of min_blocks)", p["judged_blocks"]["rule"])

    def test_d053_and_d054_the_harm_contrast(self):
        p = pre()
        self.assertEqual(p["level_window"]["from_attack_start_s"], 90.0)
        self.assertIn("level window", p["outcomes"]["primary"]["harm"])
        self.assertIn("Q over the whole attack window", p["outcomes"]["secondary"])
        self.assertIn("keyed by block", p["statistics"]["harm"]["pairing"])


if __name__ == "__main__":
    unittest.main()
