"""The P1 verdict code (ml/l7v2_verdict.py; docs/L7V2_DESIGN.md section 11, ml/l7v2_verdict_prereg.json): synthetic
fixtures for V-A, V-B, V-C, V-D and inconclusive, each reachable and each made unreachable by one change, the contrasts
(the GRU vs R*, vs the HGB, vs the shuffled-GRU, vs the age-only arm), the open choices reported rather than picked, and
the refusals. Offline and pure; no evaluation data exists."""
import copy
import os
import sys
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7v2_verdict as J
import l7v2_verdict_prereg as P

BLOCKS = 10
PER_BLOCK = 30


def fixture(cls="C3b", q=None, recall=None, *, admitted=True, budget=None, age_auc=0.52, structured=True,
            noise=0.8, record="frozen", val_recall=None):
    """One class's inputs: Q per block around the given means (seeded noise), nested caught sets per arm at the given
    recalls over the same attack entities, every budget met unless given."""
    live = P.load()["live_set"]["per_class"][cls]
    q = {"U": 40.0, **(q or {})}
    harm = {}
    for i, a in enumerate(live):
        rng = np.random.default_rng(100 + i)
        harm[a] = list(q.get(a, 50.0) + rng.normal(0.0, noise, BLOCKS))
    recall = {"view_gru": 0.9, "hgb": 0.6, "gru_shuffled": 0.6, "R*": 0.5, "age_only": 0.3, **(recall or {})}
    u = np.random.default_rng(7).random(BLOCKS * PER_BLOCK)
    caught = {a: list((u < r).astype(int)) for a, r in recall.items()}
    ok = {a: (0, 1200) for a in live if a != "U"}
    return {"record_status": record, "frozen": {"selection_sha256": "a" * 64, "rules_selection_sha256": "b" * 64},
            "admitted": admitted, "harm": harm, "budget": budget or {"replay": dict(ok), "live": dict(ok)},
            "detection": {"blocks": [b for b in range(BLOCKS) for _ in range(PER_BLOCK)], "caught": caught},
            "validation_recall": val_recall or {"view_gru": recall["view_gru"], "hgb": recall["hgb"]},
            "age_only_val_auc": age_auc, "structured_benign_model": structured}


Q_A = {"default_rules": 60.0, "R*": 70.0, "hgb": 76.0, "view_gru": 90.0}


class ContrastTest(unittest.TestCase):
    def test_harm_outcomes(self):
        base = np.full(BLOCKS, 50.0)
        jitter = np.random.default_rng(0).normal(0, 0.5, BLOCKS)
        self.assertEqual(J.harm_contrast(base + 10 + jitter, base)["outcome"], "beats")
        self.assertEqual(J.harm_contrast(base - 10 + jitter, base)["outcome"], "loses")
        self.assertEqual(J.harm_contrast(base + 1 + jitter, base)["outcome"], "equivalent")
        c = J.harm_contrast(base + 3 + 12 * jitter, base)
        self.assertEqual(c["outcome"], "not shown")
        self.assertIsNotNone(c["power_blocks"])
        # supported but below 5 pp, with a narrow interval: equivalent, never beats
        self.assertEqual(J.harm_contrast(base + 4 + jitter, base)["outcome"], "equivalent")
        self.assertEqual(J.harm_contrast((base + 10 + jitter)[:9], base[:9])["outcome"], "not shown")

    def test_detection_outcomes_and_reproducibility(self):
        blocks = [b for b in range(BLOCKS) for _ in range(PER_BLOCK)]
        u = np.random.default_rng(7).random(len(blocks))
        hi, lo = (u < 0.9).astype(int), (u < 0.6).astype(int)
        c = J.detection_contrast(blocks, hi, lo)
        self.assertEqual(c["outcome"], "beats")
        self.assertEqual(c, J.detection_contrast(blocks, hi, lo))
        self.assertEqual(J.detection_contrast(blocks, lo, hi)["outcome"], "loses")
        self.assertEqual(J.detection_contrast(blocks, hi, hi)["outcome"], "equivalent")
        near = lo.copy()
        near[np.flatnonzero(lo == 0)[:27]] = 1                  # exactly 9 pp more: below 10, interval past 10
        c = J.detection_contrast(blocks, near, lo)
        self.assertEqual((c["diff_pp"], c["outcome"]), (9.0, "not shown"))
        with self.assertRaises(J.VerdictError):
            J.detection_contrast(blocks, hi, lo[:-1])


class LadderTest(unittest.TestCase):
    def verdict(self, cls, inputs):
        return J.judge(cls, inputs)

    # V-A
    def test_v_a_reachable(self):
        r = self.verdict("C3b", fixture(q=Q_A))
        self.assertEqual(r["verdict"], "V-A")
        for name in ("harm view_gru vs R*", "harm view_gru vs hgb", "harm view_gru vs default_rules",
                     "detection view_gru vs hgb", "detection view_gru vs gru_shuffled",
                     "detection view_gru vs age_only (descriptive)"):
            self.assertIn(name, r["contrasts"])

    def test_v_a_unreachable(self):
        for change, inputs in (("age-confounded", fixture(q=Q_A, age_auc=0.80)),
                               ("structureless benign model", fixture(q=Q_A, structured=False)),
                               ("the GRU misses the budget", fixture(q=Q_A, budget={
                                   "replay": {"default_rules": (0, 1200), "R*": (0, 1200), "hgb": (0, 1200),
                                              "view_gru": (13, 1200)},
                                   "live": {"default_rules": (0, 1200), "R*": (0, 1200), "hgb": (0, 1200),
                                            "view_gru": (13, 1200)}})),
                               ("the shuffled-GRU keeps up", fixture(q=Q_A, recall={"gru_shuffled": 0.9}))):
            with self.subTest(change):
                self.assertNotEqual(self.verdict("C3b", inputs)["verdict"], "V-A")
        r = self.verdict("C3b", fixture(q=Q_A, age_auc=0.80))
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertTrue(any("age-confounded" in n for t in r["trace"].values() for n in t["notes"]))

    # V-B
    def test_v_b_reachable_through_the_hgb_and_through_the_shuffled_gru(self):
        q = {"default_rules": 60.0, "R*": 70.0, "hgb": 85.0, "view_gru": 86.0}
        self.assertEqual(self.verdict("C3b", fixture(q=q, recall={"view_gru": 0.8, "hgb": 0.8}))["verdict"], "V-B")
        self.assertEqual(self.verdict("C3b", fixture(q=q, recall={"gru_shuffled": 0.88}))["verdict"], "V-B")

    def test_v_b_unreachable_when_learning_does_not_beat_r_star(self):
        q = {"default_rules": 60.0, "R*": 84.0, "hgb": 85.0, "view_gru": 86.0}
        r = self.verdict("C3b", fixture(q=q, recall={"view_gru": 0.8, "hgb": 0.8}))
        self.assertEqual(r["verdict"], "V-C")

    # V-C
    def test_v_c_reachable(self):
        self.assertEqual(self.verdict("C2", fixture("C2", q={"R*": 80.0, "view_gru": 81.0}))["verdict"], "V-C")

    def test_v_c_unreachable_when_the_gru_beats_r_star(self):
        r = self.verdict("C2", fixture("C2", q={"R*": 70.0, "view_gru": 90.0}))
        self.assertEqual(r["verdict"], "V-A")
        self.assertNotEqual(self.verdict("C2", fixture("C2", q={"R*": 70.0, "view_gru": 90.0},
                                                       recall={"hgb": 0.9}))["verdict"], "V-C")

    # V-D
    def test_v_d_reachable_three_ways(self):
        no_mitigation = fixture("C3a")
        no_mitigation["harm"]["R*"] = list(no_mitigation["harm"]["U"])
        no_mitigation["harm"]["view_gru"] = list(no_mitigation["harm"]["U"])
        none = {"replay": {"R*": (13, 1200), "view_gru": (20, 1200)}, "live": {"R*": (13, 1200),
                                                                             "view_gru": (20, 1200)}}
        for why, inputs in (("no admission", fixture("C3a", q={"R*": 70.0, "view_gru": 90.0}, admitted=False)),
                            ("no budget", fixture("C3a", q={"R*": 70.0, "view_gru": 90.0}, budget=none)),
                            ("no mitigation", no_mitigation)):
            with self.subTest(why):
                self.assertEqual(self.verdict("C3a", inputs)["verdict"], "V-D")

    def test_v_d_unreachable_when_admitted_within_budget_and_mitigated(self):
        self.assertNotEqual(self.verdict("C3a", fixture("C3a", q={"R*": 70.0, "view_gru": 90.0}))["verdict"], "V-D")

    # inconclusive
    def test_inconclusive_reachable_with_power(self):
        r = self.verdict("C2", fixture("C2", q={"R*": 70.0, "view_gru": 73.0}, noise=6.0))
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertIsNotNone(r["contrasts"]["harm view_gru vs R*"]["power_blocks"])

    def test_inconclusive_unreachable_when_a_rung_holds(self):
        for cls, inputs in (("C3b", fixture(q=Q_A)), ("C2", fixture("C2", q={"R*": 80.0, "view_gru": 81.0}))):
            self.assertNotEqual(self.verdict(cls, inputs)["verdict"], "inconclusive")

    # the open choices
    def test_oc4_decides_when_r_star_beats_the_learned_arms(self):
        r = self.verdict("C2", fixture("C2", q={"R*": 90.0, "view_gru": 70.0}))
        self.assertIsNone(r["verdict"])
        self.assertEqual(r["verdicts_under_options"], ["V-C", "inconclusive"])
        self.assertEqual(r["deciding_choices"], ["OC-4"])

    def test_oc1_decides_when_the_learned_arms_disagree(self):
        q = {"default_rules": 50.0, "R*": 60.0, "hgb": 75.0, "view_gru": 62.0}
        r = self.verdict("C3b", fixture(q=q, recall={"view_gru": 0.5, "hgb": 0.5},
                                        val_recall={"view_gru": 0.9, "hgb": 0.5}))
        self.assertIsNone(r["verdict"])
        self.assertEqual(r["verdicts_under_options"], ["V-B", "V-C"])
        self.assertEqual(r["deciding_choices"], ["OC-1"])

    def test_oc2_and_oc3_decide_only_where_they_matter(self):
        bud = {"replay": {"default_rules": (0, 1200), "R*": (0, 1200), "hgb": (0, 1200), "view_gru": (0, 1200)},
               "live": {"default_rules": (0, 1200), "R*": (0, 1200), "hgb": (0, 1200), "view_gru": (13, 1200)}}
        r = self.verdict("C3b", fixture(q=Q_A, budget=bud))
        self.assertEqual((r["verdict"], r["deciding_choices"]), (None, ["OC-2"]))
        q = {**Q_A, "U": 86.0}                         # the GRU beats every detector arm by 5 pp, U by 4 only
        r = self.verdict("C3b", fixture(q=q))
        self.assertEqual((r["verdict"], r["deciding_choices"]), (None, ["OC-3"]))

    def test_a_resolved_choice_is_applied(self):
        pre = copy.deepcopy(P.load())
        for c in pre["open_choices"]:
            if c["id"] == "OC-4":
                c["resolution"] = "v_c"
        r = J.judge("C2", fixture("C2", q={"R*": 90.0, "view_gru": 70.0}), pre)
        self.assertEqual(r["verdict"], "V-C")

    def test_the_effect_sizes_come_from_the_pre_registration(self):
        pre = copy.deepcopy(P.load())
        pre["effect_sizes"]["harm_beats_pp"] = 25.0
        self.assertNotEqual(J.judge("C3b", fixture(q=Q_A), pre)["verdict"], "V-A")

    # refusals
    def test_refusals(self):
        for why, inputs in (("placeholder record", fixture(q=Q_A, record="placeholder")),
                            ("measured record", fixture(q=Q_A, record="measured")),
                            ("no frozen selections", {**fixture(q=Q_A), "frozen": {}})):
            with self.subTest(why), self.assertRaises(J.VerdictError):
                J.judge("C3b", inputs)
        bad = fixture(q=Q_A)
        del bad["harm"]["R*"]
        with self.assertRaises(J.VerdictError):
            J.judge("C3b", bad)
        with self.assertRaises(J.VerdictError):
            J.judge("C4", fixture(q=Q_A))


if __name__ == "__main__":
    unittest.main()
