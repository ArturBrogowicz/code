"""The P1 verdict code (ml/l7v2_verdict.py; docs/L7V2_DESIGN.md section 11, ml/l7v2_verdict_prereg_v2.json): synthetic
fixtures for V-A, V-B, V-C, V-D and inconclusive, each reachable and each made unreachable by one change, the contrasts
(the GRU vs R*, vs the HGB, vs the shuffled-GRU, vs the age-only arm), the settled choices of D-044, C3b's primary
detection family of D-043, and the refusals. Offline and pure; no evaluation data exists."""
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
ARMS = ("view_gru", "hgb", "gru_shuffled", "R*", "age_only")


def fixture(cls="C3b", q=None, recall=None, *, admitted=True, budget=None, age_auc=0.52, structured=True,
            noise=0.8, record="frozen", val_recall=None, other_recall=None):
    """One class's inputs: Q per block around the given means (seeded noise), nested caught sets per arm at the given
    recalls over the same attack entities of the class's primary family (and, for C3b, of the families reported
    separately, at `other_recall`), every budget met unless given."""
    pre = P.load()
    live = pre["live_set"]["per_class"][cls]
    q = {"U": 40.0, **(q or {})}
    harm = {}
    for i, a in enumerate(live):
        rng = np.random.default_rng(100 + i)
        harm[a] = list(q.get(a, 50.0) + rng.normal(0.0, noise, BLOCKS))
    recall = {"view_gru": 0.9, "hgb": 0.6, "gru_shuffled": 0.6, "R*": 0.5, "age_only": 0.3, **(recall or {})}
    other = {**recall, **(other_recall or {})}
    ent = pre["detection_entities"]["per_class"][cls]
    blocks, families, caught = [], [], {a: [] for a in ARMS}
    u = iter(np.random.default_rng(7).random(BLOCKS * PER_BLOCK * 4))
    for b in range(BLOCKS):
        for fam, n, rates in [(ent["primary"][0], PER_BLOCK, recall),
                              *[(f, 10, other) for f in ent["reported_separately"]]]:
            for _ in range(n):
                x = next(u)
                blocks.append(b)
                families.append(fam)
                for a in ARMS:
                    caught[a].append(int(x < rates[a]))
    ok = {a: (0, 1200) for a in live if a != "U"}
    return {"record_status": record, "frozen": {"selection_sha256": "a" * 64, "rules_selection_sha256": "b" * 64},
            "admitted": admitted, "harm": harm, "budget": budget or {"replay": dict(ok), "live": dict(ok)},
            "detection": {"blocks": blocks, "families": families, "caught": caught},
            "validation_recall": val_recall or {"view_gru": recall["view_gru"], "hgb": recall["hgb"]},
            "age_only_val_auc": age_auc, "structured_benign_model": structured}


def over_budget(live=("view_gru",), replay=(), arms=("default_rules", "R*", "hgb", "view_gru")):
    return {"live": {a: ((13 if a in live else 0), 1200) for a in arms},
            "replay": {a: ((13 if a in replay else 0), 1200) for a in arms}}


Q_A = {"default_rules": 60.0, "R*": 70.0, "hgb": 76.0, "view_gru": 90.0}


def with_resolution(cid, option):
    pre = copy.deepcopy(P.load())
    for c in pre["choices"]:
        if c["id"] == cid:
            c["resolution"] = option
    return pre


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
    # V-A
    def test_v_a_reachable(self):
        r = J.judge("C3b", fixture(q=Q_A))
        self.assertEqual(r["verdict"], "V-A")
        self.assertEqual(r["resolutions"], {"OC-1": "validation", "OC-2": "live", "OC-3": "with_u", "OC-4": "v_c"})
        for name in ("harm view_gru vs R*", "harm view_gru vs hgb", "harm view_gru vs default_rules",
                     "harm view_gru vs U", "detection view_gru vs hgb", "detection view_gru vs gru_shuffled",
                     "detection view_gru vs age_only (descriptive)"):
            self.assertIn(name, r["contrasts"])

    def test_v_a_unreachable(self):
        for change, inputs in (("age-confounded", fixture(q=Q_A, age_auc=0.80)),
                               ("structureless benign model", fixture(q=Q_A, structured=False)),
                               ("the GRU misses the budget", fixture(q=Q_A, budget=over_budget())),
                               ("the shuffled-GRU keeps up", fixture(q=Q_A, recall={"gru_shuffled": 0.9}))):
            with self.subTest(change):
                self.assertNotEqual(J.judge("C3b", inputs)["verdict"], "V-A")
        r = J.judge("C3b", fixture(q=Q_A, age_auc=0.80))
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertTrue(any("age-confounded" in n for n in r["notes"]))

    # V-B
    def test_v_b_reachable_through_the_hgb_and_through_the_shuffled_gru(self):
        q = {"default_rules": 60.0, "R*": 70.0, "hgb": 85.0, "view_gru": 86.0}
        self.assertEqual(J.judge("C3b", fixture(q=q, recall={"view_gru": 0.8, "hgb": 0.8}))["verdict"], "V-B")
        self.assertEqual(J.judge("C3b", fixture(q=q, recall={"gru_shuffled": 0.88}))["verdict"], "V-B")

    def test_v_b_unreachable_when_learning_does_not_beat_r_star(self):
        q = {"default_rules": 60.0, "R*": 84.0, "hgb": 85.0, "view_gru": 86.0}
        self.assertEqual(J.judge("C3b", fixture(q=q, recall={"view_gru": 0.8, "hgb": 0.8}))["verdict"], "V-C")

    # V-C
    def test_v_c_reachable(self):
        self.assertEqual(J.judge("C2", fixture("C2", q={"R*": 80.0, "view_gru": 81.0}))["verdict"], "V-C")

    def test_v_c_unreachable_when_the_gru_beats_r_star(self):
        self.assertEqual(J.judge("C2", fixture("C2", q={"R*": 70.0, "view_gru": 90.0}))["verdict"], "V-A")
        self.assertNotEqual(J.judge("C2", fixture("C2", q={"R*": 70.0, "view_gru": 90.0},
                                                  recall={"hgb": 0.9}))["verdict"], "V-C")

    # V-D
    def test_v_d_reachable_three_ways(self):
        no_mitigation = fixture("C3a")
        no_mitigation["harm"]["R*"] = list(no_mitigation["harm"]["U"])
        no_mitigation["harm"]["view_gru"] = list(no_mitigation["harm"]["U"])
        none = over_budget(live=("R*", "view_gru"), arms=("R*", "view_gru"))
        for why, inputs in (("no admission", fixture("C3a", q={"R*": 70.0, "view_gru": 90.0}, admitted=False)),
                            ("no budget", fixture("C3a", q={"R*": 70.0, "view_gru": 90.0}, budget=none)),
                            ("no mitigation", no_mitigation)):
            with self.subTest(why):
                self.assertEqual(J.judge("C3a", inputs)["verdict"], "V-D")

    def test_v_d_unreachable_when_admitted_within_budget_and_mitigated(self):
        self.assertNotEqual(J.judge("C3a", fixture("C3a", q={"R*": 70.0, "view_gru": 90.0}))["verdict"], "V-D")

    # inconclusive
    def test_inconclusive_reachable_with_power(self):
        r = J.judge("C2", fixture("C2", q={"R*": 70.0, "view_gru": 73.0}, noise=6.0))
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertIsNotNone(r["contrasts"]["harm view_gru vs R*"]["power_blocks"])

    def test_inconclusive_unreachable_when_a_rung_holds(self):
        for cls, inputs in (("C3b", fixture(q=Q_A)), ("C2", fixture("C2", q={"R*": 80.0, "view_gru": 81.0}))):
            self.assertNotEqual(J.judge(cls, inputs)["verdict"], "inconclusive")


class SettledChoicesTest(unittest.TestCase):
    """D-044: the file decides; a mutated copy shows each branch is read from it."""

    def test_oc1_the_best_learned_arm_comes_from_validation(self):
        q = {"default_rules": 50.0, "R*": 60.0, "hgb": 75.0, "view_gru": 62.0}
        rec = {"view_gru": 0.5, "hgb": 0.5}
        # the HGB leads on evaluation Q, the GRU on validation: the GRU is judged, and it is equivalent to R*
        r = J.judge("C3b", fixture(q=q, recall=rec, val_recall={"view_gru": 0.9, "hgb": 0.5}))
        self.assertEqual(r["verdict"], "V-C")
        self.assertIn("view_gru", r["steps"][2][1])
        r = J.judge("C3b", fixture(q=q, recall=rec, val_recall={"view_gru": 0.5, "hgb": 0.9}))
        self.assertEqual(r["verdict"], "V-B")
        self.assertIn("hgb", r["steps"][2][1])
        # ties go to the GRU
        r = J.judge("C3b", fixture(q=q, recall=rec, val_recall={"view_gru": 0.7, "hgb": 0.7}))
        self.assertIn("view_gru", r["steps"][2][1])
        pre = with_resolution("OC-1", "eval_q")
        r = J.judge("C3b", fixture(q=q, recall=rec, val_recall={"view_gru": 0.9, "hgb": 0.5}), pre)
        self.assertIn("hgb", r["steps"][2][1])

    def test_oc1_needs_both_validation_recalls(self):
        inputs = fixture(q=Q_A)
        inputs["validation_recall"] = {"view_gru": 0.9}
        with self.assertRaises(J.VerdictError):
            J.judge("C3b", inputs)

    def test_oc2_the_live_budget_judges_and_the_replay_is_reported_beside_it(self):
        r = J.judge("C3b", fixture(q=Q_A, budget=over_budget(live=(), replay=("view_gru",))))
        self.assertEqual(r["verdict"], "V-A")
        self.assertFalse(r["budget"]["replay"]["view_gru"]["meets"])
        self.assertTrue(r["budget"]["live"]["view_gru"]["meets"])
        r = J.judge("C3b", fixture(q=Q_A, budget=over_budget(live=("view_gru",), replay=())))
        self.assertEqual(r["verdict"], "inconclusive")
        self.assertTrue(any("misses the budget" in n for n in r["notes"]))

    def test_oc3_u_is_a_live_baseline_of_v_a(self):
        inputs = fixture(q={**Q_A, "U": 86.0})              # the GRU beats every detector arm by 5 pp, U by 4 only
        self.assertEqual(J.judge("C3b", inputs)["verdict"], "inconclusive")
        self.assertEqual(J.judge("C3b", inputs, with_resolution("OC-3", "detectors_only"))["verdict"], "V-A")

    def test_oc4_rules_suffice_or_win(self):
        inputs = fixture("C2", q={"R*": 90.0, "view_gru": 70.0})
        r = J.judge("C2", inputs)
        self.assertEqual(r["verdict"], "V-C")
        self.assertTrue(any("R* beats" in n for n in r["notes"]))
        self.assertEqual(J.judge("C2", inputs, with_resolution("OC-4", "inconclusive"))["verdict"], "inconclusive")

    def test_the_effect_sizes_come_from_the_pre_registration(self):
        pre = copy.deepcopy(P.load())
        pre["effect_sizes"]["harm_beats_pp"] = 25.0
        self.assertNotEqual(J.judge("C3b", fixture(q=Q_A), pre)["verdict"], "V-A")


class DetectionEntitiesTest(unittest.TestCase):
    """D-043, E-3: C3b's contrasts read C3b@M2; M1, M3 and M2exp are reported separately and judge nothing."""

    def test_the_families_reported_separately_judge_nothing(self):
        # equal on M2, the GRU far ahead on the others: still V-B
        r = J.judge("C3b", fixture(q={"default_rules": 60.0, "R*": 70.0, "hgb": 85.0, "view_gru": 86.0},
                                   recall={"view_gru": 0.6, "hgb": 0.6, "gru_shuffled": 0.6},
                                   other_recall={"view_gru": 0.95, "hgb": 0.2, "gru_shuffled": 0.2}))
        self.assertEqual(r["verdict"], "V-B")
        self.assertEqual(r["contrasts"]["detection view_gru vs hgb"]["entities"], BLOCKS * PER_BLOCK)
        self.assertEqual(set(r["reported_separately"]), {"C3b@M1", "C3b@M3", "C3b@M2exp"})
        self.assertEqual(r["reported_separately"]["C3b@M3"]["detection view_gru vs hgb"]["outcome"], "beats")
        # ahead on M2, equal on the others: still V-A
        r = J.judge("C3b", fixture(q=Q_A, other_recall={"view_gru": 0.6, "hgb": 0.6, "gru_shuffled": 0.6}))
        self.assertEqual(r["verdict"], "V-A")
        self.assertEqual(r["reported_separately"]["C3b@M1"]["detection view_gru vs hgb"]["outcome"], "equivalent")

    def test_a_family_no_contrast_reads_is_refused(self):
        inputs = fixture("C2", q={"R*": 70.0, "view_gru": 90.0})
        inputs["detection"]["families"][0] = "C3a"
        with self.assertRaises(J.VerdictError):
            J.judge("C2", inputs)


class RefusalTest(unittest.TestCase):
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
