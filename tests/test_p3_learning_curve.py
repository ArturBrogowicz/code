"""The learning-curve runner (docs/P3_DATASET_DESIGN.md §6): nested stratified subsets, the replicate plan, the
two-level bootstrap and the decision rules on synthetic fixtures ("flattened", "still learning", "ranking", "no
ranking"), and a tiny end-to-end run in both data modes. Offline, CPU, temporary directories."""
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p3_fixtures as FX

sys.path.insert(0, os.path.join(FX.REPO, "ml"))
import learning_curve as LC
import p3_prereg
import torch
from test_l7_train import synth_dataset

torch.set_num_threads(1)
RULES = p3_prereg.load()["learning_curve"]
FR = [0.1, 0.25, 0.5, 1.0]


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def w(ent, cls, kof, cap="c1"):
    return {"ip": ent, "cls": cls, "kof": kof, "capture": cap}


class DesignTest(unittest.TestCase):
    def test_nested_and_stratified(self):
        ws = [w(f"b{i}", "benign", "browse" if i % 2 else "api") for i in range(40)]
        ws += [w(f"a{i}", "attack", "flood") for i in range(9)] + [w("s0", "attack", "slow")]
        subs = LC.nested_subsets(ws, FR, 7)
        for lo, hi in itertools.pairwise(FR):
            self.assertTrue(subs[lo] <= subs[hi], (lo, hi))
        self.assertIn("s0", subs[0.1])                         # >= 1 per stratum
        self.assertEqual(len(subs[1.0]), 50)
        self.assertEqual(len([e for e in subs[0.1] if e.startswith("b")]), 4)    # ceil(0.1 x 20) per kind
        self.assertEqual(subs, LC.nested_subsets(ws, FR, 7))
        self.assertNotEqual(subs[0.5], LC.nested_subsets(ws, FR, 8)[0.5])

    def test_fit_plan_is_fifteen_fits_per_fraction(self):
        plan = LC.fit_plan(RULES["fractions"], RULES["draws"], RULES["inits"], RULES["full_inits"])
        for f in RULES["fractions"]:
            self.assertEqual(sum(1 for x in plan if x[0] == f), 15, f)
        self.assertEqual({x[1] for x in plan if x[0] == 1.0}, {0})          # one draw at 100 %

    def test_shuffle_permutes_valid_rows_only(self):
        X = np.zeros((6, 3), dtype=np.float32)
        X[2:, 0] = 1
        X[2:, 1] = [1, 2, 3, 4]
        out = LC.shuffled([{"X": X, "ip": "e"}], 3)[0]["X"]
        self.assertTrue((out[:2] == 0).all())
        self.assertEqual(sorted(out[2:, 1]), [1, 2, 3, 4])
        self.assertEqual(X[2:, 1].tolist(), [1, 2, 3, 4])                  # the input is untouched


class BootstrapTest(unittest.TestCase):
    def test_two_level_weights_and_paired_differences(self):
        units = [(f"e{i}", "c1" if i < 5 else "c2", "f") for i in range(8)]
        rng = np.random.default_rng(0)
        ws = [LC.entity_weights(units, rng) for _ in range(50)]
        self.assertTrue(all(x.sum() in (6, 8, 10) for x in ws))           # 2 captures of 5 and 3 entities
        m = np.array([[1, 1, 1, 1, 0, 0, 0, 0]] * 3, dtype=float)
        st = LC.bootstrap({"a": m, "b": m.copy()}, units, 200, 1, pairs=[("a", "b")])
        self.assertEqual(st["a"][0], 0.5)
        self.assertEqual(st[("a", "b")], (0.0, 0.0, 0.0))
        self.assertLessEqual(st["a"][1], 0.5)
        self.assertGreaterEqual(st["a"][2], 0.5)
        self.assertEqual(LC.bootstrap({"a": m}, units, 50, 5), LC.bootstrap({"a": m}, units, 50, 5))


def stats_for(curves, diffs):
    """curves: {model: {fraction: (est, lo, hi)}}; diffs: {(a, b): (est, lo, hi)} at 100 %."""
    st = {}
    for m, c in curves.items():
        for f, v in c.items():
            st[(m, f)] = v
        for f in FR[:-1]:
            e = c[1.0][0] - c[f][0]
            st[((m, 1.0), (m, f))] = (e, e - 0.02, e + 0.02)
    for (a, b), v in diffs.items():
        st[((a, 1.0), (b, 1.0))] = v
    for m in curves:
        for n in curves:
            st.setdefault(((m, 1.0), (n, 1.0)), (0.0, -0.05, 0.05))
    return st


FLAT = {0.1: (0.9, 0.85, 0.95), 0.25: (0.9, 0.85, 0.95), 0.5: (0.9, 0.85, 0.95), 1.0: (0.9, 0.85, 0.95)}
LOW_FLAT = {f: (0.6, 0.55, 0.65) for f in FR}
RISING = {0.1: (0.3, 0.2, 0.4), 0.25: (0.45, 0.4, 0.5), 0.5: (0.6, 0.55, 0.65), 1.0: (0.8, 0.75, 0.85)}


class DecisionRuleFixtureTest(unittest.TestCase):
    models = ("gru", "hgb")

    def test_flattened(self):
        d = LC.decide(stats_for({"gru": FLAT, "hgb": FLAT}, {}), self.models, FR, RULES)
        self.assertEqual(d["curves"]["gru"]["flattened_at"], [0.1, 0.25, 0.5])
        self.assertFalse(d["curves"]["gru"]["still_learning"])
        self.assertEqual(d["verdict"], "no ranking")
        self.assertFalse(LC.flattened((0.0, -0.01, 0.06), RULES["flatten_pp"]))     # upper bound >= 5 pp
        self.assertFalse(LC.flattened((0.03, 0.01, 0.04), RULES["flatten_pp"]))     # excludes 0

    def test_still_learning_blocks_every_ranking(self):
        st = stats_for({"gru": RISING, "hgb": LOW_FLAT}, {("gru", "hgb"): (0.2, 0.1, 0.3)})
        d = LC.decide(st, self.models, FR, RULES)
        self.assertTrue(d["curves"]["gru"]["still_learning"])
        self.assertEqual(d["rankings"], [])
        self.assertTrue(d["verdict"].startswith("still learning"))

    def test_ranking(self):
        st = stats_for({"gru": FLAT, "hgb": LOW_FLAT}, {("gru", "hgb"): (0.3, 0.2, 0.4)})
        d = LC.decide(st, self.models, FR, RULES)
        self.assertEqual([(r["winner"], r["loser"]) for r in d["rankings"]], [("gru", "hgb")])
        self.assertEqual(d["verdict"], "ranking: gru > hgb")

    def test_no_ranking_below_ten_points_or_with_zero_in_the_interval(self):
        for diff in ((0.08, 0.03, 0.13), (0.15, -0.01, 0.3)):
            st = stats_for({"gru": FLAT, "hgb": LOW_FLAT}, {("gru", "hgb"): diff})
            self.assertEqual(LC.decide(st, self.models, FR, RULES)["verdict"], "no ranking", diff)

    def test_sequence_helps_is_reported(self):
        st = stats_for({"gru": FLAT, "gru_shuffled": LOW_FLAT}, {})
        for f in FR:
            st[(("gru", f), ("gru_shuffled", f))] = (0.3, 0.2, 0.4)
        d = LC.decide(st, ("gru", "gru_shuffled"), FR, RULES)
        self.assertTrue(d["sequence_helps"]["1.0"]["meets_pp"])
        self.assertEqual(d["rankings"], [])                     # the order ablation is no model ranking


TINY = {"fractions": [0.5, 1.0], "draws": 1, "inits": 1, "full_inits": 2, "epochs": 1, "hidden": 8, "layers": 1,
        "B": 20, "threads": 1}


class SelectThenScoreTest(unittest.TestCase):
    """Review T-029 P3-03: evaluation is scored only by `score`, only with the frozen selection file whose sha256
    the caller recorded, and (P3) only after the checker's rule 10 has compared the split file with it."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="p3lc_")
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_legacy_capture_select_then_score(self):
        d = os.path.join(self.root, "ds")
        synth_dataset(d, n_benign=6, n_attack=3, held_benign=1)
        cols = LC.F.columns(LC.T.variant_groups()[LC.VARIANT])
        sets = LC.legacy_sets(d, cols, LC.T.DEFAULT_SEQ, LC.T.DEFAULT_STRIDE)
        sel_dir = os.path.join(self.root, "sel")
        sel, sha = LC.select({"train": sets["train"], "val": sets["val"]}, sel_dir, valid_for_claims=False,
                             source="fixture", split_sha256=LC.legacy_split_sha256(sets), **TINY)
        path = os.path.join(sel_dir, "selection.json")
        with open(os.path.join(sel_dir, "selection.sha256"), encoding="utf-8") as fh:
            self.assertEqual(fh.read().split()[0], sha)
        self.assertEqual(len(sel["fits"]), 4 * 3)                # (1 + 2 fits) x 4 models
        self.assertTrue(all(f["artifact_sha256"] for f in sel["fits"]))
        for bad in (None, "0" * 64):
            with self.assertRaises(LC.SelectionError):
                LC.load_selection(path, bad)
        res = LC.score(sets["eval"], LC.load_selection(path, sha), path, os.path.join(self.root, "out"),
                       threads=1)
        self.assertFalse(res["valid_for_claims"])
        self.assertTrue(res["decision"]["verdict"].startswith("NOT A RESULT"))
        self.assertEqual(res["selection_sha256"], sha)
        saved = read_json(os.path.join(self.root, "out", "curve.json"))
        self.assertEqual(saved["format"], LC.FORMAT)
        self.assertIn("gru@1.0", saved["estimates"])
        self.assertIn("| gru | 1.0 |", LC.summary_md(res))
        # D-040 (T042-F01): the (IP, UA)-key age-only baseline beside the curves, and the label it sets
        age = sel["age_only_ip_ua"]
        self.assertIn(age["reading"], ("near chance", "age-assisted"))
        self.assertEqual(age["reading"] == "near chance",
                         age["val_auc"] is not None and abs(age["val_auc"] - 0.5) <= 0.15)
        self.assertEqual(sel["label"], None if age["reading"] == "near chance" else "age-assisted")
        self.assertEqual(res["age_only_ip_ua"]["reading"], age["reading"])
        self.assertIn("eval_recall", res["age_only_ip_ua"])
        self.assertIn("age-only baseline (D-040)", LC.summary_md(res))
        art = os.path.join(sel_dir, sel["fits"][0]["artifact"])
        with open(art, "ab") as fh:                              # an altered model is refused
            fh.write(b"x")
        with self.assertRaises(LC.SelectionError):
            LC.load_selection(path, sha)

    def test_the_ip_ua_key_age_and_the_age_assisted_label(self):
        d = os.path.join(self.root, "ds")
        synth_dataset(d, n_benign=6, n_attack=3, held_benign=1)
        cols = LC.F.columns(LC.T.variant_groups()[LC.VARIANT])
        sets = LC.legacy_sets(d, cols, LC.T.DEFAULT_SEQ, LC.T.DEFAULT_STRIDE)
        ws = [w for s in sets.values() for w in s]
        self.assertTrue(ws and all(w["age"] >= 0 for w in ws))
        for w in ws:                                 # the key started no later than the window's first request
            self.assertGreaterEqual(w["age"], LC.F.start_time(w["recs"][-1]) - LC.F.start_time(w["recs"][0]) - 1e-9)
        sel_path = os.path.join(self.root, "sel.json")
        with open(sel_path, "w", encoding="utf-8") as fh:
            fh.write("{}")
        sel = {"source": "fixture", "valid_for_claims": True, "variant": LC.VARIANT, "split_sha256": "0" * 64,
               "design": {"fractions": [1.0], "bootstrap_b": 10}, "counts": {}, "label": "age-assisted",
               "age_only_ip_ua": {"val_auc": 0.81}}
        res = LC._curve_result([], [], sel, sel_path, os.path.join(self.root, "o"), LC.p3_prereg.load()["learning_curve"],
                               0, 0.0, 0)
        self.assertTrue(res["decision"]["verdict"].startswith("AGE-ASSISTED"), res["decision"])
        self.assertEqual(res["label"], "age-assisted")
        sel["label"] = None
        res = LC._curve_result([], [], sel, sel_path, os.path.join(self.root, "o2"),
                               LC.p3_prereg.load()["learning_curve"], 0, 0.0, 0)
        self.assertFalse(res["decision"]["verdict"].startswith("AGE-ASSISTED"))

    def test_p3_captures_score_only_after_rule_10(self):
        V = "2026-11-t1"
        vdir = os.path.join(self.root, V)
        tr = [FX.capture(vdir, V, s, "train", FX.entities(V, s))[0] for s in (1001, 1002)]
        va = [FX.capture(vdir, V, 2001, "val", FX.entities(V, 2001))[0]]
        ev = [FX.capture(vdir, V, 3201, "eval", FX.entities(V, 3201), started="2026-11-03T10:00:00Z",
                         ended="2026-11-03T10:17:00Z")[0]]
        sel_dir, out = os.path.join(self.root, "sel"), os.path.join(self.root, "out")
        data = ["--train", *tr, "--val", *va, "--eval", *ev, "--threads", "1"]
        loaded = []
        real = LC.T.load_records

        def spy(d):
            loaded.append(os.path.abspath(d))
            return real(d)
        with mock.patch.object(LC.T, "load_records", spy):
            self.assertEqual(LC.main(["select", *data, "--out", sel_dir, "--smoke"]), 0)
        self.assertNotIn(os.path.abspath(ev[0]), loaded)          # select opened no evaluation log
        path = os.path.join(sel_dir, "selection.json")
        with open(os.path.join(sel_dir, "selection.sha256"), encoding="utf-8") as fh:
            sha = fh.read().split()[0]
        with self.assertRaises(LC.SelectionError):
            LC.main(["score", *data, "--out", out, "--selection", path, "--selection-sha256", "f" * 64])
        with self.assertRaises(SystemExit):
            LC.main(["score", *data, "--out", out])
        self.assertEqual(LC.main(["score", *data, "--out", out, "--selection", path, "--selection-sha256", sha]), 0)
        self.assertEqual(read_json(os.path.join(out, "curve.json"))["eval_attack_entities"], 4)
        split = os.path.join(sel_dir, "split.json")
        with open(split, "ab") as fh:                            # the split changed after the freeze
            fh.write(b" ")
        import l7_disjoint
        with self.assertRaises(l7_disjoint.DisjointnessError) as ctx:
            LC.main(["score", *data, "--out", out, "--selection", path, "--selection-sha256", sha])
        self.assertIn("\n  10 ", str(ctx.exception))
        bad = subprocess.run([sys.executable, os.path.join(FX.REPO, "ml", "learning_curve.py"), "select",
                              "--train", *tr, "--val", *va, "--eval", tr[0], "--out", os.path.join(self.root, "x")],
                             capture_output=True, text=True, check=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("refusing to fit", bad.stderr)


if __name__ == "__main__":
    unittest.main()
