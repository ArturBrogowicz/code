"""The P3 learning curves at the L7 v2 view level (docs/P3_DATASET_DESIGN.md 6.1, docs/L7V2_DESIGN.md 8): the view GRU,
HGB and LR on the same view windows' token summaries, and the shuffled-GRU, through the frozen select/score split.
Offline; synthetic fixtures, one-epoch fits on two threads (mechanics only)."""
import json
import os
import shutil
import sys
import tempfile
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7v2_model_prereg as PRE
import learning_curve as LC
import train_l7v2 as V
from test_l7v2_train import population

import l7_dataset as D

DESIGN = {"fractions": [0.5, 1.0], "draws": 1, "inits": 1, "full_inits": 1, "epochs": 1, "hidden": 8, "layers": 1,
          "B": 50}


class ViewCurveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.out = os.path.join(cls.dir, "sel")
        sets = {"train": V.Split([population("t1", seed=1), population("t2", seed=2)], request=False),
                "val": V.Split([population("v1", seed=3)], request=False)}
        cls.sel, cls.sha = LC.select_view(sets, cls.out, threads=2, seed=0, valid_for_claims=False,
                                          source="synthetic fixture", split_sha256="0" * 64, **DESIGN)
        cls.path = os.path.join(cls.out, "selection.json")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def test_the_selection_is_view_level_and_frozen(self):
        sel = LC.load_selection(self.path, self.sha)
        self.assertEqual((sel["level"], sel["variant"], sel["format"]), ("view", "view", LC.SEL_FORMAT))
        self.assertEqual(sel["prereg_sha256"], V._sha_file(PRE.PREREG_PATH))
        self.assertEqual(len(sel["fits"]), len(LC.MODELS) * 2)
        for fit in sel["fits"]:
            op = fit["operating_point"]
            self.assertIsNotNone(op)
            self.assertEqual(op["budget"], 0.01)
            self.assertIn("benign_units_flagged", op)
            self.assertFalse(any(k.startswith("_") for k in op))

    def test_the_models_load_at_their_level(self):
        from l7_view_model import ViewGRU
        models = LC._load_models(self.sel, self.out)
        grus = [m for kind, m, _a, _b in models.values() if kind == "gru"]
        self.assertTrue(grus)
        self.assertTrue(all(isinstance(m, ViewGRU) for m in grus))

    def test_score_view_counts_every_attack_entity(self):
        ev = V.Split([population("e1", seed=7), population("e2", seed=8)], request=False)
        ev.attack.add("e2|silent")                                 # an attack entity without a window
        res = LC.score_view(ev, self.sel, self.path, os.path.join(self.dir, "eval"), threads=2)
        self.assertEqual(res["eval_attack_entities"], 9)
        silent = sorted(ev.attack).index("e2|silent")
        for fit in res["fits"]:
            self.assertEqual(len(fit["detected"]), 9)
            self.assertEqual(fit["detected"][silent], 0)
        self.assertIn("NOT A RESULT", res["decision"]["verdict"])
        with open(os.path.join(self.dir, "eval", "curve.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["selection_sha256"], self.sha)

    def test_an_altered_fit_is_refused(self):
        tmp = os.path.join(self.dir, "copy")
        shutil.copytree(self.out, tmp)
        name = next(f["artifact"] for f in self.sel["fits"] if f["model"] == "hgb")
        with open(os.path.join(tmp, name), "ab") as fh:
            fh.write(b"x")
        with self.assertRaises(LC.SelectionError):
            LC.load_selection(os.path.join(tmp, "selection.json"), self.sha)


class LevelTest(unittest.TestCase):
    def test_the_default_level_follows_the_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, fmt in (("v3", D.DATASET_FORMAT_V3), ("v2", D.DATASET_FORMAT_V2)):
                os.makedirs(os.path.join(tmp, name))
                with open(os.path.join(tmp, name, D.MANIFEST_FILE), "w", encoding="utf-8") as fh:
                    json.dump({"format": fmt}, fh)
            self.assertEqual(LC.default_level([os.path.join(tmp, "v2"), os.path.join(tmp, "v3")]), "view")
            self.assertEqual(LC.default_level([os.path.join(tmp, "v2")]), "request")
            self.assertEqual(LC.default_level([os.path.join(tmp, "missing")]), "request")

    def test_the_view_rules_are_p3s_grids_with_v2_units(self):
        rules = PRE.selection()
        self.assertEqual(rules["budget"], 0.01)
        self.assertTrue(np.all(np.diff(rules["theta_grid"]) > 0))


if __name__ == "__main__":
    unittest.main()
