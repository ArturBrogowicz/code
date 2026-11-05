"""The L7 v2 two-level model and package format 2 (docs/L7V2_DESIGN.md 8.1): a view encoder plus a GRU over view
tokens, a "level" in the package, and a scorer that refuses a package of another level. Offline; untrained, seeded
models for mechanics only."""
import json
import os
import shutil
import sys
import tempfile
import unittest

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

import l7_features as F
import l7_scorer as S
from l7_view_model import ViewGRU


def view_package(path, cols=F.TOKEN_COLUMNS, max_views=8, seed=0, threshold=0.5, consecutive=2):
    torch.manual_seed(seed)
    model = ViewGRU(input_size=len(cols), embed_size=8, hidden_size=12, num_layers=2)
    model.eval()
    rng = np.random.default_rng(seed)
    mean = rng.normal(size=len(cols)).astype(np.float32)
    std = (1.0 + rng.random(len(cols))).astype(np.float32)
    S.save_view_package(path, model, cols, max_views, mean, std, threshold, consecutive,
                        embed_size=8, hidden_size=12, num_layers=2, meta={"note": "untrained"})
    return model, mean, std


def token_batch(rng, n, max_views=8, cols=F.TOKEN_COLUMNS):
    X = rng.random((n, max_views, len(cols))).astype(np.float32)
    for i in range(n):
        k = int(rng.integers(0, max_views + 1))
        X[i, :max_views - k, 0] = 0.0
        X[i, max_views - k:, 0] = 1.0
        X[i, :max_views - k, 1:] = 0.0
    return X


class ViewGRUTest(unittest.TestCase):
    def test_padding_content_does_not_matter(self):
        torch.manual_seed(1)
        m = ViewGRU(input_size=len(F.TOKEN_COLUMNS), embed_size=8, hidden_size=12, num_layers=2).eval()
        rng = np.random.default_rng(2)
        X = token_batch(rng, 6)
        junk = X.copy()
        pad = junk[..., 0] == 0
        junk[..., 1:][pad] = 7.0                   # garbage in the padding rows, valid still 0
        with torch.no_grad():
            a, b = m(torch.from_numpy(X)), m(torch.from_numpy(junk))
        self.assertEqual(tuple(a.shape), (6, 1))
        np.testing.assert_allclose(a.numpy(), b.numpy(), atol=1e-6)


class ViewPackageTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.pkg = os.path.join(self.dir, "view")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_round_trip_scores_like_the_model(self):
        model, mean, std = view_package(self.pkg)
        sc = S.L7Scorer.load(self.pkg)
        self.assertEqual((sc.level, sc.max_views, sc.seq_len, sc.cols), ("view", 8, 8, list(F.TOKEN_COLUMNS)))
        X = token_batch(np.random.default_rng(3), 5)
        with torch.no_grad():
            want = torch.sigmoid(model(torch.from_numpy(F.apply_scaling(X, mean, std)))).numpy().ravel()
        np.testing.assert_allclose(sc.score(X), want, atol=1e-6)
        with open(os.path.join(self.pkg, S.CONFIG_FILE), encoding="utf-8") as fh:
            cfg = json.load(fh)
        self.assertEqual((cfg["format"], cfg["level"], cfg["arch"]), ("l7-gru-package/2", "view", "view-gru"))

    def test_the_level_is_enforced(self):
        view_package(self.pkg)
        self.assertEqual(S.L7Scorer.load(self.pkg, level="view").level, "view")
        with self.assertRaises(S.PackageError):
            S.L7Scorer.load(self.pkg, level="request")
        legacy = os.path.join(self.dir, "p5c")
        U.tiny_package(legacy)
        self.assertEqual(S.L7Scorer.load(legacy).level, "request")
        with self.assertRaises(S.PackageError):
            S.L7Scorer.load(legacy, level="view")

    def test_a_view_package_is_scored_on_token_matrices_only(self):
        view_package(self.pkg)
        sc = S.L7Scorer.load(self.pkg)
        with self.assertRaises(ValueError):
            sc.score(np.zeros((2, 20, len(F.columns())), np.float32))

    def test_columns_are_checked_per_level(self):
        with self.assertRaises(S.PackageError):
            S.validate_columns(["valid", "log_iat"], "view")
        with self.assertRaises(S.PackageError):
            S.validate_columns(["valid", "log_dwell"], "request")
        S.validate_columns(["valid", "log_dwell", "ref_known"], "view")
        with self.assertRaises(S.PackageError):
            view_package(self.pkg, cols=["valid", "log_dwell", "is_page"])

    def test_altered_weights_are_refused(self):
        view_package(self.pkg)
        with open(os.path.join(self.pkg, S.WEIGHTS_FILE), "ab") as fh:
            fh.write(b"x")
        with self.assertRaises(S.PackageError):
            S.L7Scorer.load(self.pkg)

    def test_an_arch_that_does_not_match_its_level_is_refused(self):
        view_package(self.pkg)
        path = os.path.join(self.pkg, S.CONFIG_FILE)
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg["arch"] = "gru"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        with self.assertRaises(S.PackageError):
            S.L7Scorer.load(self.pkg)


class RequestPackageV2Test(unittest.TestCase):
    def test_the_seq64_ablation_package_and_the_unchanged_format_1(self):
        from GRU_ML_model import GRUDDoSClassifier
        cols = F.columns(F.V2_REQUEST_GROUPS)
        torch.manual_seed(0)
        model = GRUDDoSClassifier(input_size=len(cols), hidden_size=8, num_layers=1).eval()
        mean, std = np.zeros(len(cols), np.float32), np.ones(len(cols), np.float32)
        with tempfile.TemporaryDirectory() as tmp:
            v2 = S.save_package(os.path.join(tmp, "r2"), model, cols, 64, mean, std, 0.9, 3, 8, 1, level="request")
            v1 = S.save_package(os.path.join(tmp, "r1"), model, cols, 64, mean, std, 0.9, 3, 8, 1)
            self.assertEqual((v2["format"], v2["level"]), ("l7-gru-package/2", "request"))
            self.assertEqual(v1["format"], "l7-gru-package/1")
            self.assertNotIn("level", v1)
            for name in ("r1", "r2"):
                sc = S.L7Scorer.load(os.path.join(tmp, name), level="request")
                self.assertEqual((sc.level, sc.seq_len, sc.max_views), ("request", 64, None))
            with self.assertRaises(S.PackageError):
                S.save_package(os.path.join(tmp, "bad"), model, cols, 64, mean, std, 0.9, 3, 8, 1, level="view")


if __name__ == "__main__":
    unittest.main()
