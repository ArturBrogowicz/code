"""Unit tests for l7_scorer.py (model packages, batched scoring; Phase P2).

Uses a tiny UNTRAINED seeded GRU: these tests check mechanics, not detection.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import numpy as np
import torch

import l7_features as F
import l7_scorer as S

torch.set_num_threads(1)


class ScorerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="l7pkg_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        U.tiny_package(self.dir, seq_len=6)
        self.scorer = S.L7Scorer.load(self.dir)
        recs = [U.rec(msec=100.0 + i, method="POST" if i % 2 else "GET") for i in range(9)]
        self.batch = np.stack([F.window_matrix(recs[: k + 2], 6, self.scorer.cols)
                               for k in range(5)])

    def test_roundtrip_and_shape(self):
        p = self.scorer.score(self.batch)
        self.assertEqual(p.shape, (5,))
        self.assertTrue(np.all((p > 0) & (p < 1)))
        self.assertEqual(self.scorer.seq_len, 6)
        self.assertEqual(self.scorer.cols, F.columns())
        self.assertEqual(len(self.scorer.sha256), 64)

    def test_batched_equals_one_by_one(self):
        batched = self.scorer.score(self.batch)
        single = np.array([self.scorer.score(self.batch[i:i + 1])[0] for i in range(len(self.batch))])
        np.testing.assert_allclose(batched, single, atol=1e-6)

    def test_scaling_is_applied(self):
        x = F.apply_scaling(self.batch, self.scorer.mean, self.scorer.std)
        with torch.no_grad():
            expected = torch.sigmoid(self.scorer.model(torch.from_numpy(x))).numpy().ravel()
        np.testing.assert_allclose(self.scorer.score(self.batch), expected, atol=1e-7)

    def test_empty_and_wrong_shape(self):
        self.assertEqual(self.scorer.score(np.zeros((0, 6, len(self.scorer.cols)))).shape, (0,))
        with self.assertRaises(ValueError):
            self.scorer.score(np.zeros((2, 5, len(self.scorer.cols))))      # wrong seq_len

    def test_tampered_weights_rejected(self):
        with open(os.path.join(self.dir, S.WEIGHTS_FILE), "ab") as fh:
            fh.write(b"x")
        with self.assertRaises(S.PackageError):
            S.L7Scorer.load(self.dir)

    def _edit_config(self, **changes):
        path = os.path.join(self.dir, S.CONFIG_FILE)
        with open(path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        cfg.update(changes)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)

    def test_unknown_column_rejected(self):
        cols = F.columns()
        self._edit_config(columns=[*cols[:-1], "user_agent_raw"])
        with self.assertRaises(S.PackageError):
            S.L7Scorer.load(self.dir)

    def test_bad_policy_values_rejected(self):
        for change in ({"threshold": 1.5}, {"consecutive": 0}, {"seq_len": 0},
                       {"format": "other/9"}):
            U.tiny_package(self.dir, seq_len=6)          # restore a valid package
            self._edit_config(**change)
            with self.assertRaises(S.PackageError, msg=str(change)):
                S.L7Scorer.load(self.dir)

    def test_save_validates_columns(self):
        with self.assertRaises(S.PackageError):
            S.validate_columns(["log_iat", F.VALID])        # valid must be first
        with self.assertRaises(S.PackageError):
            S.validate_columns([F.VALID, "log_iat", "log_iat"])


if __name__ == "__main__":
    unittest.main()
