"""One enforcement path for every arm (l7_arms.py; docs/L7V2_DESIGN.md 9.5): the view GRU, the HGB and the LR
load from one frozen selection as the same kind of detector, each with its own operating point, and go through the same
engine and the same arm (R*, at its own level, is tests/test_l7_rstar.py); a placeholder operating point, the ablations, an altered artifact or another selection are
refused. A small real ViewGRU package and real sklearn models are built in a temporary directory. Offline."""
import hashlib
import json
import os
import pickle
import sys
import tempfile
import unittest

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import test_daemon_l7_enforce as DE

import l7_arms as L
import l7_engine
import l7_features as F

OPS = {"view_gru": (0.7, 3), "gru_shuffled": (0.7, 3), "hgb": (0.6, 2), "lr": (0.55, 1), "request_gru": (0.8, 2)}


def sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def windows(n, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.random((n, F.MAX_VIEWS, len(F.TOKEN_COLUMNS))).astype(np.float32)
    X[..., 0] = 1.0
    return X


class SelectionCase(unittest.TestCase):
    """A frozen selection with every arm kind, written as ml/train_l7v2.select writes it."""

    @classmethod
    def setUpClass(cls):
        import torch
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression

        import l7_scorer
        from l7_view_model import ViewGRU
        cls.tmp = tempfile.TemporaryDirectory()
        base = cls.dir = cls.tmp.name
        torch.manual_seed(0)
        cols = list(F.TOKEN_COLUMNS)
        l7_scorer.save_view_package(os.path.join(base, "view_gru"), ViewGRU(len(cols), 4, 4, 1), cols, F.MAX_VIEWS,
                                    [0.0] * len(cols), [1.0] * len(cols), *OPS["view_gru"], 4, 4, 1,
                                    meta={"arm": "view_gru", "operating_point": "selection.json"})
        X, y = L.summaries(windows(40)), np.arange(40) % 2
        for name, clf in (("hgb", HistGradientBoostingClassifier(max_iter=3)), ("lr", LogisticRegression())):
            with open(os.path.join(base, f"{name}.pkl"), "wb") as fh:
                pickle.dump(clf.fit(X, y), fh)
        with open(os.path.join(base, "request.bin"), "wb") as fh:
            fh.write(b"not loaded")
        arts = {"view_gru": "view_gru/config.json", "gru_shuffled": "view_gru/config.json", "hgb": "hgb.pkl",
                "lr": "lr.pkl", "request_gru": "request.bin"}
        cls.arms = {name: {"artifact": rel, "artifact_sha256": sha(os.path.join(base, rel)), "probe_gate_pass": True,
                           "operating_point": {"threshold": OPS[name][0], "consecutive": OPS[name][1]}}
                    for name, rel in arts.items()}
        cls.sel, cls.sha = cls.write("selection.json", cls.arms)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def write(cls, name, arms, fmt=L.SEL_FORMAT, valid=True):
        path = os.path.join(cls.dir, name)
        sel = {"format": fmt, "source": "test", "arms": arms, "valid_for_claims": valid}
        if valid is None:
            del sel["valid_for_claims"]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sel, fh)
        return path, sha(path)


class OnePathTest(SelectionCase):
    def test_every_arm_kind_is_one_detector_with_its_own_operating_point(self):
        batch = windows(5, seed=1)
        for arm, kind in (("view_gru", "gru"), ("hgb", "tabular"), ("lr", "tabular")):
            with self.subTest(arm=arm):
                det = L.load(self.sel, self.sha, arm)
                self.assertEqual((det.level, det.kind, det.arm, det.threshold, det.consecutive),
                                 ("view", kind, arm, *OPS[arm]))
                self.assertEqual((det.cols, det.max_views, det.selection_sha256),
                                 (list(F.TOKEN_COLUMNS), F.MAX_VIEWS, self.sha))
                p = det.score(batch)
                self.assertEqual(p.shape, (5,))
                self.assertTrue(((p >= 0) & (p <= 1)).all())
                engine = l7_engine.build_engine(scorer=det)             # the daemon's engine, the same for all
                self.assertIsInstance(engine, l7_engine.L7ViewEngine)
                self.assertEqual((engine.threshold, engine.consecutive, engine.max_views), (*OPS[arm], F.MAX_VIEWS))

    def test_the_tabular_arms_read_the_trainers_summaries(self):
        import train_l7v2
        X = windows(4, seed=2)
        np.testing.assert_array_equal(L.summaries(X), train_l7v2.summaries(X))
        self.assertEqual(L.SEL_FORMAT, train_l7v2.SEL_FORMAT)


class RefusalTest(SelectionCase):
    def refused(self, path, digest, arm, needle):
        with self.assertRaises(L.DetectorError) as cm:
            L.load(path, digest, arm)
        self.assertIn(needle, str(cm.exception))

    def test_a_placeholder_operating_point_is_never_enforced(self):
        arms = {**self.arms, "hgb": {**self.arms["hgb"], "operating_point": None}}
        path, digest = self.write("sel_placeholder.json", arms)
        self.refused(path, digest, "hgb", "placeholder")
        self.assertEqual(L.load(path, digest, "lr").arm, "lr")         # the other arms of that selection load

    def test_a_package_whose_own_point_or_provenance_is_not_the_selections(self):
        arms = {**self.arms, "view_gru": {**self.arms["view_gru"],
                                          "operating_point": {"threshold": 0.9, "consecutive": 3}}}
        path, digest = self.write("sel_other_point.json", arms)
        self.refused(path, digest, "view_gru", "not the selection's")

    def test_the_ablations_are_replay_only(self):
        self.refused(self.sel, self.sha, "gru_shuffled", "replay only")
        self.refused(self.sel, self.sha, "request_gru", "offline ablation")

    def test_another_or_an_altered_selection_or_artifact(self):
        self.refused(self.sel, "", "lr", "must be given")
        self.refused(self.sel, "0" * 64, "lr", "not the recorded")
        self.refused(os.path.join(self.dir, "missing.json"), self.sha, "lr", "cannot read")
        path, digest = self.write("sel_format.json", self.arms, fmt="l7v2-selection/0")
        self.refused(path, digest, "lr", "is not a")
        self.refused(self.sel, self.sha, "gru", "no arm")
        arms = {**self.arms, "lr": {**self.arms["lr"], "artifact_sha256": "1" * 64}}
        path, digest = self.write("sel_altered.json", arms)
        self.refused(path, digest, "lr", "altered")
        arms = {**self.arms, "lr": {**self.arms["lr"], "artifact": "../lr.pkl"}}
        path, digest = self.write("sel_outside.json", arms)
        self.refused(path, digest, "lr", "outside")

    def test_a_selection_not_valid_for_claims_is_never_enforced(self):
        # T-042 E05: train_l7v2 writes valid_for_claims false for a --smoke run or a legacy capture
        for name, valid in (("sel_smoke.json", False), ("sel_old.json", None)):
            with self.subTest(valid=valid):
                path, digest = self.write(name, self.arms, valid=valid)
                self.refused(path, digest, "lr", "valid_for_claims")
        self.assertTrue(L.load(self.sel, self.sha, "lr").valid_for_claims)


class DaemonLoadTest(DE.L7Case, SelectionCase):
    def test_a_smoke_selection_stops_the_daemon_and_says_why(self):
        path, digest = self.write("sel_smoke_daemon.json", self.arms, valid=False)
        d = self.daemon(**{**DE.ENFORCE, "L7_SELECTION": path, "L7_SELECTION_SHA256": digest, "L7_ARM": "hgb"})
        d.ns["l7_arms"] = L
        with self.assertRaises(SystemExit):
            d.call("l7_enforce_init")
        [err] = d.events("daemon_error")
        self.assertEqual((err["where"], err["action"]), ("l7_enforce", "the daemon stops: nothing is enforced"))
        self.assertIn("valid_for_claims=False", err["error"])
        self.assertIsNone(d.l7_arm)

    def test_the_daemon_loads_its_arm_from_the_selection_and_a_refusal_stops_it(self):
        for arm, ok in (("hgb", True), ("gru_shuffled", False)):
            with self.subTest(arm=arm):
                d = self.daemon(**{**DE.ENFORCE, "L7_SELECTION": self.sel, "L7_SELECTION_SHA256": self.sha,
                                   "L7_ARM": arm})
                d.ns["l7_arms"] = L
                if ok:
                    d.call("l7_enforce_init")
                    self.assertEqual((d.l7_detector.arm, d.l7_detector.threshold), ("hgb", 0.6))
                else:
                    with self.assertRaises(SystemExit):
                        d.call("l7_enforce_init")
                    self.assertIsNone(d.l7_arm)


if __name__ == "__main__":
    unittest.main()
