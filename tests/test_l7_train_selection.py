"""Selection on validation only (docs/P3_DATASET_DESIGN.md §4.8): the default rule reads the validation set and
nothing else; the published P5c rule stays reachable with selection="p5c"; P3 captures need --val and the
disjointness check. Offline, CPU, tiny fixtures."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import p3_fixtures as FX

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import numpy as np
import torch
import train_l7 as T
from test_l7_train import synth_dataset

import l7_dataset
import l7_scorer

torch.set_num_threads(1)


def read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def win(ent, cls, t, ua=1):
    return {"ip": ent, "ua_h": ua, "cls": cls, "t": t}


class OperatingPointTest(unittest.TestCase):
    def test_grid_point_maximises_recall_within_the_budget(self):
        ws, ps = [], []
        for i in range(3):                                   # attack entities: scores 0.97, 0.97, 0.6
            for t in range(4):
                ws.append(win(f"a{i}", l7_dataset.ATTACK, t))
                ps.append(0.97 if i < 2 else 0.6)
        for i in range(4):                                   # benign: one entity at 0.92 on 2 windows
            for t in range(4):
                ws.append(win(f"b{i}", l7_dataset.BENIGN, t))
                ps.append(0.92 if (i == 0 and t < 2) else 0.1)
        op = T.operating_point(ws, np.array(ps), theta_grid=[0.5, 0.9, 0.95], k_grid=[1, 2, 3], budget=0.01)
        self.assertEqual((op["threshold"], op["consecutive"]), (0.5, 3))   # 0.5x3: all 3 caught, b0 has only 2
        self.assertEqual((op["val_attack_caught"], op["val_benign_flagged"], op["benign_allowed"]), (3, 0, 0))
        op2 = T.operating_point(ws, np.array(ps), theta_grid=[0.95], k_grid=[1], budget=0.01)
        self.assertEqual(op2["val_attack_caught"], 2)
        self.assertIsNone(T.operating_point([w for w in ws if w["cls"] == l7_dataset.ATTACK], np.array(ps[:12])))
        many = T.operating_point(ws, np.array(ps), theta_grid=[0.5], k_grid=[1], budget=0.25)
        self.assertEqual(many["benign_allowed"], 1)          # floor(0.25 x 4)


CANDIDATES = {"a": {"probe_gate_pass": True, "val_loss": 0.3, "heldout_detected": 8, "benign_fp": 0.0,
           "operating_point": {"val_recall": 0.5, "val_benign_flagged": 0}},
     "b": {"probe_gate_pass": True, "val_loss": 0.4, "heldout_detected": 1, "benign_fp": 0.0,
           "operating_point": {"val_recall": 0.9, "val_benign_flagged": 0}},
     "c": {"probe_gate_pass": False, "val_loss": 0.1, "heldout_detected": 9, "benign_fp": 0.0,
           "operating_point": {"val_recall": 1.0, "val_benign_flagged": 0}}}


class SelectVariantTest(unittest.TestCase):
    """Validation and the test sets disagree on purpose: each rule must follow its own."""
    def test_val_rule_reads_validation_only(self):
        self.assertEqual(T.select_variant(CANDIDATES, "val"), ("b", ["a", "b"]))
        blind = {n: {k: v for k, v in c.items() if k not in ("heldout_detected", "benign_fp")}
                 for n, c in CANDIDATES.items()}
        self.assertEqual(T.select_variant(blind, "val")[0], "b")           # no test-set field needed
        no_op = dict(blind, b=dict(blind["b"], operating_point=None))
        self.assertEqual(T.select_variant(no_op, "val"), ("a", ["a"]))

    def test_p5c_rule_is_the_published_one(self):
        self.assertEqual(T.select_variant(CANDIDATES, "p5c")[0], "a")
        with self.assertRaises(ValueError):
            T.select_variant(CANDIDATES, "test")


class RunSelectionTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="l7ds_")
        self.out = tempfile.mkdtemp(prefix="l7pkg_")
        for x in (self.d, self.out):
            self.addCleanup(shutil.rmtree, x, True)
        synth_dataset(self.d)

    def test_default_is_validation_and_the_package_carries_its_point(self):
        d = tempfile.mkdtemp(prefix="l7ds12_")
        self.addCleanup(shutil.rmtree, d, True)
        synth_dataset(d, n_benign=12)                         # 8 / 1 / 3 benign IPs: one to validate on
        report, best = T.run(d, self.out, seed=1, epochs=1, hidden=8, layers=1,
                             variants=("no_size_no_server_timing",), do_baseline=True, selection="val")
        self.assertEqual(report["selection_rule"], "val")
        self.assertIsNotNone(best, report["selection"])
        op = report["selection"]["operating_point"]
        self.assertEqual(report["selection"]["uses"], ["val"])
        self.assertEqual((op["val_benign_entities"], op["benign_allowed"]), (1, 0))
        scorer = l7_scorer.L7Scorer.load(self.out)
        self.assertEqual((scorer.threshold, scorer.consecutive), (op["threshold"], op["consecutive"]))
        self.assertEqual((report["threshold"], report["consecutive"]), (op["threshold"], op["consecutive"]))
        _clf, meta = T.load_baseline(self.out)
        self.assertEqual((meta["threshold"], meta["consecutive"]), (op["threshold"], op["consecutive"]))

    def test_no_benign_validation_entity_means_no_candidate(self):
        report, best = T.run(self.d, self.out, seed=1, epochs=1, hidden=8, layers=1,
                             variants=("no_size_no_server_timing",), do_baseline=False, selection="val")
        self.assertIsNone(best)                               # 6 benign IPs split 4 / 0 / 2
        self.assertIsNone(report["variants"]["no_size_no_server_timing"]["operating_point"])
        self.assertIn("benign budget", report["selection"]["caveat"])

    def test_p5c_flag_keeps_the_published_report_shape(self):
        report, _ = T.run(self.d, self.out, seed=1, epochs=1, hidden=8, layers=1,
                          variants=("no_size_no_server_timing",), do_baseline=False, selection="p5c")
        self.assertNotIn("selection_rule", report)
        self.assertNotIn("operating_point", report["variants"]["no_size_no_server_timing"])
        self.assertTrue(set(report["selection"]) <= {"rule", "chosen", "eligible", "caveat"})
        self.assertEqual((report["threshold"], report["consecutive"]), (T.THRESHOLD, T.CONSECUTIVE))
        with self.assertRaises(ValueError):
            T.run(self.d, self.out, selection="test")


class P3CapturesTest(unittest.TestCase):
    V = "2026-11-t1"

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="l7p3_")
        self.addCleanup(shutil.rmtree, self.root, True)
        vdir = os.path.join(self.root, self.V)
        self.train = [FX.capture(vdir, self.V, s, "train", FX.entities(self.V, s))[0] for s in (1001, 1002)]
        self.val = [FX.capture(vdir, self.V, 2001, "val", FX.entities(self.V, 2001))[0]]

    def test_multi_capture_fit_checks_disjointness_and_writes_its_selection(self):
        out = os.path.join(self.root, "pkg")
        report, best = T.run(self.train, out, seed=1, epochs=1, hidden=8, layers=1, selection="val",
                             variants=("no_size_no_server_timing",), do_baseline=False, val_dirs=self.val)
        self.assertEqual(report["val_datasets"], [os.path.abspath(v) for v in self.val])
        v = report["variants"]["no_size_no_server_timing"]
        self.assertEqual(v["counts"]["benign_test"], 0)       # no test set inside a P3 fit
        if best is not None:
            sel = read_json(os.path.join(out, "selection.json"))
            import l7_disjoint
            self.assertEqual(l7_disjoint.check({"train": self.train, "val": self.val, "eval": []},
                                               split_file=os.path.join(out, "split.json"),
                                               selection_file=os.path.join(out, "selection.json")), [])
            self.assertEqual(sel["variant"], "no_size_no_server_timing")

    def test_refuses_without_disjointness(self):
        import l7_disjoint
        with self.assertRaises(l7_disjoint.DisjointnessError):
            T.run(self.train, os.path.join(self.root, "x"), epochs=1, hidden=8, layers=1,
                  variants=("no_size",), do_baseline=False, val_dirs=self.train[:1])
        with self.assertRaises(ValueError):
            T.run(self.train, os.path.join(self.root, "y"), epochs=1, hidden=8, layers=1)


if __name__ == "__main__":
    unittest.main()
