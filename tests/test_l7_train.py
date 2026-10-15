"""Unit tests for ml/train_l7.py (Phase P4). Offline, CPU, tiny synthetic dataset.

Mechanics only (splits, scaling fit, policy metric, CIs, package output, probe gate);
detection quality is a property of a real dataset, out of scope here.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import torch
import train_l7 as T

import l7_dataset
import l7_scorer

torch.set_num_threads(1)


def synth_dataset(path, n_benign=6, n_attack=3, per=40):
    """A tiny labelled dataset: benign GET a mix of paths slowly; attackers POST one
    path fast. Enough structure for the pipeline, not for a detection claim."""
    os.makedirs(path, exist_ok=True)
    benign = [{"ip": f"10.0.1.{i + 1}", "kind": "mix", "profile": "perfect"}
              for i in range(n_benign)]
    attackers = [{"ip": f"10.0.2.{i + 1}", "family": "f_train", "held_out": False,
                  "params": {}} for i in range(n_attack - 1)]
    attackers.append({"ip": f"10.0.2.{n_attack}", "family": "f_held", "held_out": True,
                      "params": {}})
    ip_map = l7_dataset.build_ip_map(benign, attackers)
    schedule = [{"ip": a["ip"], "family": a["family"], "held_out": a["held_out"],
                 "mechanism": "rate", "start_s": 1.0, "stop_s": 50.0, "params": {}}
                for a in attackers]
    manifest = l7_dataset.make_manifest(seed=1, duration_s=60.0, ip_map=ip_map,
                                        schedule=schedule, provenance={"t0_wall": 0})
    l7_dataset.write_dataset_manifest(os.path.join(path, l7_dataset.MANIFEST_FILE), manifest)
    with open(os.path.join(path, l7_dataset.ACCESS_LOG), "w", encoding="utf-8") as fh:
        t = 1000.0
        for c in benign:
            fh.writelines(json.dumps(U.obj(ip=c["ip"], ua="browser", method="GET",
                                          uri=f"/page/{j % 7}", msec=t + j * 0.8,
                                          status=200, bsent=500 + 50 * (j % 7))) + "\n" for j in range(per))
        for a in attackers:
            fh.writelines(json.dumps(U.obj(ip=a["ip"], ua="bot", method="POST",
                                          uri="/login", msec=t + j * 0.05, status=401,
                                          bsent=120)) + "\n" for j in range(per))
    return path


class LoadSplitTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="l7ds_")
        self.addCleanup(shutil.rmtree, self.d, True)
        synth_dataset(self.d)

    def test_records_labelled_and_other_dropped(self):
        _manifest, recs = T.load_records(self.d)
        classes = {r["_cls"] for r in recs}
        self.assertEqual(classes, {l7_dataset.BENIGN, l7_dataset.ATTACK})
        self.assertIn("f_held", {r["_family"] for r in recs})

    def test_windows_and_split_are_disjoint_benign_ips(self):
        _, recs = T.load_records(self.d)
        cols = T.F.columns()
        windows = T.group_windows(recs, 20, cols, 3, 5)
        self.assertTrue(windows)
        sets, _ipsplit = T.split(windows, seed=1)
        tr = {w["ip"] for w in sets["train"] if w["cls"] == l7_dataset.BENIGN}
        te = {w["ip"] for w in sets["benign_test"]}
        self.assertTrue(tr.isdisjoint(te))                 # benign IP-disjoint
        self.assertTrue(all(w["held"] for w in sets["heldout"]))
        self.assertIn("f_held", {w["family"] for w in sets["heldout"]})
        self.assertNotIn("f_held", {w["family"] for w in sets["train"]})   # never trained

    def test_fit_scaling_shapes_and_valid_untouched(self):
        _, recs = T.load_records(self.d)
        cols = T.F.columns()
        windows = T.group_windows(recs, 20, cols, 3, 5)
        sets, _ = T.split(windows, seed=1)
        mean, std = T.fit_scaling(sets["train"], len(cols))
        self.assertEqual(len(mean), len(cols))
        self.assertEqual((mean[0], std[0]), (0.0, 1.0))
        self.assertTrue((std > 0).all())


class MetricsTest(unittest.TestCase):
    def test_clopper_pearson(self):
        self.assertEqual(T.clopper_pearson(0, 0), (0.0, 1.0))
        lo, hi = T.clopper_pearson(2, 2)
        self.assertGreater(lo, 0.15)
        self.assertEqual(hi, 1.0)
        lo, hi = T.clopper_pearson(0, 5)
        self.assertEqual(lo, 0.0)

    def test_policy_detected_needs_consecutive(self):
        import numpy as np
        self.assertTrue(T.policy_detected(None, np.array([0.99, 0.99, 0.99]), 0.95, 3))
        self.assertFalse(T.policy_detected(None, np.array([0.99, 0.1, 0.99, 0.99]), 0.95, 3))
        self.assertTrue(T.policy_detected(None, np.array([0.1, 0.99, 0.99, 0.99, 0.1]), 0.95, 3))


class RunTest(unittest.TestCase):
    def test_end_to_end_tiny(self):
        d = tempfile.mkdtemp(prefix="l7ds_")
        self.addCleanup(shutil.rmtree, d, True)
        synth_dataset(d)
        out = tempfile.mkdtemp(prefix="l7pkg_")
        self.addCleanup(shutil.rmtree, out, True)
        report, _best = T.run(d, out, seed=1, epochs=1, hidden=8, layers=1,
                             variants=("default", "no_size"), do_baseline=True)
        # a loadable package was written and never in training_results/
        self.assertNotIn("training_results", os.path.abspath(out))
        scorer = l7_scorer.L7Scorer.load(out)
        self.assertEqual(scorer.threshold, T.THRESHOLD)
        # both variants evaluated, GRU + baseline present
        self.assertIn("no_size", report["variants"])
        self.assertIn("baseline_hgb", report["variants"]["default"])
        # held-out family reported, benign FP computed, probes ran
        self.assertIn("f_held", report["variants"]["default"]["gru"]["heldout"]["by_family"])
        self.assertIn("fp_per_client_hour", report["variants"]["default"]["gru"]["benign_fp"])
        self.assertIn("probe_gate_pass", report)
        self.assertIn("ua_swap", report["probes"])
        card = T.write_card(out, report)
        self.assertTrue(os.path.getsize(card) > 0)


if __name__ == "__main__":
    unittest.main()
