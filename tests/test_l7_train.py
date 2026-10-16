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


def synth_dataset(path, n_benign=6, n_attack=3, per=40, held_benign=0):
    """A tiny labelled dataset: benign GET a mix of paths slowly; attackers POST one
    path fast. Enough structure for the pipeline, not for a detection claim.
    `held_benign` adds that many held-out benign IPs (P5b decision 1)."""
    os.makedirs(path, exist_ok=True)
    benign = [{"ip": f"10.0.1.{i + 1}", "kind": "mix", "profile": "perfect"}
              for i in range(n_benign)]
    benign += [{"ip": f"10.0.1.{n_benign + i + 1}", "kind": "api", "profile": "perfect",
                "held_out": True} for i in range(held_benign)]
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


class HeldOutBenignTest(unittest.TestCase):
    def test_heldout_benign_is_its_own_set(self):
        d = tempfile.mkdtemp(prefix="l7ds_")
        self.addCleanup(shutil.rmtree, d, True)
        synth_dataset(d, held_benign=2)
        _, recs = T.load_records(d)
        windows = T.group_windows(recs, 20, T.F.columns(), 3, 5)
        sets, ipsplit = T.split(windows, seed=1)
        held = {"10.0.1.7", "10.0.1.8"}
        self.assertEqual(set(ipsplit["benign_heldout"]), held)
        self.assertEqual({w["ip"] for w in sets["benign_heldout"]}, held)
        for name in ("train", "val", "benign_test"):
            self.assertTrue(held.isdisjoint({w["ip"] for w in sets[name]}), name)
        self.assertTrue(held.isdisjoint(set(ipsplit["benign_test"])))


class VariantGateTest(unittest.TestCase):
    """R17 (§7.3.2.1): server-timing variants exist, every variant is probe-gated before
    selection, and with no eligible variant no package is produced."""

    def test_variant_groups(self):
        g = T.variant_groups()
        self.assertEqual(set(g), set(T.VARIANTS))
        cols = T.F.columns(g["no_size_no_server_timing"])
        self.assertIn("log_iat", cols)
        self.assertNotIn("log_rt", cols)
        self.assertNotIn("log_urt", cols)
        self.assertNotIn("log_rlen", cols)
        self.assertIn("log_rt", T.F.columns(g["no_size"]))

    def test_every_variant_is_gated_and_selection_is_among_eligible(self):
        d = tempfile.mkdtemp(prefix="l7ds_")
        out = tempfile.mkdtemp(prefix="l7pkg_")
        for x in (d, out):
            self.addCleanup(shutil.rmtree, x, True)
        synth_dataset(d)
        report, _ = T.run(d, out, seed=1, epochs=1, hidden=8, layers=1,
                          variants=("no_size", "no_size_no_server_timing"), do_baseline=False)
        for v in report["variants"].values():
            self.assertIn("server_load", v["probes"])
            self.assertIn("probe_gate_pass", v)
        eligible = report["selection"]["eligible"]
        self.assertEqual(eligible, [n for n, v in report["variants"].items()
                                    if v["probe_gate_pass"]])
        if report["selection"]["chosen"] is not None:
            self.assertIn(report["selection"]["chosen"], eligible)
            self.assertEqual(report["probe_gate_pass"],
                             report["variants"][report["selection"]["chosen"]]["probe_gate_pass"])

    def test_no_eligible_variant_produces_no_package(self):
        from unittest import mock
        d = tempfile.mkdtemp(prefix="l7ds_")
        out = tempfile.mkdtemp(prefix="l7pkg_")
        for x in (d, out):
            self.addCleanup(shutil.rmtree, x, True)
        synth_dataset(d)
        with mock.patch.object(T.l7_probes, "gate_pass", return_value=False):
            report, best = T.run(d, out, seed=1, epochs=1, hidden=8, layers=1,
                                 variants=("no_size",), do_baseline=False)
        self.assertIsNone(best)
        self.assertIsNone(report["selection"]["chosen"])
        self.assertFalse(report["probe_gate_pass"])
        self.assertFalse(os.path.exists(os.path.join(out, "config.json")))
        with open(T.write_card(out, report), encoding="utf-8") as fh:
            self.assertIn("No candidate", fh.read())


class CliVariantsTest(unittest.TestCase):
    def test_variants_flag_restricts_training(self):
        import subprocess
        d = tempfile.mkdtemp(prefix="l7ds_")
        out = tempfile.mkdtemp(prefix="l7pkg_")
        for x in (d, out):
            self.addCleanup(shutil.rmtree, x, True)
        synth_dataset(d)
        r = subprocess.run([sys.executable, os.path.join(U.REPO, "ml", "train_l7.py"), d,
                            "--out", out, "--epochs", "1", "--hidden", "8", "--layers", "1",
                            "--no-baseline", "--variants", "no_size_no_server_timing"],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        with open(os.path.join(out, "metrics.json"), encoding="utf-8") as fh:
            rep = json.load(fh)
        self.assertEqual(list(rep["variants"]), ["no_size_no_server_timing"])
        bad = subprocess.run([sys.executable, os.path.join(U.REPO, "ml", "train_l7.py"), d,
                              "--out", out, "--variants", "bogus"],
                             capture_output=True, text=True, check=False)
        self.assertNotEqual(bad.returncode, 0)


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
                             variants=("default", "no_server_timing"), do_baseline=True)
        # the strict load probe rejects the variant that reads server timing (R17)
        self.assertFalse(report["variants"]["default"]["probe_gate_pass"])
        self.assertEqual(report["selection"]["chosen"], "no_server_timing")
        # a loadable package was written and never in training_results/
        self.assertNotIn("training_results", os.path.abspath(out))
        scorer = l7_scorer.L7Scorer.load(out)
        self.assertEqual(scorer.threshold, T.THRESHOLD)
        self.assertNotIn("log_rt", scorer.cols)
        # both variants evaluated, GRU + baseline present
        self.assertIn("baseline_hgb", report["variants"]["default"])
        # held-out family reported, benign FP computed, probes ran
        self.assertIn("f_held", report["variants"]["default"]["gru"]["heldout"]["by_family"])
        self.assertIn("fp_per_client_hour", report["variants"]["default"]["gru"]["benign_fp"])
        self.assertIn("probe_gate_pass", report)
        self.assertIn("ua_swap", report["probes"])
        card = T.write_card(out, report)
        self.assertTrue(os.path.getsize(card) > 0)

    def test_heldout_benign_reported_and_baseline_saved(self):
        d = tempfile.mkdtemp(prefix="l7ds_")
        self.addCleanup(shutil.rmtree, d, True)
        synth_dataset(d, held_benign=1)
        out = tempfile.mkdtemp(prefix="l7pkg_")
        self.addCleanup(shutil.rmtree, out, True)
        report, _ = T.run(d, out, seed=1, epochs=1, hidden=8, layers=1,
                          variants=("no_size_no_server_timing",), do_baseline=True)
        g = report["variants"]["no_size_no_server_timing"]["gru"]
        self.assertEqual(g["benign_heldout"]["n_groups"], 1)
        self.assertIn("fp_per_client_hour", g["benign_heldout_fp"])
        clf, meta = T.load_baseline(out)
        self.assertEqual(meta["variant"], "no_size_no_server_timing")
        self.assertEqual(meta["columns"], T.F.columns(T.variant_groups()["no_size_no_server_timing"]))
        self.assertTrue(hasattr(clf, "predict_proba"))
        with open(os.path.join(out, T.BASELINE_PKL), "ab") as fh:     # tamper
            fh.write(b"x")
        with self.assertRaises(ValueError):
            T.load_baseline(out)
        with open(T.write_card(out, report), encoding="utf-8") as fh:
            self.assertIn("held-out benign kind", fh.read())


if __name__ == "__main__":
    unittest.main()
