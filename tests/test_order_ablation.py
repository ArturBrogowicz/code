"""Unit tests for ml/order_ablation.py (audit G-02). Offline: stub scorers, no training."""
import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import numpy as np
import order_ablation as OA

import l7_features as F


class AscendingScorer(U.StubScorer):
    """p = hi iff the valid rows of `col` are strictly increasing in window order: a
    property of the ORDER only (any permutation of distinct values breaks it)."""

    def score(self, batch):
        batch = np.asarray(batch, dtype=np.float32)
        self.calls.append(len(batch))
        j = self.cols.index(self.col)
        out = []
        for w in batch:
            v = w[w[:, 0] == 1.0, j]
            out.append(self.hi if len(v) > 1 and bool(np.all(np.diff(v) > 0)) else self.lo)
        return np.asarray(out, dtype=np.float32)


def write_run(d, n=60, gz=False):
    """A tiny eval run. The attacker POSTs with a request size that grows at every request;
    the benign client GETs with a constant size. So "mostly POST" is order-free and
    "sizes increase" is order-only. A second attacker (credstuff) is outside the
    comparison set."""
    ip_map = {"10.0.2.7": {"class": "attack", "family": "subthreshold_flood"},
              "10.0.2.9": {"class": "attack", "family": "credstuff"},
              "10.0.1.7": {"class": "benign", "kind": "browser_page"}}
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"ip_map": ip_map}, fh)
    lines = []
    for i in range(n):
        lines.append(json.dumps(U.obj(ip="10.0.2.7", ua="bot", method="POST",
                                      msec=100.0 + i, rlen=100 + 10 * i)))
        lines.append(json.dumps(U.obj(ip="10.0.1.7", ua="browser", method="GET",
                                      msec=100.2 + i, uri=f"/p{i % 7}", rlen=300)))
    text = "\n".join(lines) + "\n"
    path = os.path.join(d, "l7_record.jsonl" + (".gz" if gz else ""))
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return d


def window_batch(seq_len=6):
    """Two windows: one with 4 real requests (2 padding rows), one full."""
    cols = F.columns()
    recs = [U.rec(msec=100.0 + i, rlen=100 + 10 * i, uri=f"/u{i}") for i in range(6)]
    short = F.window_matrix(recs[:4], seq_len, cols)
    full = F.window_matrix(recs, seq_len, cols)
    return np.stack([short, full]), cols


class ReorderTest(unittest.TestCase):
    def scorer(self, mode, seed=0):
        return OA.OrderedScorer(U.StubScorer(seq_len=6), mode, seed)

    def test_recorded_is_untouched(self):
        batch, _ = window_batch()
        out = self.scorer("recorded").reorder(batch)
        np.testing.assert_array_equal(out, batch)
        self.assertIsNot(out, batch)

    def test_reversed_reverses_only_the_valid_rows(self):
        batch, _ = window_batch()
        out = self.scorer("reversed").reorder(batch)
        np.testing.assert_array_equal(out[0, :2], batch[0, :2])          # padding stays
        np.testing.assert_array_equal(out[0, 2:], batch[0, 2:][::-1])
        np.testing.assert_array_equal(out[1], batch[1][::-1])

    def test_shuffled_keeps_padding_and_the_multiset_of_rows(self):
        batch, _ = window_batch()
        moved = False
        for seed in range(10):
            out = self.scorer("shuffled", seed).reorder(batch)
            np.testing.assert_array_equal(out[0, :2], batch[0, :2])
            for w in (0, 1):
                a = out[w][np.lexsort(out[w].T)]
                b = batch[w][np.lexsort(batch[w].T)]
                np.testing.assert_array_equal(a, b)
            moved = moved or not np.array_equal(out[1], batch[1])
        self.assertTrue(moved, "ten seeds never changed the order of a 6-row window")

    def test_same_seed_same_permutation(self):
        batch, _ = window_batch()
        a = self.scorer("shuffled", 5).reorder(batch)
        b = self.scorer("shuffled", 5).reorder(batch)
        np.testing.assert_array_equal(a, b)

    def test_windows_with_fewer_than_two_real_rows_are_unchanged(self):
        cols = F.columns()
        one = F.window_matrix([U.rec()], 6, cols)
        none = F.window_matrix([], 6, cols)
        batch = np.stack([one, none])
        for mode in ("shuffled", "reversed"):
            np.testing.assert_array_equal(self.scorer(mode).reorder(batch), batch)

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            OA.OrderedScorer(U.StubScorer(), "sorted")

    def test_probabilities_are_kept_in_scoring_order(self):
        batch, _ = window_batch()
        s = OA.OrderedScorer(U.StubScorer(seq_len=6, col="m_post"), "recorded")
        p = s.score(batch)
        self.assertEqual(s.probs, [float(x) for x in p])


class AblateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = write_run(self.tmp.name)

    def test_an_order_free_scorer_decides_identically(self):
        rep = OA.ablate(U.StubScorer(col="m_post"), [self.run_dir])
        self.assertEqual(rep["verdict"], "order-free")
        self.assertEqual((rep["comparison_attackers"], rep["benign_ips"]), (1, 1))
        for mode in OA.MODES:
            e = rep["runs"][0]["modes"][mode]
            self.assertEqual((e["comparison_flagged"], e["benign_flagged"]), (1, 0), mode)
        s = rep["runs"][0]["modes"]["shuffled"]
        self.assertTrue(s["decisions_identical"])
        self.assertTrue(s["windows_aligned"])
        self.assertEqual((s["flip_rate"], s["mean_abs_dp"], s["max_abs_dp"]), (0.0, 0.0, 0.0))
        self.assertEqual(s["windows_flipped"], 0)
        self.assertEqual(rep["pooled"]["shuffled"]["windows_flipped"], 0)
        self.assertEqual(rep["windows"], rep["runs"][0]["windows"])

    def test_an_order_only_scorer_is_caught_out(self):
        rep = OA.ablate(AscendingScorer(col="log_rlen"), [self.run_dir])
        modes = rep["runs"][0]["modes"]
        self.assertEqual(modes["recorded"]["comparison_flagged"], 1)
        self.assertEqual(modes["shuffled"]["comparison_flagged"], 0)
        self.assertEqual(modes["reversed"]["comparison_flagged"], 0)
        self.assertFalse(modes["shuffled"]["decisions_identical"])
        # Only the attacker's windows flip (the benign client is never flagged), and they are
        # about half of all scored windows.
        self.assertGreaterEqual(modes["shuffled"]["flip_rate"], 0.4)
        flipped = modes["shuffled"]["windows_flipped"]
        self.assertEqual(flipped, round(modes["shuffled"]["flip_rate"] * rep["runs"][0]["windows"]))
        self.assertEqual(rep["pooled"]["shuffled"]["windows_flipped"], flipped)
        self.assertEqual(rep["verdict"], "order-sensitive")
        self.assertEqual(rep["pooled"]["shuffled"]["comparison_flagged"], 0)

    def test_the_comparison_set_excludes_other_families(self):
        with open(os.path.join(self.run_dir, "manifest.json"), encoding="utf-8") as fh:
            comp, benign = OA.classify(json.load(fh))
        self.assertEqual(comp, {"10.0.2.7"})
        self.assertEqual(benign, {"10.0.1.7"})

    def test_pooled_totals_are_the_sums_over_runs(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        write_run(other.name, n=40)
        rep = OA.ablate(U.StubScorer(col="m_post"), [self.run_dir, other.name])
        self.assertEqual(len(rep["runs"]), 2)
        self.assertEqual(rep["comparison_attackers"], 2)
        self.assertEqual(rep["pooled"]["recorded"]["comparison_flagged"], 2)
        self.assertEqual(rep["pooled"]["recorded"]["benign_flagged"], 0)

    def test_the_report_is_deterministic(self):
        a = OA.ablate(AscendingScorer(col="log_rlen"), [self.run_dir], seed=3)
        b = OA.ablate(AscendingScorer(col="log_rlen"), [self.run_dir], seed=3)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_a_gzipped_recording_is_read_like_a_plain_one(self):
        with tempfile.TemporaryDirectory() as gz_dir:
            write_run(gz_dir, gz=True)
            self.assertEqual(len(OA.load_items(gz_dir)), len(OA.load_items(self.run_dir)))

    def test_a_run_without_a_recording_is_an_error(self):
        with tempfile.TemporaryDirectory() as empty, self.assertRaises(FileNotFoundError):
            OA.load_items(empty)


class VerdictTest(unittest.TestCase):
    @staticmethod
    def run_with(identical=True, flip=0.0, aligned=True):
        return {"modes": {"shuffled": {"decisions_identical": identical, "flip_rate": flip,
                                       "windows_aligned": aligned}}}

    def test_identical_decisions_and_few_flips_are_order_free(self):
        self.assertEqual(OA.verdict([self.run_with(flip=0.002)]), "order-free")

    def test_too_many_flips_make_it_order_sensitive(self):
        self.assertEqual(OA.verdict([self.run_with(flip=OA.ORDER_FREE_MAX_FLIP)]),
                         "order-sensitive")

    def test_a_changed_flagged_set_makes_it_order_sensitive(self):
        self.assertEqual(OA.verdict([self.run_with(identical=False)]), "order-sensitive")

    def test_one_bad_run_is_enough(self):
        self.assertEqual(OA.verdict([self.run_with(), self.run_with(identical=False)]),
                         "order-sensitive")

    def test_misaligned_windows_are_inconclusive(self):
        self.assertEqual(OA.verdict([self.run_with(), self.run_with(aligned=False)]),
                         "inconclusive")


class CliTest(unittest.TestCase):
    def test_main_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            pkg = os.path.join(tmp, "pkg")
            U.tiny_package(pkg)
            run_dir = os.path.join(tmp, "run")
            os.makedirs(run_dir)
            write_run(run_dir)
            out_json, out_md = os.path.join(tmp, "r.json"), os.path.join(tmp, "r.md")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = OA.main([pkg, run_dir, "--out", out_json, "--md", out_md, "--seed", "1"])
            self.assertEqual(rc, 0)
            with open(out_json, encoding="utf-8") as fh:
                rep = json.load(fh)
            self.assertEqual(rep["format"], OA.FORMAT)
            self.assertEqual(rep["package"]["path"], pkg)
            self.assertIn(rep["verdict"], ("order-free", "order-sensitive", "inconclusive"))
            with open(out_md, encoding="utf-8") as fh:
                self.assertIn("Verdict:", fh.read())
            self.assertIn("Verdict:", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
