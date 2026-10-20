"""Tests for eval/run_level_stats.py (audit G-06).

Needs the venv (pandas, numpy, scipy):  venv/bin/python -m unittest discover -s tests -v

* The statistics (t-interval, paired t, sign-flip, Welch, permutation, power, the decision
  rule) against hand calculations, scipy and brute-force enumeration.
* End to end on a synthetic campaign built like tests/test_campaign_analysis.py.
* A reproduction pin: the published R3 campaign gives the run-level table of audit §9.3.
"""
import contextlib
import io
import itertools
import math
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
try:
    import numpy as np
    import run_level_stats as RLS
    from scipy import stats
    from test_campaign_analysis import SCEN, make_run
    HAVE_STACK = True
except ImportError:                      # system python without pandas/scipy: skip
    HAVE_STACK = False

R3 = os.path.join(REPO, "results", "2026-10-13_exp2a-knee_reproduction")


def brute_signflip(d):
    obs = abs(sum(d))
    hits = sum(abs(sum(s * x for s, x in zip(signs, d, strict=True))) >= obs - 1e-9
               for signs in itertools.product((1, -1), repeat=len(d)))
    return hits / 2 ** len(d)


@unittest.skipUnless(HAVE_STACK, "needs pandas/numpy/scipy (run with venv/bin/python)")
class StatisticsTest(unittest.TestCase):
    def test_t_interval_matches_the_hand_calculation(self):
        mean, lo, hi = RLS.t_interval([1, 2, 3, 4, 5])
        self.assertAlmostEqual(mean, 3.0)
        self.assertAlmostEqual(lo, 1.0369, places=3)      # 3 -/+ 2.7764 * 1.5811 / sqrt(5)
        self.assertAlmostEqual(hi, 4.9631, places=3)

    def test_t_interval_needs_two_values(self):
        mean, lo, hi = RLS.t_interval([4.0])
        self.assertEqual(mean, 4.0)
        self.assertTrue(math.isnan(lo) and math.isnan(hi))

    def test_paired_t_p_matches_scipy(self):
        d = [3.0, -1.5, 2.2, 0.7, 4.1, 1.9]
        self.assertAlmostEqual(RLS.paired_t_p(d), stats.ttest_1samp(d, 0).pvalue, places=10)

    def test_paired_t_p_of_constant_differences(self):
        self.assertEqual(RLS.paired_t_p([5.0, 5.0, 5.0]), 0.0)
        self.assertEqual(RLS.paired_t_p([0.0, 0.0, 0.0]), 1.0)
        self.assertTrue(math.isnan(RLS.paired_t_p([1.0])))

    def test_signflip_small_cases(self):
        self.assertAlmostEqual(RLS.signflip_p([1, 1, 1]), 0.25)       # the floor for n = 3
        self.assertAlmostEqual(RLS.signflip_p([1, 2]), 0.5)
        self.assertEqual(RLS.signflip_p([1, -1]), 1.0)
        self.assertEqual(RLS.signflip_p([0, 0, 0]), 1.0)

    def test_signflip_equals_brute_force(self):
        for d in ([3.0, -1.5, 2.2, 0.7, -0.4, 1.9], [10, 12, -3, 7, 9, 11, 8], [0.5] * 6):
            self.assertAlmostEqual(RLS.signflip_p(d), brute_signflip(d), places=12, msg=str(d))

    def test_signflip_floor_is_two_over_two_to_n(self):
        for n in (3, 5, 10):
            self.assertAlmostEqual(RLS.signflip_p([1.0] * n), 2 / 2 ** n)

    def test_signflip_monte_carlo_branch_is_deterministic_and_small(self):
        d = [1.0] * (RLS.EXACT_MAX_N + 2)
        p = RLS.signflip_p(d)
        self.assertEqual(p, RLS.signflip_p(d))
        self.assertTrue(0 < p < 1e-3)

    def test_same_sign_share(self):
        self.assertAlmostEqual(RLS.same_sign_share([3, 2, -1, 4]), 0.75)
        self.assertEqual(RLS.same_sign_share([1, -1]), 0.0)           # mean 0: no majority
        self.assertAlmostEqual(RLS.same_sign_share([-3, -2, 1]), 2 / 3)

    def test_welch_matches_scipy(self):
        a, b = [53.0, 53.0, 51.0], [89.0, 87.0, 93.0]
        diff, lo, hi, p = RLS.welch(a, b)
        self.assertAlmostEqual(diff, np.mean(a) - np.mean(b))
        self.assertAlmostEqual(p, stats.ttest_ind(a, b, equal_var=False).pvalue, places=10)
        self.assertLess(lo, diff)
        self.assertGreater(hi, diff)

    def test_exact_permutation_p(self):
        self.assertAlmostEqual(RLS.exact_permutation_p([1, 2, 3], [4, 5, 6]), 2 / 20)
        self.assertEqual(RLS.exact_permutation_p([1, 1], [1, 1]), 1.0)
        self.assertTrue(math.isnan(RLS.exact_permutation_p(list(range(11)), list(range(11)))))


@unittest.skipUnless(HAVE_STACK, "needs pandas/numpy/scipy (run with venv/bin/python)")
class DecisionTest(unittest.TestCase):
    def test_a_clear_positive_effect_is_supported(self):
        d = [20 + (i % 3) for i in range(10)]
        self.assertEqual(RLS.decide(d), "supported (+)")

    def test_a_clear_negative_effect_is_supported(self):
        d = [-30 - (i % 4) for i in range(12)]
        self.assertEqual(RLS.decide(d), "supported (-)")

    def test_an_interval_that_includes_zero_is_not_shown(self):
        d = [10, -8, 15, -2, 9, -11, 14, 3, -5, 12]
        _, lo, hi = RLS.t_interval(d)
        self.assertTrue(lo < 0 < hi)
        self.assertEqual(RLS.decide(d), "not shown")

    def test_a_few_extreme_blocks_cannot_carry_the_decision(self):
        d = [100.0] * 7 + [-1.0] * 3          # interval excludes 0, but only 70 % share the sign
        _, lo, _ = RLS.t_interval(d)
        self.assertGreater(lo, 0)
        self.assertEqual(RLS.decide(d), "not shown")

    def test_fewer_than_the_minimum_blocks(self):
        self.assertEqual(RLS.decide([20.0, 21.0, 22.0, 20.0, 21.0]),
                         "too few blocks (5 < 10)")
        self.assertEqual(RLS.decide([20.0, 21.0, 22.0], min_blocks=3), "supported (+)")

    def test_the_rule_constants_are_the_registered_ones(self):
        # Changing these after data exist would void the pre-registration (module doc).
        self.assertEqual((RLS.LEVEL, RLS.MIN_BLOCKS, RLS.SAME_SIGN_SHARE), (0.95, 10, 0.8))


@unittest.skipUnless(HAVE_STACK, "needs pandas/numpy/scipy (run with venv/bin/python)")
class PowerTest(unittest.TestCase):
    def test_blocks_for_80_percent_power_match_audit_9_3(self):
        self.assertEqual(RLS.blocks_for_power(6.3, 11.0), 26)         # R3-sized limits effect
        self.assertEqual(RLS.blocks_for_power(35.0, 20.2), 5)
        self.assertEqual(RLS.blocks_for_power(25.0, 14.0), 5)

    def test_no_answer_without_an_effect_or_spread(self):
        self.assertIsNone(RLS.blocks_for_power(0.0, 10.0))
        self.assertIsNone(RLS.blocks_for_power(5.0, 0.0))
        self.assertIsNone(RLS.blocks_for_power(5.0, None))

    def test_a_tiny_effect_needs_more_than_the_search_limit(self):
        self.assertIsNone(RLS.blocks_for_power(0.01, 10.0, max_n=50))


@unittest.skipUnless(HAVE_STACK, "needs pandas/numpy/scipy (run with venv/bin/python)")
class CampaignTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.addCleanup(self.tmp.cleanup)

    def paired_campaign(self):
        # during-success per run: xdp 100/100/100, unprotected 50/70/80  ->  diffs 50/30/20
        for seed, un in ((1, [1] * 5 + [0] * 5), (2, [1] * 7 + [0] * 3), (3, [1] * 8 + [0] * 2)):
            make_run(self.root, "xdp", f"run{seed}", seed, [1] * 10)
            make_run(self.root, "unprotected", f"run{seed}", seed, un)
        import campaign as C
        return C.load(self.root)

    def test_paired_contrast_by_profile_seed(self):
        df = RLS.contrasts(self.paired_campaign())
        self.assertEqual(len(df), 1)
        r = df.iloc[0]
        self.assertEqual((r.scenario, r["mode"], r.reference, r.period),
                         (SCEN, "xdp", "unprotected", "during"))
        self.assertEqual(r.design, "paired by PROFILE_SEED (3 blocks)")
        self.assertAlmostEqual(r.mean_diff_pp, 100 / 3, places=6)
        self.assertAlmostEqual(r.perm_p, 0.25)                         # 3 blocks: the floor
        self.assertAlmostEqual(r.same_sign, 1.0)
        self.assertEqual(r.decision, "too few blocks (3 < 10)")

    def test_the_interval_of_the_three_blocks_includes_zero(self):
        df = RLS.contrasts(self.paired_campaign(), min_blocks=3)
        r = df.iloc[0]
        self.assertLess(r.ci_lo, 0)
        self.assertGreater(r.ci_hi, 60)
        self.assertEqual(r.decision, "not shown")

    def test_blocks_are_matched_by_seed_not_by_run_name(self):
        # xdp run1 has seed 3 and run3 has seed 1: pairing by name would flip the sign of two blocks.
        make_run(self.root, "xdp", "run1", 3, [1] * 10)
        make_run(self.root, "xdp", "run2", 2, [1] * 10)
        make_run(self.root, "xdp", "run3", 1, [1] * 4 + [0] * 6)          # 40 %
        for seed, oks in ((1, [1] * 5 + [0] * 5), (2, [1] * 7 + [0] * 3), (3, [1] * 8 + [0] * 2)):
            make_run(self.root, "unprotected", f"run{seed}", seed, oks)
        import campaign as C
        r = RLS.contrasts(C.load(self.root)).iloc[0]
        # seed 1: 40 - 50; seed 2: 100 - 70; seed 3: 100 - 80
        self.assertAlmostEqual(r.mean_diff_pp, (-10 + 30 + 20) / 3, places=6)

    def test_runs_without_seeds_are_compared_unpaired(self):
        for i, (x, u) in enumerate((([1] * 10, [1] * 5 + [0] * 5),
                                    ([1] * 10, [1] * 7 + [0] * 3),
                                    ([1] * 9 + [0], [1] * 8 + [0] * 2)), 1):
            make_run(self.root, "xdp", f"run{i}", None, x)
            make_run(self.root, "unprotected", f"run{i}", None, u)
        import campaign as C
        r = RLS.contrasts(C.load(self.root)).iloc[0]
        self.assertTrue(r.design.startswith("unpaired (3 vs 3 runs)"))
        self.assertEqual(r.decision, "unpaired: descriptive only")
        self.assertAlmostEqual(r.perm_p, 0.1)                          # 2 / C(6, 3)

    def test_without_the_reference_mode_there_is_nothing_to_compare(self):
        make_run(self.root, "xdp", "run1", 1, [1] * 10)
        import campaign as C
        self.assertTrue(RLS.contrasts(C.load(self.root)).empty)

    def test_the_result_is_deterministic(self):
        data = self.paired_campaign()
        a, b = RLS.contrasts(data), RLS.contrasts(data)
        self.assertEqual(RLS.to_markdown(a), RLS.to_markdown(b))

    def test_main_writes_markdown_and_csv(self):
        self.paired_campaign()
        out_md, out_csv = os.path.join(self.root, "t.md"), os.path.join(self.root, "t.csv")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = RLS.main([self.root, "--md", out_md, "--csv", out_csv, "--min-blocks", "3"])
        self.assertEqual(rc, 0)
        with open(out_md, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), buf.getvalue())
        with open(out_csv, encoding="utf-8") as fh:
            self.assertIn("mean_diff_pp", fh.readline())

    def test_main_stops_without_a_reference_mode(self):
        make_run(self.root, "xdp", "run1", 1, [1] * 10)
        with self.assertRaises(SystemExit):
            RLS.main([self.root])


@unittest.skipUnless(HAVE_STACK and os.path.isdir(R3), "needs pandas/numpy/scipy and the published R3")
class PublishedR3ReproductionTest(unittest.TestCase):
    """A reproduction pin of docs audit §9.3 (the run-level re-analysis of R3), not a
    validation: the audit used per-run percentages rounded to integers, this tool uses the
    exact ok / n, so the numbers differ by up to 0.6 pp and the conclusions do not."""

    @classmethod
    def setUpClass(cls):
        import campaign as C
        cls.df = RLS.contrasts(C.load(R3)).set_index("mode")

    def test_daemon_modes_vs_unprotected(self):
        for mode in ("xdp", "iptables"):
            r = self.df.loc[mode]
            self.assertAlmostEqual(r.mean_diff_pp, 21.0, delta=0.6)
            self.assertLess(r.ci_lo, 0)                               # interval includes 0
            self.assertAlmostEqual(r.perm_p, 0.25)
            self.assertEqual(r.blocks, 3)

    def test_limits_only_vs_unprotected(self):
        r = self.df.loc["nginxlimits"]
        self.assertAlmostEqual(r.mean_diff_pp, -6.4, delta=0.6)
        self.assertAlmostEqual(r.same_sign, 2 / 3)
        self.assertEqual(r.blocks_for_80pct_power, 26)
        self.assertTrue(r.decision.startswith("too few blocks"))


if __name__ == "__main__":
    unittest.main()
