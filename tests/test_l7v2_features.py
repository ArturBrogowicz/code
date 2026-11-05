"""L7 v2 features (docs/L7V2_DESIGN.md 8.1-8.2): the per-request navigation group and the view tokens of the
two-level model, with their summaries for the HGB and the LR. Offline and pure."""
import math
import os
import sys
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import l7v2_model_prereg

import l7_features as F
import l7_ingest

BASE = "http://10.0.0.1"
P5_DEFAULT_COLUMNS = ["valid", "log_iat", "log_rt", "log_urt", "incomplete", "s_timeout", "s2xx", "s3xx", "s4xx",
                      "s5xx", "m_get", "m_post", "m_other", "log_rlen", "log_bsent", "size_ratio", "log_creq",
                      "new_conn", "uri_repeat", "lreq_limited"]


def req(uri, start, ref=None, rt=0.01, status=200, method="GET", creq=2, sid=None, ua="Mozilla/5.0 T"):
    o = U.obj(uri=uri, msec=start + rt, rt=rt, status=status, method=method, creq=creq, ua=ua)
    if ref is not None:
        o["ref"] = BASE + ref
    if sid is not None:
        o["sid"] = sid
    return l7_ingest.normalise(o)


def browser():
    """Three views: / with two assets; /page/1 (Referer /) with one new and one cached-again asset; / again
    (a revisit, Referer /page/1, known); then the opening request of a fourth view."""
    return [req("/", 0.0, creq=1), req("/static/site6/style0.css", 0.1, ref="/"),
            req("/static/site6/app1.js", 0.12, ref="/"),
            req("/page/1", 5.0, ref="/"), req("/static/site6/p1/img0.png", 5.1, ref="/page/1"),
            req("/static/site6/style0.css", 5.2, ref="/page/1"),
            req("/", 12.0, ref="/page/1"), req("/search?q=alpha", 12.5, ref="/"),
            req("/page/2", 20.0, ref="/")]


def col(m, name):
    return m[:, list(F.TOKEN_COLUMNS).index(name)]


class GroupsTest(unittest.TestCase):
    def test_the_p5_columns_are_unchanged(self):
        self.assertEqual(F.columns(), P5_DEFAULT_COLUMNS)
        self.assertEqual(F.ALL_FEATURES[:22], (*P5_DEFAULT_COLUMNS[1:], "is_h2", "is_tls", "tls_reused"))
        self.assertEqual(F.ALL_FEATURES[22:], F.FEATURE_GROUPS["nav"])

    def test_the_v2_request_columns(self):
        self.assertEqual(F.columns(F.V2_REQUEST_GROUPS),
                         [c for c in P5_DEFAULT_COLUMNS if c not in ("log_rt", "log_urt", "log_rlen", "log_bsent",
                                                                     "size_ratio")]
                         + ["is_page", "is_asset", "is_costly", "asset_refetch", "page_revisit", "ref_present",
                            "ref_known", "log_page_gap"])

    def test_the_request_ablation_reads_no_sizes_as_p5c(self):
        # T038-03 (D-034): the seq-64 ablation's groups are P5c's published variant plus nav
        import train_l7
        self.assertEqual(list(F.V2_REQUEST_GROUPS),
                         [*train_l7.variant_groups()["no_size_no_server_timing"], "nav"])
        self.assertFalse(set(F.FEATURE_GROUPS["size"]) & set(F.columns(F.V2_REQUEST_GROUPS)))

    def test_the_constants_are_the_pre_registered_ones(self):
        pre = l7v2_model_prereg.load()
        self.assertEqual(list(F.FEATURE_GROUPS["nav"]), pre["request_level"]["nav_features"])
        self.assertEqual(list(F.V2_REQUEST_GROUPS), pre["request_level"]["groups"])
        self.assertEqual(F.PAGE_GAP_CLIP, pre["request_level"]["page_gap_clip_s"])
        self.assertEqual(list(F.TOKEN_COLUMNS), l7v2_model_prereg.token_columns())
        v = pre["views"]
        self.assertEqual((F.MAX_VIEWS, F.MIN_VIEWS, F.DWELL_CLIP, F.COUNT_CLIP),
                         (v["max_views"], v["min_views"], v["dwell_clip_s"], v["count_clip"]))
        self.assertEqual(list(F.SUMMARY_COUNTS), v["summary"]["counts"])
        sm = pre["site_map"]
        self.assertEqual((list(F.PAGE_CLASSES), list(F.ASSET_CLASSES), list(F.COSTLY_CLASSES)),
                         (sm["page"], sm["asset"], sm["costly"]))


class RequestNavTest(unittest.TestCase):
    def test_navigation_within_the_window(self):
        cols = F.columns(("nav",))
        m = F.window_matrix(browser(), 16, cols)[-9:]
        get = {c: m[:, cols.index(c)] for c in cols}
        np.testing.assert_array_equal(get["is_page"], [1, 0, 0, 1, 0, 0, 1, 0, 1])
        np.testing.assert_array_equal(get["is_asset"], [0, 1, 1, 0, 1, 1, 0, 0, 0])
        np.testing.assert_array_equal(get["is_costly"], [0, 0, 0, 0, 0, 0, 0, 1, 0])
        np.testing.assert_array_equal(get["asset_refetch"], [0, 0, 0, 0, 0, 1, 0, 0, 0])
        np.testing.assert_array_equal(get["page_revisit"], [0, 0, 0, 0, 0, 0, 1, 0, 0])
        np.testing.assert_array_equal(get["ref_present"], [0, 1, 1, 1, 1, 1, 1, 1, 1])
        np.testing.assert_array_equal(get["ref_known"], [0, 1, 1, 1, 1, 1, 1, 1, 1])
        self.assertAlmostEqual(float(get["log_page_gap"][0]), 0.0)
        self.assertAlmostEqual(float(get["log_page_gap"][3]), math.log1p(5.0), places=5)
        self.assertAlmostEqual(float(get["log_page_gap"][7]), math.log1p(0.5), places=5)

    def test_a_referer_to_a_page_outside_the_window_is_unknown(self):
        cols = F.columns(("nav",))
        m = F.window_matrix([req("/search?q=onyx", 1.0, ref="/page/search")], 4, cols)
        self.assertEqual(m[-1, cols.index("ref_present")], 1.0)
        self.assertEqual(m[-1, cols.index("ref_known")], 0.0)


class ViewTokenTest(unittest.TestCase):
    def test_three_complete_views(self):
        m = F.token_matrix(browser(), 4)
        np.testing.assert_array_equal(m[:, 0], [0, 1, 1, 1])
        t = m[1:]
        np.testing.assert_allclose(col(t, "log_dwell"), np.log1p([5.0, 7.0, 8.0]), rtol=1e-6)
        np.testing.assert_allclose(col(t, "log_n_req"), np.log1p([3, 3, 2]), rtol=1e-6)
        np.testing.assert_allclose(col(t, "asset_share"), [2 / 3, 2 / 3, 0.0], rtol=1e-6)
        np.testing.assert_allclose(col(t, "asset_refetch_share"), [0.0, 0.5, 0.0], rtol=1e-6)
        np.testing.assert_allclose(col(t, "log_n_costly"), np.log1p([0, 0, 1]), rtol=1e-6)
        np.testing.assert_array_equal(col(t, "page_view"), [1, 1, 1])
        np.testing.assert_array_equal(col(t, "page_revisit"), [0, 0, 1])
        np.testing.assert_array_equal(col(t, "ref_present"), [0, 1, 1])
        np.testing.assert_array_equal(col(t, "ref_known"), [0, 1, 1])
        np.testing.assert_allclose(col(t, "s2xx_share"), [1, 1, 1])
        np.testing.assert_allclose(col(t, "get_share"), [1, 1, 1])
        np.testing.assert_allclose(col(t, "new_conn_share"), [1 / 3, 0, 0], rtol=1e-6)
        self.assertEqual(F.n_complete_tokens(browser()), 3)

    def test_the_open_view_is_never_encoded(self):
        recs = browser()
        more = recs + [req("/static/site6/p2/img0.png", 20.2, ref="/page/2"), req("/search?q=x", 25.0, ref="/page/2")]
        np.testing.assert_array_equal(F.token_matrix(recs, 8), F.token_matrix(more, 8))

    def test_pageless_tokens_for_a_key_that_never_loads_a_page(self):
        recs = [req("/search?q=w", 3.0 * i, ref="/page/search") for i in range(5)]
        m = F.token_matrix(recs, 8)
        self.assertEqual(int(m[:, 0].sum()), 4)
        t = m[m[:, 0] > 0]
        np.testing.assert_array_equal(col(t, "page_view"), [0, 0, 0, 0])
        np.testing.assert_array_equal(col(t, "ref_present"), [1, 1, 1, 1])
        np.testing.assert_array_equal(col(t, "ref_known"), [0, 0, 0, 0])
        np.testing.assert_allclose(col(t, "log_n_costly"), np.log1p([1, 1, 1, 1]), rtol=1e-6)
        np.testing.assert_allclose(col(t, "log_dwell"), np.log1p([3.0] * 4), rtol=1e-6)

    def test_requests_before_the_first_page_are_pageless_then_the_page_view_takes_the_rest(self):
        recs = [req("/api/feed", 0.0), req("/api/feed", 1.0), req("/", 2.0), req("/api/feed", 2.5), req("/page/1", 9.0)]
        self.assertEqual(F.token_starts(F.ordered(recs)), [0, 1, 2, 4])
        t = F.view_tokens(recs, 8)
        np.testing.assert_array_equal(t[:, F.TOKEN_FEATURES.index("page_view")], [0, 0, 1])
        np.testing.assert_allclose(t[:, F.TOKEN_FEATURES.index("log_n_req")], np.log1p([1, 1, 2]), rtol=1e-6)

    def test_history_is_within_the_window(self):
        recs = [req("/page/1", 0.0), req("/page/2", 5.0), req("/page/3", 10.0), req("/page/1", 15.0),
                req("/page/4", 20.0)]
        full = F.token_matrix(recs, 8)
        short = F.token_matrix(recs, 2)
        self.assertEqual(col(full, "page_revisit")[-1], 1.0)        # /page/1 is in the 4-view window
        self.assertEqual(col(short, "page_revisit")[-1], 0.0)       # but not in the 2-view one
        np.testing.assert_array_equal(short[:, 1:], F.token_matrix(recs[2:], 2)[:, 1:])   # a cut at a boundary

    def test_the_order_is_by_start_time_not_arrival(self):
        recs = browser()
        arrived = sorted(recs, key=lambda r: -r["msec"])           # any arrival order
        np.testing.assert_array_equal(F.token_matrix(recs, 4), F.token_matrix(arrived, 4))

    def test_a_ten_times_slower_server_changes_nothing(self):
        slow = [{**r, "rt": r["rt"] * 10, "urt": r["urt"] * 10, "msec": F.start_time(r) + r["rt"] * 10}
                for r in browser()]
        np.testing.assert_allclose(F.token_matrix(browser(), 4), F.token_matrix(slow, 4), atol=1e-6)

    def test_neither_the_ua_nor_the_sid_is_a_feature(self):
        other = [req("/", 0.0, sid="a" * 32, ua="X"), req("/page/1", 4.0, sid="a" * 32, ua="X"),
                 req("/page/2", 9.0, sid="a" * 32, ua="X")]
        same = [req("/", 0.0), req("/page/1", 4.0), req("/page/2", 9.0)]
        np.testing.assert_array_equal(F.token_matrix(other, 4), F.token_matrix(same, 4))

    def test_left_padding_and_column_subsets(self):
        m = F.token_matrix(browser(), 6, ["valid", "page_revisit", "log_dwell"])
        self.assertEqual(m.shape, (6, 3))
        np.testing.assert_array_equal(m[:3], 0.0)
        np.testing.assert_array_equal(m[3:, 1], [0, 0, 1])
        self.assertEqual(F.token_matrix([req("/", 0.0)], 4).sum(), 0.0)


class SummaryTest(unittest.TestCase):
    def test_names_and_counts(self):
        vec, names = F.token_summary(F.token_matrix(browser(), 4))
        self.assertEqual(len(names), 3 * len(F.TOKEN_FEATURES) + 4)
        self.assertEqual(names[:3], ["log_dwell_mean", "log_dwell_std", "log_dwell_max"])
        self.assertEqual(names[-4:], ["n_views", "log_n_req_total", "log_span", "log_rate"])
        got = dict(zip(names, vec, strict=True))
        self.assertEqual(got["n_views"], 3.0)
        self.assertAlmostEqual(got["log_n_req_total"], math.log1p(8), places=4)
        self.assertAlmostEqual(got["log_span"], math.log1p(20.0), places=4)
        self.assertAlmostEqual(got["log_rate"], math.log1p(8 / 20.0), places=4)
        self.assertAlmostEqual(got["page_revisit_mean"], 1 / 3, places=5)

    def test_a_summary_is_blind_to_token_order(self):
        rng = np.random.default_rng(3)
        m = F.token_matrix(browser(), 6)
        s = F.shuffle_valid_rows(m, rng)
        np.testing.assert_array_equal(s[:3], 0.0)
        self.assertEqual(sorted(map(tuple, s[3:])), sorted(map(tuple, m[3:])))
        np.testing.assert_allclose(F.token_summary(s)[0], F.token_summary(m)[0], rtol=1e-6)

    def test_an_empty_window(self):
        vec, names = F.token_summary(np.zeros((4, len(F.TOKEN_COLUMNS)), np.float32))
        self.assertEqual(len(vec), len(names))
        self.assertFalse(vec.any())


if __name__ == "__main__":
    unittest.main()
