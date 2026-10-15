"""Unit tests for l7_features.py (request-sequence features; Phase P2). Offline."""
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import numpy as np

import l7_features as F

COLS = F.columns(tuple(F.FEATURE_GROUPS))        # every group, incl. protocol


def col(m, name, cols=COLS):
    return m[:, cols.index(name)]


class ColumnsTest(unittest.TestCase):
    def test_default_excludes_protocol_and_starts_with_valid(self):
        cols = F.columns()
        self.assertEqual(cols[0], F.VALID)
        for f in F.FEATURE_GROUPS["protocol"]:
            self.assertNotIn(f, cols)
        self.assertIn("log_iat", cols)

    def test_unknown_group_rejected(self):
        with self.assertRaises(ValueError):
            F.columns(("timing", "nope"))


class WindowMatrixTest(unittest.TestCase):
    def test_left_padding_and_valid_column(self):
        recs = [U.rec(msec=100.0 + i) for i in range(3)]
        m = F.window_matrix(recs, 5, COLS)
        self.assertEqual(m.shape, (5, len(COLS)))
        self.assertEqual(col(m, "valid").tolist(), [0, 0, 1, 1, 1])
        self.assertTrue(np.all(m[:2] == 0))          # padding rows are all-zero

    def test_iat_uses_request_start_times(self):
        recs = [U.rec(msec=100.5, rt=0.5), U.rec(msec=101.2, rt=0.2), U.rec(msec=103.1, rt=0.1)]
        iat = col(F.window_matrix(recs, 3, COLS), "log_iat")
        self.assertAlmostEqual(float(iat[0]), 0.0, places=5)
        self.assertAlmostEqual(float(iat[1]), math.log1p(1.0), places=5)
        self.assertAlmostEqual(float(iat[2]), math.log1p(2.0), places=5)

    def test_rows_ordered_by_start_not_arrival(self):
        # A slow 408 that ARRIVES last (long rt) but STARTED first goes first.
        fast = U.rec(msec=106.0, rt=0.01, status=200, compl="OK")
        slow = U.rec(msec=110.0, rt=5.0, status=408, compl="")
        m = F.window_matrix([fast, slow], 2, COLS)
        self.assertEqual(col(m, "incomplete").tolist(), [1.0, 0.0])
        self.assertEqual(col(m, "s_timeout").tolist(), [1.0, 0.0])
        self.assertEqual(col(m, "s4xx").tolist(), [1.0, 0.0])

    def test_status_and_method_one_hots(self):
        recs = [U.rec(msec=1.0 + i, status=s, method=meth)
                for i, (s, meth) in enumerate([(200, "GET"), (302, "POST"), (404, "HEAD"),
                                               (503, "GET"), (499, "POST")])]
        m = F.window_matrix(recs, 5, COLS)
        self.assertEqual(col(m, "s2xx").tolist(), [1, 0, 0, 0, 0])
        self.assertEqual(col(m, "s3xx").tolist(), [0, 1, 0, 0, 0])
        self.assertEqual(col(m, "s4xx").tolist(), [0, 0, 1, 0, 1])
        self.assertEqual(col(m, "s5xx").tolist(), [0, 0, 0, 1, 0])
        self.assertEqual(col(m, "s_timeout").tolist(), [0, 0, 0, 0, 1])   # 499
        self.assertEqual(col(m, "m_get").tolist(), [1, 0, 0, 1, 0])
        self.assertEqual(col(m, "m_post").tolist(), [0, 1, 0, 0, 1])
        self.assertEqual(col(m, "m_other").tolist(), [0, 0, 1, 0, 0])   # HEAD

    def test_uri_repeat_connection_and_ratelimit(self):
        recs = [U.rec(msec=1.0, uri="/a", creq=1, lreq=""),
                U.rec(msec=2.0, uri="/b", creq=2, lreq="PASSED"),
                U.rec(msec=3.0, uri="/a", creq=7, lreq="REJECTED")]
        m = F.window_matrix(recs, 3, COLS)
        self.assertEqual(col(m, "uri_repeat").tolist(), [0, 0, 1])
        self.assertEqual(col(m, "new_conn").tolist(), [1, 0, 0])
        self.assertAlmostEqual(float(col(m, "log_creq")[2]), math.log1p(7), places=5)
        self.assertEqual(col(m, "lreq_limited").tolist(), [0, 0, 1])

    def test_sizes_and_protocol(self):
        r = U.rec(rlen=300, bsent=2000, proto="HTTP/2.0", tls="TLSv1.3", reused="r")
        m = F.window_matrix([r], 1, COLS)
        self.assertAlmostEqual(float(col(m, "log_rlen")[0]), math.log1p(300), places=5)
        self.assertAlmostEqual(float(col(m, "size_ratio")[0]),
                               math.log1p(2000) - math.log1p(300), places=5)
        self.assertEqual([float(col(m, c)[0]) for c in ("is_h2", "is_tls", "tls_reused")],
                         [1.0, 1.0, 1.0])

    def test_clipping(self):
        r = U.rec(rt=1e9, urt="1e9")
        m = F.window_matrix([r], 1, COLS)
        self.assertAlmostEqual(float(col(m, "log_rt")[0]), math.log1p(F.RT_CLIP), places=4)

    def test_only_last_seq_len_records_used(self):
        recs = [U.rec(msec=float(i), uri=f"/{i}") for i in range(10)]
        m = F.window_matrix(recs, 4, COLS)
        self.assertEqual(col(m, "valid").sum(), 4)

    def test_fingerprint_invariance_by_construction(self):
        # UA never enters; URIs only via equality; time only via differences.
        base = [U.rec(msec=100.0 + 0.7 * i, uri=f"/p{i % 3}", ua="A") for i in range(8)]
        other_ua = [{**r, "ua_h": 12345} for r in base]
        renamed = [{**r, "uri_h": r["uri_h"] ^ 0x5A5A5A5A} for r in base]   # bijection
        shifted = [{**r, "msec": r["msec"] + 86400.0} for r in base]
        m0 = F.window_matrix(base, 8, COLS)
        for variant in (other_ua, renamed, shifted):
            np.testing.assert_allclose(F.window_matrix(variant, 8, COLS), m0, atol=1e-6)


class ScalingTest(unittest.TestCase):
    def test_padding_stays_zero_and_valid_untouched(self):
        cols = F.columns()
        recs = [U.rec(msec=1.0 + i, rlen=100 * (i + 1)) for i in range(3)]
        m = F.window_matrix(recs, 5, cols)
        mean = np.full(len(cols), 2.0, dtype=np.float32)
        std = np.full(len(cols), 4.0, dtype=np.float32)
        std[cols.index("s3xx")] = 0.0                    # zero std → treated as 1
        out = F.apply_scaling(m[None], mean, std)[0]
        self.assertTrue(np.all(out[:2] == 0))             # padding rows unchanged (zero)
        self.assertEqual(out[:, 0].tolist(), m[:, 0].tolist())
        j = cols.index("log_rlen")
        np.testing.assert_allclose(out[2:, j], (m[2:, j] - 2.0) / 4.0, rtol=1e-6)
        k = cols.index("s3xx")
        np.testing.assert_allclose(out[2:, k], m[2:, k] - 2.0, rtol=1e-6)


class SummaryTest(unittest.TestCase):
    def test_summary_shape_and_values(self):
        cols = F.columns()
        recs = [U.rec(msec=10.0 + i, uri="/a" if i % 2 else "/b") for i in range(4)]
        vec, names = F.window_summary(recs, cols)
        self.assertEqual(len(vec), len(names))
        self.assertEqual(len(names), 3 * (len(cols) - 1) + 4)
        self.assertEqual(vec[names.index("n")], 4)
        self.assertAlmostEqual(float(vec[names.index("uri_distinct_ratio")]), 0.5)

    def test_empty_window(self):
        vec, names = F.window_summary([], F.columns())
        self.assertTrue(np.all(vec == 0))
        self.assertEqual(len(vec), len(names))


if __name__ == "__main__":
    unittest.main()
