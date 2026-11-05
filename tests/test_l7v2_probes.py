"""The L7 v2 probe gate (docs/L7V2_DESIGN.md 8.5): the class-preserving URI bijection and sid_swap, the v2 gate, and
the P5c probe and gate kept unchanged for reproducing P5c. Offline; stub scorers only."""
import os
import sys
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_probes as P
import l7_testutil as U
import l7v2_model_prereg

import l7_features as F
import l7_ingest

SID = "0123456789abcdef0123456789abcdef"


def req(uri, start, ref=None, ip="10.0.16.5", ua="Mozilla/5.0 T", sid=SID, rt=0.02):
    o = U.obj(ip=ip, ua=ua, uri=uri, msec=start + rt, rt=rt, creq=2)
    if ref is not None:
        o["ref"] = "http://10.0.0.1" + ref
    if sid is not None:
        o["sid"] = sid
    return o


def browser(offset=0.0, ip="10.0.16.5", sid=SID):
    pages = ["/", "/page/1", "/page/search", "/page/2", "/", "/page/3", "/page/1"]
    out, prev = [], None
    for i, p in enumerate(pages):
        t = offset + 6.0 * i
        out.append(req(p, t, ref=prev, ip=ip, sid=sid))
        out.append(req("/static/site6/style0.css", t + 0.1, ref=p, ip=ip, sid=sid))
        if p == "/page/search":
            out.append(req("/search?q=alpha", t + 1.0, ref=p, ip=ip, sid=sid))
        prev = p
    return out


def bot(offset=0.0, ip="10.0.17.9", sid="f" * 32):
    """Deep links with no Referer history: every view's Referer names a page the key never loaded."""
    return [req(f"/page/{50 + i}", offset + 3.0 * i, ref="/page/search", ip=ip, sid=sid) for i in range(7)]


class ContinuousStub:
    """p = a smooth function of one column's mean over the valid rows (so any feature change moves p)."""

    def __init__(self, level, cols, col, threshold=0.5, length=8):
        self.level, self.cols, self.col, self.threshold = level, list(cols), col, threshold
        self.max_views = self.seq_len = length
        self.consecutive = 1
        self.sha256 = "stub"

    def score(self, batch):
        batch = np.asarray(batch, dtype=np.float32)
        j = self.cols.index(self.col)
        valid = batch[..., 0]
        mean = (batch[..., j] * valid).sum(axis=1) / np.maximum(valid.sum(axis=1), 1)
        return (0.05 + 0.9 * mean).astype(np.float32)


def items(objs):
    return [("record", o) for o in objs]


class TransformTest(unittest.TestCase):
    def setUp(self):
        self.recs = [l7_ingest.normalise(o) for o in browser()]
        self.rng = np.random.default_rng(1)

    def test_class_preserving_bijection(self):
        out = P.uri_bijection_class(self.recs, self.rng)
        self.assertEqual([r["rc"] for r in out], [r["rc"] for r in self.recs])
        old_ids = {r["uri_h"] for r in self.recs} | {r["ref_h"] for r in self.recs if r["ref_h"] is not None}
        new_ids = {r["uri_h"] for r in out} | {r["ref_h"] for r in out if r["ref_h"] is not None}
        self.assertEqual(len(old_ids), len(new_ids))
        self.assertFalse(old_ids & new_ids)
        for a, b in zip(self.recs, out, strict=True):
            for c, d in zip(self.recs, out, strict=True):
                self.assertEqual(a["uri_h"] == c["uri_h"], b["uri_h"] == d["uri_h"])
                self.assertEqual(a["ref_h"] == c["uri_h"], b["ref_h"] == d["uri_h"])
        self.assertTrue(all((a["ref_h"] is None) == (b["ref_h"] is None) for a, b in zip(self.recs, out, strict=True)))

    def test_the_p5c_bijection_is_unchanged_and_leaves_referers(self):
        out = P.uri_bijection(self.recs, np.random.default_rng(1))
        self.assertEqual([r["ref_h"] for r in out], [r["ref_h"] for r in self.recs])
        self.assertNotEqual([r["uri_h"] for r in out], [r["uri_h"] for r in self.recs])

    def test_sid_swap(self):
        mixed = self.recs + [l7_ingest.normalise(req("/api/x", 1.0, sid=None))]
        out = P.sid_swap(mixed, self.rng)
        self.assertEqual(len({r["sid_h"] for r in out[:-1]}), 1)
        self.assertNotEqual(out[0]["sid_h"], self.recs[0]["sid_h"])
        self.assertEqual(out[-1]["sid_h"], l7_ingest.NO_SID)

    def test_the_p5c_sets_are_unchanged(self):
        self.assertEqual(list(P.TRANSFORMS), ["ua_swap", "uri_bijection", "time_offset", "pad_request", "iat_jitter",
                                              "server_load"])
        self.assertEqual(P.GATE_PROBES, ("ua_swap", "uri_bijection", "time_offset", "server_load"))
        self.assertEqual(list(P.TRANSFORMS_V2)[:6], list(P.TRANSFORMS))
        self.assertEqual(list(P.TRANSFORMS_V2)[6:], ["uri_bijection_class", "sid_swap"])

    def test_the_gates_are_the_pre_registered_ones(self):
        pr = l7v2_model_prereg.load()["probes"]
        self.assertEqual(list(P.GATE_PROBES_V2), pr["gate_v2"])
        self.assertEqual(list(P.GATE_PROBES), pr["gate_p5c"])
        self.assertEqual((P.EXACT_TOL, P.FLIP_TOL, P.LOAD_FACTOR), (pr["exact_tol"], pr["flip_tol"], pr["load_factor"]))
        self.assertTrue(all(P.TRANSFORMS_V2[n][1] for n in P.GATE_PROBES_V2))      # every gate probe is exact


class ViewGateTest(unittest.TestCase):
    def windows(self):
        objs = sorted(browser() + bot() + browser(100.0, ip="10.0.16.6", sid="a" * 32),
                      key=lambda o: o["msec"])
        return P.view_windows_from_items(items(objs), max_views=8, min_views=2)

    def test_view_windows_follow_complete_tokens(self):
        ws = self.windows()
        self.assertTrue(ws)
        for w in ws:
            self.assertGreaterEqual(F.n_complete_tokens(w), 2)
            self.assertEqual(len({l7_ingest.key_v2(r) for r in w}), 1)

    def test_a_referer_reading_model_passes_v2_and_fails_the_p5c_bijection(self):
        stub = ContinuousStub("view", F.TOKEN_COLUMNS, "ref_known")
        rep = P.run_probes(stub, self.windows(), transforms=P.TRANSFORMS_V2, seed=0)
        for name in P.GATE_PROBES_V2:
            self.assertTrue(rep[name]["pass"], name)
            self.assertLessEqual(rep[name]["max_abs_dp"], P.EXACT_TOL)
        self.assertFalse(rep["uri_bijection"]["pass"])                 # F-V8: the random rename breaks ref_known
        self.assertTrue(P.gate_pass(rep, P.GATE_PROBES_V2))
        self.assertFalse(P.gate_pass(rep))                             # the P5c gate would reject it

    def test_a_revisit_reading_model_passes_both_bijections(self):
        stub = ContinuousStub("view", F.TOKEN_COLUMNS, "page_revisit")
        rep = P.run_probes(stub, self.windows(), transforms=P.TRANSFORMS_V2, seed=0)
        self.assertTrue(rep["uri_bijection"]["pass"])
        self.assertTrue(rep["uri_bijection_class"]["pass"])

    def test_a_dwell_reading_model_is_exact_under_server_load(self):
        stub = ContinuousStub("view", F.TOKEN_COLUMNS, "log_dwell")
        rep = P.run_probes(stub, self.windows(), transforms=P.TRANSFORMS_V2, seed=0)
        self.assertTrue(rep["server_load"]["pass"])
        self.assertGreater(rep["iat_jitter"]["mean_abs_dp"], 0.0)      # the gaps move, the robustness probe sees it


class RequestLevelV2Test(unittest.TestCase):
    def test_the_seq64_ablation_columns_pass_the_v2_gate(self):
        cols = F.columns(F.V2_REQUEST_GROUPS)
        recs = [l7_ingest.normalise(o) for o in sorted(browser() + bot(), key=lambda o: o["msec"])]
        by_key = {}
        for r in recs:
            by_key.setdefault(l7_ingest.key_v2(r), []).append(r)
        windows = [seq[:n] for seq in by_key.values() for n in range(5, len(seq) + 1)]
        stub = ContinuousStub("request", cols, "ref_known", length=64)
        rep = P.run_probes(stub, windows, transforms=P.TRANSFORMS_V2, seed=0)
        self.assertTrue(P.gate_pass(rep, P.GATE_PROBES_V2))
        self.assertFalse(rep["uri_bijection"]["pass"])


if __name__ == "__main__":
    unittest.main()
