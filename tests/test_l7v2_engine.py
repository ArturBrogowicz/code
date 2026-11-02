"""The L7 v2 observe-only view engine (docs/L7V2_DESIGN.md 8.1, 8.3, 9.1): (IP, UA, sid) keys, one window per
completed view token, batched scoring, the P5 load and age gates, no ban path; and train/serve parity with the
trainer's view windows. Offline; stub scorers only."""
import os
import sys
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import l7v2_model_prereg as PRE
import replay_l7
import train_l7v2 as V

import l7_engine as E
import l7_features as F
import l7_ingest as I


def obj(uri, start, ip, sid, ref=None, ua="Mozilla/5.0 T", rt=0.02):
    o = U.obj(ip=ip, ua=ua, uri=uri, msec=start + rt, rt=rt, creq=2)
    o["sid"] = sid
    if ref is not None:
        o["ref"] = "http://10.0.0.1" + ref
    return o


def browser(ip="10.0.16.5", sid="a" * 32, views=8, t0=0.0, gap=6.0):
    out, prev = [], None
    for v in range(views):
        page = "/" if v == 0 else f"/page/{v % 3}"
        out.append(obj(page, t0 + gap * v, ip, sid, prev))
        out.append(obj(f"/static/site6/p{v}/img0.png", t0 + gap * v + 0.2, ip, sid, page))
        prev = page
    return out


def bot(ip="10.0.17.5", sid="b" * 32, views=8, t0=0.5, gap=3.0):
    out = []
    for v in range(views):
        out.append(obj(f"/page/{100 + v}", t0 + gap * v, ip, sid, "/page/search"))
        out.append(obj("/search?q=alpha", t0 + gap * v + 0.3, ip, sid, f"/page/{100 + v}"))
    return out


class RefStub:
    """View-level stub: p = 0.99 when the window's mean ref_known is below 0.5 (a deep-linking bot), else 0.01."""

    level = "view"

    def __init__(self, max_views=8, threshold=0.5, consecutive=2):
        self.cols, self.max_views, self.seq_len = list(F.TOKEN_COLUMNS), max_views, max_views
        self.threshold, self.consecutive, self.sha256, self.calls = threshold, consecutive, "stub", []

    def score(self, batch):
        batch = np.asarray(batch, np.float32)
        self.calls.append(len(batch))
        j = self.cols.index("ref_known")
        valid = batch[..., 0]
        mean = (batch[..., j] * valid).sum(axis=1) / np.maximum(valid.sum(axis=1), 1)
        return np.where(mean < 0.5, 0.99, 0.01).astype(np.float32)


def engine(scorer=None, **kw):
    store = I.L7KeyStore(idle_timeout=kw.pop("idle", 300.0), max_views=8)
    return E.L7ViewEngine(store, scorer=scorer, max_views=None if scorer else 8, **kw)


def run(eng, objs, poll_after_each=True):
    """Feed objects in completion order; poll after each record (or once at the end)."""
    events = []
    objs = sorted(objs, key=lambda o: o["msec"])
    for o in objs:
        eng.on_record(I.normalise(o))
        if poll_after_each:
            events += eng.poll(o["msec"])
    if not poll_after_each:
        events += eng.poll(objs[-1]["msec"])
    return events


class ViewEngineTest(unittest.TestCase):
    def test_only_the_bot_would_be_banned_with_its_v2_key(self):
        stub = RefStub()
        events = run(engine(stub), browser() + bot())
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual((ev["kind"], ev["level"], ev["ip"], ev["hits"]), ("l7_would_ban", "view", "10.0.17.5", 2))
        self.assertEqual(ev["sid_h"], I.stable_hash32("b" * 32))
        self.assertEqual(ev["n_views"], 5)

    def test_one_window_per_completed_view(self):
        eng = engine(RefStub())
        run(eng, browser(views=10))
        self.assertEqual(eng.totals["windows"], 10 - 1 - 4 + 1)          # complete tokens 4..9

    def test_a_late_poll_scores_at_most_max_new_windows_in_one_batch(self):
        stub = RefStub()
        eng = engine(stub)
        run(eng, browser(views=10) + bot(views=10), poll_after_each=False)
        self.assertEqual(stub.calls, [2 * E.MAX_NEW_WINDOWS])           # one batch
        self.assertEqual(eng.take_summary()["skipped"], 2 * (6 - E.MAX_NEW_WINDOWS))

    def test_the_sid_separates_pool_users(self):
        eng = engine()
        run(eng, browser(ip="10.0.16.9", sid="c" * 32) + browser(ip="10.0.16.9", sid="d" * 32, t0=1.0))
        self.assertEqual(eng.store.stats()["active_keys"], 2)
        self.assertEqual(eng.store.stats()["distinct_ips"], 1)

    def test_features_only_mode_counts_windows(self):
        eng = E.build_engine(None, level="view")
        self.assertIsInstance(eng, E.L7ViewEngine)
        self.assertEqual(run(eng, browser(views=6)), [])
        self.assertEqual(eng.totals["windows"], 6 - 1 - 4 + 1)

    def test_flood_suppression_and_the_age_gate(self):
        stub = RefStub()
        eng = engine(stub)
        objs = sorted(bot(views=12), key=lambda o: o["msec"])
        first, rest = objs[:12], objs[12:]
        run(eng, first)
        self.assertEqual(eng.poll(20.0, suppressing=True), [])
        self.assertEqual(eng.hits, {})                                    # a flood clears streaks
        eng.poll(20.5)                                                    # the flood ended: trust after 20.5
        self.assertEqual(eng.trust_after, 20.5)
        run(eng, rest[:2])                                                # windows mostly before 20.5: gated
        self.assertGreater(eng.take_summary()["gated_age"], 0)

    def test_eviction_of_an_idle_key(self):
        eng = engine(RefStub(), idle=60.0)
        run(eng, bot(views=6))
        eng.poll(100.0)
        eng.poll(200.0)
        self.assertEqual(eng.store.stats()["active_keys"], 0)

    def test_late_records_before_the_pruned_history_are_dropped(self):
        eng = engine(RefStub())
        run(eng, bot(views=14))
        eng.on_record(I.normalise(obj("/static/x.css", 0.6, "10.0.17.5", "b" * 32)))
        self.assertEqual(eng.store.stats()["late_dropped"], 1)

    def test_a_request_level_scorer_is_refused(self):
        with self.assertRaises(ValueError):
            engine(U.StubScorer())

    def test_observe_only(self):
        with open(os.path.join(REPO, "l7_engine.py"), encoding="utf-8") as fh:
            src = fh.read()
        for word in ("ban_ip", "bpf", "subprocess", "nginx -s"):
            self.assertNotIn(word, src)

    def test_the_constants_are_the_pre_registered_ones(self):
        pre = PRE.load()
        e = pre["engine"]
        self.assertEqual((E.DEFAULT_MIN_VIEWS, E.MAX_NEW_WINDOWS, E.CONTAMINATION_MAX, E.DEFAULT_EVICT_EVERY),
                         (e["min_views"], e["max_new_windows_per_key_per_poll"], e["contamination_max"],
                          e["evict_every_s"]))
        self.assertEqual((I.V2_IDLE_TIMEOUT, I.V2_MAX_RECORDS, I.V2_MAX_VIEWS, list(I.V2_PAGE_CLASSES)),
                         (pre["ingest"]["idle_timeout_s"], e["max_records_per_key"], pre["views"]["max_views"],
                          pre["site_map"]["page"]))


class ParityTest(unittest.TestCase):
    def test_the_engine_scores_the_trainers_windows(self):
        objs = (browser(views=12) + bot(views=12) + browser(ip="10.0.16.9", sid="c" * 32, views=9, t0=2.0)
                + [obj(f"/search?q=w{i}", 1.0 + 2.5 * i, "10.0.18.1", "e" * 32, "/page/search") for i in range(15)])
        seen = {}

        def hook(_now, key, recs, _p):
            seen.setdefault(key, []).append(F.token_matrix(recs, 8))

        eng = E.L7ViewEngine(I.L7KeyStore(max_views=8), max_views=8, window_hook=hook)
        run(eng, objs)
        recs = []
        for i, o in enumerate(sorted(objs, key=lambda o: o["msec"])):
            r = I.normalise(o)
            r.update({"_seq": i, "_cls": "benign", "_family": None, "_held": False, "_kof": None, "_cap": "c",
                      "_ent": r["ip"]})
            recs.append(r)
        want = {}
        for w in V.view_windows(recs, 8, 4, idle_s=300.0):
            want.setdefault(w["key"], []).append(w["X"])
        self.assertEqual(set(seen), set(want))
        for key, mats in want.items():
            self.assertEqual(len(seen[key]), len(mats), key)
            for a, b in zip(seen[key], mats, strict=True):
                np.testing.assert_array_equal(a, b)

    def test_k_consecutive_counts_the_windows_the_engine_scores(self):
        # T038-06 (D-034): a pageless key completes 8 windows per second, more than the engine's 4 per poll. Within each
        # second its windows score H L L L L H H H (by the dwell of the last complete token); the engine scores the newest
        # 4 of each poll (L H H H), so k = 4 never fires live, while every window in a row (H H H | H) would fire offline.
        offs, objs = (0.0, 0.05, 0.10, 0.15, 0.20, 0.40, 0.60, 0.80), []
        for sec in range(4):
            objs += [obj(f"/search?q=w{sec}{k}", 10.0 + sec + o, "10.0.18.7", "f" * 32, "/page/search")
                     for k, o in enumerate(offs)]

        class DwellStub(RefStub):
            def __init__(self):
                super().__init__(consecutive=4)

            def score(self, batch):
                batch = np.asarray(batch, np.float32)
                j = self.cols.index("log_dwell")
                last = [row[np.flatnonzero(row[:, 0] > 0)[-1], j] for row in batch]
                return np.array([0.99 if v > np.log1p(0.1) else 0.01 for v in last], np.float32)

        stub = DwellStub()
        eng = engine(stub)
        live, objs = [], sorted(objs, key=lambda o: o["msec"])
        nxt = 11.0
        for o in objs:
            while o["msec"] >= nxt:                     # polls at whole seconds of the log clock
                live += eng.poll(nxt)
                nxt += 1.0
            eng.on_record(I.normalise(o))
        live += eng.poll(nxt)
        self.assertGreater(eng.totals["windows"], 0)
        recs = []
        for i, o in enumerate(objs):
            r = I.normalise(o)
            r.update({"_seq": i, "_cls": "attack", "_family": "C2", "_held": False, "_kof": "C2", "_cap": "c",
                      "_ent": "c|bot"})
            recs.append(r)
        ws = V.view_windows(recs, 8, 4, idle_s=300.0)
        p = stub.score(np.stack([w["X"] for w in ws]))
        offline = V.decisions(V.key_runs(ws, p), stub.threshold, stub.consecutive)
        self.assertEqual(len(V.engine_scored(ws)), eng.totals["windows"], "the same windows are scored")
        self.assertEqual([e for e in live if e["kind"] == "l7_would_ban"], [])
        self.assertEqual([when for _e, when in offline.values()], [None], "offline agrees: no decision")
        every = V.decisions({k: [(w["t"], float(q), "c|bot") for w, q in zip(ws, p, strict=True)] for k in offline},
                            stub.threshold, stub.consecutive)
        self.assertIsNotNone(next(iter(every.values()))[1], "scoring every window would have fired")

    @staticmethod
    def split_of(objs):
        recs = []
        for i, o in enumerate(sorted(objs, key=lambda o: o["msec"])):
            r = I.normalise(o)
            r.update({"_seq": i, "_cls": "benign", "_family": None, "_held": False, "_kof": None, "_cap": "c",
                      "_ent": "c|" + r["ip"]})
            recs.append(r)
        return V.Split([({"format": "x", "entities": []}, recs, "c")], request=False)

    def test_the_parity_report_on_a_friendly_key(self):
        split = self.split_of(browser(views=12))
        rep = V.engine_parity(split)["c"]
        self.assertEqual(set(rep), {"0.0", "0.5"}, "the live poll phase is arbitrary, so two are reported")
        n = len(split.view)
        self.assertGreater(n, 0)
        for r in rep.values():
            self.assertEqual((r["trainer_windows"], r["engine_windows"], r["same"]), (n, n, n))
            self.assertEqual((r["built_differently"], r["trainer_only"], r["engine_only"], r["late_dropped"]), (0, 0, 0, 0))

    def test_a_slow_asset_is_missing_from_the_engines_window(self):
        # T-042 F06: an asset that completes after the next page's poll is absent from the engine's window only
        objs = browser(views=12, gap=6.0)
        for o in objs:
            if "/static/" in o["uri"]:
                o.update(rt=8.0, msec=o["msec"] - o["rt"] + 8.0)     # the same start, 8 s to complete
        split = self.split_of(objs)
        r = V.engine_parity(split)["c"]["0.0"]
        expected = 0
        for w in split.view:                                       # an independent reconstruction of the same windows
            poll = (np.floor(w["t"]) + 1.0)
            there = [x for x in w["recs"] if x["msec"] < poll]
            expected += int(not np.array_equal(F.token_matrix(there, F.MAX_VIEWS), w["X"]))
        self.assertGreater(expected, 0)
        self.assertEqual(r["built_differently"], expected)
        self.assertEqual(r["same"] + r["built_differently"] + r["trainer_only"], len(split.view))
        built, _store = V.engine_replay(split.records["c"], 0.0)
        w = split.view[0]
        j = list(F.TOKEN_COLUMNS).index("log_n_req")
        ours, theirs = w["X"], built[(w["key"], F.start_time(w["recs"][-1]))][0]
        self.assertGreater(ours[:, j].sum(), theirs[:, j].sum(), "the evaluator counts the late assets, the engine not")

    def test_the_report_counts_the_cap_and_agrees_with_the_rule(self):
        offs = [k / 8.0 for k in range(8)]
        objs = [obj(f"/search?q=w{sec}{k}", 10.0 + sec + o, "10.0.18.7", "f" * 32, "/page/search")
                for sec in range(4) for k, o in enumerate(offs)]
        split = self.split_of(objs)
        r = V.engine_parity(split)["c"]["0.0"]
        self.assertGreater(r["trainer_only"], 0)
        self.assertEqual(r["engine_windows"], len(V.engine_scored(split.view)))
        self.assertEqual((r["rule_not_engine"], r["engine_not_rule"], r["built_differently"]), (0, 0, 0))

    def test_a_request_older_than_the_pruned_history_is_dropped_and_counted(self):
        objs = [obj(f"/page/{k}", 1.0 + k, "10.0.16.8", "d" * 32) for k in range(60)]
        objs.append(obj("/static/site6/p0/img0.png", 1.1, "10.0.16.8", "d" * 32, rt=55.0))
        r = V.engine_parity(self.split_of(objs))["c"]["0.0"]
        self.assertEqual(r["late_dropped"], 1)
        self.assertGreater(r["built_differently"], 0)

    def test_replay_drives_the_view_engine(self):
        stub = RefStub()
        eng = engine(stub)
        items = [("record", o) for o in sorted(browser() + bot(), key=lambda o: o["msec"])]
        events = replay_l7.replay(items, eng, poll_every=1.0)
        bans = [e for e in events if e["kind"] == "l7_would_ban"]
        self.assertEqual([e["ip"] for e in bans], ["10.0.17.5"])
        final = [e for e in events if e.get("final")]
        self.assertEqual(final[0]["level"], "view")


if __name__ == "__main__":
    unittest.main()


class AblationPackageTest(unittest.TestCase):
    def test_the_engine_refuses_the_offline_request_ablation(self):
        import tempfile

        import torch

        import l7_scorer as S
        from GRU_ML_model import GRUDDoSClassifier
        cols = F.columns(F.V2_REQUEST_GROUPS)
        torch.manual_seed(0)
        model = GRUDDoSClassifier(input_size=len(cols), hidden_size=8, num_layers=1).eval()
        mean, std = np.zeros(len(cols), np.float32), np.ones(len(cols), np.float32)
        with tempfile.TemporaryDirectory() as tmp:
            S.save_package(os.path.join(tmp, "v2"), model, cols, 64, mean, std, 0.9, 3, 8, 1, level="request")
            with self.assertRaises(ValueError):
                E.build_engine(os.path.join(tmp, "v2"))
            U.tiny_package(os.path.join(tmp, "p5c"))
            self.assertIsInstance(E.build_engine(os.path.join(tmp, "p5c")), E.L7ShadowEngine)
