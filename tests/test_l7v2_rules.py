"""The L7 v2 rule arms (ml/l7v2_rules.py, ml/l7v2_rules_prereg.json; docs/L7V2_DESIGN.md 9.5, 10): the pinned spec and
its sources, the causal statistics, the vectorised policy against train_l7v2's, tuning at the common budget on
validation only, R*, and the packages behind score(batch) -> p. Offline and pure (synthetic records)."""
import hashlib
import json
import os
import random
import re
import sys
import tempfile
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.join(REPO, "tests"))
import l7_baselines
import l7_testutil as U
import l7_traffic
import l7v2_model_prereg as MPRE
import l7v2_rules as R
import l7v2_verdict_prereg as VPRE
import train_l7v2 as V

import l7_dataset as D
import l7_ingest as I

SPEC_SHA256 = "f179cf4b325a61616fc3f6f636a86286ebcb323d97378bd5914679fdb659dd9d"
COSTS = {"C0": 0.05, "C1": 3.0, "C2": 2.0, "C3": 30.0, "C5": 150.0}


def make_capture(cap="val2001", n_benign=6, attackers=((4.0, 60.0, 240.0),), seed=0, t0=1000.0):
    """(manifest, records, capture): benign browsers (a page and five assets every 5-9 s over 300 s, one sid each) and
    attackers (pageless /search requests at `rps` from `start` to `stop`, no sid), labelled as train_l7v2 labels."""
    rng = random.Random(seed)
    rows = []
    for b in range(n_benign):
        t = rng.uniform(0.0, 20.0)
        while t < 300.0:
            rows.append((t, f"10.0.1.{b + 1}", f"/page/{rng.randrange(50)}", f"s{b}", "benign", f"b{b}"))
            rows += [(t + 0.05 * (a + 1), f"10.0.1.{b + 1}", f"/static/a{a}.css", f"s{b}", "benign", f"b{b}")
                     for a in range(5)]
            t += rng.uniform(5.0, 9.0)
    for a, (rps, start, stop) in enumerate(attackers):
        t = start + a
        while t < stop:
            rows.append((t, f"10.0.2.{a + 1}", "/search?q=w", None, "attack", f"a{a}"))
            t += 1.0 / rps
    rows.sort(key=lambda r: r[0])
    recs = []
    for i, (t, ip, uri, sid, role, ent) in enumerate(rows):
        o = U.obj(ip=ip, uri=uri, msec=t0 + t + 0.02, rt=0.02)
        if sid:
            o["sid"] = sid
        r = I.normalise(o)
        r.update({"_cls": D.ATTACK if role == "attack" else D.BENIGN, "_family": "C2" if role == "attack" else None,
                  "_held": False, "_entity": ent, "_kof": "C2" if role == "attack" else "browser", "_seq": i,
                  "_cap": cap, "_ent": f"{cap}|{ent}"})
        recs.append(r)
    return {"format": "test"}, recs, cap


def stream(times, ip="10.0.2.9", uri="/search?q=w", status=200, sid=None, ua="Mozilla/5.0"):
    out = []
    for t in times:
        o = U.obj(ip=ip, uri=uri, msec=t, rt=0.0, status=status, ua=ua)
        if sid:
            o["sid"] = sid
        out.append(I.normalise(o))
    return out


def per_request(recs, costs=COSTS):
    """Each request's statistics: feed and query at the request itself (key, its time, its start)."""
    rs = R.RuleStats(costs)
    for r in recs:
        rs.observe(r)
    return rs, np.array([rs.query([(I.key_v2(r), r["msec"], r["msec"])])[0] for r in recs])


class SpecTest(unittest.TestCase):
    def test_the_spec_is_the_frozen_version(self):
        with open(R.SPEC_PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), SPEC_SHA256)
        self.assertEqual(R.load_spec()["format"], "l7v2-rules-prereg/1")

    def test_grids_restate_the_design_and_l7_baselines(self):
        a = R.load_spec()["arms"]
        self.assertEqual(list(a), list(R.ARMS))
        self.assertEqual(a["sustained_rate"]["windows_s"], list(l7_baselines.SUSTAIN_WINDOWS))
        self.assertEqual(a["sustained_rate"]["thresholds_rps"], list(l7_baselines.SUSTAIN_THRESHOLDS))
        self.assertEqual(a["token_bucket"]["rates"], list(l7_baselines.BUCKET_RATES))
        self.assertEqual(a["token_bucket"]["bursts"], list(l7_baselines.BUCKET_BURSTS))
        self.assertEqual(a["cost_budget"]["windows_s"], [10, 60, 300])
        self.assertEqual(a["multiscale_rate"]["windows_s"], [1, 10, 60, 300])
        spec = R.load_spec()
        self.assertEqual(spec["tau_grid"], [0.8, 1.0, 1.2, 1.5, 2.0])
        self.assertEqual(spec["key_grid"], ["ip_ua", "ip_ua_sid"])
        self.assertEqual((spec["theta"], spec["statistic"]["lookback_s"]), (0.5, 300.0))
        self.assertEqual(spec["statistic"]["lookback_s"], MPRE.load()["ingest"]["idle_timeout_s"])
        self.assertEqual(VPRE.load()["best_rule"]["candidates"],
                         ["sustained_rate", "token_bucket", "cost_budget", "multiscale_rate"])

    def test_the_fixed_replays_restate_the_daemon_and_nginx(self):
        with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
            src = fh.read()
        spec = R.load_spec()
        d, a = spec["daemon"], spec["arms"]
        for needle in (f"HEURISTIC_WINDOW = {d['window_s']}", f"HEURISTIC_MAX_RPS = {a['default_rules']['max_rps']}",
                       f"HEURISTIC_ERROR_RATIO = {d['error_ratio']}",
                       f"HEURISTIC_MIN_REQUESTS = {d['min_requests']}", f"BAN_TTL_SECONDS = {int(d['ban_ttl_s'])}",
                       f'"HEURISTIC_MAX_RPS": {a["tolerant_rules"]["max_rps"]}',
                       f"rps > {d['error_min_rps']})"):
            self.assertIn(needle, src)
        self.assertEqual((a["nginx_limits"]["rate_rps"], a["nginx_limits"]["burst"]),
                         (l7_traffic.THRESHOLDS["nginx_limit_req_rps"], l7_traffic.THRESHOLDS["nginx_limit_req_burst"]))
        with open(os.path.join(REPO, "nginx.conf"), encoding="utf-8") as fh:
            conf = fh.read()
        self.assertTrue(re.search(r"limit_req_zone \$binary_remote_addr .*rate=30r/s", conf))
        self.assertIn("burst=100 nodelay", conf)

    def test_columns(self):
        cols = R.columns()
        self.assertEqual(len(cols), 2 * 14 + 4 + 1)
        self.assertEqual(cols[:3], ["ip_ua:rate_1", "ip_ua:rate_10", "ip_ua:rate_30"])
        self.assertEqual(cols[-5:], ["ip:daemon_default", "ip:daemon_tolerant", "ip:pop_new_keys_60",
                                     "ip:pop_cookieless_60", "own:nginx_reject"])


class StatisticsTest(unittest.TestCase):
    def test_rates_and_costs_match_brute_force(self):
        rng = random.Random(3)
        ts = sorted(1000.0 + rng.uniform(0, 400) for _ in range(300))
        uris = [rng.choice(["/page/1", "/static/a.css", "/search?q=x", "/export", "/nowhere"]) for _ in ts]
        recs = [stream([t], uri=u)[0] for t, u in zip(ts, uris, strict=True)]
        _rs, st = per_request(recs)
        cols = R.columns()
        cost = [COSTS.get(r["rc"], 0.0) for r in recs]
        for j, t in enumerate(ts):
            for w in (1, 10, 30, 60, 300):
                n = sum(1 for x in ts[:j + 1] if x > t - w)
                self.assertAlmostEqual(st[j, cols.index(f"ip_ua:rate_{w}")], n / w)
            for w in (10, 60, 300):
                c = sum(cost[i] for i in range(j + 1) if ts[i] > t - w)
                self.assertAlmostEqual(st[j, cols.index(f"ip_ua_sid:cost_{w}")], c, places=6)

    def test_the_bucket_fires_as_l7_baselines(self):
        rng = random.Random(5)
        for trial in range(20):
            rate = rng.choice([5, 10, 30])
            ts = sorted(rng.uniform(0, 20) for _ in range(rng.randrange(20, 400)))
            _rs, st = per_request(stream(ts))
            col = R.columns().index(f"ip_ua:bucket_{rate}")
            for burst in (10, 25, 50, 100):
                with self.subTest(trial=trial, rate=rate, burst=burst):
                    self.assertEqual(bool((st[:, col] > burst).any()), l7_baselines._bucket_rejects(ts, rate, burst))

    def test_the_daemon_replica(self):
        cols = R.columns()
        dd, dt = cols.index("ip:daemon_default"), cols.index("ip:daemon_tolerant")
        _rs, st = per_request(stream([1000.0 + i / 60.0 for i in range(120)]))     # 60 req/s for 2 s
        self.assertEqual(st[:, dd].max(), 1.0)
        self.assertEqual(st[:, dt].max(), 0.0)
        # banned for BAN_TTL: the statistic stays 1, banned requests are not seen; after the TTL a fresh tracker
        times = [1000.0 + i / 60.0 for i in range(120)] + [1100.0, 1200.0, 1350.0]
        _rs, st = per_request(stream(times))
        first = int(np.argmax(st[:, dd]))
        self.assertTrue((st[first:122, dd] == 1.0).all())
        self.assertEqual(st[-1, dd], 0.0)
        # the error branch: 12 req/s of 404s fires, of 503s does not (503 is the backend's overload)
        for status, want in ((404, 1.0), (503, 0.0)):
            _rs, st = per_request(stream([1000.0 + i / 12.0 for i in range(60)], status=status))
            self.assertEqual(st[:, dd].max(), want, status)

    def test_nginx_limit_req(self):
        col = R.columns().index("own:nginx_reject")
        _rs, st = per_request(stream([1000.0 + i * 1e-5 for i in range(103)]))
        self.assertEqual(list(st[:, col]), [0.0] * 101 + [1.0, 1.0])
        _rs, st = per_request(stream([1000.0 + i / 30.0 for i in range(300)]))     # at the rate: never
        self.assertEqual(st[:, col].max(), 0.0)

    def test_population(self):
        cols = R.columns()
        recs = stream([1000.0], sid="a") + stream([1001.0], sid="b") + stream([1002.0]) + stream([1070.0], sid="a")
        _rs, st = per_request(recs)
        self.assertEqual(list(st[:, cols.index("ip:pop_new_keys_60")]), [1.0, 2.0, 3.0, 0.0])
        self.assertEqual(list(st[:, cols.index("ip:pop_cookieless_60")]), [0.0, 0.0, 1 / 3, 0.0])

    def test_a_window_sees_the_burst_since_the_previous_window(self):
        # pages every 10 s; a burst of 30 assets inside one second at 45 s: the window completing at 50 s reports it,
        # though the 1-s rate at 50 s itself is 1
        recs = []
        for i in range(7):
            recs += stream([1000.0 + 10 * i], uri=f"/page/{i}", sid="k")
        recs += stream([1045.0 + j / 31.0 for j in range(30)], uri="/static/x.css", sid="k")
        recs.sort(key=lambda r: r["msec"])
        for i, r in enumerate(recs):
            r.update({"_cls": D.BENIGN, "_family": None, "_held": False, "_entity": "b", "_kof": "browser",
                      "_seq": i, "_cap": "c", "_ent": "c|b"})
        loaded = [({"format": "test"}, recs, "c")]
        split = V.Split(loaded, view=True, request=False)
        stats = R.split_stats(loaded, split, COSTS)
        col = R.columns().index("ip_ua_sid:rate_1")
        by_t = {round(w["t"]): stats[i, col] for i, w in enumerate(split.view)}
        self.assertEqual(by_t[1040], 1.0)
        self.assertGreaterEqual(by_t[1050], 30.0)
        self.assertEqual(by_t[1060], 1.0)

    def test_streaming_equals_batch_and_late_records_are_counted(self):
        recs = stream([1000.0 + i * 0.3 for i in range(50)])
        rs = R.RuleStats(COSTS)
        for r in recs:
            rs.observe(r)
        whole = rs.query([(I.key_v2(r), r["msec"], 1000.0) for r in recs[9::10]])
        rs2, parts = R.RuleStats(COSTS), []
        for i, r in enumerate(recs):
            rs2.observe(r)
            if i % 10 == 9:
                parts.append(rs2.query([(I.key_v2(r), r["msec"], 1000.0)])[0])
        np.testing.assert_allclose(whole, np.array(parts))
        rs2.observe(stream([1001.0])[0])
        self.assertEqual(rs2.late, 1)


class PolicyTest(unittest.TestCase):
    def test_runs_equal_train_l7v2s_policy_and_assessment(self):
        loaded = [make_capture(attackers=((4.0, 60.0, 240.0), (10.0, 100.0, 200.0), (0.5, 0.0, 290.0)))]
        split = V.Split(loaded, view=True, request=False)
        runs = R.Runs(split.view, split)
        self.assertLess(len(runs.order), len(split.view), "the 10 req/s key completes > 4 windows per poll")
        rng = np.random.default_rng(1)
        for trial in range(30):
            p = (rng.random(len(split.view)) < rng.uniform(0.05, 0.9)).astype(float)
            for k in MPRE.selection()["k_grid"]:
                want = {x: v for x, v in V.assess(V.decisions(V.key_runs(split.view, p), 0.5, k), split).items()
                        if not x.startswith("_")}
                with self.subTest(trial=trial, k=k):
                    self.assertEqual(runs.evaluate(p, k), want)


class TuningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loaded = [make_capture(n_benign=120, attackers=tuple((6.0, 60.0 + a, 240.0) for a in range(5)))]
        cls.split = V.Split(cls.loaded, view=True, request=False)
        cls.stats = R.split_stats(cls.loaded, cls.split, COSTS)
        cls.runs = R.Runs(cls.split.view, cls.split)
        cls.maxima = R.benign_maxima(cls.stats, cls.split.view)

    def test_grid_sizes_and_tau_thresholds(self):
        sizes = {a: len(R.grid(a, self.maxima)) for a in R.ARMS}
        self.assertEqual(sizes, {"sustained_rate": 54, "token_bucket": 48, "cost_budget": 30, "multiscale_rate": 1250,
                                 "population": 25, "default_rules": 1, "tolerant_rules": 1, "nginx_limits": 1})
        params, cols, thr = R.grid("cost_budget", self.maxima)[1]
        self.assertEqual((params["tau"], cols), (1.0, ["ip_ua:cost_10"]))
        self.assertEqual(thr, [self.maxima["ip_ua:cost_10"]])

    def test_each_tuned_arm_meets_the_budget_and_catches_the_flood(self):
        res = {a: R.tune(a, self.stats, self.runs, self.maxima) for a in R.TUNED}
        for a in ("sustained_rate", "token_bucket", "cost_budget", "multiscale_rate"):
            op = res[a]["operating_point"]
            with self.subTest(arm=a):
                self.assertIsNotNone(op)
                self.assertLessEqual(op["benign_units_flagged"], op["allowed"])
                self.assertEqual(op["allowed"], 1)
                self.assertEqual(op["caught"], 5)
                self.assertEqual(op["threshold"], 0.5)
        self.assertIn(R.best_rule(res), VPRE.load()["best_rule"]["candidates"])
        # every candidate catches all five at no benign unit: the earliest median decision, then candidate order
        ops = {a: res[a]["operating_point"] for a in VPRE.load()["best_rule"]["candidates"]}
        best = min(ops, key=lambda a: (ops[a]["benign_units_flagged"], ops[a]["median_ttd_s"],
                                       VPRE.load()["best_rule"]["candidates"].index(a)))
        self.assertEqual(R.best_rule(res), best)

    def test_the_operating_point_is_the_brute_force_one(self):
        r = R.tune("sustained_rate", self.stats, self.runs, self.maxima)
        sel = MPRE.selection()
        points = R.grid("sustained_rate", self.maxima)
        best = None
        for ki, k in enumerate(sel["k_grid"]):
            for pi, (_params, cols, thr) in enumerate(points):
                p = R.fires(self.stats, cols, thr)
                a = V.assess(V.decisions(V.key_runs(self.split.view, p), 0.5, k), self.split)
                if a["benign_units_flagged"] > 1:
                    continue
                med = a["median_ttd_s"] if a["median_ttd_s"] is not None else float("inf")
                rank = (-a["caught"], a["benign_units_flagged"], med, ki * len(points) + pi)
                best = rank if best is None or rank < best else best
        self.assertEqual(r["operating_point"]["grid_index"], best[3])

    def test_no_point_within_the_budget_gives_no_operating_point(self):
        loaded = [make_capture(n_benign=6)]
        split = V.Split(loaded, view=True, request=False)
        stats = R.split_stats(loaded, split, COSTS)
        maxima = {c: 0.0 for c in R.columns()}       # every threshold 0: every key fires, allowed = 0
        r = R.tune("cost_budget", stats, R.Runs(split.view, split), maxima)
        self.assertIsNone(r["operating_point"])
        self.assertEqual(r["within_budget"], 0)

    def test_best_rule_ties_and_none(self):
        op = {"caught": 3, "benign_units_flagged": 0, "median_ttd_s": 2.0}
        res = {"token_bucket": {"operating_point": op}, "sustained_rate": {"operating_point": dict(op)},
               "population": {"operating_point": {**op, "caught": 9}}}
        self.assertEqual(R.best_rule(res), "sustained_rate")          # candidate order; population is no candidate
        self.assertIsNone(R.best_rule({"cost_budget": {"operating_point": None}}))

    def test_fixed_replays_are_reported_not_tuned(self):
        f = R.fixed("default_rules", self.stats, self.runs)
        self.assertEqual((f["consecutive"], f["columns"]), (1, ["ip:daemon_default"]))
        self.assertIn("within_budget", f)


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.loaded = [make_capture(n_benign=30, attackers=((3.0, 60.0, 240.0),))]
        self.split = V.Split(self.loaded, view=True, request=False)
        self.stats = R.split_stats(self.loaded, self.split, COSTS)
        self.maxima = R.benign_maxima(self.stats, self.split.view)

    def test_round_trip_score_and_tamper(self):
        op = R.tune("cost_budget", self.stats, R.Runs(self.split.view, self.split), self.maxima)["operating_point"]
        cal = {"sha256": "ab" * 32, "status": "placeholder"}
        cfg = R.make_package("cost_budget", op, COSTS, cal, self.maxima)
        self.assertEqual(cfg["calibration"], cal)
        self.assertEqual(cfg["costs_ms"], COSTS)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cost_budget.json")
            R.save_package(path, cfg)
            sc = R.RuleScorer.load(path)
            p = sc.score(sc.select(self.stats))
            self.assertTrue(set(np.unique(p)) <= {0.0, 1.0})
            np.testing.assert_array_equal(p, R.fires(self.stats, op["columns"], op["thresholds"]))
            self.assertEqual((sc.level, sc.threshold, sc.consecutive), ("view", 0.5, op["consecutive"]))
            with open(path, encoding="utf-8") as fh:
                bad = json.load(fh)
            bad["thresholds"] = [x * 2 for x in bad["thresholds"]]
            with self.assertRaises(R.RuleError):
                R.RuleScorer(bad)

    def test_select_reads_validation_only_and_freezes(self):
        with self.assertRaises(R.RuleError):
            R.refuse_non_validation([({"format": D.DATASET_FORMAT_V3, "seed_role": "eval"}, [], "e")])
        R.refuse_non_validation([({"format": D.DATASET_FORMAT_V3, "seed_role": "val"}, [], "v")])
        with tempfile.TemporaryDirectory() as d:
            sel, sha = R.select(self.loaded, d, {"route_costs_ms": COSTS, "sha256": "cd" * 32, "status": "placeholder"},
                                valid_for_claims=False, source="test")
            with open(os.path.join(d, "rules_selection.json"), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), sha)
            self.assertIn(sel["r_star"], VPRE.load()["best_rule"]["candidates"])
            self.assertEqual(set(sel["arms"]), set(R.ARMS))
            for a in R.TUNED:
                if sel["arms"][a]["operating_point"]:
                    R.RuleScorer.load(os.path.join(d, sel["arms"][a]["artifact"]))
            with self.assertRaises(R.RuleError):
                R.select(self.loaded, d, {"route_costs_ms": COSTS}, valid_for_claims=False, source="again")


if __name__ == "__main__":
    unittest.main()
