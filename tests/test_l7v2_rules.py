"""The L7 v2 rule arms at their own level (ml/l7v2_rules.py, ml/l7v2_rules_prereg_v3.json; docs/L7V2_DESIGN.md 9.5,
10; review finding T042-E08, the user's D-043): the causal statistics per (IP, UA) key and address over wall-clock
windows, the rows per key and poll, the vectorised policy against train_l7v2's, the threshold levels (multiples and
benign quantiles), the users behind a flagged key, tuning at the common budget on validation only, the (IP, UA) age-only
arm beside the rules, R*, and the packages behind score(batch) -> p. Offline and pure (synthetic records)."""
import hashlib
import json
import os
import random
import sys
import tempfile
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.join(REPO, "tests"))
import l7_baselines
import l7_pools as LP
import l7_testutil as U
import l7v2_model_prereg as MPRE
import l7v2_rules as R
import l7v2_verdict_prereg as VPRE
import train_l7v2 as V

import l7_dataset as D
import l7_ingest as I

COSTS = {"C0": 0.05, "C1": 3.0, "C2": 2.0, "C3": 30.0, "C5": 150.0}


def make_capture(cap="val2001", n_benign=6, attackers=((4.0, 60.0, 240.0),), seed=0, t0=1000.0, rotate_sid=False,
                 assets=5):
    """(manifest, records, capture): benign browsers (a page and `assets` assets every 5-9 s over 300 s, one sid each) and
    attackers (pageless /search requests at `rps` from `start` to `stop`; no sid, or a new sid per request), labelled as
    train_l7v2 labels."""
    rng = random.Random(seed)
    rows = []
    for b in range(n_benign):
        t = rng.uniform(0.0, 20.0)
        while t < 300.0:
            rows.append((t, f"10.0.1.{b + 1}", f"/page/{rng.randrange(50)}", f"s{b}", "benign", f"b{b}"))
            rows += [(t + 0.05 * (a + 1), f"10.0.1.{b + 1}", f"/static/a{a}.css", f"s{b}", "benign", f"b{b}")
                     for a in range(assets)]
            t += rng.uniform(5.0, 9.0)
    for a, (rps, start, stop) in enumerate(attackers):
        t, n = start + a, 0
        while t < stop:
            rows.append((t, f"10.0.2.{a + 1}", "/search?q=w", f"r{a}-{n}" if rotate_sid else None, "attack", f"a{a}"))
            t, n = t + 1.0 / rps, n + 1
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
    """Each request's statistics: one poll per request."""
    rs, out = R.RuleStats(costs), []
    for r in recs:
        rs.observe(r)
        (_key, _t, row), = rs.poll()
        out.append(row)
    return rs, np.array(out)


class SpecTest(unittest.TestCase):
    def test_the_spec_is_the_d043_version(self):
        spec = R.load_spec()
        self.assertEqual(spec["format"], "l7v2-rules-prereg/3")
        self.assertEqual(R.SPEC_PATH, os.path.join(REPO, "ml", "l7v2_rules_prereg_v3.json"))
        for old in ("l7v2_rules_prereg.json", "l7v2_rules_prereg_v2.json"):
            self.assertFalse(os.path.exists(os.path.join(REPO, "ml", old)), f"{old} is replaced")

    def test_columns(self):
        cols = R.columns()
        self.assertEqual(len(cols), 20 + 5 + 1)
        self.assertEqual(cols[:3], ["key:rate_1", "key:rate_10", "key:rate_30"])
        self.assertEqual(cols[8:11], ["key:bucket_0.1", "key:bucket_0.25", "key:bucket_0.5"])
        self.assertEqual(cols[19:], ["key:age", "ip:daemon_default", "ip:daemon_tolerant", "ip:pop_new_keys_60",
                                     "ip:pop_cookieless_60", "ip:age", "own:nginx_reject"])


class StatisticsTest(unittest.TestCase):
    def test_rates_costs_and_ages_match_brute_force(self):
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
                self.assertAlmostEqual(st[j, cols.index(f"key:rate_{w}")], n / w)
            for w in (10, 60, 300):
                c = sum(cost[i] for i in range(j + 1) if ts[i] > t - w)
                self.assertAlmostEqual(st[j, cols.index(f"key:cost_{w}")], c, places=6)
            self.assertAlmostEqual(st[j, cols.index("key:age")], t - ts[0])
            self.assertAlmostEqual(st[j, cols.index("ip:age")], t - ts[0])

    def test_the_bucket_fires_as_l7_baselines(self):
        rng = random.Random(5)
        for trial in range(20):
            rate = rng.choice([0.25, 5, 10, 30])
            ts = sorted(rng.uniform(0, 20) for _ in range(rng.randrange(20, 400)))
            _rs, st = per_request(stream(ts))
            col = R.columns().index(f"key:bucket_{rate}")
            for burst in (10, 25, 50, 100):
                with self.subTest(trial=trial, rate=rate, burst=burst):
                    self.assertEqual(bool((st[:, col] > burst).any()), l7_baselines._bucket_rejects(ts, rate, burst))

    def test_the_daemon_replica(self):
        cols = R.columns()
        dd, dt = cols.index("ip:daemon_default"), cols.index("ip:daemon_tolerant")
        _rs, st = per_request(stream([1000.0 + i / 60.0 for i in range(120)]))     # 60 req/s for 2 s
        self.assertEqual((st[:, dd].max(), st[:, dt].max()), (1.0, 0.0))
        times = [1000.0 + i / 60.0 for i in range(120)] + [1100.0, 1200.0, 1350.0]
        _rs, st = per_request(stream(times))
        first = int(np.argmax(st[:, dd]))
        self.assertTrue((st[first:122, dd] == 1.0).all(), "banned for BAN_TTL: requests unseen")
        self.assertEqual(st[-1, dd], 0.0)
        for status, want in ((404, 1.0), (503, 0.0)):
            _rs, st = per_request(stream([1000.0 + i / 12.0 for i in range(60)], status=status))
            self.assertEqual(st[:, dd].max(), want, status)

    def test_nginx_limit_req(self):
        col = R.columns().index("own:nginx_reject")
        _rs, st = per_request(stream([1000.0 + i * 1e-5 for i in range(103)]))
        self.assertEqual(list(st[:, col]), [0.0] * 101 + [1.0, 1.0])
        _rs, st = per_request(stream([1000.0 + i / 30.0 for i in range(300)]))
        self.assertEqual(st[:, col].max(), 0.0)

    def test_population(self):
        cols = R.columns()
        recs = stream([1000.0], sid="a") + stream([1001.0], sid="b") + stream([1002.0]) + stream([1070.0], sid="a")
        _rs, st = per_request(recs)
        self.assertEqual(list(st[:, cols.index("ip:pop_new_keys_60")]), [1.0, 2.0, 3.0, 0.0])
        self.assertEqual(list(st[:, cols.index("ip:pop_cookieless_60")]), [0.0, 0.0, 1 / 3, 0.0])

    def test_a_row_is_the_max_over_the_keys_requests_in_the_poll(self):
        rs = R.RuleStats(COSTS)
        for r in stream([1000.0 + j / 31.0 for j in range(30)]) + stream([1000.99], ua="other"):
            rs.observe(r)
        rows = rs.poll()
        self.assertEqual(len(rows), 2, "one row per (IP, UA) key")
        (_k, t, row), = [x for x in rows if x[0][1] == I.stable_hash32("Mozilla/5.0")]
        self.assertEqual(row[R.columns().index("key:rate_1")], 30.0)
        self.assertAlmostEqual(t, 1000.0 + 29 / 31.0)
        self.assertEqual(rs.poll(), [])

    def test_wall_clock_windows_reach_past_a_view_window_and_sid_rotation(self):
        # T042-E08: 120 requests in 60 s, each with a new session id, are one (IP, UA) key whose 60-s rate is 2 req/s;
        # 32 tokens of one sid would span 16 s, and each sid here has one request
        recs = []
        for i in range(120):
            recs += stream([1000.0 + i * 0.5], sid=f"s{i}")
        _rs, st = per_request(recs)
        self.assertEqual(st[-1, R.columns().index("key:rate_60")], 2.0)
        self.assertEqual(len({I.key_v2(r) for r in recs}), 120)
        self.assertEqual(len({R.rule_key(r) for r in recs}), 1)

    def test_rule_rows_poll_whole_seconds(self):
        loaded = [make_capture(attackers=((4.0, 60.0, 70.0),))]
        rows, stats = R.rule_rows(loaded, COSTS)
        self.assertEqual(stats.shape, (len(rows), len(R.columns())))
        att = [r for r in rows if r["y"]]
        self.assertEqual(len({r["poll"] for r in att}), len(att), "one row per key and poll")
        self.assertTrue(all(r["poll"] - 1.0 <= r["t"] < r["poll"] for r in rows))
        self.assertEqual({r["ip"] for r in att}, {"val2001|a0"})
        self.assertEqual(sum(1 for r in att), 10)            # 40 requests in 10 s of polls

    def test_streaming_equals_batch_and_late_records_are_counted(self):
        recs = stream([1000.0 + i * 0.3 for i in range(50)])
        loaded = [({"format": "test"}, [{**r, "_seq": i, "_ent": "c|a", "_cls": D.ATTACK} for i, r in enumerate(recs)],
                   "c")]
        _rows, whole = R.rule_rows(loaded, COSTS)
        rs, parts, boundary = R.RuleStats(COSTS), [], None
        for r in recs:
            b = int(r["msec"]) + 1
            if boundary is not None and b != boundary:
                parts += [row for _k, _t, row in rs.poll()]
            boundary = b
            rs.observe(r)
        parts += [row for _k, _t, row in rs.poll()]
        np.testing.assert_allclose(whole, np.array(parts))
        rs.observe(stream([1001.0])[0])
        self.assertEqual(rs.late, 1)


class PolicyTest(unittest.TestCase):
    def test_runs_equal_train_l7v2s_policy_and_assessment(self):
        for level in ("view", "rule"):
            loaded = [make_capture(attackers=((4.0, 60.0, 240.0), (10.0, 100.0, 200.0), (0.5, 0.0, 290.0)))]
            split = V.Split(loaded, view=level == "view", request=False)
            points = split.view if level == "view" else R.rule_rows(loaded, COSTS)[0]
            runs = R.Runs(points, split)
            if level == "view":
                self.assertLess(len(runs.order), len(points), "the 10 req/s key completes > 4 windows per poll")
            rng = np.random.default_rng(1)
            for trial in range(15):
                p = (rng.random(len(points)) < rng.uniform(0.05, 0.9)).astype(float)
                for k in MPRE.selection()["k_grid"]:
                    want = {x: v for x, v in V.assess(V.decisions(V.key_runs(points, p), 0.5, k), split).items()
                            if not x.startswith("_")}
                    with self.subTest(level=level, trial=trial, k=k):
                        self.assertEqual(runs.evaluate(p, k), want)


class TuningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loaded = [make_capture(n_benign=120, attackers=tuple((6.0, 60.0 + a, 240.0) for a in range(5)))]
        cls.rows, cls.stats, cls.runs = R.validation_rows(cls.loaded, COSTS)
        cls.levels = R.benign_levels(cls.stats, cls.rows)

    def test_grid_sizes(self):
        sizes = {a: len(R.grid(a, self.levels)) for a in R.ARMS if a not in R.JOINT}
        self.assertEqual(sizes, {"sustained_rate": 48, "token_bucket": 44, "cost_budget": 36, "default_rules": 1,
                                 "tolerant_rules": 1, "nginx_limits": 1})
        k = len(MPRE.selection()["k_grid"])
        self.assertEqual(R.tune("population", self.stats, self.runs, self.levels)["grid_size"], 12 ** 2 * k)
        self.assertEqual(R.tune("multiscale_rate", self.stats, self.runs, self.levels)["grid_size"], 12 ** 4 * k)

    def test_threshold_levels_are_multiples_and_benign_quantiles(self):
        j = R.columns().index("key:cost_60")
        ben = np.flatnonzero([not r["y"] for r in self.rows])
        per_key = {}
        for i in ben:
            k = self.rows[i]["key"]
            per_key[k] = max(per_key.get(k, 0.0), self.stats[i, j])
        vals = sorted(per_key.values())
        self.assertEqual(len(vals), 120)
        lev = dict(self.levels["key:cost_60"])
        self.assertEqual(list(lev), ["tau_0.8", "tau_1.0", "tau_1.2", "tau_1.5", "tau_2.0", "q_0.5", "q_0.75", "q_0.9",
                                     "q_0.95", "q_0.98", "q_0.99", "q_0.995"])
        self.assertEqual(lev["tau_1.0"], vals[-1])
        self.assertAlmostEqual(lev["tau_1.5"], 1.5 * vals[-1])
        self.assertAlmostEqual(lev["q_0.5"], float(np.median(vals)))
        self.assertAlmostEqual(lev["q_0.995"], float(np.quantile(vals, 0.995)))
        params, cols, thr = R.grid("cost_budget", self.levels)[1]
        self.assertEqual((params["level"], cols, thr), ("tau_1.0", ["key:cost_10"], [dict(self.levels["key:cost_10"])["tau_1.0"]]))

    def test_the_joint_search_is_the_whole_product(self):
        # dropping the levels that alone are over the budget changes nothing
        got = R.tune("population", self.stats, self.runs, self.levels)
        sel = MPRE.selection()
        cols, _names = R.joint_columns("population")
        lv = [self.levels[c] for c in cols]
        allowed, best, within = 1, None, 0
        for ki, k in enumerate(sel["k_grid"]):
            for i, (_a, t0) in enumerate(lv[0]):
                for j, (_b, t1) in enumerate(lv[1]):
                    a = self.runs.evaluate(R.fires(self.stats, cols, [t0, t1]), k)
                    if a["benign_units_flagged"] > allowed:
                        continue
                    within += 1
                    med = a["median_ttd_s"] if a["median_ttd_s"] is not None else float("inf")
                    rank = (-a["caught"], a["benign_units_flagged"], med, ki * 144 + i * 12 + j)
                    best = rank if best is None or rank < best else best
        self.assertEqual(got["within_budget"], within)
        self.assertEqual(got["operating_point"]["grid_index"], best[3])
        op = got["operating_point"]
        p = R.fires(self.stats, op["columns"], op["thresholds"])
        self.assertEqual(self.runs.evaluate(p, op["consecutive"])["caught"], op["caught"])

    def test_each_candidate_meets_the_budget_and_catches_the_flood(self):
        res = {a: R.tune(a, self.stats, self.runs, self.levels) for a in R.TUNED}
        cands = VPRE.load()["best_rule"]["candidates"]
        for a in cands:
            op = res[a]["operating_point"]
            with self.subTest(arm=a):
                self.assertIsNotNone(op)
                self.assertLessEqual(op["benign_units_flagged"], op["allowed"])
                self.assertEqual((op["allowed"], op["caught"], op["threshold"]), (1, 5, 0.5))
        ops = {a: res[a]["operating_point"] for a in cands}
        best = min(ops, key=lambda a: (-ops[a]["caught"], ops[a]["benign_units_flagged"], ops[a]["median_ttd_s"],
                                       cands.index(a)))
        self.assertEqual(R.best_rule(res), best)

    def test_the_operating_point_is_the_brute_force_one(self):
        r = R.tune("sustained_rate", self.stats, self.runs, self.levels)
        sel, points, best = MPRE.selection(), R.grid("sustained_rate", self.levels), None
        for ki, k in enumerate(sel["k_grid"]):
            for pi, (_params, cols, thr) in enumerate(points):
                p = R.fires(self.stats, cols, thr)
                a = V.assess(V.decisions(V.key_runs(self.rows, p), 0.5, k), self.runs.split)
                if a["benign_units_flagged"] > 1:
                    continue
                med = a["median_ttd_s"] if a["median_ttd_s"] is not None else float("inf")
                rank = (-a["caught"], a["benign_units_flagged"], med, ki * len(points) + pi)
                best = rank if best is None or rank < best else best
        self.assertEqual(r["operating_point"]["grid_index"], best[3])

    def test_the_age_only_arm_beside_the_rules(self):
        age = R.tune_age(self.stats, self.rows, self.runs)
        self.assertEqual(age["grid_size"], len(MPRE.selection()["theta_grid"]) * len(MPRE.selection()["k_grid"]))
        self.assertGreater(age["val_auc"], 0.65, "the attackers arrive 60 s after the benign users here")
        self.assertEqual(age["reading"], "age-confounded")
        self.assertIsNotNone(age["address_age_val_auc"])
        self.assertNotIn("age_only_key", VPRE.load()["best_rule"]["candidates"])

    def test_no_point_within_the_budget_gives_no_operating_point(self):
        _rows, stats, runs = R.validation_rows([make_capture(n_benign=6)], COSTS)
        r = R.tune("cost_budget", stats, runs, {c: [("tau_1.0", 0.0)] for c in R.columns()})
        self.assertIsNone(r["operating_point"])
        self.assertEqual(r["within_budget"], 0)

    def test_best_rule_ties_and_none(self):
        op = {"caught": 3, "benign_units_flagged": 0, "median_ttd_s": 2.0}
        res = {"token_bucket": {"operating_point": op}, "sustained_rate": {"operating_point": dict(op)},
               "population": {"operating_point": {**op, "caught": 9}}}
        self.assertEqual(R.best_rule(res), "sustained_rate")
        self.assertIsNone(R.best_rule({"cost_budget": {"operating_point": None}}))

    def test_fixed_replays_are_reported_not_tuned(self):
        f = R.fixed("default_rules", self.stats, self.runs)
        self.assertEqual((f["consecutive"], f["columns"]), (1, ["ip:daemon_default"]))
        self.assertIn("within_budget", f)


class SidRotationTest(unittest.TestCase):
    def test_a_rotating_attacker_is_one_rule_key(self):
        loaded = [make_capture(n_benign=30, attackers=((3.0, 60.0, 240.0),), rotate_sid=True)]
        rows, stats, runs = R.validation_rows(loaded, COSTS)
        self.assertEqual(len({r["key"] for r in rows if r["y"]}), 1)
        op = R.tune("sustained_rate", stats, runs, R.benign_levels(stats, rows))["operating_point"]
        self.assertEqual(op["caught"], 1)


class D043GridTest(unittest.TestCase):
    def test_the_extended_grids_reach_a_source_below_1_req_s(self):
        # 0.5 req/s against benign pages without assets: below every threshold of ml/l7_baselines' grids
        loaded = [make_capture(n_benign=120, attackers=((0.5, 20.0, 280.0),), assets=0)]
        rows, stats, runs = R.validation_rows(loaded, COSTS)
        levels = R.benign_levels(stats, rows)
        for arm, reach in (("sustained_rate", lambda op: op["params"]["threshold_rps"] < 1),
                           ("token_bucket", lambda op: op["params"]["rate"] < 1)):
            op = R.tune(arm, stats, runs, levels)["operating_point"]
            with self.subTest(arm=arm):
                self.assertEqual(op["caught"], 1)
                self.assertTrue(reach(op), op["params"])

    def test_a_quantile_catches_what_the_maximum_cannot(self):
        # one benign key has a far larger cost than the others: every multiple of the maximum sits above the attacker,
        # a quantile does not, and the budget allows that one key
        m, recs, cap = make_capture(n_benign=120, attackers=((0.5, 20.0, 280.0),), assets=0)
        outlier = [r for r in recs if r["_entity"] == "b0"]
        for r in outlier:
            r["rc"] = "C5"
        rows, stats, runs = R.validation_rows([(m, recs, cap)], COSTS)
        levels = R.benign_levels(stats, rows)
        op = R.tune("cost_budget", stats, runs, levels)["operating_point"]
        self.assertTrue(op["params"]["level"].startswith("q_"), op["params"])
        self.assertEqual((op["caught"], op["benign_units_flagged"]), (1, 1))


class UsersBehindTest(unittest.TestCase):
    def pool(self, users=12):
        return {"entity_id": "2026-11-v1:1:9", "role": "benign", "kind_or_family": "cgnat_browsers", "address": "10.0.1.7",
                "params": {"users": users, "level": 30, "first_visit_s": [0.0, 60.0], "nav": "tpcw:browsing",
                           "sessions": True}, "client_seed": 5, "schedule": {"start_s": 0.0, "stop_s": 900.0}}

    def test_plan_users_counts_devices_not_sessions(self):
        e = self.pool()
        got = R.plan_users({"format": D.DATASET_FORMAT_V3, "entities": [e]})
        plan = LP._plan_of(e)
        self.assertGreater(len(plan["users"]), 12, "sessions are plan users of their own")
        self.assertEqual(sum(got.values()), 12)
        self.assertTrue(all(k[0] == "10.0.1.7" for k in got))
        self.assertGreater(max(got.values()), 1, "UAs collide in a pool of 12")
        self.assertEqual(R.plan_users({"format": "test"}), {})

    def test_key_costs_fall_back_on_session_ids(self):
        recs = [{**r, "_seq": i} for i, r in enumerate(stream([1000.0], sid="a") + stream([1001.0], sid="b"))]
        self.assertEqual(R.key_costs([({"format": "test"}, recs, "c")]),
                         {("c", ("10.0.2.9", I.stable_hash32("Mozilla/5.0"))): 2})

    def test_a_flagged_key_costs_the_users_behind_it_up_to_the_entitys_units(self):
        loaded = [make_capture(n_benign=4, attackers=())]
        rows, _stats = R.rule_rows(loaded, COSTS)
        split = V.Split(loaded, view=False, request=False)
        ent = "val2001|b0"
        key = next(r["key"] for r in rows if r["ip"] == ent)
        p = np.array([1.0 if r["ip"] == ent else 0.0 for r in rows])
        self.assertEqual(R.Runs(rows, split).evaluate(p, 1)["benign_units_flagged"], 1)
        split.units[ent] = 24
        self.assertEqual(R.Runs(rows, split).evaluate(p, 1)["benign_units_flagged"], 1, "D-031's rule without key costs")
        runs = R.Runs(rows, split, {("val2001", key): 7})
        self.assertEqual(runs.evaluate(p, 1)["benign_units_flagged"], 7)
        split.units[ent] = 5
        runs = R.Runs(rows, split, {("val2001", key): 7})
        self.assertEqual(runs.evaluate(p, 1)["benign_units_flagged"], 5)


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.loaded = [make_capture(n_benign=30, attackers=((3.0, 60.0, 240.0),))]
        self.rows, self.stats, self.runs = R.validation_rows(self.loaded, COSTS)
        self.levels = R.benign_levels(self.stats, self.rows)

    def test_round_trip_score_and_tamper(self):
        op = R.tune("cost_budget", self.stats, self.runs, self.levels)["operating_point"]
        cal = {"sha256": "ab" * 32, "status": "placeholder"}
        cfg = R.make_package("cost_budget", op, COSTS, cal)
        self.assertEqual((cfg["calibration"], cfg["costs_ms"], cfg["level"], cfg["key"]),
                         (cal, COSTS, "rule", ["ip", "ua_h"]))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cost_budget.json")
            R.save_package(path, cfg)
            sc = R.RuleScorer.load(path)
            p = sc.score(sc.select(self.stats))
            self.assertTrue(set(np.unique(p)) <= {0.0, 1.0})
            np.testing.assert_array_equal(p, R.fires(self.stats, op["columns"], op["thresholds"]))
            self.assertEqual((sc.level, sc.threshold, sc.consecutive), ("rule", 0.5, op["consecutive"]))
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
            self.assertEqual(set(sel["recall_beside_age_only"]), {*R.ARMS, "age_only_key"})
            self.assertIn("val_auc", sel["age_only_key"])
            self.assertEqual(len(sel["benign_levels"]["key:cost_10"]), 12)
            for a in R.TUNED:
                if sel["arms"][a]["operating_point"]:
                    R.RuleScorer.load(os.path.join(d, sel["arms"][a]["artifact"]))
            with self.assertRaises(R.RuleError):
                R.select(self.loaded, d, {"route_costs_ms": COSTS}, valid_for_claims=False, source="again")


if __name__ == "__main__":
    unittest.main()
