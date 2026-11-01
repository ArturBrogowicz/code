"""The replay scorer (ml/l7v2_replay.py; docs/L7V2_DESIGN.md 11): a recorded run through every arm at the engine's poll
cadence. The rule arms on their own (IP, UA) path decide exactly the keys the rule evaluator decides on the same records
(l7v2_rules.rule_rows, k consecutive rows), and the age-only arm and a view arm exactly those train_l7v2 decides (its
windows, engine_scored), one poll later at most; frozen selections load with their hashes checked. Offline and pure
(synthetic records)."""
import math
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
import l7_testutil as U
import l7v2_replay as RP
import l7v2_rules as R
import train_l7v2 as V

import l7_dataset as D
import l7_features as F
import l7_ingest as I

COSTS = {"C0": 0.05, "C1": 3.0, "C2": 2.0, "C3": 30.0, "C5": 150.0}
CAP = "run"


def synthetic_run(n_benign=12, attackers=((4.0, 60.0, 240.0), (10.0, 100.0, 160.0), (0.5, 0.0, 290.0)), seed=0,
                  t0=1000.0):
    """(stream items with poll ticks at whole seconds, a schema-1 manifest, the labelled records the evaluator reads)."""
    rng = random.Random(seed)
    rows = []
    for b in range(n_benign):
        t = rng.uniform(0.0, 20.0)
        while t < 300.0:
            rows.append((t, f"10.0.1.{b + 1}", f"/page/{rng.randrange(50)}", f"s{b}"))
            rows += [(t + 0.05 * (a + 1), f"10.0.1.{b + 1}", f"/static/a{a}.css", f"s{b}") for a in range(5)]
            t += rng.uniform(5.0, 9.0)
    for a, (rps, start, stop) in enumerate(attackers):
        t = start + a
        while t < stop:
            rows.append((t, f"10.0.2.{a + 1}", "/search?q=w", None))
            t += 1.0 / rps
    rows.sort(key=lambda r: r[0])
    objs = []
    for t, ip, uri, sid in rows:
        o = U.obj(ip=ip, uri=uri, msec=t0 + t + 0.02, rt=0.02)
        if sid:
            o["sid"] = sid
        objs.append(o)
    items, tick = [], math.ceil(objs[0]["msec"])
    for o in objs:
        while o["msec"] >= tick:
            items.append(("poll", float(tick), False, ()))
            tick += 1
        items.append(("record", o))
    items += [("poll", float(tick + i), False, ()) for i in range(2)]
    ips = sorted({o["ip"] for o in objs})
    ip_map = {ip: ({"class": D.ATTACK, "family": "C2", "held_out": False} if ip.startswith("10.0.2.")
                   else {"class": D.BENIGN, "family": None, "held_out": False, "kind": "browser"}) for ip in ips}
    manifest = {"ip_map": ip_map}
    recs = []
    for i, o in enumerate(objs):
        r = I.normalise(o)
        attack = o["ip"].startswith("10.0.2.")
        r.update({"_cls": D.ATTACK if attack else D.BENIGN, "_family": "C2" if attack else None, "_held": False,
                  "_entity": o["ip"], "_kof": "C2" if attack else "browser", "_seq": i, "_cap": CAP,
                  "_ent": f"{CAP}|{o['ip']}"})
        recs.append(r)
    return items, manifest, recs


class CostlyStub:
    """A view-level scorer: p = 0.9 when the window's tokens carry a costly request on average, else 0.1."""
    level = "view"

    def __init__(self, consecutive=2):
        self.cols, self.max_views, self.seq_len = list(F.TOKEN_COLUMNS), F.MAX_VIEWS, F.MAX_VIEWS
        self.threshold, self.consecutive, self.sha256 = 0.5, consecutive, "stub"
        self.j = self.cols.index("log_n_costly")

    def score(self, batch):
        b = np.asarray(batch, dtype=np.float64)
        if not len(b):
            return np.zeros(0)
        valid = b[:, :, 0] > 0
        mean = (b[:, :, self.j] * valid).sum(axis=1) / np.maximum(valid.sum(axis=1), 1)
        return np.where(mean > 0.3, 0.9, 0.1)


def rule_caught(rows, split, p, k):
    a = V.assess(V.decisions(V.key_runs(rows, p), 0.5, k), split)
    return {e.split("|", 1)[1] for e in a["_caught"]}, {e.split("|", 1)[1] for e in a["_flagged"]}


def evaluator_caught(split, p, k):
    a = V.assess(V.decisions(V.key_runs(split.view, p), 0.5, k), split)
    return {e.split("|", 1)[1] for e in a["_caught"]}, {e.split("|", 1)[1] for e in a["_flagged"]}


class ReplayParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items, cls.manifest, cls.recs = synthetic_run()
        cls.loaded = [({"format": "test"}, cls.recs, CAP)]
        cls.split = V.Split(cls.loaded, view=True, request=False)
        cls.rows, cls.rstats = R.rule_rows(cls.loaded, COSTS)
        cls.labels = RP.RunLabels(cls.manifest)
        cls.truth = RP.ground_truth(cls.items, cls.labels)

    def rule(self, columns, thresholds, k):
        op = {"params": {}, "columns": columns, "thresholds": thresholds, "threshold": 0.5, "consecutive": k}
        return R.RuleScorer(R.make_package("sustained_rate", op, COSTS, {"sha256": None, "status": "placeholder"}, {}))

    def test_rule_arms_decide_the_evaluators_keys(self):
        decided = 0
        for cols, thr, k in ((["key:rate_10"], [2.0], 2), (["key:bucket_5"], [10.0], 1),
                             (["key:cost_60"], [500.0], 3), (["key:rate_1", "key:rate_60"], [5.0, 0.4], 2),
                             (["ip:pop_new_keys_60"], [0.5], 1), (["ip:daemon_default"], [0.5], 1),
                             (["own:nginx_reject"], [0.5], 1)):
            sc = self.rule(cols, thr, k)
            want_caught, want_flagged = rule_caught(self.rows, self.split, sc.score(sc.select(self.rstats)), k)
            got = RP.score_arm(self.items, RP.RulePath(sc), self.truth)
            with self.subTest(cols=cols):
                self.assertEqual(set(got["caught_entities"]), want_caught)
                self.assertEqual(got["benign_entities_flagged"], len(want_flagged))
            decided += len(want_caught) + len(want_flagged)
        self.assertGreater(decided, 0)

    def test_a_view_arm_through_l7viewengine_decides_the_evaluators_keys(self):
        stub = CostlyStub()
        p = stub.score(np.stack([w["X"] for w in self.split.view]))
        want, _ = evaluator_caught(self.split, p, 2)
        got = RP.score_arm(self.items, stub, self.truth)
        self.assertEqual(set(got["caught_entities"]), want)
        self.assertEqual(got["caught"], 3)
        self.assertGreater(got["skipped"], 0, "the 10 req/s key completes more than 4 windows per poll")

    def test_the_age_only_arm(self):
        ages = sorted(float(w["age"]) for w in self.split.view if not w["y"])
        p = V.age_scores(ages, self.split.view)
        want_caught, want_flagged = evaluator_caught(self.split, (p > 0.9).astype(float), 1)
        got = RP.score_arm(self.items, RP.AgeArm(ages, 0.9, 1), self.truth)
        self.assertEqual(set(got["caught_entities"]), want_caught)
        self.assertEqual(got["benign_entities_flagged"], len(want_flagged))

    def test_times_to_decision_are_one_poll_later_at_most(self):
        sc = self.rule(["key:rate_10"], [2.0], 2)
        p = sc.score(sc.select(self.rstats))
        a = V.assess(V.decisions(V.key_runs(self.rows, p), 0.5, 2), self.split)
        got = RP.score_arm(self.items, RP.RulePath(sc), self.truth)
        _key_ent, ent, _attack, _units = self.truth
        self.assertEqual(got["median_ttd_s"] is None, a["median_ttd_s"] is None)
        self.assertGreaterEqual(got["median_ttd_s"], a["median_ttd_s"])
        self.assertLessEqual(got["median_ttd_s"], a["median_ttd_s"] + 1.0 + 1e-9)
        self.assertEqual(set(ent), {o[1]["ip"] for o in self.items if o[0] == "record"})

    def test_the_rule_path_without_ticks_and_under_a_flood(self):
        sc = self.rule(["key:rate_10"], [2.0], 2)
        with_ticks = RP.score_arm(self.items, RP.RulePath(sc), self.truth)
        bare = [it for it in self.items if it[0] == "record"]
        self.assertEqual(RP.score_arm(bare, RP.RulePath(sc), self.truth)["caught_entities"],
                         with_ticks["caught_entities"])
        flood = [("poll", it[1], True, ()) if it[0] == "poll" else it for it in self.items]
        got = RP.score_arm(flood, RP.RulePath(sc), self.truth)
        self.assertEqual((got["decisions"], got["suppressed_polls"]), (0, got["polls"]))
        self.assertEqual(with_ticks["level"], "rule")

    def test_the_result_lists_every_arm(self):
        res = RP.replay(self.items, {"stub": CostlyStub(), "none": None}, self.labels)
        self.assertEqual(res["format"], "l7v2-replay/1")
        self.assertEqual(res["arms"]["none"], {"note": "no operating point"})
        self.assertEqual(res["arms"]["stub"]["by_family"], {"C2": {"caught": 3, "entities": 3}})
        self.assertEqual(res["attack_entities"], 3)


class FrozenArmsTest(unittest.TestCase):
    def test_load_arms_from_frozen_selections_and_refuse_altered_ones(self):
        items, manifest, recs = synthetic_run(n_benign=12)
        loaded = [({"format": "test"}, recs, CAP)]
        split = V.Split(loaded, view=True, request=True)
        with tempfile.TemporaryDirectory() as d:
            sel, sha = V.select(split, split, os.path.join(d, "sel"), arms=("hgb", "lr"), threads=1,
                                valid_for_claims=False, source="test", split_sha256="0" * 64)
            rsel, rsha = R.select(loaded, os.path.join(d, "sel"), {"route_costs_ms": COSTS, "sha256": None,
                                                                   "status": "placeholder"},
                                  valid_for_claims=False, source="test")
            arms = RP.load_arms(os.path.join(d, "sel", "selection.json"), sha,
                                os.path.join(d, "sel", "rules_selection.json"), rsha)
            for name in ("hgb", "lr", "age_only", *R.ARMS, "R*"):
                self.assertIn(name, arms)
            self.assertIsInstance(arms["default_rules"], RP.RulePath)
            self.assertEqual(arms["R*"] is None, rsel["r_star"] is None)
            res = RP.replay(items, arms, RP.RunLabels(manifest))
            self.assertEqual(set(res["arms"]), set(arms))
            if sel["arms"]["hgb"]["operating_point"]:
                self.assertEqual(res["arms"]["hgb"]["consecutive"], sel["arms"]["hgb"]["operating_point"]["consecutive"])
            with self.assertRaises(RP.ReplayError):
                RP.load_rules(os.path.join(d, "sel", "rules_selection.json"), "f" * 64)
            with self.assertRaises(V.SelectionError):
                RP.load_arms(os.path.join(d, "sel", "selection.json"), "f" * 64)
            arm = next((a for a in R.TUNED if rsel["arms"][a].get("artifact")), None)
            if arm:
                path = os.path.join(d, "sel", rsel["arms"][arm]["artifact"])
                with open(path, "ab") as fh:
                    fh.write(b" ")
                with self.assertRaises(RP.ReplayError):
                    RP.load_rules(os.path.join(d, "sel", "rules_selection.json"), rsha)


if __name__ == "__main__":
    unittest.main()
