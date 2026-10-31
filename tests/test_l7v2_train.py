"""The L7 v2 arms (docs/L7V2_DESIGN.md 8, 10; docs/P3_DATASET_DESIGN.md 4.8): view windows and request windows keyed
by (IP, UA, sid), the operating point on validation at the common benign budget with the pre-registered tie rules, the
probe-gated select step and the score step that refuses without the frozen selection. Offline; synthetic fixtures and
two-epoch fits on two threads (mechanics only)."""
import json
import os
import random
import shutil
import sys
import tempfile
import unittest

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import l7v2_model_prereg as PRE
import train_l7
import train_l7v2 as V

import l7_dataset as D
import l7_features as F
import l7_ingest as I

BASE = "http://10.0.0.1"


def _rec(cap, ent, cls, family, seq, ip, ua, sid, uri, start, ref=None, rt=0.02, sid_set=False):
    o = U.obj(ip=ip, ua=ua, uri=uri, msec=start + rt, rt=rt, creq=2)
    if ref is not None:
        o["ref"] = BASE + ref
    if sid is not None:
        o["sid_set" if sid_set else "sid"] = sid
    r = I.normalise(o)
    r.update({"_cls": cls, "_family": family, "_held": False, "_entity": ent, "_kof": family or "browser",
              "_seq": seq, "_cap": cap, "_ent": f"{cap}|{ent}"})
    return r


def population(cap="c1", seed=0, n_benign=6, n_bots=4, views=10, pool_users=3):
    """Benign browsers (Referer chains, revisits, short asset waves), a CGNAT pool (one IP and UA, one sid per user)
    and deep-linking bots (constant dwell, a Referer to a page they never loaded, one costly request per view)."""
    rng = random.Random(seed)
    recs = []

    def add(**kw):
        recs.append(_rec(seq=len(recs), **kw))

    def browse(ent, ip, ua, sid, t0):
        prev = None
        for v in range(views):
            t = t0 + 6.0 * v + rng.uniform(0, 4)
            page = "/" if v == 0 else f"/page/{rng.choice([1, 2, 3, 4])}"
            add(cap=cap, ent=ent, cls=D.BENIGN, family=None, ip=ip, ua=ua, sid=sid, uri=page, start=t, ref=prev,
                sid_set=v == 0)
            add(cap=cap, ent=ent, cls=D.BENIGN, family=None, ip=ip, ua=ua, sid=sid,
                uri=f"/static/site6/p{v % 3}/img0.png", start=t + 0.2, ref=page)
            prev = page

    for b in range(n_benign):
        browse(f"b{b}", f"10.0.16.{b + 1}", f"Mozilla/5.0 B{b % 2}", f"{b:032x}", 1.0 * b)
    for u in range(pool_users):
        browse("pool", "10.0.16.200", "Mozilla/5.0 B0", f"{100 + u:032x}", 2.0 * u)
    for a in range(n_bots):
        ip, sid = f"10.0.17.{a + 1}", f"{500 + a:032x}"
        for v in range(views):
            t = 0.5 * a + 3.0 * v
            add(cap=cap, ent=f"a{a}", cls=D.ATTACK, family="C3b@M1", ip=ip, ua="Mozilla/5.0 B1", sid=sid,
                uri=f"/page/{100 + v}", start=t, ref="/page/search", sid_set=v == 0)
            add(cap=cap, ent=f"a{a}", cls=D.ATTACK, family="C3b@M1", ip=ip, ua="Mozilla/5.0 B1", sid=sid,
                uri="/search?q=alpha", start=t + 0.3, ref=f"/page/{100 + v}")
    recs.sort(key=lambda r: r["msec"])
    for i, r in enumerate(recs):
        r["_seq"] = i
    entities = ([{"entity_id": f"b{b}", "role": "benign", "users": []} for b in range(n_benign)]
                + [{"entity_id": "pool", "role": "benign", "users": [f"pool/u{u}" for u in range(pool_users)]}]
                + [{"entity_id": f"a{a}", "role": "attack", "users": []} for a in range(n_bots)])
    return {"format": D.DATASET_FORMAT_V3, "entities": entities}, recs, cap


class WindowTest(unittest.TestCase):
    def test_view_windows_per_key_and_complete_token(self):
        _m, recs, _c = population()
        ws = V.view_windows(recs, max_views=8, min_views=4)
        per_key = {}
        for w in ws:
            per_key.setdefault(w["key"], []).append(w)
            np.testing.assert_array_equal(w["X"], F.token_matrix(w["recs"], 8))
            self.assertEqual(len({I.key_v2(r) for r in w["recs"]}), 1)
        self.assertEqual(len(per_key), 6 + 3 + 4)                 # the pool's users are three keys
        for seq in per_key.values():
            self.assertEqual(len(seq), 10 - 4)                     # tokens 4..9 complete one window each
            self.assertEqual([w["n"] for w in seq], [4, 5, 6, 7, 8, 8])
            self.assertEqual([w["t"] for w in seq], sorted(w["t"] for w in seq))

    def test_the_session_splits_at_the_idle_gap(self):
        _m, recs, _c = population(n_benign=1, n_bots=0, pool_users=0)
        late = [{**r, "msec": r["msec"] + (400.0 if i >= 10 else 0.0)} for i, r in enumerate(recs)]
        self.assertEqual(len(V.sessions(F.ordered(late), 300.0)), 2)
        self.assertEqual(len(V.view_windows(late, 8, 4, idle_s=300.0)), 1 + 1)   # two sessions of 5 views each

    def test_request_windows_by_v2_key(self):
        _m, recs, _c = population()
        cols = F.columns(F.V2_REQUEST_GROUPS)
        ws = V.request_windows(recs, cols, 64, 3, 5)
        self.assertTrue(ws)
        for w in ws:
            self.assertEqual(w["X"].shape, (64, len(cols)))
            self.assertEqual(len({I.key_v2(r) for r in w["recs"]}), 1)
            self.assertEqual(w["t"], w["recs"][-1]["msec"])

    def test_thinning_is_per_key(self):
        _m, recs, _c = population()
        ws = V.view_windows(recs, 8, 4)
        self.assertEqual(len(V.thin(ws, cap=2)), 2 * 13)
        self.assertEqual(V.MAX_TRAIN_WIN_PER_KEY, train_l7.MAX_WIN_PER_GROUP)


class OperatingPointTest(unittest.TestCase):
    def setUp(self):
        self.split = V.Split([population()], request=False)
        self.ws = self.split.view

    def scores(self, bot=0.99, benign=0.1, pool=None):
        out = []
        for w in self.ws:
            if w["y"]:
                out.append(bot)
            elif pool is not None and w["ip"].endswith("|pool"):
                out.append(pool)
            else:
                out.append(benign)
        return np.array(out)

    def test_denominators(self):
        self.assertEqual(len(self.split.attack), 4)
        self.assertEqual(sum(self.split.units.values()), 6 + 3)
        self.assertEqual(self.split.units["c1|pool"], 3)

    def test_a_perfect_separator_takes_the_first_grid_point(self):
        op = V.operating_point(self.ws, self.scores(), self.split)
        self.assertEqual((op["recall"], op["benign_units_flagged"], op["consecutive"], op["threshold"]),
                         (1.0, 0, 1, 0.5))
        self.assertEqual(op["grid_index"], 0)

    def test_the_budget_counts_a_pools_flagged_users(self):
        sel = {**PRE.selection(), "budget": 0.25}               # 9 units: 2 may be flagged
        op = V.operating_point(self.ws, self.scores(pool=0.97), self.split, sel)
        self.assertGreater(op["threshold"], 0.97)                # three flagged pool keys cost 3 units > 2
        self.assertEqual(op["benign_units_flagged"], 0)

    def test_an_entity_costs_at_most_its_units(self):
        dec = {("c1", ("10.0.16.1", 1, 1)): ("c1|b0", 50.0), ("c1", ("10.0.16.1", 1, 2)): ("c1|b0", 60.0),
               ("c1", ("10.0.16.200", 1, 3)): ("c1|pool", 70.0)}
        a = V.assess(dec, self.split)
        self.assertEqual((a["benign_units_flagged"], a["benign_entities_flagged"]), (2, 2))

    def test_one_unit_rule_for_both_budget_consumers(self):
        self.assertEqual([train_l7.unit_cost(n, 3) for n in (0, 1, 2, 3, 5)], [0, 1, 2, 3, 3])
        dec = {("c1", ("10.0.16.200", 1, s)): ("c1|pool", 50.0) for s in (1, 2)}
        self.assertEqual(V.assess(dec, self.split)["benign_units_flagged"], train_l7.unit_cost(2, 3))

    def test_ties_go_to_fewer_benign_flags_then_faster_then_grid_order(self):
        s = self.scores(bot=0.99, benign=0.55)
        op = V.operating_point(self.ws, s, self.split, {**PRE.selection(), "budget": 0.5})
        self.assertEqual(op["benign_units_flagged"], 0)          # theta 0.6 beats 0.5 (same recall, no flags)
        self.assertEqual((op["consecutive"], op["threshold"]), (1, 0.6))

    def test_recall_counts_entities_without_windows(self):
        self.split.attack.add("c1|a_silent")
        op = V.operating_point(self.ws, self.scores(), self.split)
        self.assertEqual((op["caught"], op["attack_entities"], op["recall"]), (4, 5, 0.8))

    def test_a_point_that_catches_nothing_is_still_a_point(self):
        op = V.operating_point(self.ws, self.scores(benign=1.0), self.split)
        self.assertEqual((op["recall"], op["benign_units_flagged"], op["consecutive"]), (0.0, 0, 8))

    def test_none_without_attack_entities(self):
        self.split.attack.clear()
        self.assertIsNone(V.operating_point(self.ws, self.scores(), self.split))

    def test_the_selection_rules_are_the_pre_registered_ones(self):
        sel = PRE.selection()
        self.assertEqual((sel["budget"], sel["k_grid"][0], sel["theta_grid"][0]), (0.01, 1, 0.5))


class AgeOnlyTest(unittest.TestCase):
    """The age-only baseline (ml/l7v2_model_prereg.json baselines.age_only, D-034, T038-01)."""

    def test_a_window_carries_its_key_age(self):
        _m, recs, _c = population(n_benign=1, n_bots=0, pool_users=0)
        ws = V.view_windows(recs, 8, 4)
        starts = sorted(F.start_time(r) for r in recs)
        self.assertTrue(all(w["age"] is not None and w["age"] > 0 for w in ws))
        self.assertEqual([round(w["age"], 6) for w in ws],
                         sorted(round(w["age"], 6) for w in ws), "age grows along a key")
        self.assertLessEqual(max(w["age"] for w in ws), starts[-1] - starts[0] + 1e-9)

    def test_younger_scores_higher_on_benign_quantiles(self):
        ref = [10.0, 20.0, 30.0, 40.0]
        p = V.age_scores(ref, [{"age": a} for a in (5.0, 20.0, 35.0, 50.0)])
        np.testing.assert_allclose(p, [1.0, 0.625, 0.25, 0.0])

    def test_the_reading(self):
        self.assertEqual(V.age_reading(0.62), "near chance")
        self.assertEqual(V.age_reading(0.36), "near chance")
        self.assertEqual(V.age_reading(0.66), "age-confounded")
        self.assertEqual(V.age_reading(0.30), "age-confounded")
        self.assertEqual(V.window_auc([0.9, 0.8, 0.1, 0.2], [1, 1, 0, 0]), 1.0)
        self.assertEqual(V.window_auc([0.5, 0.5], [1, 0]), 0.5)

    def test_young_bots_read_as_age_confounded(self):
        # the fixture's bots load a page every 3 s from t ~ 0, its browsers every ~8 s: attack windows are younger
        split = V.Split([population()], request=False)
        p = V.age_scores([w["age"] for w in split.view if not w["y"]], split.view)
        rep = V.age_report(split.view, p)
        self.assertGreater(rep["auc"], 0.65)
        self.assertEqual(V.age_reading(rep["auc"]), "age-confounded")
        self.assertEqual(set(rep["auc_by_family"]), {"C3b@M1"})


class TuningTest(unittest.TestCase):
    """One tuning rule for every arm (ml/l7v2_model_prereg.json models.training, D-034, T038-04)."""

    def test_the_gru_weights_do_not_depend_on_the_validation_windows(self):
        import torch

        from l7_view_model import ViewGRU
        tr = V.Split([population("t1", seed=1)], request=False).view
        va = V.Split([population("v1", seed=3)], request=False).view
        mean, std = train_l7.fit_scaling(tr, len(F.TOKEN_COLUMNS))
        states = []
        for val in (va, va[:3], []):
            torch.manual_seed(0)                       # the same initial weights each time
            m, _loss = V.fit_torch(ViewGRU(len(F.TOKEN_COLUMNS), 8, 8, 1, 0.0), tr, val, mean, std, seed=0, epochs=3,
                                   lr=0.01, batch=16, threads=1)
            states.append({k: v.clone() for k, v in m.state_dict().items()})
        for st in states[1:]:
            for k in st:
                self.assertTrue(torch.equal(st[k], states[0][k]), k)

    def test_the_hgb_is_balanced_without_early_stopping(self):
        import pickle
        d = tempfile.mkdtemp()
        try:
            train = V.Split([population("t1", seed=1)], request=False)
            val = V.Split([population("v1", seed=3)], request=False)
            V.select(train, val, d, arms=("hgb",), threads=1, valid_for_claims=False, source="fixture",
                     split_sha256="0" * 64)
            with open(os.path.join(d, "hgb.pkl"), "rb") as fh:
                params = pickle.load(fh).get_params()
        finally:
            shutil.rmtree(d)
        self.assertEqual((params["class_weight"], params["early_stopping"], params["max_iter"]),
                         ("balanced", False, PRE.load()["models"]["hgb"]["max_iter"]))
        self.assertEqual(PRE.load()["models"]["lr"]["class_weight"], "balanced")


class ShuffledVariantsTest(unittest.TestCase):
    """T038-05 (D-034): the pin_first variant and the benign units beside every gap."""

    def test_pin_first_keeps_the_first_valid_token(self):
        _m, recs, _c = population()
        ws = V.view_windows(recs, 8, 4)
        X = V.shuffled_stack(ws, 7, pin_first=True)
        moved = 0
        for w, x in zip(ws, X, strict=True):
            idx = np.flatnonzero(w["X"][:, 0] > 0)
            np.testing.assert_array_equal(x[idx[0]], w["X"][idx[0]])
            self.assertEqual(sorted(map(tuple, x[idx])), sorted(map(tuple, w["X"][idx])))
            moved += int(not np.array_equal(x, w["X"]))
        self.assertGreater(moved, 0)
        np.testing.assert_array_equal(V.shuffled_stack(ws, 7), np.stack([F.shuffle_valid_rows(w["X"], r) for w, r in
                                                                          zip(ws, [np.random.default_rng(7)] * len(ws),
                                                                              strict=True)]))

    def test_the_gap_carries_both_units(self):
        g = V.order_gap({"recall": 0.8, "benign_units_flagged": 1}, {"recall": 0.5, "benign_units_flagged": 4}, 2)
        self.assertEqual(g, {"recall_gap_pp": 30.0, "benign_units_view_gru": 1, "benign_units_shuffled": 4,
                             "allowed": 2, "shuffled_within_budget": False})


class FreezeTest(unittest.TestCase):
    """T038-07 (D-034): a selection is never overwritten, and score's train/val captures are split.json's."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.sel_path = os.path.join(self.dir, "selection.json")
        with open(os.path.join(self.dir, "split.json"), "w", encoding="utf-8") as fh:
            json.dump({"format": "x", "captures": {"T1": {"split": "train", "seed": 1001, "manifest_sha256": "a"},
                                                   "V1": {"split": "val", "seed": 2001, "manifest_sha256": "b"}},
                       "entities": {}}, fh)
        self.man = {"/d/t1": {"capture_id": "T1", "manifest_sha256": "a"},
                    "/d/v1": {"capture_id": "V1", "manifest_sha256": "b"},
                    "/d/v2": {"capture_id": "V2", "manifest_sha256": "c"}}
        self.sel = {"split_dirs": {"train": ["/d/t1"], "val": ["/d/v1"]}}

    def derive(self, train=None, val=None, sel=None):
        return V.derive_splits(self.sel_path, self.sel if sel is None else sel, train, val, ["/d/e1"],
                               manifest_of=self.man.get)

    def test_omitted_train_and_val_come_from_the_frozen_selection(self):
        self.assertEqual(self.derive(), {"train": ["/d/t1"], "val": ["/d/v1"], "eval": ["/d/e1"]})

    def test_given_ones_must_be_split_jsons(self):
        self.assertEqual(self.derive(["/d/t1"], ["/d/v1"])["val"], ["/d/v1"])
        for train, val in ((["/d/t1"], ["/d/v2"]), (["/d/t1"], []), ([], ["/d/v1"])):
            with self.subTest(train=train, val=val), self.assertRaises(V.SelectionError):
                self.derive(train, val, sel={})
        with self.assertRaises(V.SelectionError):
            V.derive_splits(os.path.join(self.dir, "nowhere", "selection.json"), self.sel, None, None, [],
                            manifest_of=self.man.get)

    def test_select_refuses_an_existing_selection(self):
        for name in ("selection.json", "split.json"):
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d)
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write("{}")
            with self.subTest(name=name), self.assertRaises(V.SelectionError):
                V.refuse_overwrite(d)
        with self.assertRaises(V.SelectionError):
            V.main(["select", "--train", "/d/t1", "--val", "/d/v1", "--out", self.dir])


def timed(cap="c1", seed=0, phase=(20.0, 40.0), intensity=2.0):
    """population() with a P3 timeline (t0_wall 0, one attack phase) and its bots scheduled in that phase."""
    m, recs, cap = population(cap, seed)
    m = {**m, "timeline": {"t0_wall": 0.0, "phases": [{"name": "C3b", "start_s": phase[0], "stop_s": phase[1],
                                                       "intensity": intensity}]}}
    for e in m["entities"]:
        e["schedule"] = {"start_s": 0.0, "stop_s": 99.0, "phase": "C3b" if e["role"] == "attack" else None}
    return m, recs, cap


class LoadSplitTest(unittest.TestCase):
    """The descriptive load split (ml/l7v2_model_prereg.json load_split, D-034, T038-02): never a gate."""

    def test_benign_flags_inside_and_outside_the_phases_and_recall_by_level(self):
        split = V.Split([timed()], request=False)
        ws = split.view
        p = np.array([0.99 if (w["y"] or split.inside(w)) else 0.1 for w in ws])
        res = V.load_split(ws, p, split, {"threshold": 0.5, "consecutive": 1})
        inside = [w for w in ws if not w["y"] and split.inside(w)]
        outside = [w for w in ws if not w["y"] and not split.inside(w)]
        self.assertTrue(inside and outside)
        self.assertEqual(res["benign_inside"], {"flagged": len(inside), "windows": len(inside), "rate": 1.0})
        self.assertEqual(res["benign_outside"], {"flagged": 0, "windows": len(outside), "rate": 0.0})
        self.assertEqual(res["recall_by_load"], {"2.0": {"caught": 4, "entities": 4, "recall": 1.0}})

    def test_no_point_no_split_and_no_timeline_no_phase(self):
        split = V.Split([population()], request=False)
        self.assertIsNone(V.load_split(split.view, np.zeros(len(split.view)), split, None))
        res = V.load_split(split.view, np.zeros(len(split.view)), split, {"threshold": 0.5, "consecutive": 1})
        self.assertEqual(res["benign_inside"]["windows"] + res["benign_outside"]["windows"], 0)
        self.assertEqual(res["recall_by_load"], {"None": {"caught": 0, "entities": 4, "recall": 0.0}})


class SelectScoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.out = os.path.join(cls.dir, "sel")
        train = V.Split([population("t1", seed=1), population("t2", seed=2)])
        val = V.Split([population("v1", seed=3)])
        cls.sel, cls.sha = V.select(train, val, cls.out, epochs=2, threads=2, valid_for_claims=False,
                                    source="synthetic fixture", split_sha256="0" * 64)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def test_every_arm_is_gated_and_has_a_point(self):
        self.assertEqual(set(self.sel["arms"]), set(PRE.ARMS))
        for name in ("view_gru", "hgb", "lr", "request_gru"):
            arm = self.sel["arms"][name]
            self.assertTrue(arm["probe_gate_pass"], name)
            self.assertEqual(arm["probes"]["gate"], list(PRE.load()["probes"]["gate_v2"]))
            self.assertIn("operating_point", arm)
        self.assertEqual(self.sel["arms"]["gru_shuffled"]["operating_point"],
                         self.sel["arms"]["view_gru"]["operating_point"])

    def test_the_shuffled_variants_report_their_units_beside_the_gap(self):
        sh = self.sel["arms"]["gru_shuffled"]
        for part in (sh, sh["pin_first"]):
            self.assertIn("benign_units_flagged", part["val_at_point"])
            if self.sel["arms"]["view_gru"]["operating_point"] is not None:
                self.assertEqual(part["gap"]["benign_units_shuffled"], part["val_at_point"]["benign_units_flagged"])
                self.assertIn("benign_units_view_gru", part["gap"])

    def test_every_arm_reports_the_load_split(self):
        for name, arm in [*self.sel["arms"].items(), *self.sel["baselines"].items()]:
            self.assertIn("load_split", arm, name)
            if arm["operating_point"] is not None:
                self.assertEqual(set(arm["load_split"]), {"benign_inside", "benign_outside", "recall_by_load"}, name)

    def test_the_age_only_baseline_is_scored_beside_the_arms(self):
        b = self.sel["baselines"]["age_only"]
        self.assertNotIn("age_only", self.sel["arms"])
        self.assertEqual(b["artifact"], "age_only.json")
        self.assertIn("operating_point", b)
        self.assertIn(b["reading"], ("near chance", "age-confounded"))
        self.assertEqual(b["reading"], V.age_reading(b["val_auc"]))
        self.assertEqual(set(b["val_auc_by_family"]), {"C3b@M1"})

    def test_an_altered_age_artifact_is_refused(self):
        tmp = os.path.join(self.dir, "copy_age")
        shutil.copytree(self.out, tmp)
        with open(os.path.join(tmp, "age_only.json"), "a", encoding="utf-8") as fh:
            fh.write(" ")
        with self.assertRaises(V.SelectionError):
            V.load_selection(os.path.join(tmp, "selection.json"), self.sha)

    def test_the_packages_carry_their_level(self):
        import l7_scorer as S
        self.assertEqual(S.L7Scorer.load(os.path.join(self.out, "view_gru"), level="view").max_views,
                         PRE.load()["views"]["max_views"])
        self.assertEqual(S.L7Scorer.load(os.path.join(self.out, "request_gru"), level="request").seq_len,
                         PRE.load()["request_level"]["seq_len"])

    def test_the_selection_file_is_frozen(self):
        with open(os.path.join(self.out, "selection.sha256"), encoding="utf-8") as fh:
            self.assertEqual(fh.read().split()[0], self.sha)
        sel = V.load_selection(os.path.join(self.out, "selection.json"), self.sha)
        self.assertEqual((sel["format"], sel["valid_for_claims"]), ("l7v2-selection/1", False))
        self.assertEqual(sel["prereg_sha256"], V._sha_file(PRE.PREREG_PATH))
        with self.assertRaises(V.SelectionError):
            V.load_selection(os.path.join(self.out, "selection.json"), "f" * 64)
        with self.assertRaises(V.SelectionError):
            V.load_selection(os.path.join(self.out, "selection.json"), None)

    def test_a_second_select_into_the_same_directory_is_refused(self):
        with open(os.path.join(self.out, "selection.json"), "rb") as fh:
            before = fh.read()
        with self.assertRaises(V.SelectionError):
            V.select(V.Split([population("t1", seed=1)]), V.Split([population("v1", seed=3)]), self.out, epochs=1,
                     threads=1, valid_for_claims=False, source="again", split_sha256="1" * 64)
        with open(os.path.join(self.out, "selection.json"), "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_an_altered_artifact_is_refused(self):
        tmp = os.path.join(self.dir, "copy")
        shutil.copytree(self.out, tmp)
        with open(os.path.join(tmp, "hgb.pkl"), "ab") as fh:
            fh.write(b"x")
        with self.assertRaises(V.SelectionError):
            V.load_selection(os.path.join(tmp, "selection.json"), self.sha)

    def test_score_applies_the_frozen_points(self):
        ev = V.Split([population("e1", seed=9)])
        sel = V.load_selection(os.path.join(self.out, "selection.json"), self.sha)
        res = V.score(ev, sel, os.path.join(self.out, "selection.json"), os.path.join(self.dir, "eval"))
        self.assertEqual(set(res["arms"]), set(PRE.ARMS))
        for arm in res["arms"].values():
            self.assertEqual(arm["attack_entities"], 4)
            self.assertEqual(set(arm["by_family"]), {"C3b@M1"})
        self.assertIn("pin_first", res["arms"]["gru_shuffled"])
        self.assertIn("benign_units_flagged", res["arms"]["gru_shuffled"]["pin_first"])
        self.assertEqual(res["baselines"]["age_only"]["attack_entities"], 4)
        self.assertIn("auc", res["baselines"]["age_only"])
        with open(os.path.join(self.dir, "eval", "eval.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["selection_sha256"], self.sha)


if __name__ == "__main__":
    unittest.main()
