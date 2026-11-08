"""The P1 analysis (eval/p1_analysis.py; docs/L7V2_DESIGN.md 5.3, 10, 11): fake campaigns of eval/p1_runner.py on the fake host,
through eval/l7v2_harm.py, the replay and ml/l7v2_verdict.py, to one verdict per class. Each verdict is reached end to end on
fake outputs: only the arms' decisions in the replay are stubs, behind the engine's real path. Offline."""
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import calibration_fixtures
import harm_gate as HG
import l7v2_harm as LH
import l7v2_replay as RP
import l7v2_verdict_prereg as VP
import p1_analysis as A
import p1_fake_host as F
import p1_records as REC
import p1_runner as R
import p1_traffic as PT

import l7_backend
import l7_ingest as I

SEEDS = VP.load()["units"]["eval_seeds"]
ARMS = ("view_gru", "hgb", "gru_shuffled", "R*", "age_only", "default_rules")
LEAN = {"tpcw_browsing": 4, "search_user": 2, "exporter": 1, "flash_crowd": 1, "api_bulk": 1}


class StubArm(RP._Tapped):
    """An arm's decisions in the replay: p = 1 on the given addresses, through the engine's real windows and policy."""

    def __init__(self, addresses):
        super().__init__(0.5, 1, "stub")
        self.addresses = addresses

    def rows(self, ctx):
        return np.array([1.0 if k[0] in self.addresses else 0.0 for k, _t, _s0, _s in ctx], dtype=np.float64)

    def p(self, rows):
        return rows


class StubPath(RP.RulePath):
    """The same decisions on the (IP, UA) path, without the engine's cost: a key is decided at its first record."""

    def __init__(self, addresses):
        self.addresses = addresses
        self.threshold, self.consecutive, self.sha256 = 0.5, 1, "stub"

    def run(self, items):
        decided = {}
        for it in items:
            if it[0] == "record" and it[1]["ip"] in self.addresses:
                decided.setdefault((it[1]["ip"], I.stable_hash32(it[1]["ua"])), float(it[1]["msec"]))
        return decided, {"polls": 0, "suppressed_polls": 0, "rows": 0, "late": 0}


def factory(shares):
    """arms_factory: for each arm, the given share of each attack family's addresses of the run's class. The GRU goes through
    the engine's real windows and policy, the other arms through StubPath."""
    def build(_run_dir, man):
        fams = {}
        for e in man["entities"]:
            if e["role"] == "attack":
                fams.setdefault(e["kind_or_family"], []).append(e["address"])
        out = {}
        for arm in ARMS:
            share = shares.get(man["class"], {}).get(arm, 0.0)
            chosen = {a for addrs in fams.values() for a in addrs[:round(share * len(addrs))]}
            out[arm] = StubArm(chosen) if arm == "view_gru" else StubPath(chosen)
        return out
    return build


def fail_from(table):
    """fail_share(run, block_dir, t) from {run: share or callable(seed)}: the block's seed gives it a little noise."""
    def fail(run, block_dir, _t):
        seed = int(re.search(r"b(\d+)_a", block_dir).group(1))
        v = table.get(run, 0.0)
        v = v(seed) if callable(v) else v
        return v if v == 0.0 else max(0.0, v + 0.004 * (seed % 5 - 2))
    return fail


def run_campaign(root, frozen, fail, acts=None, cut=False, seeds=SEEDS):
    for seed in seeds:
        block = R.plan_block("campaign", seed, root, frozen=frozen, cut=cut, benign_specs=F.thin_benign(LEAN), max_sources=3)
        res = R.run_block(F.P1FakeHost(fail_share=fail, acts=acts), block)
        assert all(x["ok"] for _n, x in res), res


def run_campaign_any(root, frozen, fail, acts=None, cut=False, seeds=SEEDS):
    """run_campaign that lets a run be invalid."""
    for seed in seeds:
        block = R.plan_block("campaign", seed, root, frozen=frozen, cut=cut, benign_specs=F.thin_benign(LEAN), max_sources=3)
        R.run_block(F.P1FakeHost(fail_share=fail, acts=acts), block)


def deny_first_benign(names):
    """acts: in the named runs the daemon denies one view-level key of the run's first benign entity."""
    def acts(run, block_dir):
        if run not in names:
            return []
        plan = REC.read_json(os.path.join(block_dir, run, "plan.json"))
        ip = next(e["address"] for e in plan["entities"] if e["role"] == "benign")
        return [(1.0, {"kind": "l7_deny", "level": 1, "ip": ip, "ua_h": 1, "sid_h": 2}), (2.0, {"kind": "l7_reload", "ok": True})]
    return acts


class Campaign(unittest.TestCase):
    TABLE, ACTS, SHARES, CUT = {}, None, {}, False

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        run_campaign(cls.root, cls.frozen, fail_from(cls.TABLE), cls.ACTS, cut=cls.CUT)
        cls.res = A.analyse(cls.root, cls.cal, cls.frozen, arms_factory=factory(cls.SHARES), cut=cls.CUT)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


TABLE_A = {"U_C3b": 0.60, "M_default_rules_C3b": 0.40, "M_rstar_C3b": 0.30, "M_hgb_C3b": 0.24, "M_gru_C3b": 0.10,
           "U_C2": 0.40, "M_rstar_C2": 0.10, "M_gru_C2": 0.09}
SHARES_A = {"C3b": {"view_gru": 1.0, "hgb": 0.34, "gru_shuffled": 0.34, "R*": 0.34, "age_only": 0.0},
            "C2": {"view_gru": 1.0, "hgb": 1.0, "gru_shuffled": 1.0, "R*": 1.0}}
TABLE_B = {"U_C3b": 0.60, "M_default_rules_C3b": 0.40, "M_rstar_C3b": 0.30, "M_hgb_C3b": 0.15, "M_gru_C3b": 0.14,
           "U_C2": 0.40, "M_rstar_C2": 0.20, "M_gru_C2": lambda seed: 0.05 if seed % 2 else 0.29,
           "U_C3a": 0.40, "M_rstar_C3a": 0.10, "M_gru_C3a": 0.10}
SHARES_B = {"C3b": {"view_gru": 0.67, "hgb": 0.67, "gru_shuffled": 0.34, "R*": 0.34},
            "C2": {"view_gru": 0.67, "hgb": 0.67, "gru_shuffled": 0.67, "R*": 0.67},
            "C3a": {"view_gru": 1.0, "hgb": 1.0, "gru_shuffled": 1.0, "R*": 1.0}}


class CampaignA(Campaign):
    """C3b V-A, C2 V-C, C3a V-D (no harm)."""
    TABLE, SHARES = TABLE_A, SHARES_A

    def test_v_a(self):
        r = self.res["C3b"]
        self.assertEqual(r["verdict"], "V-A", r.get("judge", {}).get("notes"))
        self.assertTrue(r["admission"]["admitted"])
        self.assertEqual(r["blocks_judged"], SEEDS)
        contrasts = r["judge"]["contrasts"]
        for name in ("harm view_gru vs R*", "harm view_gru vs hgb", "harm view_gru vs default_rules", "harm view_gru vs U",
                     "detection view_gru vs hgb", "detection view_gru vs gru_shuffled",
                     "detection view_gru vs age_only (descriptive)"):
            self.assertIn(name, contrasts)
        self.assertAlmostEqual(contrasts["harm view_gru vs R*"]["mean_pp"], 20.0, delta=3.0)

    def test_c3b_reads_m2_and_reports_the_others(self):
        r = self.res["C3b"]["judge"]
        self.assertEqual(r["contrasts"]["detection view_gru vs hgb"]["entities"], 3 * len(SEEDS))
        self.assertEqual(sorted(r["reported_separately"]), ["C3b@M1", "C3b@M2exp", "C3b@M3"])

    def test_v_c(self):
        self.assertEqual(self.res["C2"]["verdict"], "V-C", self.res["C2"].get("judge", {}).get("steps"))

    def test_v_d_no_harm(self):
        r = self.res["C3a"]
        self.assertEqual(r["verdict"], "V-D")
        self.assertFalse(r["admission"]["admitted"])
        self.assertEqual(r["admission"]["verdict"], "V-D: no harm")

    def test_the_budget_has_both_readings(self):
        b = self.res["C3b"]["judge"]["budget"]
        self.assertEqual(sorted(b), ["live", "replay"])
        self.assertEqual(sorted(b["live"]), ["R*", "default_rules", "hgb", "view_gru"])
        self.assertTrue(all(v["meets"] for v in b["live"].values()))
        self.assertGreater(b["live"]["view_gru"]["users"], 0)

    def test_the_replay_summary_is_per_arm_and_family(self):
        rep = self.res["C3b"]["replay"]
        self.assertEqual(rep["view_gru"]["by_family"]["C3b@M2"], {"caught": 3 * len(SEEDS), "entities": 3 * len(SEEDS)})
        self.assertEqual(rep["age_only"]["caught"], 0)

    def test_the_command_line_writes_the_verdicts(self):
        # the frozen arms need trained artifacts, so this reads an admission-only class set through the same path
        out = os.path.join(self.tmp.name, "v.json")
        with mock.patch.object(A, "default_factory", lambda _f: factory(self.SHARES)):
            code = A.main([self.root, "--calibration", self.frozen["calibration"], "--selection", self.frozen["selection"],
                           "--selection-sha256", self.frozen["selection_sha256"], "--rules", self.frozen["rules"],
                           "--rules-sha256", self.frozen["rules_sha256"], "--out", out])
        self.assertEqual(code, 0)
        res = REC.read_json(out)
        self.assertEqual(res["format"], "p1-verdicts/1")
        self.assertEqual({k: v["verdict"] for k, v in res["classes"].items()}, {"C3b": "V-A", "C2": "V-C", "C3a": "V-D"})

    def judged(self):
        return {c: r for c, r in self.res.items() if r.get("replay")}

    def test_each_admitted_class_has_the_age_only_reading_with_its_blocks(self):
        self.assertTrue(self.judged())
        for cls, row in self.judged().items():
            with self.subTest(cls=cls):
                got = row["age_only_on_U"]
                self.assertEqual([b["block"] for b in got["per_block"]], row["blocks_judged"])
                self.assertGreater(got["windows_benign"], 0)
                self.assertGreater(got["windows_attack"], 0)
                self.assertIsNotNone(got["auc"])
                self.assertIn("descriptive", got["note"])
                self.assertIn(got["reading"], ("near chance", "age-confounded"))
                self.assertEqual(got["attack_entities"], row["replay"]["age_only"]["attack_entities"])
                self.assertIn(got["per_block"][0]["age_check_pass"], (True, False))

    def test_every_view_level_contrast_of_the_judge_has_the_reading_beside_it(self):
        for cls, row in self.judged().items():
            names = [n for n in row["judge"]["contrasts"] if A.VIEW_ARMS & set(n.split())]
            with self.subTest(cls=cls):
                self.assertTrue(names)
                self.assertTrue(set(names) <= set(row["view_level_contrasts"]))
                for name in names:
                    self.assertTrue(all(row["view_level_contrasts"][name]["age_only_on_U"].values()), name)

    def test_nothing_that_judges_reads_the_age_only_reading(self):
        junk = {"by_family": {}, "note": "junk"}
        with mock.patch.object(A, "age_only_on_u", return_value=junk):
            other = A.analyse(self.root, self.cal, self.frozen, arms_factory=factory(self.SHARES), cut=self.CUT)
        for cls, row in self.judged().items():
            self.assertEqual(json.dumps(other[cls]["judge"], sort_keys=True, default=str),
                             json.dumps(row["judge"], sort_keys=True, default=str), cls)

    def test_a_dry_run_keeps_the_reading_without_a_contrast(self):
        res = A.analyse(self.root, self.cal, self.frozen, arms_factory=factory(self.SHARES), cut=self.CUT, dry_run=True)
        for cls in self.judged():
            self.assertIn("age_only_on_U", res[cls])
            self.assertNotIn("view_level_contrasts", res[cls])


class CampaignB(Campaign):
    """C3b V-B, C2 inconclusive, C3a V-D (no enforcing arm within the budget, on the live reading)."""
    TABLE, SHARES = TABLE_B, SHARES_B
    ACTS = deny_first_benign({"M_rstar_C3a", "M_gru_C3a"})

    def test_v_b(self):
        r = self.res["C3b"]
        self.assertEqual(r["verdict"], "V-B", r.get("judge", {}).get("steps"))
        self.assertEqual(r["judge"]["contrasts"]["detection view_gru vs hgb"]["outcome"], "equivalent")

    def test_inconclusive_with_power(self):
        r = self.res["C2"]
        self.assertEqual(r["verdict"], "inconclusive", r.get("judge", {}).get("steps"))
        self.assertIsNotNone(r["judge"]["contrasts"]["harm view_gru vs R*"]["power_blocks"])

    def test_v_d_no_arm_within_the_live_budget_while_the_replay_reads_clean(self):
        r = self.res["C3a"]
        self.assertEqual(r["verdict"], "V-D", r.get("judge", {}).get("steps"))
        b = r["judge"]["budget"]
        self.assertFalse(b["live"]["view_gru"]["meets"])
        self.assertTrue(b["replay"]["view_gru"]["meets"])
        self.assertEqual(b["live"]["view_gru"]["flagged"], len(SEEDS))


class SmallCampaignTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_too_few_valid_blocks_give_no_verdict_rather_than_no_harm(self):
        root = os.path.join(self.tmp.name, "two")
        run_campaign(root, self.frozen, fail_from({"U_C2": 0.4}), seeds=SEEDS[:2], cut=True)
        res = A.analyse(root, self.cal, self.frozen, arms_factory=factory({}), cut=True)
        self.assertEqual(sorted(res), ["C2", "C3b"], "the minimum cut's classes")
        self.assertIsNone(res["C2"]["verdict"])
        self.assertTrue(any("valid blocks" in w for w in res["C2"]["why_no_verdict"]))

    def test_the_last_attempt_of_a_block_counts(self):
        blocks = [{"block": 3001, "attempt": 1, "x": "old"}, {"block": 3001, "attempt": 2, "x": "new"},
                  {"block": 3002, "attempt": 1, "x": "only"}]
        self.assertEqual([b["x"] for b in A.final_attempts(blocks)], ["new", "only"])

    def test_a_block_with_an_unsound_live_run_is_excluded_with_its_reasons(self):
        ok = {"metrics": {"Q": 90.0}, "checks": {"ok": True}}
        bad = {"metrics": {"Q": 90.0}, "checks": {"ok": False, "reasons": ["the daemon exited"]}}
        blocks = [{"block": 1, "classes": {"C2": {"valid": True}}, "runs": {"U_C2": ok, "M_gru_C2": ok, "M_rstar_C2": ok}},
                  {"block": 2, "classes": {"C2": {"valid": True}}, "runs": {"U_C2": ok, "M_gru_C2": bad, "M_rstar_C2": ok}},
                  {"block": 3, "classes": {"C2": {"valid": False, "reasons": ["control"]}}, "runs": {"U_C2": ok}}]
        good, excluded = A.judged_blocks(blocks, "C2", ["U", "R*", "view_gru"])
        self.assertEqual([b["block"] for b in good], [1])
        self.assertIn("the daemon exited", excluded[2][0])
        self.assertIn("control", excluded[3])

    def test_a_block_whose_run_never_started_is_invalid_not_fatal(self):
        root = os.path.join(self.tmp.name, "dead")
        block = R.plan_block("campaign", SEEDS[0], root, frozen=self.frozen, cut=True, benign_specs=F.thin_benign(LEAN), max_sources=2)
        R.run_block(F.P1FakeHost(root=False), block)
        got = A.assess_attempts(root, self.cal, ["C2", "C3b"])
        self.assertEqual(len(got), 1)
        self.assertFalse(got[0]["classes"]["C2"]["valid"])

    def test_the_selection_inputs(self):
        recall, auc = A.selection_inputs(self.frozen)
        self.assertEqual(recall, {"view_gru": 0.9, "hgb": 0.6})
        self.assertEqual(auc, 0.52)

    def test_the_live_set_of_the_minimum_cut(self):
        pre = A.live_set(VP.load(), True)
        self.assertEqual(sorted(pre["live_set"]["per_class"]), ["C2", "C3b"])
        self.assertNotIn("default_rules", pre["live_set"]["per_class"]["C3b"])
        self.assertIn("default_rules", VP.load()["live_set"]["per_class"]["C3b"], "the file's own copy is untouched")


class LadderTest(unittest.TestCase):
    def test_the_knee_is_the_lowest_level_harmful_in_both_repeats(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        frozen = F.frozen_inputs(os.path.join(tmp.name, "frozen"))
        cal = l7_backend.load_record(frozen["calibration"])[0]
        root = os.path.join(tmp.name, "runs")
        for level, share in ((1.0, 0.02), (2.0, 0.30)):
            for rep in (1, 2):
                block = R.plan_block("ladder", R.PT.ladder_seed("C2", level, rep), root, frozen=frozen, levels={"C2": level}, runs=["C", "U_C2"],
                                     label=f"C2_L{level:g}_r{rep}", benign_specs=F.thin_benign(LEAN), max_sources=2)
                R.run_block(F.P1FakeHost(fail_share=lambda run, _b, _t, s=share: s if run == "U_C2" else 0.0), block)
        got = A.ladder_knees(root, cal)
        self.assertEqual(got["C2"]["level"], 2.0)
        self.assertEqual(got["C2"]["passing"], [2.0])
        out = os.path.join(tmp.name, "knees.json")
        self.assertEqual(A.main([root, "--calibration", frozen["calibration"], "--ladder", "--out", out]), 0)
        self.assertEqual(REC.read_json(out)["record_sha256"], calibration_fixtures.frozen()["sha256"])
        self.assertEqual(json.loads(json.dumps(REC.read_json(out)["knees"]["C2"]))["level"], 2.0)
        self.assertEqual(REC.read_json(out)["C2"], 2.0)
        self.assertEqual(REC.read_json(out)["benign_halvings"], 0)

    def test_a_ladder_at_two_factors_is_refused(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        frozen = F.frozen_inputs(os.path.join(tmp.name, "frozen"))
        other = dict(frozen, health=os.path.join(tmp.name, "h1.json"))
        with open(other["health"], "w", encoding="utf-8") as fh:
            json.dump({**REC.read_json(frozen["health"]), "benign_halvings": 1}, fh)
        root = os.path.join(tmp.name, "runs")
        for rep, inputs in ((1, frozen), (2, other)):
            block = R.plan_block("ladder", 9000 + rep, root, frozen=inputs, levels={"C2": 1.0}, runs=["C", "U_C2"],
                                 label=f"C2_L1_r{rep}", benign_specs=F.thin_benign(LEAN), max_sources=2)
            R.run_block(F.P1FakeHost(), block)
        with self.assertRaisesRegex(ValueError, "one factor"):
            A.ladder_factor(root)


class LevelWindowTest(unittest.TestCase):
    """D-053: the harm contrasts read the level window, admission and the whole-window Q the attack window."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        # U fails only in the attack's first 80 s, well before the level window: a harm the level window does not read.
        def fail(run, _b, t):
            return 0.5 if run == "U_C2" and 30.0 <= t < 110.0 else 0.0

        block = R.plan_block("campaign", SEEDS[0], cls.root, frozen=cls.frozen, cut=True, benign_specs=F.thin_benign(LEAN), max_sources=2)
        R.run_block(F.P1FakeHost(fail_share=fail), block)
        cls.block = LH.assess_block(block["dir"], cls.cal)
        cls.block["dir"] = os.path.basename(block["dir"])
        live = ["U", "R*", "view_gru"]
        cls.inputs, cls.per_arm = A.class_inputs(cls.root, cls.cal, "C2", [cls.block], live, cls.frozen, factory({"C2": {"view_gru": 1.0, "R*": 0.5}}))
        cls.report = A.class_report(cls.root, cls.cal, "C2", [cls.block], live, cls.per_arm)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_contrast_reads_the_level_window(self):
        self.assertEqual(self.inputs["harm"]["U"], {SEEDS[0]: 100.0})

    def test_the_whole_window_q_is_secondary_and_admission_reads_it(self):
        whole = self.report["whole_window_q"]["U"][SEEDS[0]]
        self.assertEqual(whole, self.block["runs"]["U_C2"]["metrics"]["Q"])
        self.assertLess(whole, 90.0)
        self.assertGreater(self.block["classes"]["C2"]["dQ"], 10.0)

    def test_the_server_side_q_and_the_late_window_are_reported_for_every_live_arm(self):
        for name in ("server_q", "late_window_q", "largest_view_slip_s"):
            self.assertEqual(sorted(self.report[name]), ["R*", "U", "view_gru"], name)
        self.assertEqual(self.report["late_window_q"]["U"][SEEDS[0]], 100.0, "U failed only before it")
        self.assertLess(self.report["server_q"]["U"][SEEDS[0]], 90.0, "the 503s of its first 80 s")
        self.assertGreater(self.report["server_q"]["view_gru"][SEEDS[0]], 99.0)

    def test_time_to_decision_and_cost_left_are_reported_per_arm(self):
        got = self.report["time_to_decision"]["view_gru"]["C2"]
        self.assertEqual(got["caught"], 2)
        self.assertGreaterEqual(got["mean_s"], 0.0)
        left = self.report["attack_cost_left"]
        self.assertLess(left["replay"]["view_gru"], 1.0)
        self.assertGreater(left["replay"]["R*"], left["replay"]["view_gru"])
        self.assertEqual(left["replay"]["hgb"], 1.0, "an arm that decides nothing removes nothing")
        self.assertEqual(sorted(left["live"]), ["R*", "view_gru"])
        self.assertEqual(left["live"]["view_gru"], 1.0, "the fake's M run serves its bots: nothing acted on them")

    def test_the_cost_left_by_hand(self):
        requests = [("a", 100.0, "C3"), ("a", 110.0, "C3"), ("a", 131.0, "C3"), ("b", 100.0, "C1"), ("c", 100.0, "C5")]
        first = {"a": 100.0, "b": 100.0, "c": 100.0}
        # a is decided 5 s after its first request: the gate gives 20 s, the reload 10 s, so its deny acts at 130 s
        left, sent = RP.cost_left(requests, first, {"a": 5.0}, {"C3": 30.0, "C1": 3.0}, 20.0, 10.0)
        self.assertEqual((left, sent), (63.0, 93.0))
        # a decision after the gate rules: at 140 s + 10 s the same request is still served
        self.assertEqual(RP.cost_left(requests, first, {"a": 40.0}, {"C3": 30.0, "C1": 3.0}, 20.0, 10.0)[0], 93.0)


class LadderAttemptsTest(unittest.TestCase):
    """T050-13: one invalid run does not sink its level for good; a re-run needs a reason; --ladder's file is what a campaign takes."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.frozen = F.frozen_inputs(os.path.join(tmp.name, "frozen"))
        self.cal = l7_backend.load_record(self.frozen["calibration"])[0]
        self.root = os.path.join(tmp.name, "runs")

    def pair(self, cls, level, rep, seed=None, attempt=1, share=0.30, **host):
        def fail(run, _b, _t, s=share, name=f"U_{cls}"):
            return s if run == name else 0.0
        block = R.plan_block("ladder", seed or R.PT.ladder_seed(cls, level, rep), self.root, frozen=self.frozen, levels={cls: level}, runs=["C", f"U_{cls}"],
                             label=f"{cls}_L{level:g}_r{rep}", attempt=attempt, benign_specs=F.thin_benign(LEAN), max_sources=2)
        return R.run_block(F.P1FakeHost(fail_share=fail, **host), block)

    def test_a_clean_re_run_restores_its_level(self):
        self.pair("C2", 1.0, 1, quiet_from=60.0)
        self.pair("C2", 1.0, 2, seed=9002)
        self.assertIsNone(A.ladder_knees(self.root, self.cal)["C2"]["level"], "repeat 1's only attempt is invalid: no harm")
        self.pair("C2", 1.0, 1, attempt=2)
        self.assertEqual(A.ladder_knees(self.root, self.cal)["C2"]["level"], 1.0)

    def test_a_repeat_with_no_sound_attempt_is_named_where_it_counts_as_no_harm(self):
        """T063-01: the registered rule stays (no sound attempt is no harm), and the file and the summary name the repeats it applied to."""
        self.pair("C2", 1.0, 1, quiet_from=60.0)
        self.pair("C2", 1.0, 2, seed=9002)
        out, said = os.path.join(self.tmp, "knees.json"), io.StringIO()
        with contextlib.redirect_stdout(said):
            self.assertEqual(A.main([self.root, "--calibration", self.frozen["calibration"], "--ladder", "--out", out]), 0)
        got = REC.read_json(out)
        self.assertEqual(got["no_sound_attempt"], [{"class": "C2", "level": 1.0, "repeat": 1, "attempts": 1}])
        self.assertIsNone(got["C2"], "the knee is read as before")
        self.assertIn("no sound attempt, counted as no harm (ml/p1_prereg_3.json ladder): C2 L1 r1", said.getvalue())
        self.pair("C2", 1.0, 1, attempt=2)
        got = A.knees_file(self.root, self.cal)
        self.assertEqual((got["no_sound_attempt"], got["C2"]), ([], 1.0))
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            A.main([self.root, "--calibration", self.frozen["calibration"], "--ladder", "--out", out])
        self.assertIn("counted as no harm (ml/p1_prereg_3.json ladder): none", said.getvalue())

    def test_every_level_has_its_status_and_a_class_without_a_knee_its_line(self):
        """D-074: run, not reachable, not run; 'no harm reached up to X on this testbed'; 'not reachable' never reads as no harm."""
        for rep in (1, 2):
            self.pair("C2", 1.0, rep)
            self.pair("C3a", 2.0, rep, share=0.0)
        why = "C3a at level 4.0 needs 333 sources, outside [50, 320]: not reachable"
        R.record_unreachable(self.root, "C3a", 4.0, 1, 9003, why)
        got = A.knees_file(self.root, self.cal)
        self.assertEqual(got["top_tested"], {"C2": 1.0, "C3a": 2.0, "C3b": None})
        lv = got["levels"]["C3a"]
        self.assertEqual([lv[k]["status"] for k in ("2", "4", "6", "8")], ["run", "not reachable", "not run", "not run"])
        self.assertEqual((lv["2"]["passed"], lv["2"]["no_sound_attempt"], lv["4"]["reason"]), (False, [], why))
        self.assertEqual(got["results"], {"C2": "C2: knee at 1",
                                          "C3a": f"C3a: no harm reached up to 2 on this testbed; not reachable: 4 ({why}); the ladder was cut "
                                                 "short below its registered top",
                                          "C3b": "C3b: not tested"})
        self.assertTrue(got["levels"]["C2"]["16"]["above_knee"])
        self.assertEqual((got["C3a"], got["no_knee"]), (None, ["C3a", "C3b"]))
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            A.main([self.root, "--calibration", self.frozen["calibration"], "--ladder", "--out", os.path.join(self.tmp, "knees.json")])
        self.assertIn("C3a: no harm reached up to 2 on this testbed", said.getvalue())

    def test_a_repeat_with_no_sound_attempt_is_named_in_the_line(self):
        self.pair("C3b", 50, 1, quiet_from=60.0, share=0.0)
        self.pair("C3b", 50, 2, share=0.0)
        got = A.knees_file(self.root, self.cal)
        self.assertEqual(got["levels"]["C3b"]["50"]["no_sound_attempt"], [1])
        self.assertEqual(got["top_tested"]["C3b"], None)
        self.assertEqual(got["results"]["C3b"], "C3b: no level ran with every repeat sound; no sound attempt, counted as no harm: 50 r1")

    def test_a_level_marked_crosses_never_becomes_a_knee(self):
        """ml/p1_prereg_5.json premise: such a level tests rate detection, not P1. None is so marked; a patched mark shows the rule."""
        for rep in (1, 2):
            self.pair("C2", 1.0, rep)
            self.pair("C2", 2.0, rep)
        self.assertEqual(A.ladder_knees(self.root, self.cal)["C2"]["level"], 1.0)
        self.assertEqual(A.knees_file(self.root, self.cal)["levels"]["C2"]["1"]["premise"], "evades")
        with mock.patch.object(A.PREMISE, "marks", return_value={("C2", 1.0): "crosses"}):
            self.assertEqual(A.ladder_knees(self.root, self.cal)["C2"]["level"], 2.0)
            self.assertEqual(A.knees_file(self.root, self.cal)["levels"]["C2"]["1"]["premise"], "crosses")

    def test_the_last_sound_attempt_counts_and_an_invalid_later_one_does_not_erase_it(self):
        self.pair("C2", 1.0, 1, quiet_from=60.0)
        self.pair("C2", 1.0, 1, attempt=2)
        self.pair("C2", 1.0, 2, seed=9002)
        self.assertEqual(A.ladder_knees(self.root, self.cal)["C2"]["level"], 1.0)

    def test_a_re_run_needs_a_reason(self):
        self.pair("C2", 1.0, 1)
        with self.assertRaisesRegex(R.PlanError, "attempt 1 was valid"):
            self.pair("C2", 1.0, 1, attempt=2)
        with self.assertRaisesRegex(R.PlanError, "the next is 2"):
            self.pair("C2", 1.0, 1, attempt=3)

    def test_the_file_is_the_one_a_campaign_takes(self):
        for cls, level in (("C2", 1.0), ("C3a", 2.0), ("C3b", 50)):
            self.pair(cls, level, 1)
            self.pair(cls, level, 2, seed=9002)
        out = os.path.join(self.tmp, "knees.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main([self.root, "--calibration", self.frozen["calibration"], "--ladder", "--out", out]), 0)
        got = REC.read_json(out)
        self.assertEqual((got["C2"], got["C3a"], got["C3b"], got["no_knee"], got["status"]), (1.0, 2.0, 50, [], "frozen"))
        self.assertEqual((got["record_sha256"], got["benign_halvings"]), (self.cal["sha256"], 0))
        block = R.plan_block("campaign", SEEDS[0], self.root, frozen={**self.frozen, "knees": out}, benign_specs=F.thin_benign(LEAN), max_sources=2)
        self.assertEqual(block["levels"], {"C2": 1.0, "C3a": 2.0, "C3b": 50})

    def test_a_class_without_a_knee_stays_out_of_the_campaign(self):
        for cls, level, share in (("C2", 1.0, 0.30), ("C3a", 2.0, 0.0), ("C3b", 50, 0.30)):
            self.pair(cls, level, 1, share=share)
            self.pair(cls, level, 2, seed=9002, share=share)
        got = A.knees_file(self.root, self.cal)
        self.assertEqual((got["C3a"], got["no_knee"]), (None, ["C3a"]))
        path = os.path.join(self.tmp, "knees.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(got, fh)
        block = R.plan_block("campaign", SEEDS[0], self.root, frozen={**self.frozen, "knees": path}, benign_specs=F.thin_benign(LEAN), max_sources=2)
        self.assertEqual((sorted(block["levels"]), block["no_knee"], block["live_classes"]), (["C2", "C3b"], ["C3a"], ["C2", "C3b"]))
        self.assertFalse([n for n in block["order"] if n.endswith("_C3a")], "D-074: no run of a class without a knee")
        self.assertIn("not in this campaign: C3a, which has no knee (D-074)", R.describe(block))
        block = R.plan_block("campaign", SEEDS[0], self.root, frozen={**self.frozen, "knees": path}, cut=True, benign_specs=F.thin_benign(LEAN), max_sources=2)
        self.assertEqual((sorted(block["levels"]), block["no_knee"]), (["C2", "C3b"], []))


class NoKneeCampaignTest(unittest.TestCase):
    """D-074: the campaign runs the classes with a knee, C2 alone if it is the only one, and the analysis judges what ran."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        rec = calibration_fixtures.frozen()
        bound = {"status": "frozen", "record_sha256": rec["sha256"]}
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"), knees={**bound, "C2": 4.0, "C3a": None, "C3b": None})
        cls.none = F.frozen_inputs(os.path.join(cls.tmp.name, "none"), knees={**bound, "C2": None, "C3a": None, "C3b": None})
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        cls.block = R.plan_block("campaign", SEEDS[0], cls.root, frozen=cls.frozen, cut=True, benign_specs=F.thin_benign(LEAN), max_sources=2)
        R.run_block(F.P1FakeHost(), cls.block)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_c2_alone_when_it_is_the_only_class_with_a_knee(self):
        self.assertEqual(sorted(self.block["order"]), ["C", "Cp", "M_gru_C2", "M_rstar_C2", "U_C2"])
        self.assertEqual((self.block["no_knee"], self.block["live_classes"]), (["C3b"], ["C2"]))
        meta = REC.read_json(os.path.join(self.block["dir"], "block.json"))
        self.assertEqual((meta["no_knee"], meta["settings"]["live_classes"]), (["C3b"], ["C2"]))

    def test_c3b_alone_when_c2_has_no_knee(self):
        rec = calibration_fixtures.frozen()
        frozen = F.frozen_inputs(os.path.join(self.tmp.name, "c3b"), knees={"status": "frozen", "record_sha256": rec["sha256"], "C2": None,
                                                                            "C3a": None, "C3b": 50, "no_knee": ["C2", "C3a"]})
        block = R.plan_block("campaign", SEEDS[1], os.path.join(self.tmp.name, "c3b_runs"), frozen=frozen, cut=True,
                             benign_specs=F.thin_benign(LEAN), max_sources=2)
        self.assertEqual(sorted(block["order"]), ["C", "Cp", "M_gru_C3b", "M_hgb_C3b", "M_rstar_C3b", "U_C3b"])
        self.assertEqual((block["no_knee"], block["levels"]), (["C2"], {"C3b": 50}))

    def test_no_class_with_a_knee_is_no_campaign(self):
        with self.assertRaisesRegex(R.PlanError, "no class of this campaign has a knee.*there is no campaign"):
            R.plan_block("campaign", SEEDS[1], os.path.join(self.tmp.name, "none_runs"), frozen=self.none, cut=True,
                         benign_specs=F.thin_benign(LEAN), max_sources=2)

    def test_the_analysis_judges_what_ran_and_names_the_rest(self):
        res = A.analyse(self.root, self.cal, self.frozen, arms_factory=factory({}), cut=True, dry_run=True)
        self.assertEqual(sorted(res), ["C2", "C3b"])
        self.assertIn("admission", res["C2"])
        self.assertEqual(res["C3b"]["verdict"], None)
        self.assertIn("not in the campaign: no knee (D-074)", res["C3b"]["status"])

    def test_a_block_that_does_not_record_its_classes_is_refused(self):
        root = os.path.join(self.tmp.name, "unsaid")
        shutil.copytree(self.root, root)
        path = os.path.join(root, "campaign", f"b{SEEDS[0]}_a1", "block.json")
        meta = REC.read_json(path)
        del meta["settings"]["live_classes"]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        with self.assertRaisesRegex(A.SettingsError, "do not record which classes they ran"):
            A.check_campaign(root, self.cal, self.frozen, cut=True)


def one_invalid(run, seed):
    """acts: `run` of block `seed` has the arm's step fail in the attack window, so that run alone is invalid."""
    def acts(name, block_dir):
        if name == run and f"b{seed}_a1" in block_dir:
            return [(100.0, {"kind": "daemon_error", "where": "l7_enforce", "error": "x", "action": "step skipped"})]
        return []
    return acts


class ReRunTest(unittest.TestCase):
    """D-058, T050-06: a re-run for one invalid run costs no class, the runner holds its limits, and an arm's bans count over all attempts."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        fail = fail_from(TABLE_A)

        def acts(name, block_dir):
            ban = [(60.0, {"kind": "ban", "engine": "l7v2", "ip": "10.9.9.9"})] if name == "M_gru_C3b" else []
            return ban + one_invalid("M_gru_C3b", SEEDS[3])(name, block_dir)

        run_campaign_any(cls.root, cls.frozen, fail, acts, cut=True)
        cls.block(SEEDS[3], 2, fail)
        cls.res = A.analyse(cls.root, cls.cal, cls.frozen, arms_factory=factory(SHARES_A), cut=True)

    @classmethod
    def block(cls, seed, attempt, fail=None, acts=None):
        block = R.plan_block("campaign", seed, cls.root, frozen=cls.frozen, cut=True, benign_specs=F.thin_benign(LEAN), max_sources=3, attempt=attempt)
        return R.run_block(F.P1FakeHost(fail_share=fail, acts=acts), block)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_reviewer_s_s2_a_re_run_for_an_m_run_keeps_every_class(self):
        for cls in ("C3b", "C2"):
            with self.subTest(cls):
                self.assertTrue(self.res[cls]["admission"]["admitted"], self.res[cls]["admission"]["reasons"])
                self.assertEqual(self.res[cls]["blocks_judged"], SEEDS)
                self.assertIsNotNone(self.res[cls]["verdict"])
        self.assertEqual(self.res["C3b"]["admission"]["reruns"], 1)

    def test_an_arm_s_bans_and_budget_count_the_superseded_attempt(self):
        self.assertEqual(self.res["C3b"]["reported"]["bans_over_attempts"]["view_gru"], {"l7v2": 10}, "10 blocks; the block re-run was clean of this fixture's ban")
        flagged, users = A.live_budget(self.root, "view_gru", "C3b")
        self.assertEqual(len(A.arm_runs(self.root, "view_gru", "C3b")), 11)
        self.assertGreater(users, 0)
        self.assertGreaterEqual(flagged, 0)

    def test_the_runner_refuses_a_re_run_without_a_reason(self):
        with self.assertRaisesRegex(R.PlanError, "allows no re-run"):
            self.block(SEEDS[0], 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "campaign", f"b{SEEDS[0]}_a2")))

    def test_the_runner_refuses_a_second_re_run_of_a_block_and_a_gap(self):
        with self.assertRaisesRegex(R.PlanError, "the next is 3"):
            self.block(SEEDS[3], 4)
        with self.assertRaisesRegex(R.PlanError, "the next is 2"):
            self.block(SEEDS[1], 3)

    def test_a_block_valid_in_itself_is_valid_all(self):
        got = LH.assess_block(os.path.join(self.root, "campaign", f"b{SEEDS[0]}_a1"), self.cal)
        self.assertTrue(got["valid_all"])
        got = LH.assess_block(os.path.join(self.root, "campaign", f"b{SEEDS[3]}_a1"), self.cal)
        self.assertFalse(got["valid_all"])


class ReRunLimitTest(unittest.TestCase):
    def test_one_per_block_and_two_per_campaign(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        frozen = F.frozen_inputs(os.path.join(tmp.name, "frozen"))
        root = os.path.join(tmp.name, "runs")

        def block(seed, attempt, invalid=False):
            plan = R.plan_block("campaign", seed, root, frozen=frozen, cut=True, benign_specs=F.thin_benign({"exporter": 1}), max_sources=1, attempt=attempt)
            acts = one_invalid("M_gru_C2", seed) if invalid else None
            acts2 = (lambda n, d: acts(n, d.replace(f"_a{attempt}", "_a1"))) if invalid else None
            R.run_block(F.P1FakeHost(acts=acts2), plan)

        for seed in SEEDS[:3]:
            block(seed, 1, invalid=True)
        block(SEEDS[0], 2, invalid=True)
        block(SEEDS[1], 2)
        with self.assertRaisesRegex(R.PlanError, "2 re-run blocks, at most 2"):
            block(SEEDS[2], 2)
        with self.assertRaisesRegex(R.PlanError, "1 re-runs already, at most 1 per block"):
            block(SEEDS[0], 3)


class TooFewJudgedBlocksTest(unittest.TestCase):
    """D-058, T050-05: the reviewer's S1, on a whole fake campaign: one invalid M run, and the GRU's gain over U of 30 pp must not read V-D."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        run_campaign_any(cls.root, cls.frozen, fail_from(TABLE_A), one_invalid("M_gru_C3b", SEEDS[3]), cut=True)
        cls.res = A.analyse(cls.root, cls.cal, cls.frozen, arms_factory=factory(SHARES_A), cut=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_class_with_the_invalid_run_has_no_verdict(self):
        r = self.res["C3b"]
        self.assertIsNone(r["verdict"])
        self.assertEqual(r["status"], "invalid (9 of 10)")
        self.assertEqual(r["blocks_judged"], [s for s in SEEDS if s != SEEDS[3]])
        self.assertTrue(any("the arm's step failed" in w for w in r["why_no_verdict"]), r["why_no_verdict"])
        self.assertNotIn("judge", r)

    def test_the_other_class_is_judged(self):
        self.assertEqual(self.res["C2"]["blocks_judged"], SEEDS)
        self.assertIsNotNone(self.res["C2"]["verdict"])
        self.assertNotIn("status", self.res["C2"])

    def test_zero_judged_blocks_do_not_raise(self):
        got = A.judged_blocks([], "C3b", ["U", "R*", "view_gru"])
        self.assertEqual(got, ([], {}))


class CampaignSettingsTest(unittest.TestCase):
    """T050-12: the analysis refuses blocks at two settings, and a record or selection other than the campaign's."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        for seed in SEEDS[:2]:
            block = R.plan_block("campaign", seed, cls.root, frozen=cls.frozen, cut=True, benign_specs=F.thin_benign(LEAN), max_sources=2)
            R.run_block(F.P1FakeHost(), block)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_one_setting_passes(self):
        A.check_campaign(self.root, self.cal, self.frozen, cut=True)

    def test_an_analysis_with_another_selection_is_refused(self):
        with self.assertRaisesRegex(A.SettingsError, "selection_sha256"):
            A.analyse(self.root, self.cal, {**self.frozen, "selection_sha256": "f" * 64}, arms_factory=factory({}), cut=True)
        with self.assertRaisesRegex(A.SettingsError, "rules_sha256"):
            A.check_campaign(self.root, self.cal, {**self.frozen, "rules_sha256": "f" * 64}, cut=True)
        with self.assertRaisesRegex(A.SettingsError, "record_digest"):
            A.check_campaign(self.root, {**self.cal, "sha256": "f" * 64}, self.frozen, cut=True)

    def command_line(self, root, *flags):
        """The analysis's command line on `root`: its exit code and what it said."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = A.main([root, "--calibration", self.frozen["calibration"], "--selection", self.frozen["selection"], "--selection-sha256",
                           self.frozen["selection_sha256"], "--rules", self.frozen["rules"], "--rules-sha256", self.frozen["rules_sha256"],
                           *flags, "--dry-run", "--out", os.path.join(self.tmp.name, "v.json")])
        return code, err.getvalue()

    def test_a_full_campaign_read_with_cut_is_refused(self):
        """T057-02: it would drop default_rules from V-A's baselines, in the GRU's favour. Blocks of the runner's own writing."""
        root = os.path.join(self.tmp.name, "full")
        block = R.plan_block("campaign", SEEDS[0], root, frozen=self.frozen, benign_specs=F.thin_benign(LEAN), max_sources=2)
        R.run_block(F.P1FakeHost(), block)
        self.assertIn("M_default_rules_C3b", block["order"])
        with self.assertRaisesRegex(A.SettingsError, "ran the full live set.*read the cut"):
            A.check_campaign(root, self.cal, self.frozen, cut=True)
        with self.assertRaisesRegex(A.SettingsError, "ran the full live set"):
            A.analyse(root, self.cal, self.frozen, arms_factory=factory({}), cut=True)
        A.check_campaign(root, self.cal, self.frozen)
        code, said = self.command_line(root, "--cut")
        self.assertEqual(code, 1)
        self.assertIn("ran the full live set", said)

    def test_a_cut_campaign_read_without_cut_is_refused(self):
        with self.assertRaisesRegex(A.SettingsError, "ran the cut.*read the full live set"):
            A.check_campaign(self.root, self.cal, self.frozen)
        code, said = self.command_line(self.root)
        self.assertEqual(code, 1)
        self.assertIn("ran the cut", said)

    def test_blocks_that_do_not_record_it_are_refused_whichever_is_asked(self):
        root = os.path.join(self.tmp.name, "unsaid")
        shutil.copytree(self.root, root)
        for seed in SEEDS[:2]:
            path = os.path.join(root, "campaign", f"b{seed}_a1", "block.json")
            meta = REC.read_json(path)
            del meta["settings"]["cut"]
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
        for cut in (True, False):
            with self.subTest(cut=cut), self.assertRaisesRegex(A.SettingsError, f"b{SEEDS[0]}_a1.*do not record whether they ran the cut"):
                A.check_campaign(root, self.cal, self.frozen, cut=cut)
        code, said = self.command_line(root, "--cut")
        self.assertEqual(code, 1)
        self.assertIn("do not record", said)

    def test_blocks_at_two_settings_are_refused_and_the_command_line_says_so(self):
        root = os.path.join(self.tmp.name, "two")
        shutil.copytree(self.root, root)
        path = os.path.join(root, "campaign", f"b{SEEDS[1]}_a1", "block.json")
        meta = REC.read_json(path)
        meta["settings"]["knees_sha256"] = "f" * 64
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        with self.assertRaisesRegex(A.SettingsError, "knees_sha256"):
            A.check_campaign(root, self.cal, self.frozen, cut=True)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = A.main([root, "--calibration", self.frozen["calibration"], "--selection", self.frozen["selection"], "--selection-sha256",
                           self.frozen["selection_sha256"], "--rules", self.frozen["rules"], "--rules-sha256", self.frozen["rules_sha256"],
                           "--cut", "--dry-run", "--out", os.path.join(self.tmp.name, "v.json")])
        self.assertEqual(code, 1)
        self.assertIn("knees_sha256", err.getvalue())


class AdmittedOnTest(unittest.TestCase):
    def test_what_admitted_a_class(self):
        self.assertEqual(A.admitted_on({"criteria": {"Q": {"passed": True}, "p95": {"passed": True}}}), "Q")
        self.assertEqual(A.admitted_on({"criteria": {"Q": {"passed": True}, "p95": {"passed": False}}}), "Q")
        self.assertEqual(A.admitted_on({"criteria": {"Q": {"passed": False}, "p95": {"passed": True}}}), "latency")


class AgeReadingTest(unittest.TestCase):
    """The age-only reading on the U replays (D-049): beside every view-level contrast, and read by nothing that judges."""

    def test_the_auc_s_sign_and_reading(self):
        young = [{"age": a, "y": 1, "family": "C2"} for a in (1.0, 2.0)] + [{"age": a, "y": 0, "family": None} for a in (10.0, 20.0, 30.0)]
        got = RP.age_auc(young)
        self.assertEqual((got["auc"], got["reading"]), (1.0, "age-confounded"))
        self.assertEqual((got["windows_benign"], got["windows_attack"], got["auc_by_family"]), (3, 2, {"C2": 1.0}))
        same = [{"age": a, "y": y, "family": "C2"} for a in (1.0, 2.0) for y in (0, 1)]
        self.assertEqual(RP.age_auc(same)["reading"], "near chance")
        self.assertEqual(RP.age_auc([{"age": 1.0, "y": 0, "family": None}])["auc"], None)

    def test_the_probe_decides_nothing_and_sees_the_arm_s_windows(self):
        rows = [(("a", "u", "s"), 1.0, 5.0, 8.0), (("b", "u", "s"), 2.0, 5.0, 5.0)]
        probe = RP._AgeProbe()
        got = probe.rows(rows)
        self.assertEqual(probe.seen, [(("a", "u", "s"), 3.0), (("b", "u", "s"), 0.0)])
        self.assertEqual(list(got), [0.0, 0.0])
        self.assertFalse((probe.p(got) > probe.threshold).any())

    def test_every_view_level_contrast_has_the_reading_beside_it(self):
        reading = {"by_family": {"C3b@M2": {"auc": 0.7}, "C3b@M1": {"auc": 0.6}}}
        judged = {"contrasts": {"detection view_gru vs hgb": {"d": 1}, "detection view_gru vs age_only (descriptive)": {"d": 2},
                                "harm hgb vs R*": {"d": 3}, "harm R* vs U": {"d": 4}},
                  "reported_separately": {"C3b@M1": {"entities": 10, "detection view_gru vs R*": {"d": 5}}}}
        got = A.view_level_contrasts(judged, reading, ["C3b@M2"])
        self.assertEqual(sorted(got), ["C3b@M1: detection view_gru vs R*", "detection view_gru vs age_only (descriptive)",
                                       "detection view_gru vs hgb", "harm hgb vs R*"])
        self.assertEqual(got["detection view_gru vs hgb"], {"contrast": {"d": 1}, "age_only_on_U": {"C3b@M2": {"auc": 0.7}}})
        self.assertEqual(got["C3b@M1: detection view_gru vs R*"]["age_only_on_U"], {"C3b@M1": {"auc": 0.6}})


class PointCheckTest(unittest.TestCase):
    """The frozen points on the pilot's benign traffic (D-052), through the replay's real accounting; only the arms' decisions are stubs."""

    LADDER = tuple((level, repeat) for level in (1.0, 2.0, 4.0, 8.0) for repeat in (1, 2))       # one (level, repeat) per seed from 9002 on

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        block = R.plan_block("health", 9001, cls.root, frozen=cls.frozen, benign_specs=F.thin_benign(LEAN))
        R.run_block(F.P1FakeHost(), block)
        cls.pair(cls.root, 9002, 9009, quiet=None)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def pair(cls, root, lo, hi, quiet):
        for seed in range(lo, hi):
            level, repeat = next((lv, r) for lv, r in cls.LADDER if R.PT.ladder_seed("C2", lv, r) == seed)
            block = R.plan_block("ladder", seed, root, frozen=cls.frozen, levels={"C2": level}, runs=["C", "U_C2"], label=f"C2_L{level:g}_r{repeat}",
                                 benign_specs=F.thin_benign(LEAN), max_sources=2)
            R.run_block(F.P1FakeHost(quiet_from=quiet), block)

    @staticmethod
    def flagging(arms):
        """arms_factory: each named arm flags that many benign addresses of the run, the others none."""
        def build(_run_dir, man):
            benign = [e["address"] for e in man["entities"] if e["role"] == "benign"]
            return {a: StubPath(set(benign[:arms.get(a, 0)])) for a in ARMS}
        return build

    def check(self, arms=None, root=None):
        return A.point_check(root or self.root, self.cal, self.frozen, 0, arms_factory=self.flagging(arms or {}))

    def test_clean_points_pass_over_every_pilot_seed(self):
        got = self.check()
        self.assertEqual(got["status"], "pass")
        self.assertEqual(([x["seed"] for x in got["per_seed"]], got["missing_seeds"], got["over_budget"]), (list(range(9001, 9009)), [], []))
        self.assertEqual(got["record_sha256"], self.cal["sha256"])
        self.assertEqual(got["selection_sha256"], self.frozen["selection_sha256"])
        units = sum(x["benign_units"] for x in got["per_seed"])
        self.assertGreater(units, 0)
        self.assertEqual(got["arms"]["R*"], {"flagged": 0, "by_kind": {}, "note": None, "units": units, "meets": True})

    def test_a_contender_over_the_budget_is_named(self):
        got = self.check({"R*": 3})
        self.assertEqual((got["status"], got["over_budget"]), ("over_budget", ["R*"]))
        self.assertFalse(got["arms"]["R*"]["meets"])
        self.assertGreater(got["arms"]["R*"]["flagged"], 0)
        self.assertTrue(got["arms"]["R*"]["by_kind"])

    def test_an_arm_that_does_not_stop_it_is_only_reported(self):
        got = self.check({"default_rules": 3, "age_only": 3, "gru_shuffled": 3})
        self.assertEqual(got["status"], "pass")
        self.assertFalse(got["arms"]["default_rules"]["meets"])

    def test_a_seed_without_a_valid_control_leaves_it_incomplete(self):
        root = os.path.join(self.tmp.name, "seven")
        block = R.plan_block("health", 9001, root, frozen=self.frozen, benign_specs=F.thin_benign(LEAN))
        R.run_block(F.P1FakeHost(), block)
        self.pair(root, 9002, 9008, quiet=None)
        self.pair(root, 9008, 9009, quiet=30)
        got = self.check(root=root)
        self.assertEqual((got["status"], got["missing_seeds"]), ("incomplete", [9008]))

    def test_a_control_at_another_factor_does_not_count(self):
        got = A.point_check(self.root, self.cal, self.frozen, 1, arms_factory=self.flagging({}))
        self.assertEqual((got["status"], len(got["missing_seeds"]), got["benign_halvings"]), ("incomplete", 8, 1))

    def test_the_command_line_writes_the_file_a_campaign_takes(self):
        out = os.path.join(self.tmp.name, "points.json")
        argv = [self.root, "--calibration", self.frozen["calibration"], "--points", "--selection", self.frozen["selection"],
                "--selection-sha256", self.frozen["selection_sha256"], "--rules", self.frozen["rules"], "--rules-sha256",
                self.frozen["rules_sha256"], "--out", out]
        with mock.patch.object(A, "default_factory", return_value=self.flagging({})), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main(argv), 0)
        block = R.plan_block("campaign", 3001, self.root, frozen={**self.frozen, "points": out}, benign_specs=F.thin_benign(LEAN), max_sources=2)
        self.assertEqual(block["frozen"]["points"]["status"], "pass")
        with mock.patch.object(A, "default_factory", return_value=self.flagging({"view_gru": 3})), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main(argv), 1)
        with self.assertRaisesRegex(R.PlanError, "view_gru"):
            R.plan_block("campaign", 3001, self.root, frozen={**self.frozen, "points": out}, benign_specs=F.thin_benign(LEAN), max_sources=2)


class HealthTest(unittest.TestCase):
    """The halving rule on fake runs: a control's real figures through eval/harm_gate.control_health, into the health file that the
    ladder and the campaign take (ml/p1_prereg.json, D-049)."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.frozen = F.frozen_inputs(os.path.join(tmp.name, "frozen"))
        self.cal = l7_backend.load_record(self.frozen["calibration"])[0]
        self.root = os.path.join(tmp.name, "runs")

    def step(self, halvings, attempt=1, **host):
        block = R.plan_block("health", 9001, self.root, frozen=self.frozen, halvings=halvings, attempt=attempt,
                             benign_specs=F.thin_benign(LEAN))
        R.run_block(F.P1FakeHost(**host), block)

    def result_file(self, code=0):
        out = os.path.join(self.tmp, "health.json")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main([self.root, "--calibration", self.frozen["calibration"], "--health", "--out", out]), code)
        return out

    @staticmethod
    def sick_until(h):
        return lambda _run, block_dir, _t: 0.05 if int(re.search(r"_h(\d)", block_dir).group(1)) < h else 0.0

    def test_a_client_side_failure_stops_the_rule_and_the_ladder_says_so(self):
        """D-058, T050-09: unhealthy on the client, with nginx's own Q at 100 %."""
        self.step(0, fail_share=self.sick_until(1), client_side=True)
        got = A.health_result(self.root, self.cal)
        self.assertEqual(got["decision"], "stopped")
        self.assertEqual(got["steps"][0]["server_q"], [100.0, 100.0])
        self.assertEqual(got["stopped_step"], got["steps"][0]["dir"])
        health = self.result_file(code=1)
        with self.assertRaisesRegex(R.PlanError, "stopped.*waits for a dated decision"):
            R.plan_block("ladder", 9001, self.root, frozen={**self.frozen, "health": health}, levels={"C2": 1.0}, runs=["C", "U_C2"],
                         benign_specs=F.thin_benign(LEAN), max_sources=2)
        out = os.path.join(self.tmp, "h2.json")
        step = got["stopped_step"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(A.main([self.root, "--calibration", self.frozen["calibration"], "--health", "--out", out,
                                     "--health-decision", f"{step}=fire:D-999, 2026-11-05: the client's limit, halve anyway"]), 0)
        self.assertEqual((REC.read_json(out)["decision"], REC.read_json(out)["next_halvings"]), ("run", 1))
        self.assertIn(step, REC.read_json(out)["decisions"])

    def test_an_undated_decision_is_refused(self):
        for text in ("d=fire:the user said so", "d=later:D-1, 2026-11-05", "d:2026-11-05"):
            with self.subTest(text), self.assertRaisesRegex(ValueError, "dated decision"):
                A.parse_health_decision(text)

    def test_the_class_floor_reads_from_20_judged_requests(self):
        """D-058, T050-10: one slow export of five decides nothing; harm_gate.control_health itself is unchanged."""
        cal = self.cal
        def m(n, ok):
            return {"Q": 99.5, "by_class": {"C5": {"n": n, "ok": ok, "Q": 100.0 * ok / n, "p95_s": 0.1}}}
        reasons, small = LH.control_health(m(5, 4), cal)
        self.assertEqual((reasons, small), ([], {"C5": {"n": 5, "ok": 4, "Q": 80.0}}))
        reasons, small = LH.control_health(m(20, 18), cal)
        self.assertEqual((len(reasons), small), (1, {}))
        self.assertTrue(HG.control_health(m(5, 4), cal), "the harm benchmark's own stays as it was")
        self.assertEqual(LH.CONTROL_CLASS_MIN_N, PT.prereg_4()["control_health"]["class_floor_from_n"])

    def test_the_file_records_each_control_s_server_q_cpu_and_slip(self):
        """T050-09's recording: a client-side firing can be told from a server-side one; the rule itself does not read them."""
        self.step(0)
        got = A.health_result(self.root, self.cal)["steps"][0]["controls"]["C"]
        self.assertEqual(got["server_q"], 100.0)
        self.assertEqual(sorted(got["cpu"]), ["attack", "legit", "server"])
        self.assertLess(got["view_slip"]["largest_s"], 2.0)

    def test_healthy_at_once(self):
        self.step(0)
        got = A.health_result(self.root, self.cal)
        self.assertEqual((got["decision"], got["benign_halvings"]), ("frozen", 0))
        self.assertEqual(got["record_sha256"], self.cal["sha256"])
        self.assertEqual(sorted(got["steps"][0]["controls"]), ["C", "Cp"])

    def test_an_unhealthy_control_halves_and_a_healthy_step_freezes_the_factor(self):
        self.step(0, fail_share=self.sick_until(1))
        got = A.health_result(self.root, self.cal)
        self.assertEqual((got["decision"], got["next_halvings"]), ("run", 1))
        self.assertIn("below 99", got["steps"][0]["controls"]["C"]["reasons"][0])
        self.step(1, fail_share=self.sick_until(1))
        got = A.health_result(self.root, self.cal)
        self.assertEqual((got["decision"], got["benign_halvings"]), ("frozen", 1))
        health = self.result_file()
        block = R.plan_block("ladder", 9001, self.root, frozen={**self.frozen, "health": health}, levels={"C2": 1.0},
                             runs=["C", "U_C2"], label="C2_L1_r1", benign_specs=F.thin_benign(LEAN), max_sources=2)
        self.assertEqual(block["halvings"], 1)

    def test_one_unhealthy_control_is_enough(self):
        self.step(0, fail_share=lambda run, _b, _t: 0.05 if run == "Cp" else 0.0)
        self.assertEqual(A.health_result(self.root, self.cal)["next_halvings"], 1)

    def test_unhealthy_at_the_floor_refuses_and_the_ladder_and_the_campaign_say_so(self):
        for h in (0, 1, 2):
            self.step(h, fail_share=self.sick_until(3))
        health = self.result_file(code=1)
        got = REC.read_json(health)
        self.assertEqual((got["decision"], got["benign_halvings"]), ("refused", None))
        frozen = {**self.frozen, "health": health}
        with self.assertRaisesRegex(R.PlanError, "does not reach health at the floor of 2 halvings"):
            R.plan_block("ladder", 9001, self.root, frozen=frozen, levels={"C2": 1.0}, runs=["C", "U_C2"],
                         benign_specs=F.thin_benign(LEAN), max_sources=2)
        with self.assertRaisesRegex(R.PlanError, "does not reach health at the floor of 2 halvings"):
            R.plan_block("campaign", 3001, self.root, frozen=frozen, benign_specs=F.thin_benign(LEAN), max_sources=2)

    def test_a_control_that_failed_its_checks_gives_no_reading(self):
        self.step(0, quiet_from=30)
        got = A.health_result(self.root, self.cal)
        self.assertFalse(got["steps"][0]["sound"])
        self.assertEqual((got["decision"], got["next_halvings"]), ("run", 0))


if __name__ == "__main__":
    unittest.main()
