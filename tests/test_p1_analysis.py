"""The P1 analysis (eval/p1_analysis.py; docs/L7V2_DESIGN.md 5.3, 10, 11): fake campaigns of eval/p1_runner.py on the fake host,
through eval/l7v2_harm.py, the replay and ml/l7v2_verdict.py, to one verdict per class. Each verdict is reached end to end on
fake outputs: only the arms' decisions in the replay are stubs, behind the engine's real path. Offline."""
import json
import os
import re
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
import l7v2_replay as RP
import l7v2_verdict_prereg as VP
import p1_analysis as A
import p1_fake_host as F
import p1_records as REC
import p1_runner as R

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


def deny_first_benign(names):
    """acts: in the named runs the daemon denies one view-level key of the run's first benign entity."""
    def acts(run, block_dir):
        if run not in names:
            return []
        plan = REC.read_json(os.path.join(block_dir, run, "plan.json"))
        ip = next(e["address"] for e in plan["entities"] if e["role"] == "benign")
        return [(1.0, {"kind": "l7_deny", "level": 1, "ip": ip, "ua_h": 1, "sid_h": 2})]
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
            for rep, seed in ((1, 9001), (2, 9002)):
                block = R.plan_block("ladder", seed, root, frozen=frozen, levels={"C2": level}, runs=["C", "U_C2"],
                                     label=f"C2_L{level:g}_r{rep}", benign_specs=F.thin_benign(LEAN), max_sources=2)
                R.run_block(F.P1FakeHost(fail_share=lambda run, _b, _t, s=share: s if run == "U_C2" else 0.0), block)
        got = A.ladder_knees(root, cal)
        self.assertEqual(got["C2"]["level"], 2.0)
        self.assertEqual(got["C2"]["passing"], [2.0])
        out = os.path.join(tmp.name, "knees.json")
        self.assertEqual(A.main([root, "--calibration", frozen["calibration"], "--ladder", "--out", out]), 0)
        self.assertEqual(REC.read_json(out)["record_sha256"], calibration_fixtures.frozen()["sha256"])
        self.assertEqual(json.loads(json.dumps(REC.read_json(out)["knees"]["C2"]))["level"], 2.0)


if __name__ == "__main__":
    unittest.main()
