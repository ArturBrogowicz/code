"""The P1 analysis (eval/p1_analysis.py; docs/L7V2_DESIGN.md 5.3, 10, 11): fake campaigns of eval/p1_runner.py on the fake host,
through eval/l7v2_harm.py, the replay and ml/l7v2_verdict.py, to one verdict per class. Each verdict is reached end to end on
fake outputs: only the arms' decisions in the replay are stubs, behind the engine's real path. Offline."""
import contextlib
import io
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
            block = R.plan_block("ladder", 9001, root, frozen=inputs, levels={"C2": 1.0}, runs=["C", "U_C2"],
                                 label=f"C2_L1_r{rep}", benign_specs=F.thin_benign(LEAN), max_sources=2)
            R.run_block(F.P1FakeHost(), block)
        with self.assertRaisesRegex(ValueError, "one factor"):
            A.ladder_factor(root)


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
