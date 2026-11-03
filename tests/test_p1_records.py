"""A P1 run's records (eval/p1_records.py; docs/L7V2_DESIGN.md 5, 11): the harm figures through eval/l7v2_harm.py, the benign
users wrongly acted on, the U run's recording for the replay, and the labels from the run's manifest. Offline: blocks on the
fake host of tests/p1_fake_host.py."""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7v2_harm as LH
import l7v2_replay as RP
import p1_fake_host as F
import p1_records as REC
import p1_runner as R

import ban_events
import l7_backend
import l7_dataset as D


def share_in(names, share):
    return lambda run, _block, _t: share if run in names else 0.0


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.frozen = F.frozen_inputs(os.path.join(cls.tmp.name, "frozen"))
        cls.cal = l7_backend.load_record(cls.frozen["calibration"])[0]
        cls.root = os.path.join(cls.tmp.name, "runs")
        block = R.plan_block("smoke", 9001, cls.root, frozen=cls.frozen, levels={"C2": 1.0, "C3b": 50},
                             runs=["C", "Cp", "U_C3b", "U_C2", "M_gru_C2"], benign_specs=F.thin_benign(), max_sources=3)
        cls.block = block
        cls.results = dict(R.run_block(F.P1FakeHost(fail_share=share_in({"U_C3b", "U_C2"}, 0.3)), block))
        cls.runs = {r["name"]: r for r in block["runs"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def manifest(self, name):
        return REC.read_json(os.path.join(self.runs[name]["out"], D.MANIFEST_FILE))


class HarmTest(Base):
    def test_every_run_is_valid_and_goes_through_the_harm_module(self):
        self.assertTrue(all(r["ok"] for r in self.results.values()), self.results)
        got = LH.assess_block(self.block["dir"], self.cal)
        self.assertEqual(set(got["runs"]), set(self.runs))
        self.assertEqual(got["runs"]["C"]["metrics"]["Q"], 100.0)
        self.assertAlmostEqual(got["runs"]["U_C3b"]["metrics"]["Q"], 70.0, delta=2.0)
        c = got["classes"]["C3b"]
        self.assertTrue(c["valid"], c["reasons"])
        self.assertAlmostEqual(c["dQ"], 30.0, delta=2.0)
        self.assertEqual(sorted(got["classes"]), ["C2", "C3b"], "M runs are not U runs")

    def test_harm_admission_reads_the_block(self):
        rep = LH.admission([LH.assess_block(self.block["dir"], self.cal)], self.cal, "C3b")
        self.assertEqual(rep["verdict"], "INVALID", "one block is fewer than ten")
        self.assertTrue(any("valid blocks" in r for r in rep["reasons"]))
        self.assertFalse(any("calibration sha256" in r for r in rep["reasons"]), "block.json names the record by its digest")

    def test_a_run_record_has_the_figures_and_the_secondary_outcomes(self):
        rec = REC.run_record(self.runs["U_C2"]["out"], self.cal, 9001, 1)
        self.assertEqual((rec["run"], rec["arm"], rec["class"], rec["valid"]), ("U_C2", "U", "C2", True))
        self.assertAlmostEqual(rec["Q"], 70.0, delta=2.0)
        self.assertGreater(rec["attacker_served"], 0)
        self.assertIn("server", rec["cpu"])
        self.assertEqual(sorted(rec["cpu"]), ["attack", "legit", "server"])
        self.assertEqual(rec["addresses"]["silent"], [])
        self.assertIn("shadow", rec)
        self.assertIn("bans_by_engine", rec)
        self.assertIsNotNone(rec["attacker_served"])
        self.assertEqual(rec["addresses"]["seen"], rec["addresses"]["planned"])
        self.assertAlmostEqual(rec["server_q"], rec["Q"], delta=2.0)
        self.assertIsNone(rec["time_to_mitigate_s"], "a U run that keeps failing never recovers")
        c = REC.run_record(self.runs["C"]["out"], self.cal)
        self.assertEqual(c["attacker_served"], 0)

    def test_time_to_mitigate_is_design_11s(self):
        q = [100.0] * 30 + [50.0] * 40 + [99.0, 99.5, 100.0, 100.0, 100.0] + [100.0] * 10
        self.assertEqual(REC.time_to_mitigate(q, 30.0), 40.0)
        self.assertEqual(REC.time_to_mitigate([100.0] * 60, 30.0), 0.0)
        self.assertIsNone(REC.time_to_mitigate([50.0] * 60, 30.0))
        self.assertIsNone(REC.time_to_mitigate(None, 30.0))

    def test_every_attempt_is_summarized_valid_or_not(self):
        root = tempfile.mkdtemp(dir=self.tmp.name)
        b = R.plan_block("smoke", 9002, root, frozen=self.frozen, levels={"C2": 1.0}, runs=["C", "U_C2"],
                         benign_specs=F.thin_benign(), max_sources=2)
        R.run_block(F.P1FakeHost(root=False), b)
        out = os.path.join(root, "runs.jsonl")
        self.assertEqual(REC.main([root, out, "--calibration", self.frozen["calibration"], "--phase", "smoke"]), 0)
        with open(out, encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh]
        self.assertEqual(sorted(x["run"] for x in lines), ["C", "U_C2"])
        self.assertTrue(all(x["valid"] is False and x["Q"] is None for x in lines))


class LabelsTest(Base):
    def test_the_replay_labels_every_family_from_the_manifest(self):
        man = self.manifest("U_C3b")
        items = REC.recording(self.runs["U_C3b"]["out"])
        keys, ent, attack, units = RP.ground_truth(items, RP.RunLabels(man))
        fams = {ent[e]["family"] for e in attack}
        self.assertEqual(fams, {"C3b@M2", "C3b@M1", "C3b@M3", "C3b@M2exp"})
        self.assertEqual(len(attack), sum(1 for e in man["entities"] if e["role"] == "attack"))
        self.assertEqual(sum(units.values()), sum(REC.benign_units(man).values()))
        self.assertGreater(sum(REC.benign_units(man).values()), sum(1 for e in man["entities"] if e["role"] == "benign"),
                           "a CGNAT pool counts by its users")
        self.assertNotIn(F.MONITOR, {k[0] for k in keys["view"]}, "the monitoring identity is nobody's")
        self.assertTrue(keys["rule_cost"])

    def test_the_recording_has_ticks_at_whole_seconds_after_their_records(self):
        items = REC.recording(self.runs["U_C2"]["out"])
        ticks = [it[1] for it in items if it[0] == "poll"]
        self.assertTrue(all(t == int(t) for t in ticks))
        self.assertEqual(ticks, sorted(set(ticks)))
        self.assertGreater(len(ticks), 170)
        next_tick = None
        for it in reversed(items):
            if it[0] == "poll":
                next_tick = it[1]
            else:
                self.assertLess(float(it[1]["msec"]), next_tick)


class ActedOnTest(Base):
    def setUp(self):
        self.man = self.manifest("U_C3b")
        self.t0 = D.time_origin(self.man)
        self.by = {e["kind_or_family"]: e for e in reversed(self.man["entities"])}
        self.pool = self.by["cgnat_browsers"]
        self.browser = self.by["tpcw_browsing"]
        self.bot = self.by["C3b@M2"]

    def ev(self, kind, e, **kw):
        return {"kind": kind, "ip": e["address"], "t_wall": self.t0 + 60.0, **kw}

    def test_a_view_level_deny_costs_one_user_per_key(self):
        got = REC.acted_on(self.man, [self.ev("l7_deny", self.pool, ua_h=1, sid_h=i) for i in range(3)], "view_key")
        self.assertEqual(got["benign_users"], 3)
        self.assertEqual(got["benign_by_kind"], {"cgnat_browsers": 3})
        self.assertEqual(got["denies"], 3)
        same = REC.acted_on(self.man, [self.ev("l7_deny", self.browser, ua_h=1, sid_h=2)] * 2, "view_key")
        self.assertEqual(same["benign_users"], 1)

    def test_an_ip_ua_deny_costs_the_users_behind_it(self):
        behind = REC.RULES.plan_users(self.man)
        (ua, n) = next((k[1], v) for k, v in sorted(behind.items(), key=lambda kv: -kv[1]) if k[0] == self.pool["address"])
        self.assertGreater(n, 1)
        got = REC.acted_on(self.man, [self.ev("l7_deny", self.pool, ua_h=ua, sid_h=7)], "rule_key")
        self.assertEqual(got["benign_users"], n)

    def test_an_xdp_ban_costs_everyone_behind_the_address_whichever_engine(self):
        users = REC.benign_units(self.man)[self.pool["entity_id"]]
        for engine in (ban_events.L7V2_ENGINE, "l7_rate"):
            got = REC.acted_on(self.man, [self.ev("ban", self.pool, engine=engine)], "view_key")
            self.assertEqual((got["benign_users"], got["bans_by_engine"]), (users, {engine: 1}))

    def test_an_attack_entity_is_no_benign_cost_and_an_unknown_address_is_counted(self):
        got = REC.acted_on(self.man, [self.ev("ban", self.bot, engine="l7v2"), {"kind": "l7_deny", "ip": "10.9.9.9", "t_wall": self.t0}],
                           "view_key")
        self.assertEqual((got["benign_users"], got["attack_entities"], got["unattributed"]), (0, [self.bot["entity_id"]], 1))

    def test_an_unenforced_ban_acts_on_nobody(self):
        got = REC.acted_on(self.man, [self.ev("ban", self.browser, engine="l7_rate", enforced=False)], "view_key")
        self.assertEqual(got["benign_users"], 0)

    def test_the_budget_is_capped_at_the_entitys_units(self):
        got = REC.acted_on(self.man, [self.ev("l7_deny", self.browser, ua_h=1, sid_h=i) for i in range(4)], "view_key")
        self.assertEqual(got["benign_users"], 1)


if __name__ == "__main__":
    unittest.main()
