"""P1 traffic (ml/p1_traffic.py; docs/L7V2_DESIGN.md 5.3, 6, 7, 14): one block's population as data, on the frozen
benign mix and class table, under its own stream. Offline and pure."""
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "bench"), os.path.join(REPO, "tests")):
    sys.path.insert(0, _p)
import calibration as CAL
import calibration_fixtures
import l7_bots
import l7_pools as LP
import l7v2_prereg
import l7v2_verdict_prereg as VP
import p1_traffic as P
import p3_prereg

import l7_backend

FROZEN = calibration_fixtures.frozen()
KNEES = {"status": "frozen", "record_sha256": FROZEN["sha256"], "C2": 4.0, "C3a": 1.0, "C3b": 100}
_TMP = tempfile.TemporaryDirectory()
RECORD = os.path.join(_TMP.name, "frozen.json")
with open(RECORD, "w", encoding="utf-8") as _fh:
    json.dump(FROZEN, _fh)
LEVELS = {"C2": 4.0, "C3a": 1.0, "C3b": 100}
_BLOCKS = {}


def block(seed=3001):
    if seed not in _BLOCKS:
        _BLOCKS[seed] = P.build_block(seed, "eval", LEVELS, record_path=RECORD, knees=KNEES)
    return _BLOCKS[seed]


class BlockTest(unittest.TestCase):
    def test_the_frozen_constants(self):
        self.assertEqual(P.TIMELINE, {"baseline_s": 30, "attack_s": 120, "recovery_s": 30})
        self.assertEqual(P.run_seconds(), 180)
        self.assertEqual(sorted(P.PRIMARY), sorted(VP.load()["classes"]))
        self.assertEqual(P.PRIMARY["C3b"], VP.load()["detection_entities"]["per_class"]["C3b"]["primary"][0])
        self.assertEqual(set(P.SIDE_FAMILIES["C3b"]),
                         set(VP.load()["detection_entities"]["per_class"]["C3b"]["reported_separately"]))
        self.assertTrue(set(P.FAMILY_ORDER) <= set(l7_bots.FAMILIES))
        self.assertEqual(P.ladder_levels("C2"), [1, 2, 4, 8])
        self.assertEqual(P.ladder_levels("C3b"), [50, 100, 200, 300])

    def test_seeds_are_the_pre_registered_ones(self):
        seeds = p3_prereg.load()["seeds"]
        self.assertEqual(block()["seed"], seeds["p1_live_eval"][0])
        for seed, role in ((1001, "eval"), (3201, "eval"), (3001, "pilot"), (3001, "train")):
            with self.subTest(seed=seed, role=role), self.assertRaises(P.PlanError):
                P.build_block(seed, role, LEVELS, record_path=RECORD, knees=KNEES)

    def test_the_benign_mix_is_the_frozen_one_with_its_held_out_kinds(self):
        kinds = {}
        for e in block()["benign"]:
            kinds[e["kind_or_family"]] = kinds.get(e["kind_or_family"], 0) + 1
        want = {}
        for s in LP.POPULATIONS["l7v2"]["benign"]:
            want[s["kind"]] = want.get(s["kind"], 0) + s["count"]
        got = {k: v for k, v in kinds.items()}
        for name, n in want.items():
            self.assertLessEqual(got.get(name, 0), n, name)
        self.assertGreaterEqual(sum(e["params"].get("users", 1) for e in block()["benign"]), 120)
        self.assertEqual(got["flash_crowd"], 30)
        self.assertTrue(all(e["held_out"] for e in block()["benign"] if e["kind_or_family"] == "flash_crowd"))

    def test_c2_rate_follows_its_rule(self):
        rec = l7_backend.load_record(RECORD)[0]
        rows = block()["attack"]["C2"]
        self.assertEqual(len(rows), l7v2_prereg.load()["classes"]["C2"]["sources_p1"])
        want = 4.0 * CAL.spare_capacity(rec) / (100 * rec["route_costs_ms"]["C3"] / 1000.0)
        for e in rows:
            self.assertAlmostEqual(e["params"]["rps"], want, places=3)

    def test_c3a_sources_follow_their_rule_and_refuse_out_of_bounds(self):
        rec = l7_backend.load_record(RECORD)[0]
        s, c = CAL.spare_capacity(rec), rec["route_costs_ms"]
        import math
        want = math.ceil(1.0 * s / ((c["C1"] + c["C3"]) / 1000.0 / 5.0))
        self.assertEqual(block()["sources"]["C3a"], want)
        self.assertEqual(len(block()["attack"]["C3a"]), want)
        with self.assertRaisesRegex(P.PlanError, "not reachable"):
            P.build_block(9001, "pilot", {"C3a": 8}, record_path=RECORD, knees=None)

    def test_c3b_runs_m2_at_the_level_and_a_fixed_side(self):
        rows = block()["attack"]["C3b"]
        fam = {}
        for e in rows:
            fam[e["kind_or_family"]] = fam.get(e["kind_or_family"], 0) + 1
        self.assertEqual(fam, {"C3b@M2": 100, "C3b@M1": 10, "C3b@M3": 10, "C3b@M2exp": 10})
        for e in rows:
            self.assertEqual(e["params"]["route"], "C5")
            self.assertEqual(e["held_out"], e["kind_or_family"] in ("C3b@M3", "C3b@M2exp"))
            self.assertEqual(e["params"]["mimicry"], e["kind_or_family"].split("@")[1])

    def test_every_family_has_a_plan_with_its_entity_labels(self):
        rows = block()["attack"]
        for cls, ents in rows.items():
            for e in ents[:3] + ents[-3:]:
                self.assertIsNotNone(LP._plan_of(e), e["kind_or_family"])
                self.assertEqual(e["schedule"]["phase"], cls)

    def test_a_family_keeps_its_addresses_whatever_the_levels(self):
        low = P.build_block(9001, "pilot", {"C3b": 50, "C2": 1}, record_path=RECORD)
        high = P.build_block(9001, "pilot", {"C3b": 100, "C2": 8}, record_path=RECORD)
        lo = {e["index"]: e["address"] for e in low["attack"]["C3b"]}
        hi = {e["index"]: e["address"] for e in high["attack"]["C3b"]}
        self.assertTrue(all(hi[i] == a for i, a in lo.items()))
        self.assertEqual([e["address"] for e in low["benign"]], [e["address"] for e in high["benign"]])
        self.assertEqual([e["address"] for e in low["attack"]["C2"]], [e["address"] for e in high["attack"]["C2"]])

    def test_addresses_are_a_seeded_permutation_of_the_pool(self):
        a, b = block(3001), block(3002)
        addr = [e["address"] for e in a["benign"]] + [e["address"] for r in a["attack"].values() for e in r]
        self.assertEqual(len(addr), len(set(addr)))
        self.assertTrue(all(x.startswith("10.0.") and LP.ipaddress.ip_address(x) in LP.POOL_NET for x in addr))
        self.assertNotEqual([e["address"] for e in a["benign"]], [e["address"] for e in b["benign"]])

    def test_netem_is_balanced_for_attackers_too(self):
        for cls, rows in block()["attack"].items():
            m2 = [e for e in rows if e["kind_or_family"] == P.PRIMARY[cls]]
            counts = {}
            for e in m2:
                counts[e["netem"]] = counts.get(e["netem"], 0) + 1
            self.assertEqual(set(counts), set(LP.NETEM_PROFILES), cls)
            self.assertLessEqual(max(counts.values()) - min(counts.values()), 1, cls)

    def test_schedules_follow_the_arrivals_on_one_slot(self):
        lo, hi = P.attack_window()
        rule = l7v2_prereg.load()["arrivals"]
        for rows in block()["attack"].values():
            for e in rows:
                s = e["schedule"]
                self.assertTrue(lo <= s["start_s"] <= hi - rule["min_active_s"])
                self.assertTrue(s["start_s"] < s["stop_s"] <= hi, "the recovery is attack-free")
        for e in block()["benign"]:
            s = e["schedule"]
            self.assertTrue(0.0 <= s["start_s"] <= hi - rule["min_active_s"], e["kind_or_family"])
            self.assertLessEqual(s["stop_s"], P.run_seconds())
            if e["kind_or_family"] in ("tpcw_browsing", "search_user"):
                self.assertTrue(e["params"]["sessions"])
                self.assertEqual(s["stop_s"], P.run_seconds())

    def test_an_evaluation_block_runs_at_the_frozen_knees_on_a_frozen_record(self):
        with self.assertRaisesRegex(P.PlanError, "frozen knees"):
            P.build_block(3001, "eval", {**LEVELS, "C2": 8.0}, record_path=RECORD, knees=KNEES)
        with self.assertRaises(P.PlanError):
            P.build_block(3001, "eval", LEVELS, record_path=None, knees=KNEES)
        with self.assertRaises(P.PlanError):
            P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees={**KNEES, "record_sha256": "0" * 64})
        with self.assertRaises(P.PlanError):
            P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees=None)

    def test_a_run_holds_the_benign_entities_and_its_class(self):
        b = block()
        c = P.run_entities(b)
        self.assertEqual(len(c), len(b["benign"]))
        u = P.run_entities(b, "C3b")
        self.assertEqual(len(u), len(b["benign"]) + 130)
        self.assertLessEqual(len(u), 300)
        with self.assertRaises(P.PlanError):
            P.run_entities(b, "C4")

    def test_a_level_over_the_address_limit_is_refused_per_run(self):
        b = P.build_block(9001, "pilot", {"C3b": 200}, record_path=RECORD)
        with self.assertRaisesRegex(P.PlanError, "verified limit"):
            P.run_entities(b, "C3b")

    def test_a_thin_plan_for_tests_keeps_the_rates(self):
        thin = P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees=KNEES, max_sources=2,
                             benign_specs=[dict(s, count=1) for s in LP.POPULATIONS["l7v2"]["benign"][:1]])
        self.assertEqual(len(thin["attack"]["C2"]), 2)
        self.assertEqual(thin["attack"]["C2"][0]["params"]["rps"], block()["attack"]["C2"][0]["params"]["rps"])

    def test_the_age_check_is_recorded_per_class(self):
        rep = P.age_report(block())
        self.assertEqual(sorted(rep), ["C2", "C3a", "C3b"])
        self.assertTrue(all("ks" in r and "auc" in r and "pass" in r for r in rep.values()))


if __name__ == "__main__":
    unittest.main()
