"""P1 traffic (ml/p1_traffic.py; docs/L7V2_DESIGN.md 5.3, 6, 7, 14): one block's population as data, on the frozen
benign mix and class table, under its own stream. Offline and pure."""
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

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
PINNED_ROWS_SHA256 = "4395b2a7bdafbe4e06f5323368a6ac447bacab1da87ac8e1a4338fa9bce4cd92"         # the rows of seed 9001's C2 1 and C3b 50 block as planned before D-073's extension
_BLOCKS = {}


def block(seed=3001):
    if seed not in _BLOCKS:
        _BLOCKS[seed] = P.build_block(seed, "eval", LEVELS, record_path=RECORD, knees=KNEES)
    return _BLOCKS[seed]


class BlockTest(unittest.TestCase):
    def test_the_frozen_constants(self):
        self.assertEqual(P.TIMELINE, {"baseline_s": 30, "attack_s": 210, "recovery_s": 30})
        self.assertEqual({k: P.prereg_2()["timeline"][k] for k in P.TIMELINE}, P.TIMELINE)
        self.assertEqual(P.run_seconds(), 270)
        self.assertEqual(P.level_window(), (120.0, 240.0))
        self.assertEqual(P.late_window(), (210.0, 240.0))
        self.assertEqual(P.level_window({"baseline_s": 10, "attack_s": 100, "recovery_s": 0}), (100.0, 110.0))
        self.assertEqual(sorted(P.PRIMARY), sorted(VP.load()["classes"]))
        self.assertEqual(P.PRIMARY["C3b"], VP.load()["detection_entities"]["per_class"]["C3b"]["primary"][0])
        self.assertEqual(set(P.SIDE_FAMILIES["C3b"]),
                         set(VP.load()["detection_entities"]["per_class"]["C3b"]["reported_separately"]))
        self.assertTrue(set(P.FAMILY_ORDER) <= set(l7_bots.FAMILIES))
        self.assertEqual(P.ladder_levels("C2"), [1, 2, 4, 8, 16])
        self.assertEqual(P.ladder_levels("C3a"), [2, 4, 6, 8])
        self.assertEqual(P.ladder_levels("C3b"), [50, 100, 150, 200, 300])

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
        with self.assertRaisesRegex(P.PlanError, "have C2 = None"):
            P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees={**KNEES, "C2": None})
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


class LadderExtensionTest(unittest.TestCase):
    """D-073 (ml/p1_prereg_5.json): the per-class ladder, its seed map, C3a past 100 sources and P1's own address limit."""
    FROZEN_RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")

    def test_the_seed_map_never_puts_a_level_s_repeats_on_one_seed(self):
        self.assertEqual([P.ladder_seed("C2", lv, r) for lv in (1, 2, 16) for r in (1, 2)], [9001, 9002, 9003, 9004, 9001, 9002])
        self.assertEqual(P.ladder_seed("C3a", 8, 2), 9008)
        for cls in ("C2", "C3a", "C3b"):
            for lv in P.ladder_levels(cls):
                self.assertNotEqual(P.ladder_seed(cls, lv, 1), P.ladder_seed(cls, lv, 2))
                self.assertTrue(all(9001 <= P.ladder_seed(cls, lv, r) <= 9008 for r in (1, 2)))
        with self.assertRaisesRegex(P.PlanError, "not one of its pre-registered levels"):
            P.ladder_seed("C2", 3, 1)

    def test_c3a_carries_level_8_and_its_lower_levels_keep_their_sources(self):
        """On the frozen record C3a needs 316 sources at level 8; level 2's 79 are the first of them, unchanged."""
        low = P.build_block(9001, "pilot", {"C3a": 2}, record_path=self.FROZEN_RECORD)
        top = P.build_block(9001, "pilot", {"C3a": 8}, record_path=self.FROZEN_RECORD)
        self.assertEqual((low["sources"]["C3a"], top["sources"]["C3a"]), (79, 316))
        key = ("index", "subseed", "address", "params", "schedule", "netem")
        self.assertEqual([{k: e[k] for k in key if k != "netem"} for e in low["attack"]["C3a"]],
                         [{k: e[k] for k in key if k != "netem"} for e in top["attack"]["C3a"][:79]])
        self.assertEqual(len({e["address"] for e in top["attack"]["C3a"]}), 316)
        with self.assertRaisesRegex(P.Unreachable, r"outside \[50, 320\]: not reachable"):
            P.build_block(9001, "pilot", {"C3a": 9}, record_path=self.FROZEN_RECORD)

    def test_the_address_limit_is_p1_s_own_once_the_read_is_decided(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "limit.json")
        b = P.build_block(9001, "pilot", {"C3b": 200}, record_path=RECORD)
        with self.assertRaisesRegex(P.Unreachable, "368 addresses exceed the verified limit of 300.*not reachable on this testbed"):
            P.run_entities(b, "C3b")
        for limit, decision, ok in ((400, "D-099, 2026-11-20, the smoke's read", True), (469, "D-099, 2026-11-20", False),
                                    (400, "the read passed", False), (True, "D-099, 2026-11-20", False)):
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"limit": limit, "decision": decision}, fh)
            with self.subTest(limit=limit, decision=decision), mock.patch.object(P, "ADDRESS_LIMIT_FILE", path):
                if ok:
                    self.assertEqual(P.address_limit(), 400)
                    self.assertEqual(len(P.run_entities(P.build_block(9001, "pilot", {"C3b": 200}, record_path=RECORD), "C3b")), 368)
                else:
                    with self.assertRaises(P.PlanError):
                        P.address_limit()

    def test_no_entity_of_today_moves(self):
        """A guard: the appended range moves no benign or C3b entity of a block planned before it (sha256 of index, sub-seed and address)."""
        b = P.build_block(9001, "pilot", {"C3b": 50, "C2": 1}, record_path=RECORD)
        rows = [(e["index"], e["subseed"], e["address"]) for e in b["benign"] + b["attack"]["C3b"] + b["attack"]["C2"]]
        self.assertEqual(hashlib.sha256(json.dumps(rows).encode()).hexdigest(), PINNED_ROWS_SHA256)


class ArrivalsAt210Test(unittest.TestCase):
    """D-053's slot: the frozen arrival rules on 30 + 210 + 30 s, flash_gap_s now kept."""

    def test_arrivals_and_stops(self):
        for seed in (3001, 3002):
            b = block(seed)
            for e in b["benign"]:
                if e["kind_or_family"] not in ("cgnat_browsers",):
                    self.assertLessEqual(e["schedule"]["start_s"], 180.0)
                self.assertLessEqual(e["schedule"]["stop_s"], 270.0)
            for rows in b["attack"].values():
                for e in rows:
                    self.assertTrue(30.0 <= e["schedule"]["start_s"] <= 180.0, e["schedule"])
                    self.assertLessEqual(e["schedule"]["stop_s"], 240.0)
                    self.assertGreaterEqual(e["schedule"]["stop_s"] - e["schedule"]["start_s"], 60.0)

    def test_the_flash_gap_is_kept(self):
        for seed in p3_prereg.load()["seeds"]["p1_live_eval"][:4]:
            flash = P.build_block(seed, "eval", LEVELS, record_path=RECORD, knees=KNEES)["flash"]
            self.assertTrue(flash["gap_kept"])
            self.assertTrue(90.0 <= flash["start_s"] <= 120.0, flash)


class BenignLoadTest(unittest.TestCase):
    """The plan's benign rate against the record's rho, on the path a campaign uses (D-049's check): a frozen record, build_block."""

    def test_the_arithmetic_on_a_counted_plan(self):
        one = dict(LP.POPULATIONS["l7v2"]["benign"][0], count=1)
        plan = P.build_block(9001, "pilot", {}, record_path=RECORD, benign_specs=[one])
        got = P.benign_load(plan, FROZEN)
        e = plan["benign"][0]
        reqs = [(t, p) for u in LP._plan_of(e)["users"] for t, p in LP.nominal_requests(u)
                if 30.0 <= e["schedule"]["start_s"] + t < 240.0]
        self.assertGreater(len(reqs), 0)
        self.assertEqual(got["req_s"], round(len(reqs) / 210.0, 1))
        self.assertEqual(set(got["by_kind"]), {one["kind"]})

    def test_the_frozen_record_s_rho_and_the_full_mix(self):
        got = P.benign_load(P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees=KNEES), FROZEN)
        self.assertEqual(got["rho_req_s"], CAL.rho_rps(FROZEN))
        self.assertEqual(got["rho_req_s"], 90.0)
        self.assertEqual((got["c_slo_req_s"], got["c_slo_cpu_s_s"]), (180.0, round(180.0 * CAL.mean_cost_ms(FROZEN) / 1000.0, 3)))
        self.assertGreater(got["peak_20s_req_s"], got["req_s"])
        self.assertGreater(got["level_req_s"], got["req_s"], "benign arrivals run to 180 s, so the level window carries the most")
        self.assertEqual(got["spare_cpu_s"], round(CAL.spare_capacity(FROZEN), 3))
        self.assertGreater(got["req_s"], got["rho_req_s"], "more requests than rho, the fixture's numbers")
        self.assertLess(got["cpu_s_s"], got["rho_cpu_s_s"], "and less CPU: the mix is cheaper than the record's")
        self.assertEqual(got["without_a_plan"], ["api_poll", "curl_oneshot", "downloader", "http2", "keepalive", "nat_gateway",
                                                 "uploader"])

    def test_the_mix_does_not_read_the_record(self):
        cal = calibration_fixtures.placeholder()
        cal["capacity"].update(c_slo_rps=360.0, c_sat_rps=520.0)
        other = calibration_fixtures.frozen(cal)
        a = P.build_block(9001, "pilot", {}, record_path=RECORD)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "other.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(other, fh)
            b = P.build_block(9001, "pilot", {}, record_path=path)
        self.assertEqual(a["benign"], b["benign"])
        self.assertEqual(P.benign_load(a, other)["req_s"], P.benign_load(a, FROZEN)["req_s"])
        self.assertEqual(P.benign_load(a, other)["rho_req_s"], 180.0)

    def test_a_halving_lowers_it(self):
        full = P.benign_load(P.build_block(9001, "pilot", {}, record_path=RECORD), FROZEN)
        half = P.benign_load(P.build_block(9001, "pilot", {}, record_path=RECORD, halvings=1), FROZEN)
        self.assertLess(half["req_s"], full["req_s"])
        self.assertLess(half["cpu_s_s"], full["cpu_s_s"])


class HalvingTest(unittest.TestCase):
    """The halving rule of ml/p1_prereg.json (D-049), as ml/p4_traffic.py's."""

    @classmethod
    def setUpClass(cls):
        cls.plans = {h: P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees=KNEES, halvings=h) for h in (0, 1, 2)}

    def test_kept_entities(self):
        self.assertEqual([P.kept_entities(52, h) for h in range(3)], [52, 26, 13])
        self.assertEqual([P.kept_entities(5, h) for h in range(4)], [5, 2, 1, 1])
        self.assertEqual([P.kept_entities(1, h) for h in range(4)], [1, 1, 1, 1])

    def test_a_halved_plan_is_the_full_plan_without_the_dropped_entities(self):
        full = {e["entity_id"]: e for e in self.plans[0]["benign"]}
        for h in (1, 2):
            rows = self.plans[h]["benign"]
            self.assertLess(len(rows), len(full))
            for e in rows:
                self.assertEqual(e, full[e["entity_id"]])
            self.assertEqual(self.plans[h]["attack"], self.plans[0]["attack"])
            self.assertEqual(self.plans[h]["pool"], self.plans[0]["pool"])
            self.assertEqual(self.plans[h]["flash"], self.plans[0]["flash"])

    def test_the_dropped_are_the_last_of_each_kind(self):
        full, half = self.plans[0]["benign"], self.plans[1]["benign"]
        for kind in {e["kind_or_family"] for e in full}:
            all_idx = [e["index"] for e in full if e["kind_or_family"] == kind]
            kept = [e["index"] for e in half if e["kind_or_family"] == kind]
            self.assertEqual(kept, all_idx[:len(kept)], kind)

    def test_cgnat_pools_and_single_entities_are_never_removed(self):
        multi = {s["kind"] for s in LP.POPULATIONS["l7v2"]["benign"] if s["count"] > 1}
        full = sorted(e["entity_id"] for e in self.plans[0]["benign"] if e["kind_or_family"] not in multi)
        self.assertEqual(sum(e["kind_or_family"] == "cgnat_browsers" for e in self.plans[0]["benign"]), 2)
        for h in (1, 2):
            self.assertEqual(sorted(e["entity_id"] for e in self.plans[h]["benign"] if e["kind_or_family"] not in multi), full)

    def test_the_record_s_counts_and_its_disclosed_shares(self):
        floor = P.prereg()["halving"]["floor"]
        kinds = {}
        for e in self.plans[2]["benign"]:
            kinds[e["kind_or_family"]] = kinds.get(e["kind_or_family"], 0) + 1
        self.assertEqual({k: kinds.get(k, 0) for k in floor["counts_at_the_floor"]}, floor["counts_at_the_floor"])
        def users(rows):
            return sum(len(e.get("users", [0])) for e in rows)

        shares = []
        for h in (0, 1, 2):
            rows = self.plans[h]["benign"]
            shares.append(users([e for e in rows if e["kind_or_family"] == "cgnat_browsers"]) / users(rows))
            self.assertEqual(len({e["address"] for e in rows}), floor["addresses_by_halvings"][h] - len(self.plans[h]["dropped"]))
        self.assertEqual([round(s, 1) for s in shares], [0.2, 0.3, 0.4])
        self.assertLess(shares[2], 0.5)
        self.assertEqual(self.plans[1]["halvings"], 1)

    def test_past_the_floor_there_is_no_plan(self):
        for bad in (3, -1, True, 1.0, "1"):
            with self.subTest(bad=bad), self.assertRaisesRegex(P.PlanError, "rule's floor"):
                P.build_block(3001, "eval", LEVELS, record_path=RECORD, knees=KNEES, halvings=bad)

    def test_halve_judges_two_controls(self):
        self.assertFalse(P.halve([[], []]))
        self.assertTrue(P.halve([["Q(C) is 98.00 %"], []]))
        self.assertTrue(P.halve([[], ["class C3"]]))
        with self.assertRaisesRegex(P.PlanError, "two pilot controls"):
            P.halve([[]])

    @staticmethod
    def step(h, *reasons, sound=True):
        return {"halvings": h, "sound": sound, "reasons": list(reasons) if reasons else [[], []]}

    def test_the_rule_stops_at_the_first_healthy_step(self):
        sick = (["Q(C) is 98.00 %"], [])
        self.assertEqual(P.next_step([])["next_halvings"], 0)
        got = P.next_step([self.step(0)])
        self.assertEqual((got["decision"], got["benign_halvings"]), ("frozen", 0))
        got = P.next_step([self.step(0, *sick)])
        self.assertEqual((got["decision"], got["next_halvings"]), ("run", 1))
        got = P.next_step([self.step(0, *sick), self.step(1)])
        self.assertEqual((got["decision"], got["benign_halvings"]), ("frozen", 1))
        got = P.next_step([self.step(0, *sick), self.step(1, *sick), self.step(2)])
        self.assertEqual((got["decision"], got["benign_halvings"]), ("frozen", 2))

    def test_the_rule_refuses_at_the_floor_and_says_so(self):
        sick = (["Q(C) is 98.00 %"], [])
        got = P.next_step([self.step(0, *sick), self.step(1, *sick), self.step(2, *sick)])
        self.assertEqual((got["decision"], got["benign_halvings"]), ("refused", None))
        self.assertIn("does not reach health at the floor of 2 halvings", got["why"])
        self.assertIn("Q(C) is 98.00 %", got["why"])

    def test_a_client_side_limit_stops_the_rule_for_a_dated_decision(self):
        """D-058, T050-09."""
        sick = {"dir": "health/h0", "halvings": 0, "sound": True, "reasons": [["Q(C) is 98.00 %"], []], "server_q": [99.5, 100.0]}
        got = P.next_step([sick])
        self.assertEqual((got["decision"], got["benign_halvings"], got["stopped_step"]), ("stopped", None, "health/h0"))
        self.assertIn("server-side Q of 99.50 %", got["why"])
        fire = P.next_step([sick], {"health/h0": {"action": "fire", "text": "D-1, 2026-11-05"}})
        self.assertEqual((fire["decision"], fire["next_halvings"]), ("run", 1))
        repeat = P.next_step([sick], {"health/h0": {"action": "repeat", "text": "D-1, 2026-11-05"}})
        self.assertEqual((repeat["decision"], repeat["next_halvings"]), ("run", 0))
        self.assertEqual(P.next_step([sick, self.step(0)], {"health/h0": {"action": "repeat", "text": "x"}})["benign_halvings"], 0)

    def test_a_server_side_limit_fires_the_rule_as_before(self):
        sick = {"dir": "d", "halvings": 0, "sound": True, "reasons": [["Q(C) is 90.00 %"], []], "server_q": [90.0, 100.0]}
        self.assertEqual(P.next_step([sick])["next_halvings"], 1)
        self.assertEqual(P.prereg_4()["halving"]["server_q_min"], 99.0)
        healthy_side = {"dir": "d", "halvings": 0, "sound": True, "reasons": [["Q(C) is 90.00 %"], []], "server_q": [90.0, 99.9]}
        self.assertEqual(P.next_step([healthy_side])["next_halvings"], 1, "the unhealthy control's own server-side Q decides")

    def test_no_step_runs_out_of_order_or_after_the_stop(self):
        sick = (["class C3"], [])
        for steps in ([self.step(1)], [self.step(0, *sick), self.step(2)], [self.step(0), self.step(0)],
                      [self.step(0), self.step(1)]):
            with self.subTest(steps=steps):
                self.assertEqual(P.next_step(steps)["decision"], "refused")

    def test_an_unsound_control_fires_nothing_and_is_re_run_within_a_limit(self):
        unsound = self.step(0, sound=False)
        got = P.next_step([unsound])
        self.assertEqual((got["decision"], got["next_halvings"]), ("run", 0))
        self.assertEqual(P.next_step([unsound, unsound, self.step(0)])["benign_halvings"], 0)
        got = P.next_step([unsound, unsound, unsound])
        self.assertEqual(got["decision"], "refused")
        self.assertIn("no reading", got["why"])


if __name__ == "__main__":
    unittest.main()
