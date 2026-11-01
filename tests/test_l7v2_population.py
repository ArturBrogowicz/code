"""The L7 v2 population of the P3 capture plans (ml/l7_pools.py POPULATIONS["l7v2"]; docs/L7V2_DESIGN.md §6, §7.2,
§7.3; docs/P3_DATASET_DESIGN.md §5). Offline and pure; the admissibility gate is simulated over two seeds."""
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    sys.path.insert(0, _p)
import calibration as CAL
import l7_benign
import l7_pools as LP
import p3_prereg

import l7_backend
import l7_dataset as D

FROZEN_KNEES = {"status": "frozen", "C2": 4.0}
GATE = (0, 1)


def plan(seed, role, knees=FROZEN_KNEES, **kw):
    return LP.build_plan("2026-11-v1", seed, role, "l7v2", knees=knees, gate_seeds=GATE, check_role=False, **kw)


_PLANS = {}


class Cache:
    @staticmethod
    def get(seed, role):
        if (seed, role) not in _PLANS:
            _PLANS[(seed, role)] = plan(seed, role)
        return _PLANS[(seed, role)]


class TrainingPlanTest(unittest.TestCase):
    def test_the_core_phases_and_no_held_out_entity(self):
        p = Cache.get(1001, "train")
        self.assertEqual(p["duration_s"], 900.0)
        self.assertEqual(sorted(ph["name"] for ph in p["timeline"]["phases"]), ["C2", "C3a", "C3b"])
        self.assertFalse([e for e in p["entities"] if e["held_out"]])
        self.assertEqual(p["schema"], 3, "the CGNAT pools' users are entities")
        pools = [e for e in p["entities"] if e["params"].get("users", 1) > 1]
        self.assertTrue(pools and all(e["users"] == [f"{e['entity_id']}/u{k}" for k in range(e["params"]["users"])]
                                      for e in pools))
        self.assertEqual(p["server"]["backend"], "costed")
        counts = {}
        for e in p["entities"]:
            counts[e["kind_or_family"]] = counts.get(e["kind_or_family"], 0) + 1
        self.assertEqual({k: counts[k] for k in ("C2", "C3a", "C3b@M2", "C3b@M1")},
                         {"C2": 50, "C3a": 50, "C3b@M2": 50, "C3b@M1": 10})
        vol = p3_prereg.load()["volume"]
        self.assertGreaterEqual(min(counts[k] for k in ("C2", "C3a", "C3b@M2")), vol["attack_entities_per_core_family_min"])
        self.assertEqual(counts["C3b@M1"], vol["c3b_m1_entities"])

    def test_benign_users_and_addresses(self):
        p = Cache.get(1001, "train")
        benign = [e for e in p["entities"] if e["role"] == "benign"]
        users = sum(e["params"].get("users", 1) for e in benign)
        cgnat = [e["params"]["users"] for e in benign if e["kind_or_family"] == "cgnat_browsers"]
        self.assertEqual(sorted(cgnat), [12, 24])
        self.assertEqual(len(benign), 87)
        self.assertTrue(124 <= users <= 130, users)   # 120 + the nat_gateway's 4-10 users
        self.assertGreaterEqual(users, p3_prereg.load()["volume"]["benign_users_min"], "P3's re-registered 120 users")

    def test_training_needs_frozen_knees(self):
        for knees in (None, {"status": "placeholder", "C2": 1.0}):
            with self.subTest(knees=knees), self.assertRaises(LP.PlanError):
                plan(1001, "train", knees=knees)

    def test_c2_rate_follows_its_rule_on_the_record_in_use(self):
        p = Cache.get(1001, "train")
        rec, _, _ = l7_backend.load_record()
        s = CAL.spare_capacity(rec)
        ph = next(x for x in p["timeline"]["phases"] if x["name"] == "C2")
        for e in (e for e in p["entities"] if e["kind_or_family"] == "C2"):
            self.assertAlmostEqual(e["params"]["rps"], ph["intensity"] * 4.0 * s / (50 * 0.030), places=3)
            self.assertIn(e["params"]["ua"], [ua for _, ua in l7_benign.UA_TABLE])
        self.assertEqual((p["intensity"]["record_status"], p["intensity"]["label"]), ("placeholder", "PLACEHOLDER"))

    def test_c3b_aims_at_export(self):
        p = Cache.get(1001, "train")
        self.assertEqual({e["params"]["route"] for e in p["entities"] if e["kind_or_family"].startswith("C3b@")}, {"C5"})
        self.assertEqual({e["params"]["route"] for e in p["entities"] if e["kind_or_family"] in ("C2", "C3a")}, {"C3"})

    def test_c3a_gaps_scale_with_the_phase(self):
        p = Cache.get(1001, "train")
        m = next(x for x in p["timeline"]["phases"] if x["name"] == "C3a")["intensity"]
        for e in (e for e in p["entities"] if e["kind_or_family"] == "C3a"):
            self.assertEqual(e["params"]["page_gap_s"], [round(2.0 / m, 3), round(8.0 / m, 3)])

    def test_plans_are_seeded(self):
        self.assertEqual(plan(1002, "train")["plan_set_sha256"], plan(1002, "train")["plan_set_sha256"])


class EvaluationPlanTest(unittest.TestCase):
    def test_the_eval_slot_and_the_reused_addresses(self):
        p = Cache.get(3201, "eval")
        self.assertEqual(p["duration_s"], 1140.0, "D-034: the 120 s benign tail follows the M3 slot")
        slot = p["timeline"]["phases"][-1]
        self.assertEqual((slot["name"], slot["start_s"], slot["stop_s"]), ("C3b@M3", 780.0, 1020.0))
        self.assertEqual(p["schema"], 3)
        ents = {e["entity_id"]: e for e in p["entities"]}
        m3 = [e for e in p["entities"] if e["kind_or_family"] == "C3b@M3"]
        trained = {e["address"]: e for e in p["entities"] if e["role"] == "attack" and not e["held_out"]}
        self.assertEqual(len(m3), 50)
        self.assertEqual(len({e["address"] for e in m3}), 50, "D-034: no two M3 bots share a donor")
        self.assertGreater(sum(trained[e["address"]]["kind_or_family"] == "C2" for e in m3), 0, "C2 donors first")
        for e in m3:
            donor = trained[e["address"]]
            self.assertTrue(e["held_out"])
            self.assertEqual((e["namespace"], e["netem"]), (donor["namespace"], donor["netem"]))
            self.assertNotEqual(e["params"]["ua"], donor["params"]["ua"], "a new UA on a reused address")
            self.assertLessEqual(donor["schedule"]["stop_s"], e["schedule"]["start_s"])
        self.assertEqual(len(ents), len(p["entities"]))
        held_benign = [e for e in p["entities"] if e["role"] == "benign" and e["held_out"]]
        self.assertEqual(sorted({e["kind_or_family"] for e in held_benign}),
                         ["api_bulk", "flash_crowd", "tpcw_shopping", "zipf_browser"])
        self.assertTrue([e for e in held_benign if e["kind_or_family"] != "flash_crowd" and e["schedule"]["start_s"] < 600],
                        "held-out kinds arrive across the timeline, not with the M3 slot")
        addresses = {e["address"] for e in p["entities"]}
        self.assertLessEqual(len(addresses), p3_prereg.load()["pool"]["address_limit"])
        for ns in p["namespaces"]:
            self.assertEqual(len(ns["addresses"]), len(set(ns["addresses"])))

    def test_an_eval_plan_makes_a_valid_schema_three_manifest(self):
        p = Cache.get(3201, "eval")
        with tempfile.TemporaryDirectory():
            m = D.make_manifest_v2(
                dataset_version=p["dataset_version"], capture_id="c", seed=p["seed"], seed_role=p["seed_role"],
                started_utc="2026-11-05T10:00:00Z", ended_utc="2026-11-05T10:17:00Z", duration_s=p["duration_s"],
                code={"commit": "0" * 40, "dirty": False, "inputs_sha256": {"x": "0" * 64}},
                server={"config_id": p["server"]["config_id"]}, host={}, pool=p["pool"],
                timeline=dict(p["timeline"], t0_wall=1.0e9), entities=p["entities"],
                files=[{"path": D.ACCESS_LOG_GZ, "size": 1, "sha256": "0" * 64}], schema=p["schema"])
        self.assertEqual(D.manifest_problems(m), [])
        label = D.labeler(m)
        e3 = next(e for e in p["entities"] if e["kind_or_family"] == "C3b@M3")
        self.assertEqual(label(e3["address"], e3["schedule"]["start_s"] + 1.0)[1:], ("C3b@M3", True, e3["entity_id"]))

    def test_the_pool_role_map_does_not_list_a_reused_address_twice(self):
        p = Cache.get(3201, "eval")
        self.assertEqual(set(p["pool"]["role_map"]), {e["address"] for e in p["entities"]})

    def test_a_pilot_plan_uses_the_placeholder_knee_and_says_so(self):
        p = plan(9201, "pilot", knees=None)
        self.assertEqual(p["intensity"]["knees"], {"status": "placeholder", "C2": 1.0})
        self.assertEqual(p["duration_s"], 1140.0)


class HeldOutNamesTest(unittest.TestCase):
    def test_no_kind_is_held_out_in_one_population_and_trained_in_another(self):
        flags = {}
        for pop in LP.POPULATIONS.values():
            for s in pop["benign"] + pop["attack"]:
                flags.setdefault(s.get("kind") or s.get("family"), set()).add(bool(s.get("held_out")))
        self.assertEqual({k: v for k, v in flags.items() if len(v) > 1}, {}, "rule 9 checks flags by name")

    def test_zipf_browser_is_the_iid_model_with_referer(self):
        import random
        a = l7_benign.plan_client("zipf_browser", {"level": 30}, 600.0, random.Random(4))
        b = l7_benign.plan_client("browser_page", {"level": 30, "referer": True}, 600.0, random.Random(4))
        self.assertEqual(a["users"], b["users"])


class KeyAgeTest(unittest.TestCase):
    """L7V2-03: key age (first-seen time) carries no information on role in a seed's plan (ml/l7v2_prereg.json arrivals,
    re-registered 2026-10-31)."""
    RULE = None

    @classmethod
    def setUpClass(cls):
        import l7v2_prereg
        cls.RULE = l7v2_prereg.load()["arrivals"]["age_check"]
        cls.plans = [Cache.get(1001, "train"), Cache.get(3201, "eval"), plan(2001, "val"), plan(1002, "train"),
                     plan(3202, "eval"), plan(9201, "pilot", knees=None)]

    def test_first_seen_times_are_matched_across_roles(self):
        for p in self.plans:
            a = p["age_check"]
            self.assertTrue(a["pass"], (p["seed"], a))
            self.assertLessEqual(a["ks"], self.RULE["ks_max"])
            self.assertLessEqual(abs(a["auc"] - 0.5), self.RULE["auc_band"])
            self.assertEqual(a, LP.age_check(p["entities"], self.RULE))

    def test_benign_users_arrive_across_the_whole_timeline_in_every_role(self):
        for p in self.plans:
            last_slot_end = max(ph["stop_s"] for ph in p["timeline"]["phases"])
            ben = [t for r, _h, _k, t in LP.first_seen(p["entities"]) if r == "benign"]
            self.assertLess(min(ben), 60.0)
            self.assertGreater(max(ben), 0.8 * (last_slot_end - 60.0), p["seed_role"])

    def test_attack_entities_arrive_across_their_slot(self):
        p = Cache.get(1001, "train")
        for ph in p["timeline"]["phases"]:
            starts = [e["schedule"]["start_s"] for e in p["entities"] if e["kind_or_family"] in ph["families"]]
            self.assertGreater(max(starts) - min(starts), 120.0, ph["name"])
            self.assertTrue(all(ph["start_s"] <= s <= ph["stop_s"] - 60.0 for s in starts))

    def test_held_out_kinds_are_not_born_with_an_attack_slot(self):
        for p in (Cache.get(3201, "eval"), self.plans[4]):
            slots = [ph["start_s"] for ph in p["timeline"]["phases"]]
            flash = {e["schedule"]["start_s"] for e in p["entities"] if e["kind_or_family"] == "flash_crowd"}
            self.assertEqual(len(flash), 1)
            f = flash.pop()
            self.assertTrue(all(not (f - 60.0 <= s < f + 120.0) for s in slots), (f, slots))
            self.assertLessEqual(p["age_check"]["held_out_ks"], self.RULE["held_out_ks_max"])

    def test_the_old_arrivals_fail_the_check(self):
        rows = [{"kind_or_family": "tpcw_browsing", "role": "benign", "held_out": False,
                 "schedule": {"start_s": 0.3 * k, "stop_s": 900.0}} for k in range(90)]
        rows += [{"kind_or_family": "C2", "role": "attack", "held_out": False,
                  "schedule": {"start_s": s + 0.2 * k, "stop_s": s + 240.0}} for s in (60.0, 300.0, 540.0) for k in range(50)]
        first_seen_rule = {k: self.RULE[k] for k in ("ks_max", "auc_band", "held_out_ks_max")}
        a = LP.age_check(rows, first_seen_rule)
        self.assertFalse(a["pass"])
        self.assertGreater(a["ks"], 0.9)

    def test_the_extended_check_passes_every_plan_d034(self):
        for p in self.plans:
            a = p["age_check"]
            self.assertLessEqual(a["lifetime_ks"], self.RULE["lifetime_ks_max"], p["seed"])
            self.assertLessEqual(abs(a["lifetime_auc"] - 0.5), self.RULE["lifetime_auc_band"], p["seed"])
            self.assertLessEqual(abs(a["window_age_auc"] - 0.5), self.RULE["window_age_auc_band"], p["seed"])
            self.assertTrue({"C2", "C3a", "C3b@M2"} <= set(a["window_age_auc_by_family"]), p["seed"])
            for fam, v in a["window_age_auc_by_family"].items():
                self.assertLessEqual(abs(v - 0.5), self.RULE["window_age_auc_band"], (p["seed"], fam))
            if p["seed_role"] in ("eval", "pilot"):
                self.assertIn("C3b@M3", a["window_age_auc_by_family"], "held-out families are checked too")
                self.assertLessEqual(a["held_out_lifetime_ks"], self.RULE["held_out_lifetime_ks_max"])

    def test_the_lifetimes_of_t038_fail_the_extended_check(self):
        # T038-01's plans: benign keys to the capture's end, attack keys inside their slot (window-age AUC ~0.88)
        import copy
        rows = copy.deepcopy(Cache.get(1001, "train")["entities"])
        stops = {ph["name"]: ph["stop_s"] for ph in Cache.get(1001, "train")["timeline"]["phases"]}
        for e in rows:
            e["params"].pop("sessions", None)
            e["schedule"]["stop_s"] = stops[e["schedule"]["phase"]] if e["role"] == "attack" else 900.0
        a = LP.age_check(rows, self.RULE)
        self.assertFalse(a["pass"])
        self.assertGreater(abs(a["window_age_auc"] - 0.5), 0.3, a)
        self.assertTrue(a["ks"] <= self.RULE["ks_max"], "the first-seen check alone passed them")

    def test_the_address_and_ip_ua_age_report_d040(self):
        # T042-F01, report-only: a benign device keeps its address and UA, so these ages still separate the roles
        for p in self.plans:
            a = p["age_check"]
            self.assertTrue(a["pass"], "report-only: it refuses no plan")
            r = a["report_v3"]
            self.assertTrue({"C2", "C3a", "C3b@M2", "C3b@M1"} <= set(r["address_age_auc_by_family"]), p["seed"])
            self.assertEqual(set(r["address_age_auc_by_family"]), set(r["ip_ua_age_auc_by_family"]))
            self.assertLess(r["address_age_auc"], 0.35, (p["seed"], "attack windows are younger, outside the band"))
            self.assertLess(r["ip_ua_age_auc"], 0.35, p["seed"])
            if p["seed_role"] in ("eval", "pilot"):
                self.assertIn("C3b@M3", r["address_age_auc_by_family"])

    def test_the_report_counts_from_the_address_and_the_key(self):
        toks = [0.0, 10.0, 20.0, 30.0, 40.0, 50.0]
        def at(t):
            return [t + x for x in toks]
        units = [
            # one device, two sessions: the second's address and key age count from the first session's start
            ("benign", False, "tpcw_browsing", 0.0, 50.0, at(0.0), "a1", "ua1"),
            ("benign", False, "tpcw_browsing", 100.0, 150.0, at(100.0), "a1", "ua1"),
            # a CGNAT address, two UAs: the address counts from the first user, the key from its own
            ("benign", False, "cgnat_browsers", 0.0, 50.0, at(0.0), "a2", "ua1"),
            ("benign", False, "cgnat_browsers", 200.0, 250.0, at(200.0), "a2", "ua2"),
            # an M3 bot on a donor's address: the address counts from the donor's first request, the key from its own
            ("attack", False, "C2", 300.0, 350.0, at(300.0), "a3", "ua3"),
            ("attack", True, "C3b@M3", 700.0, 750.0, at(700.0), "a3", "ua4"),
            ("benign", False, "uploader", 5.0, 9.0, None, "a4", None),          # no plan: no windows
        ]
        r = LP.age_report_v3(units, 4)
        # window ages (j >= 4: tokens 40 and 50 s): benign address 40, 50, 140, 150, 40, 50, 240, 250; key 40, 50, 140,
        # 150, 40, 50, 40, 50; C2 40, 50 in both; M3 address 440, 450 (740 and 750 minus the donor's 300), key 40, 50
        self.assertEqual(r["ip_ua_age_auc_by_family"]["C3b@M3"], r["ip_ua_age_auc_by_family"]["C2"])
        self.assertEqual(r["address_age_auc_by_family"]["C3b@M3"], 1.0)
        self.assertEqual(r["ip_ua_age_auc"], LP.auc([40, 50, 140, 150, 40, 50, 40, 50], [40, 50]))
        self.assertEqual(r["address_age_auc"], LP.auc([40, 50, 140, 150, 40, 50, 240, 250], [40, 50]))

    def test_lifetimes_d034(self):
        import l7v2_prereg
        law = l7v2_prereg.load()["arrivals"]["lifetimes"]["law"]
        p = Cache.get(1001, "train")
        slots = {ph["name"]: ph for ph in p["timeline"]["phases"]}
        attack = [e for e in p["entities"] if e["role"] == "attack"]
        for e in attack:
            s = e["schedule"]
            self.assertLessEqual(s["stop_s"] - s["start_s"], law["hi"] + 1e-6)
            self.assertTrue(s["stop_s"] - s["start_s"] >= law["lo"] - 1e-6 or s["stop_s"] == p["duration_s"])
        past = [e for e in attack if e["schedule"]["stop_s"] > slots[e["schedule"]["phase"]]["stop_s"] + 60.0]
        self.assertGreater(len(past) / len(attack), 0.25, "a share of the attack keys stays active past its slot")
        ben = [e for e in p["entities"] if e["role"] == "benign"]
        sess = [e for e in ben if e["params"].get("sessions")]
        self.assertEqual({e["kind_or_family"] for e in sess},
                         {"tpcw_browsing", "cgnat_browsers", "search_user", "exporter"})
        for e in ben:
            if e not in sess:                              # machine clients and P5 kinds: one lifetime
                self.assertLessEqual(e["schedule"]["stop_s"] - e["schedule"]["start_s"], law["hi"] + 1e-6)
            else:
                self.assertEqual(e["schedule"]["stop_s"], p["duration_s"])
        units = LP.key_units(p["entities"])
        self.assertGreater(len([u for u in units if u[0] == "benign"]), 2 * 87, "sessions: a returning user is a new key")


class SmokeUnchangedTest(unittest.TestCase):
    def test_the_smoke_population_keeps_its_plan(self):
        p = LP.build_plan("2026-11-smoke1", 9201, "pilot", "smoke")
        self.assertEqual((p["duration_s"], p["schema"], p["intensity"]), (900.0, 2, None))
        self.assertEqual(p["server"]["backend"], "legacy")
        self.assertTrue(p["plan_set_sha256"].startswith("1de8ed88"), "T-024's smoke plan for seed 9201")


if __name__ == "__main__":
    unittest.main()
