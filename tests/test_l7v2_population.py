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
        self.assertLess(users, p3_prereg.load()["volume"]["benign_users_min"],
                        "P3's 200-user target does not fit 300 aliases with this mix: reported, not hidden")

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
        self.assertEqual(p["duration_s"], 1020.0)
        slot = p["timeline"]["phases"][-1]
        self.assertEqual((slot["name"], slot["start_s"], slot["stop_s"]), ("C3b@M3", 780.0, 1020.0))
        self.assertEqual(p["schema"], 3)
        ents = {e["entity_id"]: e for e in p["entities"]}
        m3 = [e for e in p["entities"] if e["kind_or_family"] == "C3b@M3"]
        c2 = {e["address"]: e for e in p["entities"] if e["kind_or_family"] == "C2"}
        self.assertEqual(len(m3), 50)
        for e in m3:
            donor = c2[e["address"]]
            self.assertTrue(e["held_out"])
            self.assertEqual((e["namespace"], e["netem"]), (donor["namespace"], donor["netem"]))
            self.assertNotEqual(e["params"]["ua"], donor["params"]["ua"], "a new UA on a reused address")
            self.assertLessEqual(donor["schedule"]["stop_s"], e["schedule"]["start_s"])
        self.assertEqual(len(ents), len(p["entities"]))
        held_benign = [e for e in p["entities"] if e["role"] == "benign" and e["held_out"]]
        self.assertEqual(sorted({e["kind_or_family"] for e in held_benign}),
                         ["api_bulk", "browser_page", "flash_crowd", "tpcw_shopping"])
        self.assertTrue(all(e["schedule"]["start_s"] == 780.0 for e in held_benign))
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
        self.assertEqual(label(e3["address"], 800.0)[1:], ("C3b@M3", True, e3["entity_id"]))

    def test_the_pool_role_map_does_not_list_a_reused_address_twice(self):
        p = Cache.get(3201, "eval")
        self.assertEqual(set(p["pool"]["role_map"]), {e["address"] for e in p["entities"]})

    def test_a_pilot_plan_uses_the_placeholder_knee_and_says_so(self):
        p = plan(9201, "pilot", knees=None)
        self.assertEqual(p["intensity"]["knees"], {"status": "placeholder", "C2": 1.0})
        self.assertEqual(p["duration_s"], 1020.0)


class SmokeUnchangedTest(unittest.TestCase):
    def test_the_smoke_population_keeps_its_plan(self):
        p = LP.build_plan("2026-11-smoke1", 9201, "pilot", "smoke")
        self.assertEqual((p["duration_s"], p["schema"], p["intensity"]), (900.0, 2, None))
        self.assertEqual(p["server"]["backend"], "legacy")
        self.assertTrue(p["plan_set_sha256"].startswith("1de8ed88"), "T-024's smoke plan for seed 9201")


if __name__ == "__main__":
    unittest.main()
