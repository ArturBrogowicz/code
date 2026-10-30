"""P3 capture plans (docs/P3_DATASET_DESIGN.md §4.1-§4.3, §5; docs/L7V2_DESIGN.md §6): per-seed pools and role
maps from 10.0.16.0/20, netem for every entity, per-entity draws, phases, namespaces. Pure; the admissibility
gate runs on two simulated seeds to stay fast."""
import hashlib
import ipaddress
import itertools
import os
import subprocess
import sys
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_pools as P
import l7_traffic
import p3_prereg

import l7_dataset

V = "2026-11-v1"
FAST = (0, 1)
_CACHE = {}


def plan(seed, role, **kw):
    key = (seed, role, tuple(sorted(kw.items())))
    if key not in _CACHE:
        _CACHE[key] = P.build_plan(V, seed, role, gate_seeds=FAST, **kw)
    return _CACHE[key]


class PoolTest(unittest.TestCase):
    def test_seed_one_no_longer_reproduces_todays_map(self):
        b, a, _, _ = l7_traffic.build_plan(1, 12, 600.0, benign_mix="overlap", gate_seeds=FAST,
                                           heuristics="tolerant")
        legacy = {c["ip"]: "benign" for c in b} | {x["ip"]: "attack" for x in a}
        p = plan(1, "pilot", check_role=False)
        new = p["pool"]["role_map"]
        self.assertFalse(set(new.items()) & set(legacy.items()))
        self.assertFalse(set(new) & set(legacy))
        for addr in new:
            ip = ipaddress.ip_address(addr)
            self.assertIn(ip, P.POOL_NET)
            self.assertFalse(any(ip in n for n in P.LEGACY_NETS), addr)
        with self.assertRaises(P.PlanError):                 # and seed 1 is no P3 seed at all
            P.build_plan(V, 1, "pilot", gate_seeds=FAST)

    def test_role_maps_differ_between_seeds(self):
        seeds = [(s, "train") for s in (1001, 1002, 1003, 1004)] + [(2001, "val"), (9201, "pilot"), (9202, "pilot")]
        for (s1, r1), (s2, r2) in itertools.combinations(seeds, 2):
            pos, pairs = P.role_map_agreement(plan(s1, r1), plan(s2, r2))
            self.assertLess(pos, 0.10, (s1, s2))
            self.assertLess(pairs, 0.10, (s1, s2))

    def test_pool_is_inside_the_testbed_and_unique(self):
        p = plan(9201, "pilot")
        addrs = [e["address"] for e in p["entities"]]
        self.assertEqual(len(addrs), len(set(addrs)))
        self.assertTrue(all(ipaddress.ip_address(x) in P.TESTBED_NET for x in addrs))
        self.assertNotIn("10.0.16.0", addrs)
        self.assertNotIn("10.0.31.255", addrs)
        self.assertEqual(p["pool"]["permutation_seed"], P.subseed(V, 9201, "pool"))
        self.assertEqual(len(P.pool_hosts()), 4094)

    def test_subseeds(self):
        want = int.from_bytes(hashlib.blake2b(f"p3|{V}|9201|3".encode(), digest_size=8).digest(), "big")
        self.assertEqual(P.subseed(V, 9201, 3), want & (2 ** 63 - 1))
        a, b = plan(9201, "pilot"), plan(9202, "pilot")
        sa = [e["subseed"] for e in a["entities"]]
        self.assertEqual(len(sa), len(set(sa)))
        self.assertFalse(set(sa) & {e["subseed"] for e in b["entities"]})
        for e in a["entities"]:
            self.assertEqual(e["subseed"], P.subseed(V, 9201, e["index"]))
            self.assertEqual(e["entity_id"], f"{V}:9201:{e['index']}")

    def test_deterministic(self):
        self.assertEqual(P.build_plan(V, 9202, "pilot", gate_seeds=FAST), plan(9202, "pilot"))


class EntityTest(unittest.TestCase):
    def test_netem_for_every_entity_balanced_within_each_role(self):
        p = plan(9201, "pilot")
        for role in ("benign", "attack"):
            group = [e for e in p["entities"] if e["role"] == role]
            counts = [sum(e["netem"] == prof for e in group) for prof in P.NETEM_PROFILES]
            self.assertLessEqual(max(counts) - min(counts), 1, (role, counts))
        self.assertTrue(all(e["netem"] in P.NETEM_PROFILES for e in p["entities"]))
        shares = P.netem_shares(p)
        self.assertAlmostEqual(sum(shares["attack"].values()), 1.0, places=3)

    def test_parameters_are_drawn_per_entity_and_recorded(self):
        p = plan(9201, "pilot")
        floods = [e for e in p["entities"] if e["kind_or_family"] == "subthreshold_flood"]
        self.assertGreater(len({e["params"]["rps"] for e in floods}), 1)
        curls = [e for e in p["entities"] if e["kind_or_family"] == "curl_oneshot"]
        self.assertGreater(len({tuple(e["params"]["think_s"]) for e in curls}), 1)
        for e in p["entities"]:
            self.assertEqual(e["plan_sha256"], l7_dataset.entity_plan_sha256(e))
            if e["role"] == "attack" and not e["held_out"]:
                rec = l7_traffic._check_spec(l7_traffic.AttackSpec(e["kind_or_family"], e["mechanism"],
                                                                   False, e["params"]))
                self.assertEqual(rec["violations"], [], e["entity_id"])
        self.assertEqual(p["plan_set_sha256"], l7_dataset.plan_set_sha256(p["entities"]))

    def test_held_out_kinds_only_in_evaluation_and_pilot_captures(self):
        for seed, role in ((1001, "train"), (2001, "val")):
            self.assertFalse([e for e in plan(seed, role)["entities"] if e["held_out"]], role)
        held = {e["kind_or_family"] for e in plan(3201, "eval")["entities"] if e["held_out"]}
        self.assertEqual(held, {"api_bulk", "padded_flood", "credstuff", "slowread"})

    def test_attacks_stay_inside_their_phase(self):
        p = plan(9201, "pilot")
        pre = p3_prereg.load()["volume"]
        self.assertEqual(p["duration_s"], pre["capture_s"])
        phases = {ph["name"]: ph for ph in p["timeline"]["phases"]}
        for e in p["entities"]:
            s = e["schedule"]
            if e["role"] == "benign":
                self.assertEqual((s["start_s"], s["stop_s"]), (0.0, p["duration_s"]))
                continue
            ph = phases[s["phase"]]
            self.assertIn(e["kind_or_family"], ph["families"])
            self.assertTrue(ph["start_s"] <= s["start_s"] < s["stop_s"] <= ph["stop_s"], e["entity_id"])
        orders = {tuple(x["name"] for x in plan(s, "train")["timeline"]["phases"]) for s in (1001, 1002, 1003, 1004)}
        self.assertGreater(len(orders), 1)                 # the phase order is drawn per seed

    def test_namespaces_group_by_profile_under_the_alias_cap(self):
        p = plan(9201, "pilot")
        by_name = {n["name"]: n for n in p["namespaces"]}
        for e in p["entities"]:
            ns = by_name[e["namespace"]]
            self.assertEqual(ns["profile"], e["netem"])
            self.assertIn(e["address"], ns["addresses"])
        with mock.patch.object(P, "MAX_ALIASES", 3):
            small = P.build_plan(V, 9201, "pilot", gate_seeds=FAST)
        self.assertTrue(all(len(n["addresses"]) <= 3 for n in small["namespaces"]))
        names = [n["name"][:12] for n in small["namespaces"]]
        self.assertEqual(len(names), len(set(names)))      # the host-side veth names stay distinct

    def test_server_config_alternates(self):
        self.assertEqual(plan(9201, "pilot")["server"]["config_id"], "A")
        self.assertEqual(plan(9202, "pilot")["server"]["config_id"], "B")
        self.assertEqual(plan(9202, "pilot")["server"]["gunicorn_workers"], 4)


class RefusalTest(unittest.TestCase):
    def test_role_and_limits_fail_closed(self):
        with self.assertRaises(P.PlanError):
            P.build_plan(V, 1001, "eval", gate_seeds=FAST)
        with self.assertRaises(P.PlanError):
            P.build_plan("v1", 1001, "train", gate_seeds=FAST)
        with self.assertRaises(P.PlanError):
            P.build_plan(V, 9201, "pilot", population="nope", gate_seeds=FAST)
        with self.assertRaises(P.PlanError):
            P.build_plan(V, 9201, "pilot", scale=9, gate_seeds=FAST)      # > 300 addresses


class CapturePlanCliTest(unittest.TestCase):
    def run_capture(self, *argv):
        return subprocess.run([sys.executable, os.path.join(REPO, "ml", "capture_l7.py"), *argv],
                              capture_output=True, text=True, check=False)

    def test_p3_is_the_default_pipeline_and_plan_mode_is_offline(self):
        r = self.run_capture("--plan", "--version", V, "--seed", "9201", "--seed-role", "pilot",
                             "--gate-seeds", "2")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertIn("P3 plan 2026-11-v1 seed 9201 (pilot)", r.stdout)
        self.assertIn("netem share per role", r.stdout)
        self.assertNotIn("10.0.2.", r.stdout)

    def test_seed_one_is_refused_by_the_p3_pipeline(self):
        r = self.run_capture("--plan", "--version", V, "--seed", "1", "--seed-role", "pilot")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pre-registered", r.stderr + r.stdout)


if __name__ == "__main__":
    unittest.main()
