"""D-073 (1) and (2) (2026-11-07T08:33Z): the loris ladder to 500 sources, its pool drawn at 600 addresses without moving any address the
400-address pool gave, and the attack-validity floor 0.5 x min(planned, 1,800) (T-074). Nothing touches the machine."""
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import l7_pools
import p4_fake_host as F
import p4_runner as R
import p4_traffic as P

OLD_POOL = 60 + 300 + 40           # the pool before D-073 (1)


class LadderTest(unittest.TestCase):
    def test_the_ladder_is_the_notes(self):
        with open(os.path.join(REPO, "docs", "P4_SLOW_DESIGN.md"), encoding="utf-8") as fh:
            row = next(line for line in fh if line.startswith("| D-073 (1) |"))
        levels = tuple(int(x) for x in re.search(r"\*\*\(([\d, ]+)\)\*\*", row).group(1).split(", "))
        self.assertEqual(P.FAMILIES["loris"]["levels"], levels)
        self.assertEqual(P.FAMILIES["post"]["levels"], (5, 10, 20, 40))
        self.assertEqual(P.ALWAYS_RUN, 3)
        self.assertIn("The first three levels of a family always run", row)

    def test_the_top_plan(self):
        plan = P.build_plan(9101, "pilot", loris=500)
        loris = [e for e in plan["entities"] if e["role"] == "attack"]
        self.assertEqual((len(loris), sum(e["params"]["conns"] for e in loris), plan["pool"]["size"]), (500, 3000, 600))
        self.assertEqual(len({e["address"] for e in plan["entities"]}), 560)
        with self.assertRaises(P.PlanError):
            P.build_plan(9101, "pilot", loris=501)

    def test_the_larger_pool_keeps_every_address_of_the_smaller(self):
        for role, seeds in P.SEEDS.items():
            for seed in seeds:
                self.assertEqual(l7_pools.draw_pool(P.VERSION, seed, P.POOL_SIZE)[:OLD_POOL],
                                 l7_pools.draw_pool(P.VERSION, seed, OLD_POOL), (role, seed))
        old = l7_pools.draw_pool(P.VERSION, 3101, OLD_POOL)
        plan = P.build_plan(3101, "eval", loris=300)
        self.assertEqual([e["address"] for e in plan["entities"]], [old[e["index"]] for e in plan["entities"]],
                         "every benign and loris address of the 400-address pool")


class FloorTest(unittest.TestCase):
    def test_half_of_the_planned_up_to_1800(self):
        self.assertEqual((R.ATTACK_MIN_OPENED_SHARE, R.ATTACK_OPENED_CAP), (0.5, 1800))
        self.assertEqual([R.opened_floor(n) for n in (600, 1050, 1500, 1800, 2400, 3000)], [300, 525, 750, 900, 900, 900])

    def test_a_saturated_top_is_a_valid_run(self):
        def run(root):
            block = R.plan_block("campaign", 3101, root, sources={"loris": 500}, thresholds=(5, 256, 2), families=("loris",))
            return next(r for r in block["runs"] if r["arm"] == "U_loris")
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            res = R.execute_run(F.FakeHost(attack_opened_share=0.4, modelled_attackers=1), run(one))   # 2 of 6 a source: 1,000 of 3,000
            self.assertFalse([r for r in res["reasons"] if "the attack opened" in r], res["reasons"])
            res = R.execute_run(F.FakeHost(attack_opened_share=0.2, modelled_attackers=1), run(two))   # 1 of 6: 500 of 3,000
            self.assertIn("the attack opened 500 of its 3000 connections, under the floor of 900 (D-073 (2))", res["reasons"])


if __name__ == "__main__":
    unittest.main()
