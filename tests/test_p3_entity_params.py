"""Per-entity model values (docs/P3_DATASET_DESIGN.md §4.3): a P3 plan can draw a browser's think time,
views per visit and visit gap per entity; a client without them keeps the frozen values, so every earlier
plan is unchanged (pinned by hash below, computed on the parent commit)."""
import hashlib
import json
import os
import random
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_benign as B
import l7_traffic


def plan_sha(kind, params, seed, duration_s=600.0):
    plan = B.plan_client(kind, params, duration_s, random.Random(seed))
    return hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()


class ModelValuesTest(unittest.TestCase):
    def test_overrides_reach_the_views(self):
        one = {"level": 30, "views_per_visit": [1, 1]}
        slow = B.plan_client("browser_page", {**one, "visit_gap_s": [500, 600]}, 3000.0, random.Random(5))
        fast = B.plan_client("browser_page", {**one, "visit_gap_s": [1, 2]}, 3000.0, random.Random(5))
        sv, fv = slow["users"][0]["views"], fast["users"][0]["views"]
        for v in sv:                                    # one view per visit: every pause holds a visit gap
            self.assertGreaterEqual(v["pause_s"], 500.0)
        self.assertGreater(len(fv), 3 * len(sv))
        busy = B.plan_client("browser_page", {"level": 30, "think_mean_s": 0.5}, 600.0, random.Random(5))
        idle = B.plan_client("browser_page", {"level": 30, "think_mean_s": 30.0}, 600.0, random.Random(5))
        self.assertGreater(len(busy["users"][0]["views"]), len(idle["users"][0]["views"]))

    def test_every_cgnat_user_gets_the_values(self):
        plan = B.plan_client("cgnat_browsers", {"users": 3, "level": 30, "views_per_visit": [1, 1],
                                                "visit_gap_s": [400, 500]}, 2000.0, random.Random(9))
        for u in plan["users"]:
            for v in u["views"]:
                self.assertGreaterEqual(v["pause_s"], 400.0)

    def test_model_values(self):
        self.assertEqual(B.model_values({"level": 30}), {})
        self.assertEqual(B.model_values({"think_mean_s": 5, "views_per_visit": [2, 4],
                                         "visit_gap_s": [10, 20]}),
                         {"think_mean_s": 5.0, "views_per_visit": (2, 4), "visit_gap_s": (10.0, 20.0)})
        self.assertEqual(B.MODEL_KEYS, ("think_mean_s", "views_per_visit", "visit_gap_s"))


PINNED = (
    ("browser_page", 0, "b57b3063c3c3855d21cc9974bd57e34114a62512373b9aabab4478d5241ea495"),
    ("browser_page", 2, "118897175a5981c80a9d2ca5d9f524d1c0834b4965036ac742650d61fa533760"),
    ("cgnat_browsers", 4, "485c9c0bb5835cc5506041bfeb201d64543a67e609f2e0a0f4e8240795dea6b3"),
    ("api_bulk", 6, "3248db7a846dff694ab41becbf8d8229f7a72cf10e15533b77cd77f79ae6e2d6"),
    ("crawler_polite", 7, "7237ce5d472e961cec1912b5692c80e4add90eaa42c6f9052584a7b697d6f740"),
)


class EarlierPlansUnchangedTest(unittest.TestCase):
    """Hashes of the P5b plans as the parent commit builds them (e1754df). A P3 change that moved any draw
    of an earlier plan would change what a re-run of P5b/P5c executes."""

    def test_overlap_kind_plans_are_byte_identical(self):
        for kind, i, want in PINNED:
            spec = l7_traffic.OVERLAP_KINDS[i]
            self.assertEqual(spec.kind, kind)
            self.assertEqual(plan_sha(kind, dict(spec.params), 1234 + i), want, (kind, i))


if __name__ == "__main__":
    unittest.main()
