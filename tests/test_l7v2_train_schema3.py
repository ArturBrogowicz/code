"""train_l7 on L7 v2 (schema-3) captures: the default selection rule (T-030 L7V2-06). Offline: fixture captures are
written under temporary directories."""
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "tests")):
    sys.path.insert(0, _p)
import test_l7_manifest_v3 as V3
import train_l7 as T


class DefaultSelectionTest(unittest.TestCase):
    def test_a_schema_three_capture_gets_validation_only_selection(self):
        with tempfile.TemporaryDirectory() as root:
            d, m = V3.capture_v3(root, V3.reuse_entities()[0])
            self.assertEqual(m["schema"], 3)
            self.assertEqual(T.default_selection([d]), "val")


def window(ent, cls, units=1, ua=1):
    return {"ip": ent, "ua_h": ua, "t": 0.0, "cls": cls, "recs": [{"_units": units}]}


class UserUnitsTest(unittest.TestCase):
    def test_a_flagged_pool_key_costs_one_unit(self):
        """The budget's denominator counts a pool by its users (T-030 L7V2-07); a flagged key costs one unit, at
        most its entity's units: the user's per-key rule of 2026-10-31 (a CGNAT user = one key; T-035)."""
        windows = [window(f"b{i}", "benign") for i in range(173)] + [window("pool", "benign", 24)]
        windows += [window(f"a{i}", "attack") for i in range(20)]
        scores = [0.0] * 173 + [0.96] + [0.96] * 20
        point = T.operating_point(windows, scores, theta_grid=[0.95, 0.98], k_grid=[1], budget=0.01)
        self.assertEqual((point["benign_allowed"], point["val_benign_units"]), (1, 197))
        self.assertEqual((point["threshold"], point["val_benign_flagged"], point["val_attack_caught"]), (0.95, 1, 20))
        two = windows + [window("pool", "benign", 24, ua=2)]         # a second user of the pool: 2 units > 1
        point2 = T.operating_point(two, scores + [0.96], theta_grid=[0.95, 0.98], k_grid=[1], budget=0.01)
        self.assertEqual((point2["threshold"], point2["val_benign_flagged"], point2["val_attack_caught"]),
                         (0.98, 0, 0))
        one_unit = [dict(w, recs=[{}]) for w in two]                 # one unit per entity: two keys still cost 1
        self.assertEqual(T.operating_point(one_unit, scores + [0.96], theta_grid=[0.95, 0.98], k_grid=[1],
                                           budget=0.01)["threshold"], 0.95)

    def test_records_carry_their_pools_units(self):
        with tempfile.TemporaryDirectory() as root:
            ents = V3.reuse_entities()[0]
            pool = next(e for e in ents if e["role"] == "benign")
            pool["kind_or_family"], pool["params"] = "cgnat_browsers", {"users": 12, "level": 30}
            pool["users"] = V3.D.pool_users(pool)
            for e in ents:
                e["plan_sha256"] = V3.D.entity_plan_sha256(e)
            d, _m = V3.capture_v3(root, ents)
            _m2, recs = T.load_records(d)
        self.assertEqual({r["_units"] for r in recs if r["_entity"] == pool["entity_id"]}, {12})
        self.assertEqual({r["_units"] for r in recs if r["_entity"] != pool["entity_id"]}, {1})


if __name__ == "__main__":
    unittest.main()
