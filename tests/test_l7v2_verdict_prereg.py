"""The verdict pre-registration's loader (ml/l7v2_verdict_prereg.py) on its settled version: the consistency checks and
the resolutions the verdict code judges under. tests/test_l7v2_verdict_prereg_v3.py pins every value. Offline and pure."""
import copy
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7v2_verdict_prereg as P


class LoaderTest(unittest.TestCase):
    def _load(self, mutate):
        pre = copy.deepcopy(P.load())
        mutate(pre)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(pre, fh)
            return P.load(path)

    def test_the_settled_version_loads(self):
        self.assertEqual(P.PREREG_PATH, os.path.join(REPO, "ml", "l7v2_verdict_prereg_v3.json"))
        self.assertEqual(P.load()["format"], "l7v2-verdict-prereg/3")
        for old in ("l7v2_verdict_prereg.json", "l7v2_verdict_prereg_v2.json"):
            self.assertFalse(os.path.exists(os.path.join(REPO, "ml", old)), f"{old} is replaced")
        self.assertEqual(P.resolutions(), {"OC-1": "validation", "OC-2": "live", "OC-3": "with_u", "OC-4": "v_c"})

    def test_refuses_inconsistent_files(self):
        def reorder(p):
            p["ladder"][1], p["ladder"][2] = p["ladder"][2], p["ladder"][1]

        def drop_gru(p):
            p["live_set"]["per_class"]["C2"] = ["U", "R*"]

        def runs(p):
            p["live_set"]["runs_per_block"] = 12

        def steps(p):
            p["testing_order"] = p["testing_order"][::-1]

        def unresolved(p):
            p["choices"][0]["resolution"] = None

        def unknown(p):
            p["choices"][0]["resolution"] = "something else"

        def blocks(p):
            p["units"]["min_blocks"] = 8

        def no_primary(p):
            p["detection_entities"]["per_class"]["C3b"]["primary"] = []

        def default_rules_contend(p):
            p["arms"]["contenders"].append("default_rules")

        def no_gain(p):
            p["latency_alone"]["min_mean_gain_pp"] = 0.0

        for mutate in (reorder, drop_gru, runs, steps, unresolved, unknown, blocks, no_primary, default_rules_contend, no_gain):
            with self.subTest(mutate.__name__), self.assertRaises(P.PreregError):
                self._load(mutate)


if __name__ == "__main__":
    unittest.main()
