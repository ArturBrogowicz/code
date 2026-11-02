"""The P1 record of D-049 (ml/p1_prereg.json): every value that judges is pinned, so a change shows up as a failing test and must
become a new file. Offline and pure."""
import hashlib
import json
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATH = os.path.join(REPO, "ml", "p1_prereg.json")
PREREG_SHA256 = "2c256fedc2352c8004ccb619748244ac5ee0c4cd5f677a5668a0cee3004b01ac"


def load():
    with open(PATH, encoding="utf-8") as fh:
        return json.load(fh)


class FrozenFileTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_SHA256)
        rec = load()
        self.assertEqual((rec["format"], rec["date"]), ("p1-prereg/1", "2026-11-02"))
        self.assertIn("D-049", rec["decision"])

    def test_the_halving_rule(self):
        rule = load()["halving"]
        self.assertEqual((rule["seed"], rule["controls"]), (9001, ["C", "Cp"]))
        self.assertEqual((rule["health"]["q_min"], rule["health"]["class_q_min"]), (99.0, 95.0))
        self.assertEqual((rule["floor"]["max_halvings"], rule["max_reruns"]), (2, 2))

    def test_the_floor_is_the_mix_it_says(self):
        """The record's counts are the frozen mix's: count >> halvings, at least 1, on every spec of count > 1."""
        import sys
        sys.path.insert(0, os.path.join(REPO, "ml"))
        import l7_pools as LP
        specs = LP.POPULATIONS["l7v2"]["benign"]
        floor = load()["halving"]["floor"]
        h = floor["max_halvings"]
        kept = {s["kind"]: max(1, s["count"] >> h) for s in specs if s["count"] > 1}
        self.assertEqual(kept, floor["counts_at_the_floor"])
        by_h = [sum(max(1, s["count"] >> k) for s in specs) for k in range(4)]
        self.assertEqual(by_h, floor["addresses_by_halvings"])

    def test_the_age_rule_and_the_readings(self):
        rec = load()
        self.assertIn("not applied", rec["age_check"]["p1"])
        self.assertIn("enforced", rec["age_check"]["p3"])
        self.assertEqual(sorted(rec["readings"]["assumptions"]), ["file_sink_silence_s", "side_bots"])
        for text in rec["readings"]["assumptions"].values():
            self.assertTrue(text.startswith("[ASSUMPTION]"))


if __name__ == "__main__":
    unittest.main()
