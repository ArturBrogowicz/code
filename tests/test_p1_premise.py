"""P1's premise check (eval/p1_premise.py, ml/p1_prereg_5.json premise, D-073): on the pilot plans at nominal times, every ladder level's
sources against the benign per-key window maxima, pinned in ml/p1_premise.json before any ladder run. Plans only; nothing is sent."""
import hashlib
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "bench"), os.path.join(REPO, "eval"), os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p1_premise as PR
import p1_traffic as PT

PREMISE_SHA256 = "2a378e09d2c4f92abda697ddf21767785eb8eeb0538c50774f84159de3bf1d01"
FROZEN_RECORD = os.path.join(REPO, "bench", "calibration", "ddos-mitigation-2026-11-04.json")


class WindowTest(unittest.TestCase):
    def test_a_window_maximum_is_the_busiest_window_over_its_length(self):
        self.assertEqual(PR.window_max([0.0, 0.5, 0.9, 5.0], 1), 3.0)
        self.assertEqual(PR.window_max([0.0, 1.0, 2.0], 1), 1.0, "a window of 1 s holds [t, t + 1)")
        self.assertEqual(PR.window_max([0.0, 3.0, 6.0, 9.0], 10), 0.4)
        self.assertEqual(PR.window_max([], 10), 0.0)

    def test_the_quantile_and_the_keys(self):
        self.assertEqual(PR.quantile(list(range(1, 101)), 0.99), 99)
        self.assertIsNone(PR.quantile([], 0.99))


class PinnedTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version_and_covers_every_level(self):
        with open(PR.PREMISE_FILE, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREMISE_SHA256)
        with open(PR.PREMISE_FILE, encoding="utf-8") as fh:
            got = json.load(fh)
        with open(FROZEN_RECORD, encoding="utf-8") as fh:
            self.assertEqual(got["record"]["sha256"], json.load(fh)["sha256"])
        self.assertEqual((got["format"], got["date"], got["windows_s"], got["quantile"]), ("p1-premise/1", "2026-11-07", [1, 10, 30, 60, 300], 0.99))
        for cls in ("C2", "C3a", "C3b"):
            self.assertEqual(sorted(got["levels"][cls], key=float), [f"{lv:g}" for lv in PT.ladder_levels(cls)])
        self.assertEqual({row["mark"] for rows in got["levels"].values() for row in rows.values()}, {"evades"})
        self.assertEqual(PR.marks()[("C2", 16.0)], "evades")

    def test_the_code_still_writes_the_pinned_marks(self):
        """The plans of today give the pinned file again: a change to the plans needs a new, dated premise check."""
        with open(PR.PREMISE_FILE, encoding="utf-8") as fh:
            pinned = json.load(fh)
        got = PR.premise(FROZEN_RECORD)
        self.assertEqual(json.loads(json.dumps({**got, "date": pinned["date"]}, sort_keys=True)), pinned)


if __name__ == "__main__":
    unittest.main()
