"""Tests for eval/check_addendum.py (the addendum's numbers against the published campaigns).

Needs the venv (pandas, numpy, scipy):  venv/bin/python -m unittest discover -s tests -v

* The comparison rules on small synthetic inputs: strict rounding, tolerance, missing values.
* The real comparison on the published campaigns: how many rows match, which differ and which
  cannot be checked, and that results/2026-10-21_prototype-claims-check/ equals a fresh run.
"""
import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "eval"))
try:
    import check_addendum as K
    HAVE_STACK = True
except ImportError:                      # system python without pandas / scipy: skip these tests
    HAVE_STACK = False

RESULTS = os.path.join(REPO, "results")
DERIVED = os.path.join(RESULTS, "2026-10-21_prototype-claims-check")
NEEDED = [] if not HAVE_STACK else [K.EXP1, K.EXP2A, K.EXP2B, K.F45, K.CALIB, K.BASELINE]
HAVE_DATA = HAVE_STACK and all(os.path.isdir(os.path.join(RESULTS, d)) for d in NEEDED)


@unittest.skipUnless(HAVE_STACK, "needs the venv")
class ComparisonRulesTest(unittest.TestCase):

    def verdict(self, quoted, got, **kw):
        t = K.Table()
        t.nums("X", "T", "claim", quoted, got, **kw)
        return t.rows[0]["verdict"]

    def test_a_value_matches_when_it_rounds_to_the_quoted_one(self):
        self.assertEqual(self.verdict([1.54], [1.5449], nd=2), K.MATCH)
        self.assertEqual(self.verdict([1.54], [1.5351], nd=2), K.MATCH)
        self.assertEqual(self.verdict([1.54], [1.55], nd=2), K.DIFFERS)
        self.assertEqual(self.verdict([100], [99.6], nd=0), K.MATCH)
        self.assertEqual(self.verdict([100], [99.4], nd=0), K.DIFFERS)

    def test_a_tolerance_replaces_the_rounding(self):
        self.assertEqual(self.verdict([4], [3.4], nd=1, tol=0.7), K.MATCH)
        self.assertEqual(self.verdict([4], [3.2], nd=1, tol=0.7), K.DIFFERS)

    def test_missing_values_and_length_mismatch_differ(self):
        self.assertEqual(self.verdict([1.0], [float("nan")]), K.DIFFERS)
        self.assertEqual(self.verdict([1.0, 2.0], [1.0]), K.DIFFERS)
        self.assertEqual(self.verdict([None], [1.0]), K.DIFFERS)

    def test_every_value_must_agree(self):
        self.assertEqual(self.verdict([1.0, 2.0], [1.0, 2.0]), K.MATCH)
        self.assertEqual(self.verdict([1.0, 2.0], [1.0, 2.2]), K.DIFFERS)

    def test_text_and_unchecked_rows(self):
        t = K.Table()
        t.text("A", "T", "c", "x", "x", True)
        t.text("B", "T", "c", "x", "y", False, "why")
        t.unchecked("C", "T", "c", "x", "no data")
        self.assertEqual([r["verdict"] for r in t.rows], [K.MATCH, K.DIFFERS, K.UNCHECKED])
        self.assertEqual(K.counts(t.rows), {K.MATCH: 1, K.DIFFERS: 1, K.UNCHECKED: 1})

    def test_the_minutes_of_a_time_are_truncated_or_rounded(self):
        self.assertTrue(K._minute_ok("10:53", 10 * 3600 + 52 * 60 + 58))     # 10:52:58 rounds to 10:53
        self.assertTrue(K._minute_ok("08:57", 8 * 3600 + 57 * 60 + 46))      # 08:57:46 truncates to 08:57
        self.assertFalse(K._minute_ok("08:55", 8 * 3600 + 57 * 60 + 46))

    def test_markdown_escapes_pipes(self):
        rows = [{"id": "X", "where": "A", "claim": "a | b", "addendum": "1", "recomputed": "1", "verdict": K.MATCH,
                 "note": ""}]
        self.assertIn("a \\| b", K.to_markdown(rows))


@unittest.skipUnless(HAVE_DATA, "needs the venv and the published prototype campaigns in results/")
class AddendumAgainstPublishedDataTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rows = K.run(RESULTS)
        cls.by_id = {r["id"]: r for r in cls.rows}

    def test_counts(self):
        self.assertEqual(K.counts(self.rows), {K.MATCH: 129, K.DIFFERS: 4, K.UNCHECKED: 6})

    def test_what_differs(self):
        self.assertEqual(sorted(r["id"] for r in self.rows if r["verdict"] == K.DIFFERS),
                         ["H-2", "H-25", "H-26", "L-3"])
        self.assertIn("2.10 s from the Phase-1", self.by_id["L-3"]["recomputed"])
        self.assertIn("0.97 s from the Phase-2", self.by_id["L-3"]["recomputed"])
        self.assertIn("62.7", self.by_id["H-26"]["note"])

    def test_what_cannot_be_checked(self):
        self.assertEqual(sorted(r["id"] for r in self.rows if r["verdict"] == K.UNCHECKED),
                         ["A-6", "B-1", "C-26", "E-11", "H-27", "L-5"])

    def test_headline_rows_match(self):
        for ident in ("C-1", "C-2", "C-14", "C-18", "D-1.ACK", "D-3", "D-4", "E-1", "E-4", "H-1", "H-3", "H-4",
                      "H-7.HTTP.unprotected", "H-19", "H-21", "I-1", "I-7", "I-4.HTTP", "K-1", "L-2", "M-1", "M-2"):
            self.assertEqual(self.by_id[ident]["verdict"], K.MATCH, ident)

    def test_every_row_has_text(self):
        for r in self.rows:
            for key in ("id", "where", "claim", "addendum", "recomputed", "verdict"):
                self.assertTrue(r[key], (r["id"], key))
        self.assertEqual(len({r["id"] for r in self.rows}), len(self.rows))

    def test_the_derived_directory_equals_a_fresh_run(self):
        with open(os.path.join(DERIVED, "claims_check.md"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), K.to_markdown(self.rows))
        with open(os.path.join(DERIVED, "claims_check.csv"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), K.to_csv(self.rows))

    def test_the_derived_directory_checksums_match(self):
        listed = {}
        with open(os.path.join(DERIVED, "SHA256SUMS"), encoding="utf-8") as fh:
            for line in fh:
                digest, _, rel = line.rstrip("\n").partition("  ")
                listed[rel] = digest
        found = {os.path.relpath(os.path.join(d, f), DERIVED)
                 for d, _, files in os.walk(DERIVED) for f in files} - {"SHA256SUMS"}
        self.assertEqual(set(listed), found)
        for rel, digest in listed.items():
            with open(os.path.join(DERIVED, rel), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest, rel)


if __name__ == "__main__":
    unittest.main()
