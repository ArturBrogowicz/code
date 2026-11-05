"""The TPC-W v1.8 navigation tables (ml/tpcw_v18.json) and their sampler (ml/l7_tpcw.py), docs/L7V2_DESIGN.md §12.1.
Offline and pure."""
import hashlib
import os
import random
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_tpcw as T

KEPT = {"Home", "Product Detail", "New Products", "Best Sellers", "Search Request", "Search Results",
        "Order Inquiry", "Order Display"}


class FixedR:
    """A stand-in rng whose randint returns a chosen r (the specification's worked example)."""

    def __init__(self, r):
        self.r = r

    def randint(self, lo, hi):
        assert (lo, hi) == (1, 9999)
        return self.r


class TableTest(unittest.TestCase):
    def test_the_committed_table_is_the_reviewed_transcription(self):
        with open(T.TPCW_PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(),
                             TABLE_SHA256, "a change to the table is a new file version")
        doc = T.load()
        self.assertEqual(doc["source"]["pdf_sha256"], "d74231b78dadbcc0d7cc37608299ffb0749238a9ff7c1f2662d68c20bda0c65e")
        self.assertEqual(len(T.states()), 14)
        self.assertEqual(T.mixes(), ["browsing", "ordering", "shopping"])
        for mix in T.mixes():
            self.assertEqual(sum(len(r) for r in doc["mixes"][mix]["thresholds"].values()), 45, mix)

    def test_rows_sum_to_one_and_the_rule_is_the_specifications(self):
        for mix in T.mixes():
            for frm, row in T.probabilities(mix).items():
                self.assertAlmostEqual(sum(row.values()), 1.0, places=12, msg=(mix, frm))
        p = T.probabilities("browsing")["Home"]
        self.assertAlmostEqual(p["Best Sellers"], 3792 / 9999)
        self.assertAlmostEqual(p["Shopping Cart"], (9999 - 9559) / 9999)

    def test_the_worked_example_of_comment_1(self):
        # "the EB generates the random number 6371 ... the Threshold that is most immediately greater than 6371
        # is 6718. This indicates that an Order Inquiry web interaction must be selected" (Shopping table)
        self.assertEqual(T.next_state("shopping", "Home", FixedR(6371)), "Order Inquiry")
        self.assertEqual(T.next_state("shopping", "Home", FixedR(6718)), "Order Inquiry", "equal to the threshold")
        self.assertEqual(T.next_state("browsing", "Home", FixedR(1)), "Best Sellers")
        self.assertEqual(T.next_state("browsing", "Home", FixedR(9999)), "Shopping Cart")

    def test_each_chain_reproduces_its_printed_mix(self):
        for mix in T.mixes():
            pi = T.stationary(T.probabilities(mix), T.states())
            printed = T.printed_mix(mix)
            for s in T.states():
                self.assertLess(abs(pi[s] - printed[s]) / printed[s], 0.02, (mix, s, pi[s], printed[s]))

    def test_a_malformed_table_is_refused(self):
        import json
        import tempfile
        doc = T.load()
        bad = json.loads(json.dumps(doc))
        bad["mixes"]["browsing"]["thresholds"]["Home"][-1][1] = 9998
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(bad, fh)
            with self.assertRaises(T.ChainError):
                T.load(path)


class WatchedChainTest(unittest.TestCase):
    def test_the_watched_chain_keeps_the_stationary_shares_of_the_kept_states(self):
        for mix in ("browsing", "shopping"):
            w = T.watched_matrix(mix, KEPT)
            for frm, row in w.items():
                self.assertAlmostEqual(sum(row.values()), 1.0, places=10, msg=(mix, frm))
            pw = T.stationary(w, sorted(KEPT))
            pi = T.stationary(T.probabilities(mix), T.states())
            z = sum(pi[s] for s in KEPT)
            for s in KEPT:
                self.assertAlmostEqual(pw[s], pi[s] / z, places=9, msg=(mix, s))

    def test_the_walk_samples_the_watched_chain(self):
        rng, n = random.Random(7), 40_000
        walk = T.walk("browsing", rng, KEPT)
        first = next(walk)
        self.assertEqual(first, "Home", "a session starts at Home (2.2.20)")
        counts = dict.fromkeys(KEPT, 0)
        for _ in range(n):
            counts[next(walk)] += 1
        pw = T.stationary(T.watched_matrix("browsing", KEPT), sorted(KEPT))
        for s in KEPT:
            self.assertLess(abs(counts[s] / n - pw[s]), 0.01, s)
        self.assertNotIn("Shopping Cart", counts)

    def test_the_walk_is_seeded(self):
        a = T.walk("shopping", random.Random(3), KEPT)
        b = T.walk("shopping", random.Random(3), KEPT)
        self.assertEqual([next(a) for _ in range(200)], [next(b) for _ in range(200)])

    def test_search_results_always_follows_the_search_form(self):
        # the only way into Search Results is Search Request, so /search is always issued from the form page
        for mix in T.mixes():
            into = [frm for frm, row in T.probabilities(mix).items() if row.get("Search Results")]
            self.assertEqual(into, ["Search Request"], mix)


TABLE_SHA256 = "71eea96edc3b620c919a3ed7a5007856ed2669fae2121e6338b057383419122e"

if __name__ == "__main__":
    unittest.main()
