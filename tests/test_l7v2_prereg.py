"""The L7 v2 traffic-side pre-registration (ml/l7v2_prereg.json), docs/L7V2_DESIGN.md section 13: every frozen value is
pinned here, so a change shows up as a failing test and must become a new file version. Offline and pure."""
import hashlib
import json
import os
import random
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_tpcw
import l7v2_prereg as P

PREREG_SHA256 = "6a42743f73b50cc448a7074d78a38b6c882fb8e2cfb1b9f4b25984e63887f13b"


class FrozenFileTest(unittest.TestCase):
    def test_the_file_is_the_frozen_version(self):
        with open(P.PREREG_PATH, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), PREREG_SHA256)
        self.assertEqual(P.load()["format"], "l7v2-prereg/1")

    def test_navigation(self):
        nav = P.load()["navigation"]
        self.assertEqual((nav["train_mix"], nav["held_out_mixes"], nav["unused_mixes"]),
                         ("browsing", ["shopping"], ["ordering"]))
        self.assertEqual(nav["iid_zipf"], "held_out")
        self.assertEqual(nav["session_start"], "Home")
        self.assertEqual(nav["think"]["mean_s"], 7.0)
        self.assertEqual(nav["think"]["cap_s"], 70.0)
        self.assertEqual(P.routes(), {
            "Home": ("page", "/"), "Product Detail": ("product", "/page/<n>"), "New Products": ("page", "/page/new"),
            "Best Sellers": ("page", "/page/best"), "Search Request": ("page", "/page/search"),
            "Search Results": ("inpage", "search"), "Order Inquiry": ("page", "/page/account"),
            "Order Display": ("inpage", "export")})
        self.assertEqual(sorted(nav["unmapped"]), ["Admin Confirm", "Admin Request", "Buy Confirm", "Buy Request",
                                                    "Customer Registration", "Shopping Cart"])
        self.assertEqual(nav["product_popularity"], {"law": "Zipf", "alpha": 0.75, "pages": 200,
                                                      "note": "ASSUMPTION kept from P5b (ml/l7_benign.py)"})
        self.assertEqual(P.page_states(), {"Home", "Product Detail", "New Products", "Best Sellers",
                                           "Search Request", "Order Inquiry"})

    def test_the_review_rules_hold(self):
        # T-018 review: the Search Request form page is not /search; the Order group is not /export
        r = P.routes()
        self.assertEqual(r["Search Request"][0], "page")
        self.assertEqual([s for s, v in r.items() if v == ("inpage", "search")], ["Search Results"])
        self.assertEqual([s for s, v in r.items() if v == ("inpage", "export")], ["Order Display"])
        for s in ("Shopping Cart", "Customer Registration", "Buy Request", "Buy Confirm"):
            self.assertNotIn(s, r)

    def test_the_mapped_shares(self):
        # the shares of the browsing interactions that reach /search and /export, from the printed mix
        mix = l7_tpcw.printed_mix("browsing")
        self.assertAlmostEqual(mix["Search Results"], 0.11)
        self.assertAlmostEqual(mix["Order Display"], 0.0025)
        unmapped = sum(mix[s] for s in P.load()["navigation"]["unmapped"])
        self.assertAlmostEqual(unmapped, 0.0445, places=6)

    def test_benign_kinds(self):
        b = P.load()["benign_kinds"]
        self.assertEqual(b["search_user"]["p_detail"], 0.619462)
        self.assertAlmostEqual(b["search_user"]["p_detail"],
                               l7_tpcw.probabilities("browsing")["Search Results"]["Product Detail"], places=6)
        self.assertEqual(b["exporter"]["visit_gap_s"], [60.0, 300.0])
        self.assertEqual(b["exporter"]["first_visit_s"], [0.0, 120.0])
        self.assertEqual((b["flash_crowd"]["users"], b["flash_crowd"]["arrive_within_s"], b["flash_crowd"]["held_out"]),
                         (30, 60.0, True))
        self.assertEqual(P.load()["export_r"], {"law": "uniform integer", "lo": 1, "hi": 1000,
                                                "note": "r changes only the URL's work factor (bench/origin.py)"})

    def test_classes(self):
        c = P.load()["classes"]
        self.assertEqual((c["C2"]["route"], c["C2"]["variant_route"], c["C2"]["sources_p1"], c["C2"]["pacing"]),
                         ("C3", "C5", 100, "Poisson"))
        self.assertEqual((c["C3a"]["page_gap_s"], c["C3a"]["sources_bounds"], c["C3a"]["route"]),
                         ([2.0, 8.0], [50, 100], "C3"))
        self.assertEqual((c["C3b"]["ladder_bots"], c["C3b"]["level_choices"], c["C3b"]["first_view_s"], c["C3b"]["route"]),
                         ([50, 100, 200, 300], [30, 60], [0.0, 10.0], "C3"))
        self.assertEqual({k: v["role"] for k, v in c.items()},
                         {"C2": "control", "C3a": "control", "C3b": "the GRU's fair chance"})

    def test_mimicry(self):
        m = P.load()["mimicry"]
        self.assertEqual(m["M1"]["dwell_s"], {"law": "constant", "value": 3.0})
        self.assertEqual(m["M2"]["dwell_s"], {"law": "uniform", "lo": 2.0, "hi": 12.0})
        self.assertEqual(m["M3"]["dwell_s"], {"law": "uniform", "lo": 2.0, "hi": 12.0})
        self.assertEqual(m["M2exp"]["dwell_s"], {"law": "negative exponential, truncated", "mean": 7.0, "cap": 70.0})
        self.assertEqual({k: m[k]["held_out"] for k in P.MIMICRY},
                         {"M1": False, "M2": False, "M3": True, "M2exp": True})
        rng = random.Random(1)
        self.assertEqual(P.dwell("M1", rng), 3.0)
        d = [P.dwell("M2", rng) for _ in range(2000)]
        self.assertTrue(2.0 <= min(d) and max(d) <= 12.0)
        self.assertAlmostEqual(sum(d) / len(d), 7.0, delta=0.25)
        e = [P.dwell("M2exp", rng) for _ in range(4000)]
        self.assertLessEqual(max(e), 70.0)
        self.assertAlmostEqual(sum(e) / len(e), 7.0, delta=0.4)

    def test_harm(self):
        h = P.load()["harm"]
        self.assertEqual(h["never_sent_after_s"], 10.0)
        self.assertEqual((h["cross_check"]["client_dq_pp"], h["cross_check"]["server_q_min"]), (10.0, 99.0))
        self.assertEqual((h["ladder"]["levels"], h["ladder"]["repeats"]), ([1, 2, 4, 8], 2))
        self.assertIn("only a frozen calibration record", h["verdict_record"])


class ConsistencyTest(unittest.TestCase):
    def _write(self, d, mutate, i):
        pre = json.loads(json.dumps(P.load()))
        mutate(pre)
        path = os.path.join(d, f"p{i}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(pre, fh)
        return path

    def test_inconsistent_files_are_refused(self):
        cases = [
            lambda p: p.update(format="l7v2-prereg/0"),
            lambda p: p["navigation"]["unmapped"].append("Home"),                  # routed and unmapped
            lambda p: p["navigation"]["unmapped"].remove("Shopping Cart"),         # neither
            lambda p: p["navigation"]["routes"].update({"Shopping Cart": ["inpage", "cart"]}),
            lambda p: p["navigation"].update(unused_mixes=[]),
            lambda p: p["mimicry"].pop("M3"),
        ]
        with tempfile.TemporaryDirectory() as d:
            for i, mutate in enumerate(cases):
                with self.subTest(case=i), self.assertRaises(P.PreregError):
                    P.load(self._write(d, mutate, i))


if __name__ == "__main__":
    unittest.main()
