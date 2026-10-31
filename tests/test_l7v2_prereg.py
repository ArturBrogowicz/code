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

PREREG_SHA256 = "b29fd14a7fa1d0adeb170b6da785702ecb8914a9a5c6d14e11be07f251d008a0"


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
                         ([50, 100, 200, 300], [30, 60], [0.0, 10.0], "C5"))
        self.assertEqual(c["C3b"]["variant_route"], "C3")
        self.assertTrue(c["C3b"]["route_label"].startswith("re-registered 2026-10-31 by the user, before any capture"))
        self.assertIn("forward reference, confirmed by the user on 2026-10-31", c["C3b"]["costly_label"])
        self.assertIn("issued in-page from that form page", c["C3b"]["costly"])
        self.assertTrue(c["C3b"]["costly_label"].startswith("re-registered 2026-10-31 by the user, before any capture"))
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

    def test_arrivals(self):
        a = P.load()["arrivals"]
        self.assertTrue(a["label"].startswith("re-registered 2026-10-31 by the user, before any capture"))
        self.assertEqual((a["min_active_s"], a["flash_gap_s"], a["first_visit_s"]), (60.0, 60.0, [0.0, 10.0]))
        self.assertEqual({k: a["age_check"][k] for k in ("ks_max", "auc_band", "held_out_ks_max")},
                         {"ks_max": 0.3, "auc_band": 0.15, "held_out_ks_max": 0.45})
        self.assertIn("every role", a["benign"])

    def test_lifetimes_d034(self):
        # T038-01, re-registered 2026-10-31 under D-034: one lifetime law for every key unit of either role
        life = P.load()["arrivals"]["lifetimes"]
        self.assertTrue(life["label"].startswith("re-registered 2026-10-31 under D-034"))
        self.assertIn("2026-10-31T12:10:57Z", life["label"])
        self.assertEqual(life["law"], {"law": "uniform", "lo": 60.0, "hi": 420.0})
        self.assertEqual((life["gap_s"], life["min_left_s"]), ([10.0, 120.0], 60.0))
        self.assertIn("a returning user is a new key", life["benign"])
        self.assertIn("past its slot's end into the next slot", life["attack"])
        self.assertIn("one lifetime drawn from the law", life["machine_clients"])
        self.assertIn("stopped before the M3 bot starts", life["reuse"])
        rng = random.Random(3)
        draws = [P.lifetime(rng) for _ in range(4000)]
        self.assertTrue(60.0 <= min(draws) and max(draws) <= 420.0)
        self.assertAlmostEqual(sum(draws) / len(draws), 240.0, delta=6.0)
        self.assertGreater(sum(d > 240.0 for d in draws) / len(draws), 0.4, "a share of the keys outlives one slot")

    def test_the_extended_age_check_d034(self):
        a = P.load()["arrivals"]["age_check"]
        self.assertEqual({k: a[k] for k in ("ks_max", "auc_band", "held_out_ks_max")},
                         {"ks_max": 0.3, "auc_band": 0.15, "held_out_ks_max": 0.45}, "the first-seen check is unchanged")
        self.assertEqual({k: a[k] for k in ("min_views", "lifetime_ks_max", "lifetime_auc_band", "window_age_auc_band",
                                            "family_min_units", "held_out_lifetime_ks_max")},
                         {"min_views": 4, "lifetime_ks_max": 0.3, "lifetime_auc_band": 0.15, "window_age_auc_band": 0.15,
                          "family_min_units": 20, "held_out_lifetime_ks_max": 0.45})
        self.assertTrue(a["label_v2"].startswith("extended 2026-10-31 under D-034, before any capture"))
        self.assertIn("held-out families included", a["rule_v2"])
        self.assertIn("each plan user of a benign entity (a session", a["key_units_v2"])

    def test_harm(self):
        h = P.load()["harm"]
        self.assertEqual(h["never_sent_after_s"], 10.0)
        self.assertEqual(h["never_sent_schedule"], "the device's own closed loop")
        self.assertIn("the completion of the device's previous view (or request) plus that one's pause", h["never_sent_rule"])
        self.assertTrue(h["never_sent_label"].startswith("re-registered 2026-10-31 by the user, before any capture"))
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
            lambda p: p["arrivals"]["lifetimes"]["law"].update(lo=30.0),        # below min_active_s
            lambda p: p["arrivals"]["lifetimes"]["law"].update(law="lognormal"),
            lambda p: p["arrivals"]["lifetimes"].update(gap_s=[30.0, 10.0]),
        ]
        with tempfile.TemporaryDirectory() as d:
            for i, mutate in enumerate(cases):
                with self.subTest(case=i), self.assertRaises(P.PreregError):
                    P.load(self._write(d, mutate, i))


if __name__ == "__main__":
    unittest.main()
