"""L7 v2 benign navigation (ml/l7_benign.py, ml/l7_gen.py; docs/L7V2_DESIGN.md §7.2, §8.4, §12.1): TPC-W v1.8 chains,
Referer and cookies on the benign side, the search_user, exporter and flash_crowd kinds. Offline: plans are pure, and
the executor is driven against a fake session (nothing is sent)."""
import collections
import hashlib
import itertools
import json
import os
import random
import sys
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_admissibility as adm
import l7_benign as B
import l7_gen
import l7_tpcw
import l7_traffic
import l7v2_prereg as P

import l7_webapp

# the P5b plans of the base commit (11de88b), hashed by tasks/T-025a/scripts/legacy_digests.py
LEGACY_DIGEST = "4b4ab500d17109f9b488d376d1ce819a6de5b83b302dce1474a0fe59cac49651"
LEGACY_CASES = [("browser_page", {"level": 30, "first_visit_s": [0.0, 30.0]}),
                ("browser_page", {"level": 60, "first_visit_s": [0.0, 30.0], "think_mean_s": 6.0}),
                ("cgnat_browsers", {"users": 12, "level": 30, "first_visit_s": [0.0, 60.0]}),
                ("api_bulk", {"rps": [15.0, 20.0], "endpoints": [2, 3]}),
                ("crawler_polite", {"rps": [2.0, 5.0], "level": 30})]
TPCW = {"level": 30, "first_visit_s": [0.0, 30.0], "nav": "tpcw:browsing", "think_mean_s": 7.5}


def views(kind, params, seed, duration=900.0):
    plan = B.plan_client(kind, params, duration, random.Random(seed))
    return [v for u in plan["users"] for v in u["views"]]


class LegacyTest(unittest.TestCase):
    def test_p5b_plans_are_unchanged_draw_for_draw(self):
        h = hashlib.sha256()
        for kind, params in LEGACY_CASES:
            for seed in (0, 1, 2):
                h.update(json.dumps(B.plan_client(kind, params, 600.0, random.Random(seed)), sort_keys=True).encode())
        self.assertEqual(h.hexdigest(), LEGACY_DIGEST)

    def test_referer_on_the_iid_model_adds_keys_and_changes_no_draw(self):
        plain = views("browser_page", {"level": 30}, 4)
        withref = views("browser_page", {"level": 30, "referer": True}, 4)
        self.assertEqual([{k: v[k] for k in ("t", "page", "waves", "pause_s")} for v in withref], plain)
        firsts = 0
        for prev, v in zip([None, *withref], withref):
            self.assertEqual(v["doc"], v["waves"][0][0])
            if v["ref"] is None:
                firsts += 1                                     # a visit's first view: a direct navigation
            else:
                self.assertEqual(v["ref"], prev["doc"])
        self.assertGreater(firsts, 0)


class TpcwDeviceTest(unittest.TestCase):
    def test_a_session_starts_at_home_and_every_view_refers_to_the_previous_document(self):
        vs = views("browser_page", TPCW, 11)
        self.assertEqual((vs[0]["waves"][0], vs[0]["ref"], vs[0]["state"]), (["/"], None, "Home"))
        doc = None
        for v in vs:
            self.assertEqual(v["ref"], doc)
            if len(v["waves"]) == 1:                            # in-page: one request from the current document
                self.assertEqual(v["doc"], doc)
                self.assertIn(v["state"], ("Search Results", "Order Display"))
            else:
                doc = v["waves"][0][0]
                self.assertEqual(v["doc"], doc)
                self.assertEqual(l7_webapp.route_class("GET", doc), "C1")

    def test_routes_follow_the_review_rules(self):
        searches = exports = 0
        for seed in range(12):
            for v in views("browser_page", TPCW, seed, 3600.0):
                path = v["waves"][0][0]
                if path.startswith("/search"):
                    searches += 1
                    self.assertEqual(v["ref"], "/page/search", "a search is issued from the form page")
                    self.assertEqual(v["state"], "Search Results")
                if path.startswith("/export"):
                    exports += 1
                    self.assertEqual(v["state"], "Order Display")
                self.assertNotIn(v["state"], P.load()["navigation"]["unmapped"])
                if v["state"] == "Search Request":
                    self.assertEqual(path, "/page/search")
        self.assertGreater(searches, 0)
        self.assertGreater(exports, 0)

    def test_state_shares_follow_the_watched_chain(self):
        counts, n = collections.Counter(), 0
        for seed in range(40):
            for v in views("browser_page", TPCW, seed, 3600.0):
                counts[v["state"]] += 1
                n += 1
        watched = l7_tpcw.stationary(l7_tpcw.watched_matrix("browsing", set(P.routes())), sorted(P.routes()))
        for state, share in watched.items():
            self.assertLess(abs(counts[state] / n - share), 0.02, (state, counts[state] / n, share))

    def test_think_time_is_the_specifications(self):
        pauses = [v["pause_s"] for seed in range(30) for v in views("browser_page", TPCW, seed, 3600.0)]
        self.assertAlmostEqual(sum(pauses) / len(pauses), 7.5 * (1 - 2.718281828 ** -(70 / 7.5)), delta=0.35)
        self.assertLessEqual(max(pauses), 70.0)

    def test_a_device_never_fetches_an_asset_twice(self):
        for seed in range(5):
            assets = [p for v in views("browser_page", {**TPCW, "level": 60}, seed) for w in v["waves"][1:]
                      for p in w]
            self.assertEqual(len(assets), len(set(assets)))

    def test_the_mix_kinds_are_the_nav_param_under_their_own_names(self):
        params = {"level": 30, "first_visit_s": [0.0, 30.0], "think_mean_s": 7.5}
        for mix in ("browsing", "shopping"):
            a = B.plan_client(f"tpcw_{mix}", params, 900.0, random.Random(8))
            b = B.plan_client("browser_page", {**params, "nav": f"tpcw:{mix}"}, 900.0, random.Random(8))
            self.assertEqual(a["users"], b["users"])
            self.assertEqual(a["kind"], f"tpcw_{mix}")

    def test_the_held_out_mix_and_cgnat(self):
        shop = views("browser_page", {**TPCW, "nav": "tpcw:shopping"}, 3, 3600.0)
        self.assertEqual(shop[0]["state"], "Home")
        plan = B.plan_client("cgnat_browsers", {"users": 12, "level": 30, "nav": "tpcw:browsing"}, 900.0,
                             random.Random(2))
        self.assertEqual(len(plan["users"]), 12)
        self.assertTrue(all(u["views"][0]["state"] == "Home" for u in plan["users"] if u["views"]))
        with self.assertRaises(ValueError):
            views("browser_page", {**TPCW, "nav": "tpcw:nowhere"}, 1)


class NewKindsTest(unittest.TestCase):
    def test_search_user(self):
        vs = views("search_user", {"level": 30}, 5, 3600.0)
        self.assertEqual([v["state"] for v in vs[:3]], ["Home", "Search Request", "Search Results"])
        after = collections.Counter()
        for a, b in itertools.pairwise(vs):
            if a["state"] == "Search Results":
                after[b["state"]] += 1
                self.assertEqual(a["ref"], "/page/search")
            if a["state"] == "Product Detail":
                self.assertEqual(b["state"], "Search Request")
        share = after["Product Detail"] / sum(after.values())
        self.assertAlmostEqual(share, P.load()["benign_kinds"]["search_user"]["p_detail"], delta=0.12)

    def test_exporter(self):
        vs = views("exporter", {"level": 30}, 6, 3600.0)
        self.assertGreater(len(vs), 4)
        for a, b in zip(vs[::2], vs[1::2]):
            self.assertEqual((a["state"], a["ref"], a["waves"][0]), ("Order Inquiry", None, ["/page/account"]))
            self.assertEqual((b["state"], b["ref"]), ("Order Display", "/page/account"))
            self.assertRegex(b["waves"][0][0], r"^/export\?r=\d{1,4}$")
        visits = [v["t"] for v in vs if v["state"] == "Order Inquiry"]
        self.assertTrue(all(b - a >= 60.0 for a, b in itertools.pairwise(visits)))

    def test_flash_crowd_arrives_within_its_minute(self):
        for seed in range(20):
            vs = views("flash_crowd", {"level": 30}, seed, 600.0)
            self.assertLess(vs[0]["t"], 60.0)
            self.assertEqual(vs[0]["state"], "Home")

    def test_search_and_export_paths_are_the_sites(self):
        rng = random.Random(1)
        self.assertRegex(l7_webapp.search_path(rng), r"^/search\?q=[a-z]+$")
        self.assertEqual(l7_webapp.route_class("GET", l7_webapp.search_path(rng)), "C3")
        self.assertEqual(l7_webapp.route_class("GET", l7_webapp.export_path(rng)), "C5")
        sys.path.insert(0, os.path.join(REPO, "bench"))
        import origin
        self.assertEqual(l7_webapp.SEARCH_WORDS, origin.WORDS, "the terms the origin's search ranks")

    def test_new_kinds_pass_the_admissibility_gate(self):
        lim = l7_traffic.PROFILES["tolerant"]
        for kind, params in (("browser_page", {**TPCW, "level": 60}), ("browser_page", TPCW),
                             ("search_user", {"level": 30}), ("exporter", {"level": 60}),
                             ("flash_crowd", {"level": 60}),
                             ("cgnat_browsers", {"users": 24, "level": 30, "nav": "tpcw:browsing"}),
                             ("browser_page", {"level": 60, "referer": True})):
            rep = adm.check_spec(kind, params, 900.0, range(4), lim)
            self.assertTrue(rep["admissible"], (kind, params, rep["trips"]))


class FakeSession:
    def __init__(self, log):
        self.log, self.headers = log, {}

    def get(self, url, verify=False, timeout=10, headers=None):
        self.log.append((url, (headers or {}).get("Referer")))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ExecutorTest(unittest.TestCase):
    def run_device(self, vs):
        log = []
        with mock.patch.object(l7_gen, "_session", lambda ua, conns: FakeSession(log)), \
                mock.patch.object(l7_gen.time, "sleep", lambda s: None):
            l7_gen._browser_device("http://10.0.0.1:80", {"ua": "UA", "views": vs}, l7_gen.time.time() - 1e6,
                                   l7_gen.time.time() + 1e6)
        return log

    def test_tpcw_views_send_their_referers(self):
        vs = views("browser_page", TPCW, 9, 300.0)
        base = "http://10.0.0.1:80"
        want = []
        for v in vs:
            want.append((base + v["waves"][0][0], base + v["ref"] if v["ref"] else None))
            want += [(base + p, base + v["doc"]) for wave in v["waves"][1:] for p in wave]
        self.assertEqual(sorted(self.run_device(vs), key=repr), sorted(want, key=repr))

    def test_legacy_views_send_no_referer(self):
        vs = views("browser_page", {"level": 30}, 9, 300.0)
        self.assertTrue(all(ref is None for _, ref in self.run_device(vs)))

    def test_the_new_kinds_are_registered(self):
        for kind in B.L7V2_KINDS:
            self.assertIs(l7_gen.resolve("benign", kind), getattr(l7_gen, f"benign_{kind}"))


if __name__ == "__main__":
    unittest.main()
