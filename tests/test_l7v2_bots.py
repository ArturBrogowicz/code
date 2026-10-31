"""The L7 v2 classes C2, C3a and C3b (ml/l7_bots.py; docs/L7V2_DESIGN.md §7.1, §12 items 2 and 4) and their execution by
ml/l7_gen.py. Offline: plans are pure, and the executor is driven against a fake session (nothing is sent)."""
import ast
import os
import random
import subprocess
import sys
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_bots
import l7_gen
import l7_traffic
import l7v2_prereg as P

import l7_webapp

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"


def plan(family, params, seed=1, duration=600.0):
    return l7_bots.plan_bot(family, {"ua": UA, **params}, duration, random.Random(seed))["users"][0]


class GuardTest(unittest.TestCase):
    def test_the_bot_module_imports_nothing_from_the_benign_planner(self):
        with open(os.path.join(REPO, "ml", "l7_bots.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertEqual(names, {"os", "random", "sys", "l7_tpcw", "l7v2_prereg", "l7_webapp"})
        code = (f"import sys; sys.path[:0] = [{REPO!r}, {os.path.join(REPO, 'ml')!r}]; import l7_bots; "
                "print('l7_benign' in sys.modules)")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "False")


class C2Test(unittest.TestCase):
    def test_poisson_requests_to_one_costly_route(self):
        reqs = plan("C2", {"rps": 0.5, "route": "C3"}, 3, 20_000.0)["requests"]
        gaps = [g for _, g, _ in reqs]
        self.assertAlmostEqual(sum(gaps) / len(gaps), 2.0, delta=0.15)
        self.assertTrue(all(l7_webapp.route_class("GET", p) == "C3" for p, _, _ in reqs))
        self.assertEqual({r for _, _, r in reqs}, {"/page/search"})
        exp = plan("C2", {"rps": 0.5, "route": "C5"})["requests"]
        self.assertTrue(all(p.startswith("/export?r=") and r == "/page/account" for p, _, r in exp))

    def test_bad_parameters_are_refused(self):
        for family, params in (("C2", {"rps": 0}), ("C2", {"rps": 1, "route": "C1"}), ("C9", {}),
                               ("C3b@M2", {"level": 30, "mimicry": "M1"})):
            with self.subTest(family=family, params=params), self.assertRaises(l7_bots.BotPlanError):
                plan(family, params)
        with self.assertRaises(l7_bots.BotPlanError):
            l7_bots.plan_bot("C2", {"rps": 1}, 60.0, random.Random(0))          # no UA


class C3aTest(unittest.TestCase):
    def test_a_page_then_its_costly_request_then_a_gap(self):
        reqs = plan("C3a", {"route": "C3"})["requests"]
        pages, costly = reqs[0::2], reqs[1::2]
        prev = None
        for (page, g0, ref0), (path, gap, ref1) in zip(pages, costly):
            self.assertEqual(l7_webapp.route_class("GET", page), "C1")
            self.assertEqual((g0, ref0), (0.0, prev))
            self.assertEqual((l7_webapp.route_class("GET", path), ref1), ("C3", page))
            self.assertTrue(2.0 <= gap <= 8.0)
            prev = page
        self.assertFalse([p for p, _, _ in reqs if p.startswith("/static/")], "no assets")


FORM = {"C3": "/page/search", "C5": "/page/account"}
C3B_ROUTE = P.load()["classes"]["C3b"]["route"]


class C3bTest(unittest.TestCase):
    def check_views(self, views, route=None, deep_links=True):
        """Cycles of (navigation view, the form page, one in-page costly request), each step a dwell after the last."""
        route = route or C3B_ROUTE
        doc, seen, assets = None, set(), []
        for i, v in enumerate(views):
            step = i % 3
            if step == 2:                                   # the costly request, from the form page
                self.assertEqual(len(v["waves"]), 1)
                self.assertEqual(l7_webapp.route_class("GET", v["waves"][0][0]), route)
                self.assertEqual((v["ref"], v["doc"]), (FORM[route], FORM[route]))
                continue
            page = v["waves"][0][0]
            self.assertEqual((v["ref"], v["doc"], len(v["waves"])), (doc, page, 3))
            assets += [p for w in v["waves"][1:] for p in w]
            if step == 1:
                self.assertEqual(page, FORM[route])
            elif page.startswith("/page/") and page[6:].isdigit():
                self.assertNotIn(page, seen, "no revisit of a product page")
                seen.add(page)
            elif deep_links:
                self.fail(f"a deep-link bot loaded {page}")
            doc = page
        self.assertEqual(len(assets), len(set(assets)), "a browser cache: no asset twice")
        return [v for i, v in enumerate(views) if i % 3 == 0]

    def test_m1_constant_dwell(self):
        u = plan("C3b@M1", {"level": 30})
        self.check_views(u["views"])
        self.assertEqual({v["pause_s"] for v in u["views"]}, {3.0})
        self.assertLess(u["views"][0]["t"], 10.0)

    def test_m2_uniform_dwell_and_the_c3_variant(self):
        vs = plan("C3b@M2", {"level": 60}, 2, 1200.0)["views"]
        self.check_views(vs)
        self.assertTrue(all(2.0 <= v["pause_s"] <= 12.0 for v in vs))
        self.check_views(plan("C3b@M2", {"level": 30, "route": "C3"})["views"], route="C3")

    def test_m3_walks_the_page_states_of_the_benign_chain(self):
        vs = plan("C3b@M3", {"level": 30}, 4, 6000.0)["views"]
        nav = self.check_views(vs, deep_links=False)
        self.assertEqual(vs[0]["waves"][0][0], "/", "the chain's sessions start at Home")
        self.assertTrue({"/", "/page/new", "/page/best", "/page/search"} <= {v["waves"][0][0] for v in nav})
        self.assertTrue(all(2.0 <= v["pause_s"] <= 12.0 for v in vs))

    def test_m2exp_benign_think_law(self):
        vs = [v for s in range(10) for v in plan("C3b@M2exp", {"level": 30}, s, 3000.0)["views"]]
        self.assertLessEqual(max(v["pause_s"] for v in vs), 70.0)
        self.assertAlmostEqual(sum(v["pause_s"] for v in vs) / len(vs), 7.0, delta=0.5)

    def test_the_product_universe_restarts_after_it_is_exhausted(self):
        nav = plan("C3b@M1", {"level": 30}, 5, 9 * 450.0)["views"][0::3]      # revisits begin only after all 200
        pages = [v["waves"][0][0] for v in nav]
        self.assertEqual(len(set(pages[:200])), 200)
        self.assertGreater(len(pages), 200)

    def test_c3b_costly_requests_are_exports_from_the_export_page(self):
        # the user's 2026-10-31 decision: C3b aims at export, from the page that benign exporters load
        import l7_benign
        ex = l7_benign.plan_client("exporter", {"level": 30}, 3600.0, random.Random(3))["users"][0]["views"]
        export_page = {v["ref"] for v in ex if v["waves"][0][0].startswith("/export")}
        self.assertEqual(export_page, {"/page/account"})
        for family in ("C3b@M1", "C3b@M2", "C3b@M3", "C3b@M2exp"):
            costly = plan(family, {"level": 30}, 9, 1200.0)["views"][2::3]
            self.assertGreater(len(costly), 10, family)
            for v in costly:
                self.assertEqual(l7_webapp.route_class("GET", v["waves"][0][0]), "C5", family)
                self.assertRegex(v["waves"][0][0], r"^/export\?r=\d{1,4}$")
                self.assertEqual(v["ref"], "/page/account", family)

    def test_costly_requests_carry_no_placement_tell(self):
        # T-030 L7V2-04: like a benign search, the costly request names its form page and comes a dwell after it
        vs = plan("C3b@M2", {"level": 30}, 6, 3000.0)["views"]
        for form_view, costly in zip(vs[1::3], vs[2::3], strict=False):
            self.assertEqual(costly["ref"], form_view["waves"][0][0])
            self.assertGreaterEqual(costly["t"] - form_view["t"], 2.0)
            self.assertAlmostEqual(costly["t"] - form_view["t"], form_view["pause_s"], places=3)


class CalibrationTest(unittest.TestCase):
    def test_c2_is_a_rate_family_and_c3_a_navigation_family(self):
        ok = l7_traffic._check_spec(l7_traffic.AttackSpec("C2", "rate", False, {"rps": 0.7, "route": "C3"}))
        self.assertEqual((ok["violations"], ok["error_ratio"]), ([], 0.0))
        bad = l7_traffic._check_spec(l7_traffic.AttackSpec("C2", "rate", False, {"rps": 60, "route": "C3"}))
        self.assertTrue(bad["violations"])
        nav = l7_traffic._check_spec(l7_traffic.AttackSpec("C3b@M2", "nav", False, {"level": 30}))
        self.assertEqual(nav["violations"], [])
        self.assertIn("harm ladder", nav["note"])


class FakeSession:
    def __init__(self, log):
        self.log, self.headers = log, {}

    def get(self, url, verify=False, timeout=10, headers=None):
        self.log.append((url, (headers or {}).get("Referer")))

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ExecutionTest(unittest.TestCase):
    def test_every_class_is_registered(self):
        for family in l7_bots.FAMILIES:
            self.assertEqual(l7_gen.resolve("attack", family).__name__, "attack_" + family.replace("@", "_").lower())

    def test_a_c3a_plan_runs_with_its_referers(self):
        log = []
        with mock.patch.object(l7_gen, "_session", lambda ua, conns: FakeSession(log)), \
                mock.patch.object(l7_gen.time, "sleep", lambda s: None):
            l7_gen.resolve("attack", "C3a")("10.0.0.1", 80, {"ua": UA}, 30.0, random.Random(3))
        want = l7_bots.plan_bot("C3a", {"ua": UA}, 30.0, random.Random(3))["users"][0]["requests"]
        base = "http://10.0.0.1:80"
        self.assertEqual(log, [(base + p, base + r if r else None) for p, _, r in want])

    def test_benign_paced_users_still_send_no_referer(self):
        log = []
        with mock.patch.object(l7_gen, "_session", lambda ua, conns: FakeSession(log)), \
                mock.patch.object(l7_gen.time, "sleep", lambda s: None):
            l7_gen._paced_user("http://h", {"ua": "x", "requests": [("/api/sync", 0.1), ("/api/items", 0.1)]},
                               l7_gen.time.time() + 100)
        self.assertEqual(log, [("http://h/api/sync", None), ("http://h/api/items", None)])

    def test_the_prereg_values_are_the_ones_used(self):
        self.assertEqual(P.load()["classes"]["C3a"]["page_gap_s"], [2.0, 8.0])
        self.assertEqual(l7_bots.PRODUCT_PAGES, P.load()["navigation"]["product_popularity"]["pages"])


if __name__ == "__main__":
    unittest.main()
