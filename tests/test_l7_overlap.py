"""Unit tests for the P5b benign-overlap pieces (docs/L7_GRU_DESIGN.md §7.2, §7.2.1):
the benign client plans (ml/l7_benign), the admissibility gate's replicas of the
deployed mechanisms (ml/l7_admissibility), and the overlap mix in the plan. Offline:
nothing is sent, no namespaces.
"""
import os
import random
import re
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_admissibility as adm
import l7_benign
import l7_traffic

import l7_dataset
import l7_webapp

FAST_GATE = (0, 1)        # two simulated seeds keep the plan tests quick


class BenignPlanTest(unittest.TestCase):
    def test_plans_are_seeded(self):
        for kind, params in (("browser_page", {"level": 30}),
                             ("cgnat_browsers", {"users": 4, "level": 30}),
                             ("api_bulk", {"rps": [15, 20]}),
                             ("crawler_polite", {"rps": [2, 5]})):
            a = l7_benign.plan_client(kind, params, 120, random.Random(5))
            b = l7_benign.plan_client(kind, params, 120, random.Random(5))
            self.assertEqual(a, b, kind)

    def test_cold_view_loads_level_assets_and_cache_holds(self):
        views = l7_benign.plan_client("browser_page", {"level": 30}, 600,
                                      random.Random(2))["users"][0]["views"]
        first = views[0]
        self.assertEqual(first["waves"][0], [f"/page/{first['page']}"])
        self.assertEqual(sum(len(w) for w in first["waves"]), 31)      # HTML + 30 assets
        seen = set()
        for v in views:                      # an asset is never requested twice
            for wave in v["waves"][1:]:
                self.assertFalse(seen & set(wave))
                seen.update(wave)
        self.assertTrue(all(len(v["waves"][1]) == 0 for v in views[1:]))   # CSS/JS cached

    def test_cgnat_users_share_uas_sometimes(self):
        plan = l7_benign.plan_client("cgnat_browsers", {"users": 24, "level": 30}, 60,
                                     random.Random(1))
        uas = [u["ua"] for u in plan["users"]]
        self.assertEqual(len(uas), 24)
        self.assertLess(len(set(uas)), 24)                  # identical reduced strings collide
        self.assertTrue(all(ua in {u for _, u in l7_benign.UA_TABLE} for ua in uas))

    def test_paced_kinds(self):
        api = l7_benign.plan_client("api_bulk", {"rps": [15, 20], "endpoints": [2, 3]}, 60,
                                    random.Random(3))
        self.assertTrue(15 <= api["rps"] <= 20)
        paths = {p for p, _ in api["users"][0]["requests"]}
        self.assertLessEqual(paths, set(api["endpoints"]))
        crawl = l7_benign.plan_client("crawler_polite", {"rps": [2, 5]}, 60, random.Random(4))
        reqs = crawl["users"][0]["requests"]
        self.assertEqual(reqs[0][0], "/robots.txt")
        self.assertTrue(all(l7_webapp.route_status("GET", p) == 200 for p, _ in reqs))

    def test_zipf_and_ua_draws_are_in_range(self):
        rng = random.Random(0)
        pages = [l7_benign.zipf_page(rng) for _ in range(5000)]
        self.assertTrue(all(1 <= p <= l7_benign.PAGE_UNIVERSE for p in pages))
        self.assertGreater(pages.count(1), pages.count(50))             # popularity skew

    def test_generator_knows_the_new_kinds(self):
        for kind in l7_benign.KINDS:
            r = subprocess.run([sys.executable, os.path.join(REPO, "ml", "l7_gen.py"),
                                "--role", "benign", "--kind", kind, "--host", "10.0.0.1",
                                "--port", "443", "--duration", "5", "--plan"],
                               capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)


class MechanismReplicaTest(unittest.TestCase):
    def test_rate_rule_clamps_a_burst_to_one_second(self):
        burst = [0.001 * i for i in range(61)]                     # 61 requests in 61 ms
        rps, banned = adm.l7_rate_scan(burst, [200] * 61)
        self.assertEqual(rps, 61.0)
        self.assertTrue(banned)
        rps, banned = adm.l7_rate_scan(burst[:31], [200] * 31)
        self.assertEqual(rps, 31.0)
        self.assertFalse(banned)

    def test_rate_rule_error_branch_and_503(self):
        ts = [i / 20 for i in range(200)]                           # 20 rps for 10 s
        self.assertTrue(adm.l7_rate_scan(ts, [401] * 200)[1])      # > 0.8 errors, > 10 rps
        self.assertFalse(adm.l7_rate_scan(ts, [503] * 200)[1])     # 503 is not an error
        slow = [i / 5 for i in range(50)]                          # 5 rps: under 10
        self.assertFalse(adm.l7_rate_scan(slow, [401] * 50)[1])

    def test_limit_req_bucket(self):
        rejected, peak = adm.limit_req_scan([0.0] * 150)
        self.assertEqual(rejected, 49)              # 1 free + burst 100, then rejected
        self.assertEqual(peak, 100)
        self.assertEqual(adm.limit_req_scan([i / 25 for i in range(500)])[0], 0)   # 25 r/s

    def test_max_concurrent(self):
        self.assertEqual(adm.max_concurrent([(0, 1), (0.5, 2), (1, 3), (2.5, 4)]), 2)

    def test_slowconn_needs_conns_and_quiet(self):
        ten = [(0.0, 100.0)] * 10
        self.assertTrue(adm.slowconn_scan(ten, [], 20.0)[0])
        busy = [i * 0.5 for i in range(40)]
        self.assertFalse(adm.slowconn_scan(ten, busy, 20.0)[0])
        self.assertFalse(adm.slowconn_scan([(0.0, 100.0)] * 7, [], 20.0)[0])

    def test_device_keeps_connections_alive_for_the_timeout(self):
        views = [{"t": 0.0, "waves": [["/page/1"], [f"/static/{i}.css" for i in range(12)], []],
                  "pause_s": 40.0},
                 {"t": 40.0, "waves": [["/page/2"], [], []], "pause_s": 1.0}]
        reqs, spans = adm._device_requests(views, 6)
        self.assertEqual(len(reqs), 14)
        self.assertEqual(adm.max_concurrent([(s, e) for s, e, _, _ in reqs]), 6)
        # 6 connections opened by the first view, closed 15 s after their last use; the
        # second view (40 s later) reopens one.
        self.assertEqual(len(spans), 7)
        self.assertTrue(all(c - o <= 15.1 for o, c in spans))


class LimitsMatchSourceTest(unittest.TestCase):
    def test_limits_match_control_plane_and_nginx(self):
        with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
            cp = fh.read()
        with open(os.path.join(REPO, "nginx.conf"), encoding="utf-8") as fh:
            ng = fh.read()
        t = l7_traffic.THRESHOLDS
        for name, key in (("HEURISTIC_WINDOW", "l7_rate_window_s"),
                          ("HEURISTIC_MIN_REQUESTS", "l7_rate_min_requests"),
                          ("HEURISTIC_ERROR_RATIO", "l7_error_ratio"),
                          ("SLOWCONN_IDLE_BYTES", "slowconn_idle_bytes"),
                          ("SLOWCONN_CONSECUTIVE", "slowconn_consecutive"),
                          ("L4_POLL_INTERVAL", "l4_poll_interval_s")):
            m = re.search(rf"^{name} = ([0-9.]+)", cp, re.MULTILINE)
            self.assertIsNotNone(m, name)
            self.assertEqual(float(m.group(1)), float(t[key]), name)
        self.assertIn("error_ratio > HEURISTIC_ERROR_RATIO and rps > 10", cp)
        self.assertEqual(t["l7_error_min_rps"], 10)
        self.assertIn("rps = len(entries) / max(window_duration, 1.0)", cp)
        self.assertIn("is_error = status >= 400 and status != 503", cp)
        self.assertIn(f"burst={t['nginx_limit_req_burst']} nodelay", ng)
        self.assertIn(f"limit_conn connlimit {t['nginx_limit_conn']};", ng)
        self.assertIn(f"keepalive_timeout {t['nginx_keepalive_timeout_s']}s;", ng)
        self.assertIs(adm.LIMITS, t)


class CalibrationR10Test(unittest.TestCase):
    def test_error_ratio_branch_is_reported(self):
        rep = l7_traffic.calibrate(enforce=False)
        self.assertTrue(rep["calibrated"])                 # trained attacks still clean
        cred = next(r for r in rep["held_out"] if r["family"] == "credstuff")
        self.assertEqual(cred["error_ratio"], 1.0)
        self.assertTrue(any("error-ratio" in v for v in cred["violations"]))
        flood = next(r for r in rep["trained"] if r["family"] == "subthreshold_flood")
        self.assertEqual(flood["error_ratio"], 0.0)

    def test_trained_error_attack_is_rejected(self):
        bad = [l7_traffic.AttackSpec("x", "rate", params={"rps": 20, "path": "/nope"})]
        with self.assertRaises(l7_traffic.CalibrationError):
            l7_traffic.calibrate(trained=bad)


class OverlapMixTest(unittest.TestCase):
    def test_overlap_mix_keeps_the_p5_plan(self):
        p5 = l7_traffic.build_plan(1, 12, 300.0)
        ov = l7_traffic.build_plan(1, 12, 300.0, benign_mix="overlap", gate_seeds=FAST_GATE)
        self.assertEqual(p5[0], ov[0][:12])                         # the P5 benign clients
        self.assertEqual(p5[1], ov[1])                              # attackers
        self.assertEqual(p5[2], ov[2])                              # schedule
        added = ov[0][12:]
        self.assertTrue(added)
        self.assertTrue(all(c["mix"] == "overlap" for c in added))
        gate = ov[3]["benign_gate"]
        ips = {c["ip"] for c in added}
        for j, r in enumerate(gate["benign"]):        # fixed IPs; dropped kinds not launched
            self.assertEqual(f"10.0.1.{13 + j}" in ips, r["admissible"])

    def test_heldout_benign_is_labelled(self):
        ov = l7_traffic.build_plan(2, 12, 300.0, benign_mix="overlap", gate_seeds=FAST_GATE)
        ip_map = l7_dataset.build_ip_map(ov[0], ov[1])
        held = [ip for ip, e in ip_map.items() if e["class"] == "benign" and e["held_out"]]
        self.assertEqual([ip_map[ip]["kind"] for ip in held], ["api_bulk"])
        self.assertEqual(l7_dataset.label_for(held[0], ip_map), ("benign", None, True))

    def test_profiles_of_p5_clients_unchanged(self):
        import capture_l7

        class A:
            seed, benign, duration, no_held_out, no_flood = 3, 12, 300.0, False, False
        a = A()
        a.mix = "p5"
        p5 = capture_l7.build_plan(a)[0]
        a.mix, a.gate_seeds = "overlap", FAST_GATE
        ov = capture_l7.build_plan(a)[0]
        self.assertEqual([c["profile"] for c in p5], [c["profile"] for c in ov[:12]])

    def test_unknown_mix_rejected(self):
        with self.assertRaises(ValueError):
            l7_traffic.build_plan(1, 12, 300.0, benign_mix="other")

    def test_gate_drops_the_heavy_page_and_reports_overlap(self):
        gate = l7_traffic.benign_gate(FAST_GATE)
        by = {(r["kind"], r["params"].get("level"), r["params"].get("users")): r
              for r in gate["benign"]}
        self.assertFalse(by[("browser_page", 60, None)]["admissible"])     # 61 rps > 50
        self.assertIn("l7_rate", by[("browser_page", 60, None)]["trips"])
        self.assertTrue(by[("browser_page", 30, None)]["admissible"])
        self.assertTrue(by[("crawler_polite", 30, None)]["admissible"])
        self.assertEqual(set(gate["overlap"]), {"O1_peak", "O2_sustained"})


if __name__ == "__main__":
    unittest.main()
