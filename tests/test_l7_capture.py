"""Unit tests for the P3 capture pieces (docs/L7_GRU_DESIGN.md §6). All offline:
the web app is driven through WSGI, the generators only via --plan / scope-lock,
and the plan/dataset/calibration are pure functions. No namespaces, no traffic.
"""
import io
import json
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_gen
import l7_traffic

import l7_dataset
import l7_webapp


def wsgi(method, path, body=b"", qs=""):
    """Drive l7_webapp.app once; return (status, headers, body_bytes)."""
    cap = {}

    def start_response(status, headers):
        cap["status"] = status
        cap["headers"] = dict(headers)

    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    chunks = l7_webapp.app(environ, start_response)
    return cap["status"], cap["headers"], b"".join(chunks)


class WebappTest(unittest.TestCase):
    def test_routes_and_status_classes(self):
        self.assertEqual(wsgi("GET", "/")[0], "200 OK")
        self.assertEqual(wsgi("GET", "/api/status")[0], "200 OK")
        self.assertEqual(wsgi("POST", "/login", b'{"u":"a","p":"b"}')[0], "401 Unauthorized")
        self.assertEqual(wsgi("GET", "/nope")[0], "404 Not Found")
        status, _, body = wsgi("POST", "/upload", b"x" * 1234)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(body)["received"], 1234)

    def test_response_sizes_vary_by_path_and_match_content_length(self):
        sizes = {}
        for p in ("/page/1", "/page/2", "/page/7", "/static/3.css", "/static/9.png"):
            status, headers, body = wsgi("GET", p)
            self.assertEqual(status, "200 OK")
            self.assertEqual(int(headers["Content-Length"]), len(body))
            sizes[p] = len(body)
        self.assertGreater(len(set(sizes.values())), 2)            # sizes differ by path

    def test_sizes_are_process_independent(self):
        # Not Python's salted hash(): a subprocess must produce the same sizes.
        code = (f"import sys; sys.path.insert(0, {REPO!r}); import l7_webapp as w; "
                "print(w._size_for('/static/3.css'), w._stable_hash('/page/7'))")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             check=True, env={**os.environ, "PYTHONHASHSEED": "7"})
        self.assertEqual(out.stdout.split(),
                         [str(l7_webapp._size_for("/static/3.css")),
                          str(l7_webapp._stable_hash("/page/7"))])

    def test_large_download_and_search_delay(self):
        self.assertEqual(len(wsgi("GET", "/download/large")[2]), l7_webapp.DOWNLOAD_BYTES)
        import time
        t = time.time()
        wsgi("GET", "/search", qs="q=1")
        self.assertGreaterEqual(time.time() - t, l7_webapp.UPSTREAM_DELAY_MS / 1000.0 - 0.01)


class CalibrationTest(unittest.TestCase):
    def test_thresholds_match_control_plane_and_nginx(self):
        with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
            src = fh.read()
        for needle in ("HEURISTIC_MAX_RPS = 50", "SLOWCONN_CONN_THRESHOLD = 8",
                       "RUDY_TIMEOUT_THRESHOLD = 3"):
            self.assertIn(needle, src)
        self.assertEqual(l7_traffic.THRESHOLDS["l7_rate_ban_rps"], 50)
        self.assertEqual(l7_traffic.THRESHOLDS["slowconn_ban_conns"], 8)
        self.assertEqual(l7_traffic.THRESHOLDS["rudy_ban_timeouts"], 3)
        with open(os.path.join(REPO, "nginx.conf"), encoding="utf-8") as fh:
            nginx = fh.read()
        self.assertIn("rate=30r/s", nginx)
        self.assertIn("client_max_body_size 64k", nginx)

    def test_default_trained_attacks_are_sub_threshold(self):
        rep = l7_traffic.calibrate()
        self.assertTrue(rep["calibrated"])
        self.assertTrue(all(not r["violations"] for r in rep["trained"]))

    def test_over_threshold_rate_is_rejected(self):
        bad = [l7_traffic.AttackSpec("x", "rate", params={"rps": 48})]   # > 50-5
        with self.assertRaises(l7_traffic.CalibrationError):
            l7_traffic.calibrate(trained=bad)

    def test_fast_dribble_and_big_body_rejected(self):
        for p in ({"conns": 6, "byte_every_s": 6}, {"conns": 6, "header_every_s": 5},
                  {"conns": 6, "byte_every_s": 3, "body_bytes": 70000}):
            with self.assertRaises(l7_traffic.CalibrationError):
                l7_traffic.calibrate(trained=[l7_traffic.AttackSpec("x", "conns", params=p)])

    def test_too_many_conns_rejected(self):
        with self.assertRaises(l7_traffic.CalibrationError):
            l7_traffic.calibrate(trained=[l7_traffic.AttackSpec("x", "conns", params={"conns": 8})])


class PlanTest(unittest.TestCase):
    def test_build_plan_is_seeded_and_labelled(self):
        b1, _a1, s1, _ = l7_traffic.build_plan(1, 8, 300.0)
        b2, _a2, s2, _ = l7_traffic.build_plan(1, 8, 300.0)
        self.assertEqual([c["ip"] for c in b1], [c["ip"] for c in b2])
        self.assertEqual([e["start_s"] for e in s1], [e["start_s"] for e in s2])
        self.assertNotEqual(l7_traffic.build_plan(2, 8, 300.0)[2][0]["start_s"], s1[0]["start_s"])
        self.assertEqual(len(b1), 8)
        for e in s1:
            self.assertLessEqual(e["stop_s"], 300.0 + 1e-6)
            self.assertLessEqual(e["start_s"], e["stop_s"])

    def test_ip_map_and_manifest_roundtrip(self):
        benign, attackers, schedule, _ = l7_traffic.build_plan(3, 6, 200.0)
        for c in benign:
            c["profile"] = "perfect"
        ip_map = l7_dataset.build_ip_map(benign, attackers)
        self.assertEqual(l7_dataset.label_for(benign[0]["ip"], ip_map)[0], l7_dataset.BENIGN)
        atk = next(a for a in attackers if not a["held_out"])
        self.assertEqual(l7_dataset.label_for(atk["ip"], ip_map)[0], l7_dataset.ATTACK)
        self.assertEqual(l7_dataset.label_for("8.8.8.8", ip_map), (l7_dataset.OTHER, None, False))
        m = l7_dataset.make_manifest(seed=3, duration_s=200.0, ip_map=ip_map,
                                     schedule=schedule, provenance={"x": 1})
        l7_dataset.validate_manifest(m)
        self.assertIn("subthreshold_flood", l7_dataset.families(m, held_out=False))
        self.assertIn("credstuff", l7_dataset.families(m, held_out=True))

    def test_validate_manifest_rejects_bad(self):
        with self.assertRaises(ValueError):
            l7_dataset.validate_manifest({"format": "other/9"})
        with self.assertRaises(ValueError):
            l7_dataset.validate_manifest(l7_dataset.make_manifest(
                seed=1, duration_s=10.0, ip_map={"1.1.1.1": {"class": "benign"}},
                schedule=[{"ip": "1.1.1.1", "start_s": 0, "stop_s": 20}],  # stop > duration
                provenance={}))


class GeneratorScopeTest(unittest.TestCase):
    def run_gen(self, argv):
        return subprocess.run([sys.executable, os.path.join(REPO, "ml", "l7_gen.py"), *argv],
                              capture_output=True, text=True, check=False)

    def test_refuses_target_outside_testbed(self):
        r = self.run_gen(["--role", "benign", "--kind", "keepalive", "--host", "8.8.8.8",
                          "--port", "443", "--duration", "1"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing", (r.stderr + r.stdout).lower())

    def test_refuses_non_ip_host(self):
        r = self.run_gen(["--role", "attack", "--family", "scraper", "--host", "example.com",
                          "--port", "80", "--duration", "1"])
        self.assertNotEqual(r.returncode, 0)

    def test_plan_mode_sends_nothing_and_lists_known_kinds(self):
        r = self.run_gen(["--role", "attack", "--family", "slowloris", "--host", "10.0.0.1",
                          "--port", "80", "--duration", "60", "--plan",
                          "--params", '{"conns":6,"header_every_s":3}'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["name"], "slowloris")
        self.assertEqual(set(l7_gen.BENIGN) | set(l7_gen.ATTACK) >=
                         {"keepalive", "http2", "slowloris", "slowpost", "scraper",
                          "credstuff", "padded_flood", "slowread"}, True)

    def test_unknown_family_errors(self):
        r = self.run_gen(["--role", "attack", "--family", "nope", "--host", "10.0.0.1",
                          "--duration", "1", "--plan"])
        self.assertNotEqual(r.returncode, 0)


class OrchestratorPlanTest(unittest.TestCase):
    def test_capture_plan_mode_offline(self):
        r = subprocess.run([sys.executable, os.path.join(REPO, "ml", "capture_l7.py"),
                            "--plan", "--duration", "300", "--benign", "12", "--seed", "1"],
                           capture_output=True, text=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("calibrated: True", r.stdout)
        self.assertIn("netem=", r.stdout)
        self.assertIn("volumetric_flood", r.stdout)


if __name__ == "__main__":
    unittest.main()
