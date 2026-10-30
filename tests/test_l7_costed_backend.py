"""The costed backend of the L7 app (l7_backend.py, l7_webapp.route_class; docs/L7V2_DESIGN.md section 4, D-V1).
Offline: the WSGI app is called in-process with small knobs; no server is started."""
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))
sys.path.insert(0, os.path.join(REPO, "bench"))
import calibration as CAL
import calibration_fixtures as CF
import origin as O

import l7_backend as B
import l7_webapp

SMALL = {"rows_total": 2000, "page_rows": 20, "page_burn": 10, "api_burn": 10, "search_rows": 500,
         "export_rows": 50, "export_burn": 10}
MEASURED = os.path.join(REPO, "ml", "l7v2_records", "measured_hg2_3.json")


def call(app, method, path, qs="", cookie=None, body=b""):
    cap = {}

    def start_response(status, headers, exc_info=None):
        cap["status"], cap["headers"] = status, headers

    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": qs,
               "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
    if cookie is not None:
        environ["HTTP_COOKIE"] = cookie
    out = b"".join(app(environ, start_response))
    return cap["status"], cap["headers"], out


def header(headers, name):
    got = [v for k, v in headers if k.lower() == name.lower()]
    return got[0] if got else None


class SiteMapTest(unittest.TestCase):
    def test_route_classes(self):
        cases = {("GET", "/"): "C1", ("GET", "/page/7"): "C1", ("GET", "/page/search"): "C1",
                 ("GET", "/static/site30/app1.js"): "C0", ("HEAD", "/static/3.css"): "C0",
                 ("GET", "/api/items"): "C2", ("GET", "/search?q=alpha"): "C3", ("GET", "/search"): "C3",
                 ("GET", "/export"): "C5", ("GET", "/export?r=12"): "C5", ("GET", "/download/large"): None,
                 ("POST", "/upload"): None, ("POST", "/login"): None, ("GET", "/robots.txt"): None,
                 ("GET", "/nope"): None, ("POST", "/page/1"): None, ("GET", "/exports"): None}
        for (method, path), want in cases.items():
            self.assertEqual(l7_webapp.route_class(method, path), want, (method, path))

    def test_route_status_ignores_the_query_and_knows_export(self):
        self.assertEqual(l7_webapp.route_status("GET", "/export?r=5"), 200)
        self.assertEqual(l7_webapp.route_status("GET", "/export"), 200)
        self.assertEqual(l7_webapp.route_status("GET", "/search?q=1"), 200)
        self.assertEqual(l7_webapp.route_status("GET", "/nope?x=1"), 404)


class LegacyStaysTest(unittest.TestCase):
    def test_without_the_switch_app_is_the_legacy_app(self):
        self.assertIsNone(l7_webapp._backend())
        for path in ("/", "/page/7", "/static/3.css", "/api/x", "/robots.txt", "/nope"):
            a = call(l7_webapp.app, "GET", path)
            b = call(l7_webapp.legacy_app, "GET", path)
            self.assertEqual(a, b, path)
            self.assertIsNone(header(a[1], "X-Origin-Calibration"), "the legacy app does not label answers")
            self.assertIsNone(header(a[1], "Set-Cookie"), "the legacy app sets no cookie")

    def test_legacy_export_is_a_small_csv(self):
        status, headers, body = call(l7_webapp.app, "GET", "/export", "r=3")
        self.assertEqual(status, "200 OK")
        self.assertTrue(body.startswith(b"id,score\n"))
        self.assertEqual(int(header(headers, "Content-Length")), len(body))

    def test_an_unknown_backend_is_refused(self):
        with mock.patch.dict(os.environ, {"L7_BACKEND": "fast"}), mock.patch.object(l7_webapp, "_BACKEND", []), \
                self.assertRaises(ValueError):
            l7_webapp._backend()


class CostedAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ids = iter(f"{i:032x}" for i in range(1, 1000))
        cls.app = B.CostedApp(knobs=SMALL, sid_factory=lambda: next(ids))

    def test_pages_are_c1_html_with_a_session_cookie(self):
        status, headers, _body = call(self.app, "GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertEqual(header(headers, "X-Route-Class"), "C1")
        self.assertEqual(header(headers, "X-Origin-Calibration"), "placeholder")
        self.assertTrue(header(headers, "Content-Type").startswith("text/html"))
        self.assertGreater(int(header(headers, "X-Work")), 0)
        cookie = header(headers, "Set-Cookie")
        self.assertRegex(cookie, r"^sid=[0-9a-f]{32}; Path=/; HttpOnly; SameSite=Lax$")
        sid = cookie.split(";")[0].split("=")[1]
        _, h2, _ = call(self.app, "GET", "/page/7", cookie=f"theme=dark; sid={sid}")
        self.assertIsNone(header(h2, "Set-Cookie"), "a valid sid is kept")
        _, h3, _ = call(self.app, "GET", "/page/7", cookie="sid=not-a-sid")
        self.assertIsNotNone(header(h3, "Set-Cookie"), "an invalid sid is replaced")
        _, h4, _ = call(self.app, "GET", "/api/items")
        self.assertIsNone(header(h4, "Set-Cookie"), "only HTML answers set the cookie")

    def test_assets_keep_the_legacy_size_and_cache(self):
        path = "/static/site30/app1.js"
        status, headers, body = call(self.app, "GET", path)
        self.assertEqual((status, header(headers, "X-Route-Class")), ("200 OK", "C0"))
        self.assertEqual(len(body), l7_webapp.static_size(path))
        self.assertEqual(body, call(l7_webapp.legacy_app, "GET", path)[2])
        self.assertEqual(header(headers, "Cache-Control"), "public, max-age=3600")

    def test_api_search_export(self):
        s, h, b = call(self.app, "GET", "/api/items")
        self.assertEqual((s, header(h, "X-Route-Class")), ("200 OK", "C2"))
        self.assertIn("title", json.loads(b))
        s, h, b = call(self.app, "GET", "/search", "q=alpha")
        self.assertEqual((s, header(h, "X-Route-Class")), ("200 OK", "C3"))
        self.assertIsInstance(json.loads(b), list)
        s, h, b = call(self.app, "GET", "/export", "r=12")
        self.assertEqual((s, header(h, "X-Route-Class")), ("200 OK", "C5"))
        self.assertTrue(b.startswith(b"id,title,body,score\n"))
        for path, qs in (("/search", "q=%3Cscript%3E"), ("/search", ""), ("/export", "x=1")):
            s, h, _ = call(self.app, "GET", path, qs)
            self.assertEqual(s, "400 Bad Request", (path, qs))
            self.assertEqual(header(h, "X-Origin-Calibration"), "placeholder")

    def test_search_does_not_sleep(self):
        with mock.patch("time.sleep", side_effect=AssertionError("a sleep costs no CPU")):
            self.assertEqual(call(self.app, "GET", "/search", "q=delta")[0], "200 OK")

    def test_uncosted_routes_are_the_legacy_answers_labelled(self):
        for method, path, body in (("POST", "/login", b"{}"), ("GET", "/robots.txt", b""), ("GET", "/nope", b""),
                                   ("POST", "/upload", b"xyz")):
            got = call(self.app, method, path, body=body)
            want = call(l7_webapp.legacy_app, method, path, body=body)
            self.assertEqual((got[0], got[2]), (want[0], want[2]), path)
            self.assertEqual(header(got[1], "X-Origin-Calibration"), "placeholder", path)
            self.assertIsNone(header(got[1], "X-Route-Class"))

    def test_methods_and_head(self):
        self.assertEqual(call(self.app, "POST", "/page/1")[0], "405 Method Not Allowed")
        s, h, b = call(self.app, "HEAD", "/page/1")
        self.assertEqual((s, b), ("200 OK", b""))
        self.assertGreater(int(header(h, "Content-Length")), 0)

    def test_a_replayed_url_costs_the_same(self):
        w = [header(call(self.app, "GET", "/search", "q=onyx")[1], "X-Work") for _ in range(2)]
        self.assertEqual(w[0], w[1])
        self.assertEqual(O.spread_factor("/search?q=onyx", 1, 0.25), O.spread_factor("/search?q=onyx", 1, 0.25))


class RecordTest(unittest.TestCase):
    def test_the_default_is_the_placeholder(self):
        rec, status, tag = B.load_record()
        self.assertEqual((status, tag), ("placeholder", "placeholder"))
        self.assertEqual(B.label(rec), "PLACEHOLDER")
        with self.assertRaises(B.RecordError):
            B.require_frozen(rec)

    def test_the_measured_record_is_labelled_and_refused_by_every_verdict(self):
        rec, status, tag = B.load_record(MEASURED)
        self.assertEqual(status, "measured")
        self.assertEqual(tag, "measured:" + rec["sha256"][:8])
        self.assertEqual(B.label(rec), "MEASURED, NOT FROZEN")
        self.assertEqual(rec["route_costs_ms"], {"C0": 0.005444691406250243, "C1": 3.40712200000004,
                                                 "C2": 1.77428400000057, "C3": 29.837566999999954,
                                                 "C5": 159.70452500000044})
        self.assertEqual(rec["provenance"]["sha256"], "db8af1ba608b855097ea8f7adc6131c201fecd675610f44a49c9eecf109499fa")
        self.assertEqual(rec["knobs"], CF.placeholder()["knobs"])
        self.assertEqual(rec["provenance"]["template_sha256"], CF.placeholder()["sha256"])
        with self.assertRaises(B.RecordError):
            B.require_frozen(rec)
        with self.assertRaises(CAL.RecordError):
            CAL.load(MEASURED)                       # never a calibration record
        self.assertEqual(B.measured_problems(rec), [])

    def test_a_tampered_measured_record_is_refused(self):
        with open(MEASURED, encoding="utf-8") as fh:
            rec = json.load(fh)
        rec["route_costs_ms"]["C3"] = 3.0
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "m.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(rec, fh)
            with self.assertRaises(B.RecordError):
                B.load_record(path)

    def test_a_frozen_record_is_tagged_and_self_checked(self):
        frozen = CF.frozen()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f.json")
            CAL.dump(frozen, path)
            rec, status, tag = B.load_record(path)
            self.assertEqual((status, tag), ("frozen", "frozen:" + frozen["sha256"][:8]))
            self.assertIs(B.require_frozen(rec), rec)
            ticks = iter(range(10**6))
            with self.assertRaises(O.CalibrationError):          # 1 ms per call against 0.05-150 ms frozen
                B.CostedApp(path, knobs=SMALL, clock=lambda: next(ticks) / 1000.0)

    def test_arithmetic_takes_the_weaker_status(self):
        measured, _, _ = B.load_record(MEASURED)
        base, _, _ = B.load_record()
        r = B.arithmetic_record(measured, base)
        self.assertEqual(r["status"], "placeholder")
        self.assertEqual(r["route_costs_ms"], measured["route_costs_ms"])
        self.assertEqual(r["capacity"], base["capacity"])
        self.assertGreater(CAL.spare_capacity(r), 0)

    def test_from_env_reads_the_record_path_and_seed(self):
        fake = mock.Mock(knobs=O.CostKnobs())
        with mock.patch.object(B.O, "make_app", return_value=fake) as make:
            app = B.CostedApp.from_env({"L7_CALIBRATION": MEASURED, "ORIGIN_SEED": "3"})
        self.assertEqual((app.status, app.data_seed, app.tag[:9]), ("measured", 3, "measured:"))
        args = make.call_args[0]
        self.assertEqual(args[1], 3)
        self.assertIsNone(args[2], "a measured record arms no self-check: only a frozen one does")

    def test_measured_record_sha256_is_pinned(self):
        with open(MEASURED, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), MEASURED_FILE_SHA256)


MEASURED_FILE_SHA256 = "2e6ac7fce3df8b54d86519ac1edb74f53cb90dddf10339290720ec1d83719daf"

if __name__ == "__main__":
    unittest.main()
