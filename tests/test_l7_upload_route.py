"""The upload route of profile R in the costed backend (l7_backend.py, L7_UPLOAD=streamed; docs/P4_SLOW_DESIGN.md
§4.1, §5; P4 part 2b). Offline: the WSGI app is called in-process with small knobs; no server is started. Kept apart from
tests/test_l7_costed_backend.py, which belongs to the L7 v2 track and pins the default (legacy) upload."""
import io
import json
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "bench"))

import l7_backend as B
import l7_webapp

SMALL = {"rows_total": 2000, "page_rows": 20, "page_burn": 10, "api_burn": 10, "search_rows": 500,
         "export_rows": 50, "export_burn": 10}
MEASURED = os.path.join(REPO, "ml", "l7v2_records", "measured_hg2_3.json")


class Trickle:
    """A wsgi.input that hands over at most `per_read` bytes a read, as a socket does when a body arrives slowly, and
    remembers what was asked of it."""

    def __init__(self, data, per_read):
        self.buf, self.per_read, self.asked = io.BytesIO(data), per_read, []

    def read(self, size=-1):
        self.asked.append(size)
        return self.buf.read(min(self.per_read, size) if size >= 0 else self.per_read)


def call(app, method, path, body=b"", wsgi_input=None, content_length="auto"):
    cap = {}

    def start_response(status, headers, exc_info=None):
        cap["status"], cap["headers"] = status, headers

    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "",
               "wsgi.input": wsgi_input if wsgi_input is not None else io.BytesIO(body)}
    if content_length == "auto":
        environ["CONTENT_LENGTH"] = str(len(body))
    elif content_length is not None:
        environ["CONTENT_LENGTH"] = content_length
    out = b"".join(app(environ, start_response))
    return cap["status"], dict(cap["headers"]), out


class StreamedUploadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = B.CostedApp(knobs=SMALL, upload="streamed")

    def test_an_upload_is_c6_costed_and_labelled(self):
        status, headers, body = call(self.app, "POST", "/upload", b"x" * 3000)
        self.assertEqual(status, "200 OK")
        self.assertEqual(json.loads(body), {"received": 3000})
        self.assertEqual(headers["X-Route-Class"], "C6")
        self.assertGreater(int(headers["X-Work"]), 0)
        self.assertEqual(headers["X-Origin-Calibration"], "placeholder")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_the_body_is_read_as_it_arrives_and_never_past_its_length(self):
        n = 3 * B.UPLOAD_CHUNK + 17
        src = Trickle(b"y" * n, per_read=1000)
        status, _h, body = call(self.app, "POST", "/upload", wsgi_input=src, content_length=str(n))
        self.assertEqual((status, json.loads(body)["received"]), ("200 OK", n))
        self.assertGreater(len(src.asked), n // 1000)              # many reads, each one what had arrived
        self.assertTrue(all(0 < a <= B.UPLOAD_CHUNK for a in src.asked))
        left, asked_past = n, []
        for a in src.asked:
            asked_past.append(a > left)
            left -= min(a, 1000, left)
        self.assertFalse(any(asked_past), "a read never asks for more than the body has left")

    def test_a_chunked_body_is_read_to_its_end(self):
        src = Trickle(b"z" * 70_000, per_read=4096)
        status, _h, body = call(self.app, "POST", "/upload", wsgi_input=src, content_length=None)
        self.assertEqual((status, json.loads(body)["received"]), ("200 OK", 70_000))

    def test_a_body_cut_short_is_a_400_without_work(self):
        status, headers, _b = call(self.app, "POST", "/upload", wsgi_input=io.BytesIO(b"x" * 10),
                                   content_length="500")
        self.assertEqual(status, "400 Bad Request")
        self.assertNotIn("X-Work", headers)
        self.assertEqual(call(self.app, "POST", "/upload", content_length="lots")[0], "400 Bad Request")

    def test_the_work_is_c2s_and_a_replayed_size_costs_the_same(self):
        w = [call(self.app, "POST", "/upload", b"q" * 1234)[1]["X-Work"] for _ in range(2)]
        self.assertEqual(w[0], w[1])
        self.assertEqual(B.UPLOAD_WORK_CLASS, "C2")
        self.assertIn(B.UPLOAD_WORK_CLASS, B.O.CLASSES)          # a class whose cost the record holds
        self.assertNotIn(B.UPLOAD_CLASS, B.O.CLASSES)             # C6 has an SLO, not a cost

    def test_other_routes_and_methods_are_unchanged(self):
        legacy = B.CostedApp(knobs=SMALL)
        for method, path, body in (("GET", "/upload", b""), ("HEAD", "/upload", b""), ("POST", "/login", b"{}"),
                                   ("GET", "/page/3", b""), ("GET", "/robots.txt", b"")):
            got, want = call(self.app, method, path, body), call(legacy, method, path, body)
            self.assertEqual((got[0], got[2] if path != "/page/3" else b""),
                             (want[0], want[2] if path != "/page/3" else b""), (method, path))

    def test_a_measured_record_labels_the_upload_too(self):
        app = B.CostedApp(MEASURED, knobs=SMALL, upload="streamed")
        self.assertTrue(call(app, "POST", "/upload", b"a")[1]["X-Origin-Calibration"].startswith("measured:"))


class SwitchTest(unittest.TestCase):
    def test_from_env_reads_the_switch_and_its_default_is_the_legacy_upload(self):
        default = B.CostedApp.from_env({})
        self.assertEqual(default.upload, "legacy")
        got, want = call(default, "POST", "/upload", b"abc"), call(l7_webapp.legacy_app, "POST", "/upload", b"abc")
        self.assertEqual((got[0], got[2]), (want[0], want[2]))
        self.assertNotIn("X-Route-Class", got[1])
        self.assertEqual(B.CostedApp.from_env({B.ENV_UPLOAD: "streamed"}).upload, "streamed")
        with self.assertRaises(ValueError):
            B.CostedApp.from_env({B.ENV_UPLOAD: "fast"})

    def test_profile_r_serves_the_costed_app_with_the_streamed_upload(self):
        ns = {}
        with open(os.path.join(REPO, "gunicorn_profile_r.py"), encoding="utf-8") as fh:
            exec(compile(fh.read(), "gunicorn_profile_r.py", "exec"), ns)  # noqa: S102
        self.assertEqual(ns["wsgi_app"], "l7_webapp:app")
        self.assertEqual(sorted(ns["raw_env"]), ["L7_BACKEND=costed", "L7_UPLOAD=streamed"])


if __name__ == "__main__":
    unittest.main()
