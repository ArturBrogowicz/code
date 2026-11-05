"""L7 v2 ingest (docs/L7V2_DESIGN.md 8.2-8.4): the Referer and the session cookies are hashed and dropped, the route
class of the raw URI is kept, and the key is (IP, ua_hash, sid_hash). Offline and pure."""
import os
import random
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U
import l7v2_model_prereg

import l7_ingest as I
import l7_webapp

obj = U.obj

SID_A = "0123456789abcdef0123456789abcdef"
SID_B = "fedcba9876543210fedcba9876543210"


def v2obj(ref=None, sid=None, sid_set=None, **kw):
    o = obj(**kw)
    for name, val in (("ref", ref), ("sid", sid), ("sid_set", sid_set)):
        if val is not None:
            o[name] = val
    return o


class HashingTest(unittest.TestCase):
    def test_raw_strings_are_dropped(self):
        rec = I.normalise(v2obj(ref="http://10.0.0.1/page/3", sid=SID_A, sid_set="-", uri="/page/4"))
        for raw in ("ref", "sid", "sid_set", "uri", "ua"):
            self.assertNotIn(raw, rec)
        self.assertEqual(set(rec) - {"ip", "ua_h", "uri_h", "method", "proto", "compl", "lreq", "tls", "reused",
                                     "msec", "status", "conn", "creq", "rt", "uct", "urt", "rlen", "bsent"},
                         {"ref_h", "sid_h", "rc"})

    def test_the_referer_hash_equals_the_uri_hash_of_the_page_it_names(self):
        page = I.normalise(v2obj(uri="/page/3"))
        for ref in ("http://10.0.0.1/page/3", "https://origin.test:8443/page/3", "/page/3"):
            self.assertEqual(I.normalise(v2obj(ref=ref, uri="/static/site30/a.css"))["ref_h"], page["uri_h"])
        root = I.normalise(v2obj(uri="/"))
        self.assertEqual(I.normalise(v2obj(ref="http://10.0.0.1", uri="/page/1"))["ref_h"], root["uri_h"])
        self.assertEqual(I.ref_path("http://h/search?q=alpha"), "/search?q=alpha")

    def test_an_absent_referer_is_none(self):
        for ref in (None, "", "-", "  "):
            self.assertIsNone(I.normalise(v2obj(ref=ref))["ref_h"])

    def test_the_cookie_the_answer_set_wins(self):
        self.assertEqual(I.normalise(v2obj(sid_set=SID_A))["sid_h"], I.stable_hash32(SID_A))
        self.assertEqual(I.normalise(v2obj(sid=SID_B))["sid_h"], I.stable_hash32(SID_B))
        self.assertEqual(I.normalise(v2obj(sid=SID_B, sid_set=SID_A))["sid_h"], I.stable_hash32(SID_A))
        self.assertEqual(I.normalise(v2obj(sid=SID_B, sid_set="-"))["sid_h"], I.stable_hash32(SID_B))
        for sid in (None, "", "-"):
            self.assertEqual(I.normalise(v2obj(sid=sid, sid_set=""))["sid_h"], I.NO_SID)

    def test_a_p5c_line_without_the_new_fields(self):
        rec = I.normalise(obj(uri="/page/10"))
        self.assertIsNone(rec["ref_h"])
        self.assertEqual(rec["sid_h"], I.NO_SID)
        self.assertEqual(rec["rc"], "C1")
        self.assertEqual(I.key_of(rec), (rec["ip"], rec["ua_h"]))      # the P5 key is unchanged


class KeyTest(unittest.TestCase):
    def test_the_sid_separates_users_whose_ua_collides(self):
        a = I.normalise(v2obj(ip="10.0.16.9", ua="Mozilla/5.0 X", sid=SID_A))
        b = I.normalise(v2obj(ip="10.0.16.9", ua="Mozilla/5.0 X", sid=SID_B))
        self.assertEqual(I.key_of(a), I.key_of(b))
        self.assertNotEqual(I.key_v2(a), I.key_v2(b))
        self.assertEqual(I.key_v2(a), ("10.0.16.9", a["ua_h"], I.stable_hash32(SID_A)))

    def test_a_first_request_joins_its_session(self):
        first = I.normalise(v2obj(uri="/", sid_set=SID_A))
        later = I.normalise(v2obj(uri="/page/2", sid=SID_A))
        self.assertEqual(I.key_v2(first), I.key_v2(later))

    def test_without_a_session_the_key_is_ip_and_ua(self):
        a = I.normalise(v2obj(ua="curl/8"))
        b = I.normalise(v2obj(ua="curl/8", uri="/api/x"))
        self.assertEqual(I.key_v2(a), I.key_v2(b))
        self.assertEqual(I.key_v2(a), (a["ip"], a["ua_h"], I.NO_SID))


class SiteMapTest(unittest.TestCase):
    PATHS = ("/", "/page/1", "/page/new", "/page/best", "/page/search", "/page/account", "/static/site60/app1.js",
             "/static/site30/p4/img0.png", "/static/1.css", "/api/items", "/api/item/3", "/search?q=alpha", "/search",
             "/export", "/export?r=17", "/login", "/upload", "/download/large", "/robots.txt", "/nope", "",
             "/pagex", "/apix", "/exportx", "/static", "/searchy")

    def test_the_route_class_is_l7_webapps(self):
        rng = random.Random(5)
        paths = list(self.PATHS) + ["/" + "".join(rng.choice("abcdefgsp/?=") for _ in range(rng.randint(0, 12)))
                              for _ in range(300)]
        for method in ("GET", "HEAD", "POST", "PUT", ""):
            for path in paths:
                self.assertEqual(I.route_class(method, path), l7_webapp.route_class(method, path), (method, path))

    def test_records_carry_their_route_class(self):
        for uri, rc in (("/static/site60/font0.woff2", "C0"), ("/", "C1"), ("/page/7", "C1"),
                        ("/api/feed", "C2"), ("/search?q=onyx", "C3"), ("/export?r=5", "C5"), ("/login", None)):
            self.assertEqual(I.normalise(v2obj(uri=uri))["rc"], rc, uri)
        self.assertIsNone(I.normalise(v2obj(uri="/page/1", method="POST"))["rc"])


class PreregTest(unittest.TestCase):
    def test_the_constants_are_the_pre_registered_ones(self):
        pre = l7v2_model_prereg.load()
        self.assertEqual(I.NO_SID, pre["keying"]["no_sid"])
        self.assertEqual(list(I.ABSENT), pre["keying"]["absent"])
        self.assertEqual(list(I.SID_FIELDS), pre["keying"]["sid_fields"])


if __name__ == "__main__":
    unittest.main()
