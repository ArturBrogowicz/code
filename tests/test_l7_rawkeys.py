"""The raw (UA, sid) side table of the L7 v2 enforcing arm (l7_denymap.RawKeys; T-025b F7): the engine keys on hashes,
the deny map needs the raw strings. It keeps them only for keys the map can deny, in memory, bounded, and agrees with the
key the engine computes. Offline."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import l7_denymap as D
import l7_ingest

IP = "10.0.16.7"
SID = "0123456789abcdef0123456789abcdef"
SID2 = "fedcba9876543210fedcba9876543210"
UA = "Mozilla/5.0 (X11, Linux x86_64) Firefox/143.0"


def obj(ua=UA, sid="", sid_set="", ip=IP, msec=1000.0, rt=0.01):
    """A parsed l7json record as nginx.conf logs it (escape=json: an absent cookie is "")."""
    return json.loads(json.dumps({"msec": msec, "ip": ip, "method": "GET", "uri": "/page/1", "status": 200, "rt": rt,
                                  "ua": ua, "ref": "", "sid": sid, "sid_set": sid_set}))


def note(table, o):
    rec = l7_ingest.normalise(o)
    ua, sid = D.raw_strings(o)
    table.note(l7_ingest.key_v2(rec), ua, sid, rec["msec"] - rec["rt"])
    return l7_ingest.key_v2(rec)


class RawStringsTest(unittest.TestCase):
    def test_the_raw_strings_are_the_ones_the_key_hashes(self):
        # sid_set wins (the session of a first, cookie-less request); then the cookie; then none
        for o, want in ((obj(sid_set=SID), (UA, SID)), (obj(sid=SID2, sid_set=SID), (UA, SID)),
                        (obj(sid=SID2), (UA, SID2)), (obj(), (UA, ""))):
            with self.subTest(o=o):
                ua, sid = D.raw_strings(o)
                self.assertEqual((ua, sid), want)
                rec = l7_ingest.normalise(o)
                self.assertEqual(rec["ua_h"], l7_ingest.stable_hash32(ua))
                self.assertEqual(rec["sid_h"], l7_ingest.stable_hash32(sid) if sid else l7_ingest.NO_SID)

    def test_a_literal_dash_cookie_is_kept_as_nginx_would_compare_it(self):
        # With escape=json nginx logs an absent cookie as "", so "-" is what the client sent; the hash reads it as no
        # session, the map would compare "-": the key is unenforceable at level 1, not written with "".
        o = obj(sid="-")
        self.assertEqual(D.raw_strings(o), (UA, "-"))
        self.assertEqual(l7_ingest.normalise(o)["sid_h"], l7_ingest.NO_SID)
        t = D.RawKeys()
        key = note(t, o)
        self.assertEqual(t.lookup(key), ("unenforceable", "sid_format", None))

    def test_the_legacy_field_name_of_the_user_agent(self):
        self.assertEqual(D.raw_strings({"user_agent": "curl/8.5.0"}), ("curl/8.5.0", ""))


class RawKeysTest(unittest.TestCase):
    def test_an_enforceable_key_keeps_its_strings_and_a_failing_one_only_its_rule(self):
        t = D.RawKeys()
        good = note(t, obj(sid_set=SID))
        hostile = 'x" 1; } include /etc/passwd; #'
        bad = note(t, obj(ua=hostile, sid=SID2))
        browser = note(t, obj(ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", ip="10.0.16.8"))
        self.assertEqual(t.lookup(good), ("ok", UA, SID))
        self.assertEqual(t.lookup(bad), ("unenforceable", "ua_forbidden_char", None))
        self.assertEqual(t.lookup(browser), ("ok", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", ""))   # D-038
        self.assertNotIn(hostile, repr(t._keys))                          # never kept, so never logged or written
        self.assertEqual(t.lookup((IP, 1, 2)), ("unenforceable", "no_raw", None))

    def test_the_first_request_start_is_kept_for_the_key_age_gate(self):
        t = D.RawKeys()
        key = note(t, obj(msec=1010.0, rt=0.5))
        note(t, obj(msec=1005.0, rt=1.0))                                  # logged later, started earlier
        note(t, obj(msec=1030.0))
        self.assertEqual(t.first_seen(key), 1004.0)
        self.assertIsNone(t.first_seen((IP, 1, 2)))

    def test_bounded_least_recently_seen_first(self):
        t = D.RawKeys(max_keys=3)
        keys = [note(t, obj(ip=f"10.0.16.{i}")) for i in range(1, 4)]
        note(t, obj(ip="10.0.16.1"))                                       # touched: now the most recent
        fourth = note(t, obj(ip="10.0.16.4"))
        self.assertEqual((len(t), t.evicted), (3, 1))
        self.assertEqual(t.lookup(keys[1])[:2], ("unenforceable", "no_raw"))
        for k in (keys[0], keys[2], fourth):
            self.assertEqual(t.lookup(k)[0], "ok")
        self.assertEqual(D.MAX_RAW_KEYS, 16384)

    def test_two_raw_forms_under_one_key_are_not_written(self):
        # A 32-bit hash collision (or a sid the hash strips and the map would not) puts two raw forms under one key:
        # nginx would deny only one of them, so the key becomes unenforceable.
        t = D.RawKeys()
        key = (IP, 1, -1)
        t.note(key, "a", "", 1.0)
        t.note(key, "a", "", 2.0)
        self.assertEqual(t.lookup(key), ("ok", "a", ""))
        t.note(key, "b", "", 3.0)
        self.assertEqual((t.lookup(key), t.ambiguous), (("unenforceable", "ambiguous", None), 1))
        t.note(key, "a", "", 4.0)
        self.assertEqual((t.lookup(key)[1], t.ambiguous, t.first_seen(key)), ("ambiguous", 1, 1.0))
        dash = (IP, 2, -1)
        t.note(dash, "a", "-", 1.0)                                         # "-" fails; then "" passes: two forms
        t.note(dash, "a", "", 2.0)
        self.assertEqual(t.lookup(dash)[1], "ambiguous")


if __name__ == "__main__":
    unittest.main()
