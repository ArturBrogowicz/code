"""Unit tests for l7_ingest.py (Phase P1 L7 ingestion; docs/L7_GRU_DESIGN.md).

Offline and self-contained: the datagram test binds a Unix-domain socket in a
temp dir and sends to itself. No nginx, no testbed, no XDP, no traffic.
"""
import os
import socket
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import l7_ingest as L

# A representative extended line and its Nginx syslog-framed form.
JSON_LINE = ('{"msec":1791882126.896,"ip":"10.0.2.5","port":41000,"conn":99,"creq":3,'
             '"proto":"HTTP/2.0","tls":"TLSv1.3","reused":"r","method":"POST",'
             '"uri":"/login?x=1","status":401,"compl":"OK","rt":0.004,"uct":"0.001",'
             '"urt":"0.002","rlen":320,"bsent":512,"lreq":"","lconn":"","ua":"curl/8"}')
SYSLOG_LINE = "<190>Oct 14 14:00:00 l7: " + JSON_LINE


class HashTest(unittest.TestCase):
    def test_stable_and_32bit(self):
        self.assertEqual(L.stable_hash32("/a"), L.stable_hash32("/a"))
        self.assertNotEqual(L.stable_hash32("/a"), L.stable_hash32("/b"))
        self.assertEqual(L.stable_hash32(None), L.stable_hash32(""))
        self.assertTrue(0 <= L.stable_hash32("/x") < 2 ** 32)


class ParseTest(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(L.parse_l7_line(JSON_LINE)["ip"], "10.0.2.5")

    def test_syslog_framed(self):
        self.assertEqual(L.parse_l7_line(SYSLOG_LINE)["status"], 401)

    def test_bytes_input(self):
        self.assertEqual(L.parse_l7_line(JSON_LINE.encode())["method"], "POST")

    def test_garbage_is_none(self):
        self.assertIsNone(L.parse_l7_line("not a log line"))
        self.assertIsNone(L.parse_l7_line("<190>Oct 14 l7: [1,2,3]"))

    def test_truncated_is_none_and_flagged(self):
        cut = SYSLOG_LINE[:-20]            # drop the JSON tail, incl. closing brace
        self.assertIsNone(L.parse_l7_line(cut))
        self.assertTrue(L.looks_truncated(cut))
        self.assertFalse(L.looks_truncated(SYSLOG_LINE))


class NormaliseTest(unittest.TestCase):
    def test_hashes_and_drops_raw_strings(self):
        rec = L.normalise(L.parse_l7_line(JSON_LINE))
        self.assertEqual(rec["ip"], "10.0.2.5")
        self.assertEqual(rec["ua_h"], L.stable_hash32("curl/8"))
        self.assertEqual(rec["uri_h"], L.stable_hash32("/login?x=1"))
        self.assertNotIn("ua", rec)        # raw UA/URI must not survive
        self.assertNotIn("uri", rec)
        self.assertEqual(rec["status"], 401.0)

    def test_missing_ip_is_none(self):
        self.assertIsNone(L.normalise({"status": 200}))

    def test_legacy_field_names(self):
        rec = L.normalise({"client_ip": "1.2.3.4", "request_method": "GET",
                           "user_agent": "x", "request_uri": "/y"})
        self.assertEqual(rec["ip"], "1.2.3.4")
        self.assertEqual(rec["method"], "GET")

    def test_dash_and_blank_numerics_coerce_to_zero(self):
        rec = L.normalise({"ip": "1.1.1.1", "urt": "-", "rt": "", "rlen": None})
        self.assertEqual((rec["urt"], rec["rt"], rec["rlen"]), (0.0, 0.0, 0.0))


class WindowStoreTest(unittest.TestCase):
    def rec(self, ip="10.0.2.5", ua="curl/8", msec=1.0):
        return L.normalise({"ip": ip, "ua": ua, "uri": "/", "msec": msec})

    def test_window_capped_at_maxlen(self):
        store = L.L7WindowStore(maxlen=3)
        key = None
        for i in range(10):
            key = store.add(self.rec(msec=float(i)))
        self.assertEqual(len(store.window(key)), 3)

    def test_ua_separates_keys_behind_one_ip(self):
        store = L.L7WindowStore()
        store.add(self.rec(ua="browserA"))
        store.add(self.rec(ua="browserB"))
        s = store.stats()
        self.assertEqual(s["active_keys"], 2)       # same IP, two UAs → two windows
        self.assertEqual(s["distinct_ips"], 1)

    def test_idle_eviction(self):
        store = L.L7WindowStore(idle_timeout=10.0)
        store.add(self.rec(msec=100.0), now=100.0)
        self.assertEqual(store.evict(now=105.0), 0)   # still fresh
        self.assertEqual(store.evict(now=200.0), 1)   # idle → evicted
        self.assertEqual(store.stats()["active_keys"], 0)

    def test_full_windows_counted(self):
        store = L.L7WindowStore(maxlen=2)
        store.add(self.rec(ua="a"))
        store.add(self.rec(ua="a"))
        store.add(self.rec(ua="b"))
        self.assertEqual(store.stats()["full_windows"], 1)   # only "a" reached maxlen


class DatagramReaderTest(unittest.TestCase):
    def test_roundtrip_and_counts(self):
        d = tempfile.mkdtemp(prefix="l7t_")
        path = os.path.join(d, "s.sock")
        reader = L.SyslogDatagramReader(path=path, rcvbuf=1 << 20)
        self.addCleanup(reader.close)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(client.close)

        sent = 5
        for _ in range(sent):
            client.sendto(SYSLOG_LINE.encode(), path)

        counters = L.L7Counters()
        store = L.L7WindowStore()
        got = []
        deadline = time.time() + 5.0

        def stop():
            return len(got) >= sent or time.time() > deadline

        for data in reader.messages(stop=stop, timeout=0.2):
            counters.received += 1
            counters.bytes_total += len(data)
            obj = L.parse_l7_line(data)
            if obj is None:
                counters.parse_errors += 1
                if L.looks_truncated(data):
                    counters.truncated += 1
                continue
            counters.parsed += 1
            rec = L.normalise(obj)
            if rec:
                store.add(rec)
            got.append(obj)

        self.assertEqual(counters.received, sent)
        self.assertEqual(counters.parsed, sent)
        self.assertEqual(counters.parse_errors, 0)
        self.assertEqual(store.stats()["active_keys"], 1)   # one (ip, ua) key
        self.assertGreater(reader.rcvbuf, 0)

    def test_close_unlinks_socket(self):
        d = tempfile.mkdtemp(prefix="l7t_")
        path = os.path.join(d, "s.sock")
        reader = L.SyslogDatagramReader(path=path)
        self.assertTrue(os.path.exists(path))
        reader.close()
        self.assertFalse(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
