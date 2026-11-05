"""l7_gen --source (docs/P3_DATASET_DESIGN.md §4.2): with entities grouped onto one namespace per netem profile
as address aliases, every connection a generator opens must leave from its entity's own address. Offline: the
plan mode, the refusal, the adapters' pool settings, the curl argv and a loopback bind; nothing is sent beyond
the loopback test socket."""
import json
import os
import socket
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_gen


def run_gen(*argv):
    return subprocess.run([sys.executable, os.path.join(REPO, "ml", "l7_gen.py"), *argv],
                          capture_output=True, text=True, check=False)


class SourceCliTest(unittest.TestCase):
    def test_plan_records_the_source(self):
        r = run_gen("--role", "benign", "--kind", "keepalive", "--host", "10.0.0.1", "--port", "80",
                    "--duration", "5", "--plan", "--source", "10.0.16.7")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["source"], "10.0.16.7")

    def test_source_outside_the_testbed_is_refused(self):
        r = run_gen("--role", "attack", "--family", "scraper", "--host", "10.0.0.1", "--port", "80",
                    "--duration", "1", "--source", "8.8.8.8")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing: source", r.stderr + r.stdout)


class SourceBindingTest(unittest.TestCase):
    def tearDown(self):
        l7_gen.SOURCE = None

    def test_sessions_bind_the_source(self):
        l7_gen.SOURCE = "10.0.16.7"
        for sess in (l7_gen._new_session(), l7_gen._session("ua", 6)):
            with sess:
                ad = sess.get_adapter("https://10.0.0.1/")
                self.assertEqual(ad.poolmanager.connection_pool_kw["source_address"], ("10.0.16.7", 0))
        with l7_gen._session("ua", 6) as sess:
            self.assertEqual(sess.get_adapter("http://10.0.0.1/")._pool_maxsize, 6)
        self.assertEqual(l7_gen._curl("-s", "u"), ["curl", "--interface", "10.0.16.7", "-s", "u"])

    def test_without_source_nothing_changes(self):
        with l7_gen._new_session() as sess:
            kw = sess.get_adapter("http://10.0.0.1/").poolmanager.connection_pool_kw
            self.assertNotIn("source_address", kw)
        self.assertEqual(l7_gen._curl("-s", "u"), ["curl", "-s", "u"])

    def test_raw_sockets_bind_the_source(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        l7_gen.SOURCE = "127.0.0.2"                       # any 127/8 address is local on Linux
        socks = l7_gen._open_sockets("127.0.0.1", srv.getsockname()[1], 1, b"x")
        self.assertEqual(len(socks), 1)
        conn, peer = srv.accept()
        conn.close()
        for s in socks:
            s.close()
        self.assertEqual(peer[0], "127.0.0.2")


if __name__ == "__main__":
    unittest.main()
