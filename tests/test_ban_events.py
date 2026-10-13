"""Unit tests for ban_events.py (no root, no network).

Run from the repository root:  venv/bin/python -m unittest discover -s tests -v
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ban_events


class EventLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "sub", "ban_events.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip_and_parent_dir_creation(self):
        log = ban_events.EventLog(self.path)
        self.assertTrue(log.enabled)
        log.emit("start", pid=1)
        rec = log.emit("ban", ip="10.0.2.1", engine="l4_syn", value=250, threshold=200)
        log.close()
        self.assertEqual(rec["kind"], "ban")
        events = ban_events.read_events(self.path)
        self.assertEqual([e["kind"] for e in events], ["start", "ban"])
        self.assertEqual(events[1]["ip"], "10.0.2.1")
        self.assertEqual(events[1]["value"], 250)
        self.assertLessEqual(events[0]["t_wall"], events[1]["t_wall"])
        self.assertIsInstance(events[1]["t_mono_ns"], int)

    def test_appends_across_instances(self):
        for i in range(2):
            log = ban_events.EventLog(self.path)
            log.emit("start", n=i)
            log.close()
        self.assertEqual([e["n"] for e in ban_events.read_events(self.path)], [0, 1])

    def test_disabled_for_empty_path(self):
        log = ban_events.EventLog("")
        self.assertFalse(log.enabled)
        self.assertIsNone(log.emit("ban", ip="10.0.2.1"))

    def test_unwritable_path_never_raises(self):
        blocker = os.path.join(self.tmp.name, "a_file")
        open(blocker, "w").close()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            log = ban_events.EventLog(os.path.join(blocker, "x", "events.jsonl"))
            self.assertFalse(log.enabled)
            self.assertIsNone(log.emit("ban", ip="10.0.2.1"))
        self.assertIn("unavailable", out.getvalue())   # reported once, not raised

    def test_emit_after_close_is_silent(self):
        log = ban_events.EventLog(self.path)
        log.close()
        self.assertIsNone(log.emit("ban", ip="10.0.2.1"))

    def test_concurrent_writers_produce_whole_lines(self):
        log = ban_events.EventLog(self.path)

        def writer(k):
            for i in range(200):
                log.emit("ban", ip=f"10.0.2.{k}", seq=i, pad="x" * 100)

        threads = [threading.Thread(target=writer, args=(k,)) for k in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        log.close()
        with open(self.path) as fh:
            lines = fh.read().splitlines()
        self.assertEqual(len(lines), 1600)
        for line in lines:
            json.loads(line)     # every line is a complete JSON object


class ReadEventsTest(unittest.TestCase):
    def test_skips_blank_malformed_and_partial_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write('{"t_wall": 1.0, "kind": "start"}\n\nnot json\n[1, 2]\n'
                     '{"kind": "ban"}\n{"t_wall": 2.0, "kind": "ban", "ip": "10.0.2.1"}\n'
                     '{"t_wall": 3.0, "kind": "ba')                 # partial last line
            path = fh.name
        try:
            events = ban_events.read_events(path)
            self.assertEqual([e["t_wall"] for e in events], [1.0, 2.0])
            self.assertEqual(len(ban_events.read_events(path, kinds={"ban"})), 1)
        finally:
            os.unlink(path)

    def test_missing_file_gives_empty_list(self):
        self.assertEqual(ban_events.read_events("/nonexistent/ban_events.jsonl"), [])


class FirstBansTest(unittest.TestCase):
    EVENTS = (
        {"kind": "start", "t_wall": 0.0},
        {"kind": "ban", "t_wall": 5.0, "ip": "10.0.2.1", "engine": "l7_rate"},
        {"kind": "ban", "t_wall": 4.0, "ip": "10.0.2.1", "engine": "l4_syn"},   # earlier, out of order
        {"kind": "ban", "t_wall": 6.0, "ip": "10.0.2.2", "engine": "gru"},
        {"kind": "unban", "t_wall": 7.0, "ip": "10.0.2.1"},
        {"kind": "ban", "t_wall": 9.0, "ip": "10.0.1.3", "engine": "l7_rate"},
    )

    def test_earliest_ban_per_ip(self):
        first = ban_events.first_bans(self.EVENTS)
        self.assertEqual(first["10.0.2.1"]["engine"], "l4_syn")
        self.assertEqual(set(first), {"10.0.2.1", "10.0.2.2", "10.0.1.3"})

    def test_ip_filter_and_time_bounds(self):
        first = ban_events.first_bans(self.EVENTS, ips=["10.0.2.1", "10.0.2.2"], since=4.5, until=6.0)
        self.assertEqual(first["10.0.2.1"]["t_wall"], 5.0)
        self.assertEqual(first["10.0.2.2"]["t_wall"], 6.0)
        self.assertEqual(ban_events.first_bans(self.EVENTS, ips=["10.0.1.3"], until=8.0), {})


class EngineFromReasonTest(unittest.TestCase):
    def test_all_daemon_reason_formats(self):
        cases = {   # the exact reason strings control_plane.py writes
            "Heuristic R.U.D.Y. (3 body timeouts)": "l7_rudy",
            "GRU classifier (99.7% confidence)": "gru",
            "Per-IP SYN flood (1001 SYN/s)": "l4_syn",
            "Volumetric packet flood (250000 pkts/s)": "l4_volumetric",
            "Slow connection abuse (8 conns)": "l4_slowconn",
            "Low-and-slow SYN (9 SYN/s, no handshake)": "l4_lowsyn",
            "Heuristic (RPS=51.0, errors=0%)": "l7_rate",
            "something else": "unknown",
        }
        for reason, engine in cases.items():
            self.assertEqual(ban_events.engine_from_reason(reason), engine, reason)

    def test_every_engine_has_a_label(self):
        for engine in ban_events.ENGINES:
            self.assertIn(engine, ban_events.ENGINE_LABELS)


class FileSha256Test(unittest.TestCase):
    def test_known_digest_and_missing_file(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
            fh.write(b"abc")
            path = fh.name
        try:
            self.assertEqual(ban_events.file_sha256(path),
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        finally:
            os.unlink(path)
        self.assertIsNone(ban_events.file_sha256("/nonexistent/file"))


if __name__ == "__main__":
    unittest.main()
