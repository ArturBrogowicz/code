"""Unit tests for eval/events_census.py (audit G-16, G-11). Offline, synthetic logs."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
import events_census as EC


def ev(kind, **kw):
    return json.dumps({"t_wall": 1.0, "t_mono_ns": 1, "kind": kind, **kw})


START = ev("start", xdp_gru=False, l7_shadow=True, heuristic_profile="tolerant")
BOT_BAN = ev("ban", ip="10.0.2.1", engine="l7_rate", value=60.0)
GRU_FP = ev("ban", ip="10.0.1.6", engine="gru", value=0.999, hits=3)
GRU_TP = ev("ban", ip="10.0.2.2", engine="gru", value=0.99, hits=3)
LEGIT_RULE = ev("ban", ip="10.0.1.16", engine="l7_rate", value=51.0)


class CensusTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pub = os.path.join(self.tmp.name, "pub")
        self.raw = os.path.join(self.tmp.name, "raw")

    def log(self, root, rel, *lines):
        path = os.path.join(root, rel, "ban_events.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(line + "\n" for line in lines))
        return path

    def test_a_published_log_and_its_raw_copy_count_once(self):
        self.log(self.pub, "run1", START, BOT_BAN)
        self.log(self.raw, "run1", START, BOT_BAN)          # byte-identical copy
        c = EC.census([self.pub, self.raw])
        self.assertEqual((c["files"], c["distinct_logs"], c["duplicates_removed"]), (2, 1, 1))
        self.assertEqual(c["total_bans"], 1)
        self.assertEqual(c["bans_by_engine"], {"l7_rate": 1})
        again = EC.census([self.pub, self.raw], dedupe=False)
        self.assertEqual((again["distinct_logs"], again["total_bans"]), (2, 2))

    def test_gru_bans_and_legit_bans_are_listed(self):
        self.log(self.pub, "p1", START, BOT_BAN, GRU_FP)
        self.log(self.pub, "p2", START, GRU_TP, LEGIT_RULE)
        c = EC.census([self.pub])
        self.assertEqual(len(c["gru_bans"]), 2)
        self.assertEqual(c["gru_bans_of_legit_clients"], 1)
        self.assertEqual({r["ip"] for r in c["legit_bans"]}, {"10.0.1.6", "10.0.1.16"})
        self.assertEqual(c["bans_by_engine"], {"gru": 2, "l7_rate": 2})

    def test_logs_without_events_and_malformed_lines(self):
        self.log(self.pub, "nodaemon")                      # empty: a mode without a daemon
        self.log(self.pub, "torn", START, "{not json", BOT_BAN)
        c = EC.census([self.pub])
        self.assertEqual((c["distinct_logs"], c["logs_without_events"]), (2, 1))
        self.assertEqual(c["total_bans"], 1)                # the torn line is skipped, not fatal

    def test_start_configurations_are_tallied(self):
        self.log(self.pub, "a", START)
        self.log(self.pub, "b", ev("start", backend="xdp"))
        c = EC.census([self.pub])
        self.assertEqual(c["start_configs"], {
            "xdp_gru=False l7_shadow=True profile=tolerant": 1,
            "xdp_gru=None l7_shadow=None profile=None": 1})

    def test_the_result_does_not_depend_on_the_order_of_the_roots(self):
        self.log(self.pub, "run1", START, BOT_BAN)
        self.log(self.raw, "run2", START, GRU_FP)
        a = EC.census([self.pub, self.raw])
        b = EC.census([self.raw, self.pub])
        for key in ("files", "distinct_logs", "events_by_kind", "bans_by_engine", "total_bans"):
            self.assertEqual(a[key], b[key], key)

    def test_main_writes_markdown_and_json(self):
        self.log(self.pub, "p1", START, GRU_FP)
        md, js = os.path.join(self.tmp.name, "c.md"), os.path.join(self.tmp.name, "c.json")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = EC.main([self.pub, "--md", md, "--json", js])
        self.assertEqual(rc, 0)
        with open(md, encoding="utf-8") as fh:
            text = fh.read()
        self.assertEqual(text, buf.getvalue())
        self.assertIn("GRU bans: 1, of which 1 of legitimate clients", text)
        with open(js, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["distinct_logs"], 1)


if __name__ == "__main__":
    unittest.main()
