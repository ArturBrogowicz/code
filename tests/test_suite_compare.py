"""Unit tests for eval/suite_compare.py (the scenario-by-scenario table of suite runs)."""
import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
import suite_compare as SC

FIELDS = ["Data_Scenario", "Bots", "Banned_Events", "TTM_Exact_Median_s", "TTM_Exact_Max_s",
          "TTM_Exact_By_Bot", "Engine_By_Bot", "FP_IPs", "Legit_HTTP_OK", "Legit_HTTP_Total",
          "Result"]


def row(name, banned=5, engines=None, median=0.5, tmax=0.6, fp=(), http=15, bots=5, ttm=None):
    """One scenario row. Every banned bot took `median` seconds unless `ttm` maps bots to times."""
    engines = engines or {f"10.0.2.{i + 1}": "l4_syn" for i in range(banned)}
    ttm = ttm if ttm is not None else {ip: median for ip in engines}
    return {"Data_Scenario": name, "Bots": bots, "Banned_Events": banned,
            "TTM_Exact_Median_s": median, "TTM_Exact_Max_s": tmax,
            "TTM_Exact_By_Bot": json.dumps(ttm), "Engine_By_Bot": json.dumps(engines),
            "FP_IPs": json.dumps(list(fp)), "Legit_HTTP_OK": http, "Legit_HTTP_Total": 15,
            "Result": "PASS"}


def write_run(directory, rows):
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, SC.FILE), "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    return directory


class FindRunsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_run_directory_is_one_column_with_the_given_label(self):
        d = write_run(os.path.join(self.tmp.name, "pub"), [row("SYN")])
        self.assertEqual(SC.find_runs("R2", d), [("R2", d)])

    def test_a_campaign_gives_one_column_per_run_in_order(self):
        for k in (2, 1, 3):
            write_run(os.path.join(self.tmp.name, "xdp", f"run{k}"), [row("SYN")])
        cols = SC.find_runs("tol", self.tmp.name)
        self.assertEqual([c for c, _ in cols], ["tol/run1", "tol/run2", "tol/run3"])

    def test_a_campaign_with_a_single_nested_run_keeps_the_label(self):
        d = write_run(os.path.join(self.tmp.name, "xdp", "run1"), [row("SYN")])
        self.assertEqual(SC.find_runs("after", self.tmp.name), [("after", d)])

    def test_nothing_found(self):
        self.assertEqual(SC.find_runs("x", self.tmp.name), [])


class LoadRunTest(unittest.TestCase):
    def test_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            engines = {"10.0.2.1": "l4_syn", "10.0.2.2": "l7_rate", "10.0.2.3": "l7_rate"}
            write_run(tmp, [row("Multi", banned=3, engines=engines, median=0.48, tmax=1.5,
                                fp=["10.0.1.4"], http=14)])
            s = SC.load_run(tmp)["Multi"]
        self.assertEqual((s["bots"], s["banned"], s["median"], s["max"]), (5, 3, 0.48, 1.5))
        self.assertEqual(dict(s["engines"]), {"l4_syn": 1, "l7_rate": 2})
        self.assertEqual((s["fp"], s["http_ok"]), (1, False))


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = write_run(os.path.join(self.tmp.name, "a"), [
            row("SYN flood", median=0.5, tmax=0.6),
            row("Slowloris", engines={f"10.0.2.{i}": "l4_slowconn" for i in range(1, 6)},
                median=3.7, tmax=3.8)])
        mixed = {"10.0.2.1": "l4_syn", "10.0.2.2": "l7_rate", "10.0.2.3": "l7_rate",
                 "10.0.2.4": "l7_rate", "10.0.2.5": "l7_rate"}
        self.b = write_run(os.path.join(self.tmp.name, "b"), [
            row("SYN flood", banned=3, median=1.25, tmax=2.0),
            row("Slowloris", engines=mixed, fp=["10.0.1.9"]),
            row("Only here", median=0.1, tmax=0.2)])

    def md(self):
        return SC.compare([f"A={self.a}", f"B={self.b}"])

    def test_bans_table(self):
        text = self.md()
        self.assertIn("| SYN flood | 5/5 | 3/5 |", text)
        self.assertIn("| Slowloris | 5/5 | 5/5 ! |", text)           # a legitimate client banned
        self.assertIn("| Only here | — | 5/5 |", text)                  # scenario missing in A
        self.assertIn("Scenarios with every bot banned: A 2/3, B 2/3.", text)

    def test_engine_table(self):
        text = self.md()
        self.assertIn("| Slowloris | L4 SlowConn | L4 SYN 1, L7 rate 4 |", text)
        self.assertIn("| SYN flood | L4 SYN | L4 SYN |", text)

    def test_time_table(self):
        text = self.md()
        self.assertIn("| SYN flood | 0.50 / 0.60 | 1.25 / 2.00 |", text)
        self.assertIn("| Only here | — | 0.10 / 0.20 |", text)

    def test_bounds_per_engine_pool_every_bot_of_every_run(self):
        text = self.md()
        # l4_syn: A's SYN flood 5 x 0.5, B's SYN flood 3 x 1.25, one bot of B's Slowloris at
        # 0.5, B's "Only here" 5 x 0.1 -> 14 bots; the median is the mean of the two middle ones.
        self.assertIn("| L4 SYN | 14 | 0.10 | 0.50 | 1.25 |", text)
        self.assertIn("| L4 SlowConn | 5 | 3.70 | 3.70 | 3.70 |", text)
        self.assertIn("| L7 rate | 4 | 0.50 | 0.50 | 0.50 |", text)

    def test_an_unbanned_scenario_adds_no_bots_to_the_bounds(self):
        d = write_run(os.path.join(self.tmp.name, "d"), [
            row("Slowloris", banned=0, engines={}, median="", tmax="", ttm={})])
        text = SC.compare([f"D={d}"])
        self.assertIn("| Slowloris | 0/5 |", text)
        self.assertIn("| Slowloris | — |", text)
        self.assertNotIn("| L4 SYN |", text)

    def test_a_failed_http_check_is_marked(self):
        d = write_run(os.path.join(self.tmp.name, "c"), [row("SYN flood", http=12)])
        self.assertIn("| SYN flood | 5/5 ! |", SC.compare([f"C={d}"]))

    def test_bad_specifications_stop_with_a_message(self):
        with self.assertRaises(SystemExit):
            SC.compare([self.a])                                        # no LABEL=
        with self.assertRaises(SystemExit):
            SC.compare([f"X={os.path.join(self.tmp.name, 'empty')}"])   # nothing below

    def test_main_writes_the_markdown(self):
        out = os.path.join(self.tmp.name, "t.md")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = SC.main([f"A={self.a}", f"B={self.b}", "--md", out])
        self.assertEqual(rc, 0)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), buf.getvalue())


if __name__ == "__main__":
    unittest.main()
