"""Offline tests for eval/expc_probe.py: the table of an EXP-C probe is built from a synthetic run directory
with the files the suite writes (provenance.json, scenario_results.csv, availability_raw.csv,
server_requests.csv, DONE). Standard library only.

The legit window starts at the attack's real start, not at the label "during"; the load window counts
bot lines by arrival second; a percentile of fewer than ten successes is not printed.
"""
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
import expc_probe as P

START = 1000.0
RAW_FIELDS = ["Timestamp", "Scenario", "Period", "Profile", "HTTP_Code", "Latency_ms", "OK", "Client_IP", "T_Start"]
SRV_FIELDS = ["Data_Scenario", "Mode", "T_Epoch_s", "T_Rel_s", "Client_Class", "Status", "Requests",
              "Request_Time_Mean_s", "Request_Time_Max_s"]


def write_csv(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def legit_row(offset, code="200", latency=5.0, period="during"):
    return {"Timestamp": "", "Scenario": "S", "Period": period, "Profile": "perfect", "HTTP_Code": code,
            "Latency_ms": latency, "OK": "1" if code == "200" else "0", "Client_IP": "10.0.1.1",
            "T_Start": START + offset}


def server_row(rel, cls, status, n):
    return {"Data_Scenario": "S", "Mode": "m", "T_Epoch_s": int(START) + rel, "T_Rel_s": rel,
            "Client_Class": cls, "Status": status, "Requests": n, "Request_Time_Mean_s": 0.001,
            "Request_Time_Max_s": 0.002}


def make_run(root, label="unprotected@loadgen20", rate=20, tool="loadgen", legit=(), server=(), done=None):
    run = os.path.join(root, "20260101T000000Z_knee_s4", label, "run1")
    os.makedirs(run)
    with open(os.path.join(run, "provenance.json"), "w", encoding="utf-8") as fh:
        json.dump({"status": "completed", "mode": {"label": label},
                   "settings": {"FLOOD_TOOL": tool, "FLOOD_RATE": rate, "BOTNET_COUNT": 10}}, fh)
    write_csv(os.path.join(run, "scenario_results.csv"), ["Scenario", "Attack_Start"], [{"Scenario": "S", "Attack_Start": START}])
    write_csv(os.path.join(run, "availability_raw.csv"), RAW_FIELDS, list(legit))
    if server is not None:
        write_csv(os.path.join(run, "server_requests.csv"), SRV_FIELDS, list(server))
    if done:
        with open(os.path.join(run, "DONE"), "w", encoding="utf-8") as fh:
            json.dump(done, fh)
    return run


class AnalyseRunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_legit_window_starts_at_the_attack_not_at_the_label(self):
        legit = [legit_row(-5, "200", period="before"), legit_row(-0.1, "000", period="before"),
                 legit_row(0.5, "000", period="before"),            # labelled before: the launch check
                 legit_row(3, "200"), legit_row(31, "000", period="after")]
        run = make_run(self.tmp.name, legit=legit, server=[])
        out = P.analyse_run(run)
        self.assertEqual((out["legit"]["n"], out["legit"]["ok"]), (2, 1))
        self.assertEqual(out["legit"]["success"], 50.0)
        self.assertEqual(out["legit"]["timeout"], 50.0)
        self.assertEqual((out["legit_before"]["n"], out["legit_before"]["success"]), (2, 50.0))
        self.assertEqual(out["legit_first_5s"]["n"], 2)

    def test_percentiles_need_ten_successes(self):
        few = P.analyse_run(make_run(self.tmp.name, label="few", legit=[legit_row(i, latency=10 + i) for i in range(9)], server=[]))
        self.assertIsNone(few["legit"]["p50_ms"])
        many = P.analyse_run(make_run(self.tmp.name, label="many", legit=[legit_row(i, latency=10 + i) for i in range(10)], server=[]))
        self.assertEqual(many["legit"]["p50_ms"], 14.5)
        self.assertAlmostEqual(many["legit"]["p95_ms"], 18.55)

    def test_bot_lines_are_counted_by_arrival_second_and_by_status(self):
        server = [server_row(-1, "bot", "200", 99),                  # before the attack
                  server_row(0, "bot", "200", 60), server_row(1, "bot", "200", 200),
                  server_row(1, "bot", "504", 4), server_row(2, "bot", "499", 6),
                  server_row(2, "legit", "200", 7),                  # not a bot
                  server_row(30, "bot", "200", 50)]                  # after the window
        out = P.analyse_run(make_run(self.tmp.name, server=server), window=30)["bot"]
        self.assertEqual(out["total"], 270)
        self.assertEqual(out["offered_per_s"], 9.0)
        self.assertEqual(out["served_per_s"], 260 / 30)
        self.assertEqual(out["status"], {"200": 260, "499": 6, "504": 4})
        self.assertEqual(out["per_second"][:3], [60, 204, 6])
        self.assertEqual(out["offered_median_per_s"], 0)             # seconds 1-29: mostly empty

    def test_nominal_total_is_the_rate_times_the_bots_and_absent_for_wrk(self):
        self.assertEqual(P.analyse_run(make_run(self.tmp.name, rate=20, server=[]))["nominal_total"], 200)
        wrk = P.analyse_run(make_run(self.tmp.name, label="unprotected", tool="wrk", rate=0, server=[]))
        self.assertIsNone(wrk["nominal_total"])

    def test_a_run_without_server_requests_has_no_bot_block(self):
        self.assertNotIn("bot", P.analyse_run(make_run(self.tmp.name, server=None)))

    def test_done_adds_exit_code_and_seconds(self):
        out = P.analyse_run(make_run(self.tmp.name, server=[], done={"exit_code": 0, "seconds": 395.4}))
        self.assertEqual((out["exit_code"], out["seconds"]), (0, 395.4))


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_find_runs_looks_below_a_campaign_or_a_collection_of_campaigns(self):
        run = make_run(self.tmp.name, server=[])
        self.assertEqual(P.find_runs([self.tmp.name]), [run])
        self.assertEqual(P.find_runs([run]), [run])
        self.assertEqual(P.find_runs([os.path.join(self.tmp.name, "20260101T000000Z_knee_s4")]), [run])

    def test_main_prints_and_writes_both_tables_and_the_json(self):
        make_run(self.tmp.name, legit=[legit_row(i) for i in range(12)], server=[server_row(1, "bot", "200", 200)],
                 done={"exit_code": 0, "seconds": 90.2})
        md, js = os.path.join(self.tmp.name, "t.md"), os.path.join(self.tmp.name, "t.json")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(P.main([self.tmp.name, "--md", md, "--json", js]), 0)
        with open(md, encoding="utf-8") as fh:
            table = fh.read()
        self.assertEqual(out.getvalue(), table)
        self.assertIn("loadgen, 20/s per bot | 200 | 7 | 0 | 7 | - | 90 |", table)
        self.assertIn("| 12 | 100.0 | 0.0 |", table)
        self.assertEqual(table.count("`20260101T000000Z`"), 2)          # the campaign names the row in both tables
        with open(js, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)[0]["legit"]["n"], 12)

    def test_main_refuses_a_directory_without_runs(self):
        with self.assertRaises(SystemExit):
            P.main([self.tmp.name])


if __name__ == "__main__":
    unittest.main()
