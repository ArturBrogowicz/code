"""Offline tests for analysing an EXP-C campaign: run labels `mode@cell` (eval/run_campaign.py --loads), where the plain
label is the closed-loop `wrk` cell. Contrasts are drawn inside a cell, never across load models; the load the server
received (server_requests.csv) is tabulated; published campaigns keep their analysis byte for byte.

Needs the venv (pandas, numpy, scipy, matplotlib):  venv/bin/python -m unittest discover -s tests -v
"""
import csv
import filecmp
import json
import os
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "eval"))
try:
    import campaign as C
    import plot_campaign as PC
    import run_level_stats as RLS
    from analyze_campaign import analyse
    from test_campaign_analysis import make_run
    HAVE_STACK = True
except ImportError:                      # system python without pandas/scipy/matplotlib: skip
    HAVE_STACK = False

R3 = os.path.join(REPO, "results", "2026-10-13_exp2a-knee_reproduction")
SERVER_FIELDS = ["Data_Scenario", "Mode", "T_Epoch_s", "T_Rel_s", "Client_Class", "Status", "Requests",
                 "Request_Time_Mean_s", "Request_Time_Max_s"]
# successes out of 20 legit requests per block (seeds 1-3), by (cell, mode)
OK_OF_20 = {("", "xdp"): [20, 20, 20], ("", "unprotected"): [10, 12, 8],
            ("loadgen100", "xdp"): [20, 20, 20], ("loadgen100", "unprotected"): [19, 20, 18]}


def label_of(mode, cell):
    return mode + ("@" + cell if cell else "")


def write_server_requests(run_dir, rows):
    with open(os.path.join(run_dir, "server_requests.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(SERVER_FIELDS)
        for rel, cls, status, n in rows:
            w.writerow(["Distributed HTTP Flood", "m", 1000 + rel, rel, cls, status, n, 0.001, 0.002])


def set_attack_duration(run_dir, seconds):
    path = os.path.join(run_dir, "provenance.json")
    with open(path) as fh:
        prov = json.load(fh)
    prov["settings"]["ATTACK_DURATION"] = seconds
    with open(path, "w") as fh:
        json.dump(prov, fh)


def build_campaign(root, server=False):
    for (cell, mode), counts in OK_OF_20.items():
        label = label_of(mode, cell)
        for seed, ok in enumerate(counts, start=1):
            make_run(root, label, f"run{seed}", seed, [1] * ok + [0] * (20 - ok))
            run_dir = os.path.join(root, label, f"run{seed}")
            if server:
                set_attack_duration(run_dir, 5)
                scale = 1 if mode == "xdp" else 2
                write_server_requests(run_dir, [
                    (-1, "bot", "200", 77), (0, "bot", "200", 50 * scale), (1, "bot", "200", 100 * scale),
                    (1, "bot", "503", 20 * scale), (2, "bot", "499", 30 * scale), (2, "bot", "200", 100 * scale),
                    (2, "legit", "200", 9), (3, "bot", "200", 100 * scale), (4, "bot", "200", 100 * scale),
                    (5, "bot", "200", 999)])
    return root


@unittest.skipUnless(HAVE_STACK, "needs the venv (pandas, scipy, matplotlib)")
class LabelTest(unittest.TestCase):
    def test_a_plain_label_is_the_closed_loop_cell(self):
        self.assertEqual(C.split_label("xdp"), ("xdp", ""))
        self.assertEqual(C.split_label("xdp@loadgen125"), ("xdp", "loadgen125"))
        self.assertEqual(C.reference_label("unprotected", ""), "unprotected")
        self.assertEqual(C.reference_label("unprotected", "loadgen125"), "unprotected@loadgen125")
        self.assertFalse(C.has_cells(["xdp", "unprotected"]))
        self.assertTrue(C.has_cells(["xdp", "unprotected@loadgen125"]))

    def test_the_order_without_cells_is_the_old_one(self):
        self.assertEqual(C.ordered_modes(["unprotected", "zzz", "xdp", "aaa", "iptables", "nginxlimits"]),
                         ["xdp", "iptables", "nginxlimits", "unprotected", "aaa", "zzz"])

    def test_the_order_with_cells_is_closed_loop_first_then_each_cell_in_natural_order(self):
        labels = ["xdp@loadgen1000", "xdp@loadgen250", "unprotected@loadgen125", "xdp", "unprotected",
                  "nginxlimits@loadgen125", "xdp@loadgen125", "unprotected@loadgen250"]
        self.assertEqual(C.ordered_modes(labels), [
            "xdp", "unprotected",
            "xdp@loadgen125", "nginxlimits@loadgen125", "unprotected@loadgen125",
            "xdp@loadgen250", "unprotected@loadgen250", "xdp@loadgen1000"])
        self.assertEqual(C.cells(labels), ["", "loadgen125", "loadgen250", "loadgen1000"])

    def test_display_names(self):
        self.assertEqual(C.display_name("xdp"), "XDP + daemon")
        self.assertEqual(C.display_name("xdp@loadgen125"), "XDP + daemon (loadgen125)")
        self.assertEqual(C.display_name("something"), "something")


@unittest.skipUnless(HAVE_STACK, "needs the venv (pandas, scipy, matplotlib)")
class ContrastsByCellTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = build_campaign(self.tmp.name)
        self.data = C.load(self.root)

    def test_delta_compares_each_label_with_the_reference_of_its_own_cell(self):
        dl = C.delta_vs_reference_by_cell(self.data["raw"], self.data["runs"]).set_index("cell")
        self.assertEqual(sorted(dl.index), ["", "loadgen100"])
        self.assertEqual((dl.loc[""]["mode"], dl.loc[""].reference), ("xdp", "unprotected"))
        self.assertEqual((dl.loc["loadgen100"]["mode"], dl.loc["loadgen100"].reference),
                         ("xdp@loadgen100", "unprotected@loadgen100"))
        self.assertAlmostEqual(dl.loc[""].delta_pp, 50.0)
        self.assertAlmostEqual(dl.loc["loadgen100"].delta_pp, 5.0)
        self.assertIn("paired by PROFILE_SEED (3 blocks)", dl.loc["loadgen100"].method)

    def test_the_plain_function_still_compares_everything_with_one_label(self):
        dl = C.delta_vs_reference(self.data["raw"], self.data["runs"])
        # the old reading: everything against the one label, across load models
        self.assertEqual(sorted(dl["mode"]), ["unprotected@loadgen100", "xdp", "xdp@loadgen100"])

    def test_run_level_contrasts_by_cell_with_the_reference_arm_and_the_harm_check(self):
        df = RLS.contrasts_by_cell(self.data, min_blocks=3).set_index("cell")
        closed, opened = df.loc[""], df.loc["loadgen100"]
        self.assertEqual((closed["mode"], closed.reference), ("xdp", "unprotected"))
        self.assertEqual((opened["mode"], opened.reference), ("xdp@loadgen100", "unprotected@loadgen100"))
        self.assertAlmostEqual(closed.mean_diff_pp, 50.0)
        self.assertAlmostEqual(opened.mean_diff_pp, 5.0)
        self.assertEqual((closed.decision, opened.decision), ("supported (+)", "not shown"))
        self.assertAlmostEqual(closed.reference_mean_pp, 50.0)
        self.assertAlmostEqual(opened.reference_mean_pp, 95.0)
        self.assertEqual((bool(closed.harmed), bool(opened.harmed)), (True, False))

    def test_the_harm_check_is_strict_below_ninety_percent(self):
        self.assertEqual(RLS.HARM_BELOW_PCT, 90.0)
        df = RLS.contrasts_by_cell(self.data, min_blocks=3)
        self.assertEqual(list(df.columns[:2]), ["cell", "scenario"])

    def test_the_markdown_names_the_cell_and_whether_it_tests_anything(self):
        text = RLS.to_markdown(RLS.contrasts_by_cell(self.data, min_blocks=3))
        self.assertIn("| Load cell |", text)
        self.assertIn("| Harm check |", text)
        self.assertIn("xdp@loadgen100 vs unprotected@loadgen100 (during)", text)
        self.assertIn("| wrk | Distributed HTTP Flood |", text)
        self.assertIn("harmed", text)
        self.assertIn("not harmed", text)

    def test_a_campaign_without_cells_keeps_the_old_columns(self):
        with tempfile.TemporaryDirectory() as plain:
            for seed, ok in enumerate([20, 20, 20], start=1):
                make_run(plain, "xdp", f"run{seed}", seed, [1] * ok + [0] * (20 - ok))
            for seed, ok in enumerate([10, 12, 8], start=1):
                make_run(plain, "unprotected", f"run{seed}", seed, [1] * ok + [0] * (20 - ok))
            cols = list(RLS.contrasts(C.load(plain), min_blocks=3).columns)
        self.assertNotIn("cell", cols)
        self.assertNotIn("reference_mean_pp", cols)


@unittest.skipUnless(HAVE_STACK, "needs the venv (pandas, scipy, matplotlib)")
class OfferedLoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = build_campaign(self.tmp.name, server=True)
        self.data = C.load(self.root)

    def test_bot_lines_by_arrival_in_the_attack_window(self):
        off = C.offered(self.data["server_requests"], self.data["runs"]).set_index("mode")
        x = off.loc["xdp@loadgen100"]
        # seconds 0-4 of a 5 s attack: 50, 120, 130, 100, 100 bot lines; 77 before, 999 after, legit ignored
        self.assertEqual((x.runs, x.window_s), (3, 5))
        self.assertAlmostEqual(x.offered_per_s, 100.0)
        self.assertAlmostEqual(x.offered_median_per_s, 110.0)      # seconds 1-4: 100, 100, 120, 130
        self.assertAlmostEqual(x.status_200_per_s, 90.0)
        self.assertAlmostEqual(x.status_503_per_s, 4.0)
        self.assertAlmostEqual(x.status_499_per_s, 6.0)
        self.assertAlmostEqual(x.other_status_per_s, 0.0)
        self.assertAlmostEqual(off.loc["unprotected"].offered_per_s, 200.0)   # the unprotected runs doubled

    def test_rows_follow_the_cell_order_and_no_file_means_no_table(self):
        off = C.offered(self.data["server_requests"], self.data["runs"])
        self.assertEqual(list(off["mode"]), ["xdp", "unprotected", "xdp@loadgen100", "unprotected@loadgen100"])
        with tempfile.TemporaryDirectory() as plain:
            build_campaign(plain)
            data = C.load(plain)
            self.assertTrue(C.offered(data["server_requests"], data["runs"]).empty)

    def test_analyse_writes_the_cell_tables_and_the_offered_table_only_when_there_are_data(self):
        out = os.path.join(self.tmp.name, "out")
        analyse(self.root, out)
        self.assertTrue(os.path.isfile(os.path.join(out, "offered.csv")))
        with open(os.path.join(out, "delta_vs_reference.csv")) as fh:
            self.assertEqual(next(csv.reader(fh))[:3], ["cell", "scenario", "mode"])
        with open(os.path.join(out, "summary.md")) as fh:
            text = fh.read()
        self.assertIn("## Offered load at the server", text)
        self.assertIn("## Difference vs the unprotected arm of the same load cell", text)
        self.assertIn("| loadgen100 | Distributed HTTP Flood | XDP + daemon |", text)
        self.assertIn("unprotected (loadgen100)", text)
        with tempfile.TemporaryDirectory() as plain:
            only_closed = os.path.join(plain, "c")
            for seed, ok in enumerate([20, 20, 20], start=1):
                make_run(only_closed, "xdp", f"run{seed}", seed, [1] * ok + [0] * (20 - ok))
            for seed, ok in enumerate([10, 12, 8], start=1):
                make_run(only_closed, "unprotected", f"run{seed}", seed, [1] * ok + [0] * (20 - ok))
            analyse(only_closed, os.path.join(plain, "out"))
            self.assertFalse(os.path.exists(os.path.join(plain, "out", "offered.csv")))
            with open(os.path.join(plain, "out", "delta_vs_reference.csv")) as fh:
                self.assertEqual(next(csv.reader(fh))[0], "scenario")


@unittest.skipUnless(HAVE_STACK and os.path.isdir(R3), "needs the venv and the published R3 campaign")
class PublishedAnalysisUnchangedTest(unittest.TestCase):
    def test_the_published_analysis_of_r3_regenerates_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            analyse(R3, tmp)
            committed = os.path.join(R3, "analysis")
            names = sorted(f for f in os.listdir(committed) if os.path.isfile(os.path.join(committed, f)))
            self.assertEqual(sorted(os.listdir(tmp)), names)
            match, mismatch, errors = filecmp.cmpfiles(tmp, committed, names, shallow=False)
            self.assertEqual((mismatch, errors), ([], []))
            self.assertEqual(match, names)


@unittest.skipUnless(HAVE_STACK, "needs the venv (pandas, scipy, matplotlib)")
class FiguresByCellTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = build_campaign(os.path.join(self.tmp.name, "campaign"), server=True)

    def test_one_availability_figure_per_scenario_and_cell(self):
        out = os.path.join(self.tmp.name, "figs")
        written = [os.path.basename(p) for p in PC.plot_all(self.root, out)]
        self.assertIn("availability_distributed_http_flood__wrk.png", written)
        self.assertIn("availability_distributed_http_flood__loadgen100.png", written)
        self.assertNotIn("availability_distributed_http_flood.png", written)

    def test_a_campaign_without_cells_keeps_its_figure_name(self):
        plain = os.path.join(self.tmp.name, "plain")
        for seed in (1, 2):
            make_run(plain, "xdp", f"run{seed}", seed, [1] * 10)
            make_run(plain, "unprotected", f"run{seed}", seed, [1] * 5 + [0] * 5)
        written = [os.path.basename(p) for p in PC.plot_all(plain, os.path.join(self.tmp.name, "f2"))]
        self.assertIn("availability_distributed_http_flood.png", written)

    def test_the_cell_styles_follow_the_mode_not_the_whole_label(self):
        self.assertEqual(PC._mode_style("xdp@loadgen100"), PC._mode_style("xdp"))
        self.assertEqual(PC._mode_style("unprotected@loadgen9"), PC._mode_style("unprotected"))


if __name__ == "__main__":
    unittest.main()
