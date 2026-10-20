"""Unit tests for ml/l7_run_audit.py (audit G-01, G-05, G-08). Offline, synthetic runs."""
import contextlib
import gzip
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import l7_testutil as U

sys.path.insert(0, os.path.join(U.REPO, "ml"))
import l7_run_audit as A

T0 = 1000.0


def at(t, **kw):
    """An l7json object whose request STARTS at T0 + t (msec is the completion time)."""
    rt = kw.pop("rt", 0.002)
    return U.obj(msec=T0 + t + rt, rt=rt, **kw)


def write_run(d, gz=False):
    ip_map = {
        "10.0.1.1": {"class": "benign", "kind": "browser_page", "profile": "perfect"},
        "10.0.1.2": {"class": "benign", "kind": "api_bulk", "profile": "mobile_3g"},
        "10.0.1.3": {"class": "benign", "kind": "curl_oneshot", "profile": "broadband"},
        "10.0.2.1": {"class": "attack", "family": "subthreshold_flood", "profile": None},
        "10.0.2.2": {"class": "attack", "family": "scraper", "profile": None},
        "10.0.2.3": {"class": "attack", "family": "credstuff", "profile": None},
        "10.0.2.9": {"class": "attack", "family": "volumetric_flood", "profile": None}}
    schedule = [{"ip": "10.0.2.1", "family": "subthreshold_flood", "start_s": 10, "stop_s": 50},
                {"ip": "10.0.2.2", "family": "scraper", "start_s": 20, "stop_s": 40},
                {"ip": "10.0.2.9", "family": "volumetric_flood", "start_s": 60, "stop_s": 68}]
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"seed": 3, "provenance": {"t0_wall": T0}, "schedule": schedule,
                   "ip_map": ip_map}, fh)
    with open(os.path.join(d, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"analysis": {"would_ban_ips": ["10.0.2.1", "10.0.2.2", "10.0.1.1"],
                                "det_banned_ips": {"10.0.2.3": "l7_rate"}}}, fh)
    with open(os.path.join(d, "baselines.json"), "w", encoding="utf-8") as fh:
        json.dump({"families": {"B2": {"key:mean60s>10": ["10.0.2.1", "10.0.2.2"]},
                                "B3": {"key:r=10,b=100": ["10.0.2.1"]},
                                "B4": {"p>0.99x3": [], "p>0.95x3": ["10.0.1.2"]}}}, fh)
    objs = []
    objs += [at(15 + i, ip="10.0.1.1") for i in range(10)]                      # attackers active
    objs += [at(30 + i, ip="10.0.1.2", rt=0.004) for i in range(5)]             # attackers active
    objs += [at(100 + i, ip="10.0.1.1", rt=0.020, status=503 if i == 0 else 200)
             for i in range(10)]                                                # none active
    objs += [at(62, ip="10.0.1.1", rt=5.0)]                                      # in the flood window
    objs += [at(10 + 0.03 * i, ip="10.0.2.1") for i in range(30)]               # 30 in < 1 s
    objs += [at(11 + k, ip="10.0.2.1") for k in range(1, 61)]                   # then 1 per second
    objs += [at(5, ip="10.0.1.3")]
    objs.sort(key=lambda o: o["msec"])
    text = "\n".join(json.dumps({"rx": o["msec"], "obj": o}) for o in objs) + "\n"
    path = os.path.join(d, "l7_record.jsonl" + (".gz" if gz else ""))
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(text)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return d


class RunCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = write_run(self.tmp.name)


class HarmTest(RunCase):
    def test_benign_requests_with_and_without_an_attacker_active(self):
        h = A.harm(self.run_dir)
        a, n = h["attackers_active"], h["no_attacker"]
        self.assertEqual((a["n"], a["p50_ms"], a["p95_ms"], a["p99_ms"], a["success"]),
                         (15, 2.0, 4.0, 4.0, 1.0))
        # ten 20-ms requests (one of them a 503) plus the 2-ms request of 10.0.1.3 at t = 5 s
        self.assertEqual((n["n"], n["p50_ms"], n["p99_ms"], n["success"]), (11, 20.0, 20.0, 0.9091))

    def test_requests_in_the_flood_window_are_left_out(self):
        h = A.harm(self.run_dir)
        # the 5-second request at t = 62 s would dominate the p99 of "no attacker" if it were kept
        self.assertEqual(h["no_attacker"]["n"], 11)
        self.assertLess(h["no_attacker"]["p99_ms"], 100)

    def test_attacker_requests_are_not_counted(self):
        h = A.harm(self.run_dir)
        self.assertEqual(h["attackers_active"]["n"] + h["no_attacker"]["n"], 26)

    def test_percentile_definition_is_nearest_rank(self):
        self.assertEqual(A._pctl(list(range(1, 11)), 0.5), 6)
        self.assertEqual(A._pctl([7], 0.99), 7)
        self.assertIsNone(A._pctl([], 0.5))

    def test_markdown_row(self):
        text = A.render_harm([A.harm(self.run_dir)])
        self.assertIn("| " + os.path.basename(self.run_dir) + " | 15, 2.0 / 4.0 / 4.0, 1.0 |", text)


class RolesTest(RunCase):
    def test_who_is_caught_and_flagged(self):
        r = A.roles(self.run_dir)
        self.assertEqual((r["seed"], r["comparison_attackers"], r["benign_ips"]), (3, 2, 3))
        self.assertEqual(r["deterministic_caught"], 0)           # credstuff is outside the set
        d = r["detectors"]
        self.assertEqual((d["GRU"]["caught"], d["GRU"]["benign_flagged"]), (2, 1))
        self.assertEqual(d["GRU"]["benign_roles"], ["10.0.1.1 browser_page/perfect"])
        self.assertEqual((d["B2"]["caught"], d["B2"]["benign_flagged"]), (2, 0))
        self.assertEqual((d["B3"]["caught"], d["B3"]["benign_flagged"]), (1, 0))
        self.assertEqual((d["B4"]["caught"], d["B4"]["benign_flagged"]), (0, 0))
        self.assertEqual(d["B4@0.95"]["benign_roles"], ["10.0.1.2 api_bulk/mobile_3g"])

    def test_pooled_and_by_role_over_runs(self):
        other = tempfile.TemporaryDirectory()
        self.addCleanup(other.cleanup)
        write_run(other.name)
        s = A.roles_summary([A.roles(self.run_dir), A.roles(other.name)])
        self.assertEqual((s["runs"], s["comparison_attackers"], s["benign_ips"]), (2, 4, 6))
        self.assertEqual(s["pooled"]["GRU"], {"caught": 4, "benign_flagged": 2})
        self.assertEqual(s["benign_flags_by_role"]["GRU"], {"10.0.1.1 browser_page/perfect": 2})

    def test_markdown_lists_the_detectors(self):
        text = A.render_roles([A.roles(self.run_dir)])
        self.assertIn("| GRU | B2 | B3 | B4 | B4@0.95 |", text)
        self.assertIn("2/2 · 1 benign", text)
        self.assertIn("Pooled: GRU 2/2 attackers, 1/3 benign", text)

    def test_a_missing_baseline_setting_gives_an_empty_flag_set(self):
        r = A.roles(self.run_dir, settings=(("B2", "B2", "key:mean60s>99"),))
        self.assertEqual(r["detectors"]["B2"]["caught"], 0)


class RatesTest(RunCase):
    def test_peak_and_sixty_second_mean(self):
        by_ip = {c["ip"]: c for c in A.rates(self.run_dir)["clients"]}
        flood = by_ip["10.0.2.1"]
        self.assertEqual(flood["requests"], 90)
        self.assertEqual(flood["peak_1s"], 30)
        self.assertEqual(flood["max_60s_mean_rps"], 1.5)         # 90 requests in the busiest 60 s

    def test_default_selection_and_everything(self):
        default = {c["ip"] for c in A.rates(self.run_dir)["clients"]}
        self.assertEqual(default, {"10.0.1.1", "10.0.1.2", "10.0.2.1"})
        everything = {c["ip"] for c in A.rates(self.run_dir, everything=True)["clients"]}
        self.assertIn("10.0.1.3", everything)

    def test_role_and_netem_are_reported(self):
        c = {c["ip"]: c for c in A.rates(self.run_dir)["clients"]}["10.0.1.2"]
        self.assertEqual((c["role"], c["netem"]), ("api_bulk", "mobile_3g"))


class InputTest(unittest.TestCase):
    def test_gzipped_recording(self):
        with tempfile.TemporaryDirectory() as plain, tempfile.TemporaryDirectory() as gz:
            write_run(plain)
            write_run(gz, gz=True)
            self.assertEqual(A.harm(plain)["attackers_active"], A.harm(gz)["attackers_active"])

    def test_missing_recording(self):
        with tempfile.TemporaryDirectory() as empty, self.assertRaises(FileNotFoundError):
            list(A.iter_objects(empty))


class CliTest(RunCase):
    def test_each_view_writes_markdown_and_json(self):
        for view in ("harm", "roles", "rates"):
            md, js = os.path.join(self.tmp.name, f"{view}.md"), os.path.join(self.tmp.name, f"{view}.json")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = A.main([view, self.run_dir, "--md", md, "--json", js])
            self.assertEqual(rc, 0, view)
            with open(md, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), buf.getvalue(), view)
            with open(js, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["view"], view)
            self.assertEqual(len(data["runs"]), 1)
            self.assertEqual("summary" in data, view == "roles")


if __name__ == "__main__":
    unittest.main()
