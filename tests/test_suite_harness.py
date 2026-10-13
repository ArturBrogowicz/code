"""Unit tests for the evaluation settings and result bookkeeping of
test_distributed_suite.py (no root, no network; no suite command is executed).

Importing the suite registers cleanup_all() with atexit, and that function pkills
test processes and deletes the namespaces. The import below patches
atexit.register and signal.signal so neither handler is ever installed.
"""
import csv
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
with mock.patch("atexit.register"), mock.patch("signal.signal"):
    import test_distributed_suite as S

PROFILES = ["perfect", "broadband", "mobile_3g", "mobile_bad"]
WEIGHTS = [0.30, 0.35, 0.25, 0.10]


class CaptureScriptContractTest(unittest.TestCase):
    def test_every_suite_symbol_the_capture_uses_exists(self):
        # capture_testbed_dataset.py does `import test_distributed_suite as S` and reuses
        # its topology/traffic helpers; renaming one would break the dataset capture.
        import re
        with open(os.path.join(REPO, "capture_testbed_dataset.py"), encoding="utf-8") as fh:
            used = set(re.findall(r"\bS\.([A-Za-z_]\w*)", fh.read()))
        self.assertTrue(used)
        self.assertEqual(sorted(n for n in used if not hasattr(S, n)), [])


class OperatingPointTest(unittest.TestCase):
    def test_default_is_the_historical_configuration(self):
        name, op = S.resolve_operating_point({})
        self.assertEqual(name, "default")
        self.assertEqual(op, {"GUNICORN_WORKERS": "8", "GUNICORN_THREADS": "4", "WRK_CONNS": "50",
                              "WRK_THREADS": "2", "BOTNET_COUNT": "5", "SERVER_CPUS": "",
                              "ATTACK_CPUS": ""})

    def test_knee_is_the_exp2a_configuration(self):
        # docs/REPORT_ADDENDUM_EXP0_EXP1.md §J: 1 worker/thread on cpu0, attackers on 1-7,
        # wrk -c400 from 10 bots.
        _, op = S.resolve_operating_point({"OPERATING_POINT": "knee"})
        self.assertEqual((op["GUNICORN_WORKERS"], op["GUNICORN_THREADS"]), ("1", "1"))
        self.assertEqual((op["SERVER_CPUS"], op["ATTACK_CPUS"]), ("0", "1-7"))
        self.assertEqual((op["WRK_CONNS"], op["BOTNET_COUNT"]), ("400", "10"))

    def test_variable_overrides_preset(self):
        _, op = S.resolve_operating_point({"OPERATING_POINT": "knee", "WRK_CONNS": "200"})
        self.assertEqual(op["WRK_CONNS"], "200")
        self.assertEqual(op["GUNICORN_WORKERS"], "1")

    def test_unknown_name_is_rejected(self):
        with self.assertRaises(ValueError):
            S.resolve_operating_point({"OPERATING_POINT": "kneee"})


class ProfilePlanTest(unittest.TestCase):
    def test_same_seed_same_plan(self):
        self.assertEqual(S.profile_plan(20, 7, PROFILES, WEIGHTS),
                         S.profile_plan(20, 7, PROFILES, WEIGHTS))
        self.assertNotEqual(S.profile_plan(20, 1, PROFILES, WEIGHTS),
                            S.profile_plan(20, 2, PROFILES, WEIGHTS))

    def test_seed_zero_plan_is_pinned(self):
        # The default plan (PROFILE_SEED=0). If this changes, runs before and after the
        # change no longer share their client mix; update docs/EVALUATION.md as well.
        self.assertEqual(S.profile_plan(20, 0, PROFILES, WEIGHTS), [
            "mobile_3g", "mobile_3g", "broadband", "perfect", "broadband", "broadband",
            "mobile_3g", "broadband", "broadband", "broadband", "mobile_bad", "broadband",
            "perfect", "mobile_3g", "broadband", "perfect", "mobile_bad", "mobile_bad",
            "mobile_3g", "mobile_bad"])


class EqualExposureTest(unittest.TestCase):
    def test_hold_remaining(self):
        self.assertEqual(S.attack_hold_remaining(100.0, 0, 105.0), 0.0)       # historical mode
        self.assertEqual(S.attack_hold_remaining(None, 30, 105.0), 0.0)
        self.assertEqual(S.attack_hold_remaining(100.0, 30, 110.0), 20.0)
        self.assertEqual(S.attack_hold_remaining(100.0, 30, 200.0), 0.0)

    def test_wrk_runs_at_least_as_long_as_the_window(self):
        with mock.patch.object(S, "ATTACK_DURATION", 0.0):
            self.assertEqual(S._wrk_seconds(), 30)
        with mock.patch.object(S, "ATTACK_DURATION", 60.0):
            self.assertEqual(S._wrk_seconds(), 65)


class ModeTest(unittest.TestCase):
    CASES = (   # (env, NGINX_PROTECTED, tag, label, nginx conf)
        ({}, False, "performance", "xdp", "nginx.conf"),
        ({"MITIGATION_BACKEND": "iptables"}, False, "iptables", "iptables", "nginx.conf"),
        ({"MITIGATION_MODE": "none"}, False, "unprotected", "unprotected", "nginx_unprotected.conf"),
        ({"MITIGATION_MODE": "none"}, True, "nginxlimits", "nginxlimits", "nginx.conf"),
    )

    def test_tags_labels_and_nginx_config(self):
        for env, protected, tag, label, conf in self.CASES:
            with mock.patch.dict(os.environ, env, clear=False), \
                    mock.patch.object(S, "NGINX_PROTECTED", protected):
                for k in ("MITIGATION_MODE", "MITIGATION_BACKEND"):
                    if k not in env:
                        os.environ.pop(k, None)
                self.assertEqual(S._mode_tag(), tag)
                self.assertEqual(S._mode_label(), label)
                self.assertEqual(os.path.basename(S._nginx_conf()), conf)
                self.assertEqual(S._avail_csv_paths()[0], f"/tmp/availability_{tag}.csv")


class CommandTest(unittest.TestCase):
    def test_daemon_command_is_unchanged_outside_a_run(self):
        with mock.patch.object(S, "_results_dir", None), \
                mock.patch.dict(os.environ, {"MITIGATION_BACKEND": "iptables"}):
            self.assertEqual(S._daemon_cmd(), ["ip", "netns", "exec", "server_ns", "env",
                                               "MITIGATION_BACKEND=iptables", S.PYTHON_VENV,
                                               "-u", S.CONTROL_PLANE])

    def test_daemon_command_logs_events_into_the_run(self):
        with mock.patch.object(S, "_results_dir", "/var/tmp/ddos_campaigns/r1"):
            self.assertIn("BAN_EVENTS=/var/tmp/ddos_campaigns/r1/ban_events.jsonl", S._daemon_cmd())

    def test_cpu_pinning(self):
        with mock.patch.object(S, "SERVER_CPUS", ""):
            self.assertEqual(S._srv(["nginx"]), ["nginx"])
        with mock.patch.object(S, "SERVER_CPUS", "0"):
            self.assertEqual(S._srv(["nginx"]), ["taskset", "-c", "0", "nginx"])
        with mock.patch.object(S, "ATTACK_CPUS", "1-7"), \
                mock.patch.object(S.subprocess, "run") as fake_run:
            S.run(["wrk", "-c400"], ns="bot_3")
            S.run(["curl", "x"], ns="legit_1")
        bot_argv, legit_argv = (c.args[0] for c in fake_run.call_args_list)
        self.assertEqual(bot_argv, ["ip", "netns", "exec", "bot_3", "taskset", "-c", "1-7",
                                    "wrk", "-c400"])
        self.assertEqual(legit_argv, ["ip", "netns", "exec", "legit_1", "curl", "x"])


class ResultsFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_out_paths(self):
        with mock.patch.object(S, "_results_dir", None):
            self.assertEqual(S._out_paths("/tmp/a.csv", "a.csv"), ["/tmp/a.csv"])
        with mock.patch.object(S, "_results_dir", self.dir):
            self.assertEqual(S._out_paths("/tmp/a.csv", "a.csv"),
                             ["/tmp/a.csv", os.path.join(self.dir, "a.csv")])

    def test_append_csv_writes_header_once(self):
        path = os.path.join(self.dir, "x.csv")
        S._append_csv(path, ["A", "B"], [[1, 2]])
        S._append_csv(path, ["A", "B"], [[3, 4], [5, 6]])
        with open(path) as fh:
            self.assertEqual(list(csv.reader(fh)), [["A", "B"], ["1", "2"], ["3", "4"], ["5", "6"]])

    def test_scenario_events_from_ban_log(self):
        events = [
            {"t_wall": 50.0, "kind": "start"},
            {"t_wall": 99.0, "kind": "ban", "ip": "10.0.2.9", "engine": "l4_syn"},   # before attack
            {"t_wall": 101.5, "kind": "ban", "ip": "10.0.2.1", "engine": "l7_rate"},
            {"t_wall": 101.2, "kind": "ban", "ip": "10.0.2.1", "engine": "l4_syn"},  # earliest wins
            {"t_wall": 102.0, "kind": "ban", "ip": "10.0.2.2", "engine": "gru"},
            {"t_wall": 130.0, "kind": "ban", "ip": "10.0.2.3", "engine": "l4_syn"},  # after the kill
            {"t_wall": 125.0, "kind": "ban", "ip": "10.0.1.4", "engine": "l7_rate"}, # legit: FP
        ]
        with open(os.path.join(self.dir, "ban_events.jsonl"), "w") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in events)
        bots = ["10.0.2.1", "10.0.2.2", "10.0.2.3", "10.0.2.9"]
        with mock.patch.object(S, "_results_dir", self.dir), \
                mock.patch.dict(S._attack, {"t0": 90.0, "start": 100.0, "end": 120.0}):
            ev = S._scenario_events(bots, ["10.0.1.4", "10.0.1.5"])
        self.assertTrue(ev["available"])
        self.assertEqual({ip: round(t, 3) for ip, t in ev["ttm"].items()},
                         {"10.0.2.1": 1.2, "10.0.2.2": 2.0})
        self.assertEqual(ev["engine"], {"10.0.2.1": "l4_syn", "10.0.2.2": "gru"})
        self.assertEqual(ev["fp"], {"10.0.1.4"})

    def test_scenario_events_unavailable_without_daemon_start(self):
        with mock.patch.object(S, "_results_dir", self.dir):
            self.assertFalse(S._scenario_events(["10.0.2.1"], [])["available"])

    def test_daemon_log_archive(self):
        live = os.path.join(self.dir, "live.log")
        with open(live, "w") as fh:
            fh.write("[BAN] 10.0.2.1 banned for 300s. Reason: Heuristic (RPS=51.0, errors=0%)")
        with mock.patch.object(S, "LOG_FILE", live), mock.patch.object(S, "_results_dir", self.dir), \
                mock.patch.object(S, "_daemon_log_label", "Distributed HTTP Flood"):
            S._archive_daemon_log()
            S._archive_daemon_log()                 # label consumed: second call is a no-op
        with open(os.path.join(self.dir, "daemon.log")) as fh:
            self.assertEqual(fh.read(), "===== Distributed HTTP Flood =====\n[BAN] 10.0.2.1 banned "
                                        "for 300s. Reason: Heuristic (RPS=51.0, errors=0%)\n")

    def test_provenance_records_code_and_settings(self):
        with mock.patch.object(S, "_results_dir", self.dir), \
                mock.patch.object(S, "_profile_plan", [("10.0.1.1", "perfect")]):
            S._write_provenance("running")
        with open(os.path.join(self.dir, "provenance.json")) as fh:
            prov = json.load(fh)
        self.assertEqual(prov["status"], "running")
        self.assertEqual(prov["profile_plan"], [{"ip": "10.0.1.1", "profile": "perfect"}])
        self.assertEqual(prov["inputs_sha256"]["control_plane.py"],
                         S.ban_events.file_sha256(os.path.join(REPO, "control_plane.py")))
        self.assertIn(prov["operating_point"]["name"], S.OPERATING_POINTS)
        self.assertEqual(len(prov["git"]["commit"] or ""), 40)


if __name__ == "__main__":
    unittest.main()
