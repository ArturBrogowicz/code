"""Unit tests for the evaluation settings and result bookkeeping of
test_distributed_suite.py (no root, no network; no suite command is executed).

Importing the suite registers cleanup_all() with atexit, and that function pkills
test processes and deletes the namespaces. The import below patches
atexit.register and signal.signal so neither handler is ever installed.
"""
import csv
import datetime
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "bench"))
with mock.patch("atexit.register"), mock.patch("signal.signal"):
    import test_distributed_suite as S
import loadtools as LT

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


class PreflightTest(unittest.TestCase):
    def test_missing_venv_stops_before_the_run_starts(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(S, "PYTHON_VENV", os.path.join(d, "venv/bin/python")), \
                mock.patch.object(S.os, "geteuid", return_value=0), \
                mock.patch.object(S.atexit, "register"), \
                mock.patch.object(S, "_init_results_dir") as init_results, \
                mock.patch.object(S, "_write_provenance"), \
                mock.patch.object(S, "build_topology") as build_topology, \
                mock.patch("builtins.print"), \
                self.assertRaises(SystemExit) as cm:
            S.main()
        self.assertEqual(cm.exception.code, 1)
        init_results.assert_not_called()
        build_topology.assert_not_called()


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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def flood_manifest(tmp):
    """A manifest for the flood's preflight: the real engine file, a stand-in k6 binary and a vegeta
    that is only smoke-tested."""
    tools = {"loadgen": {"kind": "builtin", "version": "1", "path": "bench/loadgen.py",
                         "sha256": LT.sha256_file(os.path.join(REPO, "bench", "loadgen.py")),
                         "status": "verified"}}
    for name, status in (("k6", "verified"), ("vegeta", "smoke-tested")):
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(f"stand-in {name}".encode())
        os.chmod(path, 0o755)
        tools[name] = {"kind": "external", "version": "v1", "path": name,
                       "sha256": sha(f"stand-in {name}".encode()), "status": status}
    return {"schema": 1, "root": tmp, "tools": tools}


class FakeBot:
    def __init__(self, alive=True):
        self.alive, self.killed = alive, False

    def poll(self):
        return None if self.alive else 1

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return 0


class FloodSettingTest(unittest.TestCase):
    def test_the_default_is_the_closed_loop_wrk_without_a_rate(self):
        for env in ({}, {"FLOOD_TOOL": "wrk"}, {"FLOOD_TOOL": "wrk", "FLOOD_RATE": ""},
                    {"FLOOD_TOOL": "wrk", "FLOOD_RATE": "0"}):
            self.assertEqual(S.resolve_flood(env), ("wrk", 0.0))
        self.assertEqual((S.FLOOD_TOOL, S.FLOOD_RATE), ("wrk", 0.0))   # the environment of these tests

    def test_an_open_loop_tool_takes_a_rate_per_bot(self):
        self.assertEqual(S.resolve_flood({"FLOOD_TOOL": "loadgen", "FLOOD_RATE": "100"}),
                         ("loadgen", 100.0))
        self.assertEqual(S.resolve_flood({"FLOOD_TOOL": " k6 ", "FLOOD_RATE": "62.5"}), ("k6", 62.5))

    def test_settings_that_do_not_go_together_are_refused(self):
        for env in ({"FLOOD_TOOL": "vegeta", "FLOOD_RATE": "100"},      # not a flood tool
                    {"FLOOD_TOOL": "wrk2", "FLOOD_RATE": "100"},
                    {"FLOOD_TOOL": "wrk", "FLOOD_RATE": "100"},         # wrk is closed-loop
                    {"FLOOD_TOOL": "loadgen"},                          # open-loop needs a rate
                    {"FLOOD_TOOL": "k6", "FLOOD_RATE": "0"},
                    {"FLOOD_TOOL": "k6", "FLOOD_RATE": "-5"},
                    {"FLOOD_TOOL": "k6", "FLOOD_RATE": "fast"},
                    {"FLOOD_TOOL": "k6", "FLOOD_RATE": "nan"},
                    {"FLOOD_TOOL": "k6", "FLOOD_RATE": "inf"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                S.resolve_flood(env)

    def test_the_tools_are_those_the_wrapper_lists(self):
        self.assertEqual(S.FLOOD_TOOLS, LT.FLOOD_TOOLS)
        self.assertEqual(S.FLOOD_TOOLS, ("wrk",) + LT.OPEN_LOOP_TOOLS)

    def test_the_label_names_an_open_loop_flood_and_the_default_label_is_unchanged(self):
        with mock.patch.dict(os.environ, {"MITIGATION_MODE": "none"}), \
                mock.patch.object(S, "NGINX_PROTECTED", False):
            self.assertEqual(S._mode_label(), "unprotected")
            with mock.patch.object(S, "FLOOD_TOOL", "loadgen"), mock.patch.object(S, "FLOOD_RATE", 100.0):
                self.assertEqual(S._mode_label(), "unprotected@loadgen100")
            with mock.patch.object(S, "FLOOD_TOOL", "k6"), mock.patch.object(S, "FLOOD_RATE", 62.5):
                self.assertEqual(S._mode_label(), "unprotected@k662.5")


class FloodCommandTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.manifest = flood_manifest(self.tmp)

    def launched(self, ns="bot_3"):
        with mock.patch.object(S.subprocess, "Popen") as popen:
            S.start_flood(ns, "10.0.2.3")
        return popen.call_args.args[0]

    def test_the_default_flood_is_exactly_the_historical_wrk_command(self):
        with mock.patch.object(S, "WRK_THREADS", "2"), mock.patch.object(S, "WRK_CONNS", "400"), \
                mock.patch.object(S, "ATTACK_DURATION", 0.0), mock.patch.object(S, "ATTACK_CPUS", "1-7"):
            self.assertEqual(self.launched(), ["ip", "netns", "exec", "bot_3", "taskset", "-c", "1-7",
                                              "wrk", "-t2", "-c400", "-d30s", "http://10.0.0.1/"])
        with mock.patch.object(S, "WRK_THREADS", "2"), mock.patch.object(S, "WRK_CONNS", "50"), \
                mock.patch.object(S, "ATTACK_DURATION", 60.0), mock.patch.object(S, "ATTACK_CPUS", ""):
            self.assertEqual(self.launched(), ["ip", "netns", "exec", "bot_3", "wrk", "-t2", "-c50",
                                              "-d65s", "http://10.0.0.1/"])

    def test_the_engine_runs_in_the_bots_namespace_with_its_own_open_file_limit(self):
        with mock.patch.object(S, "FLOOD_TOOL", "loadgen"), mock.patch.object(S, "FLOOD_RATE", 100.0), \
                mock.patch.object(S, "ATTACK_DURATION", 0.0), mock.patch.object(S, "ATTACK_CPUS", "1-7"), \
                mock.patch.object(S, "_results_dir", self.tmp):
            argv = S.flood_argv("bot_3", manifest=self.manifest, root=self.tmp)
            with mock.patch.object(S, "flood_argv", return_value=argv):
                full = self.launched()
        self.assertEqual(full[:10], ["ip", "netns", "exec", "bot_3", "taskset", "-c", "1-7",
                                     "prlimit", "--nofile=16384", "--"])
        self.assertEqual(argv[:3], ["prlimit", "--nofile=16384", "--"])
        rest = argv[3:]
        self.assertEqual(rest[:2], [sys.executable, os.path.join(REPO, "bench", "loadgen.py")])
        for flag, value in (("--url", "http://10.0.0.1/"), ("--rate", "100"), ("--duration", "30"),
                            ("--timeout", "10"), ("--max-inflight", "5000"), ("--pool", "100"),
                            ("--method", "GET")):
            self.assertEqual(rest[rest.index(flag) + 1], value, flag)
        self.assertNotIn("taskset", argv)                        # run() adds the pinning
        self.assertNotIn("--allow-loopback", argv)               # the target is inside the testbed
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "attackers", "bot_3")))

    def test_k6_gets_its_script_and_never_reports_usage(self):
        with mock.patch.object(S, "FLOOD_TOOL", "k6"), mock.patch.object(S, "FLOOD_RATE", 200.0), \
                mock.patch.object(S, "ATTACK_DURATION", 0.0), mock.patch.object(S, "_results_dir", self.tmp):
            argv = S.flood_argv("bot_1", manifest=self.manifest, root=self.tmp)
        self.assertIn("--no-usage-report", argv)
        self.assertEqual(argv[argv.index("RATE=200") - 1], "-e")
        self.assertIn("PRE_VUS=100", argv)                       # 200 x 0.3 s, at least 100
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "attackers", "bot_1", "k6.js")))

    def test_the_rate_sets_the_pool_by_the_rule_of_the_verification(self):
        with mock.patch.object(S, "FLOOD_TOOL", "loadgen"), mock.patch.object(S, "_results_dir", self.tmp):
            argv = S.flood_argv("bot_1", rate=1000.0, manifest=self.manifest, root=self.tmp)
        self.assertEqual(argv[argv.index("--pool") + 1], "300")   # 1000 x 0.3 s

    def test_the_launch_check_needs_every_generator_alive(self):
        bots = [(FakeBot(), f"bot_{i}", f"10.0.2.{i}") for i in range(3)]
        with mock.patch.object(S, "FLOOD_TOOL", "loadgen"), mock.patch.object(S.time, "sleep") as sleep:
            S.flood_alive(bots, 3)
            sleep.assert_called_once_with(S.FLOOD_LAUNCH_CHECK_S)
            for procs, bots_n, why in (([*bots[:2], (FakeBot(alive=False), "bot_2", "10.0.2.2")], 3, "exited"),
                                       (bots[:2], 3, "launched: 2")):
                with self.subTest(why=why), mock.patch.object(S, "kill_procs") as kill, \
                        self.assertRaisesRegex(RuntimeError, "did not start"):
                    S.flood_alive(procs, bots_n)
                kill.assert_called_once()

    def test_wrk_needs_no_launch_check_and_loses_no_time(self):
        with mock.patch.object(S.time, "sleep") as sleep:
            S.flood_alive([], 10)
        sleep.assert_not_called()

    def test_kill_procs_stops_open_loop_generators_too_and_nothing_extra_for_wrk(self):
        for tool, extra in (("wrk", []), ("loadgen", ["pkill -9 -f bench/loadgen.py", "pkill -9 -x k6"])):
            with self.subTest(tool=tool), mock.patch.object(S, "FLOOD_TOOL", tool), \
                    mock.patch.object(S, "run") as run, mock.patch.dict(S._attack):
                S.kill_procs([(FakeBot(), "bot_1", "10.0.2.1")])
            self.assertEqual([c.args[0] for c in run.call_args_list],
                             ["pkill -9 -f hping3", "pkill -9 -x wrk", "pkill -9 -f _dist_", *extra])

    def test_cleanup_kills_wrk_by_exact_name_and_nothing_by_a_substring_of_its_own_runner(self):
        with mock.patch.object(S.subprocess, "run") as sub_run, mock.patch.object(S.time, "sleep"), \
                mock.patch.object(S, "_daemon_proc", None), mock.patch("builtins.print"):
            sub_run.return_value = mock.Mock(stdout="", returncode=0)
            S.cleanup_all()
        killed = [c.args[0] for c in sub_run.call_args_list if c.args and c.args[0][:1] == ["pkill"]]
        self.assertIn(["pkill", "-9", "-x", "wrk"], killed)
        self.assertNotIn(["pkill", "-9", "-f", "wrk"], killed)

    RUNNER_COMMAND_LINES = (
        "python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 10 --attack-duration 30",
        ("sudo timeout -s INT 600 python3 eval/run_campaign.py --operating-point knee --scenarios 4 "
         "--attack-duration 30 --modes unprotected --runs 1 --seed-base 100 --loads wrk,loadgen:20"),
        "sudo python3 eval/run_campaign.py --modes xdp,iptables,nginxlimits,unprotected --set FLOOD_TOOL=wrk",
        ("sudo python3 eval/run_campaign.py --modes unprotected,nginxlimits,xdp --runs 10 "
         "--loads wrk,loadgen:50,loadgen:100,loadgen:200 --attack-duration 30"),
        "sudo python3 eval/run_campaign.py --loads loadgen:40,loadgen:80,k6:160 --scenarios 4,7,8,9",
    )

    def kill_patterns(self):
        """Every pattern the suite hands to `pkill -f` or `pgrep -f`, read from its source."""
        with open(os.path.join(REPO, "test_distributed_suite.py"), encoding="utf-8") as fh:
            src = fh.read()
        patterns = set()
        for m in re.finditer(r'\[\s*"(?:pkill|pgrep)"([^\]]*)\]', src):
            args = re.findall(r'"([^"]*)"', m.group(1))
            if "-f" in args:
                patterns.add(args[args.index("-f") + 1])
        patterns.update(m.group(2) for m in re.finditer(r'pkill\s+((?:-\S+\s+)*)-f\s+([^\s"]+)', src))
        return patterns

    def test_no_pattern_the_suite_kills_by_matches_the_command_line_of_a_campaign_runner(self):
        # The suite kills with `pkill -f <pattern>`, which matches the whole command line of every
        # process on the machine. A runner whose arguments match kills itself (it did, with
        # `--loads wrk,...`, on 2026-10-22). Unit tests never run pkill, so read the patterns.
        patterns = self.kill_patterns()
        self.assertTrue({"control_plane.py", "gunicorn", "hping3", "_dist_", "nginx: master process",
                         "bench/loadgen.py"} <= patterns, patterns)
        self.assertNotIn("wrk", patterns)
        for line in self.RUNNER_COMMAND_LINES:
            for pattern in patterns:
                with self.subTest(pattern=pattern, line=line[:60]):
                    self.assertIsNone(re.search(pattern, line))


class FloodPreflightTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.manifest = flood_manifest(self.tmp)

    def check(self, tool, **kw):
        with mock.patch.object(S.shutil, "which", return_value="/usr/bin/prlimit"):
            return S.flood_preflight(tool, self.manifest, self.tmp, **kw)

    def test_wrk_needs_nothing(self):
        self.assertIsNone(S.flood_preflight("wrk", {"tools": {}}))

    def test_verified_tools_pass(self):
        self.assertIsNone(self.check("loadgen"))
        self.assertIsNone(self.check("k6"))

    def test_a_tool_that_is_not_verified_is_refused(self):
        self.assertRegex(self.check("vegeta"), "FLOOD_TOOL=vegeta.*not 'verified'")

    def test_a_changed_or_missing_binary_is_refused(self):
        with open(os.path.join(self.tmp, "k6"), "ab") as f:
            f.write(b" tampered")
        self.assertRegex(self.check("k6"), "binary changed")
        os.remove(os.path.join(self.tmp, "k6"))
        self.assertRegex(self.check("k6"), "missing")

    def test_a_target_outside_the_testbed_is_refused(self):
        with mock.patch.object(S, "HTTP_URL", "http://8.8.8.8/"):
            self.assertIsNotNone(self.check("loadgen"))

    def test_without_prlimit_the_open_file_limit_cannot_be_raised(self):
        with mock.patch.object(S.shutil, "which", return_value=None):
            self.assertRegex(S.flood_preflight("loadgen", self.manifest, self.tmp), "needs prlimit")

    def test_a_refusal_stops_main_before_the_run_starts(self):
        with mock.patch.object(S.os, "geteuid", return_value=0), \
                mock.patch.object(S.os, "access", return_value=True), \
                mock.patch.object(S, "flood_preflight", return_value="FLOOD_TOOL=vegeta: not verified"), \
                mock.patch.object(S.atexit, "register"), \
                mock.patch.object(S, "_init_results_dir") as init_results, \
                mock.patch.object(S, "build_topology") as build_topology, \
                mock.patch("builtins.print"), \
                self.assertRaises(SystemExit) as cm:
            S.main()
        self.assertEqual(cm.exception.code, 1)
        init_results.assert_not_called()
        build_topology.assert_not_called()


class FloodProvenanceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def provenance(self):
        with mock.patch.object(S, "_results_dir", self.dir):
            S._write_provenance("running")
        with open(os.path.join(self.dir, "provenance.json")) as fh:
            return json.load(fh)

    def test_a_default_run_records_wrk_and_no_flood_block(self):
        prov = self.provenance()
        self.assertEqual((prov["settings"]["FLOOD_TOOL"], prov["settings"]["FLOOD_RATE"]), ("wrk", 0.0))
        self.assertNotIn("flood", prov)
        self.assertFalse([f for f in prov["inputs_sha256"] if f.startswith("bench/")])

    def test_an_open_loop_run_records_the_tool_its_settings_and_the_files_that_define_them(self):
        with mock.patch.object(S, "FLOOD_TOOL", "loadgen"), mock.patch.object(S, "FLOOD_RATE", 100.0), \
                mock.patch.object(S, "BOTNET_COUNT", 10):
            prov = self.provenance()
        flood, manifest = prov["flood"], LT.load_manifest()["tools"]["loadgen"]
        self.assertEqual((flood["tool"], flood["rate_per_bot"], flood["bots"], flood["scenario"]),
                         ("loadgen", 100.0, 10, 4))
        self.assertEqual(flood["limits"], {"workers": 100, "max_workers": 5000, "connections": 100})
        self.assertEqual(flood["manifest"], {"version": manifest["version"], "sha256": manifest["sha256"],
                                             "status": manifest["status"]})
        self.assertEqual(prov["settings"]["FLOOD_RATE"], 100.0)
        for name in ("bench/loadtools.py", "bench/loadtools.json", "bench/loadgen.py"):
            self.assertEqual(prov["inputs_sha256"][name],
                             S.ban_events.file_sha256(os.path.join(REPO, name)))


def log_line(stamp, ip, status=200, took=0.001):
    """A line of nginx.conf's json_ml_format."""
    return json.dumps({"timestamp": stamp, "client_ip": ip, "request_method": "GET", "request_uri": "/",
                       "status": status, "request_time": took, "request_length": 60, "bytes_sent": 300,
                       "user_agent": ""})


def stamp(second):
    return f"2026-10-22T17:00:{second:02d}+00:00"


def epoch(text):
    return int(datetime.datetime.fromisoformat(text).timestamp())


class ServerRequestsTest(unittest.TestCase):
    LINES = (log_line(stamp(1), "10.0.2.1", 200, 0.010), log_line(stamp(1), "10.0.2.2", 200, 0.030),
             log_line(stamp(1), "10.0.2.3", 503, 0.0), log_line(stamp(1), "10.0.1.7", 200, 0.002),
             log_line(stamp(2), "10.0.0.1", 200, 0.001), log_line(stamp(2), "10.0.2.1", 200, 0.050))

    def test_requests_are_counted_per_second_client_class_and_status(self):
        rows, bad = S.aggregate_access_log(self.LINES, epoch(stamp(1)) + 0.4)
        sec = epoch(stamp(1))
        self.assertEqual(bad, 0)
        self.assertEqual(rows, [[sec, 0, "bot", 200, 2, 0.02, 0.03],
                                [sec, 0, "bot", 503, 1, 0.0, 0.0],
                                [sec, 0, "legit", 200, 1, 0.002, 0.002],
                                [sec + 1, 1, "bot", 200, 1, 0.05, 0.05],
                                [sec + 1, 1, "other", 200, 1, 0.001, 0.001]])

    def test_time_before_the_attack_is_negative_and_blank_without_an_attack(self):
        rows, _ = S.aggregate_access_log(self.LINES, epoch(stamp(2)) + 0.9)
        self.assertEqual([r[1] for r in rows], [-1, -1, -1, 0, 0])
        rows, _ = S.aggregate_access_log(self.LINES)
        self.assertEqual({r[1] for r in rows}, {""})

    def test_a_request_is_binned_by_the_second_it_arrived_not_the_second_it_ended(self):
        end = epoch(stamp(10))
        rows, bad = S.aggregate_access_log([
            log_line(stamp(10), "10.0.2.1", 200, 0.2),       # 10.5 - 0.2: the second it ended in
            log_line(stamp(10), "10.0.2.1", 200, 0.6),       # 9.9: the one before
            log_line(stamp(10), "10.0.2.1", 499, 2.3),       # 8.2
            log_line(stamp(10), "10.0.2.1", 499, 10.4)])     # 0.1
        self.assertEqual(bad, 0)
        self.assertEqual([(r[0] - end, r[3]) for r in rows],
                         [(-10, 499), (-2, 499), (-1, 200), (0, 200)])

    def test_a_fast_request_stays_in_its_log_second(self):
        rows, _ = S.aggregate_access_log([log_line(stamp(7), "10.0.2.1", 200, t)
                                          for t in (0.0, 0.001, 0.2, 0.49)])
        self.assertEqual([r[0] for r in rows], [epoch(stamp(7))])

    def test_the_offset_of_the_timestamp_is_honoured(self):
        rows, _ = S.aggregate_access_log([log_line("1970-01-01T01:00:10+01:00", "10.0.2.1"),
                                          log_line("1970-01-01T00:00:10+00:00", "10.0.2.1")])
        self.assertEqual(rows, [[10, "", "bot", 200, 2, 0.001, 0.001]])

    def test_lines_that_cannot_be_read_are_counted_not_fatal(self):
        rows, bad = S.aggregate_access_log([
            "not json", "{}", '{"timestamp": "x"}', '{"timestamp": 5, "client_ip": "10.0.2.1"}',
            log_line("garbage", "10.0.2.1"), log_line(stamp(3), "10.0.2.1")])
        self.assertEqual(bad, 5)
        self.assertEqual(len(rows), 1)

    def test_a_request_time_that_is_not_a_finite_number_is_unreadable_not_fatal(self):
        def line(value):
            return (f'{{"timestamp": "{stamp(3)}", "client_ip": "10.0.2.1", "status": 200, '
                    f'"request_time": {value}}}')

        rows, bad = S.aggregate_access_log([line("Infinity"), line("NaN"), line("-Infinity"),
                                            line('"-"'), line("0.5")])
        self.assertEqual(bad, 4)
        self.assertEqual(len(rows), 1)

    def test_an_empty_log_gives_no_rows(self):
        self.assertEqual(S.aggregate_access_log([]), ([], 0))

    def test_client_classes_follow_the_address_plan(self):
        self.assertEqual([S._client_class(ip) for ip in ("10.0.2.1", "10.0.2.10", "10.0.1.40", "10.0.0.1",
                                                          "10.0.21.1", "127.0.0.1")],
                         ["bot", "bot", "legit", "other", "other", "other"])


class ServerRequestsFileTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)
        self.log = os.path.join(self.dir, "access.log")
        with open(self.log, "w") as f:
            f.write("\n".join(ServerRequestsTest.LINES) + "\nnot json\n")

    def archive(self, scenario, **patches):
        with mock.patch.object(S, "NGINX_ACCESS_LOG", self.log), \
                mock.patch.object(S, "_results_dir", patches.get("results_dir", self.dir)), \
                mock.patch.dict(S._attack, {"start": epoch(stamp(1)) + 0.4}), \
                mock.patch.dict(os.environ, {"MITIGATION_MODE": "none"}), \
                mock.patch.object(S, "NGINX_PROTECTED", False), \
                mock.patch("builtins.print") as printed:
            S._archive_server_requests(scenario)
        return printed

    def rows(self):
        with open(os.path.join(self.dir, "server_requests.csv"), newline="") as f:
            return list(csv.reader(f))

    def test_each_scenario_appends_its_rows_under_one_header(self):
        self.archive("Distributed HTTP Flood")
        self.archive("Distributed UDP Flood")
        rows = self.rows()
        self.assertEqual(rows[0], S.SERVER_REQUESTS_FIELDS)
        self.assertEqual(rows.count(S.SERVER_REQUESTS_FIELDS), 1)
        self.assertEqual({r[0] for r in rows[1:]}, {"Distributed HTTP Flood", "Distributed UDP Flood"})
        self.assertEqual({r[1] for r in rows[1:]}, {"unprotected"})        # the mode label of the run
        first = [r for r in rows[1:] if r[0] == "Distributed HTTP Flood"]
        self.assertEqual(len(first), 5)
        self.assertEqual(first[0][2:], [str(epoch(stamp(1))), "0", "bot", "200", "2", "0.02", "0.03"])

    def test_lines_it_could_not_read_are_reported(self):
        printed = self.archive("Distributed HTTP Flood")
        self.assertIn("1 access-log lines could not be read", printed.call_args.args[0])

    def test_without_a_results_directory_nothing_is_written(self):
        self.archive("Distributed HTTP Flood", results_dir=None)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "server_requests.csv")))

    def test_an_unreadable_log_is_a_warning_not_an_error(self):
        os.remove(self.log)
        printed = self.archive("Distributed HTTP Flood")
        self.assertIn("access log is unreadable", printed.call_args.args[0])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "server_requests.csv")))

    def test_every_scenario_ends_by_archiving_its_log(self):
        with mock.patch.object(S, "_avail_finalize"), \
                mock.patch.object(S, "check_collateral_damage", return_value=(True, [])), \
                mock.patch.object(S, "_scenario_events", return_value={"available": False, "fp": set(),
                                                                       "ttm": {}, "engine": {}}), \
                mock.patch.object(S, "verify_legit_http", return_value=(1, 0, 1)), \
                mock.patch.object(S, "_write_scenario_result"), \
                mock.patch.object(S, "_archive_server_requests") as archive, \
                mock.patch.object(S, "_avail_scenario", "Distributed HTTP Flood"), \
                mock.patch.object(S, "results", []), \
                mock.patch("builtins.print"):
            S.report("Distributed HTTP Flood", {"10.0.2.1": ("XDP", 1.0)}, [("bot_1", "10.0.2.1")],
                     [("legit_1", "10.0.1.1", "perfect")])
        archive.assert_called_once_with("Distributed HTTP Flood")


if __name__ == "__main__":
    unittest.main()
