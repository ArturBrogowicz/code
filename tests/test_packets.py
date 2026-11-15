"""The packets of the re-calibration (bench/packets; docs/RECALIBRATION_2026-11_DESIGN.md 5.2, 5.3, 6.2 and K7): the script's syntax,
its --print output for every packet (pinned), its refusals, and each pre-check on fixture inputs. Nothing here runs a step."""
import contextlib
import datetime
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
for sub in ("bench", "bench/packets", "eval"):
    sys.path.insert(0, os.path.join(REPO, sub))
import calibration as C
import hostcheck as HC
import prechecks as PC
import sim_host as S

SCRIPT = os.path.join(REPO, "bench", "packets", "packet.sh")
GOLDEN = os.path.join(HERE, "golden", "packets")
NOW = datetime.datetime(2026, 11, 16, 9, 0, tzinfo=datetime.UTC).timestamp()
HEAD = "abcdef0" + "1" * 33                 # a commit id as `git rev-parse HEAD` prints it


def script(*args):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, check=False, timeout=60)


class ScriptTest(unittest.TestCase):
    def test_the_script_parses(self):
        r = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True, check=False)
        self.assertEqual((r.returncode, r.stderr), (0, ""))

    def test_the_print_mode_of_every_packet_is_pinned(self):
        """`--print` runs nothing and needs no root; the goldens are what it prints (regenerate them on purpose, never by habit)."""
        self.assertEqual(sorted(f[:-4] for f in os.listdir(GOLDEN)), sorted(PC.PACKETS))
        for packet in PC.PACKETS:
            with self.subTest(packet=packet):
                r = script(packet, "--print", "--session", "/S", "--record", "/R", "--campaign", "/C")
                self.assertEqual(r.returncode, 0, r.stderr)
                with open(os.path.join(GOLDEN, packet + ".txt"), encoding="utf-8") as fh:
                    self.assertEqual(r.stdout, fh.read())

    def test_every_step_that_makes_runs_has_the_packets_budget_and_the_budget_is_85_of_90_minutes(self):
        for packet in PC.PACKETS:
            with open(os.path.join(GOLDEN, packet + ".txt"), encoding="utf-8") as fh:
                text = fh.read()
            with self.subTest(packet=packet):
                self.assertIn("budget      85 min", text)
                self.assertIn("ends within 90 min", text)
                self.assertIn("bench/hostcheck.py speed-hold", text)
                for line in text.splitlines():
                    if line.startswith("step") and ("calibrate.py" in line or "gate_campaign.py" in line) and " origin " not in line:
                        self.assertIn("--stop-after REMAINING", line)

    def test_root_runs_python_without_bytecode_and_takes_absolute_paths_only(self):
        """T-105 F10: root's Python writes no bytecode into the repository (-B, and PYTHONDONTWRITEBYTECODE for what it starts), and a
        relative --session or --campaign, which the stage would resolve under the repository's root, is refused."""
        for packet in PC.PACKETS:
            with open(os.path.join(GOLDEN, packet + ".txt"), encoding="utf-8") as fh:
                lines = [line for line in fh.read().splitlines() if line.startswith(("step", "pre-checks"))]
            with self.subTest(packet=packet):
                self.assertTrue(lines)
                for line in lines:
                    self.assertIn("./venv/bin/python -B bench/", line)
        with open(SCRIPT, encoding="utf-8") as fh:
            self.assertIn("\nexport PYTHONDONTWRITEBYTECODE=1\n", fh.read())
        for flag in ("--session", "--campaign"):
            with self.subTest(flag=flag):
                r = script("R2a", "--print", flag, "rel/dir")
                self.assertEqual(r.returncode, 2)
                self.assertIn(f"packet.sh: {flag} takes an absolute path (the stage runs from the repository's root), got 'rel/dir'",
                              r.stderr)

    def test_the_budget_left_is_counted_in_seconds(self):
        """T-105 F15: the minutes left to the hundredth, rounded down, never more than is left (the floored minutes gave up to 59 s
        more); less than a minute left is none."""
        with open(SCRIPT, encoding="utf-8") as fh:
            text = fh.read()
        fn = text[text.index("budget_left() {"):text.index("\n}\n", text.index("budget_left() {")) + 3]

        def left(elapsed):
            r = subprocess.run(["bash", "-c", f"BUDGET_MIN=85\n{fn}\nbudget_left 1000 {1000 + elapsed}"], capture_output=True, text=True,
                               check=False)
            return r.returncode, r.stdout.strip()
        self.assertEqual(left(0), (0, "85.00"))
        self.assertEqual(left(119), (0, "83.01"), "83 min 1 s left (the floored minutes said 84)")
        self.assertEqual(left(85 * 60 - 60), (0, "1.00"))
        self.assertEqual(left(85 * 60 - 59), (1, ""))
        self.assertEqual(left(85 * 60 + 5), (1, ""))

    def test_r1_names_the_paired_check_of_the_two_probe_contexts_as_a_manual_step(self):
        """T-105 F8 (part 2, reported only): HS1's probe is not in this tree, so R1 names the paired check as a manual step, in its
        --print and in its log."""
        with open(os.path.join(GOLDEN, "R1.txt"), encoding="utf-8") as fh:
            self.assertIn("paired      manual step, not run by this packet (T-105 F8): before R1's hold, one HS1 probe in HS1's own "
                          "context", fh.read())
        for packet in PC.PACKETS[1:]:
            with open(os.path.join(GOLDEN, packet + ".txt"), encoding="utf-8") as fh:
                self.assertNotIn("paired", fh.read())
        with open(SCRIPT, encoding="utf-8") as fh:
            self.assertIn('[ "$PACKET" = R1 ] && echo "paired check: $PAIRED"', fh.read())

    def test_r1_holds_against_hs1s_medians_on_this_pc_and_later_packets_against_r1s(self):
        """K11: R1's hold takes HS1's medians on the PC that runs the programme, never the 2026-11-04 costs (another PC's)."""
        with open(os.path.join(GOLDEN, "R1.txt"), encoding="utf-8") as fh:
            self.assertIn("--medians HS1_MEDIANS --session /S --lo -0.10 --hi 0.10 --agree 0.05 --max-min 45", fh.read())
        with open(os.path.join(GOLDEN, "R3.txt"), encoding="utf-8") as fh:
            self.assertIn("--reference /S/origin/origin.json --lo -0.10 --hi 0.10 --max-min 30", fh.read())

    def test_refusals(self):
        r = script("R9", "--print")
        self.assertEqual(r.returncode, 2)
        self.assertIn("PACKET is one of R1 R2a R2b R2c R3 R4 P2-1 P2-2", r.stderr)
        r = script("R4", "--session", "/S")
        self.assertEqual(r.returncode, 2)
        self.assertIn("R4 runs on the new frozen record: --record FILE", r.stderr)
        r = script("R2a", "--session", "/S")
        self.assertEqual(r.returncode, 2)
        self.assertIn("a packet runs at a pinned commit, which its pre-checks hold the tree and the frozen hashes to: --commit SHA", r.stderr)
        if os.geteuid() != 0:
            r = script("R2a", "--session", "/S", "--commit", HEAD)
            self.assertEqual(r.returncode, 2)
            self.assertIn("the steps need root", r.stderr)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            PC.main(["--packet", "R2a", "--session", "/S"])           # the pre-checks need the pinned commit too


def tracking(offset=0.000123, leap="Normal"):
    return f"B97DBE7B,185.125.190.123,3,1794422163.845455648,{offset:.9f},-0.000957563,2870.78,3.012,-0.111,3.214,0.0436,0.0024,258.4,{leap}"


class PrecheckTest(unittest.TestCase):
    def test_tree(self):
        self.assertEqual(PC.check_tree("", HEAD, "abcdef0"), [])
        self.assertEqual(PC.check_tree(" M bench/calibrate.py\n", HEAD, "abcdef0"), ["uncommitted change: M bench/calibrate.py"])
        self.assertEqual(PC.check_tree("", "123456789abc" + "0" * 28, "abcdef0"), ["HEAD is 123456789abc, the packet is pinned to abcdef0"])

    def test_a_command_that_failed_or_printed_nothing_is_a_problem_never_a_pass(self):
        """T-105 F5: git, systemctl, bpftool, ps and pidstat each print something when they work; nothing (or a failure, None) is a
        problem, and a packet needs its pinned commit."""
        self.assertEqual(PC.check_tree("", "", "abc1234"), ["HEAD cannot be read (git printed '')"])
        self.assertEqual(PC.check_tree(None, HEAD, "abcdef0"), ["git status failed: whether the tree is clean cannot be read"])
        for commit in (None, "", "abc", "not-a-sha"):
            with self.subTest(commit=commit):
                self.assertEqual(PC.check_tree("", HEAD, commit),
                                 [f"no pinned commit ({commit!r}): a packet runs at one (--commit SHA, 7 to 40 hex digits)"])
        for text in (None, "", "  \n"):
            with self.subTest(timers=text):
                self.assertEqual(PC.check_timers(text, NOW, 90), ["systemctl list-timers printed nothing: it cannot be read"])
            with self.subTest(bpftool=text):
                self.assertEqual(PC.check_testbed_free("", "bash\n", text), ["bpftool -j prog show printed nothing: it cannot be read"])
            with self.subTest(ps=text):
                self.assertEqual(PC.check_jobs(text), ["ps printed nothing: the running jobs cannot be read"])
                self.assertEqual(PC.check_testbed_free("", text, "[]"), ["ps printed nothing: the processes cannot be read"])
            with self.subTest(pidstat=text):
                self.assertEqual(PC.check_quiet(text), ["pidstat gave no sample: whether the host is quiet cannot be read"])
        self.assertEqual(PC.check_timers("Failed to connect to bus", NOW, 90),
                         ["systemctl list-timers did not print JSON: 'Failed to connect to bus'"])
        self.assertEqual(PC.check_testbed_free(None, "bash\n", "[]"), ["ip netns list failed: the namespaces cannot be read"])
        self.assertEqual(PC.check_quiet("Linux 7.0.0-42-generic (h) \t2026-11-16 \t_x86_64_\t(8 CPU)\n\n"),
                         ["pidstat gave no sample: whether the host is quiet cannot be read"], "a header and no sample")
        self.assertEqual(PC.check_chrony(None, None), ["chronyc gave no tracking record"])
        with mock.patch.object(PC.subprocess, "run", return_value=subprocess.CompletedProcess([], 128, "", "fatal: not a git repository")):
            self.assertIsNone(PC._sh(["git", "status"]), "a failed command is not empty output")

    def test_the_frozen_hashes(self):
        """5.2's frozen hashes match (T-105 F5): every file of the pinned commit under bench/, eval/ and the testbed's own files, and the
        frozen record, hashes here to the commit's blob."""
        blob, other = "1" * 40, "2" * 40
        self.assertEqual(PC.check_frozen({"bench/a.py": blob, "bench/r.json": other}, {"bench/a.py": blob, "bench/r.json": other},
                                         "bench/r.json"), [])
        self.assertEqual(PC.check_frozen({"bench/a.py": blob}, {"bench/a.py": other}),
                         ["bench/a.py is 222222222222 here, 111111111111 at the pinned commit"])
        self.assertEqual(PC.check_frozen({"bench/a.py": blob}, {}), ["bench/a.py is missing here, 111111111111 at the pinned commit"])
        self.assertEqual(PC.check_frozen({"bench/a.py": blob}, {"bench/a.py": blob}, "/tmp/r.json"),
                         ["the record /tmp/r.json is not a file of the pinned commit: a frozen record is committed before it is used"])
        for listing in (None, {}):
            self.assertEqual(PC.check_frozen(listing, {}), ["git ls-tree of the pinned commit listed nothing: the frozen hashes cannot be read"])
        self.assertEqual(PC.FROZEN, ("bench", "eval", "nginx.conf", "nginx_unprotected.conf", "control_plane.py", "xdp_ddos_filter.c",
                                     "test_distributed_suite.py"))

    def test_the_frozen_hashes_through_git(self):
        """parse_ls_tree and frozen_here on a small repository: they agree on a committed file and see a change to it."""
        with tempfile.TemporaryDirectory() as tmp:
            git = ["git", "-c", f"safe.directory={tmp}", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", tmp]
            os.makedirs(os.path.join(tmp, "bench"))
            with open(os.path.join(tmp, "bench", "a.py"), "w", encoding="utf-8") as fh:
                fh.write("A = 1\n")
            for argv in (["init", "-q"], ["add", "bench/a.py"], ["commit", "-q", "-m", "x"]):
                subprocess.run([*git, *argv], check=True, capture_output=True)
            head = PC._sh([*git, "rev-parse", "HEAD"]).strip()
            with mock.patch.object(PC, "REPO", tmp):
                at = PC.parse_ls_tree(PC._sh([*git, "ls-tree", "-r", head, "--", *PC.FROZEN]))
                self.assertEqual(sorted(at), ["bench/a.py"])
                self.assertEqual(PC.check_frozen(at, PC.frozen_here(git, at)), [])
                with open(os.path.join(tmp, "bench", "a.py"), "a", encoding="utf-8") as fh:
                    fh.write("B = 2\n")
                self.assertEqual(len(PC.check_frozen(at, PC.frozen_here(git, at))), 1)
                os.remove(os.path.join(tmp, "bench", "a.py"))
                self.assertIn("missing here", PC.check_frozen(at, PC.frozen_here(git, at))[0])

    def test_host(self):
        here = {"uname": "Linux ddos-mitigation 7.0.0-42-generic #42-Ubuntu SMP x86_64", "mem_mib": 7422,
                "cpu_model": "AMD Ryzen 7 7730U with Radeon Graphics", "vbox_host_version": "7.2.10r174163"}       # the laptop (K10)
        self.assertEqual(PC.check_host(here, PC.PROGRAMME_HOST), [])
        self.assertEqual(len(PC.check_host({**here, "cpu_model": "Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz",
                                            "vbox_host_version": "7.2.4r170995"}, PC.PROGRAMME_HOST)), 2, "the desktop")
        self.assertEqual(len(PC.check_host({**here, "uname": "Linux h 7.0.0-43-generic x86_64"}, PC.PROGRAMME_HOST)), 1)
        self.assertIn("the session", PC.check_host({**here, "mem_mib": 9426}, {**PC.PROGRAMME_HOST, "first_step": "origin"})[0])

    def test_uptime(self):
        self.assertEqual(PC.check_uptime(1800.0), [])
        self.assertEqual(PC.check_uptime(1799.0), ["up 1799 s, the packet waits for 1800 s"])

    def test_a_chrony_record_out_of_bounds(self):
        self.assertEqual(PC.check_chrony(tracking(), "^,*,185.125.190.123,2,6,377,22,-0.000123,-0.000130,0.012"), [])
        self.assertEqual(PC.check_chrony(tracking(0.1), ""), ["the system clock was +0.100 s off (limit 0.1 s)"])
        self.assertEqual(PC.check_chrony(tracking(0.0, "Not synchronised"), "^,*,185.125.190.123,2,6,377,22,-13836.6,-13836.6,0.012"),
                         ["chrony was not synchronised", "the source 185.125.190.123 read -13836.600 s (limit 1 s)"])
        self.assertEqual(PC.check_chrony("", ""), ["chronyc gave no tracking record"])

    def test_a_timer_due(self):
        timers = [{"unit": "apt-daily.timer", "activates": "apt-daily.service", "next": int((NOW + 95 * 60) * 1e6)},
                  {"unit": "logrotate.timer", "activates": "logrotate.service", "next": int((NOW + 101 * 60) * 1e6)},
                  {"unit": "fstrim.timer", "activates": "fstrim.service", "next": int((NOW + 60) * 1e6)},
                  {"unit": "man-db.timer", "activates": "man-db.service", "next": None}]
        self.assertEqual(PC.check_timers(json.dumps(timers), NOW, 90),
                         ["apt-daily.timer is due at 2026-11-16T10:35:00+00:00, within the packet and 10 min"])
        self.assertEqual(PC.check_timers("[]", NOW, 90), [])

    def test_a_package_job_running(self):
        self.assertEqual(PC.check_jobs("/usr/bin/python3 /usr/bin/unattended-upgrade --download-only\nbash\n"),
                         ["a package job runs: /usr/bin/python3 /usr/bin/unattended-upgrade --download-only"])
        self.assertEqual(PC.check_jobs("/usr/bin/dpkg --configure -a\n")[0][:20], "a package job runs: ")
        self.assertEqual(PC.check_jobs("vim apt-notes.txt\n"), [])

    def test_a_stray_process_or_namespace_or_program(self):
        self.assertEqual(PC.check_testbed_free("", "bash\nsshd\n", "[]"), [])
        got = PC.check_testbed_free("hg_0_perfect (id: 0)\n", "nginx: worker process\n/v/bin/python bench/loadgen.py --url x\n",
                                    json.dumps([{"id": 41, "type": "xdp", "name": "xdp_ddos_mitiga"}, {"id": 7, "type": "cgroup_skb"}]))
        self.assertEqual(got, ["a namespace is left: hg_0_perfect", "a testbed process is left: nginx: worker process",
                               "a testbed process is left: /v/bin/python bench/loadgen.py --url x",
                               "an XDP program is loaded: id 41 xdp_ddos_mitiga"])

    def test_another_process_above_5_percent(self):
        text = ("Linux 7.0.0-42-generic (h) \t2026-11-16 \t_x86_64_\t(8 CPU)\n\n"
                "09:00:00   UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command\n"
                "09:01:00  1000      1874    5.10    0.00    0.00    0.00    5.10     3  /home/u/.claude/remote/srv/x/server --serve\n"
                "09:01:00  1000      2121    4.00    0.00    0.00    0.00    4.00     2  sshd-session: artur@notty\n"
                "09:01:00     0       918   90.00    0.00    0.00    0.00   90.00     4  [kworker/4:1-events]\n")
        self.assertEqual(PC.check_quiet(text), ["/home/u/.claude/remote/srv/x/server --serve (uid 1000) used 5.1 % of a CPU"])


MAINS = ("bench/hostcheck.py", "bench/calibrate.py", "bench/executor.py", "bench/gate_campaign.py", "bench/packets/prechecks.py")
RESTORE = "signal.signal(signal.SIGINT, signal.default_int_handler)"


class StopTest(unittest.TestCase):
    """T-105 F3: packet.sh starts its stage with `setsid nohup bash ... &` and the step as `$cmd &`. A non-interactive bash starts an
    asynchronous command with SIGINT ignored, and Python keeps an ignored SIGINT, so `kill -INT` did nothing. Each Python main reached
    from packet.sh now restores the default handler at entry; `kill -TERM`, which the script and design 5.3 say, works as before."""

    def test_every_main_reached_from_packet_sh_restores_the_default_sigint_handler_at_entry(self):
        for path in MAINS:
            with open(os.path.join(REPO, path), encoding="utf-8") as fh:
                entry = fh.read().split('\nif __name__ == "__main__":\n')[-1]
            with self.subTest(path=path):
                self.assertTrue(entry.lstrip().startswith(RESTORE), entry[:200])
        with open(SCRIPT, encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn("kill -INT", text)
        self.assertEqual(text.count("kill -TERM"), 3)

    def test_a_step_launched_as_packet_sh_launches_it_stops_on_int(self):
        """The chrony sampler (bench/hostcheck.py, a main the packet's steps start) as the step of a stage launched as packet.sh
        launches it: it runs with SIGINT ignored before its main, and `kill -INT` ends it within seconds, exit 0 (its main catches
        the interrupt)."""
        with tempfile.TemporaryDirectory() as tmp:
            stage = os.path.join(tmp, "stage.sh")
            with open(stage, "w", encoding="utf-8") as fh:
                fh.write(f"""set -u
echo "stage ignores: $(awk '/^SigIgn/ {{print $2}}' /proc/$$/status)"
{sys.executable} -B {os.path.join(REPO, "bench", "hostcheck.py")} chrony-sampler --every 30 > {tmp}/sampler.txt 2>&1 & pid=$!
echo $pid > {tmp}/step.pid; wait $pid; echo "exit $?" > {tmp}/exit.txt
""")
            subprocess.run(["bash", "-c", f"setsid nohup bash {stage} > {tmp}/stage.log 2>&1 < /dev/null &"], check=True, timeout=30)
            pid = None
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline and not (os.path.exists(f"{tmp}/step.pid") and os.path.getsize(f"{tmp}/sampler.txt")):
                    time.sleep(0.1)
                with open(f"{tmp}/step.pid", encoding="utf-8") as fh:
                    pid = int(fh.read())
                with open(f"{tmp}/stage.log", encoding="utf-8") as fh:
                    ignored = int(fh.read().split("stage ignores: ")[1].split()[0], 16)
                self.assertTrue(ignored & (1 << (signal.SIGINT - 1)), "the stage runs with SIGINT ignored, as packet.sh's does")
                os.kill(pid, signal.SIGINT)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and not os.path.exists(f"{tmp}/exit.txt"):
                    time.sleep(0.1)
                self.assertTrue(os.path.exists(f"{tmp}/exit.txt"), "the step is still alive 15 s after kill -INT")
                with open(f"{tmp}/exit.txt", encoding="utf-8") as fh:
                    self.assertEqual(fh.read().strip(), "exit 0")
            finally:
                if pid and not os.path.exists(f"{tmp}/exit.txt"):
                    os.kill(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline and not os.path.exists(f"{tmp}/exit.txt"):
                        time.sleep(0.1)


class SpeedHoldCommandTest(unittest.TestCase):
    def test_it_exits_0_when_the_host_holds_and_5_when_it_does_not(self):
        costs = dict(C.load(C.PLACEHOLDER)["route_costs_ms"])
        with tempfile.TemporaryDirectory() as tmp:
            ref = os.path.join(tmp, "origin.json")
            with open(ref, "w", encoding="utf-8") as fh:
                json.dump({"route_costs_ms": costs}, fh)
            args = HC.main.__globals__["argparse"].Namespace(calibration=C.PLACEHOLDER, reference=ref, lo=-0.05, hi=0.12, agree=0.05,
                                                             every_s=300.0, max_min=45.0)
            said = io.StringIO()
            with contextlib.redirect_stdout(said):
                self.assertEqual(HC.speed_hold_main(args, S.SimHost(origin_costs=costs)), 0)
                slow = S.SimHost(origin_costs=costs, origin_slow=lambda t: 0.2)
                self.assertEqual(HC.speed_hold_main(args, slow), HC.EXIT_HOST_UNFIT)
            self.assertIn("speed hold: held after 2 probe pairs, 300 s (band -5% to +12%, agreeing within 5%)", said.getvalue())
            self.assertIn("speed hold: NOT held after 10 probe pairs, 2700 s", said.getvalue())


if __name__ == "__main__":
    unittest.main()
