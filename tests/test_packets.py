"""The packets of the re-calibration (bench/packets; docs/RECALIBRATION_2026-11_DESIGN.md 5.2, 5.3, 6.2 and K7): the script's syntax,
its --print output for every packet (pinned), its refusals, and each pre-check on fixture inputs. Nothing here runs a step."""
import contextlib
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

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

    def test_r1_holds_against_the_2026_11_04_costs_in_the_normal_band_and_later_packets_against_r1s(self):
        with open(os.path.join(GOLDEN, "R1.txt"), encoding="utf-8") as fh:
            self.assertIn("--reference bench/calibration/ddos-mitigation-2026-11-04.json --lo -0.05 --hi 0.12 --agree 0.05 --max-min 45",
                          fh.read())
        with open(os.path.join(GOLDEN, "R3.txt"), encoding="utf-8") as fh:
            self.assertIn("--reference /S/origin/origin.json --lo -0.10 --hi 0.10 --max-min 30", fh.read())

    def test_refusals(self):
        r = script("R9", "--print")
        self.assertEqual(r.returncode, 2)
        self.assertIn("PACKET is one of R1 R2a R2b R2c R3 R4 P2-1 P2-2", r.stderr)
        r = script("R4", "--session", "/S")
        self.assertEqual(r.returncode, 2)
        self.assertIn("R4 runs on the new frozen record: --record FILE", r.stderr)
        if os.geteuid() != 0:
            r = script("R2a", "--session", "/S")
            self.assertEqual(r.returncode, 2)
            self.assertIn("the steps need root", r.stderr)


def tracking(offset=0.000123, leap="Normal"):
    return f"B97DBE7B,185.125.190.123,3,1794422163.845455648,{offset:.9f},-0.000957563,2870.78,3.012,-0.111,3.214,0.0436,0.0024,258.4,{leap}"


class PrecheckTest(unittest.TestCase):
    def test_tree(self):
        self.assertEqual(PC.check_tree("", "abcdef0123", "abcdef0"), [])
        self.assertEqual(PC.check_tree(" M bench/calibrate.py\n", "abc", None), ["uncommitted change: M bench/calibrate.py"])
        self.assertEqual(PC.check_tree("", "123456789abc", "abcdef0"), ["HEAD is 123456789abc, the packet is pinned to abcdef0"])

    def test_host(self):
        here = {"uname": "Linux ddos-mitigation 7.0.0-42-generic #42-Ubuntu SMP x86_64", "mem_mib": 7422}
        self.assertEqual(PC.check_host(here, PC.PROGRAMME_HOST), [])
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
