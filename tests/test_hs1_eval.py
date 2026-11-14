"""HS1's evaluator, probe and series script (docs/HS1_PREREG.md): the published 2026-11-11 speed series and synthetic runs.

Hermetic: every run directory is written to a temporary directory; nothing reads the journal, /proc or the network, and no
route of the origin is timed (the probe is tested with a stand-in origin module).
"""
import datetime as dt
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench", "vm"))
import hs1_eval as H
import hs1_probe as HP

UTC = dt.UTC
FROZEN = {"C0": 0.005444691406250243, "C1": 3.40712200000004, "C2": 1.77428400000057, "C3": 29.837566999999954,
          "C5": 159.70452500000044}
T0 = dt.datetime(2026, 11, 20, 9, 0, 0, tzinfo=UTC)
LAPTOP = {"utc": "", "boot_id": "8ac83bb1-82e8-4aa0-9d00-000000000001", "uptime_s": "3600.25", "kernel": "7.0.0-42-generic",
          "cmdline": "BOOT_IMAGE=/vmlinuz-7.0.0-42-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro", "memtotal_kb": "7600852",
          "cpu_model": "AMD Ryzen 7 7730U with Radeon Graphics", "tsc_mhz": "1996.250", "vbox_host_version": "7.2.10r174163",
          "storage": "internal SSD", "timezone": "Etc/UTC", "utc_offset": "+0000",
          "chrony_tracking": "B97DBE7B,185.125.190.123,3,1794422163.8,0.000012,-0.000095,0.0001,3.012,-0.111,3.214,0.0436,"
                             "0.0024,258.4,Normal",
          "chrony_sources": "^,*,185.125.190.123,2,10,377,100,0.0001,0.0001,0.01|^,-,185.125.190.122,2,10,377,90,0.002,0.002,0.02",
          "masked": "".join(f"{t}:masked," for t in H.MASKED_TIMERS), "holds": " ".join(sorted(H.HELD)),
          "dpkg_sha256": "a" * 64, "snap_sha256": "b" * 64, "busy_procs": "", "repeats": "21", "n_samples": "36",
          "interval_s": "300"}

# The published offline speed series of 2026-11-11 (results/2026-11-11_harm-drift-check/speed_series/speed_series.txt), on the
# desktop (i7-10700F, VirtualBox 7.2.4), 46 probes on CPUs 0 and 1, offsets from the 2026-11-04 costs as printed.
SERIES_20261111 = """\
19:27:36Z series cpus [0] C0 +25% C1 +41% C2 +48% C3 +32% C5 +38% refused
19:27:39Z series cpus [1] C0 +22% C1 +30% C2 +34% C3 +23% C5 +33% refused
19:32:42Z series cpus [0] C0 +54% C1 +52% C2 +35% C3 +43% C5 +33% refused
19:32:44Z series cpus [1] C0 +13% C1 +26% C2 +71% C3 +42% C5 +35% refused
19:37:47Z series cpus [0] C0 +16% C1 +2% C2 +3% C3 +0% C5 +8% accepted
19:37:49Z series cpus [1] C0 +4% C1 +34% C2 +62% C3 +21% C5 +22% refused
19:42:51Z series cpus [0] C0 -1% C1 -6% C2 -2% C3 -3% C5 -3% accepted
19:42:53Z series cpus [1] C0 -1% C1 -2% C2 +0% C3 -3% C5 +1% accepted
19:47:58Z series cpus [0] C0 +25% C1 +14% C2 +33% C3 +28% C5 +32% refused
19:48:01Z series cpus [1] C0 +37% C1 +25% C2 +48% C3 +33% C5 +40% refused
19:53:07Z series cpus [0] C0 +8% C1 +9% C2 +78% C3 +26% C5 +20% refused
19:53:09Z series cpus [1] C0 +27% C1 +12% C2 +21% C3 +14% C5 +12% refused
19:58:13Z series cpus [0] C0 +1% C1 +11% C2 +3% C3 +12% C5 +8% accepted
19:58:15Z series cpus [1] C0 +5% C1 -3% C2 -0% C3 +6% C5 +6% accepted
20:03:19Z series cpus [0] C0 +5% C1 +1% C2 +6% C3 +16% C5 +12% accepted
20:03:21Z series cpus [1] C0 +18% C1 +4% C2 -1% C3 +4% C5 +11% accepted
20:08:24Z series cpus [0] C0 +1% C1 +5% C2 -1% C3 +9% C5 +12% accepted
20:08:26Z series cpus [1] C0 +5% C1 +4% C2 +16% C3 +2% C5 +4% accepted
20:13:29Z series cpus [0] C0 +21% C1 +20% C2 +1% C3 +5% C5 +4% accepted
20:13:32Z series cpus [1] C0 +3% C1 +2% C2 +20% C3 +8% C5 +4% accepted
20:18:35Z series cpus [0] C0 +10% C1 +3% C2 +0% C3 +9% C5 +10% accepted
20:18:37Z series cpus [1] C0 +25% C1 +8% C2 +4% C3 +8% C5 +6% refused
20:23:42Z series cpus [0] C0 -1% C1 -5% C2 +0% C3 +2% C5 +2% accepted
20:23:44Z series cpus [1] C0 +7% C1 +2% C2 +2% C3 +7% C5 +6% accepted
20:28:47Z series cpus [0] C0 +7% C1 +24% C2 +24% C3 +14% C5 +17% accepted
20:28:49Z series cpus [1] C0 +7% C1 +17% C2 +35% C3 +12% C5 +12% refused
20:33:52Z series cpus [0] C0 +10% C1 +24% C2 +26% C3 +8% C5 +15% refused
20:33:54Z series cpus [1] C0 +20% C1 +21% C2 +17% C3 +14% C5 +18% accepted
20:38:59Z series cpus [0] C0 +26% C1 +10% C2 +30% C3 +19% C5 +28% refused
20:39:02Z series cpus [1] C0 +18% C1 +24% C2 +27% C3 +28% C5 +23% refused
20:44:05Z series cpus [0] C0 +24% C1 +18% C2 +33% C3 +19% C5 +18% refused
20:44:07Z series cpus [1] C0 +2% C1 +5% C2 +3% C3 +5% C5 +3% accepted
20:49:11Z series cpus [0] C0 +30% C1 +39% C2 +26% C3 +41% C5 +32% refused
20:49:14Z series cpus [1] C0 +12% C1 +22% C2 +28% C3 +23% C5 +31% refused
20:54:19Z series cpus [0] C0 +25% C1 +31% C2 +43% C3 +40% C5 +45% refused
20:54:21Z series cpus [1] C0 +25% C1 +23% C2 +29% C3 +37% C5 +31% refused
20:59:25Z series cpus [0] C0 +35% C1 +26% C2 +31% C3 +26% C5 +28% refused
20:59:28Z series cpus [1] C0 +40% C1 +46% C2 +50% C3 +33% C5 +28% refused
21:04:32Z series cpus [0] C0 +27% C1 +40% C2 +25% C3 +27% C5 +32% refused
21:04:35Z series cpus [1] C0 +35% C1 +25% C2 +19% C3 +33% C5 +32% refused
21:09:40Z series cpus [0] C0 +37% C1 +20% C2 +31% C3 +27% C5 +27% refused
21:09:42Z series cpus [1] C0 +14% C1 +11% C2 +14% C3 +20% C5 +17% accepted
21:14:46Z series cpus [0] C0 -2% C1 -6% C2 -2% C3 -2% C5 -2% accepted
21:14:48Z series cpus [1] C0 +4% C1 -6% C2 +6% C3 +0% C5 +1% accepted
21:19:52Z series cpus [0] C0 -1% C1 -5% C2 -2% C3 +4% C5 +3% accepted
21:19:54Z series cpus [1] C0 -2% C1 +1% C2 +11% C3 +6% C5 +5% accepted
"""
# The journal of that boot (1b4af896) in the series' window, as `journalctl --utc -o short-iso` printed it.
CHRONYD_20261111 = """\
2026-11-11T19:32:23+00:00 ddos-mitigation chronyd[1342]: Forward time jump detected!
2026-11-11T19:32:23+00:00 ddos-mitigation chronyd[1342]: Can't synchronise: no selectable sources (0 unreachable sources)
2026-11-11T19:34:32+00:00 ddos-mitigation chronyd[1342]: Selected source 185.125.190.122 (1.ntp.ubuntu.com)
"""
KERNEL_20261111 = """\
2026-11-11T19:30:25+00:00 ddos-mitigation kernel: workqueue: ata_sff_pio_task hogged CPU for >10000us 67 times, consider switching to WQ_UNBOUND
2026-11-11T21:17:35+00:00 ddos-mitigation kernel: workqueue: vmstat_shepherd hogged CPU for >10000us 11 times, consider switching to WQ_UNBOUND
"""
DESKTOP = {"cpu_model": "Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz", "vbox_host_version": "7.2.4r170995",
           "kernel": "7.0.0-42-generic", "memtotal_kb": "7600852", "storage": "not recorded"}


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def jline(t, ident, text):
    return f"{t.strftime('%Y-%m-%dT%H:%M:%S')}+00:00 ddos-mitigation {ident}: {text}"


def extract_text(name, boot, body, mode="ok", stderr=()):
    """An extract as hs1_series.sh's collector writes it (header with the command's exit status, body, end marker), or a
    damaged one: mode 'missing' (None), 'nomarker' (the body alone), 'rc1' (the command failed), 'otherboot'."""
    if mode == "missing":
        return None
    if mode == "nomarker":
        return "".join(x + "\n" for x in body)
    head = (f"# hs1-collect v1 file={name} boot={'f' * 32 if mode == 'otherboot' else boot} rc={1 if mode == 'rc1' else 0} "
            "utc=2026-11-20T12:00:00Z")
    return "\n".join([head, *body, *(f"# stderr: {x}" for x in stderr), "# hs1-collect end"]) + "\n"


def clean_cost(sample, cpu, route):
    return FROZEN[route] * 1.06 * (1 + 0.02 * math.sin(1.7 * sample + 2.3 * int(cpu) + len(route)))


class Run:
    """A synthetic HS1 run directory: the files hs1_series.sh writes, with what a test changes."""

    def __init__(self, d, n=36, start=T0, cpus=("0", "1", "7"), cost=clean_cost, end_reason="complete", ident=None):
        self.d, self.n, self.start, self.cpus, self.cost = d, n, start, cpus, cost
        self.ident = dict(LAPTOP if ident is None else ident, utc=iso(start))
        self.ident_end_changes, self.no_ident_end = {}, False
        self.end_reason = end_reason if end_reason != "complete" else f"complete {n}"
        self.kernel, self.chronyd, self.gaps, self.busy, self.offsets = [], [], [], set(), {}
        self.boot_end, self.dpkg, self.snap, self.iostat, self.probe_lines = None, [], [], None, None
        self.modes, self.stderr, self.end_text, self.pidstat_hms = {}, {}, None, False

    def sample_time(self, i):
        return self.start + dt.timedelta(seconds=30 + (i - 1) * H.INTERVAL_S)

    def end_time(self):
        return self.sample_time(self.n) + dt.timedelta(seconds=40)

    def at(self, s):
        return self.start + dt.timedelta(seconds=s)

    def write(self):
        os.makedirs(self.d, exist_ok=True)
        end = self.end_time()
        def w(name, text):
            with open(os.path.join(self.d, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        w("identity_start.txt", "".join(f"{k}={v}\n" for k, v in self.ident.items()))
        if self.end_reason and not self.no_ident_end:
            w("identity_end.txt", "".join(f"{k}={v}\n" for k, v in dict(self.ident, utc=iso(end), **self.ident_end_changes).items()))
        if self.end_reason:
            w("END", self.end_text or f"{iso(end)} {self.end_reason}\n")
        if self.probe_lines is None:
            lines = []
            for i in range(1, self.n + 1):
                for j, c in enumerate(self.cpus):
                    costs = {r: self.cost(i, c, r) for r in FROZEN}
                    off = {r: (costs[r] - FROZEN[r]) / FROZEN[r] * 100 for r in FROZEN}
                    lines.append(json.dumps({"utc": iso(self.sample_time(i) + dt.timedelta(seconds=5 * j)), "sample": i,
                                             "cpus": [int(c)], "repeats": 21, "costs_ms": costs, "offset_pct": off,
                                             "refused": sorted(r for r in off if abs(off[r]) > 25)}))
            self.probe_lines = lines
        w("probes.jsonl", "\n".join(self.probe_lines) + "\n")
        total = int((end - self.start).total_seconds())
        skip = set()
        for at_s, gap in self.gaps:
            skip |= set(range(at_s + 5, at_s + gap, 5))
        mp = [f"Linux 7.0.0-42-generic (ddos-mitigation) \t{self.start:%Y-%m-%d} \t_x86_64_\t(8 CPU)", ""]
        for s in range(5, total + 5, 5):
            if s in skip:
                continue
            hh = self.at(s).strftime("%H:%M:%S")
            mp += [f"{hh}     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle",
                   f"{hh}     all    0.10    0.00    0.10    0.00    0.00    0.00    0.00    0.00    0.00   99.80",
                   f"{hh}       0    0.20    0.00    0.10    0.00    0.00    0.00    0.00    0.00    0.00   99.70", ""]
        w("mpstat.txt", "\n".join(mp) + "\n")
        pid = [f"Linux 7.0.0-42-generic (ddos-mitigation) \t{self.start:%m/%d/%Y} \t_x86_64_\t(8 CPU)", "",
               "# Time        UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command"]
        busy_t = [self.sample_time(i).timestamp() for i in self.busy]
        for s in range(10, total + 10, 10):
            e = int(self.at(s).timestamp())
            e = self.at(s).strftime("%H:%M:%S") if self.pidstat_hms else e
            pid += [f" {e}      0        15    0.00    0.20    0.00    0.00    0.20     5  rcu_preempt",
                    f" {e}   1000      2315    0.20    0.10    0.00    0.00    0.30     3  /home/artur/.claude/remote/srv/x/server --serve",
                    (f" {e}   1000      9001   99.00    0.50    0.00    0.00   99.50     0  /home/artur/DDoS-mitigation/.venv/bin/python -I -B "
                     f"{REPO}/bench/vm/hs1_probe.py 3 21")]
            if any(abs(self.at(s).timestamp() - b) <= 30 for b in busy_t):
                pid.append(f" {e}   1000      7777   60.00    1.00    0.00    0.00   61.00     2  /usr/bin/python3 -m unittest discover -s tests")
        w("pidstat.txt", "\n".join(pid) + "\n")
        ch = []
        for s in range(0, total + 30, 30):
            t = self.at(s)
            off = self.offsets.get(s, 0.00012)
            ch.append(f"{iso(t)} T B97DBE7B,185.125.190.123,3,1794422163.8,{off:.6f},-0.000095,0.0001,3.0,-0.1,3.2,0.04,0.002,258.4,Normal")
            ch.append(f"{iso(t)} S ^,*,185.125.190.123,2,10,377,100,0.000100,0.000100,0.010")
        w("chrony.txt", "\n".join(ch) + "\n")
        sb = self.ident["boot_id"].replace("-", "")
        tail = [jline(end, "systemd[1]", "Finished sysstat-collect.service")]
        state = self.boot_end or "running"
        cur = sb if state == "running" else "f" * 32
        if state == "clean":
            tail.append(jline(end, "systemd-shutdown[1]", "Syncing filesystems and block devices."))
        bodies = {
            "journal_kernel.txt": [jline(self.at(-3600), "kernel", "Linux version 7.0.0-42-generic")]
            + [jline(self.at(s), "kernel", x) for s, x in self.kernel],
            "journal_chronyd.txt": [jline(self.at(s), "chronyd[1340]", x) for s, x in self.chronyd],
            "boot_end.txt": [f"series_boot_id={sb}", f"current_boot_id={cur}", "tail:", *tail],
            "dpkg_log_window.txt": [f"{self.at(s):%Y-%m-%d %H:%M:%S} {x}" for s, x in self.dpkg],
            "snap_changes.txt": ["ID   Status  Spawn                 Ready                 Summary"]
            + [f"{n}  Done    {iso(self.at(s))}  {iso(self.at(s + 20))}  {x}" for n, (s, x) in enumerate(self.snap, 9)]}
        for name, body in bodies.items():
            text = extract_text(name, sb, body, self.modes.get(name, "ok"), self.stderr.get(name, ()))
            path = os.path.join(self.d, name)
            if text is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                w(name, text)
        if self.iostat is not None:
            w("iostat.txt", self.iostat)
        return self.d


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def run_dir(self, name="run", **kw):
        return Run(os.path.join(self._tmp.name, name), **kw)

    def evaluate(self, run, **kw):
        return H.evaluate(run.write(), **kw)


class PublishedSeries(Base):
    def make(self):
        start = dt.datetime(2026, 11, 11, 19, 27, 0, tzinfo=UTC)
        lines, k = [], 0
        for i, row in enumerate(SERIES_20261111.strip().splitlines()):
            f = row.split()
            t = dt.datetime.combine(start.date(), dt.time.fromisoformat(f[0][:-1]), UTC)
            off = {f[n]: float(f[n + 1].rstrip("%")) for n in range(4, 14, 2)}
            word = f[-1]
            k = i // 2 + 1
            lines.append(json.dumps({"utc": iso(t), "sample": k, "cpus": [int(f[3].strip("[]"))], "repeats": 5,
                                     "costs_ms": {r: FROZEN[r] * (1 + o / 100) for r, o in off.items()}, "offset_pct": off,
                                     "refused": sorted(r for r, o in off.items() if abs(o) >= 25) if word == "refused" else []}))
        run = self.run_dir(n=k, start=start, cpus=("0", "1"), end_reason="interrupted",
                           ident=dict(LAPTOP, cpu_model=DESKTOP["cpu_model"], vbox_host_version=DESKTOP["vbox_host_version"],
                                      tsc_mhz="2904.008", storage=DESKTOP["storage"]))
        run.probe_lines = lines
        run.end_time = lambda: dt.datetime(2026, 11, 11, 21, 23, 30, tzinfo=UTC)
        os.makedirs(run.d, exist_ok=True)
        run.write()
        boot = run.ident["boot_id"].replace("-", "")
        for name, text in (("journal_chronyd.txt", CHRONYD_20261111), ("journal_kernel.txt", KERNEL_20261111)):
            with open(os.path.join(run.d, name), "w", encoding="utf-8") as fh:
                fh.write(extract_text(name, boot, text.strip().splitlines()))
        return run

    def test_the_published_series_fails_on_steadiness(self):
        run = self.make()
        v = H.evaluate(run.d, expected=DESKTOP)
        self.assertEqual(v["verdict"], "FAIL")
        self.assertEqual(v["reasons"], ["P2"])
        r = v["rules"]
        for route in ("C3", "C5"):
            self.assertFalse(r["P2"][route]["pass"])
            self.assertLess(r["P2"][route]["within_10pct_share"], 0.95)
            self.assertGreaterEqual(r["P2"][route]["beyond_20pct_n"], 1)
            self.assertEqual(r["P2"][route]["n"], 46)
        self.assertEqual(r["P4"]["events"], 1)                  # the forward jump of 19:32:23Z, within the allowed 2
        self.assertEqual(r["P4"]["result"], "pass")
        self.assertEqual(r["P4"]["cant_synchronise_lines"], 1)
        self.assertEqual(r["P4"]["hogged_cpu_lines"], 2)
        self.assertEqual((r["P1_reported"]["0"]["accepted"], r["P1_reported"]["1"]["accepted"]), (11, 11))
        self.assertEqual(r["completeness"]["complete_sample_times"], 0)   # no CPU 7 in that series

    def test_against_the_laptop_it_also_fails_on_identity(self):
        v = H.evaluate(self.make().d)
        self.assertEqual(v["verdict"], "FAIL")
        self.assertIn("P7", v["reasons"])


class Synthetic(Base):
    def test_clean_series_passes_and_writes_medians(self):
        run = self.run_dir()
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "PASS", v["reasons"])
        self.assertEqual(v["rules"]["completeness"]["complete_sample_times"], 36)
        self.assertEqual(v["rules"]["P4"]["events"], 0)
        m = v["medians"]
        self.assertTrue(m["usable_as_reference"])
        self.assertEqual(sorted(m["medians_ms"]), ["0", "1"])
        self.assertEqual(sorted(m["reported_only"]), ["7"])
        want = sorted(clean_cost(i, "1", "C5") for i in range(1, 37))
        self.assertAlmostEqual(m["medians_ms"]["1"]["C5"]["median_ms"], (want[17] + want[18]) / 2)
        self.assertEqual(m["medians_ms"]["0"]["C3"]["n"], 36)
        self.assertEqual(m["host"]["vbox_host_version"], "7.2.10r174163")

    def test_allowed_pause_events(self):
        self.assertEqual(H.allowed_pauses(36), 2)
        self.assertEqual(H.allowed_pauses(96), 4)

    def test_rate_boundary_is_inclusive(self):
        run = self.run_dir()
        run.kernel = [(1000, "clocksource: Long readout interval, skipping watchdog check: cs_nsec: 3000000000 wd_nsec: 3000000001")]
        run.chronyd = [(5000, "Forward time jump detected!")]
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["rules"]["P4"]["events"]), ("PASS", 2))
        run.chronyd.append((9000, "System clock wrong by 2.500000 seconds"))
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["reasons"], v["rules"]["P4"]["events"]), ("FAIL", ["P4"], 3))

    def test_lines_within_60_s_are_one_event(self):
        run = self.run_dir()
        run.kernel = [(1000, "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:")]
        run.chronyd = [(1060, "Forward time jump detected!"), (5000, "Forward time jump detected!"),
                       (5061, "Forward time jump detected!")]
        v = self.evaluate(run)
        self.assertEqual(v["rules"]["P4"]["events"], 3)        # 1000+1060 merged; 5000 and 5061 are 61 s apart
        self.assertEqual(v["verdict"], "FAIL")

    def test_a_single_long_pause_does_not_fail_by_itself(self):
        run = self.run_dir()
        run.kernel = [(4000, "clocksource: Long readout interval, skipping watchdog check: cs_nsec: 120000000000 wd_nsec: 120000000001")]
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "PASS")
        self.assertAlmostEqual(v["rules"]["P4"]["longest_measured_s"], 120.0)

    def test_an_mpstat_gap_is_a_pause_line(self):
        run = self.run_dir()
        run.gaps = [(3000, 20)]
        v = self.evaluate(run)
        self.assertEqual(v["rules"]["P4"]["events"], 1)
        self.assertAlmostEqual(v["rules"]["P4"]["list"][0]["measured_s"], 15.0)
        self.assertEqual(v["verdict"], "PASS")
        hour = T0 + dt.timedelta(hours=1)
        for gap, n in ((6, 0), (7, 1)):                         # exactly 6 s is not a gap
            self.assertEqual(len(H.pause_events([T0, T0 + dt.timedelta(seconds=gap)], [], [], T0, hour)), n)

    def test_one_unclean_end_fails(self):
        run = self.run_dir(n=20, end_reason=None)
        run.boot_end = "unclean"
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["reasons"]), ("FAIL", ["P3"]))

    def test_a_clean_shutdown_mid_series_is_no_reading(self):
        run = self.run_dir(n=20, end_reason=None)
        run.boot_end = "clean"
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "NO READING")

    def test_an_early_stop_is_no_reading(self):
        v = self.evaluate(self.run_dir(n=20, end_reason="interrupted"))
        self.assertEqual(v["verdict"], "NO READING")
        self.assertTrue(any(r.startswith("early: 20 of 36") for r in v["reasons"]), v["reasons"])

    def test_a_host_identity_change_fails(self):
        run = self.run_dir()
        run.ident_end_changes = {"vbox_host_version": "7.2.4r170995"}
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["reasons"]), ("FAIL", ["P7"]))
        run = self.run_dir(name="other", ident=dict(LAPTOP, storage="USB HDD"))
        self.assertEqual(self.evaluate(run)["reasons"], ["P7"])

    def test_a_busy_guest_is_no_reading(self):
        run = self.run_dir()
        run.busy = {5, 6, 20}
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "NO READING")
        self.assertEqual(len(v["rules"]["evidence"]["busy_sample_times"]), 3)
        run.busy = {5}                                          # 1 of 36 = 2.8 %, inside the 5 %
        self.assertEqual(self.evaluate(run)["verdict"], "PASS")

    def test_clock_offset_bound_is_strict(self):
        run = self.run_dir()
        run.offsets = {600: 0.0999}
        self.assertEqual(self.evaluate(run)["verdict"], "PASS")
        run.offsets = {600: -0.1}
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["reasons"]), ("FAIL", ["P5"]))

    def test_software_changes_fail(self):
        run = self.run_dir()
        run.dpkg = [(2000, "upgrade ca-certificates:all 1 2")]
        self.assertEqual(self.evaluate(run)["reasons"], ["P6"])
        run = self.run_dir(name="snap")
        run.snap = [(2000, 'Auto-refresh snap "core22"')]
        self.assertEqual(self.evaluate(run)["reasons"], ["P6"])
        run = self.run_dir(name="dpkg-before")
        run.dpkg = [(-600, "upgrade ca-certificates:all 1 2")]  # before the series: not a change in it
        self.assertEqual(self.evaluate(run)["verdict"], "PASS")

    def test_steadiness_boundaries(self):
        def cost(bumped, factor):
            return lambda i, c, r: FROZEN[r] * (factor if (r == "C5" and (i, c) in bumped) else 1.0)
        five = {(i, "0") for i in range(1, 6)}
        six = five | {(6, "0")}
        self.assertEqual(self.evaluate(self.run_dir(name="a", cost=cost(five, 1.15)))["verdict"], "PASS")   # 103/108
        v = self.evaluate(self.run_dir(name="b", cost=cost(six, 1.15)))                                         # 102/108
        self.assertEqual((v["verdict"], v["reasons"]), ("FAIL", ["P2"]))
        self.assertEqual(self.evaluate(self.run_dir(name="c", cost=cost({(3, "7")}, 1.20)))["verdict"], "PASS")
        self.assertEqual(self.evaluate(self.run_dir(name="d", cost=cost({(3, "7")}, 1.21)))["reasons"], ["P2"])

    def test_not_started(self):
        run = self.run_dir(end_reason="precheck refused")
        self.assertEqual(self.evaluate(run)["verdict"], "NO READING")

    def test_missing_monitor_is_no_reading(self):
        run = self.run_dir()
        run.write()
        os.remove(os.path.join(run.d, "chrony.txt"))
        v = H.evaluate(run.d)
        self.assertEqual(v["verdict"], "NO READING")

    def test_disk_latency_is_reported(self):
        run = self.run_dir()
        rows = []
        for k, aw in enumerate((2.0, 27.0, 93.0)):
            rows += [f"{(T0 + dt.timedelta(seconds=60 + 30 * k)).strftime('%Y-%m-%dT%H:%M:%S')}+0000",
                     ("Device            r/s     rkB/s   rrqm/s  %rrqm r_await rareq-sz     w/s     wkB/s   wrqm/s  %wrqm w_await "
                      "wareq-sz     d/s     dkB/s   drqm/s  %drqm d_await dareq-sz     f/s f_await  aqu-sz  %util"),
                     (f"dm-0           5.00     40.00     0.00   0.00  {aw:6.2f}     8.00    2.00     16.00     0.00   0.00  {aw:6.2f}"
                      "     8.00    0.00      0.00     0.00   0.00    0.00     0.00    0.00    0.00    0.10   3.00"), ""]
        run.iostat = "Linux 7.0.0-42-generic (ddos-mitigation) \t2026-11-20 \t_x86_64_\t(8 CPU)\n\n" + "\n".join(rows)
        v = self.evaluate(run)
        d = v["rules"]["disk_reported"]["dm-0"]
        self.assertEqual(d["samples"], 3)
        self.assertEqual((d["r_await_ms"]["median"], d["r_await_ms"]["max"]), (27.0, 93.0))
        self.assertEqual(v["verdict"], "PASS")                  # reported only

    def test_main_writes_both_files(self):
        run = self.run_dir()
        run.write()
        with open(os.devnull, "w") as null:
            old, sys.stdout = sys.stdout, null
            try:
                rc = H.main([run.d])
            finally:
                sys.stdout = old
        self.assertEqual(rc, 0)
        with open(os.path.join(run.d, "verdict.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["verdict"], "PASS")
        with open(os.path.join(run.d, "medians.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["schema"], "hs1-medians/1")


class ReviewT105(Base):
    """Fixes after the independent review T-105 (docs/HS1_PREREG.md, 'Changes after review T-105'); each failed before."""
    THREE = ((600, "rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:"),
             (3000, "INFO: task jbd2/dm-0-8:401 blocked for more than 122 seconds."),
             (6000, "clocksource: Long readout interval, skipping watchdog check: cs_nsec: 28000000000 wd_nsec: 1"))

    def test_f4_a_missing_or_failed_journal_extract_is_no_reading(self):
        run = self.run_dir()
        run.kernel = list(self.THREE)
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["reasons"]), ("FAIL", ["P4"]))
        cases = {("journal_kernel.txt", "missing"): "journal_kernel.txt missing",
                 ("journal_kernel.txt", "nomarker"): "no collector header",
                 ("journal_kernel.txt", "rc1"): "command failed",
                 ("journal_kernel.txt", "otherboot"): "not the series' boot"}
        for (name, mode), why in cases.items():
            with self.subTest(name=name, mode=mode):
                run.modes = {name: mode}
                v = self.evaluate(run)
                self.assertEqual(v["verdict"], "NO READING")
                self.assertTrue(any(why in r for r in v["reasons"]), v["reasons"])
        run.kernel = []                                         # no pause line in the kernel extract: chronyd's must count too
        run.modes = {"journal_chronyd.txt": "missing"}
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "NO READING")
        self.assertTrue(any("journal_chronyd.txt missing" in r for r in v["reasons"]), v["reasons"])
        run.modes = {}
        run.write()
        with open(os.path.join(run.d, "journal_kernel.txt"), "w", encoding="utf-8") as fh:   # journalctl's error, as the review wrote it
            fh.write("Data from the specified boot (8ac83bb182e84aa09d00000000000001) is not available: No such boot ID in journal\n")
        self.assertEqual(H.evaluate(run.d)["verdict"], "NO READING")

    def test_f4_an_empty_kernel_extract_does_not_count(self):
        run = self.run_dir()
        run.write()
        with open(os.path.join(run.d, "journal_kernel.txt"), "w", encoding="utf-8") as fh:
            fh.write(extract_text("journal_kernel.txt", run.ident["boot_id"].replace("-", ""), []))
        v = H.evaluate(run.d)
        self.assertEqual(v["verdict"], "NO READING")
        self.assertTrue(any("no time-stamped line" in r for r in v["reasons"]), v["reasons"])

    def test_f4_mpstat_gaps_still_fail_without_the_journal(self):
        run = self.run_dir()
        run.gaps = [(1000, 20), (4000, 20), (8000, 20)]
        run.modes = {"journal_kernel.txt": "missing"}
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["reasons"], v["rules"]["P4"]["events"]), ("FAIL", ["P4"], 3))

    def test_f4_package_and_boot_records_must_be_present(self):
        for name, mode in (("dpkg_log_window.txt", "missing"), ("snap_changes.txt", "missing"), ("snap_changes.txt", "rc1"),
                           ("dpkg_log_window.txt", "nomarker")):
            with self.subTest(name=name, mode=mode):
                run = self.run_dir(name=f"{name}-{mode}")
                run.modes = {name: mode}
                v = self.evaluate(run)
                self.assertEqual((v["verdict"], v["rules"]["P6"]["result"]), ("NO READING", "unknown"))
                self.assertTrue(any(name in r for r in v["reasons"]), v["reasons"])
        run = self.run_dir(name="snap-none")
        run.modes, run.stderr = {"snap_changes.txt": "rc1"}, {"snap_changes.txt": ["error: no changes found"]}
        self.assertEqual(self.evaluate(run)["verdict"], "PASS")    # snap's own "no changes found" is a positive empty answer
        run = self.run_dir(name="no-end", n=20, end_reason=None)
        run.boot_end, run.modes = "unclean", {"boot_end.txt": "missing"}
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["rules"]["P3"]["result"]), ("NO READING", "unknown"))

    def test_f12_an_unreadable_end_time_is_no_reading(self):
        run = self.run_dir()
        run.end_text = "Sat 14 Nov 15:00 complete 36\n"
        v = self.evaluate(run)
        self.assertEqual((v["verdict"], v["rules"]["P3"]["result"]), ("NO READING", "unknown"))

    def test_f11_a_guest_not_in_utc(self):
        run = self.run_dir(ident=dict(LAPTOP, utc_offset="+0100", timezone="Europe/Warsaw"))
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "NO READING")
        self.assertTrue(any("not UTC" in r for r in v["reasons"]), v["reasons"])
        self.assertTrue(any("not UTC" in b for b in H.precheck(dict(LAPTOP, utc_offset="+0100"))))

    def test_f11_monitors_run_in_utc(self):
        with open(SeriesScript.SCRIPT, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("\nexport TZ=UTC\n", text)
        for tool in ("mpstat -P ALL", "pidstat -u", "iostat -dxy"):
            line = next(x for x in text.splitlines() if tool in x)
            self.assertIn("TZ=UTC", line)

    def test_pidstat_without_epoch_times_is_read(self):
        """The dry run of 2026-11-14 showed `pidstat -h` printing HH:MM:SS, which the evaluator skipped (pidstat 'missing', every
        sample time 'busy'): the series now asks for epoch times (-H) and the evaluator reads both."""
        run = self.run_dir()
        run.pidstat_hms = True
        self.assertEqual(self.evaluate(run)["verdict"], "PASS")
        run.busy = {5, 6, 20}
        self.assertEqual(len(self.evaluate(run)["rules"]["evidence"]["busy_sample_times"]), 3)
        with open(SeriesScript.SCRIPT, encoding="utf-8") as fh:
            self.assertIn("pidstat -u -l -h -H 10", fh.read())

    def test_dry_run_is_judged_on_its_length_and_never_a_reference(self):
        run = self.run_dir(n=2, ident=dict(LAPTOP, dry_run="1", n_samples="2"))
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "NO READING")             # 2 probes a CPU: P2 needs 12, so a dry run never passes
        self.assertIn("P2 not computable", v["reasons"])
        self.assertEqual(v["rules"]["completeness"]["required"], 2)
        self.assertTrue(v["dry_run"])
        self.assertTrue(any("DRY RUN" in r for r in v["reasons"]))
        self.assertFalse(v["medians"]["usable_as_reference"])


class Precheck(unittest.TestCase):
    def test_good_identity(self):
        self.assertEqual(H.precheck(dict(LAPTOP)), [])

    def test_refusals(self):
        cases = {"uptime_s": "1200.0", "storage": "USB HDD", "masked": "apt-daily.timer:enabled,",
                 "holds": "linux-generic", "busy_procs": "4242 python -m unittest",
                 "chrony_tracking": LAPTOP["chrony_tracking"].replace("0.000012", "0.250000"),
                 "cpu_model": "Intel(R) Core(TM) i7-10700F CPU @ 2.90GHz"}
        for k, val in cases.items():
            with self.subTest(k=k):
                self.assertNotEqual(H.precheck(dict(LAPTOP, **{k: val})), [])


class Probe(unittest.TestCase):
    def test_probe_line(self):
        @dataclass_like
        class Knobs:
            pass
        calls = []

        class Org:
            def __init__(self, knobs, seed, tag):
                calls.append((seed, tag))

            def close(self):
                calls.append("closed")

        def time_routes(org, repeats, clock):
            return {"costs_ms": {r: c * 1.5 for r, c in FROZEN.items()}, "batch": {r: 1 for r in FROZEN}, "clock": "fake"}

        def self_check(measured, frozen, tol=0.25):
            return [{"class": k} for k in frozen if abs(measured[k] - frozen[k]) / frozen[k] > tol]

        O = types.SimpleNamespace(CostKnobs=Knobs, Origin=Org, time_routes=time_routes, self_check=self_check, ESTIMATOR_VERSION=2)
        out = HP.probe(O, {"knobs": {"unused": 1}, "route_costs_ms": FROZEN}, 7, repeats=21, now=lambda: "2026-11-20T09:00:00.000000Z",
                       cpus=[1])
        self.assertEqual(calls, [(1, "hs1"), "closed"])
        self.assertEqual((out["sample"], out["cpus"], out["repeats"], out["estimator_version"]), (7, [1], 21, 2))
        self.assertAlmostEqual(out["offset_pct"]["C5"], 50.0)
        self.assertEqual(out["refused"], sorted(FROZEN))
        line = json.dumps(out)
        probes, bad = H.parse_probes(line)
        self.assertEqual((len(probes), bad, probes[0]["cpu"]), (1, 0, "1"))


def dataclass_like(cls):
    import dataclasses
    return dataclasses.dataclass(cls)


class SeriesScript(unittest.TestCase):
    SCRIPT = os.path.join(REPO, "bench", "vm", "hs1_series.sh")

    def test_syntax(self):
        self.assertEqual(subprocess.run(["bash", "-n", self.SCRIPT], check=False).returncode, 0)

    def host_tmp(self):
        base = "/home/artur/agent_workspace/host"
        if not os.access(base, os.W_OK):
            self.skipTest(f"{base} not writable here")
        d = tempfile.mkdtemp(prefix=".hs1test_", dir=base)
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def launch(self, run, **env):
        e = dict(os.environ, HS1_SBX="", HS1_STORAGE="internal SSD")
        e.update(env)
        return subprocess.run(["bash", self.SCRIPT, run], env=e, capture_output=True, text=True, timeout=180, check=False)

    @staticmethod
    def alive(pid):
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
        except FileNotFoundError:
            return False

    def wait_for(self, cond, timeout):
        t = time.monotonic() + timeout
        while time.monotonic() < t:
            if cond():
                return True
            time.sleep(0.5)
        return False

    def test_f3_term_stops_a_detached_series_and_collects(self):
        d = self.host_tmp()
        stub = os.path.join(d, "probe_stub.sh")
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\necho \'{"stub": true}\'\n')
        os.chmod(stub, 0o755)
        run = os.path.join(d, "r")
        p = self.launch(run, HS1_DRYRUN="1", HS1_SAMPLES="30", HS1_INTERVAL="30", HS1_PY=stub)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn('kill -TERM "$(cat ', p.stdout)
        self.assertNotIn("kill -INT", p.stdout)
        probes = os.path.join(run, "probes.jsonl")
        self.assertTrue(self.wait_for(lambda: os.path.exists(os.path.join(run, "run.pid")) and os.path.exists(probes)
                                      and os.path.getsize(probes) > 0, 120), "the series did not start")
        with open(os.path.join(run, "run.pid"), encoding="utf-8") as fh:
            pid = int(fh.read())
        os.kill(pid, signal.SIGINT)                              # ignored: bash started the detached series with SIGINT ignored
        time.sleep(2)
        self.assertTrue(self.alive(pid))
        self.assertFalse(os.path.exists(os.path.join(run, "END")))
        os.kill(pid, signal.SIGTERM)
        self.assertTrue(self.wait_for(lambda: not self.alive(pid), 150), "TERM did not end the series")
        with open(os.path.join(run, "END"), encoding="utf-8") as fh:
            self.assertTrue(fh.read().rstrip().endswith(" interrupted"))
        self.assertTrue(os.path.exists(os.path.join(run, "identity_end.txt")))
        for name in ("journal_kernel.txt", "journal_chronyd.txt", "boot_end.txt", "dpkg_log_window.txt", "snap_changes.txt"):
            with open(os.path.join(run, name), encoding="utf-8") as fh:
                lines = fh.read().rstrip("\n").splitlines()
            self.assertTrue(lines[0].startswith(f"# hs1-collect v1 file={name} boot="), (name, lines[:2]))
            self.assertEqual(lines[-1], "# hs1-collect end", name)
        self.assertEqual([x for x in os.listdir(run) if x.startswith(".x.")], [])

    def test_a_refused_precheck_stops_the_launch(self):
        run = os.path.join(self.host_tmp(), "r")
        p = self.launch(run, HS1_SAMPLES="2", HS1_INTERVAL="30", HS1_STORAGE="nowhere")
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("PRECHECK REFUSED", p.stderr)
        with open(os.path.join(run, "END"), encoding="utf-8") as fh:
            self.assertIn("precheck refused", fh.read())
        self.assertFalse(os.path.exists(os.path.join(run, "run.pid")))

    def test_dry_run_needs_fewer_than_36_samples(self):
        run = os.path.join(self.host_tmp(), "r")
        p = self.launch(run, HS1_DRYRUN="1", HS1_SAMPLES="36")
        self.assertEqual(p.returncode, 2)
        self.assertIn("only with HS1_SAMPLES < 36", p.stderr)
        self.assertFalse(os.path.exists(run))

    def test_refuses_a_run_dir_outside_host(self):
        for arg in ("/tmp/hs1_test_run", "/home/artur/agent_workspace/host", "/home/artur/agent_workspace/hostx/r"):
            with self.subTest(arg=arg):
                p = subprocess.run(["bash", self.SCRIPT, arg], check=False, capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertIn("must be under", p.stderr)
        self.assertFalse(os.path.exists("/tmp/hs1_test_run"))


if __name__ == "__main__":
    unittest.main()


class MemTotalAmendmentD102(Base):
    """D-102 (2026-11-14, before any HS1 data): MemTotal within 1 % of 7,600,852 kB; start and end of one boot still equal."""

    def test_the_constant_is_pinned(self):
        self.assertEqual(H.MEMTOTAL_TOL, 0.01)
        self.assertEqual(H.EXPECTED["memtotal_kb"], "7600852")

    def test_boot_to_boot_values_match_and_other_memory_sizes_do_not(self):
        for have in ("7600844", "7600852", "7600856", str(int(7600852 * 1.01))):
            with self.subTest(have=have):
                self.assertTrue(H.matches("memtotal_kb", have, "7600852"))
        for have in (str(int(7600852 * 1.0101) + 1), "9652000", "10485304", "", None, "abc"):
            with self.subTest(have=have):
                self.assertFalse(H.matches("memtotal_kb", have, "7600852"))
        self.assertFalse(H.matches("kernel", "7.0.0-43-generic", "7.0.0-42-generic"))

    def test_precheck_accepts_this_boots_memtotal_and_refuses_10_gib(self):
        self.assertEqual(H.precheck(dict(LAPTOP, memtotal_kb="7600856")), [])
        self.assertNotEqual(H.precheck(dict(LAPTOP, memtotal_kb="9652000")), [])

    def test_a_series_on_a_boot_with_another_few_kb_passes_p7(self):
        run = self.run_dir(ident=dict(LAPTOP, memtotal_kb="7600856"))
        v = self.evaluate(run)
        self.assertEqual(v["verdict"], "PASS", v["reasons"])
        self.assertEqual(v["rules"]["P7"]["result"], "pass")

    def test_memtotal_changing_within_the_boot_still_fails_p7(self):
        run = self.run_dir(ident=dict(LAPTOP, memtotal_kb="7600856"))
        run.ident_end_changes = {"memtotal_kb": "7600852"}
        self.assertEqual(self.evaluate(run)["reasons"], ["P7"])
