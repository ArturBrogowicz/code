"""Host validity per run (docs/RECALIBRATION_2026-11_DESIGN.md 5.1): what the host's own records say about the stretch a run was made
in, judged by fixed rules. Nothing here reads a run's Q, p95 or harm: the rules read the speed probes, the generators' timing and the
monitors' records only, so that they can be fixed before the data and applied by a tool.

H1, the speed bracket: before the stack starts and after the teardown, the origin's own estimator (origin.time_routes, 21 repeats, the
calling thread's CPU time, the record's knobs) on CPU 0 and on CPU 1, the same command as a session of the calibrator's step 1
(`calibrate.py origin-session`). `d` is the mean over the two CPUs of the mean of C3's and C5's deviations from the reference costs
(in a calibration session the costs of its own origin step, afterwards the frozen record's); a run is host-invalid when |d| exceeds
SPEED_DEV at either end. What the origin spent in the run per unit of frozen cost it served, the in-run index, is recorded beside them
and judged by nothing.

H3-H7 (K4): the runner starts `mpstat -P ALL 5`, `pidstat -u -l 10`, a 30-s chrony sampler (`hostcheck.py chrony-sampler`) and a
journal follower on the executor's CPU, keeps their records in the session, and after each run judges over the run's window (from the
first speed probe to the end of the second): H3 the legit streams' pooled slip p99 (not on a staged capacity run, D-099), H4 the
clock (chrony and the journal), H5 the gaps between mpstat's samples, H6 the CPU of the processes that are not the testbed's, H7 that
the monitors were alive and their records cover the window (fails closed). A host-invalid run is set aside as `<run>.hostinvalid<k>` with its reasons and made again with the
same seed after a speed hold; three in a row, or the fourth of a packet, pause the packet ("host unfit").

    python3 bench/hostcheck.py chrony-sampler --every 30          # the sampler the runner starts (chronyc -c tracking and sources)
    python3 bench/hostcheck.py judge RUN_DIR --monitors DIR --start ISO --end ISO     # the rules on a finished run, offline
    sudo ./venv/bin/python bench/hostcheck.py speed-hold --calibration CAL --reference FILE --lo -0.10 --hi 0.10 --max-min 30
                                                                    # a packet's speed hold (5.2; bench/packets/packet.sh)
    sudo ./venv/bin/python bench/hostcheck.py speed-hold --calibration CAL --medians HS1_MEDIANS --session DIR \
        --lo -0.10 --hi 0.10 --agree 0.05 --max-min 45              # R1's, against HS1's medians on this PC (K11)
"""
import argparse
import csv
import datetime
import hashlib
import itertools
import json
import os
import re
import signal
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CALIBRATE = os.path.join(HERE, "calibrate.py")

SPEED_DEV = 0.10                     # H1: |d| at most this before and after a run
SPEED_ROUTES = ("C3", "C5")          # the CPU-bound routes the speed series of 2026-11-11 read (finding 2)
SPEED_CPUS = ("0", "1")              # the server's CPUs (population.PIN_PLAN and PIN_PLAN_DAEMON)
SPEED_REPEATS = 21                   # as a session of the origin step
PROBE_TIMEOUT_S = 600
EXIT_REFUSED = 2                     # speed-hold: a reference it does not take (another PC, another estimator, a record that names no PC)
EXIT_INTERRUPTED = 130               # speed-hold: stopped by TERM, HUP or INT; the pairs it had are kept (T-115 LOW 10), as calibrate.py's 130
# R1's speed hold (K11; a proposal the user approves before it is committed; D-096): the costs of 2026-11-04 were measured on another
# PC than the one that runs the programme, so R1 holds against the medians of HS1's series on this PC instead (docs/HS1_PREREG.md 7),
# each CPU against its own, with H1's band, two pairs in a row agreeing within 5 % (as the hold of 5.2 asked) and at most 45 min. The
# old record is never a speed reference. The medians file is HS1's medians.json (schema hs1-medians/1); what the hold reads of it:
#   "usable_as_reference": true (HS1's PASS)        "host": {"cpu_model", "vbox_host_version", ...}  the PC (K10's comparison)
#   "estimator": {"repeats": 21, "origin_sha256", "knobs_from", "record_sha256", ...}   the probe's own: the hold's estimator, code
#                and knobs must be the same (this checkout's bench/origin.py; knobs_from's file at record_sha256, its knobs the hold's)
#   "medians_ms": {"0": {"C3": {"median_ms": ms, ...}, "C5": {...}, ...}, "1": {...}}  per CPU and route, the series' median cost
# Its sha256 is printed and kept, with the costs, the rule and every hold against it, in the session's speed_reference.json.
R1_HOLD = {"lo": -0.10, "hi": 0.10, "agree": 0.05, "max_min": 45.0}
MEDIANS_SCHEMA = "hs1-medians/1"
SPEED_REFERENCE = "speed_reference.json"
REPO = os.path.dirname(HERE)


def utc(t):
    return datetime.datetime.fromtimestamp(t, datetime.UTC).isoformat(timespec="seconds")


def probe_command(cpu, cal_path, python=sys.executable):
    """The command of one speed probe: a session of the calibrator's step 1, pinned to `cpu`, with the knobs of the record at `cal_path`."""
    return ["taskset", "-c", cpu, python, CALIBRATE, "origin-session", "--repeats", str(SPEED_REPEATS), "--calibration", cal_path]


def speed_probe(host, cal_path):
    """One probe pair, CPU 0 then CPU 1: each CPU's route costs in ms (None when its output could not be read, with the reason), and when
    it began and ended on the host's wall clock."""
    began = host.time()
    out = {"utc_start": utc(began), "t_start": began, "cpus": {}, "errors": {}}
    for cpu in SPEED_CPUS:
        r = host.run(probe_command(cpu, cal_path), timeout=PROBE_TIMEOUT_S)
        try:
            out["cpus"][cpu] = {k: float(v) for k, v in json.loads(r.out)["costs_ms"].items()}
        except (ValueError, KeyError, TypeError, AttributeError):
            out["cpus"][cpu] = None
            out["errors"][cpu] = f"exit {r.code}: {(r.err or r.out or '')[:200]}"
    ended = host.time()
    out.update(utc_end=utc(ended), t_end=ended)
    return out


def cpu_reference(reference_costs, cpu):
    """The reference costs of `cpu`: a flat {route: ms} (a record's, origin.json's) is every CPU's; HS1's medians are per CPU (K11)."""
    own = reference_costs.get(cpu)
    return own if isinstance(own, dict) else reference_costs


def speed_deviation(probe, reference_costs, routes=SPEED_ROUTES):
    """d of one probe pair: the mean over the CPUs of the mean over `routes` of cost / reference - 1, each CPU against its own reference
    when the reference is per CPU. None when a CPU's probe could not be read or a route is missing: a probe that says nothing cannot
    vouch for the run."""
    per_cpu = []
    for cpu in SPEED_CPUS:
        costs, ref = (probe or {}).get("cpus", {}).get(cpu), cpu_reference(reference_costs, cpu)
        if not costs or any(costs.get(k) is None or not isinstance(ref.get(k), (int, float)) or not ref.get(k) for k in routes):
            return None
        per_cpu.append(statistics.fmean(costs[k] / ref[k] - 1.0 for k in routes))
    return statistics.fmean(per_cpu)


def speed_verdict(d_before, d_after, limit=SPEED_DEV):
    """H1 on the two ends of a run: the reasons it fails (none: the bracket holds). A missing end fails."""
    reasons = []
    for end, d in (("before", d_before), ("after", d_after)):
        if d is None:
            reasons.append(f"H1: the speed probe {end} the run could not be read")
        elif not abs(d) <= limit:
            reasons.append(f"H1: speed {end} the run {d:+.1%} from the reference costs (limit {limit:.0%})")
    return reasons


def judge_speed(before, after, reference_costs):
    """H1 from the two probe pairs of a run and the reference costs: the deviations and the verdict."""
    d_before, d_after = speed_deviation(before, reference_costs), speed_deviation(after, reference_costs)
    reasons = speed_verdict(d_before, d_after)
    return {"d_before": d_before, "d_after": d_after, "limit": SPEED_DEV, "ok": not reasons, "reasons": reasons}


def in_run_index(run_dir, reference_costs):
    """What the origin spent in the run per unit of the frozen cost of the requests it answered: its CPU-seconds from server.csv (the
    1 Hz `origin_cpu_pct` over `t_rel`) over the sum, across the streams of run.json, of each stream's 2xx answers (its summary's
    `status`, else `completed`) times its route's reference cost. server_requests.csv has no route, so the streams' own counts are
    used. Recorded, never judged; None when the files do not give it."""
    try:
        with open(os.path.join(run_dir, "server.csv"), encoding="utf-8", newline="") as fh:
            rows = [r for r in csv.DictReader(fh)]
        with open(os.path.join(run_dir, "run.json"), encoding="utf-8") as fh:
            streams = json.load(fh)["streams"]
        cpu_s, last = 0.0, None
        for r in rows:
            t = float(r["t_rel"])
            if last is not None and r.get("origin_cpu_pct") not in (None, ""):
                cpu_s += float(r["origin_cpu_pct"]) / 100.0 * (t - last)
            last = t
        cost_s = 0.0
        for s in streams:
            with open(os.path.join(run_dir, s["summary"]), encoding="utf-8") as fh:
                summary = json.load(fh)
            status = summary.get("status")
            served = sum(n for code, n in status.items() if str(code).startswith("2")) if isinstance(status, dict) else summary["completed"]
            cost_s += served * reference_costs[s["route_class"]] / 1000.0
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return {"origin_cpu_s": cpu_s, "frozen_cost_s": cost_s, "index": cpu_s / cost_s if cost_s > 0 else None}


class SpeedBracket:
    """H1 for the runs of a step: `before` is called by the executor once the environment gate has passed and before the stack starts
    (executor.execute's `before_stack`), `finish` by the caller after the run has returned, its testbed taken down. The reference costs
    are the calibration session's origin step's or the frozen record's; `cal_path` gives the probe the record's knobs."""

    def __init__(self, cal_path, reference_costs, source):
        self.cal_path, self.reference_costs, self.source = cal_path, dict(reference_costs), source
        self.pending = None

    def before(self, host):
        self.pending = speed_probe(host, self.cal_path)
        return self.pending

    def finish(self, host, run_dir):
        """The after-probe, H1's verdict and the in-run index, as run.json and DONE keep them."""
        before, self.pending = self.pending, None
        after = speed_probe(host, self.cal_path)
        out = {"reference": self.source, "reference_costs_ms": self.reference_costs, "before": before, "after": after,
               **judge_speed(before, after, self.reference_costs), "in_run": in_run_index(run_dir, self.reference_costs)}
        out["window"] = {"start": before["utc_start"] if before else None, "end": after["utc_end"],
                         "t_start": before["t_start"] if before else None, "t_end": after["t_end"]}
        return out


# --- H3-H7: the monitors and their rules (K4) ----------------------------------------------------------------------------------------

MPSTAT_S, PIDSTAT_S, CHRONY_S = 5.0, 10.0, 30.0
MPSTAT_GAP_S = 10.0                  # H5: no gap above this between consecutive mpstat samples (D-099 2, 2026-11-14, pre-data; was 6)
# The sampling monitors run at real-time priority (D-099 2): SCHED_FIFO at the lowest real-time priority, 1, which is above every
# SCHED_OTHER task (all of the testbed's load: nothing in it asks for another policy) and below the kernel's own real-time threads (the
# interrupt threads and watchdogd at 50, migration at 99), so testbed load cannot delay a sample and a sample cannot delay an
# interrupt. The step runs as root (the packet's sudo), which may set it. A sample of mpstat or pidstat takes a few ms of CPU and then
# blocks until the next; the kernel's real-time throttling (sched_rt_runtime_us 950000 of 1000000) caps real-time tasks at 95 % of a
# CPU in any case. The journal follower stays SCHED_OTHER: journald stamps its lines, so a late read moves no time in the record, and
# a flood of lines must not hold a CPU.
REALTIME = ("chrt", "--fifo", "1")
OTHER_CPU_MEAN_PCT = 5.0             # H6: the non-testbed processes, % of one CPU on average over the run's window
OTHER_CPU_PEAK_PCT = 50.0            # and in any 10-s sample
CLOCK_OFFSET_S = 0.1                 # H4: |System time| below this in every chrony sample overlapping the run
SOURCE_OFFSET_S = 1.0                # and no selected source (state * or +) more than this off
CLOCK_LINES = ("Forward time jump", "Can't synchronise", "Long readout interval")      # H4: none in the journal in the run's window
# H3 does not judge the staged capacity runs (D-099 1, the user's amendment of 2026-11-14, before any calibration data): the scenario of
# calibrate.py's capacity plan. They keep H1 and H4-H7; every ladder, reference, confirmation and P2 run keeps H3. Their slip is still
# recorded beside the verdict. (T-105 F1: the three staged runs of 2026-11-03 gave a pooled legit slip p99 of 255, 179 and 291 ms, the
# ladder runs of the same session 25-51 ms.)
STAGED_SCENARIO = "capacity"
H3_EXEMPT = "H3 does not judge a staged capacity run (D-099, 2026-11-14, pre-data); its slip is recorded, not judged"
INVALID_IN_A_ROW, INVALID_IN_PACKET = 3, 4      # a packet pauses ("host unfit") at the third host-invalid run in a row or the fourth
COVER_SLACK_S = 5.0                 # H7: a monitor's first sample in a run's window at most one interval plus this after its start
                                    # (T-105 F6; the lateness H5's 10-s line allows mpstat, one 5-s interval)
HOLD_EVERY_S, HOLD_MAX_MIN = 300.0, 30.0        # the speed hold after a host-invalid run: a probe pair every 5 min, at most 30 min
ASIDE = ".hostinvalid"
MONITOR_ENV = {"TZ": "UTC", "LC_ALL": "C", "S_TIME_FORMAT": "ISO"}
EXIT_HOST_UNFIT = 5


class HostUnfit(RuntimeError):
    """The packet pauses: the host made too many runs host-invalid, or a speed hold did not end within its time. The same command
    resumes the step from its finished runs in a later packet."""


def monitor_commands(python=sys.executable):
    """The four monitors: name -> argv (each started under `taskset -c <the executor's CPU>`). sysstat's tools buffer their output when
    it is a file, so they run under `stdbuf -oL`: a sample reaches the record when it is taken, and a run can be judged right after. The
    three sampling ones run at real-time priority (REALTIME, D-099); a monitor that cannot get it exits, and H7 voids the run."""
    return {"mpstat": [*REALTIME, "stdbuf", "-oL", "mpstat", "-P", "ALL", f"{MPSTAT_S:g}"],
            "pidstat": [*REALTIME, "stdbuf", "-oL", "pidstat", "-u", "-l", f"{PIDSTAT_S:g}"],
            "chrony": [*REALTIME, python, os.path.abspath(__file__), "chrony-sampler", "--every", f"{CHRONY_S:g}"],
            "journal": ["stdbuf", "-oL", "journalctl", "-f", "-n", "0", "-o", "short-iso-precise", "--no-pager"]}


class Monitors:
    """The monitors of one invocation, their files in `directory`, their processes on `cpu`."""

    def __init__(self, host, directory, cpu):
        self.host, self.directory, self.cpu = host, directory, cpu
        self.procs, self.files = {}, {}

    def start(self):
        os.makedirs(self.directory, exist_ok=True)
        for name, argv in monitor_commands().items():
            fh = open(os.path.join(self.directory, name + ".txt"), "a", encoding="utf-8")       # noqa: SIM115 (open while it runs)
            self.files[name] = fh
            self.procs[name] = self.host.popen(["taskset", "-c", self.cpu, *argv], env=MONITOR_ENV, stdout=fh, stderr=fh)
        return self

    def alive(self):
        return {name: proc.poll() is None for name, proc in self.procs.items()}

    def path(self, name):
        return os.path.join(self.directory, name + ".txt")

    def stop(self):
        for proc in self.procs.values():
            if proc.poll() is None:
                proc.terminate()
        for fh in self.files.values():
            fh.close()
        self.files = {}


def _text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read().replace("\x00", "")          # a reset can leave a file's tail as NUL bytes
    except OSError:
        return None


DATE = re.compile(r"\b(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\b")
CLOCK = re.compile(r"^(\d{2}):(\d{2}):(\d{2})(?:\s+(AM|PM))?\s+(.*)$")


def _sysstat_lines(text):
    """(epoch, rest of the line) of each timed line of a sysstat report (mpstat, pidstat), in UTC: the date from its first line (ISO, or
    MM/DD/YYYY), the time of day from each line (24 h, or 12 h with AM/PM); a time of day that goes back by more than 12 h is the next
    day. The monitors run with TZ=UTC."""
    m = DATE.search(text.split("\n", 1)[0]) if text else None
    if not m:
        return []
    d = m.group(1)
    day = (datetime.date.fromisoformat(d) if "-" in d else
           datetime.date(int(d[6:]), int(d[:2]), int(d[3:5])))
    base = datetime.datetime(day.year, day.month, day.day, tzinfo=datetime.UTC).timestamp()
    out, last, offset = [], None, 0.0
    for line in text.splitlines()[1:]:
        c = CLOCK.match(line.strip())
        if not c:
            continue
        h, mi, sec, ampm, rest = int(c.group(1)), int(c.group(2)), int(c.group(3)), c.group(4), c.group(5)
        if ampm:
            h = h % 12 + (12 if ampm == "PM" else 0)
        tod = h * 3600 + mi * 60 + sec
        if last is not None and tod < last - 43200:
            offset += 86400
        last = tod
        out.append((base + offset + tod, rest))
    return out


def parse_mpstat(text):
    """The times of mpstat's samples (its `all` rows)."""
    return [t for t, rest in _sysstat_lines(text or "") if rest.split()[:1] == ["all"]]


def parse_pidstat(text, interval=PIDSTAT_S):
    """pidstat -u [-l]'s samples: [{"t": the end of the interval, "rows": [{"uid", "pid", "cpu_pct", "command"}]}], an interval with no
    active process too (a header with no rows: it ends `interval` later)."""
    samples, current = [], None
    for t, rest in _sysstat_lines(text or ""):
        fields = rest.split()
        if fields[:2] == ["UID", "PID"]:
            current = {"t": t + interval, "rows": []}
            samples.append(current)
            continue
        if len(fields) < 9 or current is None:
            continue
        try:
            row = {"uid": int(fields[0]), "pid": int(fields[1]), "cpu_pct": float(fields[6]), "command": " ".join(fields[8:])}
        except ValueError:
            continue
        current["t"] = t
        current["rows"].append(row)
    return samples


def parse_chrony(text):
    """The chrony sampler's records: [{"t", "tracking": {"system_time_s", "leap"} or None, "sources": [{"state", "name", "offset_s"}]}].
    A sample is an ISO time line followed by `chronyc -c tracking` (14 fields) and `chronyc -c sources` (10 fields a source)."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})", line):
            out.append({"t": datetime.datetime.fromisoformat(line).timestamp(), "tracking": None,
                        "sources": []})
            continue
        if not out:
            continue
        f = line.split(",")
        try:
            if len(f) == 14:
                out[-1]["tracking"] = {"system_time_s": float(f[4]), "leap": f[13]}
            elif len(f) == 10 and f[0] in ("^", "=", "#"):
                out[-1]["sources"].append({"state": f[1], "name": f[2], "offset_s": float(f[7])})
        except ValueError:
            continue
    return out


def parse_journal(text):
    """(epoch, line) of each journal line (journalctl -o short-iso-precise)."""
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(.*)$", line)
        if m:
            stamp = m.group(1).replace("Z", "+00:00")
            if re.search(r"[+-]\d{4}$", stamp):
                stamp = stamp[:-2] + ":" + stamp[-2:]
            out.append((datetime.datetime.fromisoformat(stamp).timestamp(), m.group(2)))
    return out


# the testbed's processes (5.1 H6): Nginx, gunicorn, the engines, the executor, the calibrator, the probes, ip, tc, taskset, sudo, the
# monitors and kernel threads; everything else is not the testbed's
TESTBED_PROGRAMS = {"nginx", "nginx:", "gunicorn", "gunicorn:", "ip", "tc", "taskset", "sudo", "stdbuf", "mpstat", "pidstat", "chronyc",
                    "journalctl", "sadc",
                    "ping", "curl", "bpftool", "setsid"}
TESTBED_SCRIPTS = {"executor.py", "calibrate.py", "gate_campaign.py", "loadgen.py", "loadtool_validate.py", "hostcheck.py",
                   "control_plane.py", "gunicorn"}
KERNEL_THREAD = re.compile(r"^\[?(kworker|ksoftirqd|migration|rcu_|rcuog|rcuop|rcub|kthreadd|kswapd|khugepaged|kcompactd|irq/|"
                           r"idle_inject|cpuhp|watchdog|jbd2|kblockd|writeback|oom_reaper|ksmd|kauditd|kintegrityd|kdevtmpfs|"
                           r"psimon|khungtaskd|napi/|scsi_|kthrotld|ipv6_addrconf|zswap|hwrng|ttm|kstrp|xfsaild|ext4|nvme|"
                           r"kmpathd|kmpath_|dm_bufio|edac|devfreq|blkcg|tpm|md_|raid|loop\d|card\d|i915|netns|inet_frag|"
                           r"mm_percpu|pool_workqueue|ecryptfs|charger|kverityd|ksgxd|krfcommd|hfi|iou-|bioset)")


def is_testbed(command, uid):
    """Whether a pidstat row is the testbed's: by its program (with -l the first word of its command line, a path's base name),
    a Python process by its script (`python bench/loadgen.py ...`, `python -m gunicorn`), a kernel thread by its name. A bare `python`
    (pidstat without -l, as AP-7's record) is the testbed's when it runs as root, as the testbed does; the app's server, sshd and the
    agents' processes are not."""
    words = command.split()
    if not words:
        return False
    first = os.path.basename(words[0])
    if KERNEL_THREAD.match(command):
        return True
    if first in TESTBED_PROGRAMS:
        return True
    if re.fullmatch(r"python3?(\.\d+)?", first):
        if len(words) == 1:
            return uid == 0
        args = [w for w in words[1:] if not w.startswith("-")]
        if "-m" in words[1:] and words[words.index("-m") + 1:words.index("-m") + 2] == ["gunicorn"]:
            return True
        return bool(args) and os.path.basename(args[0]) in TESTBED_SCRIPTS
    return False


def pooled_legit_slip_p99(run_dir):
    """H3's figure: the p99 of the lateness (t_sent - t_intended) of every sent request of the run's legit streams pooled, as the
    gate's validity reads it (harm_gate.run_metrics `slip_p99_s`); None when no request was sent. Reads the records, nothing else."""
    import numpy as np
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), "eval"))
    import harm_gate as H
    with open(os.path.join(run_dir, "run.json"), encoding="utf-8") as fh:
        streams = [s for s in json.load(fh)["streams"] if s["kind"] == "legit"]
    parts = []
    for s in streams:
        rec = H.read_records(os.path.join(run_dir, s["records"]))
        sent = ~np.isnan(rec["t_sent"])
        parts.append((rec["t_sent"] - rec["t_intended"])[sent])
    slip = np.concatenate(parts) if parts else np.array([])
    return float(np.quantile(slip, 0.99)) if len(slip) else None


def _rule(reasons):
    return {"ok": not reasons, "reasons": reasons}


def rule_slip(slip_p99_s, limit_s):
    """H3: the pooled legit slip p99 at most `limit_s` (the record's validity.slip_pooled_s)."""
    if slip_p99_s is None:
        return _rule(["H3: no legit request was sent: the slip cannot be read"])
    return _rule([] if slip_p99_s <= limit_s else
                 [f"H3: pooled legit slip p99 {slip_p99_s * 1000:.0f} ms above {limit_s * 1000:.0f} ms"])


def rule_clock(chrony, journal, t_start, t_end):
    """H4: every chrony sample overlapping the run (within one interval of it) with |System time| below 0.1 s, chrony not
    unsynchronised, no selected or combined source (state * or +) more than 1 s off; no clock line in the journal in the window."""
    reasons = []
    for sample in [c for c in chrony if t_start - CHRONY_S <= c["t"] <= t_end + CHRONY_S]:
        when = utc(sample["t"])
        tr = sample["tracking"]
        if tr is None:
            reasons.append(f"H4: the chrony sample of {when} has no tracking record")
            continue
        if not abs(tr["system_time_s"]) < CLOCK_OFFSET_S:
            reasons.append(f"H4: at {when} the system clock was {tr['system_time_s']:+.3f} s off (limit {CLOCK_OFFSET_S:g} s)")
        if tr["leap"].strip().lower() == "not synchronised":
            reasons.append(f"H4: at {when} chrony was not synchronised")
        for src in sample["sources"]:
            if src["state"] in ("*", "+") and not abs(src["offset_s"]) <= SOURCE_OFFSET_S:
                reasons.append(f"H4: at {when} the source {src['name']} read {src['offset_s']:+.3f} s (limit {SOURCE_OFFSET_S:g} s)")
    for t, line in journal or ():
        if t_start <= t <= t_end and any(word in line for word in CLOCK_LINES):
            reasons.append(f"H4: at {utc(t)} the journal says: {line[:160]}")
    return _rule(reasons)


def rule_pause(mpstat, t_start, t_end):
    """H5: no gap above MPSTAT_GAP_S (10 s, D-099) between consecutive mpstat samples over the run's window (the samples in it and the
    one on either side)."""
    times = sorted(mpstat)
    before = [t for t in times if t < t_start][-1:]
    after = [t for t in times if t > t_end][:1]
    seq = before + [t for t in times if t_start <= t <= t_end] + after
    gaps = [(a, b) for a, b in itertools.pairwise(seq) if b - a > MPSTAT_GAP_S]
    return _rule([f"H5: no mpstat sample for {b - a:.0f} s from {utc(a)}" for a, b in gaps])


def other_cpu(pidstat, t_start, t_end):
    """H6's figures: per 10-s pidstat sample overlapping the run, the %CPU (of one CPU) of the processes that are not the testbed's, and
    who they were."""
    rows = []
    for sample in pidstat:
        if t_start < sample["t"] <= t_end + PIDSTAT_S:
            others = [r for r in sample["rows"] if not is_testbed(r["command"], r["uid"])]
            rows.append({"t": sample["t"], "pct": sum(r["cpu_pct"] for r in others),
                         "top": sorted(((r["cpu_pct"], r["command"][:60]) for r in others), reverse=True)[:3]})
    return rows


def rule_other_cpu(pidstat, t_start, t_end):
    """H6: the non-testbed processes use at most 5 % of one CPU on average over the run's window and at most 50 % in any 10-s sample."""
    rows = other_cpu(pidstat, t_start, t_end)
    if not rows:
        return _rule(["H6: no pidstat sample overlaps the run"])
    reasons = []
    mean = statistics.fmean(r["pct"] for r in rows)
    if not mean <= OTHER_CPU_MEAN_PCT:
        reasons.append(f"H6: processes that are not the testbed's used {mean:.1f} % of a CPU on average (limit {OTHER_CPU_MEAN_PCT:g} %)")
    for r in rows:
        if not r["pct"] <= OTHER_CPU_PEAK_PCT:
            reasons.append(f"H6: {r['pct']:.1f} % of a CPU in the sample of {utc(r['t'])} (limit {OTHER_CPU_PEAK_PCT:g} %): "
                           + ", ".join(f"{c} {p:.1f} %" for p, c in r["top"]))
    return _rule(reasons)


def rule_evidence(records, alive, t_start, t_end):
    """H7: every monitor alive when the run is judged, and the records of the sampling ones cover the window to their resolution: a
    sample at or after its start and no later than one interval plus COVER_SLACK_S after it (an earlier sample, of a run before, does
    not do: T-105 F6), and one no earlier than one interval before its end. A window shorter than one interval plus the slack (a smoke
    test's; a run of the programme lasts about two minutes) may have no sample of its own: there the first needs one no earlier than
    one interval plus the slack before its end. Fails closed."""
    reasons = []
    for name, ok in sorted((alive or {}).items()):
        if not ok:
            reasons.append(f"H7: the monitor {name} had died")
    for name, times, every in (("mpstat", records.get("mpstat"), MPSTAT_S), ("pidstat", records.get("pidstat"), PIDSTAT_S),
                               ("chrony", records.get("chrony"), CHRONY_S)):
        if times is None:
            reasons.append(f"H7: no {name} record")
        elif not any(min(t_start, t_end - every - COVER_SLACK_S) <= t <= t_start + every + COVER_SLACK_S for t in times):
            reasons.append(f"H7: the {name} record has no sample in the first {every + COVER_SLACK_S:g} s of the run (from {utc(t_start)})"
                           if t_end - t_start >= every + COVER_SLACK_S else
                           f"H7: the {name} record has no sample in the last {every + COVER_SLACK_S:g} s before the end of this short run "
                           f"({utc(t_end)})")
        elif not any(t >= t_end - every for t in times):
            reasons.append(f"H7: the {name} record does not cover the run ({utc(t_start)} to {utc(t_end)})")
    if records.get("journal") is None:
        reasons.append("H7: no journal record")
    return _rule(reasons)


def read_monitors(directory):
    """The monitors' records in `directory` (None for a record that is not there)."""
    def text(name):
        return _text(os.path.join(directory, name + ".txt"))
    mp, pid, ch, jo = text("mpstat"), text("pidstat"), text("chrony"), text("journal")
    return {"mpstat": None if mp is None else parse_mpstat(mp), "pidstat": None if pid is None else parse_pidstat(pid),
            "chrony": None if ch is None else parse_chrony(ch), "journal": None if jo is None else parse_journal(jo)}


def judge_host(speed, slip_p99_s, slip_limit_s, records, alive, t_start, t_end, staged=False):
    """A run's host validity from what the host recorded (5.1): H1 from its speed bracket (judge_speed's result, or None), H3 from its
    legit streams' pooled slip (not for a staged capacity run, `staged`: D-099), H4-H6 from the monitors' records, H7 from their
    presence. Reads no Q, p95 or harm. Returns ok, the reasons and each rule's own verdict."""
    pid = records.get("pidstat") or []
    rules = {"H1": _rule(list(speed["reasons"])) if speed else _rule(["H1: no speed bracket"]),
             "H3": {**_rule([]), "exempt": H3_EXEMPT} if staged else rule_slip(slip_p99_s, slip_limit_s),
             "H4": rule_clock(records.get("chrony") or [], records.get("journal"), t_start, t_end),
             "H5": rule_pause(records.get("mpstat") or [], t_start, t_end),
             "H6": rule_other_cpu(pid, t_start, t_end),
             "H7": rule_evidence({"mpstat": records.get("mpstat"), "pidstat": None if records.get("pidstat") is None else
                                  [s["t"] for s in pid], "chrony": None if records.get("chrony") is None else
                                  [c["t"] for c in records["chrony"]], "journal": records.get("journal")}, alive, t_start, t_end)}
    reasons = [r for rule in rules.values() for r in rule["reasons"]]
    return {"ok": not reasons, "reasons": reasons, "rules": rules, "window": {"start": utc(t_start), "end": utc(t_end)},
            "slip_p99_s": slip_p99_s, "other_cpu": other_cpu(pid, t_start, t_end)}


def speed_hold(host, cal_path, reference_costs, say=None, lo=-SPEED_DEV, hi=SPEED_DEV, agree=None, every_s=HOLD_EVERY_S,
               max_min=HOLD_MAX_MIN, note=None):
    """A probe pair every `every_s` until two in a row lie within [lo, hi] of the reference costs (and, with `agree`, within `agree` of
    each other), at most `max_min` minutes: after a host-invalid run with H1's band (5.1), before R1 with -5 % to +12 % and 5 % (5.2).
    Returns held (whether it ended so) and every pair's d. `note` is given each pair as it is made, so that a stop keeps them."""
    say, note = say or (lambda m: None), note or (lambda pair: None)
    first, pairs = host.monotonic(), []
    while True:
        p = speed_probe(host, cal_path)
        d = speed_deviation(p, reference_costs)
        pairs.append({"utc": p["utc_start"], "d": d})
        note(pairs[-1])
        say(f"speed hold: probe pair {len(pairs)}: " + ("unreadable" if d is None else f"{d:+.1%}"))
        good = [x["d"] is not None and lo <= x["d"] <= hi for x in pairs[-2:]]
        if len(pairs) >= 2 and all(good) and (agree is None or abs(pairs[-1]["d"] - pairs[-2]["d"]) <= agree):
            return {"held": True, "pairs": pairs, "waited_s": round(host.monotonic() - first, 1)}
        if host.monotonic() - first + every_s > max_min * 60:
            return {"held": False, "pairs": pairs, "waited_s": round(host.monotonic() - first, 1)}
        host.sleep(every_s)


class HostCheck:
    """H1 and H3-H7 for the runs of one invocation (a packet): the speed bracket, the monitors (started with the first run, on `cpu`,
    their records in `directory`), the verdict after each run, setting a host-invalid run aside, the counts that pause the packet, and
    the speed hold before a run is made again (5.1)."""

    def __init__(self, host, speed, directory, cpu, slip_limit_s):
        self.host, self.speed, self.slip_limit_s = host, speed, slip_limit_s
        self.monitors = Monitors(host, directory, cpu)
        self.started, self.in_a_row, self.invalid = False, 0, 0

    def start(self):
        if not self.started:
            self.monitors.start()
            self.started = True

    def judge(self, run_dir, speed, staged=False):
        """H1 and H3-H7 on a finished run; `staged`: a staged capacity run, which H3 does not judge (D-099)."""
        w = speed["window"]
        records = read_monitors(self.monitors.directory)
        try:
            slip = pooled_legit_slip_p99(run_dir)
        except Exception as exc:                         # noqa: BLE001 (a record that cannot be read is a run that cannot be judged)
            slip, records["slip_error"] = None, f"{type(exc).__name__}: {exc}"
        return judge_host(speed, slip, self.slip_limit_s, records, self.monitors.alive(), w["t_start"], w["t_end"], staged)

    def set_aside(self, run_dir, record, say=None):
        """The host-invalid run goes beside its place as <run>.hostinvalid<k>, with its record (DONE) and its reasons; counts it and
        pauses the packet at the third in a row or the fourth (HostUnfit); else holds until the host's speed is back."""
        k = 1
        while os.path.exists(f"{run_dir}{ASIDE}{k}"):
            k += 1
        aside = f"{run_dir}{ASIDE}{k}"
        os.rename(run_dir, aside)
        _write_json(os.path.join(aside, "DONE"), record)
        with open(os.path.join(aside, "HOSTINVALID"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(record["host"]["reasons"]) + "\n")
        self.in_a_row += 1
        self.invalid += 1
        say = say or (lambda m: None)
        say(f"{os.path.basename(run_dir)}: host-invalid ({'; '.join(record['host']['reasons'])[:300]}); kept as "
            f"{os.path.basename(aside)}; {self.in_a_row} in a row, {self.invalid} in this packet")
        if self.in_a_row >= INVALID_IN_A_ROW or self.invalid >= INVALID_IN_PACKET:
            raise HostUnfit(f"paused: host unfit ({self.in_a_row} host-invalid runs in a row, {self.invalid} in this packet; "
                            f"the limits are {INVALID_IN_A_ROW} and {INVALID_IN_PACKET}); the same command resumes the step later")
        hold = speed_hold(self.host, self.speed.cal_path, self.speed.reference_costs, say)
        _write_json(os.path.join(aside, "HOLD.json"), hold)
        if not hold["held"]:
            raise HostUnfit(f"paused: host unfit (the speed hold after {os.path.basename(aside)} did not find two probe pairs in a row "
                            f"within {SPEED_DEV:.0%} in {HOLD_MAX_MIN:g} min)")
        return aside

    def valid(self):
        self.in_a_row = 0

    def close(self):
        if self.started:
            self.monitors.stop()


def _write_json(path, obj):
    """As executor.write_json: synced, renamed, the directory synced (K6)."""
    with open(path + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(path + ".tmp", path)
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# --- the command line ----------------------------------------------------------------------------------------------------------------

def chrony_sampler(every_s, out=sys.stdout, run=None, sleep=time.sleep, count=None):
    """Every `every_s`: the UTC time, `chronyc -c tracking` and `chronyc -c sources`, flushed (the runner's H4 monitor)."""
    import subprocess
    run = run or (lambda argv: subprocess.run(argv, capture_output=True, text=True, check=False, timeout=20).stdout)
    n = 0
    while count is None or n < count:
        out.write(datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds").replace("+00:00", "Z") + "\n")
        for argv in (["chronyc", "-n", "-c", "tracking"], ["chronyc", "-n", "-c", "sources"]):
            try:
                out.write(run(argv))
            except Exception as exc:                     # noqa: BLE001 (a failed call is a sample without that record)
                out.write(f"# {argv[-1]}: {exc}\n")
        out.flush()
        n += 1
        if count is None or n < count:
            sleep(every_s)


class SpeedReferenceError(ValueError):
    """A speed reference the hold does not take: a medians file that is not of the assumed shape, another PC's, other knobs."""


def _positive_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 < value < float("inf")


def _sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def load_medians(path):
    """HS1's medians file (K11; docs/HS1_PREREG.md 7): its sha256, verdict, PC, estimator and, for the CPUs the hold probes, each
    route's median cost in ms. SpeedReferenceError naming what is missing."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:                      # a refusal, not a traceback (T-116)
        raise SpeedReferenceError(f"{path}: cannot be read ({type(exc).__name__}: {exc.strerror or exc})") from exc
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise SpeedReferenceError(f"{path}: not JSON ({exc})") from exc
    if not isinstance(doc, dict):
        raise SpeedReferenceError(f"{path}: the medians file is a JSON object of schema {MEDIANS_SCHEMA}")
    p = [] if doc.get("schema") == MEDIANS_SCHEMA else [f"schema {MEDIANS_SCHEMA}"]
    host, estimator, medians = doc.get("host"), doc.get("estimator"), doc.get("medians_ms")
    import calibration as C
    p += ["host"] if not isinstance(host, dict) else [f"host.{key}" for key in C.pc_unnamed(host)]
    if not isinstance(estimator, dict):
        p.append("estimator")
    if not isinstance(doc.get("usable_as_reference"), bool):
        p.append("usable_as_reference")
    for cpu in SPEED_CPUS:
        routes = medians.get(cpu) if isinstance(medians, dict) else None
        if not isinstance(routes, dict):
            p.append(f"medians_ms.{cpu}")
            continue
        p += [f"medians_ms.{cpu}.{k}.median_ms (a positive number of ms)" for k in SPEED_ROUTES
              if not (isinstance(routes.get(k), dict) and _positive_number(routes[k].get("median_ms")))]
    if p:
        raise SpeedReferenceError(f"{path}: the medians file lacks " + ", ".join(p))
    costs = {cpu: {k: float(v["median_ms"]) for k, v in medians[cpu].items()
                   if isinstance(v, dict) and _positive_number(v.get("median_ms"))} for cpu in SPEED_CPUS}
    return {"path": os.path.abspath(path), "sha256": hashlib.sha256(raw).hexdigest(), "verdict": doc.get("verdict"),
            "usable": doc["usable_as_reference"], "host": dict(host), "estimator": dict(estimator), "costs": costs}


def medians_problems(ref, facts, knobs, repo=REPO):
    """Why HS1's medians are not R1's speed reference on this host: a series that is not usable as one (no PASS), another PC
    (calibration.pc_problems, K10), or an estimator other than the hold's: other repeats, another bench/origin.py, or knobs other than
    `knobs` (the hold's --calibration's), as read from the file the series named at the hash it recorded."""
    import calibration as C
    p = [] if ref["usable"] is True else [f"HS1's series was judged {ref['verdict']}: its medians are not usable as a reference"]
    p += C.pc_problems(ref["host"], facts, f"HS1's series ({ref['sha256'][:8]})")
    est = ref["estimator"]
    if est.get("repeats") != SPEED_REPEATS:
        p.append(f"HS1's probe took {est.get('repeats')!r} repeats, the hold {SPEED_REPEATS}")
    here = _sha256_file(os.path.join(repo, "bench", "origin.py"))
    if est.get("origin_sha256") != here:
        p.append(f"HS1's probe ran bench/origin.py {str(est.get('origin_sha256'))[:8]}, this checkout's is {here[:8]}")
    source = os.path.join(repo, str(est.get("knobs_from") or ""))
    try:
        sha = _sha256_file(source)
        with open(source, encoding="utf-8") as fh:
            theirs = json.load(fh)["knobs"]
    except (OSError, ValueError, KeyError, TypeError):
        p.append(f"the knobs HS1's probe took cannot be read ({est.get('knobs_from')!r})")
        return p
    if sha != est.get("record_sha256"):
        p.append(f"{est.get('knobs_from')} is {sha[:8]} here, HS1's probe read {str(est.get('record_sha256'))[:8]}")
    other = sorted(k for k in set(theirs) | set(knobs) if theirs.get(k) != knobs.get(k))
    if other:
        p.append(f"HS1's probe took other knobs than the hold's ({', '.join(other)})")
    return p


def record_reference_problems(doc, facts):
    """A calibration record as a speed reference (`--reference`): one of schema 1 names no PC and is never one (K11: the record of
    2026-11-04 was measured on another PC); a frozen one of schema 2 only on its own host and PC (K5, K10)."""
    if not isinstance(doc, dict) or "status" not in doc or "schema" not in doc:
        return []                                          # origin.json: the session's own costs (its host.json names the PC)
    import calibration as C
    sha = str(doc.get("sha256") or "")[:8]
    if doc.get("schema") == 1:
        return [f"the record {sha} is of schema 1 and names no PC: it is never a speed reference (K11)"]
    try:
        C.require_host(doc, facts)
    except C.RecordError as exc:
        return [str(exc)]
    return []


def _read_json(path, what):
    """A JSON file the hold is given (--calibration, --reference): SpeedReferenceError naming it when it is not there or is not JSON,
    rather than a traceback (T-116)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise SpeedReferenceError(f"{what} {path} cannot be read ({type(exc).__name__}: {exc.strerror or exc})") from exc
    except ValueError as exc:
        raise SpeedReferenceError(f"{what} {path} is not JSON ({exc})") from exc


def _session_reference(session, ref, rule, calibration):
    """The session's speed reference: written before the first hold against it; a session has one, so another file is refused."""
    path = os.path.join(session, SPEED_REFERENCE)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            have = json.load(fh)
        if have.get("sha256") != ref["sha256"]:
            raise SpeedReferenceError(f"the session holds against the HS1 medians {str(have.get('sha256'))[:8]} ({have.get('path')}); "
                                      f"this file is {ref['sha256'][:8]}: a session has one speed reference")
        return path, have
    os.makedirs(session, exist_ok=True)
    have = {"reference": "HS1's medians on this PC (K11)", "path": ref["path"], "sha256": ref["sha256"], "host": ref["host"],
            "estimator": ref["estimator"], "calibration": os.path.abspath(calibration), "reference_costs_ms": ref["costs"],
            "rule": rule, "holds": []}
    _write_json(path, have)
    return path, have


def speed_hold_main(args, host=None):
    """The speed hold of a packet on this host (executor.RealHost): exit 0 when it held, EXIT_HOST_UNFIT when it did not, EXIT_REFUSED
    for a reference it does not take or a file it cannot read (T-116), EXIT_INTERRUPTED when TERM, HUP or INT stopped it. With --medians (R1, K11) the reference is HS1's
    medians on this PC, each CPU against its own; their sha256 is printed and, with --session, kept with every hold in the session's
    speed_reference.json, a stopped one with the pairs it made (T-115 LOW 10)."""
    if host is None:
        import executor as X
        host = X.RealHost()
        X._install_signal_handlers()                 # TERM and HUP end the hold as an INT does, through the record below
    medians, session = getattr(args, "medians", None), getattr(args, "session", None)
    rule = {"lo": args.lo, "hi": args.hi, "agree": args.agree, "max_min": args.max_min}
    record = None
    try:
        cal = _read_json(args.calibration, "--calibration")      # the record whose knobs the probe takes, also under --reference
        if not isinstance(cal, dict) or not isinstance(cal.get("knobs"), dict):
            raise SpeedReferenceError(f"--calibration {args.calibration} has no knobs: the probe takes a record's knobs")
        if medians:
            ref = load_medians(medians)
            problems = medians_problems(ref, host.facts(), cal["knobs"])
            if problems:
                raise SpeedReferenceError("; ".join(problems))
            print(f"speed hold: reference HS1's medians {ref['path']}, sha256 {ref['sha256']}, PC {ref['host']['cpu_model']}, "
                  f"VirtualBox host {ref['host']['vbox_host_version']}")
            costs = ref["costs"]
            if session:
                record = _session_reference(session, ref, rule, args.calibration)
        else:
            doc = _read_json(args.reference, "--reference")
            problems = record_reference_problems(doc, host.facts())
            if problems:
                raise SpeedReferenceError("; ".join(problems))
            costs = doc.get("route_costs_ms") if isinstance(doc, dict) else None
            if not isinstance(costs, dict) or not costs:
                raise SpeedReferenceError(f"--reference {args.reference} has no route_costs_ms: it is not a speed reference")
    except SpeedReferenceError as exc:
        print(f"speed hold: refused: {exc}")
        return EXIT_REFUSED
    made, began = [], host.monotonic()
    try:
        r = speed_hold(host, os.path.abspath(args.calibration), costs, print, args.lo, args.hi, args.agree, args.every_s, args.max_min,
                       note=made.append)
    except KeyboardInterrupt as exc:
        r = {"held": False, "stopped": f"interrupted ({str(exc) or 'INT'}) after {len(made)} probe pairs", "pairs": made,
             "waited_s": round(host.monotonic() - began, 1)}
        if record:
            path, have = record
            have["holds"].append(r)
            _write_json(path, have)
        print(f"speed hold: stopped, {r['stopped']}" + (f"; they are kept in {record[0]}" if record else ""))
        return EXIT_INTERRUPTED
    if record:
        path, have = record
        have["holds"].append(r)
        _write_json(path, have)
    print(f"speed hold: {'held' if r['held'] else 'NOT held'} after {len(r['pairs'])} probe pairs, {r['waited_s']:.0f} s "
          f"(band {args.lo:+.0%} to {args.hi:+.0%}" + (f", agreeing within {args.agree:.0%}" if args.agree is not None else "") + ")")
    return 0 if r["held"] else EXIT_HOST_UNFIT


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("chrony-sampler", help="the 30-s chrony sampler")
    p.add_argument("--every", type=float, default=CHRONY_S)
    p = sub.add_parser("judge", help="H3-H7 on a finished run from monitors' records, offline (H1 from its run.json if there)")
    p.add_argument("run_dir")
    p.add_argument("--monitors", required=True)
    p.add_argument("--start", required=True, help="the window's start, ISO UTC")
    p.add_argument("--end", required=True)
    p.add_argument("--slip-limit-s", type=float, default=0.1)
    p = sub.add_parser("speed-hold", help="probe pairs every 5 min until two in a row lie in the band (a packet's pre-condition)")
    p.add_argument("--calibration", required=True, help="the record whose knobs the probe takes")
    ref = p.add_mutually_exclusive_group(required=True)
    ref.add_argument("--reference", help="a JSON file with route_costs_ms: the session's origin.json, or a frozen record of this PC")
    ref.add_argument("--medians", help="HS1's medians on this PC (R1, K11): per CPU and route, the series' median cost")
    p.add_argument("--session", default=None, help="with --medians: keep the file's sha256 and every hold in DIR/speed_reference.json")
    p.add_argument("--lo", type=float, default=-SPEED_DEV)
    p.add_argument("--hi", type=float, default=SPEED_DEV)
    p.add_argument("--agree", type=float, default=None)
    p.add_argument("--max-min", type=float, default=HOLD_MAX_MIN)
    p.add_argument("--every-s", type=float, default=HOLD_EVERY_S)
    args = ap.parse_args(argv)
    if args.command == "chrony-sampler":
        try:
            chrony_sampler(args.every)
        except KeyboardInterrupt:
            pass
        return 0
    if args.command == "speed-hold":
        return speed_hold_main(args)
    t0, t1 = (datetime.datetime.fromisoformat(x).timestamp() for x in (args.start, args.end))
    with open(os.path.join(args.run_dir, "run.json"), encoding="utf-8") as fh:
        run = json.load(fh)
    verdict = judge_host(run.get("speed"), pooled_legit_slip_p99(args.run_dir), args.slip_limit_s, read_monitors(args.monitors), None,
                         t0, t1, staged=run.get("scenario") == STAGED_SCENARIO)
    print(json.dumps(verdict, indent=1, sort_keys=True))
    return 0 if verdict["ok"] else 3


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)  # a step started by packet.sh (`cmd &`) inherits SIGINT ignored (T-105 F3)
    sys.exit(main())
