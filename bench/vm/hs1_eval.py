#!/usr/bin/env python3
"""HS1, the standalone host stability check: the evaluator (docs/HS1_PREREG.md, section 5).

Reads only the files of one run directory written by bench/vm/hs1_series.sh, prints PASS, FAIL or NO READING with every
rule's numbers, and writes verdict.json and medians.json into that directory. medians.json holds, per CPU (0 and 1) and per
route, the series' median of the origin's cost estimates: R1's speed hold uses it as its reference on this host (section 7
of the pre-registration). Standard library only.

usage: hs1_eval.py RUN_DIR             evaluate a run (exit 0 PASS, 1 FAIL, 3 NO READING)
       hs1_eval.py --precheck RUN_DIR  judge only the start conditions in RUN_DIR/identity_start.txt (exit 0: may start)
"""
import argparse
import collections
import datetime as dt
import itertools
import json
import math
import os
import re
import statistics
import sys

# --- pre-registered constants (docs/HS1_PREREG.md v1; changing one is a new version of the pre-registration) ----------
N_SAMPLES = 36                           # sample times, 300 s apart: 3 h
INTERVAL_S = 300
CPUS = ("0", "1", "7")                   # probed at every sample time, in this order
REF_CPUS = ("0", "1")                    # the CPUs of R1's speed hold (medians.json)
ROUTES = ("C0", "C1", "C2", "C3", "C5")
STEADY_ROUTES = ("C3", "C5")             # P2: the CPU-bound routes
WITHIN = 0.10                            # P2: |dev| <= 10 % counts as steady ...
WITHIN_SHARE = 0.95                      # ... for at least 95 % of the pooled values (inclusive)
BEYOND = 0.20                            # P2: no |dev| above 20 % (exactly 20 % passes)
MIN_PROBES_P2 = 12                       # a CPU enters P2 with at least 12 probes (1 h)
PAUSE_RATE_PER_H = 0.5                   # P4: the allowed pause events = ceil(0.5 per hour x the series' hours)
MERGE_S = 60.0                           # P4: a line within 60 s of an event's first line belongs to that event
MPSTAT_NOMINAL_S = 5.0
MPSTAT_GAP_S = 6.0                       # P4: a gap above 6 s between consecutive mpstat samples is a pause line
OFFSET_MAX_S = 0.1                       # P5: |chrony System time| below 0.1 s in every 30-s sample
SOURCE_MAX_S = 1.0                       # P5: the selected source at most 1 s off
BUSY_MEAN_PCT = 5.0                      # guest-busy sample time: foreign processes above 5 % of a CPU on average ...
BUSY_MAX_PCT = 50.0                      # ... or above 50 % in one 10-s pidstat sample ...
BUSY_HALF_WINDOW_S = 30.0                # ... within 30 s of the sample time
BUSY_SHARE_MAX = 0.05                    # NO READING above 5 % guest-busy sample times
COVER_S = 60.0                           # every monitor's records reach within 60 s of the series' start and end
MIN_UPTIME_S = 1800.0
EXPECTED = {"cpu_model": "AMD Ryzen 7 7730U with Radeon Graphics", "vbox_host_version": "7.2.10r174163",
            "kernel": "7.0.0-42-generic", "memtotal_kb": "7600852",     # the user's PC for the programme (D-096)
            "storage": "internal SSD"}   # user-reported (HS1_STORAGE); "USB HDD" only by a dated amendment (prereg 2.7)
MEMTOTAL_TOL = 0.01                      # MemTotal within 1 % of EXPECTED (amendment D-102, 2026-11-14, before any data; K5's tolerance)
MASKED_TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer", "fwupd-refresh.timer", "logrotate.timer", "man-db.timer")
HELD = ("linux-generic", "linux-headers-generic", "linux-image-generic")
P6_KEYS = ("kernel", "cmdline", "dpkg_sha256", "snap_sha256", "holds")
P7_KEYS = ("boot_id", "cpu_model", "vbox_host_version", "tsc_mhz", "memtotal_kb")

KERNEL_PAUSE = re.compile(r"Long readout interval.*cs_nsec: (\d+)|rcu: INFO: \S+ detected stalls|blocked for more than \d+ seconds")
CHRONY_PAUSE = re.compile(r"Forward time jump|System clock was stepped by (-?[\d.]+)|System clock wrong by (-?[\d.]+)")
HOG = re.compile(r"hogged CPU for >\d+us")
CANT_SYNC = re.compile(r"Can't synchronise")
LINE_TIME = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)")
HDR_DATE = re.compile(r"(\d{4})-(\d\d)-(\d\d)|(\d\d)/(\d\d)/(\d{2,4})")
COLLECT_HEAD = re.compile(r"^# hs1-collect v1 file=(\S+) boot=(\S*) rc=(-?\d+) utc=\S+$")
COLLECT_END = "# hs1-collect end"
RFC3339 = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)")
DPKG_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ")
OWN = re.compile(r"hs1_(series\.sh|probe\.py|eval\.py)|sbx\.sh|^(?:\S*/)?(mpstat|pidstat|chronyc|sleep|date|sed|tail|cat|cut|"
                 r"grep|awk|sha256sum|git|dpkg-query|snap|apt-mark|systemctl|journalctl|taskset|sudo|unshare|mount|pgrep|"
                 r"paste|sort|tr|head|realpath|uname|wc|iostat)(\s|$)")
EPS = 1e-9
UTC = dt.UTC


def matches(key, have, want):
    """Whether an identity value meets its expected one: MemTotal within MEMTOTAL_TOL of it (it moves by a few kB between boots of
    the same VM: 7,600,844 / 7,600,852 / 7,600,856 kB), every other key exactly. An unreadable MemTotal does not match."""
    if key == "memtotal_kb":
        try:
            h, w = int(have), int(want)
        except (TypeError, ValueError):
            return False
        return abs(h - w) <= MEMTOTAL_TOL * w
    return have == want


def allowed_pauses(n_samples=N_SAMPLES):
    """The pause events allowed in a series of n sample times: the rate times the hours, rounded up (1.5 -> 2)."""
    return math.ceil(PAUSE_RATE_PER_H * n_samples * INTERVAL_S / 3600 - EPS)


# --- reading ------------------------------------------------------------------------------------------------------------

def read(run, name):
    try:
        with open(os.path.join(run, name), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def parse_utc(s):
    t = dt.datetime.fromisoformat(s.strip())
    return (t if t.tzinfo else t.replace(tzinfo=UTC)).astimezone(UTC)


def parse_identity(text):
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip():
            out[k.strip()] = v.strip()
    return out


def parse_end(text):
    """(time, reason) of the END file the series script writes when it stops, or None."""
    if not text or not text.strip():
        return None
    first = text.strip().splitlines()[0]
    stamp, _, reason = first.partition(" ")
    try:
        return parse_utc(stamp), reason.strip()
    except ValueError:
        return None, first.strip()


def parse_probes(text):
    probes, bad = [], 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            p = json.loads(line)
            costs = p["costs_ms"]
            if len(p["cpus"]) != 1 or not all(isinstance(costs.get(r), (int, float)) and costs[r] > 0 for r in ROUTES):
                raise ValueError(line)
            probes.append({"t": parse_utc(p["utc"]), "sample": int(p["sample"]), "cpu": str(p["cpus"][0]),
                           "costs": {r: float(costs[r]) for r in ROUTES}, "offset_pct": dict(p.get("offset_pct", {})),
                           "refused": list(p.get("refused", [])), "repeats": p.get("repeats")})
        except (ValueError, KeyError, TypeError):
            bad += 1
    return probes, bad


def parse_mpstat(text):
    """Times of the 'all' rows of `mpstat -P ALL 5` (24-h or AM/PM times; the date from the header; midnight rolls over)."""
    times, day, prev = [], None, None
    for line in (text or "").splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "Linux":
            m = HDR_DATE.search(line)
            if m and m.group(1):
                day = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            elif m:
                y = int(m.group(6))
                day = dt.date(y + 2000 if y < 100 else y, int(m.group(4)), int(m.group(5)))
            continue
        if day is None or not re.fullmatch(r"\d\d:\d\d:\d\d", f[0]):
            continue
        rest, ampm = f[1:], None
        if rest and rest[0] in ("AM", "PM"):
            ampm, rest = rest[0], rest[1:]
        if not rest or rest[0] != "all" or len(rest) < 3:
            continue
        hh, mm, ss = (int(x) for x in f[0].split(":"))
        if ampm:
            hh = hh % 12 + (12 if ampm == "PM" else 0)
        t = dt.datetime(day.year, day.month, day.day, hh, mm, ss, tzinfo=UTC)
        while prev is not None and t < prev - dt.timedelta(hours=12):
            t += dt.timedelta(days=1)
        prev = t
        times.append(t)
    return times


def is_kernel_thread(uid, cmd):
    return uid == 0 and " " not in cmd and not cmd.startswith("/")


def parse_pidstat(text):
    """{epoch: [summed %CPU of the foreign processes, [(pct, command)]]} from `pidstat -u -l -h -H 10` (epoch times; a plain
    `-h` prints HH:MM:SS, read here against the header's date in UTC); foreign = neither HS1's own processes nor kernel
    threads. Every interval that printed any line is present (0.0 when nothing foreign)."""
    cols, out, day, prev = None, {}, None, None
    for line in (text or "").splitlines():
        if line.startswith("Linux"):
            m = HDR_DATE.search(line)
            if m and m.group(1):
                day = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            elif m:
                y = int(m.group(6))
                day = dt.date(y + 2000 if y < 100 else y, int(m.group(4)), int(m.group(5)))
            continue
        if line.startswith("#"):
            h = line[1:].split()
            if "%CPU" in h and "Command" in h and "Time" in h and "UID" in h:
                cols = (h.index("Time"), h.index("UID"), h.index("%CPU"), h.index("Command"))
            continue
        f = line.split()
        if cols is None or len(f) <= cols[3]:
            continue
        try:
            if re.fullmatch(r"\d\d:\d\d:\d\d", f[cols[0]]):
                if day is None:
                    continue
                hh, mm, ss = (int(x) for x in f[cols[0]].split(":"))
                when = dt.datetime(day.year, day.month, day.day, hh, mm, ss, tzinfo=UTC)
                while prev is not None and when < prev - dt.timedelta(hours=12):
                    when += dt.timedelta(days=1)
                prev, t = when, when.timestamp()
            else:
                t = float(f[cols[0]])
            uid, pct = int(f[cols[1]]), float(f[cols[2]])
        except ValueError:
            continue
        cmd = " ".join(f[cols[3]:])
        slot = out.setdefault(t, [0.0, []])
        if OWN.search(cmd) or is_kernel_thread(uid, cmd):
            continue
        slot[0] += pct
        slot[1].append((pct, cmd[:70]))
    return out


def parse_chrony(text):
    """Tracking samples (time, System time offset s, leap) and selected-source samples (time, offset s)."""
    track, sel = [], []
    for line in (text or "").splitlines():
        f = line.split(" ", 2)
        if len(f) < 3:
            continue
        try:
            t = parse_utc(f[0])
        except ValueError:
            continue
        c = f[2].strip().split(",")
        try:
            if f[1] == "T" and len(c) >= 14:
                track.append((t, float(c[4]), c[13]))
            elif f[1] == "S" and len(c) >= 10 and c[1] == "*":
                sel.append((t, float(c[7])))
        except ValueError:
            continue
    return track, sel


def parse_iostat(text):
    """{device: [(time, {column: value})]} from `iostat -dxy -t 30` (ISO or locale timestamps; columns named by the header)."""
    out, t, cols = collections.defaultdict(list), None, None
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            cols = None
            continue
        m = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)([+-]\d\d):?(\d\d)", s)
        if m:
            t = parse_utc(f"{m.group(1)}{m.group(2)}:{m.group(3)}")
            continue
        f = s.split()
        if f[0] == "Device":
            cols = f
            continue
        if cols and t and len(f) == len(cols):
            try:
                out[f[0]].append((t, {c: float(x) for c, x in zip(cols[1:], f[1:])}))
            except ValueError:
                continue
    return out


def disk_latency(io, start, end):
    """Reported only: per device, the await of the 30-s samples that had I/O, and the busiest %util."""
    out = {}
    for dev, rows in io.items():
        rows = [r for t, r in rows if start <= t <= end]
        rep = {"samples": len(rows), "max_util_pct": max((r.get("%util", 0.0) for r in rows), default=None)}
        for kind, rate in (("r_await", "r/s"), ("w_await", "w/s"), ("await", "tps")):
            vals = sorted(r[kind] for r in rows if kind in r and r.get(rate, 1.0) > 0)
            if vals:
                rep[kind + "_ms"] = {"n": len(vals), "median": statistics.median(vals),
                                     "p95": vals[min(len(vals) - 1, math.ceil(0.95 * len(vals)) - 1)], "max": vals[-1]}
        out[dev] = rep
    return out


def read_extract(run, name, boot_id):
    """(content lines, None) of an extract hs1_series.sh's collector wrote, or (None, why it does not count): missing, without
    the collector's header or end marker (not written by it, or cut short), of another boot, or its command failed. The
    kernel extract must also hold a time-stamped line (a boot's kernel log is never empty). `snap changes` may fail with
    "no changes found", which is a positive empty answer."""
    text = read(run, name)
    if text is None:
        return None, f"{name} missing"
    lines = text.rstrip("\n").splitlines()
    m = COLLECT_HEAD.match(lines[0]) if lines else None
    if not m or m.group(1) != name or lines[-1].strip() != COLLECT_END:
        return None, f"{name} has no collector header and end marker"
    if m.group(2).replace("-", "") != boot_id:
        return None, f"{name} is of boot {m.group(2)}, not the series' boot {boot_id}"
    err = [x[len("# stderr: "):] for x in lines if x.startswith("# stderr: ")]
    if m.group(3) != "0" and not (name == "snap_changes.txt" and any(re.search(r"no changes", x, re.IGNORECASE) for x in err)):
        return None, f"{name}: its command failed (exit {m.group(3)})" + (f": {err[0][:80]}" if err else "")
    body = [x for x in lines[1:-1] if not x.startswith("# ")]
    if name == "journal_kernel.txt" and not any(LINE_TIME.match(x) for x in body):
        return None, f"{name} holds no time-stamped line"
    return body, None


def journal_lines(lines, start, end):
    out = []
    for line in lines or []:
        m = LINE_TIME.match(line)
        if m:
            t = dt.datetime.fromisoformat(m.group(1)).replace(tzinfo=UTC)
            if start <= t <= end:
                out.append((t, line))
    return out


def boot_end_state(lines):
    """'running' (the series' boot is the boot that collected), 'clean', 'unclean' or 'unknown', from boot_end.txt's content."""
    if not lines:
        return "unknown"
    head, _, tail = "\n".join(lines).partition("\ntail:")
    info = parse_identity(head)
    sb = info.get("series_boot_id", "").replace("-", "")
    cb = info.get("current_boot_id", "").replace("-", "")
    if not sb or not cb:
        return "unknown"
    if sb == cb:
        return "running"
    return "clean" if "systemd-shutdown[1]" in tail else "unclean"


# --- the rules ------------------------------------------------------------------------------------------------------------

def pause_events(mp_times, kern, chron, start, end):
    """P4's pause events: pause lines (mpstat gaps, kernel and chronyd lines) merged when within MERGE_S of the event's first."""
    lines = []
    for a, b in itertools.pairwise(mp_times):
        gap = (b - a).total_seconds()
        if gap > MPSTAT_GAP_S + EPS and start <= b <= end:
            lines.append((b, f"mpstat gap {gap:.0f} s", gap - MPSTAT_NOMINAL_S))
    for t, line in kern:
        m = KERNEL_PAUSE.search(line)
        if m:
            lines.append((t, "kernel: " + m.group(0)[:48], int(m.group(1)) / 1e9 if m.group(1) else None))
    for t, line in chron:
        m = CHRONY_PAUSE.search(line)
        if m:
            mag = m.group(1) or m.group(2)
            lines.append((t, "chronyd: " + m.group(0)[:48], abs(float(mag)) if mag else None))
    lines.sort(key=lambda x: x[0])
    events = []
    for t, what, dur in lines:
        if events and (t - events[-1]["t"]).total_seconds() <= MERGE_S + EPS:
            e = events[-1]
            e["lines"].append(what)
            if dur is not None:
                e["measured_s"] = max(e["measured_s"] or 0.0, dur)
        else:
            events.append({"t": t, "lines": [what], "measured_s": dur})
    return events


def steadiness(probes):
    """P2 per steady route: each CPU's values against that CPU's own median, pooled over the CPUs with enough probes."""
    by_cpu = collections.defaultdict(list)
    for p in probes:
        by_cpu[p["cpu"]].append(p)
    out, verdicts = {}, []
    for r in STEADY_ROUTES:
        devs, per_cpu = [], {}
        for c in CPUS:
            ps = by_cpu.get(c, [])
            if len(ps) < MIN_PROBES_P2:
                continue
            med = statistics.median(p["costs"][r] for p in ps)
            d = [p["costs"][r] / med - 1 for p in ps]
            devs += d
            per_cpu[c] = {"n": len(d), "median_ms": med, "worst_dev_pct": 100 * max(d, key=abs)}
        if not devs:
            out[r] = {"computable": False}
            continue
        within = sum(abs(x) <= WITHIN + EPS for x in devs) / len(devs)
        beyond = sum(abs(x) > BEYOND + EPS for x in devs)
        ok = within >= WITHIN_SHARE - EPS and beyond == 0
        verdicts.append(ok)
        out[r] = {"computable": True, "n": len(devs), "within_10pct_share": within, "beyond_20pct_n": beyond,
                  "worst_dev_pct": 100 * max(devs, key=abs), "per_cpu": per_cpu, "pass": ok}
    result = "not computable" if not verdicts else ("pass" if all(verdicts) else "fail")
    return result, out


def against_record(probes):
    """P1, reported only: the origin's own 25 % check against the 2026-11-04 costs (another CPU on the laptop)."""
    out = {}
    for c in CPUS:
        ps = [p for p in probes if p["cpu"] == c]
        if not ps:
            continue
        refusing = collections.Counter(r for p in ps for r in p["refused"])
        med_off = {r: statistics.median(p["offset_pct"][r] for p in ps if r in p["offset_pct"])
                   for r in ROUTES if any(r in p["offset_pct"] for p in ps)}
        out[c] = {"n": len(ps), "accepted": sum(not p["refused"] for p in ps), "refusing_routes": dict(refusing),
                  "median_offset_pct": med_off}
    return out


def medians(probes, cpus):
    out = {}
    for c in cpus:
        ps = [p for p in probes if p["cpu"] == c]
        if ps:
            out[c] = {r: {"median_ms": statistics.median(p["costs"][r] for p in ps), "n": len(ps),
                          "min_ms": min(p["costs"][r] for p in ps), "max_ms": max(p["costs"][r] for p in ps)}
                      for r in ROUTES}
    return out


def busy_sample_times(probes, pid):
    """Sample times at which the guest was not quiet (foreign CPU use above H6's two lines, or no pidstat record)."""
    first = {}
    for p in probes:
        first[p["sample"]] = min(first.get(p["sample"], p["t"]), p["t"])
    epochs = sorted(pid)
    busy = []
    for s, t in sorted(first.items()):
        e0 = t.timestamp()
        near = [pid[e][0] for e in epochs if abs(e - e0) <= BUSY_HALF_WINDOW_S + EPS]
        if not near or statistics.fmean(near) > BUSY_MEAN_PCT + EPS or max(near) > BUSY_MAX_PCT + EPS:
            busy.append({"sample": s, "mean_pct": statistics.fmean(near) if near else None,
                         "max_pct": max(near) if near else None})
    return busy, len(first)


def covered(times, start, end):
    return bool(times) and min(times) <= start + dt.timedelta(seconds=COVER_S) and \
        max(times) >= end - dt.timedelta(seconds=COVER_S)


def evaluate(run, expected=None, n_samples=N_SAMPLES):
    """The verdict of one run directory, as a dict (also what verdict.json holds)."""
    expected = EXPECTED if expected is None else expected
    ident0 = parse_identity(read(run, "identity_start.txt"))
    ident1 = parse_identity(read(run, "identity_end.txt"))
    end_rec = parse_end(read(run, "END"))
    probes, bad_lines = parse_probes(read(run, "probes.jsonl"))
    rules, notes = {}, []
    dry = ident0.get("dry_run") == "1"
    if dry and ident0.get("n_samples", "").isdigit():
        n_samples = int(ident0["n_samples"])        # a dry run (HS1_DRYRUN, fewer than 36 samples) is judged on its own length
    v = {"schema": "hs1-verdict/1", "run_dir": os.path.abspath(run), "n_required": n_samples, "dry_run": dry,
         "allowed_pause_events": allowed_pauses(n_samples), "rules": rules, "notes": notes,
         "identity_start": ident0, "identity_end": ident1, "malformed_probe_lines": bad_lines}
    if not ident0 or (end_rec and end_rec[1].startswith("precheck")) or not probes:
        v["verdict"], v["reasons"] = "NO READING", ["not started: no start identity, a refused pre-check or no probe"]
        return v
    start = parse_utc(ident0["utc"])
    probes = [p for p in probes if p["t"] >= start - dt.timedelta(seconds=5)]
    mp = parse_mpstat(read(run, "mpstat.txt"))
    pid = parse_pidstat(read(run, "pidstat.txt"))
    track, sel = parse_chrony(read(run, "chrony.txt"))
    last_seen = max([p["t"] for p in probes] + mp[-1:] + [t for t, _, _ in track[-1:]])
    end = end_rec[0] if end_rec and end_rec[0] else last_seen
    if end_rec:
        probes = [p for p in probes if p["t"] <= end]
    v["window"] = {"start_utc": start.isoformat(), "end_utc": end.isoformat(), "hours": (end - start).total_seconds() / 3600,
                   "end_reason": end_rec[1] if end_rec else None}
    boot = ident0.get("boot_id", "").replace("-", "")
    records = []                                      # records that do not count: NO READING at step 3
    if ident0.get("utc_offset") != "+0000":
        records.append(f"the guest's time zone is not UTC (utc_offset {ident0.get('utc_offset')!r})")
    kern_l, why_k = read_extract(run, "journal_kernel.txt", boot)
    chron_l, why_c = read_extract(run, "journal_chronyd.txt", boot)
    records += [w for w in (why_k, why_c) if w]
    kern = journal_lines(kern_l, start, end)
    chron = journal_lines(chron_l, start, end)

    # P3: no unclean end
    if end_rec and end_rec[0]:
        p3, state = "pass", "ended in its boot"
    elif end_rec:
        p3, state = "unknown", f"END's time stamp is unreadable: {end_rec[1]!r}"
    else:
        be_l, why_b = read_extract(run, "boot_end.txt", boot)
        state = why_b or boot_end_state(be_l)
        p3 = "fail" if state == "unclean" else "unknown"
    rules["P3"] = {"result": p3, "state": state}

    # P4: pause events as a rate
    events = pause_events(mp, kern, chron, start, end)
    allowed = allowed_pauses(n_samples)
    p4 = "fail" if len(events) > allowed else ("pass" if kern_l is not None and chron_l is not None else "unknown")
    rules["P4"] = {"result": p4, "events": len(events), "allowed": allowed,
                   "longest_measured_s": max([e["measured_s"] or 0.0 for e in events], default=0.0),
                   "list": [{"utc": e["t"].isoformat(), "measured_s": e["measured_s"], "lines": e["lines"]} for e in events],
                   "hogged_cpu_lines": sum(bool(HOG.search(x)) for _, x in kern),
                   "cant_synchronise_lines": sum(bool(CANT_SYNC.search(x)) for _, x in chron)}

    # P5: clock
    tw = [(t, o) for t, o, _ in track if start <= t <= end]
    sw = [(t, o) for t, o in sel if start <= t <= end]
    p5_fail = any(abs(o) >= OFFSET_MAX_S - EPS for _, o in tw) or any(abs(o) > SOURCE_MAX_S + EPS for _, o in sw)
    rules["P5"] = {"result": "fail" if p5_fail else ("pass" if tw else "unknown"), "samples": len(tw),
                   "max_abs_offset_s": max([abs(o) for _, o in tw], default=None),
                   "max_abs_selected_source_s": max([abs(o) for _, o in sw], default=None),
                   "samples_without_selected_source": len({t for t, _ in tw} - {t for t, _ in sw}),
                   "samples_leap_not_normal": sum(1 for t, _, leap in track if start <= t <= end and leap.strip() != "Normal")}

    # P6: no software change
    changed6 = [k for k in P6_KEYS if ident1 and ident0.get(k) != ident1.get(k)]
    dpkg_l, why_d = read_extract(run, "dpkg_log_window.txt", boot)
    snap_l, why_s = read_extract(run, "snap_changes.txt", boot)
    dpkg = [x for x in dpkg_l or []
            if DPKG_LINE.match(x) and start <= dt.datetime.fromisoformat(DPKG_LINE.match(x).group(1)).replace(tzinfo=UTC) <= end]
    snaps = []
    for x in snap_l or []:
        m = RFC3339.search(x)
        if m and start <= parse_utc(m.group(0)) <= end:
            snaps.append(x.strip()[:100])
    p6_fail = bool(changed6 or dpkg or snaps)
    p6_known = bool(ident1) and dpkg_l is not None and snap_l is not None
    rules["P6"] = {"result": "fail" if p6_fail else ("pass" if p6_known else "unknown"), "changed_keys": changed6,
                   "dpkg_lines_in_window": len(dpkg), "snap_changes_in_window": snaps,
                   "records_not_counted": [w for w in (why_d, why_s) if w] + ([] if ident1 else ["identity_end.txt missing"])}

    # P7: the same, expected host
    not_expected = [k for k in expected if not matches(k, ident0.get(k), expected[k])]
    changed7 = [k for k in P7_KEYS if ident1 and ident0.get(k) != ident1.get(k)]
    rules["P7"] = {"result": "fail" if (not_expected or changed7) else ("pass" if ident1 else "unknown"),
                   "start_not_expected": {k: [ident0.get(k), expected[k]] for k in not_expected},
                   "changed_start_to_end": {k: [ident0.get(k), ident1.get(k)] for k in changed7}}

    # evidence and quiet
    pid_times = [dt.datetime.fromtimestamp(e, UTC) for e in pid]
    cover = {"mpstat": covered(mp, start, end), "pidstat": covered(pid_times, start, end),
             "chrony": covered([t for t, _, _ in track], start, end)}
    busy, n_seen = busy_sample_times(probes, pid)
    busy_share = len(busy) / n_seen if n_seen else 1.0
    rules["evidence"] = {"monitors_cover_window": cover, "busy_sample_times": busy, "busy_share": busy_share,
                         "busy_share_max": BUSY_SHARE_MAX, "records_not_counted": records}

    # P2 and P1
    p2, p2d = steadiness(probes)
    rules["P2"] = {"result": p2, **p2d}
    rules["P1_reported"] = against_record(probes)
    rules["disk_reported"] = disk_latency(parse_iostat(read(run, "iostat.txt")), start, end)
    seen = collections.defaultdict(set)
    for p in probes:
        seen[p["sample"]].add(p["cpu"])
    complete = sorted(s for s, cs in seen.items() if set(CPUS) <= cs)
    rules["completeness"] = {"complete_sample_times": len(complete), "required": n_samples, "probes": len(probes)}

    fails = [k for k in ("P3", "P4", "P5", "P6", "P7") if rules[k]["result"] == "fail"]
    if fails:
        verdict, reasons = "FAIL", fails
    elif not all(cover.values()) or records or busy_share > BUSY_SHARE_MAX + EPS:
        verdict = "NO READING"
        reasons = [f"monitor records missing: {[k for k, ok in cover.items() if not ok]}"] if not all(cover.values()) else []
        reasons += records
        reasons += [f"guest not quiet at {len(busy)} of {n_seen} sample times"] if busy_share > BUSY_SHARE_MAX + EPS else []
    elif p2 == "fail":
        verdict, reasons = "FAIL", ["P2"]
    elif len(complete) < n_samples or p2 != "pass" or any(rules[k]["result"] != "pass" for k in ("P3", "P5", "P6", "P7")):
        verdict = "NO READING"
        reasons = [f"early: {len(complete)} of {n_samples} complete sample times"] if len(complete) < n_samples else []
        reasons += [f"{k} {rules[k]['result']}" for k in ("P2", "P3", "P5", "P6", "P7") if rules[k]["result"] != "pass"]
        reasons += [f"P3: {state}"] if p3 == "unknown" else []
        reasons += [f"P6: {w}" for w in rules["P6"]["records_not_counted"]]
    else:
        verdict, reasons = "PASS", []
    if dry:
        reasons.append(f"DRY RUN ({n_samples} samples): not an HS1 v1 reading")
    v["verdict"], v["reasons"] = verdict, reasons
    v["medians"] = medians_doc(run, v, probes, ident0, start, end, len(complete))
    return v


def medians_doc(run, v, probes, ident0, start, end, complete):
    reps = sorted({p["repeats"] for p in probes if p["repeats"] is not None})
    return {"schema": "hs1-medians/1", "run_dir": os.path.abspath(run), "verdict": v["verdict"],
            "usable_as_reference": v["verdict"] == "PASS" and not v["dry_run"],
            "host": {k: ident0.get(k) for k in ("cpu_model", "vbox_host_version", "kernel", "memtotal_kb", "tsc_mhz", "boot_id")},
            "estimator": {"function": "bench/origin.py time_routes (thread CPU time, median of the repeats' batches)",
                          "repeats": reps[0] if len(reps) == 1 else reps, "origin_sha256": ident0.get("origin_sha256"),
                          "probe_sha256": ident0.get("probe_sha256"), "knobs_from": "bench/calibration/ddos-mitigation-2026-11-04.json",
                          "record_sha256": ident0.get("record_sha256")},
            "window": {"start_utc": start.isoformat(), "end_utc": end.isoformat(), "complete_sample_times": complete,
                       "interval_s": INTERVAL_S},
            "medians_ms": medians(probes, REF_CPUS), "reported_only": medians(probes, tuple(c for c in CPUS if c not in REF_CPUS))}


def precheck(ident):
    """The start conditions of the pre-registration's section 2 that the guest can check; [] when all hold."""
    bad = []
    try:
        if float(ident.get("uptime_s", "0")) < MIN_UPTIME_S:
            bad.append(f"uptime {ident.get('uptime_s')} s < {MIN_UPTIME_S:.0f} s")
    except ValueError:
        bad.append("uptime unreadable")
    bad += [f"{k} is {ident.get(k)!r}, expected {want!r}" + (" (within 1 %)" if k == "memtotal_kb" else "")
            for k, want in EXPECTED.items() if not matches(k, ident.get(k), want)]
    if ident.get("utc_offset") != "+0000":
        bad.append(f"the guest's time zone is not UTC (utc_offset {ident.get('utc_offset')!r}; timezone {ident.get('timezone')!r})")
    tr = ident.get("chrony_tracking", "").split(",")
    try:
        if len(tr) < 14 or abs(float(tr[4])) >= OFFSET_MAX_S or tr[13].strip() != "Normal":
            bad.append(f"chrony not synchronised: {ident.get('chrony_tracking')!r}")
    except ValueError:
        bad.append("chrony tracking unreadable")
    sel = [s.split(",") for s in ident.get("chrony_sources", "").split("|") if s.count(",") >= 9]
    sel = [s for s in sel if s[1] == "*"]
    try:
        if not sel or abs(float(sel[0][7])) > SOURCE_MAX_S:
            bad.append("no selected chrony source within 1 s")
    except ValueError:
        bad.append("chrony sources unreadable")
    masked = dict(x.split(":", 1) for x in ident.get("masked", "").split(",") if ":" in x)
    bad += [f"{t} is {masked.get(t)!r}, not masked" for t in MASKED_TIMERS if masked.get(t) != "masked"]
    holds = set(ident.get("holds", "").split())
    bad += [f"{h} not held" for h in HELD if h not in holds]
    if ident.get("busy_procs"):
        bad.append(f"other work running: {ident['busy_procs']}")
    return bad


def report(v):
    r = v["rules"]
    out = [f"HS1 {v['run_dir']}"]
    if "window" in v:
        w = v["window"]
        out.append(f"window {w['start_utc']} .. {w['end_utc']} ({w['hours']:.2f} h), end: {w['end_reason']}")
    if "completeness" in r:
        c = r["completeness"]
        out.append(f"samples: {c['complete_sample_times']} of {c['required']} complete ({c['probes']} probes, "
                   f"{v['malformed_probe_lines']} malformed lines)")
    for cpu, x in r.get("P1_reported", {}).items():
        out.append(f"P1 (reported) CPU {cpu}: accepted {x['accepted']}/{x['n']}, refusing {x['refusing_routes']}, "
                   f"median offset vs 2026-11-04 " + " ".join(f"{k} {o:+.1f}%" for k, o in x["median_offset_pct"].items()))
    if "P2" in r:
        for route in STEADY_ROUTES:
            x = r["P2"].get(route, {})
            if x.get("computable"):
                out.append(f"P2 {route}: {x['n']} values, within 10 % {100 * x['within_10pct_share']:.1f} % (>= 95), beyond 20 % "
                           f"{x['beyond_20pct_n']} (0), worst {x['worst_dev_pct']:+.1f} % -> {'pass' if x['pass'] else 'fail'}")
        out.append(f"P2: {r['P2']['result']}")
    if "P3" in r:
        out.append(f"P3: {r['P3']['result']} ({r['P3']['state']})")
        p4 = r["P4"]
        out.append(f"P4: {p4['result']}: {p4['events']} pause events (allowed {p4['allowed']}), longest measured "
                   f"{p4['longest_measured_s']:.1f} s; hogged-CPU lines {p4['hogged_cpu_lines']}, can't-synchronise "
                   f"{p4['cant_synchronise_lines']}")
        out += [f"    {e['utc']} {e['measured_s']} {'; '.join(e['lines'])}" for e in p4["list"]]
        p5 = r["P5"]
        out.append(f"P5: {p5['result']}: {p5['samples']} samples, max |offset| {p5['max_abs_offset_s']} s, max |selected "
                   f"source| {p5['max_abs_selected_source_s']} s")
        out.append(f"P6: {r['P6']['result']} {r['P6']['changed_keys']} dpkg {r['P6']['dpkg_lines_in_window']} "
                   f"snap {len(r['P6']['snap_changes_in_window'])}")
        out.append(f"P7: {r['P7']['result']} {r['P7']['start_not_expected'] or ''}{r['P7']['changed_start_to_end'] or ''}")
        ev = r["evidence"]
        out.append(f"evidence: monitors {ev['monitors_cover_window']}, guest-busy share {100 * ev['busy_share']:.1f} % (<= 5)")
        for dev, d in r.get("disk_reported", {}).items():
            aw = {k: f"median {x['median']:.1f} p95 {x['p95']:.1f} max {x['max']:.1f} ms" for k, x in d.items() if k.endswith("_ms")}
            out.append(f"disk (reported) {dev}: {d['samples']} samples, max util {d['max_util_pct']} %, {aw}")
    out.append(f"VERDICT: {v['verdict']}" + (f"  ({'; '.join(v['reasons'])})" if v["reasons"] else ""))
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("run_dir")
    ap.add_argument("--precheck", action="store_true", help="judge only the start conditions")
    a = ap.parse_args(argv)
    if a.precheck:
        bad = precheck(parse_identity(read(a.run_dir, "identity_start.txt")))
        print("PRECHECK OK" if not bad else "PRECHECK REFUSED\n" + "\n".join(" - " + b for b in bad))
        return 0 if not bad else 1
    v = evaluate(a.run_dir)
    meds = v.pop("medians", None)
    print(report(v))
    with open(os.path.join(a.run_dir, "verdict.json"), "w", encoding="utf-8") as fh:
        json.dump(v, fh, indent=1, sort_keys=True, default=str)
    if meds is not None:
        with open(os.path.join(a.run_dir, "medians.json"), "w", encoding="utf-8") as fh:
            json.dump(meds, fh, indent=1, sort_keys=True)
    return {"PASS": 0, "FAIL": 1}.get(v["verdict"], 3)


if __name__ == "__main__":
    sys.exit(main())
