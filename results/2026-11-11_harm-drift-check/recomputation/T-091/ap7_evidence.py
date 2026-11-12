#!/usr/bin/env python3
"""AP-7 evidence beside the reading (read-only): per run, the tool's result, the single-run verdict inputs, pause
evidence (gaps between 5 s mpstat samples), CPU use on the server's CPUs 0-1, the busiest processes that are not the
testbed's, and chrony's offset. Then the descriptive statistics over the set A of the pre-registration.
Usage: ap7_evidence.py <campaign root> <ap7 dir with mpstat.txt, pidstat.txt, chrony.txt>
"""
import datetime as dt
import glob
import json
import math
import os
import statistics as st
import sys

ROOT, AP7 = sys.argv[1], sys.argv[2]
DAY = dt.date(2026, 11, 11)
TESTBED = ("nginx", "gunicorn", "python", "python3", "python3.14", "ip", "tc", "sudo", "bash", "sh")


def epoch(hms, ampm):
    h, m, s = (int(x) for x in hms.split(":"))
    if ampm == "PM" and h != 12:
        h += 12
    if ampm == "AM" and h == 12:
        h = 0
    return dt.datetime(DAY.year, DAY.month, DAY.day, h, m, s, tzinfo=dt.timezone.utc).timestamp()


def utc(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%H:%M:%S")


# ---- mpstat: {time: {cpu: busy %}} --------------------------------------------------------------------------------
mp = {}
for line in open(os.path.join(AP7, "mpstat.txt"), encoding="utf-8", errors="replace"):
    f = line.split()
    if len(f) == 13 and f[1] in ("AM", "PM") and f[2] != "CPU":
        mp.setdefault(epoch(f[0], f[1]), {})[f[2]] = {"busy": 100.0 - float(f[12]), "usr": float(f[3]),
                                                       "sys": float(f[5]), "soft": float(f[8]), "steal": float(f[9])}
times = sorted(mp)
gaps = [(a, b - a) for a, b in zip(times, times[1:]) if b - a > 6]
print(f"mpstat: {len(times)} samples, {utc(times[0])} to {utc(times[-1])}; gaps above 6 s: {len(gaps)}")
for a, g in gaps:
    print(f"  gap of {g:.0f} s after {utc(a)}")
print("  max %steal on any CPU:", max(v["steal"] for s in mp.values() for v in s.values()))

# ---- pidstat: [(time, command, cpu, %cpu)] ------------------------------------------------------------------------
ps = []
for line in open(os.path.join(AP7, "pidstat.txt"), encoding="utf-8", errors="replace"):
    f = line.split()
    if len(f) >= 11 and f[1] in ("AM", "PM") and f[2] != "UID":
        try:
            ps.append((epoch(f[0], f[1]), " ".join(f[10:]), int(f[9]), float(f[8])))
        except ValueError:
            pass

# ---- chrony ------------------------------------------------------------------------------------------------------
offs, bad = [], 0
for line in open(os.path.join(AP7, "chrony.txt"), encoding="utf-8", errors="replace"):
    f = line.strip().split(",")
    if len(f) >= 14:
        offs.append(abs(float(f[4])))
        bad += f[13] != "Normal"
print(f"chrony: {len(offs)} records, max |system-time offset| {max(offs):.6f} s, not Normal: {bad}")


def window(run):
    ex = run["executor"]
    return ex["zero_epoch_s"], max(ex["exit_epoch_s"].values())


def cpu_in(t0, t1, cpus):
    v = [s[c]["busy"] for t, s in mp.items() if t0 <= t <= t1 + 5 for c in cpus if c in s]
    return st.mean(v) if v else float("nan")


def others(t0, t1):
    """Mean %CPU per command over the window, commands that are not the testbed's, the five largest."""
    n = len({t for t, *_ in ps if t0 <= t <= t1 + 10}) or 1
    tot = {}
    for t, cmd, cpu, pc in ps:
        if t0 <= t <= t1 + 10 and cmd.split("/")[0] not in TESTBED:
            tot[cmd] = tot.get(cmd, 0.0) + pc / n
    return sorted(tot.items(), key=lambda kv: -kv[1])[:5]


def others_on_server_cpus(t0, t1):
    n = len({t for t, *_ in ps if t0 <= t <= t1 + 10}) or 1
    return sum(pc for t, cmd, cpu, pc in ps
               if t0 <= t <= t1 + 10 and cpu in (0, 1) and cmd.split("/")[0] not in TESTBED) / n


print("\nper run of AP-7 (window = timeline zero to the last stream's exit, UTC):")
for d in ("drift_20261111c_q1", "drift_20261111c_q1.second", "drift_20261111c_q2"):
    for rj in sorted(glob.glob(os.path.join(ROOT, d, "drift", "*", "*", "run.json"))):
        run = json.load(open(rj, encoding="utf-8"))
        t0, t1 = window(run)
        ex = run["executor"]
        g = [f"{x:.0f} s after {utc(a)}" for a, x in gaps if a <= t1 and a + x >= t0]
        name = os.path.relpath(os.path.dirname(rj), ROOT)
        print(f"- {name}\n    {utc(t0)}-{utc(t1)}  sound={ex['ok']}  retries={ex.get('setup_retries')}  "
              f"attack_start_error={ex.get('attack_start_error_s')}  reasons={ex['reasons']}")
        print(f"    busy % cpu0-1 {cpu_in(t0, t1, ('0', '1')):.1f}, cpu2-7 {cpu_in(t0, t1, tuple('234567')):.1f}; "
              f"non-testbed on cpu0-1 {others_on_server_cpus(t0, t1):.2f} %; mpstat gaps: {g or 'none'}")
        print("    busiest non-testbed: " + ", ".join(f"{c} {p:.1f}" for c, p in others(t0, t1)))

# ---- the set A, descriptive --------------------------------------------------------------------------------------
REF = {"legit": (100.0, 0.079438), "cheap_static_flood": (95.8089, 0.205702),
       "costly_export_flood": (75.3211, 0.251942), "costly_search_flood": (63.3700, 0.630813)}
A = [("AP-4 a1", "drift_20261108/drift/drift.json", 10), ("AP-4 a2", "drift_20261108.second/drift/drift.json", 10),
     ("AP-5 q1 a1", "drift_20261108_q1/drift/drift.json", 8),
     ("AP-7 q1 a1", "drift_20261111c_q1/drift/drift.json", 8),
     ("AP-7 q1 a2", "drift_20261111c_q1.second/drift/drift.json", 8)]
rows = []
for label, rel, ram in A:
    j = json.load(open(os.path.join(ROOT, rel), encoding="utf-8"))
    vals = {"legit": (j["legit"]["Q"], j["legit"]["p95_s"])}
    vals.update({k: (v["Q"], v["p95_s"]) for k, v in j["attacks"].items()})
    rows.append((label, ram, j["created_utc"], j["ok"], vals))
print("\nset A (descriptive; AP-7 gives no reading under rule 5):")
for label, ram, created, ok, vals in rows:
    print(f"  {label:11s} {created} RAM {ram:2d} GiB ok={ok}  " + "  ".join(
        f"{k.split('_')[1] if '_' in k else k}: Q {q:.4f} p95 {p:.6f}" for k, (q, p) in vals.items()))


def stats(sel, title):
    print(f"  {title} (n={len(sel)}):")
    for fam, (rq, rp) in REF.items():
        q = [r[4][fam][0] for r in sel]
        l2 = [math.log2(r[4][fam][1] / rp) for r in sel]
        p = [r[4][fam][1] for r in sel]
        sd = st.stdev(q) if len(q) > 1 else float("nan")
        if fam == "legit":
            inside = abs(st.mean(q) - rq) <= 2 and abs(st.mean(p) - rp) / rp <= 0.25
            extra = f"mean p95 {st.mean(p):.6f} ({(st.mean(p) - rp) / rp * 100:+.1f} %)"
        else:
            inside = abs(st.mean(q) - rq) <= 10 and abs(st.mean(l2)) <= 1.0
            extra = f"mean log2 p95 ratio {st.mean(l2):+.3f}"
        print(f"    {fam:20s} mean Q {st.mean(q):7.3f} (ref {rq:.4f}, diff {st.mean(q) - rq:+.2f})  SD {sd:5.2f}  "
              f"min {min(q):.2f} max {max(q):.2f}  {extra}  inside the floors: {inside}")


stats(rows, "all of A")
stats([r for r in rows if r[0].startswith("AP-7")], "AP-7's attempts alone")
stats([r for r in rows if r[1] == 10], "10 GiB attempts")
stats([r for r in rows if r[1] == 8], "8 GiB attempts")
