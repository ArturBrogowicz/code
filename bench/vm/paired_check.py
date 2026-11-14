#!/usr/bin/env python3
"""The paired check of the two probe contexts before R1's speed hold (re-calibration pre-registration, section 5.3, P-1).

HS1's medians (docs/HS1_PREREG.md 7) were measured by bench/vm/hs1_probe.py in the sandbox as uid 1000 (context A). R1's hold
measures with `bench/calibrate.py origin-session` as root (context B). Both use the origin's `time_routes` with 21 repeats and the
same knobs; the process context differs (T-105 F8). This tool runs both contexts on CPU 0, then CPU 1, in the order A B B A, and
judges: per CPU and route r in C3, C5, off = mean(B) / mean(A) - 1; D = the mean of the four. |D| <= 5 % (inclusive): R1 goes on.
|D| above 5 %, or a probe that cannot be read: R1 stops before the hold. Nothing here reads a Q, a p95 or a harm.

usage: paired_check.py run OUT_DIR [--medians FILE]    run the 8 probes from this tree (as the user; B through sudo), then judge
       paired_check.py judge OUT_DIR [--medians FILE]  judge OUT_DIR/probes.jsonl offline and write OUT_DIR/paired.json
exit:  0 go on; 6 stop (|D| above the limit); 3 stop (a probe could not be read); 2 usage or a start condition not met
paired.json names the boot and the time it was judged, so that the packet can refuse a check from another boot or too old.
Standard library only.
"""
import argparse
import datetime as dt
import json
import math
import os
import signal
import statistics
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# --- pre-registered (P-1); a change is a dated addendum approved by the user ------------------------------------------------
LIMIT = 0.05                            # |D| at most this (inclusive): half of the hold's 10 % band
ROUTES = ("C3", "C5")                   # the CPU-bound routes H1 and the hold read
CPUS = ("0", "1")                       # the hold's CPUs, in this order
ORDER = ("A", "B", "B", "A")            # per CPU: A = HS1's context, B = the hold's
REPEATS = 21                            # the estimator's repeats in both contexts (HS1 and hostcheck.SPEED_REPEATS)
CLOCK = "thread_time"                   # the estimator's clock in both contexts
MIN_UPTIME_S = 1800.0                   # as the packet's pre-check: no check in the first 30 min of a boot
EXIT_GO, EXIT_USAGE, EXIT_UNREADABLE, EXIT_STOP = 0, 2, 3, 6
# --- where the two contexts' programs are (the same as HS1's series and the packet's) --------------------------------------
HS1_PY = os.environ.get("HS1_PY", "/home/artur/DDoS-mitigation/.venv/bin/python")
SBX = os.environ.get("HS1_SBX", "/home/artur/agent_workspace/skills/sandboxed-offline-run/sbx.sh")
TREE_PY = os.environ.get("PAIRED_TREE_PY", os.path.join(ROOT, "venv", "bin", "python"))
WORKSPACE = "/home/artur/agent_workspace"  # sbx.sh runs only in a directory under it
PROBE_TIMEOUT_S = 600
KILL_GRACE_S = 10


def utc_now():
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def boot_id():
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
        return fh.read().strip()


def uptime_s():
    with open("/proc/uptime", encoding="ascii") as fh:
        return float(fh.read().split()[0])


def command(ctx, cpu, out_dir, sample, root=ROOT):
    """The command of one probe of context `ctx` on `cpu`: A as HS1's series ran it (in the sandbox, uid 1000, -I -B), B as the
    hold runs it (root, the tree's venv, -B, `origin-session` with the template's knobs)."""
    if ctx == "A":
        return [SBX, out_dir, "taskset", "-c", cpu, HS1_PY, "-I", "-B", os.path.join(root, "bench", "vm", "hs1_probe.py"),
                str(sample), str(REPEATS)]
    if ctx == "B":
        return ["sudo", "env", "PYTHONDONTWRITEBYTECODE=1", "taskset", "-c", cpu, TREE_PY, "-B",
                os.path.join(root, "bench", "calibrate.py"), "origin-session", "--repeats", str(REPEATS), "--calibration",
                os.path.join(root, "bench", "calibration", "placeholder.json")]
    raise ValueError(f"context {ctx!r}")


def plan():
    """The probes in the order they run: (index, cpu, ctx)."""
    return [(i, cpu, ctx) for i, (cpu, ctx) in enumerate((cpu, ctx) for cpu in CPUS for ctx in ORDER)]


def run_probe(cmd, timeout=PROBE_TIMEOUT_S):
    """Run one probe in its own session: (rc, stdout, stderr). On a timeout the session gets TERM (sudo relays it to the root
    command), then KILL after a grace period, so that no probe is left loading a CPU into the hold. rc None: it did not finish."""
    try:
        p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as e:
        return None, "", f"{type(e).__name__}: {str(e)[:200]}"
    try:
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                break
            try:
                p.communicate(timeout=KILL_GRACE_S)
                break
            except subprocess.TimeoutExpired:
                continue
        return None, "", f"TimeoutExpired: no result within {timeout} s; the probe's session was stopped"


def parse_probe(stdout):
    """The last JSON line of a probe's output that has `costs_ms`, as a dict, or None."""
    for line in reversed((stdout or "").strip().splitlines()):
        try:
            got = json.loads(line)
        except ValueError:
            continue
        if isinstance(got, dict) and isinstance(got.get("costs_ms"), dict):
            return got
    return None


def parse_costs(stdout):
    """The route costs in ms from a probe's output, or None."""
    got = parse_probe(stdout)
    try:
        return {k: float(v) for k, v in got["costs_ms"].items()} if got else None
    except (TypeError, ValueError):
        return None


def run(out_dir, runner=run_probe, now=utc_now):
    """Run the 8 probes and append one JSON line each to OUT_DIR/probes.jsonl. Returns the records."""
    os.makedirs(out_dir, exist_ok=True)
    records = []
    with open(os.path.join(out_dir, "probes.jsonl"), "a", encoding="utf-8") as fh:
        for i, cpu, ctx in plan():
            cmd = command(ctx, cpu, out_dir, 900 + i)
            start = now()
            rc, out, err = runner(cmd)
            got = parse_probe(out) if rc == 0 else None
            costs = parse_costs(out) if rc == 0 else None
            rec = {"i": i, "cpu": cpu, "ctx": ctx, "utc_start": start, "utc_end": now(), "rc": rc, "costs_ms": costs,
                   "reported": {k: got[k] for k in ("cpus", "repeats", "clock") if k in got} if got else None,
                   "error": None if costs is not None else (err or out or "")[-400:], "cmd": cmd}
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            records.append(rec)
    return records


def read_records(out_dir):
    """(records, problems): every line of OUT_DIR/probes.jsonl that is a JSON object; a line that is not is a problem."""
    records, problems = [], []
    with open(os.path.join(out_dir, "probes.jsonl"), encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                problems.append(f"probes.jsonl line {n} is not JSON (a torn write?)")
                continue
            if isinstance(rec, dict):
                records.append(rec)
            else:
                problems.append(f"probes.jsonl line {n} is not a JSON object")
    return records, problems


def medians_problems(medians):
    """What makes a file unusable as HS1's medians for the report ([] when usable). Not a rule of P-1."""
    try:
        for cpu in CPUS:
            for r in ROUTES:
                v = medians["medians_ms"][cpu][r]["median_ms"]
                if isinstance(v, bool) or not isinstance(v, (int, float)) or not v > 0:
                    return [f"medians_ms[{cpu}][{r}] is not a positive number"]
    except (KeyError, TypeError):
        return ["not HS1's medians.json: medians_ms of CPUs 0 and 1 with C3 and C5 expected"]
    return []


def deviation_from_medians(costs_by_cpu, medians):
    """H1's d of one context against HS1's medians: the mean over the CPUs of the mean over ROUTES of cost / median - 1."""
    per_cpu = []
    for cpu in CPUS:
        ref = medians["medians_ms"][cpu]
        per_cpu.append(statistics.fmean(costs_by_cpu[cpu][r] / ref[r]["median_ms"] - 1.0 for r in ROUTES))
    return statistics.fmean(per_cpu)


def record_problems(i, cpu, ctx, rec):
    """Why record `rec` cannot count as planned probe (i, cpu, ctx); [] when it can."""
    if (rec.get("i"), rec.get("cpu"), rec.get("ctx")) != (i, cpu, ctx):
        return [f"probe {i}: found cpu {rec.get('cpu')} ctx {rec.get('ctx')}, planned cpu {cpu} ctx {ctx}"]
    costs = rec.get("costs_ms")
    if not isinstance(costs, dict) or any(isinstance(costs.get(r), bool) or not isinstance(costs.get(r), (int, float))
                                          or not math.isfinite(costs[r]) or not costs[r] > 0 for r in ROUTES):
        return [f"probe {i} (CPU {cpu}, {ctx}) could not be read: {str(rec.get('error'))[:120]}"]
    rep = rec.get("reported") or {}
    out = []
    if "clock" in rep and rep["clock"] != CLOCK:
        out.append(f"probe {i} (CPU {cpu}, {ctx}) timed with {rep['clock']!r}, not {CLOCK}")
    if ctx == "A":   # HS1's probe names the CPUs it ran on and its repeats
        if rep.get("cpus") != [int(cpu)]:
            out.append(f"probe {i} (CPU {cpu}, A) reports CPUs {rep.get('cpus')}, not [{cpu}]")
        if rep.get("repeats") != REPEATS:
            out.append(f"probe {i} (CPU {cpu}, A) reports {rep.get('repeats')} repeats, not {REPEATS}")
    return out


def judge(records, medians=None, problems=()):
    """P-1's verdict from the probe records: {ok, exit, D, per_cpu, reasons, ...}. Fails closed: every planned probe must be
    present (cpu, ctx and order as planned) and readable with both routes."""
    reasons = list(problems)
    expected = plan()
    if len(records) != len(expected):
        reasons.append(f"{len(records)} probe records, {len(expected)} planned")
    by = {}
    for (i, cpu, ctx), rec in zip(expected, records):
        bad = record_problems(i, cpu, ctx, rec)
        if bad:
            reasons += bad
            continue
        by.setdefault(cpu, {}).setdefault(ctx, []).append(rec["costs_ms"])
    out = {"schema": "paired-check/1", "limit": LIMIT, "routes": list(ROUTES), "cpus": list(CPUS), "order": list(ORDER),
           "repeats": REPEATS, "per_cpu": {}, "D": None}
    if reasons:
        return {**out, "ok": False, "exit": EXIT_UNREADABLE, "reasons": reasons}
    means = {}
    for cpu in CPUS:
        means[cpu] = {ctx: {r: statistics.fmean(c[r] for c in by[cpu][ctx]) for r in ROUTES} for ctx in ("A", "B")}
        out["per_cpu"][cpu] = {"mean_ms": means[cpu],
                               "off": {r: means[cpu]["B"][r] / means[cpu]["A"][r] - 1.0 for r in ROUTES}}
    D = statistics.fmean(out["per_cpu"][cpu]["off"][r] for cpu in CPUS for r in ROUTES)
    out["D"] = D
    if medians is not None:
        out["d_vs_hs1_medians"] = {ctx: deviation_from_medians({cpu: means[cpu][ctx] for cpu in CPUS}, medians)
                                   for ctx in ("A", "B")}
    if abs(D) <= LIMIT:
        return {**out, "ok": True, "exit": EXIT_GO, "reasons": []}
    return {**out, "ok": False, "exit": EXIT_STOP,
            "reasons": [f"the contexts differ by D = {D:+.2%}, beyond {LIMIT:.0%}: R1 stops before the hold (P-1)"]}


def report(v):
    lines = []
    for cpu, x in v.get("per_cpu", {}).items():
        lines.append(f"CPU {cpu}: " + ", ".join(f"{r} A {x['mean_ms']['A'][r]:.3f} ms B {x['mean_ms']['B'][r]:.3f} ms "
                                               f"off {x['off'][r]:+.2%}" for r in ROUTES))
    if v.get("D") is not None:
        lines.append(f"D = {v['D']:+.2%} (limit {LIMIT:.0%}, inclusive)")
    for ctx, d in (v.get("d_vs_hs1_medians") or {}).items():
        lines.append(f"context {ctx}: d against HS1's medians {d:+.2%}")
    lines += v.get("reasons", [])
    lines.append("P-1: GO ON (R1's hold may start)" if v["ok"] else "P-1: STOP before R1's hold; the user decides")
    return "\n".join(lines)


def main(argv=None, read_uptime=uptime_s, read_boot=boot_id, do_run=run):
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("mode", choices=("run", "judge"))
    ap.add_argument("out_dir")
    ap.add_argument("--medians", default=None, help="HS1's medians.json: also report each context's d against it")
    a = ap.parse_args(argv)
    out_dir = os.path.realpath(a.out_dir)
    medians = None
    if a.medians:                       # read before any probe, so that a bad path costs no probe
        try:
            with open(a.medians, encoding="utf-8") as fh:
                medians = json.load(fh)
        except (OSError, ValueError) as e:
            print(f"paired_check: --medians {a.medians}: {type(e).__name__}: {e}", file=sys.stderr)
            return EXIT_USAGE
        bad = medians_problems(medians)
        if bad:
            print(f"paired_check: --medians {a.medians}: {bad[0]}", file=sys.stderr)
            return EXIT_USAGE
    up = None
    if a.mode == "run":
        if not (out_dir + "/").startswith(os.path.realpath(WORKSPACE) + "/"):
            print(f"paired_check: OUT_DIR must be under {WORKSPACE}/ (the sandbox of context A runs there)", file=sys.stderr)
            return EXIT_USAGE
        if os.path.exists(os.path.join(out_dir, "probes.jsonl")):
            print(f"paired_check: {out_dir}/probes.jsonl exists; a check is never appended to (use a new OUT_DIR)", file=sys.stderr)
            return EXIT_USAGE
        up = read_uptime()
        if up < MIN_UPTIME_S:
            print(f"paired_check: uptime {up:.0f} s, below {MIN_UPTIME_S:.0f} s: wait, then run it", file=sys.stderr)
            return EXIT_USAGE
        do_run(out_dir)
    records, problems = read_records(out_dir)
    v = judge(records, medians, problems)
    v["medians_file"] = os.path.abspath(a.medians) if a.medians else None
    v["judged_utc"] = utc_now()
    v["boot_id"] = read_boot()
    v["uptime_s_at_start"] = up
    with open(os.path.join(out_dir, "paired.json"), "w", encoding="utf-8") as fh:
        json.dump(v, fh, indent=1, sort_keys=True)
    print(report(v))
    return v["exit"]


if __name__ == "__main__":
    sys.exit(main())
