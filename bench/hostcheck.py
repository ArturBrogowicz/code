"""Host validity per run (docs/RECALIBRATION_2026-11_DESIGN.md 5.1): what the host's own records say about the stretch a run was made
in, judged by fixed rules. Nothing here reads a run's Q, p95 or harm: the rules read the speed probes, the generators' timing and the
monitors' records only, so that they can be fixed before the data and applied by a tool.

H1, the speed bracket: before the stack starts and after the teardown, the origin's own estimator (origin.time_routes, 21 repeats, the
calling thread's CPU time, the record's knobs) on CPU 0 and on CPU 1, the same command as a session of the calibrator's step 1
(`calibrate.py origin-session`). `d` is the mean over the two CPUs of the mean of C3's and C5's deviations from the reference costs
(in a calibration session the costs of its own origin step, afterwards the frozen record's); a run is host-invalid when |d| exceeds
SPEED_DEV at either end. What the origin spent in the run per unit of frozen cost it served, the in-run index, is recorded beside them
and judged by nothing.
"""
import csv
import datetime
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CALIBRATE = os.path.join(HERE, "calibrate.py")

SPEED_DEV = 0.10                     # H1: |d| at most this before and after a run
SPEED_ROUTES = ("C3", "C5")          # the CPU-bound routes the speed series of 2026-11-11 read (finding 2)
SPEED_CPUS = ("0", "1")              # the server's CPUs (population.PIN_PLAN and PIN_PLAN_DAEMON)
SPEED_REPEATS = 21                   # as a session of the origin step
PROBE_TIMEOUT_S = 600


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


def speed_deviation(probe, reference_costs, routes=SPEED_ROUTES):
    """d of one probe pair: the mean over the CPUs of the mean over `routes` of cost / reference - 1. None when a CPU's probe could
    not be read or a route is missing: a probe that says nothing cannot vouch for the run."""
    per_cpu = []
    for cpu in SPEED_CPUS:
        costs = (probe or {}).get("cpus", {}).get(cpu)
        if not costs or any(costs.get(k) is None or not reference_costs.get(k) for k in routes):
            return None
        per_cpu.append(statistics.fmean(costs[k] / reference_costs[k] - 1.0 for k in routes))
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
