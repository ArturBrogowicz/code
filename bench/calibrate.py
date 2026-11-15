#!/usr/bin/env python3
"""The calibration runner of the harm benchmark (docs/HG1C_DESIGN.md 8, docs/BENCHMARK_HARM_DESIGN.md 7.2): the steps that fill
the calibration record with what the host measures, each one a directory of runs in the run contract, so that every number can be
recomputed offline. `freeze` reads those directories and never touches the VM.

    python3 bench/calibrate.py plan                                         # the steps, their runs and their time
    sudo ./venv/bin/python bench/calibrate.py origin    --out DIR           # 1  the cost of each route, unloaded
    sudo ./venv/bin/python bench/calibrate.py capacity  --out DIR           # 2  C_slo and C_sat, three staged runs
    sudo ./venv/bin/python bench/calibrate.py ladder    --out DIR --family costly_search_flood      # 3  screening, one per family
    sudo ./venv/bin/python bench/calibrate.py reference --out DIR           # 5  the Q and p95 the drift check must reproduce
    python3 bench/calibrate.py freeze --dir DIR --out bench/calibration/<host>-<date>.json         # 4+5  the knees, the record
    sudo ./venv/bin/python bench/calibrate.py drift --calibration FILE --out DIR                   # 7  before a later campaign

Every step that runs the VM is a separate approval and takes the environment gate of a campaign's start: the steps that make runs
take it with the executor's preflight, as a campaign does; the origin step, which builds nothing, takes the gate's uptime and load
alone (Runner.quiet, docs/HG1C_DESIGN.md departure 28). Each can be given `--simulate` to run on the simulated host
(bench/sim_host.py) with a server of a known capacity: the steps, the stop rules and the arithmetic seen working offline. A step stops, and says what that means, when the host cannot be calibrated: nothing is tuned.
"""
import argparse
import copy
import csv
import dataclasses
import datetime
import hashlib
import json
import math
import os
import random
import re
import shutil
import signal
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "eval"))
import calibration as C
import executor as X
import gate_campaign as GC
import harm_gate as H
import hostcheck as HC
import loadtools as LT
import origin as O
import population as P
import scenario as SC
import sim_host as S

SPECS = os.path.join(HERE, "scenarios")
CONTROL_SPEC = "benign_control"
FAMILY_SPECS = {"costly_search_flood": "costly_search_sub_threshold", "costly_export_flood": "costly_export_sub_threshold",
                "cheap_static_flood": "cheap_static_flood"}
# step 1: the unloaded cost of each route, in three sessions on a server CPU
ORIGIN_SESSIONS, ORIGIN_REPEATS, ORIGIN_SPREAD, ORIGIN_CPU = 3, 21, 0.10, "0"
# step 2: the capacity probe, levels of legit load in requests/s, staged in one run per repeat
CAPACITY_REPEATS, STEP_S, Q_WINDOW = 3, 20.0, (5.0, 17.0)
HEALTHY_Q, SATURATED_Q, SATURATED_REPEATS = 99.0, 50.0, 2
# step 3: the screening of a family, two repeats of an attack run per level and a control after every fourth run
LADDER_REPEATS, CONTROL_EVERY, CONTROL_SPREAD_PP = 2, 4, 2.0
# steps 5 and 7: a legit probe at rho, and an attack run at a family's knee
PROBE_S, PROBE_WINDOW = 120.0, (10.0, 120.0)
# step 5: the reference is N_REF rounds on the drift check's own seeds, each a legit probe and one attack run per family at its knee
# (docs/RECALIBRATION_2026-11_DESIGN.md 4, K1); the check (step 7) is M_DRIFT such rounds
N_REF, M_DRIFT = C.N_REF, C.M_DRIFT
# the populations of the calibration are drawn from seeds the gates' blocks (1-10) do not use; the reference and the drift check share
# theirs (41, then 42, 43 and 44 for the families in sorted order: calibration.drift_seeds), so that their spreads are the host's
SEEDS = {"capacity": 11, "ladder": 21, "drift": C.DRIFT_SEED}
RUN_ESTIMATE_S = 130.0                      # a run: docs/RECALIBRATION_2026-11_DESIGN.md 6.1 (119.5 s after its gate, 131.8 s with re-probes)
EXIT_OK, EXIT_USAGE, EXIT_STOPPED, EXIT_INVALID, EXIT_INTERRUPTED = 0, 1, 2, 3, 130
EXIT_HOST_UNFIT = HC.EXIT_HOST_UNFIT             # 5: the packet paused, host unfit (docs/RECALIBRATION_2026-11_DESIGN.md 5.1, K4)
EXIT_PAUSED = GC.EXIT_PAUSED                     # 4: the packet's time budget is used (--stop-after, K6)
EXIT_NOT_FROZEN = 7                              # a step stopped by its own rule: the calibration is NOT FROZEN (prereg 6; T-115 H-1)


class CalibrationStop(RuntimeError):
    """The host cannot be calibrated as it is, or a step cannot be trusted; the message says what that means (design 7.5).
    Nothing is tuned to get past it. This class itself is a refusal or a defect (exit 2, "stopped"): no reading, and the step resumes
    or the user decides; a stop by a step's own rule is the subclass StepRuleStop (exit 7)."""


class StepRuleStop(CalibrationStop):
    """A step stopped by its own rule, the stops that read NOT FROZEN (prereg 6, design 8.3; T-115 H-1, M-5): the origin's sessions
    disagree twice, the capacity probe's three rules, a screening not valid twice or with no level that can be run, a reference run
    with no Q or p95, and a freeze refused for a rule's reason (no knee, a screening not valid, a reference that stopped). Exit 7, so
    that a reading never has to be told from a refusal by the host (2) by the log's words. Nothing is made again to get past it."""


class RunUnsoundTwice(CalibrationStop):
    """A run was not sound in either attempt of this call (design 7.5, prereg 8): the packet stops (exit 2, as before) and the step
    resumes in a later packet, which gives the run two attempts again; the log names the class."""


def now():
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def spec_path(name):
    return os.path.join(SPECS, name + ".json")


def write_json(path, obj):
    X.write_json(path, obj)


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --- step 1: the cost of each route -----------------------------------------------------------------

def origin_spread(sessions):
    """Per route, how far apart the sessions' medians are: (largest - smallest) / median."""
    out = {}
    for klass in sessions[0]:
        values = [s[klass] for s in sessions]
        med = statistics.median(values)
        out[klass] = (max(values) - min(values)) / med if med > 0 else math.inf
    return out


def origin_widest(sessions, spread):
    """Where the sessions of a round disagree most: the route with the widest spread, the number (from 1) of the session furthest
    from that route's median, its cost and the median, in ms."""
    klass = max(spread, key=spread.get)
    values = [s[klass] for s in sessions]
    med = statistics.median(values)
    which = max(range(len(values)), key=lambda i: abs(values[i] - med))
    return klass, which + 1, values[which], med


def origin_round(sessions, timing):
    """A round as the record keeps it: the sessions' medians, how each session timed the routes (its clock and the batch of each
    route), the spread of each route and where the sessions disagree most."""
    spread = origin_spread(sessions)
    klass, number, cost, med = origin_widest(sessions, spread)
    return {"sessions": sessions, "timing": timing, "spread": spread,
            "widest": {"route": klass, "session": number, "cost_ms": cost, "median_ms": med}}


def origin_estimator():
    """How a session times the routes (origin.time_routes), for the records of the step; `version` is origin.ESTIMATOR_VERSION,
    which the later steps and the freeze require of an origin (origin_estimator_problem)."""
    return {"version": O.ESTIMATOR_VERSION, "batch_min_s": O.BATCH_MIN_S, "batch_max": O.BATCH_MAX,
            "order": "the routes in turn, one batch each, per repeat", "cost": "the median over the repeats of a batch's time per call"}


def origin_sha256():
    """The sha256 of this checkout's bench/origin.py, whose time_routes and routes the sessions run."""
    with open(os.path.join(HERE, "origin.py"), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def origin_identity(cal):
    """What makes an origin step this invocation's measurement (T-115 H-3): the estimator (origin_estimator), this checkout's
    bench/origin.py, the knobs the sessions build the origin with and the template they come from, and the step's sessions, repeats and
    CPU. origin.json records each of them; a resumed origin step keeps a complete one only when all are equal (kept_origin)."""
    return {"estimator": origin_estimator(), "origin_sha256": origin_sha256(), "knobs": dict(cal["knobs"]),
            "template_sha256": cal.get("sha256") or C.digest(cal), "sessions": ORIGIN_SESSIONS, "repeats": ORIGIN_REPEATS,
            "cpu": ORIGIN_CPU}


def _said(value):
    text = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    return text[:8] if isinstance(value, str) and len(value) == 64 else text[:60]


def kept_origin(out, cal):
    """A resumed origin step (T-115 H-3; design 6.2): R1 runs `origin` again whenever it resumes, and a pause or a host-unfit stop can
    come inside capacity, after the origin step is complete. A complete origin.json of this estimator (origin_identity) is kept as it is,
    byte for byte, so that the session's costs, which every later run's speed bracket (H1) is taken against, are measured once: returns
    its path and sha256. None when there is none: a cut step leaves no origin.json and is made again whole. CalibrationStop when the one
    there was made otherwise, or cannot be read: it is neither kept (its costs are not this estimator's) nor measured over (a complete
    step is not made again, prereg 8)."""
    path = os.path.join(out, "origin", "origin.json")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        have = json.loads(raw)
        if not isinstance(have, dict) or not isinstance(have.get("route_costs_ms"), dict) or not have["route_costs_ms"]:
            raise ValueError("no route_costs_ms")
    except ValueError as exc:
        raise CalibrationStop(f"{path} cannot be read as a complete origin step ({len(raw)} bytes, {exc}): it is neither kept nor "
                              "made again over; the user decides") from exc
    want = origin_identity(cal)
    missing = [k for k in want if k not in have]
    other = [f"{k} {_said(have[k])} (this invocation's {_said(want[k])})" for k in want if k in have and have[k] != want[k]]
    if missing or other:
        said = "; ".join(([f"it does not record {', '.join(missing)}"] if missing else []) + other)
        raise CalibrationStop(f"{path} was not made by this invocation's estimator ({said}): a complete origin step is not made again "
                              "over (prereg 8), and its costs are not this estimator's; use a new session directory")
    return path, hashlib.sha256(raw).hexdigest()


def origin_estimator_problem(origin):
    """Why the costs of an origin record cannot be used with this code, or None: they were measured with another estimator than
    this code's (origin.ESTIMATOR_VERSION), or the record does not say with which, as one made before the version was recorded
    does (HG2a's, /var/tmp/ddos_campaigns/hg2_1). The costs of two estimators differ by up to about 9 % a route, within the 25 %
    of the origin's start-up self-check, which would let a frozen record of one pass under the other without a word."""
    got = (origin.get("estimator") or {}).get("version")
    if got == O.ESTIMATOR_VERSION:
        return None
    said = "does not say which estimator measured it" if got is None else f"was measured with estimator version {got}"
    return (f"the origin step {said}, and this code's is version {O.ESTIMATOR_VERSION}: its costs are not comparable with what this "
            "code measures; make the origin step again in a new session directory")


def origin_said(rnd):
    w = rnd["widest"]
    return f"{w['route']}, session {w['session']} measured {w['cost_ms']:.4g} ms against a median of {w['median_ms']:.4g} ms"


def combine_origin(sessions):
    """The median of the sessions' medians, per route."""
    return {klass: statistics.median([s[klass] for s in sessions]) for klass in sessions[0]}


def save_stopped_origin(out, cal, rounds, partial, reason, gate=None, partial_timing=None, own_rule=False):
    """What a stopped origin step measured, which would otherwise be lost with the exception: the rounds made and the sessions of
    the round it was in (with how each timed the routes), and what the environment gate saw before them. It goes beside where
    origin.json would be, under the first free number so that a second stop does not replace the first, and origin.json itself is
    never written for a stop (docs/HG1C_DESIGN.md 27). `own_rule`: the step's own rule stopped it (StepRuleStop), which a resumed step
    reads (stopped_by_own_rule)."""
    n = 1
    while os.path.exists(os.path.join(out, "origin", f"stopped_{n}.json")):
        n += 1
    path = os.path.join(out, "origin", f"stopped_{n}.json")
    write_json(path, {"step": "origin", "stopped": reason, "created_utc": now(), "gate": gate, "rounds": rounds,
                      "partial_sessions": partial, "partial_timing": partial_timing or [], "own_rule": own_rule,
                      **origin_identity(cal)})
    return path


def stopped_by_own_rule(out):
    """The record of an earlier origin step in `out` that its own rule stopped (save_stopped_origin's own_rule), or None. A step that
    stopped so read NOT FROZEN, and is not made again by a resume (prereg 8)."""
    n = 1
    while os.path.exists(path := os.path.join(out, "origin", f"stopped_{n}.json")):
        try:
            if read_json(path).get("own_rule") is True:
                return path
        except (OSError, ValueError, AttributeError):
            pass
        n += 1
    return None


def origin_session(cal, repeats=ORIGIN_REPEATS):
    """One session in this process: every route of the origin, unloaded, timed `repeats` times in batches of at least 1 ms with
    the routes in turn (origin.time_routes): the median cost of each route in ms, the batch each route was timed in, and the
    clock, the calling thread's CPU time (time.thread_time). The origin is built with the record's knobs."""
    origin = O.Origin(C.knobs_of(cal), X.ORIGIN_SEED, "placeholder")
    try:
        return O.time_routes(origin, repeats=repeats)
    finally:
        origin.close()


def origin_step(runner, cal, cal_path, out, say=print):
    """The environment gate of a campaign's start first (`runner.quiet`: uptime and load, waiting up to the runner's
    `wait_gate_min`; a machine that does not meet it refuses the step before any session, docs/HG1C_DESIGN.md departure 28), then
    three sessions, each its own process pinned to CPU 0, and their median. If any route's medians are further apart than
    10 % the three sessions are made once more and only the second round counts; if they are still, the host's timing is not
    stable enough to calibrate on. A round says which route and which session disagreed most, and a step that stops keeps the
    sessions it measured in `origin/stopped_N.json` (never in origin.json). Both records keep what the gate saw."""
    gate = runner.quiet(say)
    host = runner.host
    rounds = []
    for number in (1, 2):
        sessions, timing = [], []
        for _ in range(ORIGIN_SESSIONS):
            r = host.run(["taskset", "-c", ORIGIN_CPU, sys.executable, os.path.abspath(__file__), "origin-session",
                          "--repeats", str(ORIGIN_REPEATS), "--calibration", cal_path], timeout=600)
            try:
                got = json.loads(r.out)
                costs = {k: float(v) for k, v in got["costs_ms"].items()}
                timed = {"clock": str(got["clock"]), "batch": {k: int(v) for k, v in got["batch"].items()}}
            except (ValueError, AttributeError, KeyError, TypeError) as exc:
                reason = f"an origin session gave nothing readable (exit {r.code}): {(r.err or r.out)[:200]}"
                path = save_stopped_origin(out, cal, rounds, sessions, reason, gate, timing)
                raise CalibrationStop(f"{reason} (the sessions read so far are in {path})") from exc
            sessions.append(costs)
            timing.append(timed)
        rnd = origin_round(sessions, timing)
        rounds.append(rnd)
        say(f"origin round {number}: widest spread {max(rnd['spread'].values()):.1%} (limit {ORIGIN_SPREAD:.0%}), {origin_said(rnd)}")
        if max(rnd["spread"].values()) <= ORIGIN_SPREAD:
            break
    else:
        reason = (f"the unloaded cost of the routes differs by more than {ORIGIN_SPREAD:.0%} between sessions, twice: "
                  "the host's timing is not stable enough to calibrate on")
        path = save_stopped_origin(out, cal, rounds, [], reason, gate, own_rule=True)
        where = "; ".join(f"round {i}: {origin_said(rnd)}" for i, rnd in enumerate(rounds, 1))
        raise StepRuleStop(f"{reason} ({where}; the sessions of both rounds are in {path})")
    result = {"step": "origin", "created_utc": now(), "gate": gate, "route_costs_ms": combine_origin(rounds[-1]["sessions"]),
              "rounds": rounds, **origin_identity(cal)}
    write_json(os.path.join(out, "origin", "origin.json"), result)
    return result


# --- step 2: the capacity ---------------------------------------------------------------------------

def capacity_levels(first=50.0, ratio=1.3, count=10):
    """The levels of the capacity probe in requests/s: 50 x 1.3^k, 50 to 530."""
    return [round(first * ratio ** k, 1) for k in range(count)]


def capacity_of(levels, q, healthy=HEALTHY_Q, saturated=SATURATED_Q, saturated_repeats=SATURATED_REPEATS):
    """C_slo and C_sat from `q`, the Q of each repeat (a row) at each level (a column): C_slo is the last level before the first
    at which any repeat is below `healthy`, C_sat the lowest at which at least `saturated_repeats` repeats are below
    `saturated`. A host for which either does not exist cannot be calibrated this way: StepRuleStop (NOT FROZEN) says why."""
    bad = [k for k in range(len(levels)) if any(row[k] < healthy for row in q)]
    if not bad:
        raise StepRuleStop(f"every level up to {levels[-1]:g} req/s keeps Q at {healthy:g} % or more: the capacity is above "
                              "the range of the probe, which has to be extended before the stack can be calibrated")
    if bad[0] == 0:
        raise StepRuleStop(f"the first level, {levels[0]:g} req/s, is already below {healthy:g} % in a repeat: the stack is "
                              "unhealthy before it is loaded, and a capacity cannot be defined on it")
    sat = [k for k in range(len(levels)) if sum(row[k] < saturated for row in q) >= saturated_repeats]
    if not sat:
        raise StepRuleStop(f"no level up to {levels[-1]:g} req/s brings Q below {saturated:g} % in {saturated_repeats} repeats: "
                              "the server is not saturated within the range, so C_sat is not known")
    return {"c_slo_rps": levels[bad[0] - 1], "c_sat_rps": levels[sat[0]], "first_unhealthy_rps": levels[bad[0]]}


def step_windows(count, step_s=STEP_S, window=Q_WINDOW):
    """The span of the run's axis that each of `count` steps is read over: the middle of the step, clear of the start-up skew
    on either side."""
    return [(k * step_s + window[0], k * step_s + window[1]) for k in range(count)]


def staged_limits(step_s, window=Q_WINDOW):
    """The clock limits of a staged run: the skew that the window leaves clear on either side of a step, that is, the nearer of the
    window's start and the step's end less the window's end (3 s for 20 s steps read over 5 to 17 s). A group that begins that far from
    its plan, or spread over that much, is read all the same, because each stream's records are placed by its own offset; the
    block's 0.5 s would reject the probe's runs on the VM (2026-10-28: later steps began 0.3 to 1.0 s late, spread over up to 2.6 s).
    A step the window does not fit in leaves nothing to relax: the executor's limits stand (docs/HG1C_DESIGN.md departure 24)."""
    skew = min(window[0], step_s - window[1])
    if skew <= X.SETTINGS["t0_spread_limit_s"]:
        return {}
    return {"t0_spread_limit_s": skew, "t0_range_limit_s": skew, "group_start_limit_s": skew}


def capacity_plan(cal, cal_path, repeat, out, levels, step_s, settings=None):
    """The plan of one repeat of the probe: the legit load stepping through `levels` in one run, as a control, judged at the
    probe's own clock limits (`staged_limits`); `settings` override them."""
    ctl = SC.load(spec_path(CONTROL_SPEC))
    seed = SEEDS["capacity"] + repeat
    pop = P.staged(ctl.seed_namespace, seed, levels, step_s, ctl.benign_identities, ctl.per_profile)
    return X.plan_population(pop, HC.STAGED_SCENARIO, "C", seed, out, cal, cal_path, pop.timeline,
                             settings={**staged_limits(step_s), **(settings or {})})


def metrics_by_step(run, cal, count, step_s):
    """The metrics of each step of a staged run over its middle window (harm_gate.run_metrics)."""
    timeline = {"baseline_s": count * step_s, "attack_s": 1.0, "recovery_s": 1.0}
    out = []
    for k, window in enumerate(step_windows(count, step_s)):
        m = H.run_metrics(run, cal, timeline, window=window)
        if m["Q"] is None:
            raise CalibrationStop(f"step {k} saw no judged request between {window[0]:g} s and {window[1]:g} s")
        out.append(m)
    return out


def stack_cost(telemetry, steps, step_s, startup_s, window=Q_WINDOW):
    """The server CPU per request through the whole stack at each step of a staged run (a diagnostic, not part of the record): the
    CPU-seconds of the origin and of Nginx in the step's window, from the 1 Hz telemetry (rows with `t_rel`, `origin_cpu_pct`,
    `nginx_cpu_pct`), over the requests of all the links in it, in ms. The runs' axis begins `startup_s` after the telemetry's
    zero. This is what the in-process cost of a route leaves out: gunicorn, Nginx and the connection between them."""
    out = []
    for k, m in enumerate(steps):
        lo, hi = startup_s + k * step_s + window[0], startup_s + k * step_s + window[1]
        rows = [r for r in telemetry if lo <= float(r["t_rel"]) < hi and r["origin_cpu_pct"] != "" and r["nginx_cpu_pct"] != ""]
        requests = sum(v["n"] for v in m["by_profile"].values())
        if not rows or not requests:
            out.append(None)
            continue
        seconds = hi - lo
        origin = statistics.mean(float(r["origin_cpu_pct"]) for r in rows) / 100.0 * seconds
        nginx = statistics.mean(float(r["nginx_cpu_pct"]) for r in rows) / 100.0 * seconds
        out.append({"requests": requests, "origin_ms_per_request": 1000.0 * origin / requests,
                    "nginx_ms_per_request": 1000.0 * nginx / requests})
    return out


def combine_stack_cost(repeats):
    """Per step, the median over the repeats of each figure; a step that no repeat could read is None."""
    out = []
    for per_step in zip(*repeats, strict=True):
        got = [x for x in per_step if x]
        out.append({k: statistics.median(x[k] for x in got) for k in got[0]} if got else None)
    return out


def read_telemetry(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def capacity_step(runner, cal, cal_path, out, levels=None, step_s=STEP_S, repeats=CAPACITY_REPEATS, say=print):
    """Three staged runs and the capacity they give. `levels` and `step_s` are for a smoke test, which cannot be frozen."""
    levels = levels or capacity_levels()
    smoke = (levels != capacity_levels()) or step_s != STEP_S or repeats != CAPACITY_REPEATS
    q, costs = [], []
    for r in range(repeats):
        plan = capacity_plan(cal, cal_path, r, os.path.join(out, "capacity", f"r{r + 1}", "C"), levels, step_s,
                             settings=runner.settings)
        runner.run(plan, say)
        steps = metrics_by_step(H.read_run(plan.out), cal, len(levels), step_s)
        q.append([m["Q"] for m in steps])
        costs.append(stack_cost(read_telemetry(os.path.join(plan.out, "server.csv")), steps, step_s,
                                plan.settings["startup_delay_legit_s"]))
    result = {"step": "capacity", "created_utc": now(), "levels_rps": levels, "step_s": step_s, "window_s": list(Q_WINDOW),
              "q_pct": q, "stack_cost": combine_stack_cost(costs), "smoke": smoke, "pins": plan.pins, "waits": runner.take_waits(),
              "template_sha256": cal.get("sha256") or C.digest(cal)}
    path = os.path.join(out, "capacity", "capacity.json")
    try:
        result.update(capacity_of(levels, q))
    except CalibrationStop as exc:
        write_json(path, {**result, "stopped": str(exc)})              # the runs stay, and the record says why they gave no capacity
        raise
    say(f"capacity: C_slo {result['c_slo_rps']:g} req/s, C_sat {result['c_sat_rps']:g} req/s")
    write_json(path, result)
    return result


# --- step 3: the screening of a family --------------------------------------------------------------

def level_flags(scn, cal, level):
    """Reasons for which a ladder level is not run: the generator would be over its limits there, and a run whose validity
    depended on the attack's effect is not a valid run (docs/HG1C_DESIGN.md 8)."""
    variant = dataclasses.replace(scn, intensity={**scn.intensity, "level": level})
    g = SC.plan(variant, cal)["generator"]
    k = g["kinds"].get("attack")
    reasons = []
    if k:
        if k["share"] > g["cpu_share_limit"]:
            reasons.append(f"the generator needs {k['share']:.0%} of its CPUs, over {g['cpu_share_limit']:.0%}")
        if k["max_stream_rate"] > g["ceiling_rps"]:
            reasons.append(f"a stream plans {k['max_stream_rate']:.0f} req/s, over the engine's ceiling of {g['ceiling_rps']}")
        if k["inflight"] >= k["cap"]:
            reasons.append(f"{k['inflight']:.0f} requests could be in flight, at or over the engine's cap of {k['cap']}")
    return reasons


def runnable_levels(scn, cal):
    """The scenario's ladder up to, not including, the first level that cannot be run, and the levels left out with the reasons.
    The ladder ends below a flagged level: nothing above it is tried."""
    levels = sorted(scn.intensity["ladder"])
    for i, level in enumerate(levels):
        reasons = level_flags(scn, cal, level)
        if reasons:
            return levels[:i], {level: reasons for level in levels[i:]}
    return levels, {}


def ladder_sequence(levels, seed_text, repeats=LADDER_REPEATS, every=CONTROL_EVERY):
    """The runs of a session in the order they are made: the attack runs (each level `repeats` times) shuffled from the seed, and
    a control after every `every`-th of them and one at the end. For seven levels that is 14 attack runs and 4 controls."""
    attacks = [("U", level, rep) for level in levels for rep in range(1, repeats + 1)]
    random.Random(seed_text).shuffle(attacks)
    out = []
    for i, run in enumerate(attacks, 1):
        out.append(run)
        if i % every == 0 or i == len(attacks):
            out.append(("C", None, len([r for r in out if r[0] == "C"]) + 1))
    return out


def harm(controls, attack, floor_pp, floor_log2):
    """The harm of an attack run against the controls of its session, so that 1 is the floor: the larger of dQ / floor_pp and
    dL / floor_log2, dQ being the controls' mean Q less the run's and dL the log2 of the run's p95 over the controls' mean
    p95 (design 7.2 step 3: the either-or rule of the gate). A figure that cannot be taken is left out; with none the harm is
    None. Returns (harm, the figures)."""
    parts = {}
    if attack["Q"] is not None:
        parts["dQ"] = (statistics.mean(c["Q"] for c in controls) - attack["Q"]) / floor_pp
    p95_c = [c["p95_s"] for c in controls if c["p95_s"]]
    if attack["p95_s"] and p95_c:
        parts["dL"] = math.log2(attack["p95_s"] / statistics.mean(p95_c)) / floor_log2
    return (max(parts.values()) if parts else None), parts


def session_problems(controls, cal):
    """Reasons for which a screening session is not valid: its controls are not all healthy, or they are not within
    CONTROL_SPREAD_PP of each other."""
    reasons = []
    if len(controls) < 2:
        return ["fewer than two controls: the session has no reference"]
    for i, m in enumerate(controls, 1):
        reasons += [f"control {i}: {r}" for r in H.control_health(m, cal)]
    qs = [m["Q"] for m in controls if m["Q"] is not None]
    if qs and max(qs) - min(qs) > CONTROL_SPREAD_PP:
        reasons.append(f"the controls' Q differ by {max(qs) - min(qs):.1f} pp, over {CONTROL_SPREAD_PP:g}")
    return reasons


def analyse_ladder(entries, cal):
    """The screening of one family from its runs: `entries` are dicts with kind ("C" or "U"), level, repeat and the run's
    metrics. Returns the controls, the harm of every attack run, the session's validity and the knee (calibration.knee at 1)."""
    controls = [e["metrics"] for e in entries if e["kind"] == "C"]
    gate = cal["gate"]
    by_level = {}
    for e in entries:
        if e["kind"] == "U":
            h, parts = harm(controls, e["metrics"], gate["floor_pp"], gate["floor_log2_p95"]) if controls else (None, {})
            by_level.setdefault(e["level"], []).append({"repeat": e["repeat"], "harm": h, "parts": parts,
                                                       "Q": e["metrics"]["Q"], "p95_s": e["metrics"]["p95_s"]})
    reasons = session_problems(controls, cal)
    ladder = [(level, [r["harm"] for r in rows if r["harm"] is not None]) for level, rows in sorted(by_level.items())]
    return {"valid": not reasons, "reasons": reasons, "controls": [{"Q": m["Q"], "p95_s": m["p95_s"]} for m in controls],
            "levels": [{"level": level, "repeats": sorted(rows, key=lambda r: r["repeat"])} for level, rows in sorted(by_level.items())],
            "knee": C.knee(ladder, 1.0, LADDER_REPEATS)}


def ladder_scenario(family, level=None):
    scn = SC.load(spec_path(FAMILY_SPECS[family]))
    return scn if level is None else dataclasses.replace(scn, intensity={**scn.intensity, "level": level})


INVALID_ASIDE = ".invalid1"                 # where a session that is not valid goes before it is made once more (K1, 8.3)


def ladder_step(runner, cal, cal_path, family, out, under, levels=None, timeline=None, say=print):
    """The screening of one family on the unprotected stack at rho (design 7.2 step 3). `cal` is the record with the session's
    measured costs and capacity, so that rho and S are the calibration's own; `under` says what it was made of (under_of).
    `levels` and `timeline` are for a smoke test, which cannot be frozen. A session that is not valid is moved aside as
    `ladder_<family>.invalid1` and made once more in a new directory; a second one that is not valid is the step's end, and the
    calibration is NOT FROZEN (docs/RECALIBRATION_2026-11_DESIGN.md 8.3, K1): StepRuleStop, exit 7 (before T-116 K18 it returned the
    result and the command exited 3). Both stay, and the freeze reads `ladder_<family>`."""
    base = os.path.join(out, f"ladder_{family}")
    aside, prior = base + INVALID_ASIDE, os.path.join(base, "ladder.json")
    if os.path.exists(prior) and not read_json(prior)["valid"]:          # an earlier call ended on a session that is not valid
        if os.path.exists(aside):
            raise StepRuleStop(f"the screening of {family} was not valid twice ({aside} and {base}): the calibration is NOT "
                                  "FROZEN (docs/RECALIBRATION_2026-11_DESIGN.md 8.3); nothing is made a third time")
        os.rename(base, aside)
        say(f"ladder {family}: the session that was not valid is kept as {os.path.basename(aside)}; making it once more")
    result = ladder_session(runner, cal, cal_path, family, out, under, levels, timeline, say)
    if result["valid"]:
        return result
    if not os.path.exists(aside):
        os.rename(base, aside)
        say(f"ladder {family}: the session is kept as {os.path.basename(aside)} and made once more in a new directory")
        result = ladder_session(runner, cal, cal_path, family, out, under, levels, timeline, say)
        if result["valid"]:
            return result
    say(f"ladder {family}: the second session is not valid either: the calibration is NOT FROZEN (8.3)")
    raise StepRuleStop(f"the screening of {family} was not valid twice ({aside} and {base}): the calibration is NOT FROZEN "
                       "(docs/RECALIBRATION_2026-11_DESIGN.md 8.3); nothing is made a third time")


def ladder_session(runner, cal, cal_path, family, out, under, levels=None, timeline=None, say=print):
    """One session of the screening of `family` in `ladder_<family>` (ladder_step makes it, and once more if it is not valid)."""
    if family not in FAMILY_SPECS:
        raise CalibrationStop(f"family: one of {', '.join(FAMILY_SPECS)}, got {family!r}")
    scn = ladder_scenario(family)
    usable, left_out = runnable_levels(scn, cal)
    if not usable:                              # the ladder's own levels: the step's rule (NOT FROZEN)
        raise StepRuleStop(f"no level of {family} can be run within the generator's limits: {left_out}")
    if levels is not None:                      # a smoke test's --levels: a usage error when none is one of them (T-117 L-7)
        chosen = [lvl for lvl in sorted(levels) if lvl in usable]
        if not chosen:
            raise CalibrationStop(f"--levels {', '.join(f'{lvl:g}' for lvl in sorted(levels))}: none is a level of {family}'s ladder "
                                  f"that the generator can carry ({', '.join(f'{lvl:g}' for lvl in usable)}): a smoke test takes "
                                  "the ladder's own levels")
        usable = chosen
    seed = SEEDS["ladder"] + sorted(FAMILY_SPECS).index(family)
    sequence = ladder_sequence(usable, f"{family}|{seed}")
    base = os.path.join(out, f"ladder_{family}")
    entries = []
    for i, (kind, level, repeat) in enumerate(sequence, 1):
        label = f"{i:02d}_" + (f"L{level:g}_r{repeat}" if kind == "U" else f"control{repeat}")
        variant = ladder_scenario(family, level if level is not None else scn.intensity["level"])
        plan = X.plan_run(variant, cal, kind, seed, os.path.join(base, label, kind), cal_path, "", settings=runner.settings,
                          timeline=timeline)
        runner.run(plan, say)
        t = plan.timeline
        metrics = H.run_metrics(H.read_run(plan.out), cal, {k: t[k] for k in ("baseline_s", "attack_s", "recovery_s")})
        entries.append({"kind": kind, "level": level, "repeat": repeat, "run": label, "metrics": metrics})
    result = {"step": "ladder", "family": family, "created_utc": now(), "seed": seed, "sequence": [list(s) for s in sequence],
              "levels_run": usable, "levels_left_out": {str(k): v for k, v in left_out.items()},
              "smoke": levels is not None or timeline is not None, "under": under, "pins": plan.pins, "waits": runner.take_waits()}
    result.update(analyse_ladder(entries, cal))
    say(f"ladder {family}: " + ("session valid" if result["valid"] else "session NOT valid: " + "; ".join(result["reasons"]))
        + f"; knee {result['knee']['level']}")
    write_json(os.path.join(base, "ladder.json"), result)
    return result


# --- step 5: the reference of the drift check -------------------------------------------------------

def probe_plan(cal, cal_path, label, seed, out, settings=None):
    """The plan of a legit probe: 120 s of the benign load at rho, as a control."""
    ctl = SC.load(spec_path(CONTROL_SPEC))
    pop = P.draw(ctl.seed_namespace, seed, C.rho_rps(cal), ctl.benign_identities, None, P.Timeline(PROBE_S, 0.0, 0.0), ctl.per_profile)
    return X.plan_population(pop, label, "C", seed, out, cal, cal_path, pop.timeline, settings=settings)


def probe_metrics(run, cal):
    """Q and p95 of a legit probe over its window, which leaves the start-up out."""
    m = H.run_metrics(run, cal, {"baseline_s": PROBE_S, "attack_s": 1.0, "recovery_s": 1.0}, window=PROBE_WINDOW)
    return {"Q": m["Q"], "p95_s": m["p95_s"], "requests": m["requests"]}


def attack_metrics(plan, cal):
    t = plan.timeline
    m = H.run_metrics(H.read_run(plan.out), cal, {k: t[k] for k in ("baseline_s", "attack_s", "recovery_s")})
    return {"Q": m["Q"], "p95_s": m["p95_s"], "requests": m["requests"]}


def reference_of(rho_rps, legit, attacks):
    """The drift reference of schema 1, as the record of 2026-11-04 has it (made by this code until K1): the median Q and p95 of the
    legit probes at rho, and for each family with a knee the Q and p95 of one attack run at it. `attacks` maps a family to {"level",
    "Q", "p95_s"}. A new reference is schema 2's (reference_step, calibration.drift_reference_of)."""
    return {"rho_rps": rho_rps, "q_pct": statistics.median(m["Q"] for m in legit),
            "p95_s": statistics.median(m["p95_s"] for m in legit),
            "attack": {f: {"level": a["level"], "q_pct": a["Q"], "p95_s": a["p95_s"]} for f, a in sorted(attacks.items())}}


def attack_run(runner, cal, cal_path, family, level, seed, out, timeline=None, say=print):
    """One attack run of `family` at `level` and its Q and p95 over the attack's window."""
    plan = X.plan_run(ladder_scenario(family, level), cal, "U", seed, os.path.join(out, "U"), cal_path, "",
                      settings=runner.settings, timeline=timeline)
    runner.run(plan, say)
    return attack_metrics(plan, cal)


def reference_round_dir(out, r):
    return os.path.join(out, "reference", f"r{r}")


def reference_step(runner, draft, cal_path, knees, out, under, timeline=None, say=print, rounds=N_REF):
    """The reference the drift check must reproduce (docs/RECALIBRATION_2026-11_DESIGN.md 4, K1): N_REF rounds, each the legit probe
    at rho and one attack run per family at its knee in sorted order, on the drift check's own seeds (calibration.drift_seeds), with the
    measured record `draft` (its rho is the one the calibration will have) and what it was made of (`under`, as the screenings'). Every
    run is kept and listed; the freeze takes the means, SDs and tolerances from them. `rounds` fewer than N_REF is a smoke test's."""
    families = [f for f, k in sorted(knees.items()) if k is not None]
    seeds = C.drift_seeds(families)
    rows, plan = [], None
    for r in range(1, rounds + 1):
        base = reference_round_dir(out, r)
        plan = probe_plan(draft, cal_path, "reference_legit", seeds["legit"], os.path.join(base, "legit", "C"), runner.settings)
        runner.run(plan, say)
        legit = {**probe_metrics(H.read_run(plan.out), draft), "seed": seeds["legit"], "run": os.path.relpath(plan.out, out)}
        attacks = {}
        for family in families:
            where = os.path.join(base, f"attack_{family}")
            m = attack_run(runner, draft, cal_path, family, knees[family], seeds["attack"][family], where, timeline, say)
            attacks[family] = {"level": knees[family], **m, "seed": seeds["attack"][family],
                               "run": os.path.relpath(os.path.join(where, "U"), out)}
        rows.append({"round": r, "legit": legit, "attacks": attacks})
    result = {"step": "reference", "created_utc": now(), "rho_rps": C.rho_rps(draft), "rounds": rows, "seeds": seeds,
              "knees": {f: knees[f] for f in families}, "smoke": timeline is not None or rounds != N_REF, "under": under,
              "pins": plan.pins if plan else None, "waits": runner.take_waits()}
    missing = [f"round {row['round']} {name}" for row in rows for name, m in (("legit", row["legit"]), *row["attacks"].items())
               if m["Q"] is None or m["p95_s"] is None]
    if missing:
        result["stopped"] = f"no judged request or no successful one in {', '.join(missing)}: they cannot be a reference"
    write_json(os.path.join(out, "reference", "reference.json"), result)
    if missing:
        raise StepRuleStop("a reference run had no judged request or no successful one: it cannot be a reference "
                              f"({', '.join(missing)})")
    return result


def reference_of_rounds(reference, gate):
    """The drift reference of schema 2 from reference.json: the first N_REF rounds (calibration.drift_reference_of). CalibrationStop
    when there are fewer than N_REF complete rounds."""
    rows = [row for row in reference.get("rounds") or [] if row["legit"].get("Q") is not None]
    complete = [row for row in rows if set(row["attacks"]) == set(reference["knees"])]
    if len(complete) < N_REF:
        raise CalibrationStop(f"the reference has {len(complete)} complete rounds, and a freeze needs {N_REF} "
                              "(docs/RECALIBRATION_2026-11_DESIGN.md 4): nothing is frozen from fewer")
    sample = complete[:N_REF]
    try:
        return C.drift_reference_of(reference["rho_rps"], [row["legit"] for row in sample],
                                    {f: {"level": level, "runs": [row["attacks"][f] for row in sample]}
                                     for f, level in reference["knees"].items()}, gate)
    except ValueError as exc:
        raise CalibrationStop(str(exc)) from exc


# --- the record -------------------------------------------------------------------------------------

def draft_record(template, origin=None, capacity=None, knees=None):
    """The template (a placeholder) with what has been measured so far; still a placeholder, and the origin's
    knobs and the gate's constants are the template's."""
    cal = copy.deepcopy(template)
    cal["status"] = "placeholder"
    cal.pop("sha256", None)
    if origin:
        cal["route_costs_ms"] = {k: float(v) for k, v in origin["route_costs_ms"].items()}
    if capacity:
        cal["capacity"] = {"c_slo_rps": capacity["c_slo_rps"], "c_sat_rps": capacity["c_sat_rps"]}
    if knees is not None:
        cal["knees"] = dict(knees)
    return cal


def under_of(template, origin, capacity):
    """What the screenings and the reference run under: the template and the session's measured costs and capacity. The freeze
    checks that they all ran under the ones it freezes."""
    return {"template_sha256": template.get("sha256") or C.digest(template),
            "route_costs_ms": {k: float(v) for k, v in sorted(origin["route_costs_ms"].items())},
            "capacity": {"c_slo_rps": capacity["c_slo_rps"], "c_sat_rps": capacity["c_sat_rps"]}}


def session_draft(directory, template):
    """The template with the origin and the capacity that the session in `directory` has measured, and what that is made of.
    Steps 1 and 2 must have been made, the origin with this code's estimator."""
    parts = []
    for step in ("origin", "capacity"):
        path = os.path.join(directory, step, step + ".json")
        if not os.path.exists(path):
            raise CalibrationStop(f"{directory}: no {step} step ({path}): the steps are made in order")
        parts.append(read_json(path))
    origin, capacity = parts
    why = origin_estimator_problem(origin)
    if why:
        raise CalibrationStop(why)
    if capacity.get("stopped"):
        raise CalibrationStop(f"the capacity step stopped: {capacity['stopped']}")
    if capacity.get("smoke"):
        raise CalibrationStop("the capacity step was a smoke test: its numbers are not a calibration's")
    if capacity.get("pins") != P.PIN_PLAN:
        raise CalibrationStop(f"the capacity step was made with {said_pins(capacity.get('pins'))}, and the next steps run with "
                              f"{said_pins(P.PIN_PLAN)}: a calibration mixes no two layouts. Use another session directory.")
    return draft_record(template, origin, capacity), under_of(template, origin, capacity)


def _version(text):
    m = re.search(r"\d+(?:\.\d+)+", text or "")
    if not m:
        raise CalibrationStop(f"no version number in {text!r}")
    return m.group(0)


def host_of(env, pins):
    """The frozen record's `host` from the environment.json of one of the runs (design 4.2) and the pin plan the session's runs were
    made with (`pins`, as its steps recorded it; not this code's plan, which may be another by now): what the numbers were measured on,
    the PC too (its CPU model and VirtualBox host version, K10), which a run's environment.json must name."""
    facts, prov, stack = env["facts"], env["provenance"], env.get("stack") or {}
    limits = ((stack.get("origin") or {}).get("nofile_soft_hard") or [[None]])[0]
    if not isinstance(limits[0], int):
        raise CalibrationStop("the origin's open-file limit was not read as a number: environment.json has no stack record")
    unnamed = C.pc_unnamed(facts)
    if unnamed:
        raise CalibrationStop(f"environment.json does not name the PC the runs were made on ({', '.join(unnamed)}): a record names "
                              "its PC (K10)")
    return {"uname": facts["uname"], "cpus": facts["cpus"], "mem_mib": facts["mem_mib"],
            **{key: facts[key] for key in C.PC_KEYS}, "origin_seed": X.ORIGIN_SEED,
            "origin_sha256": prov["files"]["origin.py"], "loadgen_sha256": prov["files"]["loadgen.py"], "pins": dict(pins),
            "gunicorn": {"version": _version(facts["gunicorn"]), "workers": X.GUNICORN["workers"],
                         "threads": X.GUNICORN["threads"], "nofile": limits[0]},
            "nginx": {"version": _version(facts["nginx"]), "conf_sha256": prov["nginx_source_sha256"]}}


def read_session(directory):
    """What the steps left in `directory`, for freeze: the origin, the capacity, one screening per family and the reference."""
    got = {"origin": read_json(os.path.join(directory, "origin", "origin.json")),
           "capacity": read_json(os.path.join(directory, "capacity", "capacity.json")),
           "ladders": {f: read_json(os.path.join(directory, f"ladder_{f}", "ladder.json")) for f in FAMILY_SPECS},
           "reference": read_json(os.path.join(directory, "reference", "reference.json"))}
    return got


def freeze_problems(session, template):
    """Reasons for which `session` cannot be frozen: an origin measured with another estimator, a smoke step, a screening that is
    not valid, steps made under another template or other measured costs and capacity, or a reference that was taken for another
    set of knees."""
    defects, rules = freeze_problem_classes(session, template)
    return defects + rules


def freeze_problem_classes(session, template):
    """freeze_problems in two lists: what says the session was made wrongly or mixed (a defect, or a step started out of order: no
    reading), and what a step's own rule decided (a screening not valid twice, a reference that stopped by its rule: NOT FROZEN)."""
    reasons = [why] if (why := origin_estimator_problem(session["origin"])) else []
    under = under_of(template, session["origin"], session["capacity"])
    named = (("origin", session["origin"]), ("capacity", session["capacity"]), ("reference", session["reference"]),
             *[(f"ladder {f}", ladder) for f, ladder in session["ladders"].items()])
    for name, step in named:
        if step.get("smoke"):
            reasons.append(f"{name} is a smoke test (levels, steps or timeline changed): a smoke test is not a calibration")
        if name != "origin" and (not step.get("pins") or step["pins"] != session["capacity"].get("pins")):
            reasons.append(f"{name} was made with {said_pins(step.get('pins'))}, not the pin plan of the capacity step: "
                           "a calibration mixes no two layouts")
        if name in ("origin", "capacity") and step["template_sha256"] != under["template_sha256"]:
            reasons.append(f"{name} was made under another template")
        if name not in ("origin", "capacity") and step["under"] != under:
            reasons.append(f"{name} was made under other measured costs or capacity than the ones being frozen")
    rules = []
    for f, ladder in session["ladders"].items():
        if not ladder["valid"]:
            rules.append(f"the screening of {f} is not valid: " + "; ".join(ladder["reasons"]))
    knees = {f: ladder["knee"]["level"] for f, ladder in session["ladders"].items()}
    taken = session["reference"].get("knees") or {}
    if {f: k for f, k in knees.items() if k is not None} != taken:
        reasons.append("the reference's attack runs are not at the knees of the screenings")
    if session["reference"].get("stopped"):
        rules.append(f"the reference stopped: {session['reference']['stopped']}")
    return reasons, rules


def no_knee_text(directory, ladders):
    """What freeze says when no family has a knee (T-105 F7): the design's finding "cannot harm this server within the generator
    limit" (7.2 step 4, 8.3) for every family, reported from the screenings, and why no record is frozen from it."""
    said = "; ".join(f"{f}: no level up to {max(ladder.get('levels_run') or [0]):g} passed "
                     f"({os.path.join(directory, f'ladder_{f}', 'ladder.json')})" for f, ladder in sorted(ladders.items()))
    return ("no family has a knee: every family cannot harm this server within the generator limit (design 7.2 step 4), a finding "
            f"of the screenings, reported from them ({said}). No record is frozen: its drift check would have no family to "
            "confirm (a drift reference of schema 2 needs one)")


def freeze_step(directory, template, env, created_utc=None):
    """The frozen record from a session's directories: the template with the measured costs, capacity, knees, drift reference
    and host. Reads and writes nothing; calibration.freeze checks the result."""
    session = read_session(directory)
    defects, rules = freeze_problem_classes(session, template)
    if defects or rules:                        # a defect beside a rule's reason is no reading: the user looks first (T-115 H-1)
        raise (CalibrationStop if defects else StepRuleStop)("cannot freeze: " + "; ".join(defects + rules))
    knees = {f: ladder["knee"]["level"] for f, ladder in session["ladders"].items()}
    if all(k is None for k in knees.values()):
        raise StepRuleStop(no_knee_text(directory, session["ladders"]))
    draft = draft_record(template, session["origin"], session["capacity"], knees)
    if session["reference"]["rho_rps"] != C.rho_rps(draft):
        raise CalibrationStop(f"the reference was taken at rho {session['reference']['rho_rps']:g}, the capacity gives "
                              f"{C.rho_rps(draft):g}")
    draft["schema"] = C.SCHEMA                  # schema 2: the multi-run reference (docs/RECALIBRATION_2026-11_DESIGN.md K1)
    return C.freeze(draft, created_utc or now(), host=host_of(env, session["capacity"]["pins"]),
                    drift_reference=reference_of_rounds(session["reference"], draft["gate"]))


# --- step 7: drift ----------------------------------------------------------------------------------

def drift_check(cal, legit, attacks):
    """The drift of a new probe against the frozen reference: the legit probe by calibration.drift_ok, each attack run by
    calibration.drift_attack_ok with the record's own floors (docs/HG1C_DESIGN.md departure 33, D-062)."""
    ref = cal["drift_reference"]
    reasons = [f"legit probe: {r}" for r in C.drift_ok(ref["q_pct"], ref["p95_s"], legit["Q"], legit["p95_s"])[1]]
    for family, m in sorted(attacks.items()):
        why = C.drift_attack_ok(cal["gate"], ref["attack"][family]["q_pct"], ref["attack"][family]["p95_s"], m["Q"], m["p95_s"])[1]
        reasons += [f"{family}: {r}" for r in why]
    return {"ok": not reasons, "reasons": reasons}


def drift_step(runner, cal, cal_path, out, families=None, timeline=None, say=print):
    """The drift check of a frozen record, by the rule of its schema: on means for schema 2 (drift_step_means), the single-run check of
    departure 33 for schema 1 (drift_step_single), which the record of 2026-11-04 keeps."""
    if cal["status"] != "frozen":
        raise CalibrationStop("a drift check needs a frozen calibration")
    if cal.get("schema") == 1:
        return drift_step_single(runner, cal, cal_path, out, families, timeline, say)
    return drift_step_means(runner, cal, cal_path, out, families, timeline, say)


def drift_round_dir(out, r):
    return os.path.join(out, "drift", f"r{r}")


def drift_step_means(runner, cal, cal_path, out, families=None, timeline=None, say=print, rounds=M_DRIFT):
    """M_DRIFT rounds, each the legit probe at rho and one attack run per family at its knee on the drift check's own seeds (the
    reference's), judged on means against the record's reference of schema 2 (calibration.drift_means_check; docs/RECALIBRATION_2026-11
    _DESIGN.md 4, K2): read per family, no second attempt. `families` defaults to every family with a reference. A cut check resumes
    with its finished runs (Runner.run); drift.json lists each comparison with its numbers and the runs in the sample."""
    ref = cal["drift_reference"]
    families = sorted(families or ref["attack"])
    for family in families:
        if family not in ref["attack"]:
            raise CalibrationStop(f"the frozen record has no attack reference for {family}")
    seeds = C.drift_seeds(families)
    rows = []
    for r in range(1, rounds + 1):
        base = drift_round_dir(out, r)
        plan = probe_plan(cal, cal_path, "drift_legit", seeds["legit"], os.path.join(base, "legit", "C"), runner.settings)
        runner.run(plan, say)
        legit = {**probe_metrics(H.read_run(plan.out), cal), "seed": seeds["legit"], "run": os.path.relpath(plan.out, out)}
        attacks = {}
        for family in families:
            level, where = ref["attack"][family]["level"], os.path.join(base, f"attack_{family}")
            attacks[family] = {"level": level, **attack_run(runner, cal, cal_path, family, level, seeds["attack"][family], where,
                                                            timeline, say),
                               "seed": seeds["attack"][family], "run": os.path.relpath(os.path.join(where, "U"), out)}
        rows.append({"round": r, "legit": legit, "attacks": attacks})
    result = {"step": "drift", "schema": 2, "created_utc": now(), "calibration_sha256": cal["sha256"], "families": families,
              "rounds": rows, "waits": runner.take_waits(), "smoke": timeline is not None or rounds != M_DRIFT,
              **judge_rounds(cal, rows, families)}
    for family in families:
        row = result["check"]["families"][family]
        say(f"drift {family}: " + ("confirmed" if result["confirmed"][family] else "NOT confirmed: " + "; ".join(
            result["check"]["legit"]["reasons"] + row["reasons"])) + (" (wide spread at its knee, D6)" if row["wide_spread"] else ""))
    say("drift: " + ("within the frozen reference" if result["ok"] else "OUT of it: " + "; ".join(result["reasons"])))
    write_json(os.path.join(out, "drift", "drift.json"), result)
    return result


def judge_rounds(cal, rows, families):
    """The check on means of `rows` (the rounds as drift.json lists them) against `cal`'s reference: the comparisons, the reading per
    family, ok (every family confirmed) and the reasons."""
    check = C.drift_means_check(cal["drift_reference"], [row["legit"] for row in rows],
                                {f: [row["attacks"][f] for row in rows] for f in families})
    reasons = [f"legit probe: {r}" for r in check["legit"]["reasons"]]
    reasons += [f"{f}: {r}" for f in families for r in check["families"][f]["reasons"]]
    ok = check["legit"]["ok"] and bool(check["confirmed"]) and all(check["confirmed"].values())     # no family confirms nothing (F7)
    return {"check": check, "confirmed": check["confirmed"], "ok": ok, "reasons": reasons}


def judge_drift(cal, recorded):
    """A recorded drift.json judged again by the rule of its record's schema: schema 1 by the single-run check (drift_check, departure
    33), which the five published attempts of 2026-11-08 to 11 were judged under; schema 2 on means. Returns ok and the reasons (and
    for schema 2 the comparisons and the reading per family)."""
    if cal.get("schema") == 1:
        attacks = {f: {"Q": m["Q"], "p95_s": m["p95_s"]} for f, m in recorded["attacks"].items()}
        return drift_check(cal, {"Q": recorded["legit"]["Q"], "p95_s": recorded["legit"]["p95_s"]}, attacks)
    return judge_rounds(cal, recorded["rounds"], recorded["families"])


def drift_step_single(runner, cal, cal_path, out, families=None, timeline=None, say=print):
    """A legit probe at rho and an attack run at a family's knee against the frozen record's reference of schema 1, as before K2.
    `families` defaults to the first family that has one."""
    ref = cal["drift_reference"]
    families = families or sorted(ref["attack"])[:1]
    plan = probe_plan(cal, cal_path, "drift_legit", SEEDS["drift"], os.path.join(out, "drift", "legit", "C"), runner.settings)
    runner.run(plan, say)
    legit = probe_metrics(H.read_run(plan.out), cal)
    attacks = {}
    for i, family in enumerate(families):
        if family not in ref["attack"]:
            raise CalibrationStop(f"the frozen record has no attack reference for {family}")
        attacks[family] = {"level": ref["attack"][family]["level"],
                           **attack_run(runner, cal, cal_path, family, ref["attack"][family]["level"], SEEDS["drift"] + 1 + i,
                                        os.path.join(out, "drift", f"attack_{family}"), timeline, say)}
    result = {"step": "drift", "created_utc": now(), "calibration_sha256": cal["sha256"], "legit": legit, "attacks": attacks,
              "waits": runner.take_waits(),
              "smoke": timeline is not None, **drift_check(cal, legit, attacks)}
    say("drift: " + ("within the frozen reference" if result["ok"] else "OUT of it: " + "; ".join(result["reasons"])))
    write_json(os.path.join(out, "drift", "drift.json"), result)
    return result


# --- running the plans ------------------------------------------------------------------------------

def said_pins(pins):
    """A pin plan as a refusal says it. A record without one was made before runs and steps recorded theirs, perhaps under D14's first
    plan (`population.PIN_PLAN_BEFORE_D032`), and is read as that, as `gate_campaign.load_state` reads a campaign's."""
    if pins:
        return GC.pins_text(dict(sorted(pins.items())))         # a record's keys are sorted on disk: both sides of a refusal read alike
    return f"no pin plan on record, read as the plan of before 2026-10-31 (D-032), {GC.pins_text(P.PIN_PLAN_BEFORE_D032)}"


def done_with_other_pins(plan):
    """Why the finished run in `plan.out` may not stand in for `plan`: its plan.json has another pin plan, or says none. None if it may."""
    try:
        made_with = read_json(os.path.join(plan.out, "plan.json")).get("pins")
    except (OSError, ValueError):
        made_with = None
    if made_with == plan.pins:
        return None
    return (f"{plan.out} is finished, but it was made with {said_pins(made_with)}, and this step runs with "
            f"{said_pins(plan.pins)}: a calibration mixes no two layouts. Use another session directory.")


def first_free(base, suffix):
    """`<base><suffix><k>` for the first k from 1 that is not there (as hostcheck.HostCheck.set_aside numbers its runs)."""
    k = 1
    while os.path.exists(f"{base}{suffix}{k}"):
        k += 1
    return f"{base}{suffix}{k}"


class Runner:
    """Carries out plans through the executor for the steps of a calibration. The first run of the process waits for the full
    environment gate, the others for the timer; a run that is found unsound, or fails in its timeline, is made once more in its
    place and a second time stops the calibration; the executor's refusals stop it at once. Each unsound attempt goes aside as
    `<run>.failed<k>`, the first free k, the last one too (T-115 M-6): a resume after an earlier packet's stop finds .failed1 there,
    and the fixed name crashed on it (OSError 39), while the last attempt, left in place, was removed as an unfinished run. The count
    of attempts is this call's: a resumed step gives the run two attempts again, and every .failed<k> stays. A run that is done is not
    made again, so that a step resumes, unless it was made with another pin plan: that refuses (docs/HG1C_DESIGN.md departure 31)."""

    def __init__(self, host, settings=None, allow_dirty=False, clean=False, wait_gate_min=30.0, tries=2, speed=None, check=None,
                 stop_after_min=None):
        self.host, self.settings = host, dict(settings or {})
        self.stop_after_min = stop_after_min    # --stop-after: no run starts once this many minutes have passed since now (K6)
        self.deadline = None if stop_after_min is None else host.monotonic() + 60.0 * stop_after_min
        self.allow_dirty, self.clean, self.wait_gate_min, self.tries = allow_dirty, clean, wait_gate_min, tries
        self.check = check                      # a hostcheck.HostCheck: H1 and H3-H7 after every run it makes (K4); None judges none
        self.speed = check.speed if check else speed     # a hostcheck.SpeedBracket: H1 around every run (K3); None makes none
        self.gate = "full"
        self.waits = {}

    def remember(self, plan, record):
        """A finished run's wait for the step's summary, with what its earlier stops cost (kept beside it). Returns the record."""
        parent, name = os.path.split(plan.out)
        self.waits[os.sep.join(plan.out.split(os.sep)[-3:])] = {"refused_probes": record.get("timer_refused_probes") or 0,
                                                                "waited_s": record.get("timer_waited_s") or 0.0,
                                                                "earlier": H.earlier_waits(parent, name)}
        return record

    def take_waits(self):
        """What the timer gate cost the runs since the last call, for a step's record: recorded, not judged (docs/HG1C_DESIGN.md
        departure 32). The totals include the earlier stops; the runs that waited are named."""
        waits, self.waits = self.waits, {}
        every = [e for w in waits.values() for e in [w, *w["earlier"]]]
        return {"runs": len(waits), "refused_probes": sum(e["refused_probes"] or 0 for e in every),
                "waited_s": round(sum(e["waited_s"] or 0 for e in every), 1),
                "waited": {k: w for k, w in waits.items() if w["refused_probes"] or w["earlier"]}}

    def quiet(self, say=print):
        """The full gate's uptime and load without a run (executor.quiet_gate, the code a campaign's first run takes it through):
        waits up to `wait_gate_min` minutes, from --wait-gate, and refuses with EnvironmentRefused. For the origin step, whose
        sessions measure the host as a run does but are not one; the timer of the legit streams' CPU, which only streams need, is
        not probed. Returns what was seen."""
        return X.quiet_gate(self.host, self.wait_gate_min, say)

    def run(self, plan, say=print):
        record = GC.read_done(plan.out, say)
        if record is not None:
            why = done_with_other_pins(plan)
            if why:
                raise CalibrationStop(why)
            return self.remember(plan, record)
        GC.check_budget(self.host, self.deadline, self.stop_after_min)
        if self.check:
            self.check.start()
        reasons, attempt = [], 1
        while attempt <= self.tries:
            if os.path.exists(plan.out):
                if reasons:                      # an attempt of this call failed: it stays beside the run as evidence (T-115 M-6)
                    os.rename(plan.out, first_free(plan.out, ".failed"))
                else:                            # an unfinished run of an earlier call: what its gate saw stays beside it
                    kept = GC.keep_unfinished(os.path.dirname(plan.out), os.path.basename(plan.out), plan.out)
                    say(f"{os.sep.join(plan.out.split(os.sep)[-3:])}: removing the unfinished run{kept}")
                    shutil.rmtree(plan.out)
            say(f"{os.sep.join(plan.out.split(os.sep)[-3:])}: attempt {attempt}")
            hook = {"before_stack": self.speed.before} if self.speed else {}
            try:
                result = X.execute(plan, self.host, self.gate, self.allow_dirty, self.clean, self.wait_gate_min, say, **hook)
            except GC.STOP_ERRORS:
                raise
            except X.RunFailed as exc:
                reasons = [str(exc)]
            else:
                if result.ok:
                    self.gate = "timer"
                    record = GC.run_record(result)
                    if self.speed:
                        record["speed"] = self.bracket_done(plan, say)
                    if self.check:
                        record["host"] = self.check.judge(plan.out, record["speed"],      # H3 not on a staged run (D-099)
                                                          staged=plan.scenario == HC.STAGED_SCENARIO)
                        if not record["host"]["ok"]:            # set aside, held, made again: it uses none of the tries (5.1)
                            self.check.set_aside(plan.out, {**record, "finished_utc": now()}, say)
                            reasons = []
                            GC.check_budget(self.host, self.deadline, self.stop_after_min)     # a remake is a run like any other
                            continue
                        self.check.valid()
                    GC.mark_done(plan.out, record)
                    return self.remember(plan, GC.read_done(plan.out))
                reasons = result.reasons
            self.gate = "timer"
            attempt += 1
        kept = ""
        if os.path.exists(plan.out):            # the last attempt is evidence too: a resume would remove it as an unfinished run
            aside = first_free(plan.out, ".failed")
            os.rename(plan.out, aside)
            kept = f"; the last is kept as {os.path.basename(aside)}"
        raise RunUnsoundTwice(f"{plan.out}: the run was not sound in {self.tries} attempts ({'; '.join(reasons)[:300]}){kept}; "
                              "a calibration made of runs that are not valid is not one")

    def close(self):
        """The monitors stop (a step's end, a stop, an interrupt)."""
        if self.check:
            self.check.close()

    def bracket_done(self, plan, say=print):
        """The speed bracket's second probe, after the run's teardown, and H1's verdict (hostcheck.SpeedBracket.finish), kept in
        run.json beside the run's other records and returned for DONE."""
        speed = self.speed.finish(self.host, plan.out)
        path = os.path.join(plan.out, "run.json")
        write_json(path, {**read_json(path), "speed": speed})
        d = [("?" if x is None else f"{x:+.1%}") for x in (speed["d_before"], speed["d_after"])]
        say(f"{os.sep.join(plan.out.split(os.sep)[-3:])}: speed bracket {d[0]} before, {d[1]} after: "
            + ("within H1" if speed["ok"] else "HOST-INVALID: " + "; ".join(speed["reasons"])))
        return speed


# --- the command line -------------------------------------------------------------------------------

SESSION_HOST = "host.json"


def session_host(directory, host, step):
    """A calibration session is made on one host (K5, as departure 31 for pins) and on one PC (K10, D-096): the first step to run in
    `directory` records the kernel release, MemTotal, the CPU model and VirtualBox's host version in host.json (and refuses when it
    cannot read the PC: the record it leads to must name it), and a later step on a host with another kernel, a MemTotal more than 1 %
    away, another CPU model or another VirtualBox host version refuses before any run."""
    facts = host.facts()
    path = os.path.join(directory, SESSION_HOST)
    if not os.path.exists(path):
        unread = C.pc_unnamed(facts)
        if unread:
            raise CalibrationStop(f"{directory}: this host's PC cannot be read ({', '.join(unread)}): a session names its PC in its "
                                  "first step (K10); it stops here")
        write_json(path, {"uname": facts["uname"], "kernel": C.kernel_release(facts["uname"]), "mem_mib": facts["mem_mib"],
                          **{key: facts[key] for key in C.PC_KEYS}, "first_step": step, "created_utc": now()})
        return
    first = read_json(path)
    problems = C.host_problems(first, facts, f"the session's first step ({first['first_step']})")
    if problems:
        raise CalibrationStop(f"{directory}: this host is not the one the session began on: " + "; ".join(problems)
                              + ". A calibration is made on one host and one PC (docs/RECALIBRATION_2026-11_DESIGN.md D2, K5; K10): it "
                              "stops here")


def host_check(host, speed, out, cal):
    """H1 and H3-H7 for the runs of this invocation (K4): the monitors on the executor's CPU (the daemon's in the calibration's pin plan,
    which _host_for pins the executor to), their records in `out`/monitors/<n>, the slip limit of the record's validity block."""
    base = os.path.join(out, "monitors")
    n = 1
    while os.path.exists(os.path.join(base, str(n))):
        n += 1
    return HC.HostCheck(host, speed, os.path.join(base, str(n)), P.PIN_PLAN["daemon"], cal["validity"]["slip_pooled_s"])


def session_speed(directory, cal_path):
    """The speed bracket of a calibration session's runs (H1, K3): against the costs its own origin step measured, which must exist and
    be of this code's estimator; the probe takes the template's knobs."""
    path = os.path.join(directory, "origin", "origin.json")
    if not os.path.exists(path):
        raise CalibrationStop(f"{directory}: no origin step ({path}): the steps are made in order, and every run's speed bracket is "
                              "taken against the session's own route costs")
    origin = read_json(path)
    why = origin_estimator_problem(origin)
    if why:
        raise CalibrationStop(why)
    return HC.SpeedBracket(cal_path, origin["route_costs_ms"], "the session's origin step (origin/origin.json)")


def plan_text(template):
    """The steps, their runs and their time, as text. Pure."""
    levels = capacity_levels()
    runs = {"capacity": CAPACITY_REPEATS, "screening": 3 * (LADDER_REPEATS * 7 + 4), "reference": N_REF * (1 + len(FAMILY_SPECS))}
    sha = (template.get("sha256") or C.digest(template))[:8]
    out = [f"== calibration of the harm benchmark, template sha256:{sha} ==", ""]
    out.append("step 1  origin     three sessions of 21 timed batches per route (each at least 1 ms, the routes in turn), each its own "
               "process on CPU 0; the median of the medians;")
    out.append("                   if any route's sessions differ by more than 10 % the three are made once more, then it stops")
    out.append(f"step 2  capacity   {CAPACITY_REPEATS} runs, each the legit load stepping through {len(levels)} levels "
               f"({levels[0]:g} to {levels[-1]:g} req/s), {STEP_S:g} s a step, Q over {Q_WINDOW[0]:g}-{Q_WINDOW[1]:g} s of each;")
    out.append(f"                   C_slo = the last level before the first below {HEALTHY_Q:g} % in any repeat, C_sat = the lowest "
               f"below {SATURATED_Q:g} % in {SATURATED_REPEATS} repeats")
    out.append("step 3  ladder     per family (" + ", ".join(sorted(FAMILY_SPECS)) + "): the levels S x {1/8 .. 8} up to the first")
    out.append(f"                   the generator cannot carry, {LADDER_REPEATS} attack runs each, a control after every "
               f"{CONTROL_EVERY}th run, in a seeded random order;")
    out.append("                   harm = max(dQ / floor, dL / floor) against the session's controls; valid only if the controls are "
               f"healthy and within {CONTROL_SPREAD_PP:g} pp")
    out.append("step 4  knee       calibration.knee at 1 over the harms; none passing is 'cannot harm this server within the "
               "generator limit', and nothing is tuned")
    out.append(f"step 5  reference  {N_REF} rounds, each a legit probe of {PROBE_S:g} s at rho and one attack run per family at its "
               "knee, on the drift check's seeds;")
    out.append("                   every run kept; the means and SDs of Q and log2 p95 and the tolerances are frozen in the record")
    out.append("        freeze     reads the directories, never the VM; refuses smoke tests, invalid screenings and mixed sessions")
    floor_pp, floor_log2 = template["gate"]["floor_pp"], template["gate"]["floor_log2_p95"]
    out.append(f"step 7  drift      {M_DRIFT} rounds before a later campaign, judged on means per family: the mean Q within T_Q and the "
               "mean log2 p95 within T_L of the reference's,")
    out.append(f"                   T = min(floor, max(floor / 2, {C.C_TOL:g} sqrt(1/{N_REF} + 1/{M_DRIFT}) SD)) frozen in the record "
               f"(floors {floor_pp:g} pp and {floor_log2:g} in log2);")
    out.append(f"                   the legit probe's means within {C.DRIFT_Q_PP:g} pp and {100 * C.DRIFT_P95:g} %; no second attempt. "
               "A record of schema 1 keeps the single-run check:")
    out.append(f"                   a legit probe within {C.DRIFT_Q_PP:g} pp and {100 * C.DRIFT_P95:g} % of the reference, and an attack "
               f"run within the gate's floors, {floor_pp:g} pp and a factor of {2 ** floor_log2:g}")
    out.append("")
    total = sum(runs.values())
    out.append(f"runs    {runs['capacity']} capacity + {runs['screening']} screening + {runs['reference']} reference = {total}; at about "
               f"{RUN_ESTIMATE_S:.0f} s that is {total * RUN_ESTIMATE_S / 3600:.1f} h (the origin step is 0.1 h more)")
    out.append(f"timer   every run, on CPU {P.PIN_PLAN['legit']}: a refused probe is made again every {X.TIMER_REPROBE_S:g} s, up to --wait-gate "
               "minutes from the run's first probe (0: one probe); a last refusal stops the step; waits are not in the time above")
    out.append("seeds   " + ", ".join(f"{k} {v}+" for k, v in SEEDS.items()) + " in calib (the gate's blocks use 1-10); the reference "
               "takes the drift's: " + ", ".join(f"{k} {v}" for k, v in C.drift_seeds()["attack"].items()))
    return "\n".join(out) + "\n"


def _add_run_args(p):
    p.add_argument("--template", default=C.PLACEHOLDER, help="the template record: knobs, mix, SLOs, gate (default: the placeholder)")
    p.add_argument("--allow-dirty", action="store_true", help="run with uncommitted changes; they are recorded")
    p.add_argument("--clean", action="store_true", help="take down the namespaces and links of an earlier testbed first")
    p.add_argument("--wait-gate", type=float, default=30.0, metavar="MIN", help="minutes to wait for uptime and load at the start and, from each run's first probe, for a refused timer probe to pass; 0: one probe")
    p.add_argument("--simulate", action="store_true", help="run on the simulated host, with a server of a known capacity")
    p.add_argument("--sim-capacity-cpu", type=float, default=None, help="the simulated server's capacity in CPU-seconds a second")
    p.add_argument("--stop-after", type=float, default=None, metavar="MIN",
                   help="start no run after MIN minutes: the step pauses (exit 4) and the same command resumes it (a packet's budget)")


def _host_for(args, cal, timeline=None):
    if args.simulate:
        capacity = args.sim_capacity_cpu or cal["capacity"]["c_slo_rps"] * C.mean_cost_ms(cal) / 1000
        t = timeline or (30.0, 45.0, 30.0)
        return S.SimHost(server=S.SyntheticServer(cal, t, capacity_cpu=capacity), tag=S.origin_tag(cal),
                         origin_costs={k: v for k, v in cal["route_costs_ms"].items()})
    host = X.RealHost()
    host.pin(P.PIN_PLAN["daemon"])
    X._install_signal_handlers()
    return host


def _levels_arg(text):
    try:
        values = [float(x) for x in text.split(",")]
    except ValueError:
        values = []
    if not values or not all(math.isfinite(v) and v > 0 for v in values):
        raise argparse.ArgumentTypeError("positive numbers, separated by commas")
    return values


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("plan", help="the steps, their runs and their time (offline)")
    p.add_argument("--template", default=C.PLACEHOLDER)
    p = sub.add_parser("origin-session", help="one session of step 1, in this process (used by `origin`)")
    p.add_argument("--repeats", type=int, default=ORIGIN_REPEATS)
    p.add_argument("--calibration", default=C.PLACEHOLDER)
    p = sub.add_parser("origin", help="step 1: the unloaded cost of each route")
    _add_run_args(p)
    p.add_argument("--out", required=True)
    p = sub.add_parser("capacity", help="step 2: C_slo and C_sat")
    _add_run_args(p)
    p.add_argument("--out", required=True)
    p.add_argument("--levels", type=_levels_arg, default=None, help="smoke test: other levels in requests/s")
    p.add_argument("--step-s", type=float, default=STEP_S, help="smoke test: seconds a step")
    p.add_argument("--repeats", type=int, default=CAPACITY_REPEATS, help="smoke test: fewer repeats")
    p = sub.add_parser("ladder", help="step 3: the screening of one family")
    _add_run_args(p)
    p.add_argument("--out", required=True)
    p.add_argument("--family", required=True, choices=sorted(FAMILY_SPECS))
    p.add_argument("--levels", type=_levels_arg, default=None, help="smoke test: a subset of the ladder")
    p.add_argument("--timeline", type=X._timeline_arg, default=None, metavar="B,A,R", help="smoke test: baseline, attack, recovery seconds")
    p = sub.add_parser("reference", help="step 5: the legit probes and attack runs the drift check must reproduce")
    _add_run_args(p)
    p.add_argument("--out", required=True, help="the session directory (the one the steps wrote to)")
    p.add_argument("--timeline", type=X._timeline_arg, default=None, metavar="B,A,R")
    p = sub.add_parser("freeze", help="steps 4 and 5: the frozen record from the session's directories (never touches the VM)")
    p.add_argument("--dir", required=True, help="the session directory")
    p.add_argument("--template", default=C.PLACEHOLDER)
    p.add_argument("--out", required=True, help="where to write the frozen record, e.g. bench/calibration/<host>-<date>.json")
    p = sub.add_parser("drift", help="step 7: the drift check before a later campaign")
    _add_run_args(p)
    p.add_argument("--calibration", required=True, help="the frozen record")
    p.add_argument("--out", required=True)
    p.add_argument("--family", action="append",
                   help="a family to check (repeatable). A record of schema 2: default every family of its reference, each read on "
                        "its own (K2). Of schema 1 (the record of 2026-11-04): default the first with a reference")
    p.add_argument("--timeline", type=X._timeline_arg, default=None, metavar="B,A,R")
    args = ap.parse_args(argv)
    try:
        return _dispatch(args, host)
    except KeyboardInterrupt:
        print("interrupted; the testbed was taken down. The same command resumes the step.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except HC.HostUnfit as exc:
        print(f"HostUnfit: {exc}", file=sys.stderr)
        return EXIT_HOST_UNFIT
    except GC.Paused as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_PAUSED
    except StepRuleStop as exc:                 # a step's own rule: NOT FROZEN (prereg 6), a code of its own (T-115 H-1)
        print(f"StepRuleStop: {exc} [NOT FROZEN, exit {EXIT_NOT_FROZEN}]", file=sys.stderr)
        return EXIT_NOT_FROZEN
    except (CalibrationStop, GC.CampaignError, X.RunFailed) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_STOPPED
    except (X.PlanError, SC.ScenarioError, C.RecordError, LT.ToolError, LT.ScopeError, H.GateError, OSError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE


def _dispatch(args, host):
    if args.command == "plan":
        print(plan_text(C.load(args.template)), end="")
        return EXIT_OK
    if args.command == "origin-session":
        print(json.dumps(origin_session(C.load(args.calibration), args.repeats), sort_keys=True))
        return EXIT_OK
    if args.command == "freeze":
        template = C.load(args.template)
        env_path = os.path.join(args.dir, "capacity", "r1", "C", "environment.json")
        if not os.path.exists(env_path):
            raise CalibrationStop(f"{env_path}: no environment.json of the capacity runs: run `capacity` first")
        frozen = freeze_step(args.dir, template, read_json(env_path))
        C.dump(frozen, args.out)
        print(json.dumps(C.summary(frozen), indent=1, sort_keys=True))
        return EXIT_OK
    if args.command == "drift":
        cal = C.load(args.calibration)
        timeline = args.timeline
        host = host or _host_for(args, cal, timeline)
        out = os.path.abspath(args.out)
        try:                                    # a frozen record is used only on the host it was measured on (K5)
            C.require_host(cal, host.facts())
        except C.RecordError as exc:
            raise CalibrationStop(str(exc)) from exc
        if cal.get("schema") != 1:              # schema 2: M_DRIFT rounds on means, read per family; no second attempt (K2)
            speed = HC.SpeedBracket(os.path.abspath(args.calibration), cal["route_costs_ms"], f"the frozen record {cal['sha256'][:8]}")
            runner = Runner(host, {}, args.allow_dirty, args.clean, args.wait_gate, check=host_check(host, speed, out, cal),
                            stop_after_min=args.stop_after)
            try:
                result = drift_step(runner, cal, os.path.abspath(args.calibration), out, args.family, timeline)
            finally:
                runner.close()
            return EXIT_OK if result["ok"] else EXIT_INVALID
        deadline = None
        for attempt in (1, 2):                  # a failure is made once more after the environment gate; twice stops (design 7.5)
            runner = Runner(host, {}, args.allow_dirty, args.clean, args.wait_gate,       # a new runner waits for the full gate
                            stop_after_min=args.stop_after)
            deadline = runner.deadline = deadline or runner.deadline                    # one budget for both attempts
            result = drift_step(runner, cal, os.path.abspath(args.calibration), out if attempt == 1 else out + ".second",
                                args.family, timeline)
            if result["ok"]:
                return EXIT_OK
            print(f"drift check {attempt} of 2 failed" + ("; making it once more" if attempt == 1 else "; it stops here"))
        return EXIT_INVALID
    template = C.load(args.template)
    cal_path, out = os.path.abspath(args.template), os.path.abspath(args.out)
    timeline = getattr(args, "timeline", None)
    host = host or _host_for(args, template, timeline)
    if args.command == "origin":
        session_host(out, host, "origin")
        kept = kept_origin(out, template)       # a resumed R1 keeps a complete origin step of this estimator (T-115 H-3)
        if kept:
            print(f"origin kept: {kept[0]} {kept[1]}")
            return EXIT_OK
        ruled = stopped_by_own_rule(out)        # and does not make again one that its own rule stopped (NOT FROZEN, prereg 8)
        if ruled:
            raise StepRuleStop(f"the origin step stopped by its own rule ({read_json(ruled)['stopped']}; {ruled}): the calibration is "
                               "NOT FROZEN, and the step is not made again")
        origin_step(Runner(host, {}, args.allow_dirty, args.clean, args.wait_gate), template, cal_path, out)
        return EXIT_OK
    runner = Runner(host, {}, args.allow_dirty, args.clean, args.wait_gate,
                    check=host_check(host, session_speed(out, cal_path), out, template), stop_after_min=args.stop_after)
    session_host(out, host, args.command)
    try:
        return _run_step(args, runner, template, cal_path, out, timeline)
    finally:
        runner.close()


def _run_step(args, runner, template, cal_path, out, timeline):
    if args.command == "capacity":
        capacity_step(runner, template, cal_path, out, args.levels, args.step_s, args.repeats)
        return EXIT_OK
    draft, under = session_draft(out, template)
    if args.command == "ladder":
        ladder_step(runner, draft, cal_path, args.family, out, under, args.levels, timeline)     # not valid twice: StepRuleStop
        return EXIT_OK
    knees = {}                                  # reference: the screenings must all be made, and valid
    for family in FAMILY_SPECS:
        path = os.path.join(out, f"ladder_{family}", "ladder.json")
        if not os.path.exists(path):
            raise CalibrationStop(f"{out}: no screening of {family}: the reference is taken at the knees")
        ladder = read_json(path)
        if not ladder["valid"]:
            raise CalibrationStop(f"the screening of {family} is not valid: " + "; ".join(ladder["reasons"]))
        knees[family] = ladder["knee"]["level"]
    reference_step(runner, draft_record(template, *[read_json(os.path.join(out, s, s + ".json")) for s in ("origin", "capacity")],
                                        knees), cal_path, knees, out, under, timeline)
    return EXIT_OK


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)  # a step started by packet.sh (`cmd &`) inherits SIGINT ignored (T-105 F3)
    sys.exit(main())
