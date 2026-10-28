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

Every step that runs the VM is a separate approval, takes the same preflight and environment gate as a campaign, and can be given
`--simulate` to run on the simulated host (bench/sim_host.py) with a server of a known capacity: the steps, the stop rules and the
arithmetic seen working offline. A step stops, and says what that means, when the host cannot be calibrated: nothing is tuned.
"""
import argparse
import copy
import csv
import dataclasses
import datetime
import json
import math
import os
import random
import re
import shutil
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
PROBE_S, PROBE_WINDOW, REFERENCE_PROBES = 120.0, (10.0, 120.0), 3
# the populations of the calibration are drawn from seeds the gates' blocks (1-10) do not use
SEEDS = {"capacity": 11, "ladder": 21, "reference": 31, "drift": 41}
RUN_ESTIMATE_S = 150.0                      # a run, docs/HG1C_DESIGN.md 6.2; S4 replaces it with a measurement
EXIT_OK, EXIT_USAGE, EXIT_STOPPED, EXIT_INVALID, EXIT_INTERRUPTED = 0, 1, 2, 3, 130


class CalibrationStop(RuntimeError):
    """The host cannot be calibrated as it is, or a step cannot be trusted; the message says what that means (design 7.5).
    Nothing is tuned to get past it."""


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


def combine_origin(sessions):
    """The median of the sessions' medians, per route."""
    return {klass: statistics.median([s[klass] for s in sessions]) for klass in sessions[0]}


def origin_session(cal, repeats=ORIGIN_REPEATS):
    """One session in this process: `repeats` timings of every route of the origin, unloaded, and their median in ms. The
    origin is built with the record's knobs; the clock is the process's CPU time."""
    origin = O.Origin(C.knobs_of(cal), X.ORIGIN_SEED, "placeholder")
    try:
        return O.measure_unloaded(origin, repeats=repeats)
    finally:
        origin.close()


def origin_step(host, cal, cal_path, out, say=print):
    """Three sessions, each its own process pinned to CPU 0, and their median. If any route's medians are further apart than
    10 % the three sessions are made once more and only the second round counts; if they are still, the host's timing is not
    stable enough to calibrate on."""
    rounds = []
    for number in (1, 2):
        sessions = []
        for _ in range(ORIGIN_SESSIONS):
            r = host.run(["taskset", "-c", ORIGIN_CPU, sys.executable, os.path.abspath(__file__), "origin-session",
                          "--repeats", str(ORIGIN_REPEATS), "--calibration", cal_path], timeout=600)
            try:
                sessions.append({k: float(v) for k, v in json.loads(r.out).items()})
            except (ValueError, AttributeError) as exc:
                raise CalibrationStop(f"an origin session gave nothing readable (exit {r.code}): {(r.err or r.out)[:200]}") from exc
        spread = origin_spread(sessions)
        rounds.append({"sessions": sessions, "spread": spread})
        say(f"origin round {number}: widest spread {max(spread.values()):.1%} (limit {ORIGIN_SPREAD:.0%})")
        if max(spread.values()) <= ORIGIN_SPREAD:
            break
    else:
        raise CalibrationStop(f"the unloaded cost of the routes differs by more than {ORIGIN_SPREAD:.0%} between sessions, twice: "
                              "the host's timing is not stable enough to calibrate on")
    result = {"step": "origin", "created_utc": now(), "route_costs_ms": combine_origin(rounds[-1]["sessions"]),
              "rounds": rounds, "sessions": ORIGIN_SESSIONS, "repeats": ORIGIN_REPEATS, "cpu": ORIGIN_CPU,
              "template_sha256": cal.get("sha256") or C.digest(cal)}
    write_json(os.path.join(out, "origin", "origin.json"), result)
    return result


# --- step 2: the capacity ---------------------------------------------------------------------------

def capacity_levels(first=50.0, ratio=1.3, count=10):
    """The levels of the capacity probe in requests/s: 50 x 1.3^k, 50 to 530."""
    return [round(first * ratio ** k, 1) for k in range(count)]


def capacity_of(levels, q, healthy=HEALTHY_Q, saturated=SATURATED_Q, saturated_repeats=SATURATED_REPEATS):
    """C_slo and C_sat from `q`, the Q of each repeat (a row) at each level (a column): C_slo is the last level before the first
    at which any repeat is below `healthy`, C_sat the lowest at which at least `saturated_repeats` repeats are below
    `saturated`. A host for which either does not exist cannot be calibrated this way: CalibrationStop says why."""
    bad = [k for k in range(len(levels)) if any(row[k] < healthy for row in q)]
    if not bad:
        raise CalibrationStop(f"every level up to {levels[-1]:g} req/s keeps Q at {healthy:g} % or more: the capacity is above "
                              "the range of the probe, which has to be extended before the stack can be calibrated")
    if bad[0] == 0:
        raise CalibrationStop(f"the first level, {levels[0]:g} req/s, is already below {healthy:g} % in a repeat: the stack is "
                              "unhealthy before it is loaded, and a capacity cannot be defined on it")
    sat = [k for k in range(len(levels)) if sum(row[k] < saturated for row in q) >= saturated_repeats]
    if not sat:
        raise CalibrationStop(f"no level up to {levels[-1]:g} req/s brings Q below {saturated:g} % in {saturated_repeats} repeats: "
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
    return X.plan_population(pop, "capacity", "C", seed, out, cal, cal_path, pop.timeline,
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
              "q_pct": q, "stack_cost": combine_stack_cost(costs), "smoke": smoke,
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


def ladder_step(runner, cal, cal_path, family, out, under, levels=None, timeline=None, say=print):
    """The screening of one family on the unprotected stack at rho (design 7.2 step 3). `cal` is the record with the session's
    measured costs and capacity, so that rho and S are the calibration's own; `under` says what it was made of (under_of).
    `levels` and `timeline` are for a smoke test, which cannot be frozen."""
    if family not in FAMILY_SPECS:
        raise CalibrationStop(f"family: one of {', '.join(FAMILY_SPECS)}, got {family!r}")
    scn = ladder_scenario(family)
    usable, left_out = runnable_levels(scn, cal)
    if levels is not None:
        usable = [lvl for lvl in sorted(levels) if lvl in usable]
    if not usable:
        raise CalibrationStop(f"no level of {family} can be run: {left_out}")
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
              "smoke": levels is not None or timeline is not None, "under": under}
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
    """The drift reference: the median Q and p95 of the legit probes at rho, and for each family with a knee the Q and p95 of one
    attack run at it. `attacks` maps a family to {"level", "Q", "p95_s"}."""
    return {"rho_rps": rho_rps, "q_pct": statistics.median(m["Q"] for m in legit),
            "p95_s": statistics.median(m["p95_s"] for m in legit),
            "attack": {f: {"level": a["level"], "q_pct": a["Q"], "p95_s": a["p95_s"]} for f, a in sorted(attacks.items())}}


def attack_run(runner, cal, cal_path, family, level, seed, out, timeline=None, say=print):
    """One attack run of `family` at `level` and its Q and p95 over the attack's window."""
    plan = X.plan_run(ladder_scenario(family, level), cal, "U", seed, os.path.join(out, "U"), cal_path, "",
                      settings=runner.settings, timeline=timeline)
    runner.run(plan, say)
    return attack_metrics(plan, cal)


def reference_step(runner, draft, cal_path, knees, out, under, timeline=None, say=print):
    """The legit probes and the attack runs that the drift check must reproduce, with the measured record `draft` (its rho is the
    one the calibration will have) and what it was made of (`under`, as the screenings')."""
    legit = []
    for j in range(REFERENCE_PROBES):
        plan = probe_plan(draft, cal_path, "reference_legit", SEEDS["reference"] + j,
                          os.path.join(out, "reference", f"legit_{j + 1}", "C"), runner.settings)
        runner.run(plan, say)
        legit.append(probe_metrics(H.read_run(plan.out), draft))
    attacks = {}
    for i, (family, knee) in enumerate(sorted(knees.items())):
        if knee is None:
            continue
        m = attack_run(runner, draft, cal_path, family, knee, SEEDS["reference"] + REFERENCE_PROBES + i,
                       os.path.join(out, "reference", f"attack_{family}"), timeline, say)
        attacks[family] = {"level": knee, **m}
    if any(m["Q"] is None or m["p95_s"] is None for m in legit) or any(a["Q"] is None or a["p95_s"] is None for a in attacks.values()):
        raise CalibrationStop("a reference probe had no judged request or no successful one: it cannot be a reference")
    result = {"step": "reference", "created_utc": now(), "legit": legit, "attacks": attacks, "smoke": timeline is not None,
              "under": under, "reference": reference_of(C.rho_rps(draft), legit, attacks)}
    write_json(os.path.join(out, "reference", "reference.json"), result)
    return result


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
    Steps 1 and 2 must have been made."""
    parts = []
    for step in ("origin", "capacity"):
        path = os.path.join(directory, step, step + ".json")
        if not os.path.exists(path):
            raise CalibrationStop(f"{directory}: no {step} step ({path}): the steps are made in order")
        parts.append(read_json(path))
    origin, capacity = parts
    if capacity.get("stopped"):
        raise CalibrationStop(f"the capacity step stopped: {capacity['stopped']}")
    if capacity.get("smoke"):
        raise CalibrationStop("the capacity step was a smoke test: its numbers are not a calibration's")
    return draft_record(template, origin, capacity), under_of(template, origin, capacity)


def _version(text):
    m = re.search(r"\d+(?:\.\d+)+", text or "")
    if not m:
        raise CalibrationStop(f"no version number in {text!r}")
    return m.group(0)


def host_of(env):
    """The frozen record's `host` from the environment.json of one of the runs (design 4.2): what the numbers were measured on."""
    facts, prov, stack = env["facts"], env["provenance"], env.get("stack") or {}
    limits = ((stack.get("origin") or {}).get("nofile_soft_hard") or [[None]])[0]
    if not isinstance(limits[0], int):
        raise CalibrationStop("the origin's open-file limit was not read as a number: environment.json has no stack record")
    return {"uname": facts["uname"], "cpus": facts["cpus"], "mem_mib": facts["mem_mib"], "origin_seed": X.ORIGIN_SEED,
            "origin_sha256": prov["files"]["origin.py"], "loadgen_sha256": prov["files"]["loadgen.py"], "pins": dict(P.PIN_PLAN),
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
    """Reasons for which `session` cannot be frozen: a smoke step, a screening that is not valid, steps made under another template
    or other measured costs and capacity, or a reference that was taken for another set of knees."""
    reasons = []
    under = under_of(template, session["origin"], session["capacity"])
    named = (("origin", session["origin"]), ("capacity", session["capacity"]), ("reference", session["reference"]),
             *[(f"ladder {f}", ladder) for f, ladder in session["ladders"].items()])
    for name, step in named:
        if step.get("smoke"):
            reasons.append(f"{name} is a smoke test (levels, steps or timeline changed): a smoke test is not a calibration")
        if name in ("origin", "capacity") and step["template_sha256"] != under["template_sha256"]:
            reasons.append(f"{name} was made under another template")
        if name not in ("origin", "capacity") and step["under"] != under:
            reasons.append(f"{name} was made under other measured costs or capacity than the ones being frozen")
    for f, ladder in session["ladders"].items():
        if not ladder["valid"]:
            reasons.append(f"the screening of {f} is not valid: " + "; ".join(ladder["reasons"]))
    knees = {f: ladder["knee"]["level"] for f, ladder in session["ladders"].items()}
    attacks = session["reference"]["reference"]["attack"]
    if {f for f, k in knees.items() if k is not None} != set(attacks) or any(attacks[f]["level"] != knees[f] for f in attacks):
        reasons.append("the reference's attack runs are not at the knees of the screenings")
    return reasons


def freeze_step(directory, template, env, created_utc=None):
    """The frozen record from a session's directories: the template with the measured costs, capacity, knees, drift reference
    and host. Reads and writes nothing; calibration.freeze checks the result."""
    session = read_session(directory)
    problems = freeze_problems(session, template)
    if problems:
        raise CalibrationStop("cannot freeze: " + "; ".join(problems))
    knees = {f: ladder["knee"]["level"] for f, ladder in session["ladders"].items()}
    draft = draft_record(template, session["origin"], session["capacity"], knees)
    reference = session["reference"]["reference"]
    if reference["rho_rps"] != C.rho_rps(draft):
        raise CalibrationStop(f"the reference was taken at rho {reference['rho_rps']:g}, the capacity gives {C.rho_rps(draft):g}")
    return C.freeze(draft, created_utc or now(), host=host_of(env), drift_reference=reference)


# --- step 7: drift ----------------------------------------------------------------------------------

def drift_check(cal, legit, attacks):
    """The drift of a new probe against the frozen reference (calibration.drift_ok): the legit probe and each attack run."""
    ref = cal["drift_reference"]
    reasons = [f"legit probe: {r}" for r in C.drift_ok(ref["q_pct"], ref["p95_s"], legit["Q"], legit["p95_s"])[1]]
    for family, m in sorted(attacks.items()):
        why = C.drift_ok(ref["attack"][family]["q_pct"], ref["attack"][family]["p95_s"], m["Q"], m["p95_s"])[1]
        reasons += [f"{family}: {r}" for r in why]
    return {"ok": not reasons, "reasons": reasons}


def drift_step(runner, cal, cal_path, out, families=None, timeline=None, say=print):
    """A legit probe at rho and an attack run at a family's knee against the frozen record's reference. `families` defaults to
    the first family that has one."""
    if cal["status"] != "frozen":
        raise CalibrationStop("a drift check needs a frozen calibration")
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
              "smoke": timeline is not None, **drift_check(cal, legit, attacks)}
    say("drift: " + ("within the frozen reference" if result["ok"] else "OUT of it: " + "; ".join(result["reasons"])))
    write_json(os.path.join(out, "drift", "drift.json"), result)
    return result


# --- running the plans ------------------------------------------------------------------------------

class Runner:
    """Carries out plans through the executor for the steps of a calibration. The first run of the process waits for the full
    environment gate, the others for the timer; a run that is found unsound, or fails in its timeline, is made once more in its
    place (the first goes aside as `<run>.failed1`) and a second time stops the calibration; the executor's refusals stop it at
    once. A run that is done is not made again, so that a step resumes."""

    def __init__(self, host, settings=None, allow_dirty=False, clean=False, wait_gate_min=30.0, tries=2):
        self.host, self.settings = host, dict(settings or {})
        self.allow_dirty, self.clean, self.wait_gate_min, self.tries = allow_dirty, clean, wait_gate_min, tries
        self.gate = "full"

    def run(self, plan, say=print):
        record = GC.read_done(plan.out)
        if record is not None:
            return record
        reasons = []
        for attempt in range(1, self.tries + 1):
            if os.path.exists(plan.out):
                if reasons:                      # an attempt of this call failed: it stays beside the run as evidence
                    os.rename(plan.out, f"{plan.out}.failed{attempt - 1}")
                else:                            # an unfinished run of an earlier call
                    shutil.rmtree(plan.out)
            say(f"{os.sep.join(plan.out.split(os.sep)[-3:])}: attempt {attempt}")
            try:
                result = X.execute(plan, self.host, self.gate, self.allow_dirty, self.clean, self.wait_gate_min, say)
            except GC.STOP_ERRORS:
                raise
            except X.RunFailed as exc:
                reasons = [str(exc)]
            else:
                if result.ok:
                    self.gate = "timer"
                    GC.mark_done(plan.out, GC.run_record(result))
                    return GC.read_done(plan.out)
                reasons = result.reasons
            self.gate = "timer"
        raise CalibrationStop(f"{plan.out}: the run was not sound in {self.tries} attempts ({'; '.join(reasons)[:300]}); "
                              "a calibration made of runs that are not valid is not one")


# --- the command line -------------------------------------------------------------------------------

def plan_text(template):
    """The steps, their runs and their time, as text. Pure."""
    levels = capacity_levels()
    runs = {"capacity": CAPACITY_REPEATS, "screening": 3 * (LADDER_REPEATS * 7 + 4), "reference": REFERENCE_PROBES + 3}
    sha = (template.get("sha256") or C.digest(template))[:8]
    out = [f"== calibration of the harm benchmark, template sha256:{sha} ==", ""]
    out.append("step 1  origin     three sessions of 21 timings per route, each its own process on CPU 0; the median of the medians;")
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
    out.append(f"step 5  reference  {REFERENCE_PROBES} legit probes of {PROBE_S:g} s at rho and one attack run per family at its knee; "
               "their medians are the drift reference")
    out.append("        freeze     reads the directories, never the VM; refuses smoke tests, invalid screenings and mixed sessions")
    out.append("step 7  drift      a legit probe and an attack run against the reference, within 2 pp and 25 %; before a later campaign")
    out.append("")
    total = sum(runs.values())
    out.append(f"runs    {runs['capacity']} capacity + {runs['screening']} screening + {runs['reference']} reference = {total}; at about "
               f"{RUN_ESTIMATE_S:.0f} s that is {total * RUN_ESTIMATE_S / 3600:.1f} h (the origin step is 0.1 h more)")
    out.append("seeds   " + ", ".join(f"{k} {v}+" for k, v in SEEDS.items()) + " in calib (the gate's blocks use 1-10)")
    return "\n".join(out) + "\n"


def _add_run_args(p):
    p.add_argument("--template", default=C.PLACEHOLDER, help="the template record: knobs, mix, SLOs, gate (default: the placeholder)")
    p.add_argument("--allow-dirty", action="store_true", help="run with uncommitted changes; they are recorded")
    p.add_argument("--clean", action="store_true", help="take down the namespaces and links of an earlier testbed first")
    p.add_argument("--wait-gate", type=float, default=30.0, metavar="MIN", help="minutes to wait for uptime and load at the start")
    p.add_argument("--simulate", action="store_true", help="run on the simulated host, with a server of a known capacity")
    p.add_argument("--sim-capacity-cpu", type=float, default=None, help="the simulated server's capacity in CPU-seconds a second")


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
    p.add_argument("--family", action="append", help="a family to run an attack for (default: the first with a reference)")
    p.add_argument("--timeline", type=X._timeline_arg, default=None, metavar="B,A,R")
    args = ap.parse_args(argv)
    try:
        return _dispatch(args, host)
    except KeyboardInterrupt:
        print("interrupted; the testbed was taken down. The same command resumes the step.", file=sys.stderr)
        return EXIT_INTERRUPTED
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
        for attempt in (1, 2):                  # a failure is made once more after the environment gate; twice stops (design 7.5)
            runner = Runner(host, {}, args.allow_dirty, args.clean, args.wait_gate)       # a new runner waits for the full gate
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
    runner = Runner(host, {}, args.allow_dirty, args.clean, args.wait_gate)
    if args.command == "origin":
        origin_step(host, template, cal_path, out)
        return EXIT_OK
    if args.command == "capacity":
        capacity_step(runner, template, cal_path, out, args.levels, args.step_s, args.repeats)
        return EXIT_OK
    draft, under = session_draft(out, template)
    if args.command == "ladder":
        result = ladder_step(runner, draft, cal_path, args.family, out, under, args.levels, timeline)
        return EXIT_OK if result["valid"] else EXIT_INVALID
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
    sys.exit(main())
