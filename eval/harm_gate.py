#!/usr/bin/env python3
"""The harm gate: Gate A of docs/BENCHMARK_HARM_DESIGN.md section 10, in the form of docs/HG1B_MINIMAL_DESIGN.md 5.6.

Does an attack, run against the unprotected stack, measurably harm the legitimate clients? The unit is the
BLOCK: a control C, a placebo C' (a second attack-free run) and the attack U, with the same population, the same
rho and the same timeline, run in shuffled order. Offline and read-only: the input is what an executor wrote
under the run contract (5.5), the output is a verdict, a Markdown report and a JSON record.

  * Q of a run is the share of the legit requests whose intended time falls in the attack window that completed
    2xx within their route class's SLO. The service time is taken from the actual send: a generator that wakes
    late must not turn a healthy control into a failed block (the slip is checked on its own, below). A request
    that was never sent, dropped, timed out or answered non-2xx fails. p95 is that of the successful ones.
  * per block: dQ = Q(C) - Q(U) in pp, dL = log2(p95(U) / p95(C)), dQ' = Q(C) - Q(C').
  * PASS iff, over the valid blocks, either the mean dQ reaches the floor, its t-interval excludes 0 and enough
    blocks have its sign, or the same holds for dL. Otherwise FAIL; fewer than `min_blocks` valid blocks, or a
    campaign that broke the re-run rule, is INVALID. The same rule on dQ' and dL' is the placebo: it must not
    pass. HRR is defined only after a PASS. The constants are the calibration's, frozen with it.
  * a block is valid iff its runs meet the generator-validity profile (`relative`: a gross ceiling on slip and a
    difference to the control; `strict`: every engine flag clear and slip p99 under 50 ms, computed always and
    judging only if chosen) and the control is healthy. A failed block is re-run once with the same seed, at most
    `max_reruns` times in all; a valid block is never re-run. Validity does not read the attack's effect.
  * no verdict on a calibration that is not frozen, except with --dry-run, which labels everything it prints.

Limits, stated where they bite: p95 is over successes, so a server that fails its slowest requests looks faster
(Q, which counts the failures, is the primary number); the pooled p95 weighs route classes by their share of the
mix, the per-class figures are reported next to it; an SLO is a choice, the calibration holds it.

    ./venv/bin/python eval/harm_gate.py CAMPAIGN --calibration FILE [--dry-run] [--md FILE] [--json FILE]
"""
import argparse
import csv
import gzip
import json
import math
import os
import sys

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "eval"))
import calibration as CAL
import run_level_stats as RLS

CONTROL, PLACEBO, ATTACK = "C", "Cp", "U"
MITIGATED = "M_"                                   # M_<mode>
ROLE_OF = {CONTROL: "control", PLACEBO: "placebo", ATTACK: "attack"}
STREAM_KINDS = ("legit", "attack")
BLOCK_KEYS = ("scenario", "block", "attempt", "seed_namespace", "seed", "calibration_sha256", "timeline", "order")
STREAM_KEYS = ("id", "kind", "route_class", "summary", "records", "offset_s")
RECORD_COLUMNS = ("t_intended", "t_sent", "t_done", "status", "err")
METRICS = ("Q", "p95")
DEGRADED_Q, RECOVERED_Q, RECOVERY_BINS = 95.0, 99.0, 5     # a second below / at or above these; five seconds
HRR_DRAWS, HRR_SEED = 10_000, 20261023


class GateError(ValueError):
    """The data do not follow the run contract (docs/HG1B_MINIMAL_DESIGN.md 5.5)."""


# --- reading -----------------------------------------------------------------------------------

def _json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"{path}: {exc}") from exc


def _number(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def read_block_meta(block_dir):
    meta = _json(os.path.join(block_dir, "block.json"))
    where = os.path.join(block_dir, "block.json")
    if not isinstance(meta, dict) or [k for k in BLOCK_KEYS if k not in meta]:
        raise GateError(f"{where}: needs {', '.join(BLOCK_KEYS)}")
    for key in ("block", "attempt", "seed"):
        if not isinstance(meta[key], int) or isinstance(meta[key], bool):
            raise GateError(f"{where}: {key} is an integer")
    t = meta["timeline"]
    if not isinstance(t, dict) or set(t) != {"baseline_s", "attack_s", "recovery_s"} or \
            not all(_number(v) and v > 0 for v in t.values()):
        raise GateError(f"{where}: timeline is baseline_s, attack_s and recovery_s, all positive")
    if not isinstance(meta["order"], list):
        raise GateError(f"{where}: order is the list of runs in the order they were made")
    return meta


def read_run(run_dir):
    """run.json and the summary of each stream; the records are read when the figures are made."""
    meta = _json(os.path.join(run_dir, "run.json"))
    name = os.path.basename(run_dir)
    want = ROLE_OF.get(name, "mitigated" if name.startswith(MITIGATED) else None)
    if want is None or meta.get("role") != want:
        raise GateError(f"{run_dir}: a run called {name} has role {want or 'none'}, run.json says {meta.get('role')!r}")
    streams = []
    for s in meta.get("streams", []):
        if [k for k in STREAM_KEYS if k not in s]:
            raise GateError(f"{run_dir}/run.json: a stream needs {', '.join(STREAM_KEYS)}")
        if s["kind"] not in STREAM_KINDS:
            raise GateError(f"{run_dir}/run.json: stream {s['id']} has kind {s['kind']!r}")
        streams.append({**s, "summary": _json(os.path.join(run_dir, s["summary"])),
                        "records": os.path.join(run_dir, s["records"])})
    if not any(s["kind"] == "legit" for s in streams):
        raise GateError(f"{run_dir}: no legit stream, nothing to judge")
    return {"dir": run_dir, "name": name, "role": want, "mode": meta.get("mode"),
            "started_utc": meta.get("started_utc"), "streams": streams}


def read_records(path):
    """The engine's --records file as arrays by column; 'nan' is a request that was never sent or finished."""
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", newline="", encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
    except (OSError, EOFError, UnicodeDecodeError, csv.Error) as exc:
        raise GateError(f"{path}: {exc}") from exc
    head, body = (rows[0], rows[1:]) if rows else ([], [])
    missing = [c for c in RECORD_COLUMNS if c not in head]
    if missing:
        raise GateError(f"{path}: no column {', '.join(missing)}")
    at = {name: head.index(name) for name in RECORD_COLUMNS}
    try:
        out = {name: np.array([r[at[name]] for r in body], dtype=float) for name in RECORD_COLUMNS if name != "err"}
        out["err"] = np.array([r[at["err"]] for r in body], dtype=object)
    except (ValueError, IndexError) as exc:
        raise GateError(f"{path}: {exc}") from exc
    return out


# --- the figures of one run --------------------------------------------------------------------

def _q(values, q):
    return float(np.quantile(values, q)) if len(values) else None


def _bins(t_run, ok, n_bins):
    idx = np.floor(t_run).astype(int)
    inside = (idx >= 0) & (idx < n_bins)
    return (np.bincount(idx[inside], minlength=n_bins), np.bincount(idx[inside & ok], minlength=n_bins))


def time_resolved(n_bins_arr, ok_bins_arr, attack_start, attack_end):
    """Degraded seconds, time to the first degraded second after the attack starts, and the recovery time."""
    q = [100.0 * int(ok) / int(n) if n else None for n, ok in zip(n_bins_arr, ok_bins_arr, strict=True)]
    degraded = [x is not None and x < DEGRADED_Q for x in q]
    first = next((i for i in range(math.floor(attack_start), len(q)) if degraded[i]), None)
    recovery = None
    for t in range(math.ceil(attack_end), len(q) - RECOVERY_BINS + 1):
        if all(x is not None and x >= RECOVERED_Q for x in q[t:t + RECOVERY_BINS]):
            recovery = t - attack_end
            break
    inside = [i for i in range(len(q)) if attack_start <= i < attack_end]
    return {"degraded_s": sum(degraded), "degraded_in_attack_s": sum(degraded[i] for i in inside),
            "first_degraded_s": None if first is None else first - attack_start, "recovery_s": recovery,
            "q_per_s": q}


def run_metrics(run, cal, timeline, slo_scale=1.0):
    """Q, p95, the failures by cause, the per-class figures, the slip and the 1-s bins of a run's legit streams."""
    slo = {k: v * slo_scale / 1000.0 for k, v in cal["slo_ms"].items()}
    lo = float(timeline["baseline_s"])
    hi = lo + float(timeline["attack_s"])
    total = hi + float(timeline["recovery_s"])
    parts = {k: [] for k in ("t_run", "t_int", "t_sent", "t_done", "status", "err", "route")}
    for s in run["streams"]:
        if s["kind"] != "legit":
            continue
        if s["route_class"] not in slo:
            raise GateError(f"{s['id']}: route class {s['route_class']!r} has no SLO")
        rec = read_records(s["records"])
        parts["t_run"].append(rec["t_intended"] + float(s["offset_s"]))
        parts["t_int"].append(rec["t_intended"])
        for key, column in (("t_sent", "t_sent"), ("t_done", "t_done"), ("status", "status"), ("err", "err")):
            parts[key].append(rec[column])
        parts["route"].append(np.full(len(rec["t_intended"]), s["route_class"], dtype=object))
    a = {k: np.concatenate(v) for k, v in parts.items()}
    limit = np.zeros(len(a["route"]))
    for klass in set(a["route"]):
        limit[a["route"] == klass] = slo[klass]
    with np.errstate(invalid="ignore"):
        service = a["t_done"] - a["t_sent"]
        answered = (a["err"] == "") & ~np.isnan(a["t_sent"]) & ~np.isnan(a["t_done"])
        twoxx = (a["status"] >= 200) & (a["status"] < 300)
        ok = answered & twoxx & (service <= limit)
        window = (a["t_run"] >= lo) & (a["t_run"] < hi)
        slow = answered & twoxx & (service > limit)
    n_w, ok_w = int(window.sum()), int((ok & window).sum())
    sent = ~np.isnan(a["t_sent"])
    failed = window & ~ok
    causes = {"dropped": int((failed & (a["err"] == "dropped")).sum()),
              "never_sent": int((failed & ~sent & (a["err"] != "dropped")).sum()),
              "non_2xx": int((failed & answered & ~twoxx).sum()), "slow": int((failed & slow).sum())}
    for name in sorted({str(e) for e in a["err"][failed & sent]} - {""}):
        causes[name] = int((failed & sent & (a["err"] == name)).sum())
    by_class = {}
    for klass in sorted(set(a["route"][window])):
        m = window & (a["route"] == klass)
        good = service[m & ok]
        by_class[klass] = {"n": int(m.sum()), "ok": int((m & ok).sum()), "Q": 100.0 * int((m & ok).sum()) / int(m.sum()),
                           "p95_s": _q(good, 0.95)}
    good = service[window & ok]
    with np.errstate(invalid="ignore"):
        slip = (a["t_sent"] - a["t_int"])[sent]
    n_bins = math.ceil(total)
    nb, okb = _bins(a["t_run"], ok, n_bins)
    return {"requests": n_w, "ok": ok_w, "Q": 100.0 * ok_w / n_w if n_w else None, "lost": n_w - ok_w,
            "p50_s": _q(good, 0.5), "p95_s": _q(good, 0.95), "p99_s": _q(good, 0.99),
            "p95_from_intended_s": _q((a["t_done"] - a["t_int"])[window & ok], 0.95),
            "slip_p99_s": _q(slip, 0.99), "failures": {k: v for k, v in causes.items() if v},
            "by_class": by_class, **time_resolved(nb, okb, lo, hi)}


# --- validity ----------------------------------------------------------------------------------

def validity(run, cal, slip_p99, control_slip_p99):
    """Both profiles for a run: {'relative': {'ok', 'reasons'}, 'strict': {...}} (docs/HG1B_MINIMAL_DESIGN.md 4)."""
    v = cal["validity"]
    shared, relative, strict = [], [], []
    for s in run["streams"]:
        sm, sid = s["summary"], s["id"]
        try:
            cpu, intended, sent = sm["cpu"]["share"], sm["intended"], sm["sent"]
            dropped, flags = sm["dropped"], sm["flags"]
            slip = sm["slip_s"]["p99"]
        except (KeyError, TypeError) as exc:
            raise GateError(f"{run['dir']}: the summary of stream {sid} lacks {exc}") from exc
        if cpu > v["cpu_share"]:
            shared.append(f"{sid}: CPU share {cpu:.2f} above {v['cpu_share']:g}")
        if intended > 0 and sent < v["sent_share"] * intended:
            shared.append(f"{sid}: sent {sent} of {intended} intended")
        if flags.get("descriptors"):
            shared.append(f"{sid}: out of descriptors")
        if flags.get("ports"):
            shared.append(f"{sid}: out of ports")
        if dropped > 0 and s["kind"] == "legit":
            relative.append(f"{sid}: a legit stream dropped {dropped} requests")
        if dropped > 0:
            strict.append(f"{sid}: dropped {dropped} requests")
        if slip is not None and slip > v["slip_gross_s"]:
            relative.append(f"{sid}: slip p99 {slip * 1000:.0f} ms above the gross ceiling {v['slip_gross_s'] * 1000:.0f} ms")
        if slip is not None and slip > v["strict_slip_p99_s"]:
            strict.append(f"{sid}: slip p99 {slip * 1000:.0f} ms above {v['strict_slip_p99_s'] * 1000:.0f} ms")
    if control_slip_p99 is not None and slip_p99 is not None and slip_p99 > control_slip_p99 + v["slip_delta_s"]:
        relative.append(f"legit slip p99 {slip_p99 * 1000:.0f} ms exceeds the control's {control_slip_p99 * 1000:.0f} ms "
                        f"by more than {v['slip_delta_s'] * 1000:.0f} ms")
    return {"relative": {"ok": not shared + relative, "reasons": shared + relative},
            "strict": {"ok": not shared + strict, "reasons": shared + strict}}


def control_health(m, cal):
    """Reasons for which a control is not healthy: Q(C) at least `control_q_min`, every class's p95 within its SLO."""
    reasons = []
    floor = cal["gate"]["control_q_min"]
    if m["Q"] is None or m["Q"] < floor:
        reasons.append(f"Q(C) is {'n/a' if m['Q'] is None else format(m['Q'], '.2f')} %, below {floor:g} %")
    for klass, c in m["by_class"].items():
        if c["p95_s"] is None:
            reasons.append(f"class {klass} has no successful request in the control")
        elif c["p95_s"] * 1000 > cal["slo_ms"][klass]:
            reasons.append(f"class {klass} p95 {c['p95_s'] * 1000:.0f} ms is above its SLO of {cal['slo_ms'][klass]} ms")
    return reasons


def _log2_ratio(num, den):
    return math.log2(num / den) if num and den and num > 0 and den > 0 else None


def _diff(a, b):
    return None if a is None or b is None else a - b


# --- blocks and the campaign -------------------------------------------------------------------

def assess_block(block_dir, cal, slo_scale=1.0):
    meta = read_block_meta(block_dir)
    runs, problems = {}, []
    for name in sorted(os.listdir(block_dir)):
        if os.path.isfile(os.path.join(block_dir, name, "run.json")):
            runs[name] = read_run(os.path.join(block_dir, name))
    for need in (CONTROL, PLACEBO, ATTACK):
        if need not in runs:
            problems.append(f"run {need} is missing")
    made = sorted(n for n in runs if not n.startswith(MITIGATED))
    if sorted(meta["order"]) != made:
        problems.append(f"order {meta['order']} is not the runs made ({', '.join(made)})")
    metrics = {n: run_metrics(r, cal, meta["timeline"], slo_scale) for n, r in runs.items()}
    control = metrics.get(CONTROL)
    out_runs = {}
    for name, run in runs.items():
        m = metrics[name]
        val = validity(run, cal, m["slip_p99_s"], None if name == CONTROL or not control else control["slip_p99_s"])
        out_runs[name] = {"role": run["role"], "mode": run["mode"], "metrics": m, "validity": val,
                          "valid": val[cal["validity"]["profile"]]["ok"], "strict_ok": val["strict"]["ok"]}
    reasons = list(problems)
    for name in (CONTROL, PLACEBO, ATTACK):
        if name in out_runs and not out_runs[name]["valid"]:
            reasons += [f"{name}: {r}" for r in out_runs[name]["validity"][cal["validity"]["profile"]]["reasons"]]
    if control:
        reasons += [f"control: {r}" for r in control_health(control, cal)]
    u, cp = metrics.get(ATTACK), metrics.get(PLACEBO)
    return {"dir": os.path.basename(block_dir), "block": meta["block"], "attempt": meta["attempt"],
            "seed": meta["seed"], "seed_namespace": meta["seed_namespace"], "scenario": meta["scenario"],
            "calibration_sha256": meta["calibration_sha256"], "order": meta["order"], "runs": out_runs,
            "valid": not reasons, "reasons": reasons,
            "dQ": _diff(control and control["Q"], u and u["Q"]),
            "dL": _log2_ratio(u and u["p95_s"], control and control["p95_s"]),
            "dQ_placebo": _diff(control and control["Q"], cp and cp["Q"]),
            "dL_placebo": _log2_ratio(cp and cp["p95_s"], control and control["p95_s"])}


def protocol_problems(attempts, cal):
    """Departures from how a gate may be run: one scenario, one calibration, one re-run per failed block."""
    p = []
    for key in ("scenario", "seed_namespace"):
        if len({a[key] for a in attempts}) > 1:
            p.append(f"the blocks belong to more than one {key}: {sorted({a[key] for a in attempts})}")
    want = cal.get("sha256") or CAL.digest(cal)
    wrong = sorted({a["calibration_sha256"] for a in attempts} - {want})
    if wrong:
        p.append(f"calibration sha256 {', '.join(s[:8] for s in wrong)} is not the one given ({want[:8]})")
    by_block = {}
    for a in attempts:
        by_block.setdefault(a["block"], []).append(a)
    reruns = 0
    for number, group in sorted(by_block.items()):
        group.sort(key=lambda a: a["attempt"])
        if [a["attempt"] for a in group] != list(range(1, len(group) + 1)):
            p.append(f"block {number}: attempts {[a['attempt'] for a in group]} are not 1, 2, ...")
        elif len(group) > 2:
            p.append(f"block {number}: {len(group)} attempts; a failed block is re-run once")
        if len({a["seed"] for a in group}) > 1:
            p.append(f"block {number}: the re-run used another seed")
        if len(group) > 1:
            reruns += 1
            if group[0]["valid"]:
                p.append(f"block {number}: re-run although attempt 1 was valid")
    if reruns > cal["gate"]["max_reruns"]:
        p.append(f"{reruns} blocks were re-run; at most {cal['gate']['max_reruns']} in a gate")
    return p, reruns


def criterion(values, floor, gate):
    """The pre-registered rule on a list of block differences: the mean reaches `floor`, the t-interval excludes 0 and
    enough blocks have the sign of the mean (eval/run_level_stats.py's interval and sign share)."""
    n = len(values)
    if n < 2:
        return {"n": n, "evaluable": False, "passed": False, "floor": floor}
    mean, lo, hi = RLS.t_interval(values, gate["ci_level"])
    share = RLS.same_sign_share(values)
    mean_ok, interval_ok, share_ok = mean >= floor, bool(lo > 0), share >= gate["same_sign_share"]
    return {"n": n, "evaluable": True, "mean": float(mean), "lo": float(lo), "hi": float(hi),
            "same_sign_share": float(share), "floor": floor, "mean_ok": bool(mean_ok), "interval_ok": interval_ok,
            "share_ok": bool(share_ok), "passed": bool(mean_ok and interval_ok and share_ok)}


def _series(blocks, key):
    """The values of `key` over blocks, or None if any block lacks one (the criterion is then not evaluable)."""
    values = [b[key] for b in blocks]
    return None if any(v is None for v in values) else values


def _criteria(blocks, gate, metrics, dq_key, dl_key):
    out = {}
    if "Q" in metrics:
        v = _series(blocks, dq_key)
        out["Q"] = criterion(v, gate["floor_pp"], gate) if v is not None else {"n": len(blocks), "evaluable": False,
                                                                           "passed": False, "floor": gate["floor_pp"]}
    if "p95" in metrics:
        v = _series(blocks, dl_key)
        out["p95"] = criterion(v, gate["floor_log2_p95"], gate) if v is not None else {
            "n": len(blocks), "evaluable": False, "passed": False, "floor": gate["floor_log2_p95"]}
    return out


def hrr(valid_blocks, mode, draws=HRR_DRAWS, seed=HRR_SEED):
    """HRR = (Q(M) - Q(U)) / (Q(C) - Q(U)) from block means, with a percentile block-bootstrap interval."""
    rows = [(b["runs"][CONTROL]["metrics"]["Q"], b["runs"][ATTACK]["metrics"]["Q"], b["runs"][MITIGATED + mode]["metrics"]["Q"])
            for b in valid_blocks if MITIGATED + mode in b["runs"] and b["runs"][MITIGATED + mode]["valid"]]
    rows = [r for r in rows if None not in r]
    if not rows:
        return {"mode": mode, "n": 0, "hrr": None}
    c, u, m = (np.array(col, dtype=float) for col in zip(*rows, strict=True))
    den = c.mean() - u.mean()
    out = {"mode": mode, "n": len(rows), "hrr": float((m.mean() - u.mean()) / den) if den > 0 else None,
           "lo": None, "hi": None, "dropped_draws": 0}
    if out["hrr"] is None or len(rows) < 2:
        return out
    idx = np.random.default_rng(seed).integers(0, len(rows), size=(draws, len(rows)))
    cm, um, mm = c[idx].mean(axis=1), u[idx].mean(axis=1), m[idx].mean(axis=1)
    good = (cm - um) > 0
    values = (mm[good] - um[good]) / (cm[good] - um[good])
    out["dropped_draws"] = int(draws - good.sum())
    if len(values):
        out["lo"], out["hi"] = float(np.quantile(values, 0.025)), float(np.quantile(values, 0.975))
    return out


def analyse(root, cal, dry_run=False, metrics=METRICS, slo_scale=1.0):
    """The verdict of a campaign directory (one gate) under calibration `cal`."""
    if cal["status"] != "frozen" and not dry_run:
        CAL.require_frozen(cal)
    dirs = [d for d in sorted(os.listdir(root)) if os.path.isfile(os.path.join(root, d, "block.json"))]
    if not dirs:
        raise GateError(f"{root}: no block.json under it")
    attempts = [assess_block(os.path.join(root, d), cal, slo_scale) for d in dirs]
    problems, reruns = protocol_problems(attempts, cal)
    final = {}
    for a in sorted(attempts, key=lambda a: (a["block"], a["attempt"])):
        final[a["block"]] = a
    blocks = [final[k] for k in sorted(final)]
    valid = [b for b in blocks if b["valid"]]
    gate = cal["gate"]
    reasons = list(problems)
    if len(valid) < gate["min_blocks"]:
        reasons.append(f"{len(valid)} valid blocks, fewer than the {gate['min_blocks']} the gate needs")
    criteria = _criteria(valid, gate, metrics, "dQ", "dL")
    placebo = _criteria(valid, gate, metrics, "dQ_placebo", "dL_placebo")
    if not reasons and not any(c["evaluable"] for c in criteria.values()):
        reasons.append("no criterion could be evaluated")
    if reasons:
        verdict = "INVALID"
    else:
        verdict = "PASS" if any(c["passed"] for c in criteria.values()) else "FAIL"
    modes = sorted({n[len(MITIGATED):] for b in valid for n in b["runs"] if n.startswith(MITIGATED)})
    return {"scenario": blocks[0]["scenario"], "seed_namespace": blocks[0]["seed_namespace"],
            "calibration": {"status": cal["status"], "sha256": cal.get("sha256") or CAL.digest(cal)},
            "dry_run": cal["status"] != "frozen", "metrics": list(metrics), "slo_scale": slo_scale,
            "profile": cal["validity"]["profile"],
            "gate": {k: gate[k] for k in CAL.GATE_KEYS}, "verdict": verdict, "reasons": reasons,
            "blocks_valid": len(valid), "blocks_total": len(blocks), "reruns": reruns,
            "criteria": criteria,
            "placebo": {"criteria": placebo, "passed": any(c["passed"] for c in placebo.values())},
            "hrr": [hrr(valid, m) for m in modes] if verdict == "PASS" else None,
            "hrr_withheld": bool(modes) and verdict != "PASS",
            "blocks": blocks, "attempts": [a for a in attempts if a is not final[a["block"]]]}   # the superseded ones


# --- the report --------------------------------------------------------------------------------

def _f(x, spec=".1f"):
    return "n/a" if x is None else format(x, spec)


def _ms(x):
    return "n/a" if x is None else f"{x * 1000:.0f}"


def _row(name, c, unit):
    if not c["evaluable"]:
        return f"| {name} | {c['n']} | not evaluable | | | {_f(c['floor'], 'g')} {unit} | no |".replace("  |", " |")
    return (f"| {name} | {c['n']} | {c['mean']:+.2f} | [{c['lo']:+.2f}, {c['hi']:+.2f}] | {c['same_sign_share']:.0%} "
            f"| {f'{_f(c['floor'], 'g')} {unit}'.strip()} | {'yes' if c['passed'] else 'no'} |")


def to_markdown(r):
    head = f"# Harm gate: {r['scenario']} ({r['seed_namespace']})\n"
    out = [head]
    if r["dry_run"]:
        out += [("> **DRY RUN on a placeholder calibration.** The costs, SLOs and capacity are illustrations; "
                 "nothing below is a result.\n")]
    out.append(f"**Verdict: {r['verdict']}**" + (" (dry run)" if r["dry_run"] else "") + "\n")
    out.append(f"{r['blocks_valid']} valid blocks of {r['blocks_total']}, {r['reruns']} re-run(s); calibration "
               f"{r['calibration']['status']} `{r['calibration']['sha256'][:8]}`; validity profile `{r['profile']}`; "
               f"metrics {', '.join(r['metrics'])}.\n")
    if r["reasons"]:
        out += ["Why INVALID:\n"] + [f"* {x}" for x in r["reasons"]] + [""]
    names = {"Q": ("dQ (pp)", "dQ' (pp), placebo", "pp"), "p95": ("dL (log2 p95 ratio)", "dL' (log2 p95 ratio), placebo", "")}
    out += ["| criterion | blocks | mean | 95 % interval | same sign | floor | passed |", "|---|---|---|---|---|---|---|"]
    out += [_row(names[k][0], c, names[k][2]) for k, c in r["criteria"].items()]
    out += [_row(names[k][1], c, names[k][2]) for k, c in r["placebo"]["criteria"].items()]
    out.append("")
    out.append("The placebo (a second attack-free run) " + ("**PASSED: the gate is not specific on these data, "
               "treat the verdict as unreliable.**" if r["placebo"]["passed"] else "did not pass, as it must not.") + "\n")
    out += ["## Blocks", "",
            ("| block | seed | attempt | valid | Q C | Q C' | Q U | dQ | dL | dQ' | p95 C ms | p95 U ms | degraded s | "
             "first degraded s | recovery s |"), "|" + "---|" * 15]
    for b in r["blocks"]:
        c, cp, u = (b["runs"].get(n, {}).get("metrics") for n in (CONTROL, PLACEBO, ATTACK))
        out.append(f"| {b['block']} | {b['seed']} | {b['attempt']} | {'yes' if b['valid'] else 'no'} | "
                   f"{_f(c and c['Q'])} | {_f(cp and cp['Q'])} | {_f(u and u['Q'])} | {_f(b['dQ'])} | {_f(b['dL'], '.2f')} | "
                   f"{_f(b['dQ_placebo'])} | {_ms(c and c['p95_s'])} | {_ms(u and u['p95_s'])} | "
                   f"{_f(u and u['degraded_s'], 'd')} | {_f(u and u['first_degraded_s'])} | {_f(u and u['recovery_s'])} |")
    out.append("")
    bad = [b for b in r["blocks"] if not b["valid"]] + [a for a in r["attempts"]]
    if bad:
        out += ["## Blocks and attempts that are not valid", ""]
        for b in sorted(bad, key=lambda b: (b["block"], b["attempt"])):
            if not b["valid"]:
                out.append(f"* block {b['block']} attempt {b['attempt']} (seed {b['seed']}): " + "; ".join(b["reasons"]))
        out.append("")
    strict_bad = sum(1 for b in r["blocks"] for run in b["runs"].values() if not run["strict_ok"])
    out.append(f"Strict profile (design 8.3 as written), computed and not judged unless chosen: {strict_bad} run(s) "
               "of the final blocks would fail it.\n")
    if r["hrr"]:
        out += ["## HRR", "", "| mode | blocks | HRR | 95 % block-bootstrap interval |", "|---|---|---|---|"]
        out += [f"| {h['mode']} | {h['n']} | {_f(h['hrr'], '.2f')} | [{_f(h.get('lo'), '.2f')}, {_f(h.get('hi'), '.2f')}] |"
                for h in r["hrr"]]
        out.append("")
    elif r["hrr_withheld"]:
        out += ["HRR is not computed: its denominator is the gate-passed harm and the gate did not pass.\n"]
    out.append("Limits: p95 is over successes (Q counts the failures and is the primary number); the pooled p95 weighs "
               "route classes by their share of the mix; the SLOs and floors are the calibration's.")
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("campaign", help="directory of blocks written under the run contract")
    ap.add_argument("--calibration", required=True, help="the calibration record the blocks were run under")
    ap.add_argument("--dry-run", action="store_true", help="allow a placeholder calibration; everything is labelled")
    ap.add_argument("--metrics", default=",".join(METRICS), help="criteria to apply (default: Q,p95)")
    ap.add_argument("--md", help="write the Markdown report here")
    ap.add_argument("--json", help="write the JSON record here")
    args = ap.parse_args(argv)
    metrics = tuple(m for m in args.metrics.split(",") if m)
    if not metrics or not set(metrics) <= set(METRICS):
        ap.error(f"--metrics: a non-empty subset of {', '.join(METRICS)}")
    try:
        result = analyse(args.campaign, CAL.load(args.calibration), args.dry_run, metrics)
    except (GateError, CAL.RecordError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(result))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=1, sort_keys=True)
            fh.write("\n")
    print(f"{result['verdict']}{' (dry run)' if result['dry_run'] else ''}: {result['blocks_valid']} valid blocks of "
          f"{result['blocks_total']}" + ("; " + "; ".join(result["reasons"]) if result["reasons"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
