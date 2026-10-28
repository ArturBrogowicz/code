#!/usr/bin/env python3
"""The calibration record of the harm benchmark: its schema, its hash and the pure rules built on it
(docs/BENCHMARK_HARM_DESIGN.md 7.2, docs/HG1B_MINIMAL_DESIGN.md 5.2).

Everything the harm gate needs to be fixed *before* the data it judges lives in one JSON file: the
unloaded cost of each route, the knobs that produce it, the capacity probe's result, the legit route mix,
the SLO of each route class, the gate's constants and the generator-validity rules. A calibration is
`placeholder` (the design's illustrative numbers, never a result) or `frozen` (measured on a host,
committed, hashed). The gate refuses a verdict on anything but a frozen one.

Two things in it come from the first look at the real links (docs/HG1C_DESIGN.md 4.1, 4.2): `judged_profiles`,
the link profiles whose clients vote on the gate's Q and p95 (the others are reported: their own links exceed
the SLOs), and `drift_reference`, the Q and p95 that the drift check before every later campaign must
reproduce. A frozen record must carry the second and a complete `host`; a placeholder may leave them out.

The hash is the sha256 of the canonical JSON (sorted keys, no whitespace) without the `sha256` field.
This module measures nothing and runs nothing: the runner that fills a record is bench/calibrate.py.

    python3 bench/calibration.py check FILE     # schema and hash
    python3 bench/calibration.py show FILE      # the derived numbers: rho, the mean cost, the spare capacity
    python3 bench/calibration.py rehash FILE    # rewrite the hash of a PLACEHOLDER after editing it
"""
import argparse
import copy
import hashlib
import itertools
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import origin as O

SCHEMA = 1
STATUSES = ("placeholder", "frozen")
PROFILES = ("relative", "strict")
LINK_PROFILES = ("perfect", "broadband", "mobile_3g", "mobile_bad")      # the suite's netem profiles (population.NETEM_MIX)
PINS = ("server", "daemon", "legit", "attack")
HEX64 = re.compile(r"[0-9a-f]{64}")
# what a frozen record's `host` must carry (docs/HG1C_DESIGN.md 4.2, F2); "sha" is a 64-digit hex string
HOST_SHAPE = {"uname": str, "cpus": int, "mem_mib": int, "origin_seed": int, "origin_sha256": "sha",
              "loadgen_sha256": "sha", "pins": {k: str for k in PINS},
              "gunicorn": {"version": str, "workers": int, "threads": int, "nofile": int},
              "nginx": {"version": str, "conf_sha256": "sha"}}
SLO_CLASSES = ("C0", "C1", "C2", "C3", "C4", "C5", "C6")      # C4 and C6 (POST) are not served yet
PLACEHOLDER = os.path.join(HERE, "calibration", "placeholder.json")
GATE_KEYS = ("floor_pp", "floor_log2_p95", "min_blocks", "same_sign_share", "ci_level", "control_q_min",
             "max_reruns")
VALIDITY_KEYS = ("profile", "slip_pooled_s", "slip_delta_s", "strict_slip_p99_s", "cpu_share", "sent_share",
                 "timer_p99_ms")
CANNOT_HARM = "cannot harm this server within the generator limit"
RHO_SHARE = 0.5                          # the legit load is this share of the SLO capacity (design 6.1)
DRIFT_Q_PP, DRIFT_P95 = 2.0, 0.25        # design 7.2 step 7


class RecordError(ValueError):
    """The record does not meet the schema, or its hash does not match."""


def canonical(cal):
    """The bytes the hash is taken over."""
    body = {k: v for k, v in cal.items() if k != "sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(cal):
    return hashlib.sha256(canonical(cal)).hexdigest()


def _positive(problems, where, value):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not value > 0 or not math.isfinite(value):
        problems.append(f"{where}: a positive number, got {value!r}")


def _percent(problems, where, value):
    if (not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value)
            or not 0 < value <= 100):
        problems.append(f"{where}: a percentage above 0 and at most 100, got {value!r}")


def _shape_problems(value, shape, where):
    """What is wrong with `value` against `shape`: a type, "sha", or a dict of shapes (every key required)."""
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            return [f"{where}: an object"]
        out = [f"{where}: missing {', '.join(k for k in shape if k not in value)}"] if set(shape) - set(value) else []
        for key, sub in shape.items():
            if key in value:
                out += _shape_problems(value[key], sub, f"{where}.{key}")
        return out
    if shape == "sha":
        ok, what = isinstance(value, str) and bool(HEX64.fullmatch(value)), "a 64-digit hex sha256"
    elif shape is int:
        ok, what = isinstance(value, int) and not isinstance(value, bool) and value >= 0, "a non-negative integer"
    else:
        ok, what = isinstance(value, str) and bool(value.strip()), "a non-empty string"
    return [] if ok else [f"{where}: {what}, got {value!r}"]


def _drift_problems(ref):
    """The drift reference: the legit probe at rho, and one attack run at each family's knee."""
    if not isinstance(ref, dict) or set(ref) != {"rho_rps", "q_pct", "p95_s", "attack"}:
        return ["drift_reference: rho_rps, q_pct, p95_s and attack"]
    p = []
    _positive(p, "drift_reference.rho_rps", ref["rho_rps"])
    _percent(p, "drift_reference.q_pct", ref["q_pct"])
    _positive(p, "drift_reference.p95_s", ref["p95_s"])
    if not isinstance(ref["attack"], dict):
        return p + ["drift_reference.attack: an object of family -> {level, q_pct, p95_s}"]
    for family, item in ref["attack"].items():
        where = f"drift_reference.attack.{family}"
        if not isinstance(item, dict) or set(item) != {"level", "q_pct", "p95_s"}:
            p.append(f"{where}: level, q_pct and p95_s")
            continue
        _positive(p, where + ".level", item["level"])
        _percent(p, where + ".q_pct", item["q_pct"])
        _positive(p, where + ".p95_s", item["p95_s"])
    return p


def problems_of(cal):
    """Every way in which `cal` departs from the schema (not the hash)."""
    p = []
    if not isinstance(cal, dict):
        return ["the record is not an object"]
    if cal.get("schema") != SCHEMA:
        p.append(f"schema: {SCHEMA}, got {cal.get('schema')!r}")
    if cal.get("status") not in STATUSES:
        p.append(f"status: one of {', '.join(STATUSES)}, got {cal.get('status')!r}")
    if not isinstance(cal.get("created_utc"), str) or not cal.get("created_utc"):
        p.append("created_utc: a non-empty string")
    if not isinstance(cal.get("host"), dict):
        p.append("host: an object")
    costs = cal.get("route_costs_ms")
    if not isinstance(costs, dict) or set(costs) != set(O.CLASSES):
        p.append(f"route_costs_ms: exactly {', '.join(O.CLASSES)}")
    else:
        for klass, value in costs.items():
            _positive(p, f"route_costs_ms.{klass}", value)
    knobs = cal.get("knobs")
    if not isinstance(knobs, dict):
        p.append("knobs: an object")
    else:
        try:
            O.CostKnobs(**knobs)
        except TypeError as exc:
            p.append(f"knobs: {exc}")
    cap = cal.get("capacity")
    if not isinstance(cap, dict) or set(cap) != {"c_slo_rps", "c_sat_rps"}:
        p.append("capacity: c_slo_rps and c_sat_rps")
    else:
        before = len(p)
        _positive(p, "capacity.c_slo_rps", cap["c_slo_rps"])
        _positive(p, "capacity.c_sat_rps", cap["c_sat_rps"])
        if len(p) == before and not cap["c_sat_rps"] > cap["c_slo_rps"]:
            p.append("capacity: c_sat_rps must exceed c_slo_rps")
    mix = cal.get("mix")
    if not isinstance(mix, dict) or not mix or not set(mix) <= set(O.CLASSES):
        p.append(f"mix: weights of served classes ({', '.join(O.CLASSES)})")
    elif any(not isinstance(w, (int, float)) or w < 0 for w in mix.values()) or abs(sum(mix.values()) - 1) > 1e-6:
        p.append(f"mix: non-negative weights that sum to 1, got {sum(mix.values())!r}")
    slo = cal.get("slo_ms")
    if not isinstance(slo, dict) or set(slo) != set(SLO_CLASSES):
        p.append(f"slo_ms: exactly {', '.join(SLO_CLASSES)}")
    else:
        for klass, value in slo.items():
            _positive(p, f"slo_ms.{klass}", value)
    gate = cal.get("gate")
    if not isinstance(gate, dict) or set(gate) != set(GATE_KEYS):
        p.append(f"gate: exactly {', '.join(GATE_KEYS)}")
    else:
        for key in ("floor_pp", "floor_log2_p95", "control_q_min"):
            _positive(p, f"gate.{key}", gate[key])
        if not (isinstance(gate["min_blocks"], int) and gate["min_blocks"] >= 3):
            p.append("gate.min_blocks: an integer of at least 3")
        if not (isinstance(gate["max_reruns"], int) and gate["max_reruns"] >= 0):
            p.append("gate.max_reruns: a non-negative integer")
        if not (isinstance(gate["ci_level"], (int, float)) and 0 < gate["ci_level"] < 1):
            p.append("gate.ci_level: in (0, 1)")
        if not (isinstance(gate["same_sign_share"], (int, float)) and 0 < gate["same_sign_share"] <= 1):
            p.append("gate.same_sign_share: in (0, 1]")
    val = cal.get("validity")
    if not isinstance(val, dict) or set(val) != set(VALIDITY_KEYS):
        p.append(f"validity: exactly {', '.join(VALIDITY_KEYS)}")
    else:
        if val["profile"] not in PROFILES:
            p.append(f"validity.profile: one of {', '.join(PROFILES)}")
        for key in VALIDITY_KEYS[1:]:
            _positive(p, f"validity.{key}", val[key])
    knees = cal.get("knees")
    if not isinstance(knees, dict) or any(v is not None and not isinstance(v, (int, float)) for v in knees.values()):
        p.append("knees: an object of family -> level or null")
    judged = cal.get("judged_profiles")
    if not (isinstance(judged, list) and judged and len(set(judged)) == len(judged)
            and set(judged) <= set(LINK_PROFILES)):
        p.append(f"judged_profiles: a non-empty list of distinct link profiles from {', '.join(LINK_PROFILES)}")
    frozen = cal.get("status") == "frozen"
    ref = cal.get("drift_reference")
    if ref is None:
        if frozen:
            p.append("drift_reference: a frozen record carries the Q and p95 its drift check must reproduce")
    else:
        p += _drift_problems(ref)
    if frozen and isinstance(cal.get("host"), dict):
        p += _shape_problems(cal["host"], HOST_SHAPE, "host")
    return p


def validate(cal):
    """The record itself, or RecordError listing every problem; a frozen record must carry its hash."""
    problems = problems_of(cal)
    if not problems:
        have = cal.get("sha256")
        if cal["status"] == "frozen" and not have:
            problems.append("sha256: a frozen record carries its hash")
        elif have is not None and have != digest(cal):
            problems.append(f"sha256: {have!r} is not the hash of the record ({digest(cal)})")
    if problems:
        raise RecordError("; ".join(problems))
    return cal


def load(path):
    with open(path, encoding="utf-8") as fh:
        return validate(json.load(fh))


def dump(cal, path):
    validate(cal)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cal, fh, indent=1, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


def with_hash(cal):
    """The record with its hash set (any status)."""
    out = copy.deepcopy(cal)
    out["sha256"] = digest(out)
    return out


def freeze(cal, created_utc=None, host=None, drift_reference=None):
    """The record as a frozen one with its hash. Does not write anything. `host` and `drift_reference`, when
    given, replace the record's: a frozen record must carry both (the calibrator measures them)."""
    out = copy.deepcopy(cal)
    out["status"] = "frozen"
    if created_utc:
        out["created_utc"] = created_utc
    if host is not None:
        out["host"] = copy.deepcopy(host)
    if drift_reference is not None:
        out["drift_reference"] = copy.deepcopy(drift_reference)
    return validate(with_hash(out))


def require_frozen(cal):
    """The gate's precondition: no verdict on a placeholder."""
    if cal.get("status") != "frozen":
        raise RecordError("the calibration is a placeholder: its numbers are illustrations, not measurements")
    return cal


# --- derived quantities (never stored) ---------------------------------------------------------

def rho_rps(cal):
    """The nominal legit load: half of the SLO capacity."""
    return RHO_SHARE * cal["capacity"]["c_slo_rps"]


def mean_cost_ms(cal):
    return sum(w * cal["route_costs_ms"][k] for k, w in cal["mix"].items())


def spare_capacity(cal):
    """S = (C_slo - rho) x the mean cost of the legit mix, in CPU-seconds per second (design 3)."""
    return (cal["capacity"]["c_slo_rps"] - rho_rps(cal)) * mean_cost_ms(cal) / 1000


def knobs_of(cal):
    return O.CostKnobs(**cal["knobs"])


# --- the pure rules ----------------------------------------------------------------------------

def knee(ladder, floor, repeats=2):
    """The knee of a ladder (design 7.2 step 4): the lowest level whose harm reaches `floor` in every one of
    at least `repeats` repeats. `ladder` is [(level, [harm per repeat])]. Nothing passing is a finding, not a
    reason to tune: `level` is None and `why` says so. `monotone` is whether the mean harm never falls from
    one level to the next, the dose-response the verdict is reported next to."""
    rows = sorted(((float(level), [float(h) for h in harms]) for level, harms in ladder), key=lambda r: r[0])
    passing = [level for level, harms in rows if len(harms) >= repeats and all(h >= floor for h in harms)]
    means = [sum(h) / len(h) for _, h in rows if h]
    out = {"level": passing[0] if passing else None, "passing": passing,
           "monotone": all(b >= a for a, b in itertools.pairwise(means))}
    if not passing:
        out["why"] = CANNOT_HARM
    return out


def drift_ok(frozen_q, frozen_p95, q, p95):
    """Design 7.2 step 7: `Q` within 2 pp and p95 within 25 % of the frozen values, else no campaign starts."""
    reasons = []
    if abs(q - frozen_q) > DRIFT_Q_PP + 1e-9:
        reasons.append(f"Q {q:g} against {frozen_q:g} frozen (more than {DRIFT_Q_PP:g} pp)")
    if frozen_p95 <= 0 or abs(p95 - frozen_p95) / frozen_p95 > DRIFT_P95 + 1e-9:
        reasons.append(f"p95 {p95:g} against {frozen_p95:g} frozen (more than {DRIFT_P95:.0%})")
    return not reasons, reasons


def summary(cal):
    return {"status": cal["status"], "sha256": cal.get("sha256"), "rho_rps": rho_rps(cal),
            "mean_cost_ms": mean_cost_ms(cal), "spare_capacity_cpu_s_per_s": spare_capacity(cal),
            "c_slo_rps": cal["capacity"]["c_slo_rps"], "knees": cal["knees"],
            "judged_profiles": cal["judged_profiles"]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=("check", "show", "rehash"))
    ap.add_argument("file")
    args = ap.parse_args(argv)
    with open(args.file, encoding="utf-8") as fh:
        raw = json.load(fh)
    if args.command == "rehash":
        if raw.get("status") != "placeholder":
            print(f"{args.file}: only a placeholder is rehashed; a frozen record is never rewritten", file=sys.stderr)
            return 2
        dump(with_hash(raw), args.file)
        print(f"{args.file}: sha256 {'updated' if raw.get('sha256') else 'set'}")
        return 0
    try:
        cal = validate(raw)
    except RecordError as exc:
        print(f"{args.file}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary(cal), indent=1, sort_keys=True) if args.command == "show" else f"{args.file}: valid, {cal['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
