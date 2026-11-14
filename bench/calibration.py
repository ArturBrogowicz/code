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
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import origin as O

SCHEMA = 2                               # a record frozen by this code; schema 1 (the record of 2026-11-04, the placeholder) stays loadable
SCHEMAS = (1, 2)
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
DRIFT_Q_PP, DRIFT_P95 = 2.0, 0.25        # design 7.2 step 7, for the legit probe; an attack run has the record's gate floors (drift_attack_ok)
# the reference and the check on means (docs/RECALIBRATION_2026-11_DESIGN.md 4, D1): n reference rounds, m check rounds, and a band of
# C_TOL standard errors of the difference of two means, clamped to [half the gate's floor, the floor]
N_REF, M_DRIFT, C_TOL = 5, 3, 3.0
# the drift check's own seeds, which the reference of schema 2 uses too: the legit probe 41, then one attack run per family in sorted order
DRIFT_SEED = 41
DRIFT_FAMILIES = ("cheap_static_flood", "costly_export_flood", "costly_search_flood")
REFERENCE_V2_KEYS = ("rho_rps", "n", "seeds", "rule", "legit", "attack")
SUMMARY_KEYS = ("q_pct", "log2_p95", "mean_q_pct", "mean_log2_p95", "sd_q_pp", "sd_log2_p95")
ATTACK_V2_KEYS = ("level", *SUMMARY_KEYS, "tol_q_pp", "tol_log2", "wide_spread")


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


def drift_seeds(families=DRIFT_FAMILIES):
    """The seeds of a round of the drift check, and of the reference of schema 2: the legit probe's, and each family's attack run's."""
    return {"legit": DRIFT_SEED, "attack": {f: DRIFT_SEED + 1 + DRIFT_FAMILIES.index(f) for f in families}}


def drift_rule(gate):
    """The constants of the check on means, as a record of schema 2 keeps them: n, m, c and k = c sqrt(1/n + 1/m), the gate's floors
    that cap the tolerances (half of each is their lower bound), the legit probe's 2 pp and 25 %, and D6's line for a wide spread."""
    return {"n": N_REF, "m": M_DRIFT, "c": C_TOL, "k": C_TOL * math.sqrt(1 / N_REF + 1 / M_DRIFT),
            "floor_pp": gate["floor_pp"], "floor_log2_p95": gate["floor_log2_p95"], "legit_q_pp": DRIFT_Q_PP,
            "legit_p95": DRIFT_P95, "wide_sd_q_pp": gate["floor_pp"] / 2}


def drift_tolerance(sd, floor, k):
    """min(floor, max(floor / 2, k sd)): the band of the check on means for a spread `sd` (docs/RECALIBRATION_2026-11_DESIGN.md 4)."""
    return min(floor, max(floor / 2, k * sd))


def mean_sd(values):
    """The mean and the sample standard deviation (n - 1 in the denominator)."""
    return statistics.fmean(values), statistics.stdev(values)


def summary_of(runs):
    """Q and log2 p95 of reference runs ({"Q", "p95_s"} each), their means and SDs."""
    q = [float(r["Q"]) for r in runs]
    lg = [math.log2(r["p95_s"]) for r in runs]
    (mq, sq), (ml, sl) = mean_sd(q), mean_sd(lg)
    return {"q_pct": q, "log2_p95": lg, "mean_q_pct": mq, "mean_log2_p95": ml, "sd_q_pp": sq, "sd_log2_p95": sl}


def drift_reference_of(rho_rps, legit, attacks, gate):
    """The drift reference of schema 2 from the runs of N_REF rounds: `legit` the legit probes ({"Q", "p95_s"}), `attacks` a family ->
    {"level", "runs": [{"Q", "p95_s"}]}; per family the means and SDs of Q and of log2 p95 and the tolerances the check reads, computed
    here at the freeze and never again. A run without a Q or a p95 cannot be in a reference: ValueError."""
    rule = drift_rule(gate)
    runs = [*legit, *[r for a in attacks.values() for r in a["runs"]]]
    if any(r.get("Q") is None or not r.get("p95_s") or r["p95_s"] <= 0 for r in runs):
        raise ValueError("a reference run had no judged request or no successful one: it cannot be in a reference")
    if len(legit) != N_REF or any(len(a["runs"]) != N_REF for a in attacks.values()):
        raise ValueError(f"a reference of schema 2 is {N_REF} rounds, no more and no fewer")
    out = {"rho_rps": rho_rps, "n": N_REF, "seeds": drift_seeds(sorted(attacks)), "rule": rule, "legit": summary_of(legit),
           "attack": {}}
    for family, a in sorted(attacks.items()):
        s = summary_of(a["runs"])
        out["attack"][family] = {"level": a["level"], **s,
                                 "tol_q_pp": drift_tolerance(s["sd_q_pp"], rule["floor_pp"], rule["k"]),
                                 "tol_log2": drift_tolerance(s["sd_log2_p95"], rule["floor_log2_p95"], rule["k"]),
                                 "wide_spread": s["sd_q_pp"] > rule["wide_sd_q_pp"]}
    return out


def _close(a, b):
    return isinstance(a, (int, float)) and not isinstance(a, bool) and abs(a - b) <= 1e-9


def _summary_problems(p, where, item, n):
    """A summary block of schema 2: n values of Q (0 to 100) and of log2 p95 (finite), and means and SDs that are theirs."""
    q, lg = item["q_pct"], item["log2_p95"]
    if not (isinstance(q, list) and len(q) == n and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                                                         and math.isfinite(v) and 0 <= v <= 100 for v in q)):
        p.append(f"{where}.q_pct: {n} values of Q between 0 and 100")
        return
    if not (isinstance(lg, list) and len(lg) == n and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                                                          and math.isfinite(v) for v in lg)):
        p.append(f"{where}.log2_p95: {n} finite numbers")
        return
    (mq, sq), (ml, sl) = mean_sd(q), mean_sd(lg)
    for key, want in (("mean_q_pct", mq), ("sd_q_pp", sq), ("mean_log2_p95", ml), ("sd_log2_p95", sl)):
        if not _close(item[key], want):
            p.append(f"{where}.{key}: {item[key]!r} is not that of its runs ({want!r})")


def _drift_v2_problems(ref, gate):
    """The drift reference of schema 2 (docs/RECALIBRATION_2026-11_DESIGN.md 4, K1): N_REF rounds on the drift's own seeds, every
    run's Q and log2 p95, their means and SDs, the rule's constants and the tolerances they give."""
    if not isinstance(ref, dict) or set(ref) != set(REFERENCE_V2_KEYS):
        return [f"drift_reference: {', '.join(REFERENCE_V2_KEYS)} (schema 2)"]
    p = []
    _positive(p, "drift_reference.rho_rps", ref["rho_rps"])
    n = ref["n"]
    if not (isinstance(n, int) and not isinstance(n, bool) and n == N_REF):
        return p + [f"drift_reference.n: {N_REF} rounds, no more and no fewer, got {n!r}"]
    rule = drift_rule(gate) if isinstance(gate, dict) and {"floor_pp", "floor_log2_p95"} <= set(gate) else None
    if ref["rule"] != rule:
        p.append(f"drift_reference.rule: {rule!r}, got {ref['rule']!r}")
    legit, attack = ref["legit"], ref["attack"]
    if not isinstance(legit, dict) or set(legit) != set(SUMMARY_KEYS):
        p.append(f"drift_reference.legit: {', '.join(SUMMARY_KEYS)}")
    else:
        _summary_problems(p, "drift_reference.legit", legit, n)
    if not isinstance(attack, dict):
        return p + ["drift_reference.attack: an object of family -> its runs, means, SDs and tolerances"]
    if set(attack) - set(DRIFT_FAMILIES):
        return p + [f"drift_reference.attack: families of the drift check only ({', '.join(DRIFT_FAMILIES)})"]
    if ref["seeds"] != drift_seeds(sorted(attack)):
        p.append(f"drift_reference.seeds: the drift check's own, {drift_seeds(sorted(attack))!r}, got {ref['seeds']!r}")
    for family, item in attack.items():
        where = f"drift_reference.attack.{family}"
        if not isinstance(item, dict) or set(item) != set(ATTACK_V2_KEYS):
            p.append(f"{where}: {', '.join(ATTACK_V2_KEYS)}")
            continue
        before = len(p)
        _positive(p, where + ".level", item["level"])
        _summary_problems(p, where, item, n)
        if rule and len(p) == before:
            for key, sd, floor in (("tol_q_pp", item["sd_q_pp"], rule["floor_pp"]),
                                   ("tol_log2", item["sd_log2_p95"], rule["floor_log2_p95"])):
                if not _close(item[key], drift_tolerance(sd, floor, rule["k"])):
                    p.append(f"{where}.{key}: {item[key]!r} is not the rule's for its SD")
            if item["wide_spread"] is not (item["sd_q_pp"] > rule["wide_sd_q_pp"]):
                p.append(f"{where}.wide_spread: true exactly when the SD of Q is above {rule['wide_sd_q_pp']:g} pp (D6)")
    return p


def problems_of(cal):
    """Every way in which `cal` departs from the schema (not the hash)."""
    p = []
    if not isinstance(cal, dict):
        return ["the record is not an object"]
    if cal.get("schema") not in SCHEMAS:
        p.append(f"schema: one of {', '.join(map(str, SCHEMAS))}, got {cal.get('schema')!r}")
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
    elif cal.get("schema") == 2:
        p += _drift_v2_problems(ref, gate)
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
    """Design 7.2 step 7, for the legit probe: `Q` within 2 pp and p95 within 25 % of the frozen values, else no campaign starts."""
    reasons = []
    if abs(q - frozen_q) > DRIFT_Q_PP + 1e-9:
        reasons.append(f"Q {q:g} against {frozen_q:g} frozen (more than {DRIFT_Q_PP:g} pp)")
    if frozen_p95 <= 0 or abs(p95 - frozen_p95) / frozen_p95 > DRIFT_P95 + 1e-9:
        reasons.append(f"p95 {p95:g} against {frozen_p95:g} frozen (more than {DRIFT_P95:.0%})")
    return not reasons, reasons


def drift_attack_ok(gate, frozen_q, frozen_p95, q, p95):
    """Design 7.2 step 7 for an attack run, as departed from on 2026-11-04 (docs/HG1C_DESIGN.md departure 33, D-062): `Q` within the
    record's gate.floor_pp and p95 within its gate.floor_log2_p95, in log2, of the frozen values, else no campaign starts. The reasons
    name the tolerance that failed. A `Q` or a p95 that is missing, or a p95 that is not positive, cannot be compared and fails."""
    floor_pp, floor_log2 = gate["floor_pp"], gate["floor_log2_p95"]
    reasons = []
    if q is None or abs(q - frozen_q) > floor_pp + 1e-9:
        reasons.append(f"Q {'none' if q is None else format(q, 'g')} against {frozen_q:g} frozen (more than the gate's floor_pp, {floor_pp:g} pp)")
    if p95 is None or p95 <= 0 or frozen_p95 <= 0:
        reasons.append(f"p95 {'none' if p95 is None else format(p95, 'g')} against {frozen_p95:g} frozen (cannot be compared)")
    elif abs(math.log2(p95 / frozen_p95)) > floor_log2 + 1e-9:
        reasons.append(f"p95 {p95:g} against {frozen_p95:g} frozen (more than the gate's floor_log2_p95, a factor of {2 ** floor_log2:g})")
    return not reasons, reasons


def _means(runs):
    """Mean Q and mean log2 p95 of check runs, or None when a run has no Q or no p95 (no served request): it cannot be compared."""
    if not runs or any(r.get("Q") is None or not r.get("p95_s") or r["p95_s"] <= 0 for r in runs):
        return None
    return statistics.fmean(float(r["Q"]) for r in runs), statistics.fmean(math.log2(r["p95_s"]) for r in runs)


def drift_means_check(ref, legit, attacks):
    """The drift check on means against a reference of schema 2 (docs/RECALIBRATION_2026-11_DESIGN.md 4, K2). `legit` is the check's
    legit probes ({"Q", "p95_s"} each), `attacks` a family -> its check runs. A family passes when |mean Q - the reference's| <= its
    tol_q_pp and |mean log2 p95 - the reference's| <= its tol_log2, the tolerances as frozen in the record; the legit probe when its mean
    Q is within the rule's legit_q_pp and 2^(the difference of the mean log2 p95) within [1 - legit_p95, 1 + legit_p95]. Every bound is
    inclusive. A run without a Q or a p95 fails its family; a failed legit probe confirms no family. Read per family: `confirmed`."""
    rule = ref["rule"]
    out = {"rule": rule, "legit": None, "families": {}, "confirmed": {}}
    got = _means(legit)
    leg = {"n": len(legit), "ref_mean_q_pct": ref["legit"]["mean_q_pct"], "ref_mean_log2_p95": ref["legit"]["mean_log2_p95"],
           "tol_q_pp": rule["legit_q_pp"], "p95_ratio_band": [1 - rule["legit_p95"], 1 + rule["legit_p95"]], "reasons": []}
    if got is None:
        leg.update(mean_q_pct=None, mean_log2_p95=None, ok=False)
        leg["reasons"].append("a legit probe without a Q or a p95: it cannot be compared")
    else:
        dq, dl = got[0] - leg["ref_mean_q_pct"], got[1] - leg["ref_mean_log2_p95"]
        ratio = 2 ** dl
        leg.update(mean_q_pct=got[0], mean_log2_p95=got[1], dq_pp=dq, p95_ratio=ratio)
        if not abs(dq) <= rule["legit_q_pp"]:
            leg["reasons"].append(f"mean Q {got[0]:.4g} against {leg['ref_mean_q_pct']:.4g} (more than {rule['legit_q_pp']:g} pp)")
        if not leg["p95_ratio_band"][0] <= ratio <= leg["p95_ratio_band"][1]:
            leg["reasons"].append(f"mean p95 a factor of {ratio:.4g} of the reference's (outside {leg['p95_ratio_band'][0]:g} to "
                                  f"{leg['p95_ratio_band'][1]:g})")
        leg["ok"] = not leg["reasons"]
    out["legit"] = leg
    for family, runs in sorted(attacks.items()):
        r = ref["attack"][family]
        got = _means(runs)
        row = {"n": len(runs), "level": r["level"], "ref_mean_q_pct": r["mean_q_pct"], "ref_mean_log2_p95": r["mean_log2_p95"],
               "tol_q_pp": r["tol_q_pp"], "tol_log2": r["tol_log2"], "wide_spread": r["wide_spread"], "reasons": []}
        if got is None:
            row.update(mean_q_pct=None, mean_log2_p95=None)
            row["reasons"].append("a run without a Q or a p95 (no served request): it cannot be compared")
        else:
            dq, dl = got[0] - r["mean_q_pct"], got[1] - r["mean_log2_p95"]
            row.update(mean_q_pct=got[0], mean_log2_p95=got[1], dq_pp=dq, dlog2_p95=dl)
            if not abs(dq) <= r["tol_q_pp"]:
                row["reasons"].append(f"mean Q {got[0]:.4g} against {r['mean_q_pct']:.4g} (more than {r['tol_q_pp']:.4g} pp)")
            if not abs(dl) <= r["tol_log2"]:
                row["reasons"].append(f"mean log2 p95 {dl:+.4g} from the reference's (more than {r['tol_log2']:.4g})")
        row["ok"] = not row["reasons"]
        out["families"][family] = row
        out["confirmed"][family] = leg["ok"] and row["ok"]
    return out


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
