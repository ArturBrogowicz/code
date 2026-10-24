#!/usr/bin/env python3
"""The scenario record of the harm benchmark and its offline plan (docs/BENCHMARK_HARM_DESIGN.md Appendix B,
docs/HG1B_MINIMAL_DESIGN.md 5.4).

A scenario is a JSON record: the family, the route classes, the intensity as a cost rate in units of the
spare capacity S, the number of sources, the arrival process, the timeline, the seed namespace, the gate's
blocks and metrics, and the attack-free scenario it is paired with. The SLO table and the floors are the
calibration's (frozen and hashed with it), so they are not repeated here. Nothing in a record says how a
client avoids a detector: a source's behaviour is a rate, a route mix and a schedule.

`--plan` prints, without root, without a socket and without a process, what a block of the scenario would
be: the entity seeds, the legit load and its route mix against the calibration's, the attack's cost rate and
each source's rate against the deployed per-source rules, the load on the generator, and the gate class the
cost-rate model expects. The deployed thresholds are printed and never used: no intensity is chosen, moved
or clipped by them (a test changes them and checks that nothing moves).

    python3 bench/scenario.py --plan bench/scenarios/costly_search_sub_threshold.json
    python3 bench/scenario.py --check bench/scenarios/*.json
"""
import argparse
import collections
import dataclasses
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import calibration as C
import origin as O
import population as P

SCHEMA = 1
KEYS = ("schema", "id", "description", "family", "class", "grounding", "resource", "routes", "intensity",
        "sources", "arrival", "benign", "netem", "timeline", "seed_namespace", "first_seed", "gate", "controls")
OPTIONAL = ("description", "first_seed")
BENIGN = "benign"                                  # the family of an attack-free scenario
THREAT_CLASSES = tuple("ABCDEFG")                  # REPORT 11.2
RESOURCES = ("app_cpu", "worker_slots", "accept_queue", "packet_processing", "bandwidth")      # design 7.1
LADDER_UNIT = "cost_rate_S"
METRICS = ("Q", "p95")
NETEM = "suite_mix"                                # the one link-profile distribution of every class
PLACEBO = "repeat"                                 # a second attack-free run of the same population
ID_RE = re.compile(r"[a-z0-9][a-z0-9_]{0,63}")
MIN_PHASE_S = 5.0                                  # the recovery rule needs five 1-s bins
LIKELY_PASS_A, LIKELY_FAIL_A = 2.0, 0.5            # Appendix B: the cost-rate model's first-order reading
MIX_TOLERANCE_PP = 3.0                             # the legit route mix against the calibration's
JUDGED_SHARE_MIN = 0.5                             # the share of the legit requests that the judged links must carry
URL = "http://10.0.0.1/"                           # only to build the engine commands whose sizes are printed


@dataclasses.dataclass(frozen=True)
class Threshold:
    name: str
    limit: float                                   # requests/s from one source
    where: str
    effect: str


# What is deployed, printed and never used to pick an intensity. tests/test_scenario.py reads the same
# numbers out of nginx.conf and control_plane.py.
LIMIT_REQ_RATE, LIMIT_REQ_BURST = 30.0, 100        # nginx.conf: limit_req_zone rate=30r/s, limit_req burst=100 nodelay
LIMIT_CONN = 50                                    # nginx.conf: limit_conn connlimit 50
L7_MAX_RPS, L7_WINDOW_S = 50.0, 10                 # control_plane.py: HEURISTIC_MAX_RPS, HEURISTIC_WINDOW
ERROR_RATIO, ERROR_RATIO_MIN_RPS = 0.8, 10         # control_plane.py: the error-ratio branch of the L7 rule
SLOWCONN_CONNS = 8                                 # control_plane.py: SLOWCONN_CONN_THRESHOLD
RATE_THRESHOLDS = (
    Threshold("limit_req", LIMIT_REQ_RATE, f"nginx.conf: rate={LIMIT_REQ_RATE:g}r/s per source, "
                                           f"burst={LIMIT_REQ_BURST} nodelay", "Nginx rejects what exceeds the bucket"),
    Threshold("l7_rule", L7_MAX_RPS, f"control_plane.py: HEURISTIC_MAX_RPS over a {L7_WINDOW_S} s window",
              "the daemon bans the source"),
)


class ScenarioError(ValueError):
    """The record does not meet the schema, or it cannot be planned."""


# --- the record --------------------------------------------------------------------------------

def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _attack_problems(raw, fam):
    """The fields that describe the attack: empty in a control, tied to the family in an attack."""
    p = []
    if raw.get("family") == BENIGN:
        for key, want in (("routes", {}), ("intensity", None), ("sources", 0), ("arrival", None), ("gate", None),
                          ("controls", None)):
            if key in raw and (raw[key] != want or type(raw[key]) is not type(want)):
                p.append(f"{key}: {want!r} in an attack-free scenario, got {raw[key]!r}")
        return p
    if fam is None:
        return p
    if raw.get("routes") != {fam.route_class: 1.0}:
        p.append(f"routes: {{{fam.route_class!r}: 1.0}} for {fam.name}, got {raw.get('routes')!r}")
    it = raw.get("intensity")
    if not isinstance(it, dict) or set(it) != {"unit", "ladder", "level"}:
        p.append("intensity: unit, ladder and level")
    else:
        if it["unit"] != LADDER_UNIT:
            p.append(f"intensity.unit: {LADDER_UNIT!r} (a cost rate in units of the spare capacity), got {it['unit']!r}")
        ladder = it["ladder"]
        if not (isinstance(ladder, list) and ladder and all(_num(x) and x > 0 for x in ladder)
                and ladder == sorted(set(ladder))):
            p.append("intensity.ladder: a strictly increasing list of positive numbers")
        if not (it["level"] == "knee" or (_num(it["level"]) and it["level"] > 0)):
            p.append("intensity.level: a positive number, or 'knee' for the level the calibration recorded")
    hosts = sum(len(list(net.hosts())) for net in P.ATTACK_NETS)
    if not (_int(raw.get("sources")) and 1 <= raw["sources"] <= hosts):
        p.append(f"sources: an integer from 1 to {hosts} (the attack addresses), got {raw.get('sources')!r}")
    ar = raw.get("arrival")
    if not isinstance(ar, dict) or set(ar) != {"process", "loop"}:
        p.append("arrival: process and loop")
    else:
        if ar["process"] != fam.process:
            p.append(f"arrival.process: {fam.process!r} for {fam.name}, got {ar['process']!r}")
        if ar["loop"] != "open":
            p.append("arrival.loop: 'open' (the in-repo engine is open-loop; closed-loop generators are the suite's)")
    gate = raw.get("gate")
    if not isinstance(gate, dict) or set(gate) != {"blocks", "metrics"}:
        p.append("gate: blocks and metrics")
    else:
        if not (_int(gate["blocks"]) and gate["blocks"] >= 3):
            p.append("gate.blocks: an integer of at least 3")
        m = gate["metrics"]
        if not (isinstance(m, list) and m and len(set(m)) == len(m) and set(m) <= set(METRICS)):
            p.append(f"gate.metrics: a non-empty subset of {', '.join(METRICS)}")
    ctl = raw.get("controls")
    if not isinstance(ctl, dict) or set(ctl) != {"control", "placebo"}:
        p.append("controls: control and placebo")
    else:
        if not (isinstance(ctl["control"], str) and ID_RE.fullmatch(ctl["control"])):
            p.append("controls.control: the id of the attack-free scenario it is paired with")
        if ctl["placebo"] != PLACEBO:
            p.append(f"controls.placebo: {PLACEBO!r} (a second attack-free run), got {ctl['placebo']!r}")
    return p


def _common_problems(raw):
    p = []
    b = raw.get("benign")
    if not isinstance(b, dict) or set(b) != {"identities", "per_profile"}:
        p.append("benign: identities and per_profile")
    else:
        top = sum(len(list(net.hosts())) for net in P.BENIGN_NETS)
        if not (_int(b["identities"]) and len(P.BENIGN_CLASSES) <= b["identities"] <= top):
            p.append(f"benign.identities: an integer from {len(P.BENIGN_CLASSES)} (one a class) to {top} "
                     "(the benign addresses)")
        if not (_int(b["per_profile"]) and 1 <= b["per_profile"] <= 6):
            p.append("benign.per_profile: an integer from 1 to 6 (client namespaces per link profile)")
    if raw.get("netem") != NETEM:
        p.append(f"netem: {NETEM!r}, the one distribution of every class, got {raw.get('netem')!r}")
    t = raw.get("timeline")
    if not isinstance(t, dict) or set(t) != {"baseline_s", "attack_s", "recovery_s"}:
        p.append("timeline: baseline_s, attack_s and recovery_s")
    elif not all(_num(v) and v >= MIN_PHASE_S for v in t.values()):
        p.append(f"timeline: every phase at least {MIN_PHASE_S:g} s (the recovery rule needs five 1-s bins)")
    ns = raw.get("seed_namespace")
    if ns not in P.SEED_RANGES:
        p.append(f"seed_namespace: one of {', '.join(P.SEED_RANGES)}, got {ns!r}")
    else:
        r = P.SEED_RANGES[ns]
        first = raw.get("first_seed", r.start)
        gate = raw.get("gate")
        blocks = gate["blocks"] if isinstance(gate, dict) and _int(gate.get("blocks")) else 1
        if not (_int(first) and first in r and first + blocks - 1 in r):
            p.append(f"first_seed: an integer such that the seeds first_seed .. first_seed + blocks - 1 lie in "
                     f"{ns} ({r.start}-{r.stop - 1})")
    return p


def problems_of(raw):
    """Every way in which `raw` departs from the schema."""
    if not isinstance(raw, dict):
        return ["the record is not an object"]
    p = []
    unknown, missing = sorted(set(raw) - set(KEYS)), sorted(set(KEYS) - set(OPTIONAL) - set(raw))
    if unknown:
        p.append(f"unknown keys: {', '.join(unknown)}")
    if missing:
        p.append(f"missing keys: {', '.join(missing)}")
    if not _int(raw.get("schema")) or raw["schema"] != SCHEMA:
        p.append(f"schema: {SCHEMA}, got {raw.get('schema')!r}")
    if not (isinstance(raw.get("id"), str) and ID_RE.fullmatch(raw["id"])):
        p.append("id: lower-case letters, digits and underscores, at most 64")
    if not isinstance(raw.get("description", ""), str):
        p.append("description: a string")
    family = raw.get("family")
    fam = P.ATTACK_FAMILIES.get(family) if isinstance(family, str) else None
    if family != BENIGN and fam is None:
        p.append(f"family: {BENIGN} or one of {', '.join(P.ATTACK_FAMILIES)}, got {family!r}")
    if raw.get("class") not in THREAT_CLASSES:
        p.append(f"class: one of {', '.join(THREAT_CLASSES)} (REPORT 11.2), got {raw.get('class')!r}")
    if not (isinstance(raw.get("grounding"), str) and raw["grounding"].strip()):
        p.append("grounding: the external reference, or 'assumed'")
    if raw.get("resource") not in RESOURCES:
        p.append(f"resource: one of {', '.join(RESOURCES)}, got {raw.get('resource')!r}")
    return p + _attack_problems(raw, fam) + _common_problems(raw)


@dataclasses.dataclass(frozen=True)
class Scenario:
    id: str
    description: str
    family: str
    threat_class: str
    grounding: str
    resource: str
    intensity: dict | None
    sources: int
    benign_identities: int
    per_profile: int
    timeline: P.Timeline
    seed_namespace: str
    first_seed: int
    gate: dict | None
    controls: dict | None

    @property
    def is_control(self):
        return self.family == BENIGN


def from_record(raw):
    problems = problems_of(raw)
    if problems:
        raise ScenarioError("; ".join(problems))
    t = raw["timeline"]
    return Scenario(raw["id"], raw.get("description", ""), raw["family"], raw["class"], raw["grounding"],
                    raw["resource"], raw["intensity"], raw["sources"], raw["benign"]["identities"],
                    raw["benign"]["per_profile"], P.Timeline(float(t["baseline_s"]), float(t["attack_s"]),
                                                             float(t["recovery_s"])),
                    raw["seed_namespace"], raw.get("first_seed", P.SEED_RANGES[raw["seed_namespace"]].start),
                    raw["gate"], raw["controls"])


def load(path):
    with open(path, encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ScenarioError(f"{path}: not JSON ({exc})") from exc
    try:
        return from_record(raw)
    except ScenarioError as exc:
        raise ScenarioError(f"{path}: {exc}") from exc


def pair_problems(scn, control):
    """What makes `control` unfit to be paired with `scn`: a block is one population, one rho and one timeline."""
    p = []
    if not control.is_control:
        p.append(f"{control.id} is not attack-free (family {control.family})")
    if scn.controls and scn.controls["control"] != control.id:
        p.append(f"{scn.id} is paired with {scn.controls['control']}, not {control.id}")
    for field in ("benign_identities", "per_profile", "timeline", "seed_namespace", "first_seed"):
        if getattr(scn, field) != getattr(control, field):
            p.append(f"{field}: {getattr(scn, field)!r} in {scn.id}, {getattr(control, field)!r} in {control.id}")
    return p


def resolve_level(scn, cal):
    """The level in units of S: the number in the record, or the knee the calibration recorded for the family."""
    level = scn.intensity["level"]
    if level != "knee":
        return float(level)
    knee = cal["knees"].get(scn.family)
    if not _num(knee):
        raise ScenarioError(f"level 'knee' needs a knee for {scn.family} in the calibration (the ladder of HG2 "
                            f"records it); it holds {knee!r}")
    return float(knee)


# --- the plan ----------------------------------------------------------------------------------

def _cpu_count(cpus):
    """The number of CPUs in a taskset list such as '3-5,7'."""
    n = 0
    for part in cpus.split(","):
        lo, _, hi = part.partition("-")
        n += int(hi or lo) - int(lo) + 1
    return n


def expected_gate(level):
    """The cost-rate model's first-order reading (Appendix B); the ladder, not the model, finds the knee."""
    if level is None:
        return {"class": "n/a", "basis": "no attack in this scenario"}
    if level >= LIKELY_PASS_A:
        verdict = "likely PASS"
    elif level <= LIKELY_FAIL_A:
        verdict = "likely FAIL"
    else:
        verdict = "cannot say"
    return {"class": verdict, "basis": f"A = {level:g} S; PASS is expected from {LIKELY_PASS_A:g}, FAIL up to "
                                       f"{LIKELY_FAIL_A:g}; first order"}


def _entities(pop):
    counts = collections.Counter(i.role for i in pop.identities)
    return [{"role": role, "n": n, "first": P.entity_seed(pop.namespace, pop.seed, role, 0),
             "last": P.entity_seed(pop.namespace, pop.seed, role, n - 1)} for role, n in counts.items()]


def _benign(pop, cal, rho, capacity):
    costs = cal["route_costs_ms"]
    counts = collections.Counter(i.cls for i in pop.identities if i.role.startswith("benign:"))
    classes = []
    for c in P.BENIGN_CLASSES:
        rate = rho * c.rate_share
        cost = rate * sum(w * costs[r] for r, w in c.routes) / 1000
        classes.append({"name": c.name, "basis": c.basis, "process": c.process, "identities": counts[c.name],
                        "rate_share": c.rate_share, "rate": rate, "cost_cpu_s": cost, "utilisation": cost / capacity})
    drawn = pop.route_rates("legit")
    total = sum(drawn.values())
    cost = sum(rate * costs[k] for k, rate in drawn.items()) / 1000
    mix = [{"route": k, "drawn": drawn.get(k, 0.0) / total, "calibration": cal["mix"].get(k, 0.0)}
           for k in O.CLASSES if k in drawn or k in cal["mix"]]
    legit = pop.of_kind("legit")
    links = {p: sum(s.rate for s in legit if s.netem == p) / total for p in C.LINK_PROFILES}
    judged = list(cal["judged_profiles"])
    return {"rho": rho, "classes": classes, "drawn_rate": total, "drawn_cost_cpu_s": cost,
            "drawn_utilisation": cost / capacity, "mix": mix,
            "mix_gap_pp": 100 * max(abs(m["drawn"] - m["calibration"]) for m in mix),
            "link_shares": links, "judged_profiles": judged, "judged_share": sum(links[p] for p in judged)}


def _attack(scn, pop, cal, level, spare, capacity):
    if level is None:
        return None
    route = P.ATTACK_FAMILIES[scn.family].route_class
    cost_ms = cal["route_costs_ms"][route]
    total = sum(pop.route_rates("attack").values())
    cost = total * cost_ms / 1000
    per_source = total / scn.sources
    rows = []
    for t in RATE_THRESHOLDS:
        needed = math.floor(total / t.limit) + 1
        rows.append({"name": t.name, "limit": t.limit, "where": t.where, "effect": t.effect, "per_source": per_source,
                     "ratio": per_source / t.limit, "above": per_source > t.limit, "sources_to_fall_below": needed,
                     "below": scn.sources >= needed})
    limits = {t.name: t.limit for t in RATE_THRESHOLDS}
    limit_req, l7 = limits["limit_req"], limits["l7_rule"]
    reject = max(0.0, 1 - limit_req / per_source)
    ladder = scn.intensity["ladder"]
    knees = cal["knees"]
    return {"family": scn.family, "route": route, "route_cost_ms": cost_ms, "level": level, "ladder": ladder,
            "on_ladder": level in ladder, "knee": knees.get(scn.family) if scn.family in knees else "not measured",
            "spare_cpu_s": spare, "sources": scn.sources, "total_rate": total, "per_source_rate": per_source,
            "cost_cpu_s": cost, "cost_in_s": cost / spare, "utilisation": cost / capacity,
            "thresholds": rows,
            "rules": {"limit_req_sheds": per_source > limit_req, "reject_share": reject,
                      "l7_rule_bans": per_source > l7,
                      "error_ratio_branch": reject > ERROR_RATIO and per_source > ERROR_RATIO_MIN_RPS},
            "connections": {"pool": P.POOL["attack"], "in_flight": per_source * cost_ms / 1000,
                            "limit_conn": LIMIT_CONN, "slowconn": SLOWCONN_CONNS}}


def _generator(pop, cal):
    kinds = {}
    for kind in ("legit", "attack"):
        streams = pop.of_kind(kind)
        if not streams:
            continue
        specs = [P.to_load_spec(s, URL) for s in streams]
        rate = sum(s.rate for s in streams)
        cpus = _cpu_count(P.PIN_PLAN[kind])
        cores = rate * P.CPU_MS_PER_REQUEST / 1000
        kinds[kind] = {"streams": len(streams), "rate": rate, "max_stream_rate": max(s.rate for s in streams),
                       "inflight": max(s.rate * sp.timeout for s, sp in zip(streams, specs, strict=True)),
                       "cap": specs[0].max_workers,
                       "pin": P.PIN_PLAN[kind], "cpus": cpus, "cores": cores, "share": cores / cpus,
                       "keepalive": sum(len(s.addresses) * sp.connections for s, sp in zip(streams, specs, strict=True)),
                       "nofile": max(P.nofile_for(s, sp) for s, sp in zip(streams, specs, strict=True)),
                       "split": len(streams) - len({(s.process, s.route_class, s.netem, s.ns_index) for s in streams})}
    return {"ceiling_rps": P.ENGINE_CEILING_RPS, "ms_per_request": P.CPU_MS_PER_REQUEST,
            "cpu_share_limit": cal["validity"]["cpu_share"], "kinds": kinds, "processes": len(pop.streams),
            "memory_mb": len(pop.streams) * P.PROCESS_MB}


def _a(word):
    return "an" if word[:1] in "aeiou" else "a"


def _warnings(scn, cal, out):
    w = []
    if cal["status"] != "frozen":
        w.append("the calibration is a placeholder: every cost, rate and capacity here is an illustration, and the "
                 "harm gate refuses a verdict on it")
    if out["benign"]["mix_gap_pp"] > MIX_TOLERANCE_PP:
        w.append(f"the legit route mix is {out['benign']['mix_gap_pp']:.1f} pp from the calibration's "
                 f"(more than {MIX_TOLERANCE_PP:g} pp)")
    if out["benign"]["judged_share"] < JUDGED_SHARE_MIN:
        w.append(f"only {out['benign']['judged_share']:.1%} of the legit requests are on the judged links "
                 f"({', '.join(out['benign']['judged_profiles'])}): the gate would rest on a minority of the clients")
    a = out["attack"]
    if a:
        if scn.grounding.strip().lower() == "assumed":
            w.append("the attack family's grounding is 'assumed': no external reference motivates it")
        if scn.intensity["level"] != "knee" and not a["on_ladder"]:
            w.append(f"the level {a['level']:g} is not on the ladder")
        if a["knee"] is None:
            w.append(f"the calibration records that {scn.family} cannot harm this server within the generator limit")
        elif _num(a["knee"]) and a["level"] < a["knee"]:
            w.append(f"the level {a['level']:g} is below the recorded knee {a['knee']:g}: no measurable harm is expected")
    g = out["generator"]
    for kind, k in g["kinds"].items():
        if k["share"] > g["cpu_share_limit"]:
            w.append(f"the {kind} generator needs {k['share']:.0%} of its CPUs (the validity limit is "
                     f"{g['cpu_share_limit']:.0%}): the run would be invalid")
        if k["max_stream_rate"] > g["ceiling_rps"]:
            w.append(f"{_a(kind)} {kind} stream plans {k['max_stream_rate']:.0f} req/s, above the engine's ceiling of "
                     f"{g['ceiling_rps']} req/s")
        if k["inflight"] >= k["cap"]:
            w.append(f"{_a(kind)} {kind} stream could have {k['inflight']:.0f} requests in flight, at or above the engine's cap "
                     f"of {k['cap']}: a stalled server would make it drop requests, and whether the run is valid "
                     "would depend on the attack's effect")
    if scn.gate and scn.gate["blocks"] < cal["gate"]["min_blocks"]:
        w.append(f"{scn.gate['blocks']} blocks are fewer than the {cal['gate']['min_blocks']} the gate needs: "
                 "the verdict would be INVALID by construction")
    return w


def population_of(scn, cal, seed, attack=True, rho=None):
    """The population of one block of `scn` and the level of its attack (None without one): the draw that the plan and
    the executor both make. `attack=False` draws the attack-free runs, C and Cp, whose legit streams are the attack
    run's. `rho` replaces the calibration's nominal load, for a smoke test."""
    try:
        P.check_seed(scn.seed_namespace, seed)
    except ValueError as exc:
        raise ScenarioError(str(exc)) from exc
    level = None if scn.is_control or not attack else resolve_level(scn, cal)
    drawn = None
    if level is not None:
        route = P.ATTACK_FAMILIES[scn.family].route_class
        drawn = (scn.family, scn.sources, P.attack_rate(level, C.spare_capacity(cal), cal["route_costs_ms"][route]))
    try:
        pop = P.draw(scn.seed_namespace, seed, C.rho_rps(cal) if rho is None else rho, scn.benign_identities, drawn,
                     scn.timeline, scn.per_profile)
    except ValueError as exc:
        raise ScenarioError(str(exc)) from exc
    return pop, level


def plan(scn, cal, seed=None):
    """What one block of `scn` would be, as plain data. Pure: no clock, no network, no process."""
    seed = scn.first_seed if seed is None else seed
    rho, spare = C.rho_rps(cal), C.spare_capacity(cal)
    pop, level = population_of(scn, cal, seed)
    capacity = cal["capacity"]["c_slo_rps"] * C.mean_cost_ms(cal) / 1000          # CPU-s/s at the SLO capacity
    first = scn.first_seed
    blocks = scn.gate["blocks"] if scn.gate else 1
    out = {
        "scenario": {"id": scn.id, "kind": "control" if scn.is_control else "attack", "family": scn.family,
                     "class": scn.threat_class, "grounding": scn.grounding, "resource": scn.resource,
                     "description": scn.description, "seed_namespace": scn.seed_namespace, "seed": seed,
                     "seeds": [first, first + blocks - 1], "blocks": blocks if scn.gate else None,
                     "control": scn.controls["control"] if scn.controls else None,
                     "timeline": dataclasses.asdict(scn.timeline) | {"total_s": scn.timeline.total_s},
                     "metrics": scn.gate["metrics"] if scn.gate else None},
        "calibration": {"status": cal["status"], "sha8": (cal.get("sha256") or C.digest(cal))[:8],
                        "created_utc": cal["created_utc"], "c_slo_rps": cal["capacity"]["c_slo_rps"],
                        "c_sat_rps": cal["capacity"]["c_sat_rps"], "mean_cost_ms": C.mean_cost_ms(cal),
                        "spare_cpu_s": spare, "capacity_cpu_s": capacity,
                        "floor_pp": cal["gate"]["floor_pp"], "min_blocks": cal["gate"]["min_blocks"]},
        "entities": _entities(pop),
        "benign": _benign(pop, cal, rho, capacity),
        "attack": _attack(scn, pop, cal, level, spare, capacity),
        "generator": _generator(pop, cal),
        "namespaces": [{"index": n.index, "name": n.name, "netem": n.netem,
                        "aliases": len(pop.alias_plan().get(n.index, ()))} for n in pop.namespaces],
        "streams": [{"id": s.id, "kind": s.kind, "route": s.route_class, "process": s.process, "rate": s.rate,
                     "addresses": len(s.addresses), "netem": s.netem, "ns": s.ns_index, "pin": P.PIN_PLAN[s.cpu],
                     "start_s": s.start_s, "duration_s": s.duration_s, "seed": s.seed} for s in pop.streams],
        "expected_gate": expected_gate(level),
    }
    out["warnings"] = _warnings(scn, cal, out)
    return out


# --- the text ----------------------------------------------------------------------------------

def _table(header, rows, aligns, indent=2):
    widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header))]
    lines = []
    for r in [header, *rows]:
        cells = [str(c).ljust(w) if a == "<" else str(c).rjust(w) for c, w, a in zip(r, widths, aligns, strict=True)]
        lines.append(" " * indent + "  ".join(cells).rstrip())
    return lines


def _kv(label, text):
    return f"{label:<14}{text}"


def _pp(share):
    """A difference of shares in percentage points, without a negative zero."""
    return f"{round(100 * share, 1) + 0.0:+.1f} pp"


def render(p):
    s, c, b, a, g = p["scenario"], p["calibration"], p["benign"], p["attack"], p["generator"]
    t = s["timeline"]
    out = [f"== {s['id']}: {s['kind']}, {s['family']}, class {s['class']} =="]
    if s["description"]:
        out.append(s["description"])
    if c["status"] == "frozen":
        out.append(_kv("calibration", f"frozen sha256:{c['sha8']} ({c['created_utc']})"))
    else:
        out.append(_kv("calibration", f"PLACEHOLDER sha256:{c['sha8']}: illustrative numbers, not measurements; "
                                      "nothing below is a result"))
    out.append(_kv("grounding", s["grounding"]))
    out.append(_kv("resource", s["resource"]))
    seeds = f"{s['seed_namespace']} {s['seed']} (this plan)"
    if s["blocks"]:
        seeds += f"; {s['blocks']} blocks use {s['seed_namespace']} {s['seeds'][0]}-{s['seeds'][1]}"
    out.append(_kv("seeds", seeds))
    out.append(_kv("timeline", f"{t['baseline_s']:g} s baseline + {t['attack_s']:g} s attack + {t['recovery_s']:g} s "
                               f"recovery = {t['total_s']:g} s a run" + (" (no attack in the window)" if not a else "")))
    if s["control"]:
        out.append(_kv("control", f"{s['control']} (same draw, rho and timeline); the placebo is a second run of it"))
        out.append(_kv("gate", f"metrics {', '.join(s['metrics'])}; floor {c['floor_pp']:g} pp; at least "
                               f"{c['min_blocks']} valid blocks (the calibration's)"))
    out.append("")
    out.append(_kv("entity seeds", f'first 8 bytes of sha256("{s["seed_namespace"]}|{s["seed"]}|<role>|<index>")'))
    out += _table(("role", "n", "first", "last"),
                  [(e["role"], e["n"], f"0x{e['first']:016x}", f"0x{e['last']:016x}") for e in p["entities"]], "<><<")
    out.append("")
    out.append(_kv("legit load", f"rho {b['rho']:g} req/s = 0.5 x c_slo {c['c_slo_rps']:g}; mean cost "
                                 f"{c['mean_cost_ms']:.2f} ms; the SLO capacity is {c['capacity_cpu_s']:.4f} CPU-s/s"))
    if all(x["basis"] == "assumed" for x in b["classes"]):
        out.append("  every class below is assumed, none is sourced")
    out += _table(("class", "ids", "share", "process", "req/s", "CPU-s/s", "util"),
                  [(x["name"], x["identities"], f"{x['rate_share']:.2f}", x["process"], f"{x['rate']:.2f}",
                    f"{x['cost_cpu_s']:.4f}", f"{x['utilisation']:.3f}") for x in b["classes"]], "<>><>>>")
    out.append(f"  drawn into streams: {b['drawn_rate']:.2f} req/s, {b['drawn_cost_cpu_s']:.4f} CPU-s/s, "
               f"utilisation {b['drawn_utilisation']:.3f}; route mix against the calibration's:")
    out += _table(("route", "drawn", "calibration", "gap"),
                  [(m["route"], f"{m['drawn']:.3f}", f"{m['calibration']:.3f}", _pp(m["drawn"] - m["calibration"]))
                   for m in b["mix"]], "<>>>", indent=4)
    out.append("  links, share of the legit requests: " + ", ".join(f"{p} {v:.1%}" for p, v in b["link_shares"].items()))
    out.append(f"  judged links: {', '.join(b['judged_profiles'])} carry {b['judged_share']:.1%} of them; the others are "
               "reported, not judged (their own links exceed the SLOs)")
    out.append("")
    if a:
        out += _render_attack(a, b, c)
    out += _render_generator(g, p)
    out.append("")
    out.append(_kv("expected gate", f"{p['expected_gate']['class']} ({p['expected_gate']['basis']})"))
    if p["warnings"]:
        out.append("")
        out.append("warnings")
        out += [f"  - {w}" for w in p["warnings"]]
    return "\n".join(out) + "\n"


def _render_attack(a, b, c):
    knee = a["knee"] if isinstance(a["knee"], str) else ("none within the generator limit" if a["knee"] is None
                                                         else f"{a['knee']:g}")
    ladder = " ".join(f"{x:g}" for x in a["ladder"])
    out = [_kv("attack", f"{a['family']} on {a['route']} ({a['route_cost_ms']:g} ms unloaded) from {a['sources']} sources"),
           f"  level {a['level']:g} x S, S = {a['spare_cpu_s']:.4f} CPU-s/s; ladder {ladder}; knee {knee}",
           (f"  total {a['total_rate']:.2f} req/s = {a['per_source_rate']:.3f} req/s a source; cost "
            f"{a['cost_cpu_s']:.4f} CPU-s/s = {a['cost_in_s']:.3f} S"),
           (f"  model utilisation: legit {b['drawn_utilisation']:.3f} + attack {a['utilisation']:.3f} = "
            f"{b['drawn_utilisation'] + a['utilisation']:.3f} of the SLO capacity; saturation (c_sat) is at "
            f"{c['c_sat_rps'] / c['c_slo_rps']:.3f}"),
           "  a source against the deployed rules (Gate A runs without them; printed, never used):"]
    rows = [(r["name"], f"{r['limit']:g} req/s", f"{r['per_source']:.3f}", f"{r['ratio']:.3f}",
             "below" if r["below"] else f"ABOVE; below it from {r['sources_to_fall_below']} sources")
            for r in a["thresholds"]]
    out += _table(("rule", "limit", "rate", "ratio", "this source"), rows, "<>>><", indent=4)
    r, k = a["rules"], a["connections"]
    out.append("  at this rate: limit_req " + (f"sheds about {r['reject_share']:.0%} in steady state"
                                              if r["limit_req_sheds"] else "does not shed")
               + "; the L7 rule " + ("bans after its window" if r["l7_rule_bans"] else "does not ban")
               + "; the error-ratio branch " + ("applies" if r["error_ratio_branch"] else "does not apply"))
    out.append(f"  connections a source: idle pool {k['pool']}, about {k['in_flight']:.3f} in flight at the unloaded "
               f"cost (limit_conn {k['limit_conn']}, SlowConn from {k['slowconn']})")
    out.append("")
    return out


def _render_generator(g, p):
    out = [_kv("generator", f"in-repo engine; at most {g['ceiling_rps']} req/s a stream; {g['ms_per_request']:g} ms of "
                            "CPU a request")]
    out += _table(("kind", "streams", "req/s", "largest", "in flight", "cap", "vCPU", "cores", "share", "limit",
                   "idle pool", "nofile", "split"),
                  [(kind, k["streams"], f"{k['rate']:.2f}", f"{k['max_stream_rate']:.2f}", f"{k['inflight']:.0f}",
                    k["cap"], k["pin"], f"{k['cores']:.3f}", f"{k['share']:.1%}", f"{g['cpu_share_limit']:.0%}",
                    k["keepalive"], k["nofile"], k["split"]) for kind, k in g["kinds"].items()], "<>>>>><>>>>>>")
    out.append(f"  {g['processes']} processes, memory about {g['memory_mb']} MB ({P.PROCESS_MB} MB each)")
    out.append("  in flight: the largest stream's rate x the request timeout, the most it can hold when the server "
               "stalls; cap: the engine's limit on it")
    out.append("  idle pool: an upper bound over all processes; nofile: what the largest process needs; "
               "split: streams the ceiling added")
    out.append("  client namespaces and the aliases each must carry: "
               + ", ".join(f"{n['name']} {n['aliases']}" for n in p["namespaces"]))
    out.append("  streams:")
    out += _table(("id", "route", "process", "req/s", "addrs", "ns", "vCPU", "start", "seed"),
                  [(x["id"], x["route"], x["process"], f"{x['rate']:.2f}", x["addresses"], x["ns"], x["pin"],
                    f"{x['start_s']:g}", x["seed"]) for x in p["streams"]], "<<<>>><>>", indent=4)
    return out


# --- the command line --------------------------------------------------------------------------

def _paired(path, scn):
    """The control of an attack scenario, read from the same directory, and what is wrong with the pair."""
    if not scn.controls:
        return None
    control_path = os.path.join(os.path.dirname(path), scn.controls["control"] + ".json")
    if not os.path.exists(control_path):
        raise ScenarioError(f"{path}: its control {scn.controls['control']} is not at {control_path}")
    control = load(control_path)
    problems = pair_problems(scn, control)
    if problems:
        raise ScenarioError(f"{path}: " + "; ".join(problems))
    return control


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="print the plan of each scenario (the default)")
    mode.add_argument("--check", action="store_true", help="validate the records and their controls only")
    ap.add_argument("--calibration", default=C.PLACEHOLDER, help="calibration record (default: the placeholder)")
    ap.add_argument("--seed", type=int, default=None, help="seed in the scenario's namespace (default: its first)")
    ap.add_argument("--json", action="store_true", help="print the plans as JSON")
    ap.add_argument("specs", nargs="+", metavar="SPEC")
    args = ap.parse_args(argv)
    try:
        cal = C.load(args.calibration)
        loaded = [(path, load(path)) for path in args.specs]
        for path, scn in loaded:
            _paired(path, scn)
        if args.check:
            for path, scn in loaded:
                print(f"{path}: valid" + (f", paired with {scn.controls['control']}" if scn.controls else ""))
            return 0
        plans = [plan(scn, cal, args.seed) for _, scn in loaded]
    except (ScenarioError, C.RecordError, OSError) as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(plans, indent=1, sort_keys=True))
    else:
        print("\n".join(render(x) for x in plans), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
