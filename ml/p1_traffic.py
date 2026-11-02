"""P1 traffic (docs/L7V2_DESIGN.md 5.3, 6, 7, 12, 14): one block's population, as data, for eval/p1_runner.py.

Pure and seeded; nothing here touches the system. A block is one seed: build_block() draws its address pool, role map,
per-entity parameters, netem profiles and schedules, and every run of the block uses them unchanged, its entities being
the benign ones and the sources of the run's class (run_entities). It reuses l7_pools (the P3 and L7 v2 pool, sub-seeds,
draws, the benign mix and the families' parameters, the C2 rate, the age check), under its own stream name, as
ml/p4_traffic.py does; nothing is added to l7_pools's P3 population.

What a block holds:
  * benign: l7_pools.POPULATIONS["l7v2"]'s frozen mix, the held-out kinds included (5.2: FP per benign kind), through the
    benign gate under the tolerant profile, as a P3 plan;
  * C2: classes.C2.sources_p1 sources, each at L x S / (n x cost(route)) (l7_pools.c2_rps at m = 1);
  * C3a: n = ceil(L x S / ((cost_C1 + cost_route) / mean(page_gap_s))) sources, refused outside classes.C3a.sources_bounds
    ("not reachable", ml/l7v2_prereg.json);
  * C3b: `level` bots at M2, the primary family (D-043), and SIDE_FAMILIES, a fixed number of bots at M1, M3 and M2exp,
    which only the ladder's level does not move. All of ml/l7_bots.FAMILIES' C3b levels run here: M2exp is in the frozen
    class table (ml/l7v2_prereg.json mimicry, design 12.4), so it has its entity labels here, and l7_pools's P3 population
    stays without it;
  * the timeline of design 14: 30 s of baseline, 120 s of attack, 30 s of recovery;
  * the halving rule of ml/p1_prereg.json (D-049): `halvings` is how often it has fired. Every benign spec of count > 1 keeps
    count >> halvings entities, at least 1, the first of its list; a spec of count 1, the CGNAT pools among them, is never
    removed. An entity keeps its index, sub-seed, address and parameters whatever the halvings, so a halved plan is the full
    plan without the dropped entities. next_step() is the rule over its steps, up to the frozen factor or a refusal.

Arrivals and lifetimes follow ml/l7v2_prereg.json arrivals on one slot, the attack window (readings, labelled in the
design's As-built section):
  * a benign entity arrives at a uniform time over [0, the attack's end - min_active_s] and runs to the run's end; a CGNAT
    pool runs from 0 and each user arrives over that span; a browser-like kind runs sessions, a machine client one lifetime;
  * an attack entity arrives at a uniform time over [the attack's start, its end - min_active_s] and runs one lifetime,
    capped at the attack's end: the recovery is attack-free, so the run's time to mitigate means what it says;
  * the flash crowd's minute starts at a uniform time over the benign arrival span. flash_gap_s cannot be kept on one
    slot (no start is 60 s from a slot that begins at 30 s, within a span of 90 s), and the plan says so;
  * arrivals.age_check is computed and recorded per class (age_report), not applied (D-049): with a baseline, benign arrivals
    begin 30 s before the attack's, so its first-seen KS is 0.33 against a limit of 0.30 by construction. See the design's
    As-built section.

This module stays light: no numpy, no eval/ imports.
"""
import copy
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

VERSION = "2026-11-p1"           # the stream name under which l7_pools draws a P1 plan's pool and sub-seeds
PLAN_FORMAT = "p1-plan/1"
TIMELINE = {"baseline_s": 30, "attack_s": 120, "recovery_s": 30}     # design 14
ROLES = {"eval": "p1_live_eval", "pilot": "p1_pilot"}               # ml/p3_prereg.json seeds
PRIMARY = {"C2": "C2", "C3a": "C3a", "C3b": "C3b@M2"}
SIDE_FAMILIES = {"C3b": {"C3b@M1": 10, "C3b@M3": 10, "C3b@M2exp": 10}}   # [ASSUMPTION] reported separately, judge nothing
MAX_SOURCES = {"C2": 100, "C3a": 100, "C3b": 300}                   # each family's index range, its ladder's top
FAMILY_ORDER = ("C2", "C3a", "C3b@M2", "C3b@M1", "C3b@M3", "C3b@M2exp")


class PlanError(ValueError):
    """The block cannot be planned as asked (seed, level or limits)."""


def check_seed(seed, seed_role):
    import p3_prereg
    if seed_role not in ROLES:
        raise PlanError(f"a P1 seed role is one of {sorted(ROLES)}, not {seed_role!r}")
    if seed not in p3_prereg.load()["seeds"][ROLES[seed_role]]:
        raise PlanError(f"seed {seed} is not pre-registered as {ROLES[seed_role]}")


def prereg():
    """ml/p1_prereg.json, the dated record of D-049."""
    with open(os.path.join(HERE, "p1_prereg.json"), encoding="utf-8") as fh:
        return json.load(fh)


def check_halvings(halvings):
    """`halvings` if it is an int from 0 up to the rule's floor, or a refusal: past the floor there is no plan."""
    floor = prereg()["halving"]["floor"]["max_halvings"]
    if not (isinstance(halvings, int) and not isinstance(halvings, bool) and 0 <= halvings <= floor):
        raise PlanError(f"halvings must be an int in 0..{floor}, the rule's floor (ml/p1_prereg.json), got {halvings!r}")
    return halvings


def kept_entities(count, halvings):
    """How many of a benign spec's `count` entities a plan keeps: count >> halvings, at least 1; a single entity is never removed."""
    return count if count <= 1 else max(1, count >> halvings)


def _kept_indices(specs, halvings):
    """The entity indices a plan keeps: each spec's first kept_entities, by index over the full mix."""
    kept, base = set(), 0
    for spec in specs:
        kept.update(range(base, base + kept_entities(spec["count"], halvings)))
        base += spec["count"]
    return kept


def halve(control_reasons):
    """The frozen rule over the two pilot controls, as ml/p4_traffic.halve: `control_reasons` holds, for each, the reasons it is
    unhealthy (eval/harm_gate.control_health), empty when it is healthy. True iff either is unhealthy."""
    control_reasons = list(control_reasons)
    if len(control_reasons) != 2:
        raise PlanError(f"the rule judges the two pilot controls, got {len(control_reasons)}")
    return any(bool(r) for r in control_reasons)


def next_step(steps):
    """The rule of ml/p1_prereg.json over its steps in the order they ran, each {"halvings", "sound", "reasons": [C's, C''s]}:
    {"decision", "benign_halvings", "next_halvings", "why"}, the decision one of "run" (the next step's halvings), "frozen" (the
    factor) and "refused" (there is no factor, and the ladder and the campaign refuse)."""
    rule = prereg()["halving"]
    floor, max_reruns = rule["floor"]["max_halvings"], rule["max_reruns"]

    def refused(why):
        return {"decision": "refused", "benign_halvings": None, "next_halvings": None, "why": why}

    h, reruns = 0, 0
    for i, step in enumerate(steps):
        if step["halvings"] != h:
            return refused(f"step {i + 1} ran at {step['halvings']} halvings while the rule stood at {h}")
        if not step["sound"]:
            reruns += 1
            if reruns > max_reruns:
                return refused(f"the controls at {h} halvings gave no reading in {reruns} attempts (at most {max_reruns} re-runs)")
            continue
        if not halve(step["reasons"]):
            if i != len(steps) - 1:
                return refused(f"a step ran after the rule stopped at {h} halvings")
            return {"decision": "frozen", "benign_halvings": h, "next_halvings": None,
                    "why": f"both controls healthy at {h} halvings"}
        if h == floor:
            return refused(f"the benign mix does not reach health at the floor of {floor} halvings "
                           f"(ml/p1_prereg.json): {step['reasons']}")
        h, reruns = h + 1, 0
    return {"decision": "run", "benign_halvings": None, "next_halvings": h, "why": f"the next step runs at {h} halvings"}


def run_seconds():
    return sum(TIMELINE.values())


def attack_window():
    return float(TIMELINE["baseline_s"]), float(TIMELINE["baseline_s"] + TIMELINE["attack_s"])


def ladder_levels(cls):
    """A class's ladder (ml/l7v2_prereg.json harm.ladder.levels; C3b's is its number of bots)."""
    import l7v2_prereg
    pre = l7v2_prereg.load()
    return list(pre["classes"]["C3b"]["ladder_bots"]) if cls == "C3b" else list(pre["harm"]["ladder"]["levels"])


def c3a_sources(level, spare_cpu_s, costs, route, gap):
    """C3a's sources at level L (ml/l7v2_prereg.json classes.C3a.intensity)."""
    return math.ceil(level * spare_cpu_s / ((costs["C1"] + costs[route]) / 1000.0 / (sum(gap) / len(gap))))


def _family_specs():
    """The attack families' specs of l7_pools, by name, with C3b@M2exp added: C3b@M2's spec at the frozen M2exp level."""
    import l7_pools as LP
    out = {s["family"]: copy.deepcopy(s) for s in LP.POPULATIONS["l7v2"]["attack"]}
    exp = copy.deepcopy(out["C3b@M2"])
    exp.update(family="C3b@M2exp", held_out=True)
    exp["params"]["mimicry"] = "M2exp"
    out["C3b@M2exp"] = exp
    for s in out.values():
        s.pop("reuse", None)          # no M3 bot needs a C2 address here: one class runs at a time
    return out


def _bases(n_benign):
    """Each family's first entity index: a family keeps its indices, sub-seeds and addresses whatever the levels."""
    bases, at = {}, n_benign
    for fam in FAMILY_ORDER:
        bases[fam] = at
        if fam in PRIMARY.values():
            at += MAX_SOURCES[next(c for c, f in PRIMARY.items() if f == fam)]
        else:
            at += SIDE_FAMILIES["C3b"][fam]
    return bases, at


def _entity(LP, seed, index, role, name, spec):
    sub = LP.subseed(VERSION, seed, index)
    rng = random.Random(sub)
    params = copy.deepcopy(spec["params"])
    for key, how in sorted(spec.get("draws", {}).items()):
        params[key] = LP.draw_value(how, params.get(key), rng)
    port = rng.choice(spec["ports"])
    row = {"entity_id": f"{VERSION}:{seed}:{index}", "index": index, "subseed": sub, "role": role, "kind_or_family": name,
           "mechanism": spec.get("mechanism") if role == "attack" else None, "held_out": bool(spec.get("held_out")),
           "port": port, "params": params, "client_seed": rng.randrange(2 ** 31)}
    if role == "attack":
        params["port"] = port
    return row, rng


def _benign(LP, seed, specs, span, flash, heuristics, gate_seeds):
    """The benign rows on the run's timeline, through the benign gate, and what the gate dropped."""
    import l7_benign
    total = float(run_seconds())
    rows, dropped, cache, index = [], [], {}, 0
    for spec in specs:
        for _ in range(spec["count"]):
            i, index = index, index + 1
            row, _rng = _entity(LP, seed, i, "benign", spec["kind"], spec)
            params = row["params"]
            if spec.get("arrival") == "users":
                start, params["first_visit_s"] = 0.0, [0.0, round(span, 3)]
            elif spec.get("arrival") == "flash":
                start = flash
            else:
                start = round(random.Random(LP.subseed(VERSION, seed, f"arrive|{i}")).uniform(0.0, span), 3)
            stop = total
            if spec["kind"] in l7_benign.SESSION_KINDS:
                params["sessions"] = True
            else:
                stop = LP._lifetime_stop(VERSION, seed, i, start, total)
            row["schedule"] = {"start_s": start, "stop_s": stop, "phase": None}
            if spec.get("gate"):
                verdict = LP._gate(spec["kind"], params, total, gate_seeds, heuristics, cache)
                row["gate_admissible"] = verdict["admissible"]
                if not verdict["admissible"]:
                    dropped.append({"entity_index": i, "kind": spec["kind"], "params": params, "trips": verdict["trips"]})
                    continue
            rows.append(row)
    return rows, dropped


def _attack(LP, seed, cls, fam, spec, base, n, rule, rates):
    """The rows of one attack family: `n` sources from its index base, arriving over the attack's first part."""
    import l7_traffic
    lo, hi = attack_window()
    out = []
    for k in range(n):
        i = base + k
        row, rng = _entity(LP, seed, i, "attack", fam, spec)
        if fam == "C2":
            row["params"]["rps"] = LP.c2_rps(1.0, rates["C2"], rates["spare_cpu_s"], rates["c2_sources"],
                                             rates["route_costs_ms"][row["params"].get("route", "C3")])
        check = l7_traffic._check_spec(l7_traffic.AttackSpec(fam, spec["mechanism"], row["held_out"], row["params"]))
        if check["violations"] and not row["held_out"]:
            raise PlanError(f"{row['entity_id']} {fam}: not sub-threshold: {check['violations']}")
        start = round(lo + rng.uniform(0.0, hi - lo - rule["min_active_s"]), 3)
        row["schedule"] = {"start_s": start, "stop_s": min(LP._lifetime_stop(VERSION, seed, i, start, run_seconds()), hi),
                           "phase": cls}
        out.append(row)
    return out


def _netem(LP, seed, group, name):
    """Netem balanced within a group whatever its size: a seeded order of the profiles, in turn along the group."""
    order = list(LP.NETEM_PROFILES)
    random.Random(LP.subseed(VERSION, seed, f"netem|{name}")).shuffle(order)
    for k, row in enumerate(group):
        row["netem"] = order[k % len(order)]


def build_block(seed, seed_role, levels, *, record_path=None, knees=None, check_role=True, heuristics="tolerant",
                gate_seeds=(0, 1), benign_specs=None, max_sources=None, halvings=0):
    """One block's population as data. `levels` {class: level}: C2's and C3a's a level of S, C3b's a number of bots; a class
    left out has no sources. An evaluation block needs frozen knees bound to a frozen record (l7_pools._knees, L7V2-08),
    and its levels must be the knees. `halvings` is how often the halving rule has fired (ml/p1_prereg.json). `benign_specs` and
    `max_sources` thin a plan for tests, never the rates."""
    import calibration as CAL
    import l7_pools as LP
    import l7v2_prereg

    import l7_backend
    import l7_dataset
    if check_role:
        check_seed(seed, seed_role)
    check_halvings(halvings)
    rec, status, tag = l7_backend.load_record(record_path)
    if status == "measured":
        rec = l7_backend.arithmetic_record(rec, l7_backend.load_record()[0])
    try:
        bound = LP._knees(knees, seed_role, rec)
    except LP.PlanError as exc:
        raise PlanError(str(exc)) from exc
    if seed_role == "eval":
        wrong = {c: (lv, bound.get(c)) for c, lv in levels.items() if bound.get(c) != lv}
        if wrong:
            raise PlanError(f"an evaluation block runs at the frozen knees: {wrong} (level, knee)")
    pre = l7v2_prereg.load()
    rule = pre["arrivals"]
    span = attack_window()[1] - rule["min_active_s"]
    within = pre["benign_kinds"]["flash_crowd"]["arrive_within_s"]
    flash = round(random.Random(LP.subseed(VERSION, seed, "flash")).uniform(0.0, span - within), 3)
    specs = LP.POPULATIONS["l7v2"]["benign"] if benign_specs is None else benign_specs
    benign, dropped = _benign(LP, seed, specs, span, flash, heuristics, gate_seeds)
    n_full = sum(s["count"] for s in specs)
    bases, pool_size = _bases(n_full)
    costs = dict(rec["route_costs_ms"])
    spare = CAL.spare_capacity(rec)
    rates = {"spare_cpu_s": spare, "route_costs_ms": costs, "c2_sources": pre["classes"]["C2"]["sources_p1"]}
    fams, attack = _family_specs(), {}
    sources = {}
    for cls, level in sorted(levels.items()):
        if cls not in PRIMARY:
            raise PlanError(f"unknown class {cls!r} (have {sorted(PRIMARY)})")
        if cls == "C2":
            n, rates["C2"] = rates["c2_sources"], level
        elif cls == "C3a":
            c3a = pre["classes"]["C3a"]
            n = c3a_sources(level, spare, costs, fams["C3a"]["params"]["route"], c3a["page_gap_s"])
            if not c3a["sources_bounds"][0] <= n <= c3a["sources_bounds"][1]:
                raise PlanError(f"C3a at level {level} needs {n} sources, outside {c3a['sources_bounds']}: not reachable "
                                "(ml/l7v2_prereg.json classes.C3a.out_of_bounds)")
        else:
            n = int(level)
            if not 1 <= n <= MAX_SOURCES["C3b"]:
                raise PlanError(f"C3b at {level} bots is outside 1..{MAX_SOURCES['C3b']}")
        sources[cls] = n
        wanted = {PRIMARY[cls]: n, **SIDE_FAMILIES.get(cls, {})}
        rows = []
        for fam, count in wanted.items():
            count = min(count, max_sources) if max_sources else count
            group = _attack(LP, seed, cls, fam, fams[fam], bases[fam], count, rule, rates)
            _netem(LP, seed, group, fam)
            rows += group
        attack[cls] = rows
    _netem(LP, seed, benign, "benign")
    kept = _kept_indices(specs, halvings)                 # after the draws over the full mix, so that the halvings move no entity
    benign, dropped = [e for e in benign if e["index"] in kept], [d for d in dropped if d["entity_index"] in kept]
    addresses = LP.draw_pool(VERSION, seed, pool_size)
    for row in benign + [r for rows in attack.values() for r in rows]:
        row["address"] = addresses[row["index"]]
        row["plan_sha256"] = l7_dataset.entity_plan_sha256(row)
        if l7_dataset.pool_users(row):
            row["users"] = l7_dataset.pool_users(row)
    return {"format": PLAN_FORMAT, "version": VERSION, "seed": seed, "seed_role": seed_role, "levels": dict(levels),
            "halvings": halvings, "sources": sources, "timeline": dict(TIMELINE), "duration_s": float(run_seconds()), "benign": benign,
            "attack": attack, "dropped": dropped, "heuristics": heuristics,
            "intensity": {"record_status": rec["status"], "record_tag": tag, "label": l7_backend.label(rec),
                          "record_sha256": rec.get("sha256"), "spare_cpu_s": spare, "knees": bound},
            "flash": {"start_s": flash, "gap_kept": False, "why": "flash_gap_s cannot be kept on one slot"},
            "pool": {"range": str(LP.POOL_NET), "size": pool_size,
                     "permutation_seed": LP.subseed(VERSION, seed, "pool"), "address_limit": _address_limit()}}


def _address_limit():
    import p3_prereg
    return p3_prereg.load()["pool"]["address_limit"]


def run_entities(block, cls=None):
    """A run's entities: copies of the block's benign ones and, for a class, its sources. An attack-free control is cls None.
    A run over the verified address limit is refused (ml/p3_prereg.json pool.address_limit)."""
    rows = [dict(e) for e in block["benign"]]
    if cls is not None:
        if cls not in block["attack"]:
            raise PlanError(f"the block has no sources of class {cls!r}")
        rows += [dict(e) for e in block["attack"][cls]]
    limit = block["pool"]["address_limit"]
    if len({e["address"] for e in rows}) > limit:
        raise PlanError(f"{cls}: {len(rows)} addresses exceed the verified limit of {limit} (ml/p3_prereg.json "
                        "pool.address_limit): this level is not reachable as planned")
    return rows


def benign_load(block, rec):
    """The benign plan's nominal load over the attack window against the record: req/s and CPU-s/s at the record's class costs, per
    kind, beside rho in both units and the spare capacity S. The mix does not read the record: rho only sizes the attack, through S.
    Nominal: no network or server time. A kind without a plan (the P5 kinds) has no nominal times, so it is listed, not counted; an
    uncosted route (a crawler's /robots.txt) counts as a request without a class cost."""
    import calibration as CAL
    import l7_pools as LP

    import l7_webapp
    lo, hi = attack_window()
    kinds, unplanned = {}, set()
    for e in block["benign"]:
        plan, kind = LP._plan_of(e), e["kind_or_family"]
        if plan is None:
            unplanned.add(kind)
            continue
        row = kinds.setdefault(kind, {"requests": 0, "cpu_ms": 0.0})
        for user in plan["users"]:
            for t, path in LP.nominal_requests(user):
                if lo <= e["schedule"]["start_s"] + t < hi:
                    row["requests"] += 1
                    row["cpu_ms"] += rec["route_costs_ms"].get(l7_webapp.route_class("GET", path), 0.0)
    span = hi - lo
    rho = CAL.rho_rps(rec)
    return {"req_s": round(sum(r["requests"] for r in kinds.values()) / span, 1),
            "cpu_s_s": round(sum(r["cpu_ms"] for r in kinds.values()) / 1000.0 / span, 3),
            "by_kind": {k: {"req_s": round(r["requests"] / span, 1), "cpu_s_s": round(r["cpu_ms"] / 1000.0 / span, 3)}
                        for k, r in sorted(kinds.items())},
            "without_a_plan": sorted(unplanned), "rho_req_s": rho, "rho_cpu_s_s": round(rho * CAL.mean_cost_ms(rec) / 1000.0, 3),
            "spare_cpu_s": round(CAL.spare_capacity(rec), 3)}


def age_report(block):
    """The frozen key-age check (ml/l7v2_prereg.json arrivals.age_check, l7_pools.age_check) per class, recorded per run and not
    applied on P1's one-slot timeline (D-049, ml/p1_prereg.json age_check; see the module docstring)."""
    import l7_pools as LP
    import l7v2_prereg
    rule = l7v2_prereg.load()["arrivals"]["age_check"]
    return {cls: LP.age_check(run_entities(block, cls), rule) for cls in sorted(block["attack"])}
