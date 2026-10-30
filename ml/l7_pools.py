"""Per-seed address pools, role maps and entity plans for P3 captures (docs/P3_DATASET_DESIGN.md §4.1-§4.3
and §5; docs/L7V2_DESIGN.md §6, D-V3).

Pure and seeded; nothing here touches the system. build_plan() returns a whole capture plan as data:
  * the pool: as many addresses as entities, drawn from POOL_NET (10.0.16.0/20) by a seeded sample. The
    sample's order is the permutation that assigns the roles, so an address does not reveal its role and no
    address-to-role map is shared between seeds. (The legacy plan puts benign clients at 10.0.1.{i+1} and
    attackers at 10.0.2.{j+1} in every run: VR:V10.)
  * one row per entity: kind or family, held-out flag, address, netem profile, the parameters drawn from its
    kind's or family's distribution, its sub-seed blake2b("p3|<version>|<seed>|<entity index>"), the client
    seed derived from it, its schedule and plan_sha256 (l7_dataset.entity_plan_sha256);
  * netem for every entity, benign or attacking, balanced within each role (the legacy plan gives attackers
    none: the "no netem = attacker" confound);
  * namespaces: the entities grouped by netem profile, at most MAX_ALIASES address aliases per namespace,
    because netem belongs to an interface (as bench/executor.py groups its identities);
  * the timeline: a benign lead-in, one attack phase per family group in a seeded order, a benign tail. Each
    attack entity is active only inside its family's phase.

Populations are data (POPULATIONS). "smoke" uses today's generators (ml/l7_gen) for the P3 smoke capture
(seeds 9201-9202: pools, netem, manifest, storage, rebuild); the L7 v2 classes (C2, C3a, C3b) arrive with the
L7 v2 runner and are added as another population. Held-out kinds and families are left out of training and
validation captures by construction.
"""
import copy
import hashlib
import ipaddress
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import l7_traffic
import p3_prereg

import l7_dataset

PLAN_FORMAT = "p3-plan/1"
POOL_NET = ipaddress.ip_network("10.0.16.0/20")
TESTBED_NET = ipaddress.ip_network("10.0.0.0/16")
LEGACY_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"))
NETEM_PROFILES = ("perfect", "broadband", "mobile_3g", "mobile_bad")
MAX_ALIASES = 80
NS_PREFIX = "l7n"


class PlanError(ValueError):
    """A P3 plan cannot be built as asked (seed, role, population or limits)."""


def subseed(version, seed, index):
    """blake2b("p3|<version>|<seed>|<index>") as a 63-bit int; `index` may also name a stream ("pool")."""
    digest = hashlib.blake2b(f"p3|{version}|{seed}|{index}".encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") & (2 ** 63 - 1)


def pool_hosts():
    return [str(a) for a in POOL_NET.hosts()]


def draw_pool(version, seed, n):
    """`n` distinct addresses of POOL_NET in a seeded random order (the role permutation)."""
    hosts = pool_hosts()
    if n > len(hosts):
        raise PlanError(f"{n} addresses asked of a pool of {len(hosts)}")
    return random.Random(subseed(version, seed, "pool")).sample(hosts, n)


def draw_value(spec, base, rng):
    """One drawn parameter. spec: ["uniform", lo, hi] | ["int", lo, hi] | ["choice", [..]] |
    ["scale", lo, hi] (a common factor on the base value or both ends of a base range)."""
    how = spec[0]
    if how == "uniform":
        return round(rng.uniform(spec[1], spec[2]), 3)
    if how == "int":
        return rng.randint(spec[1], spec[2])
    if how == "choice":
        return copy.deepcopy(rng.choice(spec[1]))
    if how == "scale":
        f = rng.uniform(spec[1], spec[2])
        if isinstance(base, list):
            return [round(x * f, 3) for x in base]
        return round(base * f, 3)
    raise PlanError(f"unknown draw {spec!r}")


def _benign_kinds():
    """The smoke population's benign side: the P5 kinds and the P5b realistic kinds, base parameters as
    frozen in ml/l7_traffic, with per-entity draws around them."""
    return [
        {"kind": "curl_oneshot", "count": 3, "ports": [80, 443], "params": {"think_s": [1.0, 3.0], "paths": "mixed"},
         "draws": {"think_s": ["scale", 0.6, 1.6]}},
        {"kind": "keepalive", "count": 3, "ports": [80, 443],
         "params": {"think_s": [0.5, 2.0], "per_session": [4, 12], "paths": "browse"},
         "draws": {"think_s": ["scale", 0.6, 1.6]}},
        {"kind": "http2", "count": 2, "ports": [443], "params": {"think_s": [1.0, 2.0], "parallel": 6, "paths": "assets"},
         "draws": {"think_s": ["scale", 0.7, 1.5], "parallel": ["int", 3, 8]}},
        {"kind": "api_poll", "count": 2, "ports": [443], "params": {"interval_s": [0.5, 1.5], "path": "/api/status"},
         "draws": {"interval_s": ["scale", 0.7, 2.0]}},
        {"kind": "downloader", "count": 1, "ports": [443], "params": {"think_s": [5.0, 15.0], "path": "/download/large"},
         "draws": {"think_s": ["scale", 0.7, 1.5]}},
        {"kind": "uploader", "count": 1, "ports": [80],
         "params": {"think_s": [4.0, 10.0], "path": "/upload", "body_bytes": [200, 60000]},
         "draws": {"think_s": ["scale", 0.7, 1.5]}},
        {"kind": "nat_gateway", "count": 1, "ports": [443], "params": {"users": 8, "think_s": [0.5, 3.0], "paths": "browse"},
         "draws": {"users": ["int", 4, 10]}},
        {"kind": "browser_page", "count": 6, "ports": [80, 443], "gate": True,
         "params": {"level": 30, "first_visit_s": [0.0, 30.0]},
         "draws": {"level": ["choice", [30, 60]], "visit_gap_s": ["choice", [[30.0, 120.0], [60.0, 180.0]]]}},
        {"kind": "cgnat_browsers", "count": 2, "ports": [443], "gate": True,
         "params": {"users": 12, "level": 30, "first_visit_s": [0.0, 60.0]}, "draws": {"users": ["choice", [12, 24]]}},
        {"kind": "crawler_polite", "count": 1, "ports": [443], "gate": True, "params": {"rps": [2.0, 5.0], "level": 30}},
        {"kind": "api_bulk", "count": 1, "ports": [443], "gate": True, "held_out": True,
         "params": {"rps": [15.0, 20.0], "endpoints": [2, 3]}},
    ]


def _attack_families():
    """The smoke population's attack side: today's sub-threshold families with per-entity rates and
    connection counts drawn inside the calibration (trained ones are checked again per entity)."""
    return [
        {"family": "subthreshold_flood", "mechanism": "rate", "count": 4, "ports": [80, 443],
         "params": {"rps": 20, "paths": "mixed"}, "draws": {"rps": ["uniform", 10.0, 45.0]}},
        {"family": "scraper", "mechanism": "rate", "count": 3, "ports": [443],
         "params": {"rps": 25, "paths": "scrape"}, "draws": {"rps": ["uniform", 10.0, 40.0]}},
        {"family": "slowloris", "mechanism": "conns", "count": 2, "ports": [80],
         "params": {"conns": 6, "header_every_s": 3}, "draws": {"conns": ["int", 3, 7], "header_every_s": ["uniform", 2.0, 4.5]}},
        {"family": "slowpost", "mechanism": "conns", "count": 2, "ports": [80],
         "params": {"conns": 6, "byte_every_s": 3, "body_bytes": 60000},
         "draws": {"conns": ["int", 3, 7], "byte_every_s": ["uniform", 2.0, 4.5]}},
        {"family": "padded_flood", "mechanism": "rate", "count": 2, "ports": [443], "held_out": True,
         "params": {"rps": 30, "paths": "mixed", "pad_header_bytes": 500},
         "draws": {"rps": ["uniform", 15.0, 40.0], "pad_header_bytes": ["int", 200, 800]}},
        {"family": "credstuff", "mechanism": "rate", "count": 2, "ports": [443], "held_out": True,
         "params": {"rps": 20, "path": "/login", "body_bytes": 120}, "draws": {"rps": ["uniform", 8.0, 30.0]}},
        {"family": "slowread", "mechanism": "conns", "count": 1, "ports": [80], "held_out": True,
         "params": {"conns": 6, "read_every_s": 3, "path": "/download/large"}, "draws": {"conns": ["int", 3, 7]}},
    ]


POPULATIONS = {
    "smoke": {
        "name": "smoke-v1",
        "timeline": {"lead_in_s": 60.0, "phase_s": 240.0, "tail_s": 120.0, "edge_jitter_s": 10.0},
        "phases": [{"name": "rate_mixed", "families": ["subthreshold_flood", "padded_flood"]},
                   {"name": "rate_targeted", "families": ["scraper", "credstuff"]},
                   {"name": "conns", "families": ["slowloris", "slowpost", "slowread"]}],
        "intensity": [1.0],
        "benign": _benign_kinds(),
        "attack": _attack_families(),
    },
}


def _gate(kind, params, duration_s, gate_seeds, heuristics, cache):
    """The P5b admissibility verdict (ml/l7_admissibility) of one drawn benign entity, cached by params."""
    import l7_admissibility as adm
    key = (kind, l7_dataset.canonical_json(params), float(duration_s), tuple(gate_seeds), heuristics)
    if key not in cache:
        rep = adm.check_spec(kind, params, duration_s, gate_seeds, l7_traffic.PROFILES[heuristics])
        cache[key] = {"admissible": bool(rep["admissible"]), "trips": rep["trips"]}
    return cache[key]


def _timeline(pop, version, seed):
    t = pop["timeline"]
    phases = [dict(p) for p in pop["phases"]]
    random.Random(subseed(version, seed, "phases")).shuffle(phases)
    irng = random.Random(subseed(version, seed, "intensity"))
    start = t["lead_in_s"]
    for p in phases:
        p["start_s"], p["stop_s"] = start, start + t["phase_s"]
        p["intensity"] = irng.choice(pop["intensity"])
        start += t["phase_s"]
    total = start + t["tail_s"]
    return {"lead_in_s": t["lead_in_s"], "phase_s": t["phase_s"], "tail_s": t["tail_s"],
            "edge_jitter_s": t["edge_jitter_s"], "phases": phases, "duration_s": total}


def build_plan(version, seed, seed_role, population="smoke", *, heuristics="tolerant", scale=1,
               gate_seeds=l7_traffic.GATE_SEEDS, launch_inadmissible=False, prereg=None, check_role=True):
    """The capture plan of one seed as data (see the module docstring). With check_role, `seed` must be
    pre-registered for `seed_role` (ml/p3_prereg.json); tests may turn that off to probe other seeds."""
    if not l7_dataset.VERSION_RE.match(str(version)):
        raise PlanError(f"dataset version {version!r} is not <yyyy-mm>-<tag>")
    if seed_role not in l7_dataset.SEED_ROLES:
        raise PlanError(f"seed role {seed_role!r} not in {l7_dataset.SEED_ROLES}")
    pre = prereg or p3_prereg.load()
    if check_role:
        try:
            p3_prereg.check_seed(seed, seed_role, pre)
        except p3_prereg.PreregError as exc:
            raise PlanError(str(exc)) from exc
    if population not in POPULATIONS:
        raise PlanError(f"unknown population {population!r} (have {sorted(POPULATIONS)})")
    if heuristics not in l7_traffic.PROFILES:
        raise PlanError(f"unknown heuristics profile {heuristics!r}")
    if not (isinstance(scale, int) and scale >= 1):
        raise PlanError(f"scale must be a positive int, got {scale!r}")
    pop = POPULATIONS[population]
    timeline = _timeline(pop, version, seed)
    duration = timeline["duration_s"]
    phase_of = {f: p for p in timeline["phases"] for f in p["families"]}
    keep_held = seed_role in ("eval", "pilot")           # never in training or validation captures

    specs = [("benign", s) for s in pop["benign"]] + [("attack", s) for s in pop["attack"]]
    rows, dropped, gate_cache, held_report = [], [], {}, []
    index = 0
    for role, spec in specs:
        name = spec["kind"] if role == "benign" else spec["family"]
        for _ in range(spec["count"] * scale):
            i, index = index, index + 1
            if spec.get("held_out") and not keep_held:
                continue
            sub = subseed(version, seed, i)
            erng = random.Random(sub)
            params = copy.deepcopy(spec["params"])
            for key, how in sorted(spec.get("draws", {}).items()):
                params[key] = draw_value(how, params.get(key), erng)
            port = erng.choice(spec["ports"])
            row = {"entity_id": f"{version}:{seed}:{i}", "index": i, "subseed": sub, "role": role,
                   "kind_or_family": name, "mechanism": spec.get("mechanism") if role == "attack" else None,
                   "held_out": bool(spec.get("held_out")), "port": port, "params": params,
                   "client_seed": erng.randrange(2 ** 31)}
            if role == "attack":
                params["port"] = port
                ph = phase_of[name]
                if ph["intensity"] != 1.0 and "rps" in params:
                    params["rps"] = round(params["rps"] * ph["intensity"], 3)
                rec = l7_traffic._check_spec(l7_traffic.AttackSpec(name, spec["mechanism"], row["held_out"], params))
                if rec["violations"] and not row["held_out"]:
                    raise PlanError(f"{row['entity_id']} {name}: not sub-threshold: {rec['violations']}")
                if row["held_out"]:
                    held_report.append({"entity_id": row["entity_id"], "violations": rec["violations"]})
                j = timeline["edge_jitter_s"]
                start = round(ph["start_s"] + erng.uniform(0.0, j), 3)
                stop = round(ph["stop_s"] - erng.uniform(0.0, j), 3)
                row["schedule"] = {"start_s": start, "stop_s": stop, "phase": ph["name"]}
            else:
                row["schedule"] = {"start_s": 0.0, "stop_s": duration, "phase": None}
                if spec.get("gate"):
                    verdict = _gate(name, params, duration, gate_seeds, heuristics, gate_cache)
                    row["gate_admissible"] = verdict["admissible"]
                    if not verdict["admissible"] and not launch_inadmissible:
                        dropped.append({"entity_index": i, "kind": name, "params": params,
                                        "trips": verdict["trips"]})
                        continue
            rows.append(row)

    limit = pre["pool"]["address_limit"]
    if len(rows) > limit:
        raise PlanError(f"{len(rows)} entities exceed the verified address limit {limit}")
    addresses = draw_pool(version, seed, len(rows))
    for row, addr in zip(rows, addresses, strict=True):
        row["address"] = addr
    for role in ("benign", "attack"):                     # netem balanced within each role
        group = [r for r in rows if r["role"] == role]
        order = list(range(len(group)))
        random.Random(subseed(version, seed, f"netem|{role}")).shuffle(order)
        for rank, k in enumerate(order):
            group[k]["netem"] = NETEM_PROFILES[rank % len(NETEM_PROFILES)]
    namespaces, n_ns = [], 0
    for prof in NETEM_PROFILES:
        members = [r for r in rows if r["netem"] == prof]
        for c in range(0, len(members), MAX_ALIASES):
            chunk = members[c:c + MAX_ALIASES]
            name = f"{NS_PREFIX}{n_ns}_{prof}"
            n_ns += 1
            namespaces.append({"name": name, "profile": prof, "addresses": [r["address"] for r in chunk]})
            for r in chunk:
                r["namespace"] = name
    for r in rows:
        r["plan_sha256"] = l7_dataset.entity_plan_sha256(r)
    cid, cfg = p3_prereg.server_config(seed, pre)
    return {"format": PLAN_FORMAT, "dataset_version": version, "seed": seed, "seed_role": seed_role,
            "population": pop["name"], "scale": scale, "heuristics": heuristics, "duration_s": duration,
            "server": {"config_id": cid, "gunicorn_workers": cfg["gunicorn_workers"],
                       "gunicorn_threads": cfg["gunicorn_threads"]},
            "pool": {"range": str(POOL_NET), "permutation_seed": subseed(version, seed, "pool"),
                     "role_map": {r["address"]: r["role"] for r in rows}},
            "timeline": timeline, "namespaces": namespaces, "entities": rows, "dropped": dropped,
            "held_out_calibration": held_report,
            "plan_set_sha256": l7_dataset.plan_set_sha256(rows)}


def role_map_agreement(a, b):
    """The share of entity positions at which two plans put the same address with the same role, and
    the share of (address, role) pairs they share (over the larger plan)."""
    pa = [(e["address"], e["role"]) for e in a["entities"]]
    pb = [(e["address"], e["role"]) for e in b["entities"]]
    n = max(len(pa), len(pb)) or 1
    positions = sum(x == y for x, y in zip(pa, pb)) / n
    pairs = len(set(pa) & set(pb)) / n
    return positions, pairs


def netem_shares(plan):
    """The share of each netem profile per role (the descriptive confound check, §4.2)."""
    out = {}
    for role in ("benign", "attack"):
        group = [e for e in plan["entities"] if e["role"] == role]
        out[role] = {p: round(sum(e["netem"] == p for e in group) / len(group), 4) if group else None
                     for p in NETEM_PROFILES}
    return out


def summary_lines(plan):
    """A text summary of a plan for --plan review."""
    ents = plan["entities"]
    out = [(f"P3 plan {plan['dataset_version']} seed {plan['seed']} ({plan['seed_role']}), population "
            f"{plan['population']} x{plan['scale']}, {plan['duration_s']:.0f} s, heuristics {plan['heuristics']}, "
            f"server config {plan['server']['config_id']} (gunicorn {plan['server']['gunicorn_workers']} x "
            f"{plan['server']['gunicorn_threads']})"),
           f"pool {plan['pool']['range']}: {len(ents)} addresses, permutation seed {plan['pool']['permutation_seed']}",
           "timeline: lead-in {:.0f} s; ".format(plan["timeline"]["lead_in_s"])
           + "; ".join(f"{p['name']} [{p['start_s']:.0f},{p['stop_s']:.0f}] x{p['intensity']} {p['families']}"
                       for p in plan["timeline"]["phases"])
           + "; tail {:.0f} s".format(plan["timeline"]["tail_s"]),
           f"namespaces ({len(plan['namespaces'])}): "
           + ", ".join(f"{n['name']}={len(n['addresses'])}" for n in plan["namespaces"]),
           f"netem share per role: {netem_shares(plan)}",
           f"plan_set_sha256 {plan['plan_set_sha256']}"]
    for e in ents:
        s = e["schedule"]
        out.append(f"  {e['entity_id']:>18s} {e['address']:12s} {e['role']:6s} {e['kind_or_family']:18s} "
                   f":{e['port']} {e['netem']:10s} {e['namespace']:16s} [{s['start_s']:.0f},{s['stop_s']:.0f}]"
                   f"{' held-out' if e['held_out'] else ''} {e['params']}")
    for d in plan["dropped"]:
        out.append(f"  DROPPED by the benign gate: entity {d['entity_index']} {d['kind']} {d['params']}")
    return out
