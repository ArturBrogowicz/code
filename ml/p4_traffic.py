"""P4 traffic on profile R (docs/P4_SLOW_DESIGN.md §4.2, §8, §13): the benign population of a run and its halving rule.

Pure and seeded; nothing here touches the system. build_plan() returns one seed's population as data, in the P3/L7 v2
form (ml/l7_pools.py, docs/L7V2_DESIGN.md §6): the addresses are a seeded sample of 10.0.16.0/20 (l7_pools.draw_pool,
whose order is the role permutation, so an address does not reveal its role), every entity has its kind, its drawn
parameters, its sub-seed and client seed (l7_pools.subseed), a netem profile balanced within its role
(l7_pools.NETEM_PROFILES) and a schedule on the P4 run's timeline. No new address scheme: a P4 plan is an l7_pools
pool under its own stream name (VERSION).

The benign mix of §4.2, the L7 v2 runner's kinds on R:
  * 40 browser devices (tpcw_browsing, levels 30 and 60, TPC-W's think mean drawn within 7-8 s, as in L7 v2);
  * the co-resident CGNAT pools CGNAT-12 and CGNAT-24 (cgnat_browsers on the browsing chain, :443), never removed;
  * 10 search users, api_bulk and a polite crawler (their L7 v2 parameters);
  * 4 uploaders, bodies up to 2 MB on /upload, and 2 slow_uploaders, the same client behind a 16 kbit/s link
    (ml/l7_benign.py upload kinds; the runner shapes their namespace with netem at that rate, NETEM_SLOW, and the
    generator paces the body at the same rate). They are the hard negative of the per-connection rule's byte-rate leg.
Every benign entity runs for the whole run; the run is 30 s of baseline, 210 s of attack and 30 s of recovery
(eval/p4_outcome.TIMELINE, re-registered 2026-10-31).

The halving rule, frozen before the pilot (§4.2): if either of the two pilot controls is unhealthy (Q(C) < 99 % or a
route class of at least 20 judged requests below 95 %, eval/p4_outcome.control_health, D-050), the browser devices are halved and the pilot is repeated;
CGNAT-12 and CGNAT-24 are never removed. A plan carries how many times the rule has fired (`halvings`): 40, 20, 10...
browser devices. The devices dropped are the last ones of the list, and an entity keeps its index, sub-seed, address
and parameters whatever the halvings, so a halved plan is the full plan without those devices.

Each entity's P4 label (`p4_role`) is what eval/p4_validation.py and eval/p4_outcome.py read: "slow_uploader", "cgnat",
and the kind for every other benign entity ("attack" for the attack families).

The two P4 families at the frozen scale of §5 (FAMILIES; scenario parameters of the in-repo generators, ml/l7_gen.py
slowloris and slowpost, nothing else): sources from the ladders {100, 175, 250, 300} and {5, 10, 20, 40}, on port 80,
each attacking only during the attack (30-240 s of the run):
  * Slowloris (family 1): 6 connections per source, the benign device's footprint; each connection sends a header
    line of at most 32 B every U[10, 40] s, never completing the request;
  * slow POST, R.U.D.Y.-like (family 2): 1-2 connections per source (drawn per source) on /upload, each declaring a
    Content-Length of U[100 KB, 1 MB] and sending a chunk of 1-16 B every U[5, 30] s.
A connection that is closed is re-opened at once and carries on with its slot's schedule, as the in-repo generators
re-open. loris_schedule() and post_schedule() are each source's seeded schedule, the one its generator executes and
prints with --plan. Only the number of sources moves (the ladder); the pacing is frozen. Slow read stays secondary
(§5: recorded and replayed, not in the verdict) and is not built here.

This module stays light (no numpy, no eval/ imports): ml/l7_gen.py, which every generator process runs, imports it.
"""
import copy
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

VERSION = "2026-10-p4r"          # the stream name under which l7_pools draws a P4 plan's pool and sub-seeds
PLAN_FORMAT = "p4-plan/1"
# pinned against eval/p4_outcome.TIMELINE, slow_pc.VALIDATION_SEEDS and eval/p4_outcome.BLOCK_SEEDS by the tests; the
# pilot seeds are §13 row 2's
TIMELINE = {"baseline_s": 30, "attack_s": 210, "recovery_s": 30}
SEEDS = {"pilot": tuple(range(9101, 9107)), "val": (4001, 4002), "eval": tuple(range(3101, 3111))}
BROWSER_DEVICES = 40
SLOW_UPLOADER, CGNAT, ATTACK = "slow_uploader", "cgnat", "attack"
NETEM_SLOW = "rate_16kbit"       # the slow uploaders' link: netem rate 16kbit on their namespace
NETEM_SLOW_ARGV = ("tc", "qdisc", "replace", "dev", "veth_in", "root", "netem", "rate", "16kbit")
_TP = {"level": 30, "first_visit_s": [0.0, 10.0]}
_TP_DRAWS = {"level": ["choice", [30, 60]], "think_mean_s": ["uniform", 7.0, 8.0]}
_UPLOAD = {"think_s": [4.0, 10.0], "path": "/upload", "body_bytes": [200, 2_000_000]}
# The benign mix of §4.2, in entity-index order (the order fixes each entity's index, sub-seed and address).
BENIGN = (
    {"kind": "tpcw_browsing", "count": BROWSER_DEVICES, "ports": [80, 443], "params": dict(_TP),
     "draws": dict(_TP_DRAWS), "halved": True},
    {"kind": "cgnat_browsers", "count": 1, "ports": [443], "p4_role": CGNAT,
     "params": {"users": 12, "level": 30, "first_visit_s": [0.0, 60.0], "nav": "tpcw:browsing"}},
    {"kind": "cgnat_browsers", "count": 1, "ports": [443], "p4_role": CGNAT,
     "params": {"users": 24, "level": 30, "first_visit_s": [0.0, 60.0], "nav": "tpcw:browsing"}},
    {"kind": "search_user", "count": 10, "ports": [80, 443], "params": dict(_TP), "draws": dict(_TP_DRAWS)},
    {"kind": "api_bulk", "count": 1, "ports": [443], "params": {"rps": [15.0, 20.0], "endpoints": [2, 3]}},
    {"kind": "crawler_polite", "count": 1, "ports": [443], "params": {"rps": [2.0, 5.0], "level": 30}},
    {"kind": "uploader", "count": 4, "ports": [80], "params": dict(_UPLOAD)},
    {"kind": "slow_uploader", "count": 2, "ports": [80], "p4_role": SLOW_UPLOADER, "netem": NETEM_SLOW,
     "params": {**_UPLOAD, "rate_Bps": 2000}},
)
BENIGN_ENTITIES = sum(s["count"] for s in BENIGN)
# §5, frozen with the smoke run (§13 row 2). `levels` is the ladder of sources; `params` are the generator's.
LINE_MAX_BYTES = 32
FAMILIES = {
    "loris": {"family": "slowloris", "mechanism": "conns", "levels": (100, 175, 250, 300), "ports": [80],
              "params": {"conns": 6, "header_every_s": [10.0, 40.0], "line_max_bytes": LINE_MAX_BYTES}},
    "post": {"family": "slowpost", "mechanism": "conns", "levels": (5, 10, 20, 40), "ports": [80],
             "params": {"conns": 1, "byte_every_s": [5.0, 30.0], "chunk_bytes": [1, 16],
                        "content_length": [100_000, 1_000_000], "path": "/upload"},
             "draws": {"conns": ["int", 1, 2]}},
}
CONTENT_LENGTHS_PER_SLOT = 32       # the Content-Lengths a slow-POST slot declares, one per (re)open, in turn
# Entity indices after the benign ones are the attack families', loris then post, each at its ladder's top: the
# pool is drawn at its largest size, so that an address depends neither on the halvings nor on the ladder's level.
FAMILY_BASE = {"loris": BENIGN_ENTITIES, "post": BENIGN_ENTITIES + FAMILIES["loris"]["levels"][-1]}
POOL_SIZE = BENIGN_ENTITIES + sum(f["levels"][-1] for f in FAMILIES.values())


class PlanError(ValueError):
    """A P4 plan cannot be built as asked."""


def browser_devices(halvings):
    """The number of browser devices after the halving rule fired `halvings` times."""
    if not (isinstance(halvings, int) and not isinstance(halvings, bool) and halvings >= 0):
        raise PlanError(f"halvings must be an int >= 0, got {halvings!r}")
    return BROWSER_DEVICES >> halvings


def halve(control_reasons):
    """The frozen rule of §4.2 over the two pilot controls: `control_reasons` holds, for each, the reasons it is
    unhealthy (eval/p4_outcome.control_health: Q(C) < 99 %, a route class of 20 requests or more below 95 %), empty when
    it is healthy.
    True iff either is unhealthy: then the browser devices are halved and the pilot is repeated."""
    control_reasons = list(control_reasons)
    if len(control_reasons) != 2:
        raise PlanError(f"the rule judges the two pilot controls, got {len(control_reasons)}")
    return any(bool(r) for r in control_reasons)


def check_seed(seed, seed_role):
    if seed_role not in SEEDS:
        raise PlanError(f"seed role {seed_role!r} not in {tuple(SEEDS)}")
    if seed not in SEEDS[seed_role]:
        raise PlanError(f"seed {seed} is not a P4 {seed_role} seed {SEEDS[seed_role]}")


def _entity(pools, seed, index, role, name, spec):
    sub = pools.subseed(VERSION, seed, index)
    erng = random.Random(sub)
    params = copy.deepcopy(spec["params"])
    for key, how in sorted(spec.get("draws", {}).items()):
        params[key] = pools.draw_value(how, params.get(key), erng)
    port = erng.choice(spec["ports"])
    return {"entity_id": f"p4:{seed}:{index}", "index": index, "subseed": sub, "role": role,
            "p4_role": spec.get("p4_role", ATTACK if role == "attack" else name), "kind_or_family": name,
            "mechanism": spec.get("mechanism"), "held_out": False, "port": port, "params": params,
            "client_seed": erng.randrange(2 ** 31), "netem": spec.get("netem")}


def benign_rows(pools, seed, halvings):
    """The benign entities of a seed (see the module docstring), with their schedules: the whole run."""
    total = sum(TIMELINE.values())
    keep = browser_devices(halvings)
    rows, index = [], 0
    for spec in BENIGN:
        for k in range(spec["count"]):
            i, index = index, index + 1
            if spec.get("halved") and k >= keep:
                continue
            row = _entity(pools, seed, i, "benign", spec["kind"], spec)
            row["schedule"] = {"start_s": 0.0, "stop_s": float(total), "phase": None}
            rows.append(row)
    return rows


def attack_rows(pools, seed, family, sources):
    """The first `sources` sources of a family (entity indices from FAMILY_BASE), attacking from the end of the
    baseline to the end of the attack."""
    spec = FAMILIES[family]
    if not (isinstance(sources, int) and not isinstance(sources, bool) and 0 <= sources <= spec["levels"][-1]):
        raise PlanError(f"{family}: {sources!r} sources, 0 to {spec['levels'][-1]}")
    start = float(TIMELINE["baseline_s"])
    rows = []
    for k in range(sources):
        row = _entity(pools, seed, FAMILY_BASE[family] + k, "attack", spec["family"], spec)
        row["params"]["port"] = row["port"]
        row["schedule"] = {"start_s": start, "stop_s": start + TIMELINE["attack_s"], "phase": family}
        rows.append(row)
    return rows


def _events(gap, size, duration_s, rng):
    """[[t, n]]: a gap U[gap] before each event, n uniform on the integer range `size`, until duration_s."""
    out, t = [], 0.0
    while True:
        t += rng.uniform(*gap)
        if t >= duration_s:
            return out
        out.append([round(t, 3), rng.randint(*size)])


def loris_schedule(params, duration_s, rng):
    """One Slowloris source's slots: for each of its `conns` connections, the header lines it sends, [[t, line]] with
    t in seconds from the source's start (a gap U[header_every_s] before each), every line at most line_max_bytes."""
    lo, hi = params["header_every_s"]
    slots = []
    for _ in range(params["conns"]):
        srng = random.Random(rng.randrange(2 ** 31))
        lines = [[t, f"X-{srng.randrange(10 ** 4)}: {srng.randrange(10 ** 4)}\r\n"]
                 for t, _n in _events((lo, hi), (0, 0), duration_s, srng)]
        if any(len(line) > params.get("line_max_bytes", LINE_MAX_BYTES) for _t, line in lines):
            raise PlanError("a header line longer than line_max_bytes")
        slots.append({"lines": lines})
    return slots


def post_schedule(params, duration_s, rng):
    """One slow-POST source's slots: for each of its `conns` connections, the Content-Lengths it declares (one per
    (re)open, in turn) and its chunks, [[t, bytes]] with a gap U[byte_every_s] before each."""
    slots = []
    for _ in range(params["conns"]):
        srng = random.Random(rng.randrange(2 ** 31))
        lengths = [srng.randint(*params["content_length"]) for _ in range(CONTENT_LENGTHS_PER_SLOT)]
        slots.append({"content_lengths": lengths,
                      "chunks": _events(params["byte_every_s"], params["chunk_bytes"], duration_s, srng)})
    return slots


def assign(pools, seed, rows):
    """Addresses by entity index from the seed's pool, and netem balanced within each role over the profiles of
    l7_pools (an entity with a netem of its own, the slow uploaders, keeps it)."""
    pool = pools.draw_pool(VERSION, seed, POOL_SIZE)
    for r in rows:
        r["address"] = pool[r["index"]]
    for role in ("benign", "attack"):
        group = [r for r in rows if r["role"] == role and r["netem"] is None]
        order = list(range(len(group)))
        random.Random(pools.subseed(VERSION, seed, f"netem|{role}")).shuffle(order)
        for rank, k in enumerate(order):
            group[k]["netem"] = pools.NETEM_PROFILES[rank % len(pools.NETEM_PROFILES)]
    return rows


def build_plan(seed, seed_role, *, halvings=0, loris=0, post=0, check_role=True):
    """One seed's P4 population as data: the benign entities and `loris` and `post` sources of the two families (see
    the module docstring). A run uses the benign entities and the sources of its arm's family."""
    import l7_pools as pools
    if check_role:
        check_seed(seed, seed_role)
    rows = benign_rows(pools, seed, halvings) + attack_rows(pools, seed, "loris", loris) \
        + attack_rows(pools, seed, "post", post)
    rows = assign(pools, seed, rows)
    return {"format": PLAN_FORMAT, "version": VERSION, "seed": seed, "seed_role": seed_role, "halvings": halvings,
            "browser_devices": browser_devices(halvings), "sources": {"loris": loris, "post": post},
            "timeline": dict(TIMELINE),
            "pool": {"range": str(pools.POOL_NET), "size": POOL_SIZE,
                     "permutation_seed": pools.subseed(VERSION, seed, "pool")},
            "entities": rows}


def roles(entities):
    """{address: P4 label} of the given entities: the `roles` of a run manifest (eval/p4_validation.py) and the role
    map of eval/p4_outcome.summarize."""
    return {e["address"]: e["p4_role"] for e in entities}
