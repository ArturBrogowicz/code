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
(seeds 9201-9202: pools, netem, manifest, storage, rebuild). "l7v2" is the L7 v2 traffic (docs/L7V2_DESIGN.md §7,
frozen in ml/l7v2_prereg.json; counts from ml/p3_prereg.json "volume"): TPC-W browsing devices, the two CGNAT pools
(12 and 24 users), search users, exporters, a polite crawler and one of each P5 kind; the attack phases C2, C3a and
C3b (M2 with 10 M1 bots), 50 entities each, in a seeded order; and, in evaluation and pilot captures only, a 240 s
tail slot with C3b at M3 and the held-out benign kinds (the Shopping mix, the i.i.d. Zipf browser, a 30-device flash
crowd, api_bulk). The M3 bots reuse the C2 phase's addresses with new entity ids and UAs, so such a plan is schema 3
(l7_dataset: the time-indexed address map). Held-out kinds and families are left out of training and validation
captures by construction.

L7 v2 arrivals (re-registered 2026-10-31, T-030 L7V2-03; ml/l7v2_prereg.json "arrivals"): every benign entity, in every
role, arrives at a uniform time over [0, the last attack slot's end - 60 s] and runs to the end (a CGNAT pool runs from 0,
its users arriving over that span; held-out kinds arrive like the trained ones); every attack entity arrives at a uniform
time over [its slot's start, its slot's end - 60 s]; the flash crowd's minute starts at least 60 s from every slot start.
build_plan records the key-age check (the first-seen times of benign and attack units: KS distance, AUC) and refuses an
l7v2 plan whose key ages would carry its roles.

L7 v2 lifetimes (re-registered 2026-10-31 under D-034, T-038 finding T038-01; ml/l7v2_prereg.json arrivals.lifetimes):
every key lives one lifetime from one law, whatever its role. A browser-like benign kind runs sessions ("sessions": true in
its params; ml/l7_benign.session_users), each a new key; a machine client (the crawler, api_bulk, the P5 kinds) and every
attack entity run one lifetime from their arrival, capped at the capture's end, so an attack key may stay active past its
slot. An evaluation or pilot plan ends with the same 120 s benign tail after the M3 slot as every plan after its last
slot (1,140 s), and an M3 bot takes the address of a trained attack entity that has stopped (C2 first). The age check is
extended (rule_v2) to the key units' lifetimes and to window age at nominal times (key_units, nominal_tokens).

L7 v2 intensity (ml/p3_sizing_prereg.json, D-076): each core phase draws a multiplier m from {0.5, 1, 2} (ml/p3_prereg.json) on its
own family's knee from the P1 ladder, or, for a family without one, on its top tested level, marked. C2's per-entity rate is
m x K x S / (n x cost(route)), S and the cost from the calibration record in use; C3a fills its registered entities and then its pace,
page gaps divided by (m x K x S / per-source cost) / n, at most 2 x P1's pace; C3b is carried by count only, its registered bots. Target,
realized, shortfall and excess are recorded per phase in the plan's intensity and on the phase in its timeline. A pilot plan without knees
keeps the placeholder sizing (C2 at L = 1, C3a's gaps divided by m, C3b's m recorded) and says so. A
training, validation or evaluation plan needs frozen knees (`knees`) bound to a frozen calibration record: the knees
carry the sha256 of the record they were measured on (`record_sha256`, the record's own digest), and the plan's record
must be that record (T-030 L7V2-08); a pilot plan without knees uses the placeholder knee L = 1 and says so.
"""
import bisect
import copy
import hashlib
import ipaddress
import json
import math
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
    ["scale", lo, hi] (a common factor on the base value or both ends of a base range) | ["ua_table"] (a browser UA
    from ml/l7_benign.UA_TABLE by weight)."""
    how = spec[0]
    if how == "ua_table":
        import l7_benign
        return l7_benign.draw_ua(rng)
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


def _l7v2_benign():
    """The L7 v2 benign mix (docs/L7V2_DESIGN.md §7.2, §7.3; ml/l7v2_prereg.json): every browser-like kind sends a
    Referer and keeps cookies; TPC-W's think mean is drawn per device within the specification's 7-8 s."""
    tp, draws = {"level": 30, "first_visit_s": [0.0, 10.0]}, {"level": ["choice", [30, 60]],
                                                               "think_mean_s": ["uniform", 7.0, 8.0]}
    tail = {"held_out": True}                        # held-out kinds arrive across the timeline too (L7V2-03)
    return [
        {"kind": "tpcw_browsing", "count": 52, "ports": [80, 443], "gate": True, "params": dict(tp), "draws": dict(draws)},
        {"kind": "cgnat_browsers", "count": 1, "ports": [443], "gate": True, "arrival": "users",
         "params": {"users": 12, "level": 30, "first_visit_s": [0.0, 60.0], "nav": "tpcw:browsing"}},
        {"kind": "cgnat_browsers", "count": 1, "ports": [443], "gate": True, "arrival": "users",
         "params": {"users": 24, "level": 30, "first_visit_s": [0.0, 60.0], "nav": "tpcw:browsing"}},
        {"kind": "search_user", "count": 20, "ports": [80, 443], "gate": True, "params": dict(tp), "draws": dict(draws)},
        {"kind": "exporter", "count": 5, "ports": [443], "gate": True, "params": {"level": 30},
         "draws": {"level": ["choice", [30, 60]]}},
        {"kind": "crawler_polite", "count": 1, "ports": [443], "gate": True, "params": {"rps": [2.0, 5.0], "level": 30}},
        *[dict(s, count=1) for s in _benign_kinds() if s["kind"] in ("curl_oneshot", "keepalive", "http2", "api_poll",
                                                                      "downloader", "uploader", "nat_gateway")],
        {"kind": "tpcw_shopping", "count": 10, "ports": [80, 443], "gate": True, "params": dict(tp),
         "draws": dict(draws), **tail},
        {"kind": "zipf_browser", "count": 10, "ports": [80, 443], "gate": True, "params": dict(tp),
         "draws": {"level": ["choice", [30, 60]]}, **tail},
        {"kind": "flash_crowd", "count": 30, "ports": [80, 443], "gate": True, "params": {"level": 30}, "arrival": "flash",
         "draws": {"level": ["choice", [30, 60]], "think_mean_s": ["uniform", 7.0, 8.0]}, **tail},
        {"kind": "api_bulk", "count": 1, "ports": [443], "gate": True, "params": {"rps": [15.0, 20.0], "endpoints": [2, 3]},
         **tail},
    ]


def _l7v2_attack():
    """The L7 v2 classes (ml/l7_bots.py) at P3's counts; a bot's UA is drawn from l7_benign.UA_TABLE by weight."""
    ua = {"ua": ["ua_table"]}
    return [
        {"family": "C2", "mechanism": "rate", "count": 50, "ports": [80, 443], "params": {"route": "C3"},
         "draws": dict(ua), "rate_rule": "C2"},
        {"family": "C3a", "mechanism": "nav", "count": 50, "ports": [80, 443], "params": {"route": "C3",
                                                                                         "page_gap_s": [2.0, 8.0]},
         "draws": dict(ua)},
        {"family": "C3b@M2", "mechanism": "nav", "count": 50, "ports": [80, 443],
         "params": {"route": "C5", "mimicry": "M2", "level": 30}, "draws": {**ua, "level": ["choice", [30, 60]]}},
        {"family": "C3b@M1", "mechanism": "nav", "count": 10, "ports": [80, 443],
         "params": {"route": "C5", "mimicry": "M1", "level": 30}, "draws": {**ua, "level": ["choice", [30, 60]]}},
        {"family": "C3b@M3", "mechanism": "nav", "count": 50, "ports": [80, 443], "held_out": True,
         "params": {"route": "C5", "mimicry": "M3", "level": 30}, "draws": {**ua, "level": ["choice", [30, 60]]},
         "reuse": "C2"},
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
    "l7v2": {
        "name": "l7v2-v1",
        "backend": "costed",
        "schema": 3,
        "timeline": {"lead_in_s": 60.0, "phase_s": 240.0, "tail_s": 120.0, "eval_tail_s": 240.0, "edge_jitter_s": 10.0},
        "phases": [{"name": "C2", "families": ["C2"]}, {"name": "C3a", "families": ["C3a"]},
                   {"name": "C3b", "families": ["C3b@M2", "C3b@M1"]}],
        "eval_slot": {"name": "C3b@M3", "families": ["C3b@M3"]},
        "arrivals": "spread",
        "intensity": [0.5, 1.0, 2.0],
        "benign": _l7v2_benign(),
        "attack": _l7v2_attack(),
    },
}
PLACEHOLDER_KNEES = {"status": "placeholder", "C2": 1.0}


def _gate(kind, params, duration_s, gate_seeds, heuristics, cache):
    """The P5b admissibility verdict (ml/l7_admissibility) of one drawn benign entity, cached by params."""
    import l7_admissibility as adm
    key = (kind, l7_dataset.canonical_json(params), float(duration_s), tuple(gate_seeds), heuristics)
    if key not in cache:
        rep = adm.check_spec(kind, params, duration_s, gate_seeds, l7_traffic.PROFILES[heuristics])
        cache[key] = {"admissible": bool(rep["admissible"]), "trips": rep["trips"]}
    return cache[key]


def _timeline(pop, version, seed, eval_slot=False):
    """Lead-in, the phases in a seeded order, then the tail; with eval_slot (L7 v2 evaluation and pilot captures) the
    eval slot of eval_tail_s seconds, its phase at intensity 1, follows the phases: in the l7v2 population (spread
    arrivals) the tail comes after it (D-034), in any other it is the tail."""
    t = pop["timeline"]
    phases = [dict(p) for p in pop["phases"]]
    random.Random(subseed(version, seed, "phases")).shuffle(phases)
    irng = random.Random(subseed(version, seed, "intensity"))
    start = t["lead_in_s"]
    for p in phases:
        p["start_s"], p["stop_s"] = start, start + t["phase_s"]
        p["intensity"] = irng.choice(pop["intensity"])
        start += t["phase_s"]
    tail = t["tail_s"]
    if eval_slot and pop.get("eval_slot"):
        slot = t["eval_tail_s"]
        phases.append(dict(pop["eval_slot"], start_s=start, stop_s=start + slot, intensity=1.0, slot="tail"))
        if pop.get("arrivals") == "spread":        # D-034: the benign tail follows the eval slot, as it follows the
            start += slot                          # last core slot in every plan, so M3's lifetimes are cut alike
        else:
            tail = slot
    total = start + tail
    return {"lead_in_s": t["lead_in_s"], "phase_s": t["phase_s"], "tail_s": tail,
            "edge_jitter_s": t["edge_jitter_s"], "phases": phases, "duration_s": total}


def _flash_start(slots, span, rule, within, rng):
    """The flash crowd's start: uniform over [0, span - within], its minute at least flash_gap_s from every slot start."""
    gap = rule["flash_gap_s"]
    for _ in range(10_000):
        f = round(rng.uniform(0.0, span - within), 3)
        if all(not (f - gap <= s["start_s"] < f + within + gap) for s in slots):
            return f
    raise PlanError("no flash crowd start keeps its distance from the attack slots")


def ks_distance(a, b):
    """The two-sample Kolmogorov-Smirnov distance."""
    a, b = sorted(a), sorted(b)
    i = j = 0
    d = 0.0
    while i < len(a) and j < len(b):
        t = min(a[i], b[j])
        while i < len(a) and a[i] <= t:
            i += 1
        while j < len(b) and b[j] <= t:
            j += 1
        d = max(d, abs(i / len(a) - j / len(b)))
    return d


def auc(neg, pos):
    """P(a positive value exceeds a negative one), ties counting one half: first-seen time as a score for `pos`."""
    pos = sorted(pos)
    total = 0.0
    for x in neg:
        lo, hi = bisect.bisect_left(pos, x), bisect.bisect_right(pos, x)
        total += (len(pos) - hi) + 0.5 * (hi - lo)
    return total / (len(neg) * len(pos))


def first_seen(rows):
    """(role, held_out, kind, t) of every key unit: an entity's arrival (its schedule start), and each CGNAT user's first
    view; the flash crowd is left out, a burst by definition."""
    import l7_benign
    out = []
    for e in rows:
        kind, start = e["kind_or_family"], e["schedule"]["start_s"]
        if kind == "flash_crowd":
            continue
        if kind == "cgnat_browsers":
            plan = l7_benign.plan_client(kind, e["params"], e["schedule"]["stop_s"] - start, random.Random(e["client_seed"]))
            first = {}                                # a user's first view (its first session's, D-034)
            for k, u in enumerate(plan["users"]):
                if u["views"]:
                    d = u.get("device", k)
                    first[d] = min(first.get(d, math.inf), u["views"][0]["t"])
            out += [(e["role"], e["held_out"], kind, start + t) for _d, t in sorted(first.items())]
        else:
            out.append((e["role"], e["held_out"], kind, start))
    return out


def _plan_of(e):
    """An entity row's plan as its generator builds it (duration max(1, stop - start), its client seed), or None for a
    kind without a plan (the P5 kinds and the smoke families)."""
    import l7_benign
    import l7_bots
    dur = max(1.0, e["schedule"]["stop_s"] - e["schedule"]["start_s"])
    rng = random.Random(e["client_seed"])
    try:
        if e["role"] == "attack":
            return l7_bots.plan_bot(e["kind_or_family"], e["params"], dur, rng)
        return l7_benign.plan_client(e["kind_or_family"], e["params"], dur, rng)
    except ValueError:
        return None


def nominal_requests(user):
    """[(t, path)] of one plan user at nominal times (no network time), from its own start."""
    if "views" in user:
        return [(v["t"], p) for v in user["views"] for w in v["waves"] for p in w]
    out, t = [], 0.0
    for path, gap, *_rest in user["requests"]:
        out.append((t, path))
        t += gap
    return out


def nominal_tokens(reqs):
    """The token starts of a key at nominal times (docs/L7V2_DESIGN.md 8.1, section 16): a page request (route class C1)
    opens a token, a later non-page request joins the open token, a request before the key's first page is a pageless
    token of its own."""
    import l7_webapp
    toks, page_open = [], False
    for t, path in reqs:
        if l7_webapp.route_class("GET", path) == "C1":
            toks.append(t)
            page_open = True
        elif not page_open:
            toks.append(t)
    return toks


def _unit_rows(rows):
    """Every key unit of a plan's entity rows (D-034, ml/l7v2_prereg.json arrivals.age_check.key_units_v2): (role,
    held_out, kind or family, first seen, last seen, token starts or None, address, UA or None), absolute seconds."""
    out = []
    for e in rows:
        start, kof = e["schedule"]["start_s"], e["kind_or_family"]
        plan = _plan_of(e)
        if plan is None:
            out.append((e["role"], e["held_out"], kof, start, e["schedule"]["stop_s"], None, e.get("address"), None))
            continue
        for u in plan["users"]:
            reqs = nominal_requests(u)
            if reqs:
                out.append((e["role"], e["held_out"], kof, start + reqs[0][0], start + reqs[-1][0],
                            [start + t for t in nominal_tokens(reqs)], e.get("address"), u.get("ua")))
    return out


def key_units(rows):
    """Every key unit of a plan's entity rows: (role, held_out, kind or family, first seen, last seen, token starts or
    None), absolute seconds."""
    return [u[:6] for u in _unit_rows(rows)]


def window_ages(toks, min_views, origin=None):
    """The age of each view window of a key at nominal times: token j's start, j >= min_views, minus `origin` (the first
    token's start by default)."""
    toks = toks or []
    return [toks[j] - (toks[0] if origin is None else origin) for j in range(min_views, len(toks))]


def age_report_v3(units, min_views):
    """The report-only age readings of a plan (ml/l7v2_prereg.json arrivals.age_check.report_v3, D-040, T042-F01), never
    a refusal: `units` are _unit_rows; each window's age from the first request of its address (any entity's, so a
    reused address counts from its donor's) and of its (IP, UA) key; the AUC of each as a score for the attack role,
    pooled over the trained attack windows and per attack family (held-out ones too), against the trained benign
    windows. An AUC below 0.5 means attack windows are the younger."""
    first_addr, first_key = {}, {}
    for _r, _h, _k, first, _last, _toks, addr, ua in units:
        first_addr[addr] = min(first_addr.get(addr, math.inf), first)
        first_key[(addr, ua)] = min(first_key.get((addr, ua), math.inf), first)
    views = {"address": {}, "ip_ua": {}}
    for r, h, k, _first, _last, toks, addr, ua in units:
        for name, origin in (("address", first_addr[addr]), ("ip_ua", first_key[(addr, ua)])):
            views[name].setdefault((r, h, k), []).extend(window_ages(toks, min_views, origin))
    out = {}
    for name, wins in views.items():
        ben = [a for (r, h, _k), v in wins.items() if r == "benign" and not h for a in v]
        atk = [a for (r, h, _k), v in wins.items() if r == "attack" and not h for a in v]
        fams = sorted({k for r, _h, k in wins if r == "attack"})
        out[f"{name}_age_auc"] = round(auc(ben, atk), 4) if ben and atk else None
        by = {}
        for fam in fams:
            fw = [a for (r, _h, k), v in wins.items() if r == "attack" and k == fam for a in v]
            by[fam] = round(auc(ben, fw), 4) if ben and fw else None
        out[f"{name}_age_auc_by_family"] = by
    return out


def age_check(rows, rule):
    """The pre-registered key-age check (ml/l7v2_prereg.json arrivals.age_check) of a plan's entity rows: first-seen
    times; with the D-034 extension (rule_v2), key lifetimes and window age too."""
    fs = first_seen(rows)
    ben = [t for r, _h, _k, t in fs if r == "benign"]
    atk = [t for r, _h, _k, t in fs if r == "attack"]
    out = {"ks": round(ks_distance(ben, atk), 4), "auc": round(auc(ben, atk), 4), "n_benign": len(ben),
           "n_attack": len(atk)}
    ok = out["ks"] <= rule["ks_max"] and abs(out["auc"] - 0.5) <= rule["auc_band"]
    held = [t for r, h, _k, t in fs if r == "benign" and h]
    if held:
        out["held_out_ks"] = round(ks_distance(held, [t for r, h, _k, t in fs if r == "benign" and not h]), 4)
        ok = ok and out["held_out_ks"] <= rule["held_out_ks_max"]
    if "rule_v2" in rule:
        ok = _age_check_v2(rows, rule, out) and ok
    out["pass"] = ok
    return out


def small_family_aucs(benign_windows, small, wins):
    """The window-age AUC of each attack family below family_min_units (C3b@M1), against the trained benign windows, and
    of C3b@M1 pooled with C3b@M2 (report_v3.small_families, D-040, T042-F03): report-only, the per-family check of rule_v2
    exempts them."""
    out = {fam: round(auc(benign_windows, v), 4) if benign_windows and v else None for fam, v in sorted(small.items())}
    if "C3b@M1" in small:
        both = small["C3b@M1"] + [a for (r, _h, k), v in wins.items() if r == "attack" and k == "C3b@M2" for a in v]
        out["C3b@M1+C3b@M2"] = round(auc(benign_windows, both), 4) if benign_windows and both else None
    return out


def _age_check_v2(rows, rule, out):
    """rule_v2 of the age check (D-034, T038-01): lifetimes, window age pooled and per family, held-out lifetimes."""
    units = _unit_rows(rows)
    life = {(r, h): [] for r in ("benign", "attack") for h in (False, True)}
    wins, fam_units = {}, {}
    for r, h, k, first, last, toks, _addr, _ua in units:
        life[(r, h)].append(last - first)
        if r == "attack":
            fam_units[k] = fam_units.get(k, 0) + 1
        wins.setdefault((r, h, k), []).extend(window_ages(toks, rule["min_views"]))
    lb, la = life[("benign", False)], life[("attack", False)]
    bw = [a for (r, h, _k), v in wins.items() if r == "benign" and not h for a in v]
    aw = [a for (r, h, _k), v in wins.items() if r == "attack" and not h for a in v]
    out.update({"units_benign": len(lb), "units_attack": len(la), "windows_benign": len(bw), "windows_attack": len(aw),
                "lifetime_ks": round(ks_distance(lb, la), 4), "lifetime_auc": round(auc(lb, la), 4),
                "window_age_auc": round(auc(bw, aw), 4) if bw and aw else None, "window_age_auc_by_family": {}})
    ok = out["lifetime_ks"] <= rule["lifetime_ks_max"] and abs(out["lifetime_auc"] - 0.5) <= rule["lifetime_auc_band"]
    ok = ok and out["window_age_auc"] is not None and abs(out["window_age_auc"] - 0.5) <= rule["window_age_auc_band"]
    for fam, n in sorted(fam_units.items()):
        fw = [a for (r, _h, k), v in wins.items() if r == "attack" and k == fam for a in v]
        if n >= rule["family_min_units"]:
            a = round(auc(bw, fw), 4) if bw and fw else None
            out["window_age_auc_by_family"][fam] = a
            ok = ok and a is not None and abs(a - 0.5) <= rule["window_age_auc_band"]
    hb = life[("benign", True)]
    if hb:
        out["held_out_lifetime_ks"] = round(ks_distance(hb, lb), 4)
        ok = ok and out["held_out_lifetime_ks"] <= rule["held_out_lifetime_ks_max"]
    if "report_v3" in rule:                        # D-040: report-only, it never changes ok
        out["report_v3"] = age_report_v3(units, rule["min_views"])
        small = {fam: [a for (r, _h, k), v in wins.items() if r == "attack" and k == fam for a in v]
                 for fam, n in fam_units.items() if n < rule["family_min_units"]}
        out["report_v3"]["small_families"] = small_family_aucs(bw, small, wins)
    return ok


def _lifetime_stop(version, seed, index, start, duration):
    """The stop of an entity that runs one lifetime (ml/l7v2_prereg.json arrivals.lifetimes, D-034) from `start`, capped
    at the capture's end; its own seeded stream, so no other draw of the plan moves."""
    import l7v2_prereg
    life = l7v2_prereg.lifetime(random.Random(subseed(version, seed, f"life|{index}")))
    return round(min(start + life, duration), 3)


def _donor(reuser, family, rows, taken):
    """The trained attack entity whose address `reuser` takes (D-034, ml/l7v2_prereg.json arrivals.lifetimes.reuse): one
    that stopped before the reuser starts and whose address no other reuser holds, `family` first, then the other
    trained families, in plan order; None when there is none."""
    trained = [d for d in rows if d["role"] == "attack" and not d["held_out"]]
    for d in ([d for d in trained if d["kind_or_family"] == family]
              + [d for d in trained if d["kind_or_family"] != family]):
        if d["address"] not in taken and d["schedule"]["stop_s"] <= reuser["schedule"]["start_s"]:
            return d
    return None


def c2_rps(m, level, spare_cpu_s, n, cost_ms):
    """C2's per-entity Poisson rate (ml/l7v2_prereg.json classes.C2): m x L x S / (n x cost)."""
    return round(m * level * spare_cpu_s / (n * cost_ms / 1000.0), 4)


SIZING_PREREG = os.path.join(HERE, "p3_sizing_prereg.json")
CORE_FAMILIES = {"C2": "C2", "C3a": "C3a", "C3b@M2": "C3b"}      # a core phase's family -> its class in P1's knees file


def _positive(v):
    return not isinstance(v, bool) and isinstance(v, (int, float)) and v > 0


def family_knee(knees, cls):
    """D-076 (ml/p3_sizing_prereg.json knees): a core family's knee from P1's knees file, or, for a family named in no_knee, its top tested
    level, marked: (level, no_knee). Neither is a refusal naming what is there."""
    value = knees.get(cls)
    if _positive(value):
        return value, False
    top = (knees.get("top_tested") or {}).get(cls)
    if cls in (knees.get("no_knee") or []) and _positive(top):
        return top, True
    what = f"have {cls} = {value!r}" if cls in knees else f"have no {cls}"
    raise PlanError(f"the knees {what} and no top tested level for it, and a plan sizes its {cls} phase from it (ml/p3_sizing_prereg.json "
                    f"knees); they name {sorted(knees)}")


def phase_sizing(knees, phases, specs, scale, rates):
    """D-076 (ml/p3_sizing_prereg.json): each core phase's target m x K, its carrier and what it reaches, {family: record}."""
    with open(SIZING_PREREG, encoding="utf-8") as fh:
        rule = json.load(fh)
    placeholder = knees.get("status") == "placeholder"
    spare, costs = rates["spare_cpu_s"], rates["route_costs_ms"]
    by_family = {s["family"]: s for s in specs}
    out = {}
    for ph in phases:
        for fam in ph["families"]:
            cls = CORE_FAMILIES.get(fam)
            if cls is None:
                continue
            m, n, params = ph["intensity"], by_family[fam]["count"] * scale, by_family[fam]["params"]
            unit = "bots" if cls == "C3b" else "S"
            if placeholder:
                knee, marked = (knees.get("C2"), False) if cls == "C2" else (None, False)
            else:
                knee, marked = family_knee(knees, cls)
            rec = {"family": fam, "m": m, "knee": knee, "no_knee": marked, "unit": unit, "entities": n, "pace_factor": None,
                   "rule": "placeholder" if placeholder else "D-076"}
            target = None if knee is None else m * knee
            if cls == "C2":
                realized = target
            elif cls == "C3a":
                per_source = (costs["C1"] + costs[params["route"]]) / 1000.0 / (sum(params["page_gap_s"]) / len(params["page_gap_s"]))
                pace = m if placeholder else min(target * spare / per_source / n, rule["pace_cap"])
                rec["pace_factor"] = round(pace, 4)
                realized = n * pace * per_source / spare
            else:
                realized = n
            rec.update(target=None if target is None else round(target, 4), realized=round(realized, 4),
                       shortfall=None if target is None else round(max(0.0, target - realized), 4),
                       excess=None if target is None else round(max(0.0, realized - target), 4))
            out[fam] = rec
    return out


def _knees(knees, seed_role, rec, need=("C2",)):
    """The knees a plan uses (T-030 L7V2-08): for training, validation and evaluation, frozen knees measured on the
    plan's own calibration record, which must be frozen; the placeholder for a pilot without knees. Knees that name
    their record (`record_sha256`, the record's digest) are refused on any other record, whatever the role."""
    bound = knees.get("record_sha256") if knees else None
    if bound is not None and bound != rec.get("sha256"):
        raise PlanError(f"the knees were measured on the calibration record {str(bound)[:12]}..., not on the record in "
                        f"use ({str(rec.get('sha256'))[:12]}...): C2's rate would mix two records")
    if seed_role in ("train", "val", "eval"):
        if knees is None:
            raise PlanError("an L7 v2 plan for training, validation or evaluation needs the frozen knees of the P1 "
                            "ladder (docs/L7V2_DESIGN.md 5.3); none is given")
        if knees.get("status") != "frozen":
            raise PlanError(f"knees with status {knees.get('status')!r}: training, validation and evaluation need "
                            "frozen ones")
        if rec.get("status") != "frozen":
            raise PlanError(f"the calibration record in use is {rec.get('status')!r}: training, validation and evaluation "
                            "need a frozen record (--calibration)")
        if bound is None:
            raise PlanError("knees for training, validation or evaluation must name the calibration record they were "
                            "measured on (record_sha256)")
    if knees is None:
        return dict(PLACEHOLDER_KNEES)
    for cls in need:                    # C-096: a refusal naming what is there, not a KeyError or a TypeError later
        family_knee(knees, cls)
    return dict(knees)


def build_plan(version, seed, seed_role, population="smoke", *, heuristics="tolerant", scale=1,
               gate_seeds=l7_traffic.GATE_SEEDS, launch_inadmissible=False, prereg=None, check_role=True,
               knees=None, record_path=None):
    """The capture plan of one seed as data (see the module docstring). With check_role, `seed` must be
    pre-registered for `seed_role` (ml/p3_prereg.json); tests may turn that off to probe other seeds. `knees` and
    `record_path` (the calibration record; default the placeholder) set the L7 v2 intensities."""
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
    keep_held = seed_role in ("eval", "pilot")           # never in training or validation captures
    timeline = _timeline(pop, version, seed, eval_slot=keep_held)
    duration = timeline["duration_s"]
    phase_of = {f: p for p in timeline["phases"] for f in p["families"]}
    spread = None
    if pop.get("arrivals") == "spread":
        import l7_benign
        import l7v2_prereg
        rule = l7v2_prereg.load()["arrivals"]
        within = l7v2_prereg.load()["benign_kinds"]["flash_crowd"]["arrive_within_s"]
        span = max(p["stop_s"] for p in timeline["phases"]) - rule["min_active_s"]
        spread = {"rule": rule, "span": span, "flash": _flash_start(timeline["phases"], span, rule, within,
                                                                     random.Random(subseed(version, seed, "flash")))}
    rates = None
    if population == "l7v2":
        import l7_backend
        rec, status, tag = l7_backend.load_record(record_path)
        if status == "measured":
            rec = l7_backend.arithmetic_record(rec, l7_backend.load_record()[0])
        import calibration as CAL
        rates = {"knees": _knees(knees, seed_role, rec), "record_status": rec["status"], "record_tag": tag,
                 "label": l7_backend.label(rec), "spare_cpu_s": CAL.spare_capacity(rec),
                 "route_costs_ms": dict(rec["route_costs_ms"])}
        rates["phases"] = phase_sizing(rates["knees"], timeline["phases"], pop["attack"], scale, rates)
        for p in timeline["phases"]:                  # on the phase too, which the capture's manifest keeps with its timeline
            sized = {f: rates["phases"][f] for f in p["families"] if f in rates["phases"]}
            if sized:
                p["sizing"] = sized

    specs = [("benign", s) for s in pop["benign"]] + [("attack", s) for s in pop["attack"]]
    rows, dropped, gate_cache, held_report = [], [], {}, []
    index = 0
    for role, spec in specs:
        name = spec["kind"] if role == "benign" else spec["family"]
        for _ in range(spec["count"] * scale):
            i, index = index, index + 1
            if spec.get("held_out") and not keep_held:
                continue
            if role == "attack" and name not in phase_of:
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
                if spec.get("rate_rule") == "C2":
                    costs = rates["route_costs_ms"]
                    params["rps"] = c2_rps(ph["intensity"], rates["phases"][name]["knee"], rates["spare_cpu_s"],
                                           spec["count"] * scale, costs[params.get("route", "C3")])
                elif population == "l7v2" and "page_gap_s" in params:
                    pace = (rates["phases"].get(name) or {}).get("pace_factor") or ph["intensity"]
                    params["page_gap_s"] = [round(x / pace, 3) for x in params["page_gap_s"]]
                elif ph["intensity"] != 1.0 and "rps" in params:
                    params["rps"] = round(params["rps"] * ph["intensity"], 3)
                if spec.get("reuse"):
                    row["reuse"] = spec["reuse"]
                rec = l7_traffic._check_spec(l7_traffic.AttackSpec(name, spec["mechanism"], row["held_out"], params))
                if rec["violations"] and not row["held_out"]:
                    raise PlanError(f"{row['entity_id']} {name}: not sub-threshold: {rec['violations']}")
                if row["held_out"]:
                    held_report.append({"entity_id": row["entity_id"], "violations": rec["violations"]})
                j = timeline["edge_jitter_s"]
                late = ph["stop_s"] - ph["start_s"] - spread["rule"]["min_active_s"] if spread else j
                start = round(ph["start_s"] + erng.uniform(0.0, late), 3)
                if spread:                                # D-034: one lifetime from the frozen law, past the slot
                    stop = _lifetime_stop(version, seed, i, start, duration)
                else:
                    stop = round(ph["stop_s"] - erng.uniform(0.0, j), 3)
                row["schedule"] = {"start_s": start, "stop_s": stop, "phase": ph["name"]}
            elif spread:
                if spec.get("arrival") == "users":
                    start, params["first_visit_s"] = 0.0, [0.0, round(spread["span"], 3)]
                elif spec.get("arrival") == "flash":
                    start = spread["flash"]
                else:
                    start = round(random.Random(subseed(version, seed, f"arrive|{i}")).uniform(0.0, spread["span"]), 3)
                stop = duration
                if name in l7_benign.SESSION_KINDS:        # D-034: sessions, each a new key
                    params["sessions"] = True
                else:                                      # a machine client: one lifetime
                    stop = _lifetime_stop(version, seed, i, start, duration)
                row["schedule"] = {"start_s": start, "stop_s": stop, "phase": None}
            else:
                slot = next((p for p in timeline["phases"] if p.get("slot") == spec.get("slot")), None) \
                    if spec.get("slot") else None
                row["schedule"] = {"start_s": slot["start_s"] if slot else 0.0, "stop_s": duration,
                                   "phase": slot["name"] if slot else None}
            if role == "benign" and spec.get("gate"):
                verdict = _gate(name, params, duration, gate_seeds, heuristics, gate_cache)
                row["gate_admissible"] = verdict["admissible"]
                if not verdict["admissible"] and not launch_inadmissible:
                    dropped.append({"entity_index": i, "kind": name, "params": params,
                                    "trips": verdict["trips"]})
                    continue
            rows.append(row)

    reusers = [r for r in rows if r.get("reuse")]
    rows = [r for r in rows if not r.get("reuse")]
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
    taken = set()
    for k, r in enumerate(reusers):                       # schema 3: an earlier phase's address, a new UA
        family = r.pop("reuse")
        donors = [d for d in rows if d["kind_or_family"] == family]
        if not donors:
            raise PlanError(f"{r['entity_id']}: no entity of the phase whose addresses it reuses")
        if spread:                                         # D-034: lifetimes outlive slots, so pick a stopped donor
            donor = _donor(r, family, rows, taken)
            if donor is None:
                raise PlanError(f"{r['entity_id']}: no trained attack entity has stopped before it starts")
            taken.add(donor["address"])
        else:
            donor = donors[k % len(donors)]
        if not donor["schedule"]["stop_s"] <= r["schedule"]["start_s"]:
            raise PlanError(f"{r['entity_id']}: reuses {donor['entity_id']}'s address while it is active")
        r["address"], r["namespace"], r["netem"] = donor["address"], donor["namespace"], donor["netem"]
        urng = random.Random(subseed(version, seed, f"ua|{r['index']}"))
        while r["params"].get("ua") == donor["params"].get("ua"):
            r["params"]["ua"] = draw_value(["ua_table"], None, urng)
        rows.append(r)
    age = age_check(rows, spread["rule"]["age_check"]) if spread else None
    if age is not None and not age["pass"]:
        raise PlanError(f"the plan's key ages would carry its roles (ml/l7v2_prereg.json arrivals.age_check): {age}")
    schema = 3 if reusers or pop.get("schema") == 3 else 2
    for r in rows:
        r["plan_sha256"] = l7_dataset.entity_plan_sha256(r)
        if schema == 3 and l7_dataset.pool_users(r):
            r["users"] = l7_dataset.pool_users(r)       # schema 3: a pool's users are entities (P3 note 4.4, §10)
    cid, cfg = p3_prereg.server_config(seed, pre)
    out_rates = None if rates is None else {k: v for k, v in rates.items() if k != "route_costs_ms"}
    return {"format": PLAN_FORMAT, "dataset_version": version, "seed": seed, "seed_role": seed_role,
            "population": pop["name"], "scale": scale, "heuristics": heuristics, "duration_s": duration,
            "schema": schema, "intensity": out_rates, "age_check": age,
            "server": {"config_id": cid, "gunicorn_workers": cfg["gunicorn_workers"],
                       "gunicorn_threads": cfg["gunicorn_threads"], "backend": pop.get("backend", "legacy")},
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
