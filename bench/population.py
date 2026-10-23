#!/usr/bin/env python3
"""Seed namespaces, identities and traffic families for the harm benchmark
(docs/BENCHMARK_HARM_DESIGN.md 9, docs/HG1B_MINIMAL_DESIGN.md 5.3).

A population is drawn, not hand-written: for a seed namespace and a seed, the benign identities (source
address, behaviour class, link profile) and the attacker identities of one family come out the same every
time, and out differently for every seed. The result is a set of *streams*, one per engine process, because
the in-repo engine (bench/loadgen.py) has one schedule per process, splits it round-robin over the source
addresses it binds, picks paths uniformly, and writes records without a route: so a stream is class-pure,
one route class, one arrival process, one link profile (a process runs in one namespace and a namespace
carries one profile). The route class of a request is its stream's.

  * seed namespaces `calib`, `train`, `val`, `test` are disjoint ranges of the seed; the entity seed is a hash
    of (namespace, seed, role, index), so no draw is shared between them (G-03);
  * one link-profile distribution for every identity, attackers included (G-04): the suite's own mix;
  * the benign classes and attack families below are assumptions, labelled as such, tuned so that the
    aggregate route mix of the legit load matches the calibration's;
  * attack intensity is a cost rate in units of the spare capacity S; thresholds are never an input.

Nothing here opens a socket or starts a process: it builds plans (`Stream` records and engine commands).
"""
import collections
import dataclasses
import hashlib
import ipaddress
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import loadtools as LT
import origin as O

SEED_RANGES = {"calib": range(1, 100), "train": range(100, 200), "val": range(200, 300), "test": range(300, 400)}
NETEM_MIX = (("perfect", 0.30), ("broadband", 0.35), ("mobile_3g", 0.25), ("mobile_bad", 0.10))   # as the suite's
BENIGN_NETS = (ipaddress.ip_network("10.0.1.0/24"), ipaddress.ip_network("10.0.3.0/24"))
ATTACK_NETS = (ipaddress.ip_network("10.0.2.0/24"),)
ENGINE_CEILING_RPS = 5000          # per stream: the highest rate at which no CPU flag fired (verification run 2)
CPU_MS_PER_REQUEST = 0.1           # the engine's cost per request, from the same run
PROCESS_MB = 30                    # resident memory of one engine process (estimate)
PULSE_PERIOD, PULSE_DUTY = 15.0, 0.2
PATHS_PER_STREAM = 100
PIN_PLAN = {"server": "0-1", "daemon": "2", "legit": "6", "attack": "3-5,7"}      # docs/HG1B_MINIMAL_DESIGN.md 4
POOL = {"legit": 6, "attack": 4}                                                  # idle connections per identity


@dataclasses.dataclass(frozen=True)
class BenignClass:
    name: str
    rate_share: float                # of the legit request rate
    id_share: float                  # of the identities
    routes: tuple                    # ((route class, weight), ...)
    process: str                     # poisson | pulse
    rate_sigma: float = 0.5          # log-normal sigma of an identity's rate multiplier (assumed)
    basis: str = "assumed"           # sourced | assumed


BENIGN_CLASSES = (
    BenignClass("page_browser", 0.40, 0.35, (("C0", 0.55), ("C1", 0.30), ("C2", 0.15)), "poisson"),
    BenignClass("spa_burst", 0.08, 0.06, (("C2", 0.75), ("C3", 0.25)), "pulse"),
    BenignClass("api_steady", 0.08, 0.05, (("C2", 1.0),), "poisson", 0.3),
    BenignClass("api_bursty", 0.06, 0.05, (("C2", 0.9), ("C1", 0.1)), "pulse"),
    BenignClass("search_user", 0.10, 0.15, (("C3", 0.8), ("C2", 0.2)), "poisson", 0.7),
    BenignClass("crawler_polite", 0.08, 0.03, (("C1", 0.6), ("C2", 0.2), ("C0", 0.2)), "poisson", 0.2),
    BenignClass("nat_pool", 0.18, 0.04, (("C0", 0.5), ("C1", 0.3), ("C2", 0.15), ("C3", 0.05)), "poisson", 0.8),
    BenignClass("downloader", 0.02, 0.27, (("C5", 0.5), ("C1", 0.5)), "poisson", 1.0),
)


@dataclasses.dataclass(frozen=True)
class AttackFamily:
    name: str
    route_class: str
    process: str                     # the arrival process of every source
    grounding: str                   # the external reference, or "assumed" (docs/BENCHMARK_HARM_DESIGN.md 11.2)
    note: str


ATTACK_FAMILIES = {f.name: f for f in (
    AttackFamily("costly_search_flood", "C3", "poisson", "OWASP API4:2023 unrestricted resource consumption",
                 "requests to the search route, the intensity a cost rate, spread over many sources"),
    AttackFamily("costly_export_flood", "C5", "poisson", "OWASP API4:2023 unrestricted resource consumption",
                 "requests to the export route"),
    AttackFamily("cheap_static_flood", "C1", "poisson", "assumed",
                 "the control where the rules win: a plain flood of the cheap dynamic route")
)}


@dataclasses.dataclass(frozen=True)
class Timeline:
    baseline_s: float = 30.0
    attack_s: float = 45.0
    recovery_s: float = 30.0

    @property
    def total_s(self):
        return self.baseline_s + self.attack_s + self.recovery_s


@dataclasses.dataclass(frozen=True)
class NsSpec:
    index: int
    name: str
    netem: str


@dataclasses.dataclass(frozen=True)
class Identity:
    role: str                        # benign:<class> | attack:<family>
    cls: str
    index: int
    address: str
    netem: str
    ns_index: int
    seed: int


@dataclasses.dataclass(frozen=True)
class Stream:
    id: str
    kind: str                        # legit | attack
    cls: str                         # the behaviour classes it carries, or the attack family
    route_class: str
    process: str
    rate: float                      # total requests/s over its addresses (for a pulse, the mean over a period)
    period: float
    duty: float
    seed: int
    netem: str
    ns_index: int
    addresses: tuple
    paths: tuple
    start_s: float
    duration_s: float
    cpu: str                         # legit | attack: which CPUs the stream is pinned to
    pool: int


@dataclasses.dataclass(frozen=True)
class Population:
    namespace: str
    seed: int
    timeline: Timeline
    namespaces: tuple
    identities: tuple
    streams: tuple

    def of_kind(self, kind):
        return tuple(s for s in self.streams if s.kind == kind)

    def route_rates(self, kind):
        """Requests/s per route class that the streams of `kind` send."""
        out = collections.defaultdict(float)
        for s in self.of_kind(kind):
            out[s.route_class] += s.rate
        return dict(out)

    def alias_plan(self):
        """{namespace index: [address, ...]}: what the executor must add to each client namespace."""
        plan = collections.defaultdict(list)
        for ident in self.identities:
            plan[ident.ns_index].append(ident.address)
        return {k: sorted(v, key=lambda a: tuple(map(int, a.split(".")))) for k, v in sorted(plan.items())}


# --- seeds -------------------------------------------------------------------------------------

def check_seed(namespace, seed):
    if namespace not in SEED_RANGES:
        raise ValueError(f"seed namespace {namespace!r}: one of {', '.join(SEED_RANGES)}")
    if seed not in SEED_RANGES[namespace]:
        r = SEED_RANGES[namespace]
        raise ValueError(f"seed {seed} is outside the namespace {namespace!r} ({r.start}-{r.stop - 1})")


def entity_seed(namespace, seed, role, index):
    """The first 8 bytes of sha256(namespace|seed|role|index): no draw is shared between namespaces."""
    return int.from_bytes(hashlib.sha256(f"{namespace}|{seed}|{role}|{index}".encode()).digest()[:8], "big")


# --- link profiles and namespaces ---------------------------------------------------------------

def namespaces(per_profile=1):
    """The client namespaces: `per_profile` for each link profile, each carrying its profile."""
    out = []
    for profile, _ in NETEM_MIX:
        for j in range(per_profile):
            out.append(NsSpec(len(out), f"client_{profile}_{j + 1}", profile))
    return tuple(out)


def _draw_netem(rng):
    x, acc = rng.random(), 0.0
    for profile, weight in NETEM_MIX:
        acc += weight
        if x < acc:
            return profile
    return NETEM_MIX[-1][0]


def _largest_remainder(total, shares):
    raw = [total * s for s in shares]
    counts = [int(x) for x in raw]
    for i in sorted(range(len(shares)), key=lambda i: (-(raw[i] - counts[i]), i))[:total - sum(counts)]:
        counts[i] += 1
    return counts


# --- identities --------------------------------------------------------------------------------

def _addresses(nets, n, rng):
    """n distinct addresses drawn from the networks in order: the first one is used up before the second."""
    out = []
    for net in nets:
        hosts = [str(h) for h in net.hosts()]
        take = min(n - len(out), len(hosts))
        out += rng.sample(hosts, take)
    if len(out) < n:
        raise ValueError(f"{n} addresses asked of {sum(len(list(net.hosts())) for net in nets)}")
    return out


def _identities(namespace, seed, role_prefix, groups, ns_specs, nets, per_profile):
    """Identities of the given (class, count) groups, in order."""
    # addresses are drawn per seed; each identity draws its own link profile from the shared mix
    total = sum(n for _, n in groups)
    addrs = _addresses(nets, total, random.Random(entity_seed(namespace, seed, f"{role_prefix}:addresses", 0)))
    out, k = [], 0
    for cls, count in groups:
        for index in range(count):
            iseed = entity_seed(namespace, seed, f"{role_prefix}:{cls}", index)
            rng = random.Random(iseed)
            profile = _draw_netem(rng)
            ns = [n for n in ns_specs if n.netem == profile][rng.randrange(per_profile)]
            out.append(Identity(f"{role_prefix}:{cls}", cls, index, addrs[k], profile, ns.index, iseed))
            k += 1
    return out


def attack_rate(level, spare_cpu_s, cost_ms):
    """Total requests/s whose cost is `level` x S: the intensity of an L7 family (docs/BENCHMARK_HARM_DESIGN.md
    6.2). Only the level, the spare capacity and the route's cost enter: no threshold, no detector."""
    return level * spare_cpu_s / (cost_ms / 1000.0)


# --- streams -----------------------------------------------------------------------------------

def _paths(route_class, rng):
    if route_class == "C0":
        return tuple(f"/static/{n}" for n in rng.sample(range(1, 100_000), 20))
    if route_class == "C1":
        return tuple(f"/page/{n}" for n in rng.sample(range(1, 100_000), PATHS_PER_STREAM))
    if route_class == "C2":
        return tuple(f"/api/item/{n}" for n in rng.sample(range(1, 100_000), PATHS_PER_STREAM))
    if route_class == "C3":
        terms = sorted({f"{rng.choice(O.WORDS)}+{rng.choice(O.WORDS)}" for _ in range(PATHS_PER_STREAM * 2)})
        return tuple(f"/search?q={t}" for t in rng.sample(terms, min(PATHS_PER_STREAM, len(terms))))
    if route_class == "C5":
        return tuple(f"/export?r={n}" for n in rng.sample(range(1000), PATHS_PER_STREAM))
    raise ValueError(f"route class {route_class!r} is not served")


def _pulse_rate(rate):
    """A pulse sends whole requests per period: the rate becomes count / period, at least one a period."""
    return max(1, round(rate * PULSE_PERIOD)) / PULSE_PERIOD


def _make_stream(namespace, seed, sid, kind, cls, route_class, process, rate, netem, ns_index, addresses,
                 start_s, duration_s):
    if process == "pulse":
        rate = _pulse_rate(rate)
    rng = random.Random(entity_seed(namespace, seed, f"stream:{sid}", 1))
    return Stream(sid, kind, cls, route_class, process, round(rate, 6),
                  PULSE_PERIOD if process == "pulse" else 1.0, PULSE_DUTY if process == "pulse" else 0.5,
                  entity_seed(namespace, seed, f"stream:{sid}", 0) % 2**31, netem, ns_index,
                  tuple(sorted(addresses, key=lambda a: tuple(map(int, a.split("."))))),
                  _paths(route_class, rng), start_s, duration_s, "legit" if kind == "legit" else "attack",
                  POOL[kind])


def _legit_streams(namespace, seed, idents, rho_rps, timeline):
    by_class = collections.defaultdict(list)
    for ident in idents:
        by_class[ident.cls].append(ident)
    rate_of = {}
    for cls in BENIGN_CLASSES:
        members = by_class.get(cls.name, [])
        mult = [math.exp(random.Random(entity_seed(namespace, seed, f"rate:{i.role}", i.index))
                         .gauss(-cls.rate_sigma ** 2 / 2, cls.rate_sigma)) for i in members]
        for ident, m in zip(members, mult, strict=True):
            rate_of[ident.address] = rho_rps * cls.rate_share * m / sum(mult)
    acc = collections.defaultdict(lambda: {"rate": 0.0, "addresses": set(), "classes": set()})
    cls_by_name = {c.name: c for c in BENIGN_CLASSES}
    for ident in idents:
        cls = cls_by_name[ident.cls]
        for route, weight in cls.routes:
            slot = acc[(cls.process, route, ident.netem, ident.ns_index)]
            slot["rate"] += rate_of[ident.address] * weight
            slot["addresses"].add(ident.address)
            slot["classes"].add(cls.name)
    out = []
    for (process, route, netem, ns_index), slot in sorted(acc.items()):
        sid = f"L-{process}-{route}-{netem}-{ns_index}"
        out.append(_make_stream(namespace, seed, sid, "legit", "+".join(sorted(slot["classes"])), route, process,
                                slot["rate"], netem, ns_index, slot["addresses"], 0.0, timeline.total_s))
    return out


def _attack_chunks(addresses, per_source):
    """[(addresses, rate)] for the streams of one link-profile group: balanced, none above the engine's ceiling.
    One address above the ceiling by itself is carried by several processes that share it (the server sees one
    source either way)."""
    if per_source > ENGINE_CEILING_RPS:
        shares = math.ceil(per_source / ENGINE_CEILING_RPS)
        return [((a,), per_source / shares) for a in addresses for _ in range(shares)]
    per_stream = max(1, int(ENGINE_CEILING_RPS // per_source))
    chunks = math.ceil(len(addresses) / per_stream)
    return [(tuple(addresses[j::chunks]), per_source * len(addresses[j::chunks])) for j in range(chunks)]


def _attack_streams(namespace, seed, idents, family, total_rate, timeline):
    per_source = total_rate / len(idents)
    by_ns = collections.defaultdict(list)
    for ident in idents:
        by_ns[(ident.netem, ident.ns_index)].append(ident.address)
    out = []
    for (netem, ns_index), addresses in sorted(by_ns.items(), key=lambda kv: kv[0][1]):
        chunks = _attack_chunks(addresses, per_source)
        for j, (part, rate) in enumerate(chunks):
            sid = f"A-{family.name}-{netem}-{ns_index}" + (f"-{j}" if len(chunks) > 1 else "")
            out.append(_make_stream(namespace, seed, sid, "attack", family.name, family.route_class,
                                    family.process, rate, netem, ns_index, part, timeline.baseline_s,
                                    timeline.attack_s))
    return out


def draw(namespace, seed, rho_rps, benign_identities=200, attack=None, timeline=None, per_profile=1):
    """The population of one block. `attack` is None (the control) or (family name, sources, total requests/s)."""
    check_seed(namespace, seed)
    timeline = timeline or Timeline()
    ns_specs = namespaces(per_profile)
    counts = _largest_remainder(benign_identities, [c.id_share for c in BENIGN_CLASSES])
    benign = _identities(namespace, seed, "benign", [(c.name, n) for c, n in zip(BENIGN_CLASSES, counts, strict=True)],
                         ns_specs, BENIGN_NETS, per_profile)
    streams = _legit_streams(namespace, seed, benign, rho_rps, timeline)
    idents = list(benign)
    if attack is not None:
        name, sources, total_rate = attack
        family = ATTACK_FAMILIES[name]
        attackers = _identities(namespace, seed, "attack", [(name, sources)], ns_specs, ATTACK_NETS, per_profile)
        streams += _attack_streams(namespace, seed, attackers, family, total_rate, timeline)
        idents += attackers
    return Population(namespace, seed, timeline, ns_specs, tuple(idents), tuple(streams))


def to_load_spec(stream, url, pins=None):
    """The wrapper's LoadSpec for one stream (bench/loadtools.py): the engine's command comes from build_plan."""
    pins = PIN_PLAN if pins is None else pins
    return LT.LoadSpec(url=url, rate=stream.rate, duration=stream.duration_s, timeout=10.0,
                       connections=stream.pool, max_workers=2000 if stream.kind == "legit" else 5000,
                       local_addrs=stream.addresses, paths=stream.paths, process=stream.process,
                       seed=stream.seed, period=stream.period, duty=stream.duty, cpus=pins[stream.cpu],
                       name=stream.id)
