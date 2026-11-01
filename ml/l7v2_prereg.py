"""The L7 v2 traffic-side pre-registration (docs/L7V2_DESIGN.md section 13): the benign navigation model and its
mapping, the new benign kinds, the class parameter rules C2, C3a and C3b, the mimicry levels and the harm admission
rule, read from the committed l7v2_prereg.json.

Pure and standard library only. load() checks the file's format and the consistency of its navigation block with the
TPC-W table (ml/tpcw_v18.json): every TPC-W state is either routed or listed as unmapped, never both, and the train,
held-out and unused mixes are the table's three mixes. tests/test_l7v2_prereg.py pins every value.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PREREG_PATH = os.path.join(HERE, "l7v2_prereg.json")
FORMAT = "l7v2-prereg/1"
ROUTE_KINDS = ("page", "product", "inpage")
INPAGE = ("search", "export")
MIMICRY = ("M1", "M2", "M3", "M2exp")


class PreregError(ValueError):
    """The L7 v2 pre-registration file is malformed or inconsistent with the TPC-W table."""


_cache = {}


def load(path=PREREG_PATH):
    """The pre-registration as a dict, after the format and consistency checks (cached per path)."""
    if path in _cache:
        return _cache[path]
    import l7_tpcw
    with open(path, encoding="utf-8") as fh:
        pre = json.load(fh)
    if pre.get("format") != FORMAT:
        raise PreregError(f"{path}: format {pre.get('format')!r}, expected {FORMAT!r}")
    nav = pre["navigation"]
    routes, unmapped = nav["routes"], set(nav["unmapped"])
    every = set(l7_tpcw.states())
    if set(routes) & unmapped:
        raise PreregError(f"routed and unmapped at once: {sorted(set(routes) & unmapped)}")
    if set(routes) | unmapped != every:
        raise PreregError(f"states neither routed nor unmapped: {sorted(every - set(routes) - unmapped)}")
    for state, (kind, target) in routes.items():
        if kind not in ROUTE_KINDS or (kind == "inpage" and target not in INPAGE):
            raise PreregError(f"{state}: route {kind!r} {target!r}")
    used = [nav["train_mix"], *nav["held_out_mixes"], *nav["unused_mixes"]]
    if sorted(used) != l7_tpcw.mixes():
        raise PreregError(f"train, held-out and unused mixes {used} are not the table's {l7_tpcw.mixes()}")
    if nav["session_start"] not in routes:
        raise PreregError("the session start has no route")
    if set(pre["mimicry"]) - {"exhausted", "rule"} != set(MIMICRY):
        raise PreregError(f"mimicry levels must be {MIMICRY}")
    life = pre["arrivals"].get("lifetimes")
    if life is not None:
        law = life["law"]
        if law.get("law") != "uniform" or not pre["arrivals"]["min_active_s"] <= law["lo"] < law["hi"]:
            raise PreregError(f"the lifetime law must be uniform with min_active_s <= lo < hi: {law}")
        if not 0.0 <= life["gap_s"][0] <= life["gap_s"][1]:
            raise PreregError(f"the session gap must be a range: {life['gap_s']}")
    _cache[path] = pre
    return pre


def routes(pre=None):
    """{TPC-W state: (kind, target)} of the mapped states."""
    pre = pre or load()
    return {s: tuple(v) for s, v in pre["navigation"]["routes"].items()}


def page_states(pre=None):
    """The mapped states that are page views (what M3 bots walk on)."""
    return {s for s, (kind, _) in routes(pre).items() if kind in ("page", "product")}


def dwell(mimicry, rng, pre=None):
    """One dwell of a C3b bot at `mimicry`, from its frozen law."""
    law = (pre or load())["mimicry"][mimicry]["dwell_s"]
    if law["law"] == "constant":
        return float(law["value"])
    if law["law"] == "uniform":
        return rng.uniform(law["lo"], law["hi"])
    return min(rng.expovariate(1.0 / law["mean"]), law["cap"])


def lifetime(rng, pre=None):
    """One key lifetime in seconds from the frozen law (arrivals.lifetimes, re-registered 2026-10-31 under D-034, T038-01):
    the same law for a benign session, a machine client and an attack entity."""
    law = (pre or load())["arrivals"]["lifetimes"]["law"]
    return rng.uniform(law["lo"], law["hi"])
