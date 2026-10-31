#!/usr/bin/env python3
"""The L7 v2 rule arms (docs/L7V2_DESIGN.md 9.5, 10; ml/l7v2_rules_prereg.json) as detector packages on the common
score(batch) -> p interface, tuned on validation captures only at the common budget.

Every rule decides where the learned view arms decide: on the view windows of ml/train_l7v2.view_windows, keyed
(IP, ua_h, sid_h), restricted to the windows the live engine would score (train_l7v2.engine_scored), with the same
k-consecutive policy, the same budget in benign user units, the same objective and the same ties. A rule's batch row is
its statistics at the window: for each statistic, the maximum of its per-request value over the requests of its state
key that completed since the key's previous scored window (RuleStats). The rule gives p = 1 when any of its statistics
passes its threshold, else 0 (RuleScorer.score), so theta is fixed at 0.5 and k comes from the common k grid.

Arms (ml/l7v2_rules_prereg.json "arms"):
  sustained_rate   per (IP, UA) or per L7 v2 key: requests over {10, 30, 60} s > {2..50} req/s (ml/l7_baselines B2)
  token_bucket     per (IP, UA) or per key: the bucket's excess at rate {5..30} > burst {10..100} (B3)
  cost_budget      per (IP, UA) or per key: the frozen class costs summed over {10, 60, 300} s > tau x benign max
  multiscale_rate  per (IP, UA) or per key: any of the rates over {1, 10, 60, 300} s > its tau x benign max (jointly)
  population       per IP: new keys in 60 s, or the cookie-less share in 60 s, > its tau x benign max (replay only)
  default_rules, tolerant_rules, nginx_limits: the fixed replays (control_plane.py's heuristic, nginx.conf's limit_req)
R* is the best of the candidates of ml/l7v2_verdict_prereg.json best_rule by validation recall at the budget.

Offline and CPU only; it never opens an evaluation capture (select refuses one):
    ./venv/bin/python ml/l7v2_rules.py select --val V1 V2 --calibration REC --split SEL/split.json --out RULES
"""
import argparse
import bisect
import collections
import hashlib
import heapq
import json
import math
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import l7v2_model_prereg as MPRE
import l7v2_verdict_prereg as VPRE
import train_l7v2 as V

import l7_dataset as D
import l7_features as F
import l7_ingest as I

SPEC_PATH = os.path.join(HERE, "l7v2_rules_prereg.json")
SPEC_FORMAT = "l7v2-rules-prereg/1"
PACKAGE_FORMAT = "l7v2-rule-package/1"
SELECTION_FORMAT = "l7v2-rule-selection/1"
TUNED = ("sustained_rate", "token_bucket", "cost_budget", "multiscale_rate", "population")
FIXED = ("default_rules", "tolerant_rules", "nginx_limits")
ARMS = TUNED + FIXED
GROUPS = ("ip_ua", "ip_ua_sid", "ip", "own")
POP_WINDOW_S = 60.0


class RuleError(ValueError):
    """A rule spec, package or selection is malformed, altered, or would read data it must not."""


_cache = {}


def load_spec(path=SPEC_PATH):
    """The rule pre-registration, after its format and consistency checks (cached per path)."""
    if path in _cache:
        return _cache[path]
    with open(path, encoding="utf-8") as fh:
        spec = json.load(fh)
    if spec.get("format") != SPEC_FORMAT:
        raise RuleError(f"{path}: format {spec.get('format')!r}, expected {SPEC_FORMAT!r}")
    if tuple(spec["arms"]) != ARMS:
        raise RuleError(f"the rule arms are {ARMS}")
    if tuple(a for a in ARMS if spec["arms"][a]["tuned"]) != TUNED:
        raise RuleError(f"the tuned arms are {TUNED}")
    if not set(spec["key_grid"]) <= {"ip_ua", "ip_ua_sid"}:
        raise RuleError("a per-key rule is keyed (IP, UA) or (IP, UA, sid)")
    if spec["tau_grid"] != sorted(spec["tau_grid"]) or spec["theta"] != 0.5:
        raise RuleError("the tau grid is ascending and a rule's theta is 0.5")
    pk = spec["columns"]["per_key"]
    a = spec["arms"]
    if not (set(a["sustained_rate"]["windows_s"]) | set(a["multiscale_rate"]["windows_s"])) <= set(pk["rate_s"]) \
            or set(a["cost_budget"]["windows_s"]) != set(pk["cost_s"]) \
            or a["token_bucket"]["rates"] != pk["bucket_rates"]:
        raise RuleError("every arm's windows and rates must be columns")
    if max(pk["rate_s"] + pk["cost_s"]) > spec["statistic"]["lookback_s"]:
        raise RuleError("no statistic looks back further than lookback_s")
    if not set(VPRE.load()["best_rule"]["candidates"]) <= set(TUNED):
        raise RuleError("R*'s candidates are tuned rule arms")
    _cache[path] = spec
    return spec


def spec_sha256(path=SPEC_PATH):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def group_columns(spec=None):
    """{group: [column names]} in batch order: the per-key statistics for each key of key_grid, the per-IP ones, and
    the one judged on the key's own requests."""
    spec = spec or load_spec()
    pk = spec["columns"]["per_key"]
    per_key = [f"rate_{w}" for w in pk["rate_s"]] + [f"cost_{w}" for w in pk["cost_s"]] + \
        [f"bucket_{r}" for r in pk["bucket_rates"]]
    out = {g: [f"{g}:{n}" for n in per_key] for g in spec["key_grid"]}
    out["ip"] = [f"ip:{n}" for n in spec["columns"]["per_ip"]]
    out["own"] = [f"own:{n}" for n in spec["columns"]["own"]]
    return out


def columns(spec=None):
    """Every statistic column, in batch order."""
    return [c for cols in group_columns(spec).values() for c in cols]


# ───────────────────────────── statistics ─────────────────────────────

class RuleStats:
    """The rules' statistics, causal and streaming (ml/l7v2_rules_prereg.json "statistic"): observe() takes records in
    arrival order; query() gives each window's statistics after processing, in (completion, arrival) order, every
    request that completed by the window's time. The trainer feeds a whole capture, the replay feeds a recording as it
    arrives; given the same records in the same order both compute the same numbers. A record that arrives after a
    later completion was processed is processed late (counted in `late`)."""

    def __init__(self, costs, spec=None):
        self.spec = spec or load_spec()
        self.costs = {k: float(v) for k, v in costs.items()}
        pk = self.spec["columns"]["per_key"]
        self.rate_s, self.cost_s, self.rates = list(pk["rate_s"]), list(pk["cost_s"]), list(pk["bucket_rates"])
        self.max_w = max(self.rate_s + self.cost_s)
        self.lookback = float(self.spec["statistic"]["lookback_s"])
        self.groups = group_columns(self.spec)
        self.cols = columns(self.spec)
        self.daemon = self.spec["daemon"]
        arms = self.spec["arms"]
        self.max_rps = {"default": arms["default_rules"]["max_rps"], "tolerant": arms["tolerant_rules"]["max_rps"]}
        self.nginx = (float(arms["nginx_limits"]["rate_rps"]), float(arms["nginx_limits"]["burst"]))
        self._heap, self._n, self.frontier, self.late, self.processed = [], 0, -math.inf, 0, 0
        self._key, self._ip, self._hist, self._prev = {}, {}, {}, {}

    # -- input --
    def observe(self, rec):
        """Queue one normalised record (arrival order)."""
        if rec["msec"] < self.frontier:
            self.late += 1
        heapq.heappush(self._heap, (rec["msec"], self._n, rec))
        self._n += 1

    def advance(self, t):
        """Process every queued request that completed at or before t."""
        while self._heap and self._heap[0][0] <= t:
            msec, _n, rec = heapq.heappop(self._heap)
            self.frontier = max(self.frontier, msec)
            self._process(msec, rec)

    def _process(self, T, rec):
        ip, ua = rec["ip"], rec["ua_h"]
        v2 = I.key_v2(rec)
        cost = self.costs.get(rec.get("rc"), 0.0)
        keys = {"ip_ua": (ip, ua), "ip_ua_sid": v2}
        for g in self.spec["key_grid"]:
            t_g, vec = self._per_key(g, keys[g], T, cost)
            self._push(g, keys[g], t_g, vec)
        t_ip, vec, rejected = self._per_ip(ip, v2, T, rec)
        self._push("ip", ip, t_ip, vec)
        self._push("own", v2, t_ip, (rejected,))
        self.processed += 1

    def _per_key(self, g, key, T, cost):
        st = self._key.get((g, key))
        if st is None:
            st = self._key[(g, key)] = {"ts": [], "cum": [], "off": 0, "base": 0.0, "e": None, "last": None}
        if st["last"] is not None:
            T = max(T, st["last"])
        ts, cum = st["ts"], st["cum"]
        ts.append(T)
        cum.append((cum[-1] if cum else st["base"]) + cost)
        off = bisect.bisect_right(ts, T - self.max_w, st["off"])
        if off > 4096 and off > len(ts) // 2:              # compact: drop what no window reaches any more
            st["base"] = cum[off - 1]
            del ts[:off], cum[:off]
            off = 0
        st["off"] = off
        n, vec = len(ts), []
        for w in self.rate_s:
            vec.append((n - bisect.bisect_right(ts, T - w, off)) / w)
        for w in self.cost_s:
            i = bisect.bisect_right(ts, T - w, off)
            vec.append(cum[-1] - (cum[i - 1] if i > 0 else st["base"]))
        if st["last"] is None:                             # ml/l7_baselines._bucket_rejects's recursion
            e = [0.0] * len(self.rates)
        else:
            dt = T - st["last"]
            e = [max(0.0, x - r * dt + 1.0) for x, r in zip(st["e"], self.rates, strict=True)]
        st["e"], st["last"] = e, T
        return T, tuple(vec + e)

    def _new_ip(self):
        return {"last": None, "ng": [0.0, None],
                "d": {p: {"q": collections.deque(), "err": 0, "until": -math.inf} for p in ("default", "tolerant")},
                "pop": collections.deque(), "n_new": 0, "n_cl": 0, "seen": {}}

    def _per_ip(self, ip, v2, T, rec):
        st = self._ip.get(ip)
        if st is None:
            st = self._ip[ip] = self._new_ip()
        if st["last"] is not None:
            T = max(T, st["last"])
        st["last"] = T
        d = self.daemon
        status = rec.get("status") or 0
        is_err = status >= 400 and status != 503
        vec = []
        for prof in ("default", "tolerant"):                # control_plane.py's L7 heuristic, per IP
            s = st["d"][prof]
            if T < s["until"]:                             # banned: XDP drops it, the daemon never logs it
                vec.append(1.0)
                continue
            q = s["q"]
            q.append((T, is_err))
            s["err"] += is_err
            while q and T - q[0][0] > d["window_s"]:
                s["err"] -= q.popleft()[1]
            fire = False
            if len(q) >= d["min_requests"] and T - q[0][0] > 0:
                rps = len(q) / max(T - q[0][0], 1.0)
                fire = rps > self.max_rps[prof] or (s["err"] / len(q) > d["error_ratio"] and rps > d["error_min_rps"])
            if fire:
                q.clear()
                s["err"], s["until"] = 0, T + d["ban_ttl_s"]
            vec.append(1.0 if fire else 0.0)
        seen = st["seen"]                                  # population: new keys and the cookie-less share in 60 s
        new = v2 not in seen or T - seen[v2] > self.lookback
        seen[v2] = T
        if len(seen) > 4096:
            st["seen"] = {k: v for k, v in seen.items() if T - v <= self.lookback}
        cl = v2[2] == I.NO_SID
        pop = st["pop"]
        pop.append((T, new, cl))
        st["n_new"] += new
        st["n_cl"] += cl
        while pop and pop[0][0] <= T - POP_WINDOW_S:
            _t, a, b = pop.popleft()
            st["n_new"] -= a
            st["n_cl"] -= b
        vec += [float(st["n_new"]), st["n_cl"] / len(pop)]
        rate, burst = self.nginx                           # nginx limit_req, nodelay: a rejection changes no state
        e, last = st["ng"]
        excess = 0.0 if last is None else max(0.0, e - rate * (T - last) + 1.0)
        if excess > burst:
            rejected = 1.0
        else:
            st["ng"], rejected = [excess, T], 0.0
        return T, tuple(vec), rejected

    def _push(self, g, key, T, vec):
        h = self._hist.get((g, key))
        if h is None:
            h = self._hist[(g, key)] = [[], [], 0]
        h[0].append(T)
        h[1].append(vec)
        off = bisect.bisect_right(h[0], self.frontier - self.lookback - 60.0, h[2])
        if off > 4096 and off > len(h[0]) // 2:
            del h[0][:off], h[1][:off]
            off = 0
        h[2] = off

    def _window_max(self, g, key, lo, t):
        width = len(self.groups[g])
        h = self._hist.get((g, key))
        if h is None:
            return np.zeros(width)
        ts, vecs, off = h
        hi = bisect.bisect_right(ts, t, off)
        if hi == off:
            return np.zeros(width)
        i = min(max(bisect.bisect_right(ts, lo, off, hi), off), hi - 1)
        return np.max(np.asarray(vecs[i:hi], dtype=np.float64), axis=0)

    # -- output --
    def query(self, items):
        """[(L7 v2 key, t, the key session's first request start)] -> (n, len(cols)): each window's statistics, rows in
        the order given; windows are taken in completion order (stable)."""
        out = np.zeros((len(items), len(self.cols)))
        for i in sorted(range(len(items)), key=lambda i: items[i][1]):
            key, t, s0 = items[i]
            self.advance(t)
            prev = self._prev.get(key)
            same = prev is not None and prev[0] == s0
            lo = max(prev[1] if same else s0 - 1e-6, t - self.lookback)
            self._prev[key] = (s0, max(t, prev[1]) if same else t)
            ip, ua, _sid = key
            keys = {"ip_ua": (ip, ua), "ip_ua_sid": key, "ip": ip, "own": key}
            out[i] = np.concatenate([self._window_max(g, keys[g], lo, t) for g in self.groups])
        return out


def session_start(w):
    """A view window's key session's first request start: its opener's start minus its age (view_windows)."""
    return F.start_time(w["recs"][-1]) - w["age"]


def split_stats(loaded, split, costs, scored=None, spec=None):
    """The rule statistics of a Split's view windows, (n_windows, n_columns); the rows of windows the live engine
    would not score are NaN (no decision reads them). `loaded` is what built the Split: [(manifest, records, capture)]."""
    scored = V.engine_scored(split.view) if scored is None else scored
    cols = columns(spec)
    out = np.full((len(split.view), len(cols)), np.nan)
    by_cap = {}
    for i in sorted(scored):
        by_cap.setdefault(split.view[i]["capture"], []).append(i)
    for _m, recs, cap in loaded:
        idx = by_cap.get(cap, [])
        if not idx:
            continue
        rs = RuleStats(costs, spec)
        for r in sorted(recs, key=lambda r: r["_seq"]):
            rs.observe(r)
        out[idx] = rs.query([(split.view[i]["key"], split.view[i]["t"], session_start(split.view[i])) for i in idx])
    return out


# ───────────────────────────── the common policy, vectorised ─────────────────────────────

class Runs:
    """train_l7v2's policy and assessment (key_runs, decisions, assess) over a fixed list of view windows, vectorised
    so that a rule's whole grid can be scored: the same scored windows (engine_scored), the same time order per
    (capture, key), the same k-consecutive rule, the same entity outcome. A test checks it equals train_l7v2's."""

    def __init__(self, windows, split):
        keep = V.engine_scored(windows) if windows and windows[0].get("level") == "view" else range(len(windows))
        groups = {}
        for i in sorted(keep):
            w = windows[i]
            groups.setdefault((w["capture"], w["key"]), []).append((w["t"], i))
        order, gid, starts, ents = [], [], [], []
        for g, seq in enumerate(groups.values()):
            seq.sort()
            starts.append(len(order))
            order += [i for _t, i in seq]
            gid += [g] * len(seq)
            ents.append(windows[seq[0][1]]["ip"])
        names = sorted(set(ents))
        index = {e: j for j, e in enumerate(names)}
        self.split = split
        self.order = np.asarray(order, dtype=np.int64)
        self.t = np.asarray([windows[i]["t"] for i in order], dtype=np.float64)
        self.gid = np.asarray(gid, dtype=np.int64)
        self.gstart = np.zeros(len(order), dtype=bool)
        self.gstart[starts] = True
        self.gent = np.asarray([index[e] for e in ents], dtype=np.int64)
        self.attack = np.asarray([e in split.attack for e in names], dtype=bool)
        self.units = np.asarray([split.units.get(e, 1) for e in names], dtype=np.int64)
        self.first = np.asarray([split.first.get(e, math.nan) for e in names], dtype=np.float64)
        self.n_ent = len(names)

    def decided(self, p, k, thr=0.5):
        """(groups decided, their decision times): p > thr in k consecutive windows of a group."""
        if not len(self.order):
            return np.zeros(0, np.int64), np.zeros(0)
        b = np.asarray(p, dtype=np.float64)[self.order] > thr
        csum = np.cumsum(b)
        mark = ~b | self.gstart
        base = np.maximum.accumulate(np.where(mark, np.where(b, csum - 1, csum), -1))
        pos = np.flatnonzero(csum - base >= k)
        g, first = np.unique(self.gid[pos], return_index=True)
        return g, self.t[pos[first]]

    def evaluate(self, p, k, thr=0.5):
        """The fields of train_l7v2.assess for the decisions p > thr in k consecutive windows."""
        g, when = self.decided(p, k, thr)
        ent = self.gent[g]
        att = self.attack[ent]
        ttd = np.full(self.n_ent, np.inf)
        np.minimum.at(ttd, ent[att], when[att] - self.first[ent[att]])
        caught = np.isfinite(ttd)
        flagged = np.bincount(ent[~att], minlength=self.n_ent)
        ben = int(np.minimum(flagged, self.units).sum())
        ttds = np.sort(ttd[caught])
        n_att = len(self.split.attack)
        return {"caught": int(caught.sum()), "attack_entities": n_att,
                "recall": round(int(caught.sum()) / n_att, 4) if n_att else None,
                "benign_units_flagged": ben, "benign_units": sum(self.split.units.values()),
                "benign_entities_flagged": int((flagged > 0).sum()),
                "median_ttd_s": round(float(ttds[len(ttds) // 2]), 3) if len(ttds) else None}


# ───────────────────────────── grids, tuning, R* ─────────────────────────────

def benign_maxima(stats, windows):
    """{column: the maximum of the statistic over the benign windows with statistics} (the tau grid's unit)."""
    ben = np.asarray([not w["y"] for w in windows], dtype=bool)
    rows = stats[ben]
    rows = rows[~np.isnan(rows).all(axis=1)] if len(rows) else rows
    if not len(rows):
        return {}
    return {c: float(np.nanmax(rows[:, j])) for j, c in enumerate(columns())}


def grid(arm, maxima, spec=None):
    """The arm's grid in its grid order: [(params, columns, thresholds)]; a rule fires when any column passes its
    threshold (strictly)."""
    spec = spec or load_spec()
    a, tau = spec["arms"][arm], spec["tau_grid"]
    out = []
    if not a["tuned"]:
        return [({"rule": "fixed"}, [f"{'own' if a['column'] == 'nginx_reject' else 'ip'}:{a['column']}"], [0.5])]
    if arm == "population":
        cs = [f"ip:{s}" for s in a["statistics"]]
        if not all(c in maxima for c in cs):
            return []
        for t1 in tau:
            for t2 in tau:
                out.append(({"tau_new_keys": t1, "tau_cookieless": t2}, cs, [t1 * maxima[cs[0]], t2 * maxima[cs[1]]]))
        return out
    for key in spec["key_grid"]:
        if arm == "sustained_rate":
            for w in a["windows_s"]:
                for thr in a["thresholds_rps"]:
                    out.append(({"key": key, "window_s": w, "threshold_rps": thr}, [f"{key}:rate_{w}"], [float(thr)]))
        elif arm == "token_bucket":
            for r in a["rates"]:
                for b in a["bursts"]:
                    out.append(({"key": key, "rate": r, "burst": b}, [f"{key}:bucket_{r}"], [float(b)]))
        elif arm == "cost_budget":
            for w in a["windows_s"]:
                c = f"{key}:cost_{w}"
                if c in maxima:
                    out += [({"key": key, "window_s": w, "tau": t}, [c], [t * maxima[c]]) for t in tau]
        elif arm == "multiscale_rate":
            cs = [f"{key}:rate_{w}" for w in a["windows_s"]]
            if all(c in maxima for c in cs):
                for taus in _product(tau, len(cs)):
                    out.append(({"key": key, **{f"tau_{w}": t for w, t in zip(a["windows_s"], taus, strict=True)}},
                                cs, [t * maxima[c] for t, c in zip(taus, cs, strict=True)]))
    return out


def _product(values, n):
    if n == 0:
        return [()]
    return [(v, *rest) for v in values for rest in _product(values, n - 1)]


def fires(stats, cols, thresholds):
    """p in {0, 1} per row: any of the columns strictly above its threshold (NaN never fires)."""
    idx = [columns().index(c) for c in cols]
    with np.errstate(invalid="ignore"):
        return (stats[:, idx] > np.asarray(thresholds, dtype=np.float64)).any(axis=1).astype(np.float64)


def tune(arm, stats, runs, maxima, sel=None, spec=None):
    """The arm's operating point on validation (design 10): the grid point and k with the highest attack-entity
    recall within the budget; ties: fewer benign units, the lower median time to decision, grid order (k first)."""
    sel = sel or MPRE.selection()
    spec = spec or load_spec()
    total = sum(runs.split.units.values())
    points = grid(arm, maxima, spec)
    out = {"grid_size": len(points) * len(sel["k_grid"]), "within_budget": 0, "operating_point": None}
    if not runs.split.attack or not total or not points:
        return out
    allowed = math.floor(sel["budget"] * total + 1e-9)
    best = None
    for pi, (params, cols, thr) in enumerate(points):
        p = fires(stats, cols, thr)
        for ki, k in enumerate(sel["k_grid"]):
            a = runs.evaluate(p, k)
            if a["benign_units_flagged"] > allowed:
                continue
            out["within_budget"] += 1
            gi = ki * len(points) + pi
            med = a["median_ttd_s"] if a["median_ttd_s"] is not None else math.inf
            rank = (-a["caught"], a["benign_units_flagged"], med, gi)
            if best is None or rank < best[0]:
                best = (rank, {"params": params, "columns": cols, "thresholds": [float(x) for x in thr],
                               "threshold": spec["theta"], "consecutive": int(k), "grid_index": gi,
                               "allowed": allowed, "budget": sel["budget"], **a})
    out["operating_point"] = best[1] if best else None
    return out


def fixed(arm, stats, runs, sel=None, spec=None):
    """A fixed replay at its own rule (k = 1), with its validation benign units against the budget; never selected."""
    sel = sel or MPRE.selection()
    (params, cols, thr), = grid(arm, {}, spec)
    a = runs.evaluate(fires(stats, cols, thr), 1)
    allowed = math.floor(sel["budget"] * sum(runs.split.units.values()) + 1e-9)
    return {"params": params, "columns": cols, "thresholds": thr, "threshold": 0.5, "consecutive": 1,
            "allowed": allowed, "within_budget": a["benign_units_flagged"] <= allowed, **a}


def best_rule(results, candidates=None):
    """R* (ml/l7v2_verdict_prereg.json best_rule): the candidate with the most attack entities caught at its operating
    point; ties: fewer benign units, the lower median time to decision, candidate order. None when no candidate has a
    point within the budget."""
    candidates = candidates or VPRE.load()["best_rule"]["candidates"]
    best = None
    for ci, name in enumerate(candidates):
        op = (results.get(name) or {}).get("operating_point")
        if op is None:
            continue
        med = op["median_ttd_s"] if op["median_ttd_s"] is not None else math.inf
        rank = (-op["caught"], op["benign_units_flagged"], med, ci)
        if best is None or rank < best[0]:
            best = (rank, name)
    return best[1] if best else None


# ───────────────────────────── packages ─────────────────────────────

def make_package(arm, op, costs, calibration, maxima):
    """The rule package of an arm at its operating point: its columns and thresholds, theta 0.5 and k, the class costs
    and the calibration record they come from, the benign maxima its thresholds scale; sha256 over the rest."""
    cfg = {"format": PACKAGE_FORMAT, "arm": arm, "level": "view", "params": op["params"], "columns": op["columns"],
           "thresholds": op["thresholds"], "threshold": op["threshold"], "consecutive": op["consecutive"],
           "costs_ms": {k: float(v) for k, v in sorted(costs.items())},
           "calibration": {"sha256": calibration.get("sha256"), "status": calibration.get("status")},
           "benign_max": {c: maxima.get(c) for c in op["columns"]}, "spec_sha256": spec_sha256()}
    cfg["sha256"] = hashlib.sha256(D.canonical_json(cfg)).hexdigest()
    return cfg


class RuleScorer:
    """A rule package behind the common detector interface: score(batch) -> p in {0, 1}, where a batch row is the
    window's statistics of the package's columns (RuleStats). level, cols, max_views, threshold, consecutive and
    sha256 are the engine's scorer attributes; cols are the token columns the engine encodes (unused by a rule)."""

    level = "view"

    def __init__(self, cfg):
        body = {k: v for k, v in cfg.items() if k != "sha256"}
        if cfg.get("format") != PACKAGE_FORMAT or cfg.get("sha256") != hashlib.sha256(D.canonical_json(body)).hexdigest():
            raise RuleError("not an intact l7v2 rule package")
        unknown = [c for c in cfg["columns"] if c not in columns()]
        if unknown:
            raise RuleError(f"unknown rule columns {unknown}")
        self.cfg, self.arm = cfg, cfg["arm"]
        self.stat_columns = list(cfg["columns"])
        self.index = [columns().index(c) for c in self.stat_columns]
        self.thresholds = np.asarray(cfg["thresholds"], dtype=np.float64)
        self.threshold, self.consecutive = float(cfg["threshold"]), int(cfg["consecutive"])
        self.cols, self.max_views, self.seq_len = list(F.TOKEN_COLUMNS), F.MAX_VIEWS, F.MAX_VIEWS
        self.costs = dict(cfg["costs_ms"])
        self.sha256 = cfg["sha256"]

    def select(self, stats):
        """The package's columns of a full statistics matrix (RuleStats.query, split_stats)."""
        return np.asarray(stats, dtype=np.float64)[:, self.index]

    def score(self, batch):
        b = np.asarray(batch, dtype=np.float64).reshape(-1, len(self.stat_columns))
        with np.errstate(invalid="ignore"):
            return (b > self.thresholds).any(axis=1).astype(np.float64)

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))


def save_package(path, cfg):
    with open(path, "wb") as fh:
        fh.write(D.canonical_json(cfg) + b"\n")


# ───────────────────────────── select ─────────────────────────────

def refuse_non_validation(loaded):
    """Tuning reads validation captures only: a P3 manifest whose seed_role is not 'val' is refused."""
    for m, _recs, cap in loaded:
        role = m.get("seed_role")
        if m.get("format") in D.FORMATS_P3 and role != "val":
            raise RuleError(f"refusing to tune on {cap}: seed_role {role!r}; rule arms are tuned on validation only")


def select(loaded, out_dir, calibration, *, valid_for_claims, source):
    """Tune every rule arm on the validation captures `loaded` [(manifest, records, capture)], write each tuned arm's
    package (rules/<arm>.json) and rules_selection.json with its sha256 (rules_selection.sha256); returns (sel, sha)."""
    refuse_non_validation(loaded)
    for name in ("rules_selection.json", "rules_selection.sha256"):
        if os.path.exists(os.path.join(out_dir, name)):
            raise RuleError(f"refusing to overwrite {os.path.join(out_dir, name)}: select into a new directory")
    costs = calibration["route_costs_ms"]
    split = V.Split(loaded, view=True, request=False)
    stats = split_stats(loaded, split, costs)
    runs = Runs(split.view, split)
    maxima = benign_maxima(stats, split.view)
    os.makedirs(os.path.join(out_dir, "rules"), exist_ok=True)
    res = {}
    for arm in TUNED:
        r = tune(arm, stats, runs, maxima)
        if r["operating_point"] is not None:
            cfg = make_package(arm, r["operating_point"], costs, calibration, maxima)
            rel = f"rules/{arm}.json"
            save_package(os.path.join(out_dir, rel), cfg)
            r["artifact"], r["artifact_sha256"] = rel, V._sha_file(os.path.join(out_dir, rel))
        res[arm] = r
    for arm in FIXED:
        res[arm] = {"fixed": fixed(arm, stats, runs)}
    sel = {"format": SELECTION_FORMAT, "source": source, "valid_for_claims": bool(valid_for_claims),
           "spec_sha256": spec_sha256(), "calibration": {"sha256": calibration.get("sha256"),
                                                         "status": calibration.get("status")},
           "captures": sorted({cap for _m, _r, cap in loaded}),
           "counts": {"val_view_windows": len(split.view), "scored_windows": len(runs.order),
                      "val_attack_entities": len(split.attack), "val_benign_units": sum(split.units.values())},
           "benign_max": maxima, "arms": res, "r_star": best_rule(res)}
    data = D.canonical_json(sel) + b"\n"
    with open(os.path.join(out_dir, "rules_selection.json"), "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()
    with open(os.path.join(out_dir, "rules_selection.sha256"), "w", encoding="utf-8") as fh:
        fh.write(f"{sha}  rules_selection.json\n")
    return sel, sha


def check_split(val_dirs, split_path, manifest_of=None):
    """The validation captures must be exactly split.json's (capture ids and manifest hashes), as train_l7v2 score
    checks them."""
    import l7_disjoint
    manifest_of = manifest_of or (lambda d: l7_disjoint.load_manifest(d)[0])
    with open(split_path, encoding="utf-8") as fh:
        rec = json.load(fh)
    want = sorted((cid, c["manifest_sha256"]) for cid, c in rec.get("captures", {}).items() if c["split"] == "val")
    got = sorted((m["capture_id"], m["manifest_sha256"]) for m in map(manifest_of, val_dirs))
    if got != want:
        raise RuleError(f"refusing to tune: the validation captures {got} are not split.json's {want}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("step", choices=("select",))
    ap.add_argument("--val", nargs="+", required=True, help="the validation captures (P3), nothing else")
    ap.add_argument("--calibration", help="the calibration record whose class costs the cost rule uses "
                                          "(default: the placeholder; claims need a frozen one)")
    ap.add_argument("--split", help="split.json of the frozen learned-arm selection: the captures must be its val")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    import l7_backend
    rec, status, _tag = l7_backend.load_record(args.calibration)
    if args.split:
        check_split(args.val, args.split)
    loaded = [V.load_capture(d) for d in args.val]
    valid = status == "frozen" and bool(args.split)
    _sel, sha = select(loaded, args.out, {"route_costs_ms": rec["route_costs_ms"], "sha256": rec.get("sha256"),
                                          "status": status}, valid_for_claims=valid,
                       source="P3 validation captures" + ("" if valid else " (not valid for claims)"))
    print(f"{sha}  {os.path.join(args.out, 'rules_selection.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
