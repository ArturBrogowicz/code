#!/usr/bin/env python3
"""The L7 v2 rule arms at their own level (docs/L7V2_DESIGN.md 9.5, 10; ml/l7v2_rules_prereg_v2.json, re-registered
under review finding T042-E08) as detector packages on the common score(batch) -> p interface, tuned on validation
captures only at the common budget.

Each rule is keyed (IP, UA), or reaches a key through its address, as section 10 states it: its statistics are computed
at every request over wall-clock windows of the key's (or the address's) whole history, and it decides at its own
decision points, one row per (IP, UA) key and engine poll (whole seconds of the log clock, or the recording's ticks in
the replay): each statistic's maximum over the key's requests in the poll (RuleStats). The rule gives p = 1 when any of
its statistics passes its threshold (RuleScorer.score), theta is 0.5, and the policy is the section-9 one: p > theta in
k consecutive rows of the key. The budget, the objective, the ties and the k grid are the learned arms'
(ml/l7v2_model_prereg.json selection), with one unit per flagged (IP, UA) key of a benign entity, at most its units.
A rule arm never decides on the view windows of (IP, UA, sid) keys: a 32-token window of a C2 key spans seconds and
sid rotation splits an (IP, UA) key, so that would starve it (T042-E08; the format-1 build did).

Arms (ml/l7v2_rules_prereg_v2.json "arms"):
  sustained_rate   requests over {10, 30, 60} s > {2..50} req/s (ml/l7_baselines B2)
  token_bucket     the bucket's excess at rate {5..30} > burst {10..100} (B3)
  cost_budget      the frozen class costs summed over {10, 60, 300} s > tau x benign max
  multiscale_rate  any of the rates over {1, 10, 60, 300} s > its tau x benign max (jointly)
  population       the address's new keys in 60 s, or its cookie-less share in 60 s, > tau x benign max (replay only)
  default_rules, tolerant_rules, nginx_limits: the fixed replays (control_plane.py's heuristic, nginx.conf's limit_req)
  age_only_key     a diagnostic beside them: the (IP, UA) key's age (T042-F01), never R*, never live
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
import l7_ingest as I

SPEC_PATH = os.path.join(HERE, "l7v2_rules_prereg_v2.json")
SPEC_FORMAT = "l7v2-rules-prereg/2"
PACKAGE_FORMAT = "l7v2-rule-package/2"
SELECTION_FORMAT = "l7v2-rule-selection/2"
TUNED = ("sustained_rate", "token_bucket", "cost_budget", "multiscale_rate", "population")
FIXED = ("default_rules", "tolerant_rules", "nginx_limits")
ARMS = TUNED + FIXED
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
    if tuple(spec["arms"]) != ARMS or tuple(a for a in ARMS if spec["arms"][a]["tuned"]) != TUNED:
        raise RuleError(f"the rule arms are {ARMS}, the tuned ones {TUNED}")
    if spec["level"]["key"] != ["ip", "ua_h"]:
        raise RuleError("a per-key rule is keyed (IP, UA) (T042-E08)")
    if spec["tau_grid"] != sorted(spec["tau_grid"]) or spec["theta"] != 0.5:
        raise RuleError("the tau grid is ascending and a rule's theta is 0.5")
    ck, a = spec["columns"]["key"], spec["arms"]
    if not (set(a["sustained_rate"]["windows_s"]) | set(a["multiscale_rate"]["windows_s"])) <= set(ck["rate_s"]) \
            or set(a["cost_budget"]["windows_s"]) != set(ck["cost_s"]) or a["token_bucket"]["rates"] != ck["bucket_rates"]:
        raise RuleError("every arm's windows and rates must be columns")
    if max(ck["rate_s"] + ck["cost_s"]) > spec["statistic"]["lookback_s"]:
        raise RuleError("no statistic looks back further than lookback_s")
    if not set(VPRE.load()["best_rule"]["candidates"]) <= set(TUNED):
        raise RuleError("R*'s candidates are tuned rule arms")
    _cache[path] = spec
    return spec


def spec_sha256(path=SPEC_PATH):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def group_columns(spec=None):
    """{group: [column names]} in row order: the (IP, UA) key's statistics, its address's, and its own rejection."""
    spec = spec or load_spec()
    ck = spec["columns"]["key"]
    key = [f"key:rate_{w}" for w in ck["rate_s"]] + [f"key:cost_{w}" for w in ck["cost_s"]] + \
        [f"key:bucket_{r}" for r in ck["bucket_rates"]] + ["key:age"]
    return {"key": key, "ip": [f"ip:{n}" for n in spec["columns"]["ip"]],
            "own": [f"own:{n}" for n in spec["columns"]["own"]]}


def columns(spec=None):
    """Every statistic column, in row order."""
    return [c for cols in group_columns(spec).values() for c in cols]


def rule_key(rec):
    """A rule's key: (IP, ua_hash), whatever the session."""
    return (rec["ip"], rec["ua_h"])


# ───────────────────────────── statistics ─────────────────────────────

class RuleStats:
    """The rules' statistics at their own level (ml/l7v2_rules_prereg_v2.json "statistic", "decision_points"), causal
    and streaming: observe() takes records in arrival order; poll() processes, in (completion, arrival) order, every
    request observed since the previous poll, each against the whole history of its (IP, UA) key and its address, and
    returns the poll's rows, one per key with a request in it: each statistic's maximum over those requests. The trainer
    polls at whole seconds of the log clock, the replay at the recording's ticks; given the same records in the same
    polls both compute the same rows. A record that completed before an already processed one is counted in `late`."""

    def __init__(self, costs, spec=None):
        self.spec = spec or load_spec()
        self.costs = {k: float(v) for k, v in costs.items()}
        ck = self.spec["columns"]["key"]
        self.rate_s, self.cost_s, self.rates = list(ck["rate_s"]), list(ck["cost_s"]), list(ck["bucket_rates"])
        self.max_w = max(self.rate_s + self.cost_s)
        self.lookback = float(self.spec["statistic"]["lookback_s"])
        self.cols = columns(self.spec)
        self.daemon = self.spec["daemon"]
        arms = self.spec["arms"]
        self.max_rps = {"default": arms["default_rules"]["max_rps"], "tolerant": arms["tolerant_rules"]["max_rps"]}
        self.nginx = (float(arms["nginx_limits"]["rate_rps"]), float(arms["nginx_limits"]["burst"]))
        self._heap, self._n, self.frontier, self.late, self.processed = [], 0, -math.inf, 0, 0
        self._key, self._ip, self._acc = {}, {}, {}

    def observe(self, rec):
        """Queue one normalised record (arrival order)."""
        if rec["msec"] < self.frontier:
            self.late += 1
        heapq.heappush(self._heap, (rec["msec"], self._n, rec))
        self._n += 1

    def poll(self):
        """Process the queued requests; [(key, t, row)] of the keys with a request since the previous poll, in key
        order; t is the completion of the key's last request in the poll."""
        while self._heap:
            msec, _n, rec = heapq.heappop(self._heap)
            self.frontier = max(self.frontier, msec)
            self._process(msec, rec)
        out = [(k, a[1], a[0]) for k, a in sorted(self._acc.items())]
        self._acc = {}
        return out

    def _process(self, T, rec):
        key = rule_key(rec)
        vk = self._per_key(key, T, self.costs.get(rec.get("rc"), 0.0))
        vi, rejected = self._per_ip(rec["ip"], I.key_v2(rec), T, rec)
        vec = np.asarray(vk + vi + (rejected,), dtype=np.float64)
        acc = self._acc.get(key)
        if acc is None:
            self._acc[key] = [vec, rec["msec"]]
        else:
            np.maximum(acc[0], vec, out=acc[0])
            acc[1] = max(acc[1], rec["msec"])
        self.processed += 1

    def _per_key(self, key, T, cost):
        st = self._key.get(key)
        if st is None:
            st = self._key[key] = {"ts": [], "cum": [], "off": 0, "base": 0.0, "e": None, "last": None, "t0": T}
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
        return tuple(vec + e + [T - st["t0"]])

    def _per_ip(self, ip, v2, T, rec):
        st = self._ip.get(ip)
        if st is None:
            st = self._ip[ip] = {"last": None, "t0": T, "ng": [0.0, None], "pop": collections.deque(), "n_new": 0,
                                 "n_cl": 0, "seen": {},
                                 "d": {p: {"q": collections.deque(), "err": 0, "until": -math.inf}
                                       for p in ("default", "tolerant")}}
        if st["last"] is not None:
            T = max(T, st["last"])
        st["last"] = T
        d = self.daemon
        status = rec.get("status") or 0
        is_err = status >= 400 and status != 503
        vec = []
        for prof in ("default", "tolerant"):                # control_plane.py's L7 heuristic, per address
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
        vec += [float(st["n_new"]), st["n_cl"] / len(pop), T - st["t0"]]
        rate, burst = self.nginx                           # nginx limit_req, nodelay: a rejection changes no state
        e, last = st["ng"]
        excess = 0.0 if last is None else max(0.0, e - rate * (T - last) + 1.0)
        if excess > burst:
            rejected = 1.0
        else:
            st["ng"], rejected = [excess, T], 0.0
        return tuple(vec), rejected


def rule_rows(loaded, costs, poll_s=None, spec=None):
    """The rule-level decision points of the captures `loaded` [(manifest, records, capture)]: (rows, matrix). Each
    capture's records, in (completion, arrival) order, are polled at whole multiples of poll_s of the log clock (a
    request completing at t joins the first poll after t, as train_l7v2.engine_scored). A row is a dict with the
    capture, the (IP, UA) key, its time, its entity (the key's first request's) as "ip", its class "y", the poll and
    the key's distinct session ids so far; the matrix holds its statistics (columns())."""
    poll_s = MPRE.load()["selection"]["policy_engine_poll_s"] if poll_s is None else poll_s
    rows, mat = [], []
    for _m, recs, cap in loaded:
        rs, first, sids, boundary = RuleStats(costs, spec), {}, {}, None

        def emit(b, _cap=cap, _rs=rs, _first=first, _sids=sids):
            for key, t, row in _rs.poll():
                r0 = _first[key]
                rows.append({"capture": _cap, "key": key, "t": t, "ip": r0["_ent"],
                             "y": int(r0["_cls"] == D.ATTACK), "level": "rule", "poll": b,
                             "n_sids": len(_sids[key])})
                mat.append(row)

        for r in sorted(recs, key=lambda r: (r["msec"], r["_seq"])):
            b = (math.floor(r["msec"] / poll_s) + 1) * poll_s
            if boundary is not None and b != boundary:
                emit(boundary)
            boundary = b
            rs.observe(r)
            first.setdefault(rule_key(r), r)
            sids.setdefault(rule_key(r), set()).add(r.get("sid_h", I.NO_SID))
        if boundary is not None:
            emit(boundary)
    width = len(columns(spec))
    return rows, (np.asarray(mat, dtype=np.float64) if mat else np.zeros((0, width)))


# ───────────────────────────── the common policy, vectorised ─────────────────────────────

class Runs:
    """train_l7v2's policy and assessment (key_runs, decisions, assess) over a fixed list of decision points (view
    windows, of which those the live engine would score, or rule rows, all of them), vectorised so that a rule's whole
    grid can be scored: the same time order per (capture, key), the same k-consecutive rule, the same entity outcome
    (one unit per flagged key, at most the entity's units). A test checks it equals train_l7v2's."""

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
        self.split, self.names, self.gkey = split, names, list(groups)
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
        """(groups decided, their decision times): p > thr in k consecutive points of a group."""
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
        """The fields of train_l7v2.assess for the decisions p > thr in k consecutive points."""
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

    def users_behind(self, p, k, n_sids, thr=0.5):
        """The users behind the flagged benign keys (their distinct session ids, at most the entity's units): reported
        beside the per-key units, never used for selection (ml/l7v2_rules_prereg_v2.json unit_rule)."""
        g, _when = self.decided(p, k, thr)
        per = np.zeros(self.n_ent, dtype=np.int64)
        for x in g:
            e = self.gent[x]
            if not self.attack[e]:
                per[e] += n_sids.get(self.gkey[x], 1)
        return int(np.minimum(per, self.units).sum())


def key_sids(rows):
    """{(capture, key): its distinct session ids} from rule rows (the last row's count)."""
    out = {}
    for r in rows:
        out[(r["capture"], r["key"])] = max(out.get((r["capture"], r["key"]), 0), r["n_sids"])
    return out


# ───────────────────────────── grids, tuning, R* ─────────────────────────────

def benign_maxima(stats, rows):
    """{column: the maximum of the statistic over the benign rows} (the tau grid's unit)."""
    ben = np.asarray([not r["y"] for r in rows], dtype=bool)
    if not ben.any():
        return {}
    return {c: float(stats[ben, j].max()) for j, c in enumerate(columns())}


def grid(arm, maxima, spec=None):
    """The arm's grid in its grid order: [(params, columns, thresholds)]; a rule fires when any column passes its
    threshold (strictly)."""
    spec = spec or load_spec()
    a, tau = spec["arms"][arm], spec["tau_grid"]
    if not a["tuned"]:
        return [({"rule": "fixed"}, [a["column"]], [0.5])]
    out = []
    if arm == "sustained_rate":
        for w in a["windows_s"]:
            out += [({"window_s": w, "threshold_rps": t}, [f"key:rate_{w}"], [float(t)]) for t in a["thresholds_rps"]]
    elif arm == "token_bucket":
        for r in a["rates"]:
            out += [({"rate": r, "burst": b}, [f"key:bucket_{r}"], [float(b)]) for b in a["bursts"]]
    elif arm == "cost_budget":
        for w in a["windows_s"]:
            c = f"key:cost_{w}"
            if c in maxima:
                out += [({"window_s": w, "tau": t}, [c], [t * maxima[c]]) for t in tau]
    elif arm in ("multiscale_rate", "population"):
        cs = [f"key:rate_{w}" for w in a["windows_s"]] if arm == "multiscale_rate" else \
            [f"ip:{s}" for s in a["statistics"]]
        names = [f"tau_{w}" for w in a["windows_s"]] if arm == "multiscale_rate" else ["tau_new_keys", "tau_cookieless"]
        if all(c in maxima for c in cs):
            for taus in _product(tau, len(cs)):
                out.append((dict(zip(names, taus, strict=True)), cs,
                            [t * maxima[c] for t, c in zip(taus, cs, strict=True)]))
    return out


def _product(values, n):
    if n == 0:
        return [()]
    return [(v, *rest) for v in values for rest in _product(values, n - 1)]


def fires(stats, cols, thresholds):
    """p in {0, 1} per row: any of the columns strictly above its threshold."""
    idx = [columns().index(c) for c in cols]
    return (stats[:, idx] > np.asarray(thresholds, dtype=np.float64)).any(axis=1).astype(np.float64)


def _search(points, p_of, runs, sel, extra=None):
    """The common selection over (k, point): the highest recall within the budget; ties: fewer benign units, the lower
    median time to decision, grid order (k first)."""
    total = sum(runs.split.units.values())
    out = {"grid_size": len(points) * len(sel["k_grid"]), "within_budget": 0, "operating_point": None}
    if not runs.split.attack or not total or not points:
        return out
    allowed = math.floor(sel["budget"] * total + 1e-9)
    best = None
    for pi, point in enumerate(points):
        p, thr = p_of(point)
        for ki, k in enumerate(sel["k_grid"]):
            a = runs.evaluate(p, k, thr)
            if a["benign_units_flagged"] > allowed:
                continue
            out["within_budget"] += 1
            gi = ki * len(points) + pi
            med = a["median_ttd_s"] if a["median_ttd_s"] is not None else math.inf
            rank = (-a["caught"], a["benign_units_flagged"], med, gi)
            if best is None or rank < best[0]:
                best = (rank, {**extra(point, thr), "consecutive": int(k), "grid_index": gi, "allowed": allowed,
                               "budget": sel["budget"], **a, "_p": p})
    if best:
        op = best[1]
        p = op.pop("_p")
        if hasattr(runs, "n_sids"):
            op["benign_users_behind"] = runs.users_behind(p, op["consecutive"], runs.n_sids, op["threshold"])
        out["operating_point"] = op
    return out


def tune(arm, stats, runs, maxima, sel=None, spec=None):
    """The arm's operating point on validation (design 10) at its own decision points."""
    sel, spec = sel or MPRE.selection(), spec or load_spec()
    return _search(grid(arm, maxima, spec), lambda pt: (fires(stats, pt[1], pt[2]), spec["theta"]), runs, sel,
                   lambda pt, thr: {"params": pt[0], "columns": pt[1], "thresholds": [float(x) for x in pt[2]],
                                    "threshold": thr})


def age_scores(stats, rows, ref=None):
    """p of the (IP, UA) age-only arm: the share of the benign reference ages greater than the row's (ties one half);
    the reference is the benign rows' key ages."""
    ages = stats[:, columns().index("key:age")]
    if ref is None:
        ref = ages[np.asarray([not r["y"] for r in rows], dtype=bool)]
    ref = np.sort(np.asarray(ref, dtype=np.float64))
    if not len(ref):
        return np.full(len(ages), 0.5)
    lo, hi = np.searchsorted(ref, ages, "left"), np.searchsorted(ref, ages, "right")
    return (len(ref) - hi + 0.5 * (hi - lo)) / len(ref)


def tune_age(stats, rows, runs, sel=None, spec=None):
    """The (IP, UA) age-only arm (ml/l7v2_rules_prereg_v2.json age_only) on validation: its operating point on the
    theta and k grids at the budget, its validation AUC (attack rows against benign rows) and reading; the address
    age's AUC beside it (descriptive, T042-F01)."""
    sel, spec = sel or MPRE.selection(), spec or load_spec()
    p = age_scores(stats, rows)
    y = [r["y"] for r in rows]
    res = _search(list(sel["theta_grid"]), lambda thr: (p, thr), runs, sel, lambda _pt, thr: {"threshold": thr})
    auc = V.window_auc(p, y)
    ip_auc = V.window_auc(-stats[:, columns().index("ip:age")], y) if len(rows) else None
    band = spec["age_only"]["auc_band"]
    res.update({"val_auc": None if auc is None else round(auc, 4),
                "reading": None if auc is None else ("near chance" if abs(auc - 0.5) <= band + 1e-12
                                                     else "age-confounded"),
                "address_age_val_auc": None if ip_auc is None else round(ip_auc, 4)})
    return res


def fixed(arm, stats, runs, sel=None, spec=None):
    """A fixed replay at its own rule (k = 1), with its validation benign units against the budget; never selected."""
    sel = sel or MPRE.selection()
    (params, cols, thr), = grid(arm, {}, spec)
    p = fires(stats, cols, thr)
    a = runs.evaluate(p, 1)
    allowed = math.floor(sel["budget"] * sum(runs.split.units.values()) + 1e-9)
    out = {"params": params, "columns": cols, "thresholds": thr, "threshold": 0.5, "consecutive": 1,
           "allowed": allowed, "within_budget": a["benign_units_flagged"] <= allowed, **a}
    if hasattr(runs, "n_sids"):
        out["benign_users_behind"] = runs.users_behind(p, 1, runs.n_sids)
    return out


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
    """The rule package of an arm at its operating point: its level and decision points, its columns and thresholds,
    theta 0.5 and k, the class costs and the calibration record they come from, the benign maxima its thresholds
    scale; sha256 over the rest."""
    spec = load_spec()
    cfg = {"format": PACKAGE_FORMAT, "arm": arm, "level": "rule", "key": spec["level"]["key"],
           "poll_s": spec["decision_points"]["poll_s"], "params": op["params"], "columns": op["columns"],
           "thresholds": op["thresholds"], "threshold": op["threshold"], "consecutive": op["consecutive"],
           "costs_ms": {k: float(v) for k, v in sorted(costs.items())},
           "calibration": {"sha256": calibration.get("sha256"), "status": calibration.get("status")},
           "benign_max": {c: maxima.get(c) for c in op["columns"]}, "spec_sha256": spec_sha256()}
    cfg["sha256"] = hashlib.sha256(D.canonical_json(cfg)).hexdigest()
    return cfg


class RuleScorer:
    """A rule package behind the common detector interface at the rule's own decision points: score(batch) -> p in
    {0, 1}, where a batch row is an (IP, UA) key's statistics in one poll (RuleStats) restricted to the package's
    columns (select). threshold and consecutive are the section-9 policy's theta and k."""

    level = "rule"

    def __init__(self, cfg):
        body = {k: v for k, v in cfg.items() if k != "sha256"}
        if cfg.get("format") != PACKAGE_FORMAT or cfg.get("sha256") != hashlib.sha256(D.canonical_json(body)).hexdigest():
            raise RuleError("not an intact l7v2 rule package (format 2)")
        unknown = [c for c in cfg["columns"] if c not in columns()]
        if unknown:
            raise RuleError(f"unknown rule columns {unknown}")
        self.cfg, self.arm = cfg, cfg["arm"]
        self.stat_columns = list(cfg["columns"])
        self.index = [columns().index(c) for c in self.stat_columns]
        self.thresholds = np.asarray(cfg["thresholds"], dtype=np.float64)
        self.threshold, self.consecutive = float(cfg["threshold"]), int(cfg["consecutive"])
        self.costs = dict(cfg["costs_ms"])
        self.sha256 = cfg["sha256"]

    def select(self, stats):
        """The package's columns of full statistics rows (RuleStats.poll, rule_rows)."""
        return np.asarray(stats, dtype=np.float64).reshape(-1, len(columns()))[:, self.index]

    def score(self, batch):
        b = np.asarray(batch, dtype=np.float64).reshape(-1, len(self.stat_columns))
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


def validation_rows(loaded, costs):
    """(rows, statistics, Runs with the users-behind counts) of the validation captures at the rule level."""
    split = V.Split(loaded, view=False, request=False)
    rows, stats = rule_rows(loaded, costs)
    runs = Runs(rows, split)
    runs.n_sids = key_sids(rows)
    return rows, stats, runs


def select(loaded, out_dir, calibration, *, valid_for_claims, source):
    """Tune every rule arm on the validation captures `loaded` [(manifest, records, capture)] at its own level, write
    each tuned arm's package (rules/<arm>.json) and rules_selection.json with its sha256 (rules_selection.sha256);
    returns (sel, sha). The (IP, UA) age-only arm is reported beside the rule arms."""
    refuse_non_validation(loaded)
    for name in ("rules_selection.json", "rules_selection.sha256"):
        if os.path.exists(os.path.join(out_dir, name)):
            raise RuleError(f"refusing to overwrite {os.path.join(out_dir, name)}: select into a new directory")
    costs = calibration["route_costs_ms"]
    rows, stats, runs = validation_rows(loaded, costs)
    maxima = benign_maxima(stats, rows)
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
    age = tune_age(stats, rows, runs)
    recall = {a: ((r.get("operating_point") or r.get("fixed") or {}).get("recall")) for a, r in res.items()}
    sel = {"format": SELECTION_FORMAT, "source": source, "valid_for_claims": bool(valid_for_claims),
           "spec_sha256": spec_sha256(), "calibration": {"sha256": calibration.get("sha256"),
                                                         "status": calibration.get("status")},
           "captures": sorted({cap for _m, _r, cap in loaded}),
           "counts": {"rule_rows": len(rows), "rule_keys": len(runs.gkey), "val_attack_entities": len(runs.split.attack),
                      "val_benign_units": sum(runs.split.units.values())},
           "benign_max": maxima, "arms": res, "age_only_key": age,
           "recall_beside_age_only": {**recall, "age_only_key": (age["operating_point"] or {}).get("recall")},
           "r_star": best_rule(res)}
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
