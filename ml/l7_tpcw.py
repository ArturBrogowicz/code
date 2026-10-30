"""The TPC-W v1.8 customer-behaviour chains: the benign navigation model of L7 v2 (docs/L7V2_DESIGN.md §12.1, D-V6).

Pure and standard library only. The data are the specification's PRINTED Threshold tables (ml/tpcw_v18.json,
transcribed from TPC-W v1.8 clause 5.2.2.4 by the T-018 retrieval). This module derives the probabilities with the
specification's own rule (5.2.2.3), draws the next web interaction exactly as an Emulated Browser does, and maps the
interactions onto the testbed's URL space with the frozen mapping of ml/l7v2_prereg.json (the T-018 review's rules):

  Home -> GET /                      Product Detail -> GET /page/<n>    Search Results -> GET /search?q=<term> (in-page)
  Search Request -> GET /page/search (the page that carries the search form; never /search)
  New Products -> GET /page/new, Best Sellers -> GET /page/best (list pages)
  Order Inquiry -> GET /page/account (a form page), Order Display -> GET /export?r=<n> (in-page)
  Shopping Cart, Customer Registration, Buy Request, Buy Confirm, Admin Request, Admin Confirm -> no route

A state without a route emits nothing: the walk is the chain WATCHED on the mapped states. An excursion through
unmapped states costs random draws but no time and no request. Its law is the censored chain
P_A = P_AA + P_AB (I - P_BB)^-1 P_BA, whose stationary distribution is the original one restricted to A and
renormalised (watched_matrix() and the tests check both). The chain says nothing about which product, about assets,
revisits or Referer (T-018 F14): those come from the planner that uses it.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
TPCW_PATH = os.path.join(HERE, "tpcw_v18.json")
FORMAT = "tpcw-thresholds/1"
RANGE = 9999                     # 5.2.2.3: r uniform on 1..9999
MAX_SILENT_STEPS = 10_000        # an excursion through unmapped states longer than this is a broken table

_cache = {}


class ChainError(ValueError):
    """The threshold table is malformed, or a walk cannot continue."""


def load(path=TPCW_PATH):
    """The threshold table, checked: every row ends at 9999, thresholds rise, every target is a state."""
    if path in _cache:
        return _cache[path]
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("format") != FORMAT:
        raise ChainError(f"{path}: format {doc.get('format')!r}, expected {FORMAT!r}")
    states = set(doc["states"])
    for mix, body in doc["mixes"].items():
        if set(body["thresholds"]) != states:
            raise ChainError(f"{mix}: rows {sorted(set(body['thresholds']) ^ states)} differ from the states")
        for frm, row in body["thresholds"].items():
            ts = [t for _, t in row]
            if ts != sorted(ts) or len(set(ts)) != len(ts) or ts[-1] != RANGE or ts[0] < 1:
                raise ChainError(f"{mix} {frm}: thresholds {ts} do not rise to {RANGE}")
            if not {to for to, _ in row} <= states:
                raise ChainError(f"{mix} {frm}: unknown target")
    _cache[path] = doc
    return doc


def states():
    return list(load()["states"])


def mixes():
    return sorted(load()["mixes"])


def probabilities(mix):
    """{from: {to: p}} with p = (T_k - T_(k-1)) / 9999, the specification's rule."""
    out = {}
    for frm, row in load()["mixes"][mix]["thresholds"].items():
        prev, probs = 0, {}
        for to, t in row:
            probs[to] = probs.get(to, 0.0) + (t - prev) / RANGE
            prev = t
        out[frm] = probs
    return out


def printed_mix(mix):
    """The printed share of each interaction in a mix (clause 5.2.1), as fractions."""
    return {k: float(v.rstrip("%")) / 100 for k, v in load()["mixes"][mix]["printed_mix"].items()}


def next_state(mix, state, rng):
    """5.2.2.3: draw r uniform on 1..9999 and take the option whose Threshold is equal to or most immediately
    greater than r."""
    r = rng.randint(1, RANGE)
    for to, t in load()["mixes"][mix]["thresholds"][state]:
        if t >= r:
            return to
    raise ChainError(f"{mix} {state}: no threshold reaches {r}")


def walk(mix, rng, kept, start=None):
    """The emitted interactions of one session, endless: the chain from `start` (the session start, Home, 2.2.20)
    watched on the states in `kept`."""
    state = start or load()["session_start"]
    silent = 0
    while True:
        if state in kept:
            silent = 0
            yield state
        else:
            silent += 1
            if silent > MAX_SILENT_STEPS:
                raise ChainError(f"{mix}: no kept state reached in {MAX_SILENT_STEPS} steps")
        state = next_state(mix, state, rng)


# ── linear algebra on 14 states, pure Python (tests and reports only) ──

def stationary(matrix, names, iters=20_000, tol=1e-13):
    """The stationary distribution of a row-stochastic {from: {to: p}} by power iteration."""
    pi = {s: 1.0 / len(names) for s in names}
    for _ in range(iters):
        nxt = dict.fromkeys(names, 0.0)
        for frm, row in matrix.items():
            for to, p in row.items():
                nxt[to] += pi[frm] * p
        if max(abs(nxt[s] - pi[s]) for s in names) < tol:
            return nxt
        pi = nxt
    return pi


def _solve(a, b):
    """x with a x = b (Gauss-Jordan with partial pivoting); a is n x n, b is n x m."""
    n = len(a)
    m = [list(a[i]) + list(b[i]) for i in range(n)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[piv][col]) < 1e-15:
            raise ChainError("singular system")
        m[col], m[piv] = m[piv], m[col]
        d = m[col][col]
        m[col] = [v / d for v in m[col]]
        for r in range(n):
            if r != col and m[r][col]:
                f = m[r][col]
                m[r] = [x - f * y for x, y in zip(m[r], m[col], strict=True)]
    return [row[n:] for row in m]


def watched_matrix(mix, kept):
    """The censored chain on `kept`: P_A = P_AA + P_AB (I - P_BB)^-1 P_BA, as {from: {to: p}}."""
    p = probabilities(mix)
    a = [s for s in states() if s in kept]
    b = [s for s in states() if s not in kept]

    def block(rows, cols):
        return [[p[r].get(c, 0.0) for c in cols] for r in rows]
    out = {s: dict(zip(a, row, strict=True)) for s, row in zip(a, block(a, a), strict=True)}
    if b:
        i_minus = [[(1.0 if i == j else 0.0) - v for j, v in enumerate(row)] for i, row in enumerate(block(b, b))]
        n_ba = _solve(i_minus, block(b, a))                 # (I - P_BB)^-1 P_BA
        p_ab = block(a, b)
        for i, s in enumerate(a):
            for j, t in enumerate(a):
                out[s][t] += sum(p_ab[i][k] * n_ba[k][j] for k in range(len(b)))
    return out
