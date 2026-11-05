#!/usr/bin/env python3
"""Invariance-probe harness for L7 models (docs/L7_GRU_DESIGN.md §5.4).

Built in P2; it becomes a hard acceptance gate at P4. It applies edits that should
not change a decision to real windows and compares the model's scores before and
after.

Exact-invariance transforms: the feature pipeline must make them invisible, so
any score change is a pipeline defect.
  ua_swap        another User-Agent (it keys windows but is never a feature)
  uri_bijection  every path renamed consistently (the access pattern is kept)
  time_offset    all timestamps shifted by whole days

Robustness transforms: the model should rarely change its decision.
  pad_request    +50–500 B per request (the size shortcut the XDP model learned)
  iat_jitter     ±10 % on the gaps between request starts

L7 v2 (docs/L7V2_DESIGN.md 8.5; ml/l7v2_model_prereg.json "probes"). A CHANGE TO A HARD
GATE, APPROVED WITH THE DESIGN (D-V5, 2026-10-30): the v2 gate (GATE_PROBES_V2) uses
  uri_bijection_class  every URI identity renamed within its route class (each request
                       keeps rc), the same map renaming the Referers, so the site graph,
                       revisits and referrer consistency are kept
  sid_swap             every session id renamed (the sid keys windows, never a feature)
where P5c used uri_bijection, which renames paths at random and so fails, by construction,
any model that reads a route class or the referrer's consistency (F-V8). The P5c probe and
gate (uri_bijection, GATE_PROBES, TRANSFORMS) are unchanged and stay the defaults, so the
published P5c runs reproduce. A view-level scorer (level "view") is probed on view windows:
each window's records are transformed, re-tokenized and scored.

    ./venv/bin/python ml/l7_probes.py INPUT --model PKG [--stride 5] [--max-windows 2000]

INPUT is a recording or an l7json access log. The tool exits 1 if any probe fails (a view
package: any probe of the v2 gate).
"""
import argparse
import json
import os
import sys

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import l7_engine as E
import l7_features as F
import l7_ingest

EXACT_TOL = 1e-5        # |Δp| allowed for exact transforms (float64→float32 rounding only)
FLIP_TOL = 0.05         # decision-flip rate allowed for robustness transforms


def ua_swap(recs, rng):
    new = int(rng.integers(0, 2 ** 32))
    return [{**r, "ua_h": new} for r in recs]


def uri_bijection(recs, rng):
    mapping = {}
    used = set()
    for r in recs:
        if r["uri_h"] not in mapping:
            while True:
                v = int(rng.integers(0, 2 ** 32))
                if v not in used:
                    break
            used.add(v)
            mapping[r["uri_h"]] = v
    return [{**r, "uri_h": mapping[r["uri_h"]]} for r in recs]


def time_offset(recs, rng):
    off = float(rng.integers(1, 30)) * 86400.0
    return [{**r, "msec": r["msec"] + off} for r in recs]


def pad_request(recs, rng):
    return [{**r, "rlen": r["rlen"] + float(rng.integers(50, 501))} for r in recs]


def iat_jitter(recs, rng):
    recs = sorted(recs, key=F.start_time)
    out, prev_old, prev_new = [], None, None
    for r in recs:
        s = F.start_time(r)
        new_s = s if prev_old is None else prev_new + (s - prev_old) * rng.uniform(0.9, 1.1)
        prev_old, prev_new = s, new_s
        out.append({**r, "msec": new_s + r["rt"]})
    return out


LOAD_FACTOR = 10.0      # server_load: the p90 $request_time shift measured at P5c.1 (R17)


def server_load(recs, rng):
    """A LOAD_FACTOR-times slower server: rt and urt scaled, the client's request start
    times held fixed (so the client-side inter-arrival times do not change)."""
    out = []
    for r in recs:
        rt = r["rt"] * LOAD_FACTOR
        out.append({**r, "rt": rt, "urt": r["urt"] * LOAD_FACTOR, "msec": F.start_time(r) + rt})
    return out


def _fresh(rng, used):
    while True:
        v = int(rng.integers(0, 2 ** 32))
        if v not in used:
            used.add(v)
            return v


def uri_bijection_class(recs, rng):
    """L7 v2: a random bijection of the window's URI identities (request URIs and the pages the Referers name, one
    hash space) onto new ones. Every request keeps its route class (rc), so the rename stays within the class, and
    the Referers are renamed with the same map, so the site graph, revisits and referrer consistency are kept."""
    mapping, used = {}, set()
    for r in recs:
        for h in (r["uri_h"], r.get("ref_h")):
            if h is not None and h not in mapping:
                mapping[h] = _fresh(rng, used)
    return [{**r, "uri_h": mapping[r["uri_h"]],
             "ref_h": None if r.get("ref_h") is None else mapping[r["ref_h"]]} for r in recs]


def sid_swap(recs, rng):
    """L7 v2: a random bijection of the window's session ids onto new ones; a request without a session keeps
    l7_ingest.NO_SID."""
    mapping, used = {}, set()
    out = []
    for r in recs:
        sid = r.get("sid_h", l7_ingest.NO_SID)
        if sid != l7_ingest.NO_SID and sid not in mapping:
            mapping[sid] = _fresh(rng, used)
        out.append({**r, "sid_h": mapping.get(sid, sid)})
    return out


TRANSFORMS = {"ua_swap": (ua_swap, True), "uri_bijection": (uri_bijection, True),
              "time_offset": (time_offset, True), "pad_request": (pad_request, False),
              "iat_jitter": (iat_jitter, False), "server_load": (server_load, True)}
# server_load is EXACT (§7.3.2.1, amended): a decision must not move at all when only the
# server's timing changes. A flip-rate tolerance passed the load-dependent P4 candidate on
# its lightly loaded training windows (0.9 % flips) while it flipped 27 % under P5c.1 load.
GATE_PROBES = ("ua_swap", "uri_bijection", "time_offset", "server_load")   # the hard gate (P5c)
# L7 v2: the P5c transforms (uri_bijection reported, not gated) plus the two new exact ones, appended
# last so the earlier transforms draw the same random numbers as in P5c.
TRANSFORMS_V2 = {**TRANSFORMS, "uri_bijection_class": (uri_bijection_class, True),
                 "sid_swap": (sid_swap, True)}
GATE_PROBES_V2 = ("ua_swap", "uri_bijection_class", "sid_swap", "time_offset", "server_load")


def windows_from_items(items, seq_len, min_events=E.DEFAULT_MIN_EVENTS, stride=5):
    """Sliding windows per (IP, ua_hash) key, in arrival order: one window every
    `stride` requests once a key holds >= min_events, each the last seq_len."""
    per_key = {}
    windows = []
    for it in items:
        if it[0] != "record":
            continue
        rec = l7_ingest.normalise(it[1])
        if rec is None:
            continue
        seq = per_key.setdefault(l7_ingest.key_of(rec), [])
        seq.append(rec)
        if len(seq) >= min_events and (len(seq) - min_events) % stride == 0:
            windows.append(seq[-seq_len:])
    return windows


def view_windows_from_items(items, max_views=F.MAX_VIEWS, min_views=F.MIN_VIEWS):
    """L7 v2 view windows per (IP, ua_hash, sid_hash) key, in arrival order: at each request that completes a token
    (once the key has >= min_views complete tokens), the key's records so far. Each window is what a view-level
    scorer encodes with l7_features.token_matrix; transforms act on its records."""
    per_key, opened, windows = {}, {}, []
    for it in items:
        if it[0] != "record":
            continue
        rec = l7_ingest.normalise(it[1])
        if rec is None:
            continue
        key = l7_ingest.key_v2(rec)
        seq = per_key.setdefault(key, [])
        seq.append(rec)
        tokens, page_seen = opened.get(key, (0, False))
        if rec.get("rc") in F.PAGE_CLASSES or not page_seen:       # this request opens a token (arrival order)
            opened[key] = (tokens + 1, page_seen or rec.get("rc") in F.PAGE_CLASSES)
            if tokens >= min_views:                                 # `tokens` complete ones now
                windows.append(list(seq))
    return windows


def _score(scorer, windows):
    if getattr(scorer, "level", "request") == "view":
        return scorer.score(np.stack([F.token_matrix(w, scorer.max_views, scorer.cols) for w in windows]))
    return scorer.score(np.stack([F.window_matrix(w, scorer.seq_len, scorer.cols)
                                  for w in windows]))


def run_probes(scorer, windows, transforms=None, seed=0, flip_tol=FLIP_TOL):
    """Score `windows` before and after each transform; return a report dict."""
    transforms = transforms or TRANSFORMS
    if not windows:
        return {"n_windows": 0, "all_pass": False, "error": "no windows"}
    rng = np.random.default_rng(seed)
    base = _score(scorer, windows)
    base_dec = base > scorer.threshold
    report = {"n_windows": len(windows), "base_over_threshold": float(base_dec.mean())}
    for name, (fn, exact) in transforms.items():
        p = _score(scorer, [fn(w, rng) for w in windows])
        dp = np.abs(p - base)
        flips = float(np.mean((p > scorer.threshold) != base_dec))
        ok = bool(dp.max() <= EXACT_TOL) if exact else flips <= flip_tol
        report[name] = {"exact": exact, "mean_abs_dp": float(dp.mean()),
                        "max_abs_dp": float(dp.max()), "flip_rate": flips, "pass": ok}
    report["all_pass"] = all(v["pass"] for k, v in report.items() if k in transforms)
    return report


def gate_pass(report, gate=GATE_PROBES):
    """The hard probe gate: the exact probes and server_load all present and passing. `gate` is the P5c gate by
    default; L7 v2 passes GATE_PROBES_V2."""
    return all(isinstance(report.get(n), dict) and report[n]["pass"] for n in gate)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("input")
    ap.add_argument("--model", required=True, help="model package dir")
    ap.add_argument("--stride", type=int, default=5)
    ap.add_argument("--max-windows", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    import torch
    torch.set_num_threads(1)
    from l7_scorer import L7Scorer
    scorer = L7Scorer.load(args.model)
    view = getattr(scorer, "level", "request") == "view"
    with open(args.input, encoding="utf-8", errors="replace") as fh:
        if view:
            windows = view_windows_from_items(E.read_stream(fh), scorer.max_views)
        else:
            windows = windows_from_items(E.read_stream(fh), scorer.seq_len, stride=args.stride)
    if len(windows) > args.max_windows:
        idx = np.random.default_rng(args.seed).choice(len(windows), args.max_windows, replace=False)
        windows = [windows[i] for i in sorted(idx)]
    if view:
        report = run_probes(scorer, windows, transforms=TRANSFORMS_V2, seed=args.seed)
        report["gate"], report["gate_pass"] = list(GATE_PROBES_V2), gate_pass(report, GATE_PROBES_V2)
        print(json.dumps(report, indent=1))
        sys.exit(0 if report["gate_pass"] else 1)
    report = run_probes(scorer, windows, seed=args.seed)
    print(json.dumps(report, indent=1))
    sys.exit(0 if report.get("all_pass") else 1)


if __name__ == "__main__":
    main()
