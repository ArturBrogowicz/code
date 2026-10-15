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

    ./venv/bin/python ml/l7_probes.py INPUT --model PKG [--stride 5] [--max-windows 2000]

INPUT is a recording or an l7json access log. The tool exits 1 if any probe fails.
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


TRANSFORMS = {"ua_swap": (ua_swap, True), "uri_bijection": (uri_bijection, True),
              "time_offset": (time_offset, True), "pad_request": (pad_request, False),
              "iat_jitter": (iat_jitter, False)}


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


def _score(scorer, windows):
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
    with open(args.input, encoding="utf-8", errors="replace") as fh:
        windows = windows_from_items(E.read_stream(fh), scorer.seq_len, stride=args.stride)
    if len(windows) > args.max_windows:
        idx = np.random.default_rng(args.seed).choice(len(windows), args.max_windows, replace=False)
        windows = [windows[i] for i in sorted(idx)]
    report = run_probes(scorer, windows, seed=args.seed)
    print(json.dumps(report, indent=1))
    sys.exit(0 if report.get("all_pass") else 1)


if __name__ == "__main__":
    main()
