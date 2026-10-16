#!/usr/bin/env python3
"""Non-learned and tabular baselines for P5b (docs/L7_GRU_DESIGN.md §7.2), computed offline
from one evaluation run's recorded L7 engine input (l7_record.jsonl — exactly what the
daemon's shadow engine saw).

Each baseline is a FAMILY with a parameter grid; for every grid point it lists the IPs it
would flag (an (IP, UA)-keyed variant flags the key's IP, since enforcement is per IP). The
verdict (ml/p5b_report.py) tunes each family on the evaluation runs (the oracle, which
favours the baselines) and compares it with the GRU IP by IP.

  B0  per-IP peak rps in 1 s (P5's H1b)
  B1  per-(IP, UA) peak rps in 1 s — the GRU's own keying, without learning
  B2  sustained rate: the largest mean rps over a sliding 10 / 30 / 60 s window,
      per IP and per (IP, UA)
  B3  a token bucket (rate r, burst b) used as a ban trigger, per IP and per (IP, UA):
      the nginx limit_req mechanism, tuned
  B4  the HGB tabular baseline the trainer saved with the model (baseline_hgb.*), replayed
      through the engine's own windows and gating; flags at threshold x consecutive

Times are request completion times (`msec`), as in P5's sweep. Also reported: benign IPs
nginx shaped (limit_req REJECTED/DELAYED) — the §7.2 V1 admissibility check.

    ./venv/bin/python ml/l7_baselines.py RUN_DIR [--hgb PKG_DIR]   # writes RUN_DIR/baselines.json
"""
import argparse
import collections
import gzip
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_engine as E
import l7_features as F
import l7_ingest

PEAK_THRESHOLDS = (5, 10, 15, 20, 25, 30, 35, 40, 45, 50)
SUSTAIN_WINDOWS = (10, 30, 60)
SUSTAIN_THRESHOLDS = (2, 5, 10, 15, 20, 25, 30, 40, 50)
BUCKET_RATES = (5, 10, 15, 20, 25, 30)
BUCKET_BURSTS = (10, 25, 50, 100)
HGB_THRESHOLDS = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99)
SHAPED = frozenset({"REJECTED", "DELAYED"})
FAMILIES = ("B0", "B1", "B2", "B3", "B4")


def _open(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(
        path, encoding="utf-8", errors="replace")


def record_path(run_dir):
    for name in ("l7_record.jsonl", "l7_record.jsonl.gz"):
        p = os.path.join(run_dir, name)
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(f"no l7_record.jsonl[.gz] in {run_dir}")


def load_requests(path):
    """[(ip, ua_h, t, lreq)] from a recording, in file order."""
    out = []
    with _open(path) as fh:
        for item in E.read_stream(fh):
            if item[0] != "record":
                continue
            rec = l7_ingest.normalise(item[1])
            if rec:
                out.append((rec["ip"], rec["ua_h"], rec["msec"], rec.get("lreq") or ""))
    return out


def _by_key(reqs, keyed):
    groups = collections.defaultdict(list)
    for ip, ua, t, _ in reqs:
        groups[(ip, ua) if keyed else (ip, None)].append(t)
    for ts in groups.values():
        ts.sort()
    return groups


def _max_in_window(ts, w):
    best = j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > w:
            j += 1
        best = max(best, i - j + 1)
    return best


def _bucket_rejects(ts, rate, burst):
    """nginx limit_req (nodelay) on these arrivals: does any request get rejected?"""
    excess, last = 0.0, None
    for t in ts:
        e = 0.0 if last is None else max(0.0, excess - rate * (t - last) + 1.0)
        if e > burst:
            return True
        excess, last = e, t
    return False


def _flag(groups, pred):
    return sorted({k[0] for k, ts in groups.items() if pred(ts)})


def rate_baselines(reqs):
    """B0-B3: {family: {param_id: [flagged IPs]}}."""
    out = {f: {} for f in ("B0", "B1", "B2", "B3")}
    for keyed, tag in ((False, "ip"), (True, "key")):
        groups = _by_key(reqs, keyed)
        peak = {k: _max_in_window(ts, 1.0) for k, ts in groups.items()}
        for thr in PEAK_THRESHOLDS:
            flagged = sorted({k[0] for k, p in peak.items() if p > thr})
            out["B1" if keyed else "B0"][f"peak1s>{thr}"] = flagged
        for w in SUSTAIN_WINDOWS:
            sus = {k: _max_in_window(ts, float(w)) / w for k, ts in groups.items()}
            for thr in SUSTAIN_THRESHOLDS:
                out["B2"][f"{tag}:mean{w}s>{thr}"] = sorted({k[0] for k, r in sus.items() if r > thr})
        for r in BUCKET_RATES:
            for b in BUCKET_BURSTS:
                out["B3"][f"{tag}:r={r},b={b}"] = _flag(groups, lambda ts, r=r, b=b:
                                                       _bucket_rejects(ts, r, b))
    return out


def hgb_baseline(path, pkg_dir, thresholds=HGB_THRESHOLDS):
    """B4: replay the recording through a features-only engine (same windows, gating and
    poll ticks as live), score each window with the saved HGB, apply threshold x
    consecutive per (IP, UA) key in poll order. {param_id: [flagged IPs]} + meta."""
    import numpy as np
    import replay_l7
    import train_l7
    clf, meta = train_l7.load_baseline(pkg_dir)
    cols = meta["columns"]
    rows, keys = [], []

    def hook(_now, key, recs, _p):
        rows.append(F.window_summary(recs, cols)[0])
        keys.append(key)

    engine = E.build_engine(None, window=meta["seq_len"], window_hook=hook)
    with _open(path) as fh:
        replay_l7.replay(list(E.read_stream(fh)), engine)
    probs = clf.predict_proba(np.array(rows, dtype=np.float64))[:, 1] if rows else []
    out = {}
    for thr in thresholds:
        hits, flagged = collections.Counter(), set()
        for key, p in zip(keys, probs, strict=True):
            hits[key] = hits[key] + 1 if p > thr else 0
            if hits[key] >= meta["consecutive"]:
                flagged.add(key[0])
        out[f"p>{thr}x{meta['consecutive']}"] = sorted(flagged)
    return out, {"windows": len(rows), "variant": meta["variant"], "sha256": meta["sha256"],
                 "deployed_threshold": meta["threshold"]}


def shaped_ips(reqs):
    return sorted({ip for ip, _, _, lreq in reqs if lreq in SHAPED})


def compute(run_dir, hgb_dir=None):
    """Every baseline for one run directory."""
    path = record_path(run_dir)
    reqs = load_requests(path)
    out = {"format": "l7-baselines/1", "record": os.path.basename(path),
           "requests": len(reqs), "families": rate_baselines(reqs),
           "shaped_ips": shaped_ips(reqs)}
    if hgb_dir and os.path.isfile(os.path.join(hgb_dir, "baseline_hgb.json")):
        out["families"]["B4"], out["hgb"] = hgb_baseline(path, hgb_dir)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir")
    ap.add_argument("--hgb", help="model package dir holding baseline_hgb.pkl/.json (B4)")
    ap.add_argument("--out", help="default: RUN_DIR/baselines.json")
    args = ap.parse_args()
    res = compute(args.run_dir, args.hgb)
    out = args.out or os.path.join(args.run_dir, "baselines.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
        fh.write("\n")
    print(f"[+] {out}: {res['requests']} requests, families {sorted(res['families'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
