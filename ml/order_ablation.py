#!/usr/bin/env python3
"""Order-shuffle ablation of an L7 model package on recorded engine input (audit G-02).

Offline and read-only: no nginx, no sockets, no traffic, no XDP.

Does the model use the ORDER of the requests inside a window, or only the marginal
distribution of their features? Each run's recording (the daemon's L7_RECORD file) is
replayed through the shadow engine three times with the same model:

  recorded   the windows as the engine builds them (reproduces the live run);
  shuffled   the valid rows of every scored window randomly permuted before scoring;
  reversed   the valid rows reversed.

Every row keeps its own features, including the inter-arrival time computed in the true
order. The per-column distributions are therefore identical in the three replays and only
the order differs. A model that reads sequence structure loses detection, or changes its
benign flags, on the shuffled replay; an order-free model decides identically.

Reported per run and pooled: comparison-set attackers flagged (ml/p5b_report.FAST_FAMILIES),
benign IPs flagged, the mean and maximum |dp| against the recorded replay, the share of
windows whose decision (p > threshold) flips, and the correlation of the probabilities.

Verdict, fixed here before it is applied to any new data:
  order-free       the shuffled replay flags exactly the same IPs in every run AND fewer
                   than ORDER_FREE_MAX_FLIP of all windows flip their decision;
  order-sensitive  otherwise, when the windows of the replays line up;
  inconclusive     the replays scored different numbers of windows.

This tests the TRAINED model on this data. "Order-free" means this model does not use
order here, not that no model could.

    ./venv/bin/python ml/order_ablation.py PACKAGE RUN_DIR [RUN_DIR ...]
        [--seed 7] [--out report.json] [--md report.md]

RUN_DIR holds manifest.json and l7_record.jsonl[.gz] (an eval run, e.g.
results/2026-10-16_l7-p5c4-eval/runA1).
"""
import argparse
import gzip
import json
import math
import os
import sys

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import p5b_report
import replay_l7

import l7_engine as E
import l7_ingest

MODES = ("recorded", "shuffled", "reversed")
ORDER_FREE_MAX_FLIP = 0.01       # share of windows whose decision may flip
FORMAT = "l7-order-ablation/1"
DEFAULT_SEED = 7


class OrderedScorer:
    """Wraps a scorer: applies `mode` to the valid rows of every window, then scores.

    Padding rows (column 0 == 0) stay where they are; only the real requests move among
    their own positions. Every probability is kept in `probs`, in scoring order."""

    def __init__(self, inner, mode, seed=DEFAULT_SEED):
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r} (known: {', '.join(MODES)})")
        self.inner = inner
        self.mode = mode
        self.rng = np.random.default_rng(seed)
        self.probs = []
        # The engine reads these from its scorer.
        self.cols = list(inner.cols)
        self.seq_len = inner.seq_len
        self.threshold = inner.threshold
        self.consecutive = inner.consecutive
        self.sha256 = getattr(inner, "sha256", "")

    def reorder(self, batch):
        out = np.array(batch, dtype=np.float32, copy=True)
        if self.mode == "recorded":
            return out
        for i in range(out.shape[0]):
            idx = np.flatnonzero(out[i, :, 0] == 1.0)
            if len(idx) > 1:
                src = idx[::-1] if self.mode == "reversed" else self.rng.permutation(idx)
                out[i, idx] = out[i, src]
        return out

    def score(self, batch):
        p = np.asarray(self.inner.score(self.reorder(batch)), dtype=np.float64)
        self.probs.extend(float(x) for x in p)
        return p


def load_items(run_dir):
    """The engine input stream of a run (l7_record.jsonl or .jsonl.gz), as a list."""
    for name in ("l7_record.jsonl.gz", "l7_record.jsonl"):
        path = os.path.join(run_dir, name)
        if os.path.isfile(path):
            opener = gzip.open if name.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as fh:
                return list(E.read_stream(fh))
    raise FileNotFoundError(f"no l7_record.jsonl[.gz] in {run_dir}")


def classify(manifest):
    """(comparison attackers, benign IPs) of a run, as p5b_report defines them."""
    comp, benign = set(), set()
    for ip, e in manifest["ip_map"].items():
        if e.get("class") == "attack" and e.get("family") in p5b_report.FAST_FAMILIES:
            comp.add(ip)
        elif e.get("class") == "benign":
            benign.add(ip)
    return comp, benign


def replay_run(inner, items, mode, seed=DEFAULT_SEED):
    """(flagged IPs, probabilities in scoring order) of one replay of `items`."""
    scorer = OrderedScorer(inner, mode, seed)
    engine = E.L7ShadowEngine(l7_ingest.L7WindowStore(maxlen=inner.seq_len), scorer=scorer)
    events = replay_l7.replay(items, engine)
    flagged = sorted({e["ip"] for e in events if e.get("kind") == "l7_would_ban"})
    return flagged, np.asarray(scorer.probs, dtype=np.float64)


def _r(x):
    return None if x is None or math.isnan(x) else round(float(x), 6)


def ablate_run(inner, run_dir, seed=DEFAULT_SEED):
    """All three replays of one run, compared with the recorded one."""
    with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    comp, benign = classify(manifest)
    items = load_items(run_dir)
    base_flagged, base_p = replay_run(inner, items, "recorded", seed)
    thr = inner.threshold
    modes = {}
    for mode in MODES:
        flagged, p = (base_flagged, base_p) if mode == "recorded" \
            else replay_run(inner, items, mode, seed)
        entry = {"comparison_flagged": len(comp & set(flagged)),
                 "benign_flagged": len(benign & set(flagged)),
                 "benign_flagged_ips": sorted(benign & set(flagged)),
                 "over_threshold_share": _r((p > thr).mean()) if len(p) else None}
        if mode != "recorded":
            aligned = len(p) == len(base_p)
            entry["windows_aligned"] = aligned
            entry["decisions_identical"] = flagged == base_flagged
            if aligned and len(p):
                d = np.abs(p - base_p)
                entry["mean_abs_dp"] = _r(d.mean())
                entry["max_abs_dp"] = _r(d.max())
                entry["flip_rate"] = _r(((p > thr) != (base_p > thr)).mean())
                entry["p_correlation"] = _r(np.corrcoef(p, base_p)[0, 1]
                                            if p.std() > 0 and base_p.std() > 0 else None)
        modes[mode] = entry
    return {"run": os.path.basename(os.path.normpath(run_dir)), "windows": len(base_p),
            "comparison_attackers": len(comp), "benign_ips": len(benign), "modes": modes}


def verdict(runs):
    shuffled = [r["modes"]["shuffled"] for r in runs]
    if not all(s["windows_aligned"] for s in shuffled):
        return "inconclusive"
    flips = max((s.get("flip_rate") or 0.0) for s in shuffled)
    if all(s["decisions_identical"] for s in shuffled) and flips < ORDER_FREE_MAX_FLIP:
        return "order-free"
    return "order-sensitive"


def ablate(inner, run_dirs, seed=DEFAULT_SEED):
    runs = [ablate_run(inner, d, seed) for d in run_dirs]
    pooled = {m: {"comparison_flagged": sum(r["modes"][m]["comparison_flagged"] for r in runs),
                  "benign_flagged": sum(r["modes"][m]["benign_flagged"] for r in runs)}
              for m in MODES}
    v = verdict(runs)
    return {"format": FORMAT, "seed": seed,
            "package": {"weights_sha256": getattr(inner, "sha256", ""), "seq_len": inner.seq_len,
                        "threshold": inner.threshold, "consecutive": inner.consecutive},
            "order_free_max_flip": ORDER_FREE_MAX_FLIP,
            "comparison_attackers": sum(r["comparison_attackers"] for r in runs),
            "benign_ips": sum(r["benign_ips"] for r in runs),
            "runs": runs, "pooled": pooled, "verdict": v}


def to_markdown(rep):
    pkg = rep["package"]
    title = (f"**Order-shuffle ablation** (`{FORMAT}`, seed {rep['seed']}, model "
             f"`{pkg['weights_sha256'][:12]}`, threshold {pkg['threshold']} x {pkg['consecutive']})")
    header = ("| Run | Windows | Mode | Attackers flagged | Benign flagged | Windows over thr. "
              "| Flips | mean abs dp | corr(p) |")
    lines = [title, "", header, "|---|---|---|---|---|---|---|---|---|"]
    for r in rep["runs"]:
        for m in MODES:
            e = r["modes"][m]
            lines.append(f"| {r['run']} | {r['windows']} | {m} | {e['comparison_flagged']}/"
                         f"{r['comparison_attackers']} | {e['benign_flagged']}/{r['benign_ips']} "
                         f"| {e['over_threshold_share']} | {e.get('flip_rate', '—')} "
                         f"| {e.get('mean_abs_dp', '—')} | {e.get('p_correlation', '—')} |")
    p = rep["pooled"]
    pooled = "; ".join(f"{m} {p[m]['comparison_flagged']}/{rep['comparison_attackers']} "
                       f"attackers, {p[m]['benign_flagged']} benign flags" for m in MODES)
    verdict_line = (f"**Verdict: {rep['verdict']}** (order-free = identical flagged IPs in "
                    f"every run and a window flip rate below {rep['order_free_max_flip']}).")
    lines += ["", f"Pooled: {pooled}", "", verdict_line]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("package", help="model package directory (config.json + model.pth)")
    ap.add_argument("runs", nargs="+", help="run directories with manifest.json + l7_record")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="seed of the shuffle")
    ap.add_argument("--out", help="write the report as JSON")
    ap.add_argument("--md", help="write the report as Markdown")
    args = ap.parse_args(argv)
    import l7_scorer  # torch is imported only here
    rep = ablate(l7_scorer.L7Scorer.load(args.package), args.runs, args.seed)
    rep["package"]["path"] = args.package
    text = to_markdown(rep)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1)
            fh.write("\n")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
