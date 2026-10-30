#!/usr/bin/env python3
"""The P3 learning-curve runner (docs/P3_DATASET_DESIGN.md §6, T-005's protocol refined). Offline, CPU.

    # P3 captures: the disjointness check (ml/l7_disjoint.py) runs first and must pass
    ./venv/bin/python ml/learning_curve.py --train T1 T2 T3 T4 --val V1 V2 --eval E1 ... --out DIR
    # one legacy (schema-1) capture, within-capture split: mechanics only, never a claim
    ./venv/bin/python ml/learning_curve.py --legacy-capture results/2026-10-16_l7-p5c3-capture --out DIR --smoke

The design, with every constant from ml/p3_prereg.json ("learning_curve"):
  * fractions f of the TRAINING entities, stratified by (kind or family, training capture) with at least one entity
    per stratum, nested within a replicate draw (10 % within 25 % within 50 % within 100 %);
  * replicates: draws x inits fits for f < 100 % (5 x 3), 1 draw x full_inits for f = 100 % (15);
  * models on identical windows: gru (train_l7's GRU), hgb (window summaries), lr (standardised summaries, balanced
    class weights) and gru_shuffled (each fitted GRU scoring windows whose valid rows are shuffled);
  * each fit's operating point (threshold, consecutive) on the VALIDATION entities at the benign budget
    (train_l7.operating_point), applied unchanged to the evaluation entities;
  * metrics: entity recall per attack family and pooled, benign flags per client-hour per kind, time to decision;
  * a two-level bootstrap: each draw resamples the fits, the evaluation captures (clusters) and the entities within
    each capture; the estimate is the mean over fits of the pooled recall; 95 % percentile intervals;
  * the decision rules of §6.3 (decide(), fixture-tested): flattened, still learning, ranking, sequence helps.
"""
import argparse
import json
import math
import os
import random
import sys
import time

for _var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ.setdefault(_var, "2")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p3_prereg
import train_l7 as T

import l7_dataset as D
import l7_features as F

FORMAT = "p3-learning-curve/1"
MODELS = ("gru", "hgb", "lr", "gru_shuffled")
VARIANT = "no_size_no_server_timing"      # the variant every P5c result used; P3 freezes its own (§6.1)


# ───────────────────────────── data ─────────────────────────────

def _entity_meta(manifest):
    """address -> (kind or family, held_out, class) from a manifest's ip_map."""
    return {ip: (e.get("family") or e.get("kind"), bool(e.get("held_out")), e.get("class"))
            for ip, e in manifest["ip_map"].items()}


def _tag(windows, capture, meta):
    for w in windows:
        w["capture"] = capture
        w["kof"] = meta.get(w["recs"][0]["ip"], (None,))[0]
    return windows


def p3_sets(train_dirs, val_dirs, eval_dirs, cols, seq, stride):
    """Windows per split from P3 captures, keyed by entity id; windows know their capture and kind/family."""
    out = {}
    for name, dirs in (("train", train_dirs), ("val", val_dirs), ("eval", eval_dirs)):
        ws = []
        for d in dirs:
            m, recs = T.load_records(d)
            meta = _entity_meta(m)
            got = _tag(T.group_windows(recs, seq, cols, stride, T.DEFAULT_MIN_EVENTS),
                       m.get("capture_id", os.path.basename(d)), meta)
            for w in got:
                w["ip"] = w["recs"][0]["_entity"]          # an address may serve other entities elsewhere
            ws += got
        out[name] = ws
    return out


def legacy_sets(dataset_dir, cols, seq, stride, split_seed=0):
    """One schema-1 capture split as train_l7 splits it (benign by IP, trained attacks by time, held-out families and
    the held-out benign kind to evaluation). The attack side is NOT entity-disjoint: mechanics only."""
    m, recs = T.load_records(dataset_dir)
    meta = _entity_meta(m)
    windows = _tag(T.group_windows(recs, seq, cols, stride, T.DEFAULT_MIN_EVENTS), "legacy", meta)
    sets, _ = T.split(windows, split_seed)
    ev = sets["benign_test"] + sets["heldout"] + sets["trained_attack_test"] + sets["benign_heldout"]
    return {"train": sets["train"], "val": sets["val"], "eval": ev}


# ───────────────────────────── design ─────────────────────────────

def nested_subsets(train_windows, fractions, draw_seed):
    """{fraction: set of training entities}: per stratum (kind or family, capture) a seeded permutation, and fraction f
    takes its first max(1, ceil(f x n)) entities, so the subsets are nested within the draw."""
    strata = {}
    for w in train_windows:
        strata.setdefault((w["cls"], w["kof"], w["capture"]), set()).add(w["ip"])
    rng = random.Random(draw_seed)
    perms = {k: rng.sample(sorted(v), len(v)) for k, v in sorted(strata.items(), key=lambda kv: str(kv[0]))}
    return {f: {e for perm in perms.values() for e in perm[:max(1, math.ceil(f * len(perm)))]} for f in fractions}


def fit_plan(fractions, draws, inits, full_inits):
    """[(fraction, draw, init)]: draws x inits for f < 1, one draw x full_inits for f = 1."""
    plan = []
    for f in fractions:
        if f >= 1.0:
            plan += [(f, 0, i) for i in range(full_inits)]
        else:
            plan += [(f, d, i) for d in range(draws) for i in range(inits)]
    return plan


def shuffled(windows, seed):
    """Copies of the windows with each window's valid rows (column 0 > 0) permuted."""
    rng = np.random.default_rng(seed)
    out = []
    for w in windows:
        X = w["X"].copy()
        idx = np.flatnonzero(X[:, 0] > 0)
        X[idx] = X[rng.permutation(idx)]
        out.append(dict(w, X=X))
    return out


# ───────────────────────────── scoring ─────────────────────────────

def detections(windows, scores, thr, k):
    """({entity: detected}, {entity: seconds from its first request to the policy's decision, or None}),
    with the deployed policy: `k` successive windows of one key over `thr`."""
    first = {}
    for w in windows:
        first[w["ip"]] = min(first.get(w["ip"], math.inf), F.start_time(w["recs"][0]))
    det, ttd = {}, {}
    for (ent, _ua), g in T.per_group(windows, scores).items():
        run = 0
        for t, p, _w in g:
            run = run + 1 if p > thr else 0
            if run >= k:
                ttd[ent] = min(ttd.get(ent, math.inf), t - first[ent])
                break
        det[ent] = det.get(ent, False) or run >= k
    return det, {e: ttd.get(e) for e in det}


def benign_rate(windows, det):
    """Flagged benign entities per client-hour, per kind."""
    span, kind_of = {}, {}
    for w in windows:
        if w["cls"] == D.BENIGN:
            lo, hi = span.get(w["ip"], (w["t"], w["t"]))
            span[w["ip"]] = (min(lo, w["t"]), max(hi, w["t"]))
            kind_of[w["ip"]] = w["kof"]
    hours, flags = {}, {}
    for ent, (lo, hi) in span.items():
        kind = kind_of[ent]
        hours[kind] = hours.get(kind, 0.0) + max(hi - lo, 1.0) / 3600.0
        flags[kind] = flags.get(kind, 0) + int(det.get(ent, False))
    return {k: {"flagged": flags[k], "client_hours": round(hours[k], 4),
                "per_client_hour": round(flags[k] / hours[k], 3)} for k in sorted(hours, key=str)}


# ───────────────────────────── bootstrap and rules ─────────────────────────────

def eval_units(eval_windows):
    """The attack entities of the evaluation set: [(entity, capture, family)], sorted."""
    seen = {}
    for w in eval_windows:
        if w["cls"] == D.ATTACK:
            seen[w["ip"]] = (w["capture"], w["kof"])
    return sorted((e, c, f) for e, (c, f) in seen.items())


def entity_weights(units, rng):
    """Two-level resampling weights: captures with replacement, then entities with replacement within each."""
    by_cap = {}
    for i, (_e, c, _f) in enumerate(units):
        by_cap.setdefault(c, []).append(i)
    caps = sorted(by_cap)
    w = np.zeros(len(units))
    for c in rng.choice(len(caps), size=len(caps), replace=True):
        members = by_cap[caps[c]]
        for j in rng.choice(len(members), size=len(members), replace=True):
            w[members[j]] += 1
    return w


def bootstrap(curves, units, B, seed, pairs=()):
    """curves: {name: detection matrix (fits x units)}. Returns {name: (estimate, lo, hi)} and the same for each
    (a, b) in pairs as the difference a - b, all in recall units. Fits are resampled per curve; the entity weights
    are shared by every curve in a draw (paired)."""
    rng = np.random.default_rng(seed)
    est = {n: float(m.mean()) if m.size else None for n, m in curves.items()}
    draws = {n: [] for n in curves}
    diffs = {p: [] for p in pairs}
    for _ in range(B):
        w = entity_weights(units, rng)
        if w.sum() == 0:
            continue
        vals = {}
        for n, m in curves.items():
            if not m.size:
                continue
            fits = rng.choice(m.shape[0], size=m.shape[0], replace=True)
            vals[n] = float((m[fits] @ w).mean() / w.sum())
            draws[n].append(vals[n])
        for a, b in pairs:
            if a in vals and b in vals:
                diffs[(a, b)].append(vals[a] - vals[b])

    def ci(xs):
        return (float(np.percentile(xs, 2.5)), float(np.percentile(xs, 97.5))) if xs else (None, None)
    out = {n: (est[n], *ci(draws[n])) for n in curves}
    for a, b in pairs:
        if est.get(a) is not None and est.get(b) is not None:
            out[(a, b)] = (est[a] - est[b], *ci(diffs[(a, b)]))
    return out


def flattened(diff, flatten_pp):
    """diff = (estimate, lo, hi) of recall(100 %) - recall(f), in recall units."""
    _e, lo, hi = diff
    return lo is not None and lo <= 0.0 <= hi < flatten_pp / 100.0


def decide(stats, models, fractions, rules):
    """The §6.3 verdicts from bootstrap results. stats[(model, f)] = (est, lo, hi) of recall;
    stats[((model, 1.0), (model, f))] = the difference to 100 %; stats[((a, f), (b, f))] = a - b.
    Returns {"curves": {model: {...}}, "rankings": [...], "sequence_helps": {...}}."""
    full = max(fractions)
    out = {"curves": {}, "rankings": [], "sequence_helps": {}}
    for m in models:
        flat = [f for f in fractions if f < full and flattened(stats[((m, full), (m, f))], rules["flatten_pp"])]
        half = 0.5 if 0.5 in fractions else max(f for f in fractions if f < full)
        e, lo, _hi = stats[((m, full), (m, half))]
        learning = e >= rules["still_learning_pp"] / 100.0 and lo is not None and lo > 0.0
        out["curves"][m] = {"flattened_at": flat, "still_learning": learning,
                            "plateau_from": min(flat) if flat and not learning else None}
    for a in models:
        for b in models:
            if a == b or (a, b) == ("gru", "gru_shuffled"):
                continue
            ca, cb = out["curves"][a], out["curves"][b]
            if ca["plateau_from"] is None or cb["plateau_from"] is None:
                continue
            f = full
            e, lo, _hi = stats[((a, f), (b, f))]
            if e >= rules["ranking_pp"] / 100.0 and lo is not None and lo > 0.0:
                out["rankings"].append({"winner": a, "loser": b, "fraction": f, "diff": e, "ci_lo": lo})
    for f in fractions:
        key = (("gru", f), ("gru_shuffled", f))
        if key in stats:
            e, lo, hi = stats[key]
            out["sequence_helps"][str(f)] = {"diff": e, "ci": [lo, hi], "meets_pp": e >= rules["sequence_pp"] / 100.0}
    if any(c["still_learning"] for c in out["curves"].values()):
        out["verdict"] = "still learning: more data needed; no ranking is claimed"
        out["rankings"] = []
    elif out["rankings"]:
        out["verdict"] = "ranking: " + "; ".join(f"{r['winner']} > {r['loser']}" for r in out["rankings"])
    else:
        out["verdict"] = "no ranking"
    return out


# ───────────────────────────── the run ─────────────────────────────

def run(sets, out_dir, *, fractions, draws, inits, full_inits, epochs, hidden, layers, B, threads, seed=0,
        valid_for_claims, source):
    import torch
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    torch.set_num_threads(threads)
    rules = p3_prereg.load()["learning_curve"]
    cols = F.columns(T.variant_groups()[VARIANT])
    t0, c0 = time.time(), time.process_time()
    val, ev = sets["val"], sets["eval"]
    units = eval_units(ev)
    unit_idx = {u[0]: i for i, u in enumerate(units)}
    sv, _ = T.summaries(val, cols)
    se, _ = T.summaries(ev, cols)
    ev_shuf = shuffled(ev, seed)
    val_shuf = shuffled(val, seed + 1)
    fits = []
    hgb_cache = {}
    for f, d, i in fit_plan(fractions, draws, inits, full_inits):
        keep = nested_subsets(sets["train"], fractions, 1000 * seed + d)[f]
        train = [w for w in sets["train"] if w["ip"] in keep]
        mean, std = T.fit_scaling(train, len(cols))
        model, vloss = T.train_gru(train, val, cols, mean, std, seed=1000 * d + i, epochs=epochs, hidden=hidden,
                                   layers=layers, threads=threads)
        scores = {"gru": (T.gru_scores(model, val, mean, std), T.gru_scores(model, ev, mean, std)),
                  "gru_shuffled": (T.gru_scores(model, val_shuf, mean, std), T.gru_scores(model, ev_shuf, mean, std))}
        if (f, d) not in hgb_cache:
            Xs, ys = T.summaries(train, cols)
            hgb = HistGradientBoostingClassifier(max_iter=200, random_state=seed).fit(Xs, ys)   # train_l7's B4
            lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced"))
            lr.fit(Xs, ys)
            hgb_cache[(f, d)] = {"hgb": (hgb.predict_proba(sv)[:, 1], hgb.predict_proba(se)[:, 1]),
                                 "lr": (lr.predict_proba(sv)[:, 1], lr.predict_proba(se)[:, 1])}
        scores.update(hgb_cache[(f, d)])
        for m in MODELS:
            pv, pe = scores[m]
            op = T.operating_point(val_shuf if m == "gru_shuffled" else val, pv, rules["theta_grid"], rules["k_grid"],
                                   rules["benign_budget"])
            row = {"model": m, "fraction": f, "draw": d, "init": i, "train_entities": len(keep),
                   "train_windows": len(train), "val_loss": round(vloss, 5) if m.startswith("gru") else None,
                   "operating_point": op}
            if op is None:
                row["detected"] = [0] * len(units)
                row["note"] = "no operating point within the benign budget on validation: detects nothing"
            else:
                det, ttd = detections(ev_shuf if m == "gru_shuffled" else ev, pe, op["threshold"], op["consecutive"])
                vec = [0] * len(units)
                for e, hit in det.items():
                    if e in unit_idx:
                        vec[unit_idx[e]] = int(hit)
                row["detected"] = vec
                times = sorted(v for e, v in ttd.items() if e in unit_idx and v is not None)
                row["ttd_median_s"] = round(times[len(times) // 2], 3) if times else None
                row["benign"] = benign_rate(ev, det)
            fits.append(row)
    curves = {}
    for m in MODELS:
        for f in fractions:
            curves[(m, f)] = np.array([r["detected"] for r in fits if r["model"] == m and r["fraction"] == f],
                                      dtype=float)
    full = max(fractions)
    pairs = [((m, full), (m, f)) for m in MODELS for f in fractions if f < full]
    pairs += [((a, full), (b, full)) for a in MODELS for b in MODELS if a != b]
    pairs += [(("gru", f), ("gru_shuffled", f)) for f in fractions]
    stats = bootstrap(curves, units, B, seed, pairs) if units else {}
    families = sorted({u[2] for u in units})
    per_family = {}
    for fam in families:
        idx = [j for j, u in enumerate(units) if u[2] == fam]
        per_family[fam] = {f"{m}@{f}": round(float(curves[(m, f)][:, idx].mean()), 4) if curves[(m, f)].size else None
                           for m in MODELS for f in fractions}
    verdict = decide(stats, MODELS, fractions, rules) if units else {"verdict": "no evaluation attack entities"}
    if not valid_for_claims:
        verdict["verdict"] = "NOT A RESULT (mechanics only: " + source + "): " + verdict["verdict"]
    res = {"format": FORMAT, "source": source, "valid_for_claims": valid_for_claims, "variant": VARIANT,
           "design": {"fractions": fractions, "draws": draws, "inits": inits, "full_inits": full_inits,
                      "epochs": epochs, "hidden": hidden, "layers": layers, "bootstrap_b": B, "threads": threads},
           "counts": {k: len(v) for k, v in sets.items()}, "eval_attack_entities": len(units),
           "eval_families": families,
           "estimates": {f"{k[0]}@{k[1]}" if isinstance(k[0], str) else f"{k[0][0]}@{k[0][1]}-{k[1][0]}@{k[1][1]}":
                         [None if x is None else round(x, 4) for x in v] for k, v in stats.items()},
           "per_family_mean_recall": per_family, "decision": verdict, "fits": fits,
           "wall_s": round(time.time() - t0, 1), "cpu_s_main_process": round(time.process_time() - c0, 1)}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "curve.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")
    return res


def summary_md(res):
    lines = [f"# Learning curve ({res['source']})", "",
             f"valid_for_claims: **{res['valid_for_claims']}**; verdict: {res['decision']['verdict']}", "",
             (f"design: {res['design']}; counts: {res['counts']}; evaluation attack entities "
              f"{res['eval_attack_entities']} ({', '.join(map(str, res['eval_families']))})"), "",
             "| model | fraction | recall (mean over fits) | 95 % CI | fits |", "|---|---|---|---|---|"]
    for m in MODELS:
        for f in res["design"]["fractions"]:
            e = res["estimates"].get(f"{m}@{f}", [None, None, None])
            n = sum(1 for r in res["fits"] if r["model"] == m and r["fraction"] == f)
            lines.append(f"| {m} | {f} | {e[0]} | [{e[1]}, {e[2]}] | {n} |")
    lines += ["", f"wall {res['wall_s']} s, main-process CPU {res['cpu_s_main_process']} s"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--train", nargs="*", default=[])
    ap.add_argument("--val", nargs="*", default=[])
    ap.add_argument("--eval", nargs="*", default=[])
    ap.add_argument("--legacy-capture", help="one schema-1 capture, within-capture split (mechanics only)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--smoke", action="store_true",
                    help="a small design for a mechanics check: 2 draws x 1 init, 2 full inits, 5 epochs, B 300")
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    lc = p3_prereg.load()["learning_curve"]
    design = {"fractions": lc["fractions"], "draws": lc["draws"], "inits": lc["inits"], "full_inits": lc["full_inits"],
              "epochs": lc["epochs"], "hidden": lc["hidden"], "layers": lc["layers"], "B": lc["bootstrap_b"]}
    if args.smoke:
        design.update(draws=2, inits=1, full_inits=2, epochs=5, B=300)
    cols = F.columns(T.variant_groups()[VARIANT])
    if args.legacy_capture:
        if args.train or args.val or args.eval:
            ap.error("--legacy-capture takes no --train/--val/--eval")
        sets = legacy_sets(args.legacy_capture, cols, T.DEFAULT_SEQ, T.DEFAULT_STRIDE)
        valid = False
        source = (f"legacy single capture {os.path.basename(os.path.normpath(args.legacy_capture))}, "
                  "within-capture split, attack side not entity-disjoint")
    else:
        import l7_disjoint
        l7_disjoint.require({"train": args.train, "val": args.val, "eval": args.eval})
        sets = p3_sets(args.train, args.val, args.eval, cols, T.DEFAULT_SEQ, T.DEFAULT_STRIDE)
        valid, source = not args.smoke, "P3 captures" + (" (smoke design)" if args.smoke else "")
    res = run(sets, args.out, threads=args.threads, seed=args.seed, valid_for_claims=valid, source=source, **design)
    with open(os.path.join(args.out, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(summary_md(res))
    print(summary_md(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
