#!/usr/bin/env python3
"""The P3 learning-curve runner (docs/P3_DATASET_DESIGN.md §6, T-005's protocol refined). Offline, CPU. Two steps, so that
evaluation is scored only with a selection frozen before (§4.8, §8 row 5; review T-029 P3-03):

    # select: fits on the training entities, operating points on the validation entities; writes the frozen
    # selection (selection.json, its sha256 in selection.sha256, the fitted models under fits/) and split.json.
    # P3 captures go through the disjointness checker first; no evaluation log is opened.
    ./venv/bin/python ml/learning_curve.py select --train T1 T2 T3 T4 --val V1 V2 --eval E1 ... --out SEL
    # score: refuses unless --selection-sha256 is the recorded hash of SEL/selection.json and every model it names
    # still matches; for P3 captures the checker runs again with rule 10 (split file vs selection) first.
    ./venv/bin/python ml/learning_curve.py score --train ... --val ... --eval ... --selection SEL/selection.json \
        --selection-sha256 <hash> --out OUT
    # one legacy (schema-1) capture, within-capture split: mechanics only, never a claim
    ./venv/bin/python ml/learning_curve.py select --legacy-capture results/2026-10-16_l7-p5c3-capture --out SEL --smoke

The design, with every constant from ml/p3_prereg.json ("learning_curve"):
  * fractions f of the TRAINING entities, stratified by (kind or family, training capture) with at least one entity
    per stratum, nested within a replicate draw (10 % within 25 % within 50 % within 100 %);
  * replicates: draws x inits fits for f < 100 % (5 x 3), 1 draw x full_inits for f = 100 % (15);
  * models on identical windows: gru (train_l7's GRU), hgb (window summaries), lr (standardised summaries, balanced
    class weights) and gru_shuffled (each fitted GRU scoring windows whose valid rows are shuffled);
  * each fit's operating point (threshold, consecutive) on the VALIDATION entities at the benign budget
    (train_l7.operating_point), frozen in the selection and applied unchanged to the evaluation entities;
  * metrics: entity recall per attack family and pooled, benign flags per client-hour per kind, time to decision;
  * a two-level bootstrap: each draw resamples the fits, the evaluation captures (clusters) and the entities within
    each capture; the estimate is the mean over fits of the pooled recall; 95 % percentile intervals;
  * the decision rules of §6.3 (decide(), fixture-tested): flattened, still learning, ranking, sequence helps.
"""
import argparse
import hashlib
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
    """Each window's capture and kind or family: the one its records carry (train_l7.load_records, by entity, so a
    schema-3 address reused in time is tagged per entity), else the address's."""
    for w in windows:
        w["capture"] = capture
        w["kof"] = w["recs"][0].get("_kof") or meta.get(w["recs"][0]["ip"], (None,))[0]
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


# ───────────────────────────── select (validation only) ─────────────────────────────

SEL_FORMAT = "p3-lc-selection/1"
SPLIT_FORMAT_LEGACY = "p3-lc-legacy-split/1"


class SelectionError(RuntimeError):
    """The frozen selection file is missing, altered, or does not match the data it would be scored on."""


def _sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def legacy_split_sha256(sets):
    """The legacy (one capture) analogue of the split file's hash: the sorted entities of each split."""
    rec = {"format": SPLIT_FORMAT_LEGACY, **{k: sorted({w["ip"] for w in sets[k]}) for k in ("train", "val", "eval")}}
    return hashlib.sha256(D.canonical_json(rec)).hexdigest()


def select(sets, out_dir, *, fractions, draws, inits, full_inits, epochs, hidden, layers, B, threads, seed=0,
           valid_for_claims, source, split_sha256):
    """Fit every (fraction, draw, init) on the training entities, choose each fit's operating point on the
    validation entities, save every fitted model under out_dir/fits/, and write the frozen selection file
    (selection.json: design, split sha256, per fit its point and its artifact's sha256) with selection.sha256 beside
    it. Reads the "train" and "val" sets only. Returns (selection, its sha256)."""
    import pickle

    import torch
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    torch.set_num_threads(threads)
    rules = p3_prereg.load()["learning_curve"]
    cols = F.columns(T.variant_groups()[VARIANT])
    os.makedirs(os.path.join(out_dir, "fits"), exist_ok=True)
    t0 = time.time()
    val = sets["val"]
    sv, _ = T.summaries(val, cols)
    val_shuf = shuffled(val, seed + 1)
    fits, tab_cache = [], {}

    def save(obj, name, how):
        path = os.path.join(out_dir, "fits", name)
        if how == "torch":
            torch.save(obj, path)
        else:
            with open(path, "wb") as fh:
                pickle.dump(obj, fh)
        return f"fits/{name}", _sha_file(path)

    for f, d, i in fit_plan(fractions, draws, inits, full_inits):
        keep = nested_subsets(sets["train"], fractions, 1000 * seed + d)[f]
        train = [w for w in sets["train"] if w["ip"] in keep]
        mean, std = T.fit_scaling(train, len(cols))
        model, vloss = T.train_gru(train, val, cols, mean, std, seed=1000 * d + i, epochs=epochs, hidden=hidden,
                                   layers=layers, threads=threads)
        g_art = save({"state": model.state_dict(), "mean": [float(x) for x in mean], "std": [float(x) for x in std],
                      "cols": list(cols), "hidden": hidden, "layers": layers}, f"gru_f{f}_d{d}_i{i}.pt", "torch")
        val_scores = {"gru": (g_art, T.gru_scores(model, val, mean, std)),
                      "gru_shuffled": (g_art, T.gru_scores(model, val_shuf, mean, std))}
        if (f, d) not in tab_cache:
            Xs, ys = T.summaries(train, cols)
            hgb = HistGradientBoostingClassifier(max_iter=200, random_state=seed).fit(Xs, ys)   # train_l7's B4
            lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, class_weight="balanced"))
            lr.fit(Xs, ys)
            tab_cache[(f, d)] = {"hgb": (save(hgb, f"hgb_f{f}_d{d}.pkl", "pickle"), hgb.predict_proba(sv)[:, 1]),
                                 "lr": (save(lr, f"lr_f{f}_d{d}.pkl", "pickle"), lr.predict_proba(sv)[:, 1])}
        val_scores.update(tab_cache[(f, d)])
        for m in MODELS:
            (art, sha), pv = val_scores[m]
            op = T.operating_point(val_shuf if m == "gru_shuffled" else val, pv, rules["theta_grid"], rules["k_grid"],
                                   rules["benign_budget"])
            fits.append({"model": m, "fraction": f, "draw": d, "init": i, "artifact": art, "artifact_sha256": sha,
                         "train_entities": len(keep), "train_windows": len(train),
                         "val_loss": round(vloss, 5) if m.startswith("gru") else None, "operating_point": op})
    sel = {"format": SEL_FORMAT, "source": source, "valid_for_claims": valid_for_claims, "variant": VARIANT,
           "seed": seed, "split_sha256": split_sha256,
           "design": {"fractions": fractions, "draws": draws, "inits": inits, "full_inits": full_inits,
                      "epochs": epochs, "hidden": hidden, "layers": layers, "bootstrap_b": B, "threads": threads},
           "counts": {"train": len(sets["train"]), "val": len(val)}, "fits": fits,
           "select_wall_s": round(time.time() - t0, 1)}
    data = D.canonical_json(sel) + b"\n"
    with open(os.path.join(out_dir, "selection.json"), "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()
    with open(os.path.join(out_dir, "selection.sha256"), "w", encoding="utf-8") as fh:
        fh.write(f"{sha}  selection.json\n")
    return sel, sha


# ───────────────────────────── score (evaluation, frozen selection only) ─────────────────────────────

def load_selection(path, expected_sha256):
    """The frozen selection, after checking that its sha256 is the one the caller recorded and that every
    artifact it names still has its recorded sha256. Raises SelectionError otherwise."""
    if not expected_sha256:
        raise SelectionError("refusing to score: the frozen selection's sha256 must be given (--selection-sha256)")
    try:
        actual = _sha_file(path)
    except OSError as exc:
        raise SelectionError(f"refusing to score: no frozen selection file: {exc}") from exc
    if actual != expected_sha256:
        raise SelectionError(f"refusing to score: {path} has sha256 {actual}, not the recorded {expected_sha256}")
    with open(path, encoding="utf-8") as fh:
        sel = json.load(fh)
    if sel.get("format") != SEL_FORMAT:
        raise SelectionError(f"refusing to score: {path} is not a {SEL_FORMAT} file")
    base = os.path.dirname(os.path.abspath(path))
    for art, sha in sorted({(f["artifact"], f["artifact_sha256"]) for f in sel["fits"]}):
        p = os.path.normpath(os.path.join(base, art))
        if not p.startswith(base + os.sep) or not os.path.isfile(p) or _sha_file(p) != sha:
            raise SelectionError(f"refusing to score: artifact {art} is missing or altered")
    return sel


def _load_models(sel, base):
    import pickle

    import torch

    from GRU_ML_model import GRUDDoSClassifier
    out = {}
    for art in sorted({f["artifact"] for f in sel["fits"]}):
        path = os.path.join(base, art)
        if art.endswith(".pt"):
            blob = torch.load(path, weights_only=True)
            model = GRUDDoSClassifier(input_size=len(blob["cols"]), hidden_size=blob["hidden"],
                                      num_layers=blob["layers"])
            model.load_state_dict(blob["state"])
            model.eval()
            out[art] = ("gru", model, np.array(blob["mean"], dtype=np.float32), np.array(blob["std"], dtype=np.float32))
        else:
            with open(path, "rb") as fh:
                out[art] = ("tab", pickle.load(fh), None, None)      # hash-checked in load_selection
    return out


def score(eval_windows, sel, sel_path, out_dir, *, threads, seed=0):
    """Apply every fit's frozen operating point to the evaluation windows; recall per family, benign flags per kind,
    time to decision, the two-level bootstrap and the decision rules. Writes curve.json and summary.md."""
    import torch
    torch.set_num_threads(threads)
    rules = p3_prereg.load()["learning_curve"]
    cols = F.columns(T.variant_groups()[sel["variant"]])
    t0 = time.time()
    design = sel["design"]
    fractions = design["fractions"]
    ev = eval_windows
    units = eval_units(ev)
    unit_idx = {u[0]: i for i, u in enumerate(units)}
    se, _ = T.summaries(ev, cols)
    ev_shuf = shuffled(ev, seed)
    models = _load_models(sel, os.path.dirname(os.path.abspath(sel_path)))
    cache = {}
    fits = []
    for fit in sel["fits"]:
        m, art, op = fit["model"], fit["artifact"], fit["operating_point"]
        key = (art, m == "gru_shuffled")
        if key not in cache:
            kind, model, mean, std = models[art]
            if kind == "gru":
                cache[key] = T.gru_scores(model, ev_shuf if m == "gru_shuffled" else ev, mean, std)
            else:
                cache[key] = model.predict_proba(se)[:, 1]
        row = {k: fit[k] for k in ("model", "fraction", "draw", "init", "train_entities", "train_windows",
                                   "val_loss", "operating_point")}
        if op is None:
            row["detected"] = [0] * len(units)
            row["note"] = "no operating point within the benign budget on validation: detects nothing"
        else:
            det, ttd = detections(ev_shuf if m == "gru_shuffled" else ev, cache[key], op["threshold"],
                                  op["consecutive"])
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
    stats = bootstrap(curves, units, design["bootstrap_b"], seed, pairs) if units else {}
    families = sorted({u[2] for u in units})
    per_family = {}
    for fam in families:
        idx = [j for j, u in enumerate(units) if u[2] == fam]
        per_family[fam] = {f"{m}@{f}": round(float(curves[(m, f)][:, idx].mean()), 4) if curves[(m, f)].size else None
                           for m in MODELS for f in fractions}
    verdict = decide(stats, MODELS, fractions, rules) if units else {"verdict": "no evaluation attack entities"}
    if not sel["valid_for_claims"]:
        verdict["verdict"] = "NOT A RESULT (mechanics only: " + sel["source"] + "): " + verdict["verdict"]
    res = {"format": FORMAT, "source": sel["source"], "valid_for_claims": sel["valid_for_claims"],
           "variant": sel["variant"], "design": design,
           "selection_sha256": _sha_file(sel_path), "split_sha256": sel["split_sha256"],
           "counts": {**sel["counts"], "eval": len(ev)}, "eval_attack_entities": len(units), "eval_families": families,
           "estimates": {f"{k[0]}@{k[1]}" if isinstance(k[0], str) else f"{k[0][0]}@{k[0][1]}-{k[1][0]}@{k[1][1]}":
                         [None if x is None else round(x, 4) for x in v] for k, v in stats.items()},
           "per_family_mean_recall": per_family, "decision": verdict, "fits": fits,
           "score_wall_s": round(time.time() - t0, 1)}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "curve.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")
    with open(os.path.join(out_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(summary_md(res))
    return res


def summary_md(res):
    lines = [f"# Learning curve ({res['source']})", "",
             f"valid_for_claims: **{res['valid_for_claims']}**; verdict: {res['decision']['verdict']}", "",
             (f"design: {res['design']}; counts: {res['counts']}; evaluation attack entities "
              f"{res['eval_attack_entities']} ({', '.join(map(str, res['eval_families']))})"), "",
             f"frozen selection sha256 {res['selection_sha256']}, split sha256 {res['split_sha256']}", "",
             "| model | fraction | recall (mean over fits) | 95 % CI | fits |", "|---|---|---|---|---|"]
    for m in MODELS:
        for f in res["design"]["fractions"]:
            e = res["estimates"].get(f"{m}@{f}", [None, None, None])
            n = sum(1 for r in res["fits"] if r["model"] == m and r["fraction"] == f)
            lines.append(f"| {m} | {f} | {e[0]} | [{e[1]}, {e[2]}] | {n} |")
    lines += ["", f"score wall {res['score_wall_s']} s"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("step", choices=("select", "score"),
                    help="select: fits and validation operating points, writes the frozen selection; "
                         "score: the evaluation captures, only with that frozen selection")
    ap.add_argument("--train", nargs="*", default=[])
    ap.add_argument("--val", nargs="*", default=[])
    ap.add_argument("--eval", nargs="*", default=[])
    ap.add_argument("--legacy-capture", help="one schema-1 capture, within-capture split (mechanics only)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--selection", help="score: the frozen selection.json written by select")
    ap.add_argument("--selection-sha256", help="score: the sha256 recorded for that file when it was frozen")
    ap.add_argument("--smoke", action="store_true",
                    help="select: a small design for a mechanics check: 2 draws x 1 init, 2 full inits, 5 epochs, B 300")
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    lc = p3_prereg.load()["learning_curve"]
    cols = F.columns(T.variant_groups()[VARIANT])
    splits = {"train": args.train, "val": args.val, "eval": args.eval}
    if args.legacy_capture and (args.train or args.val or args.eval):
        ap.error("--legacy-capture takes no --train/--val/--eval")
    if args.step == "select":
        design = {"fractions": lc["fractions"], "draws": lc["draws"], "inits": lc["inits"],
                  "full_inits": lc["full_inits"], "epochs": lc["epochs"], "hidden": lc["hidden"],
                  "layers": lc["layers"], "B": lc["bootstrap_b"]}
        if args.smoke:
            design.update(draws=2, inits=1, full_inits=2, epochs=5, B=300)
        os.makedirs(args.out, exist_ok=True)
        if args.legacy_capture:
            sets = legacy_sets(args.legacy_capture, cols, T.DEFAULT_SEQ, T.DEFAULT_STRIDE)
            split_sha = legacy_split_sha256(sets)
            valid = False
            source = (f"legacy single capture {os.path.basename(os.path.normpath(args.legacy_capture))}, "
                      "within-capture split, attack side not entity-disjoint")
        else:
            import l7_disjoint
            l7_disjoint.require(splits)
            split_sha = l7_disjoint.write_split(os.path.join(args.out, "split.json"), splits)
            sets = p3_sets(args.train, args.val, [], cols, T.DEFAULT_SEQ, T.DEFAULT_STRIDE)    # no evaluation logs
            valid, source = not args.smoke, "P3 captures" + (" (smoke design)" if args.smoke else "")
        _sel, sha = select({"train": sets["train"], "val": sets["val"]}, args.out, threads=args.threads,
                           seed=args.seed, valid_for_claims=valid, source=source, split_sha256=split_sha, **design)
        print(f"{sha}  {os.path.join(args.out, 'selection.json')}")
        return 0
    if not args.selection:
        ap.error("score needs --selection and --selection-sha256 (the frozen file from select)")
    sel = load_selection(args.selection, args.selection_sha256)
    if args.legacy_capture:
        sets = legacy_sets(args.legacy_capture, cols, T.DEFAULT_SEQ, T.DEFAULT_STRIDE)
        if legacy_split_sha256(sets) != sel["split_sha256"]:
            raise SelectionError("refusing to score: the split differs from the one the selection was made on")
        ev = sets["eval"]
    else:
        import l7_disjoint
        l7_disjoint.require(splits, split_file=os.path.join(os.path.dirname(os.path.abspath(args.selection)),
                                                            "split.json"),
                            selection_file=args.selection)            # rule 10 before any evaluation log is read
        ev = p3_sets([], [], args.eval, cols, T.DEFAULT_SEQ, T.DEFAULT_STRIDE)["eval"]
    res = score(ev, sel, args.selection, args.out, threads=args.threads, seed=args.seed)
    print(summary_md(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
