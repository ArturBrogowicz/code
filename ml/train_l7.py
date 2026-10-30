#!/usr/bin/env python3
"""Train and evaluate an L7 request-sequence model (docs/L7_GRU_DESIGN.md §6.4; Phase P4).

Offline, CPU only: reads a dataset (l7_dataset: manifest + l7json access log), builds
per-(IP, ua_hash) request windows (l7_features), trains a GRU, and evaluates it at the
DEPLOYED policy (p > threshold in `consecutive` scored windows). It writes a model
package (l7_scorer) + a model card + a metrics report. It never touches
training_results/ (that is the XDP model's; promotion is P6's job).

Honest evaluation (the ML_INVESTIGATION lessons):
  * benign is split IP-disjoint; its test IPs give the false-positive rate.
  * generalization is measured family-disjoint: the manifest's HELD-OUT families
    (padded_flood, credstuff, slowread) are never trained, and recall on them is the
    headline. Trained attacks share too few IPs to split IP-disjoint, so their recall
    is reported as in-distribution, not a generalization claim.
  * metrics are at the policy, per family and per (IP, ua) group, with Clopper-Pearson
    intervals and the sampling always stated; window counts are shown but flagged as
    non-independent (sliding windows overlap).
  * the invariance probe battery (ml/l7_probes) is a HARD gate, applied to EVERY variant
    before selection (P5c, docs/L7_GRU_DESIGN.md §7.3.2.1): the exact transforms plus
    server_load (a 10x slower server must flip <= 1 % of decisions, R17). Only passing
    variants are eligible; the selection rule then picks among them.
  * a tabular baseline (sklearn, decision 6) is trained under the identical split and
    policy, so the thesis can say whether sequence modelling earns its place.
  * feature-set variants (with/without size, uri) are compared, as CF3 did for XDP.
  * a HELD-OUT benign kind (P5b, docs/L7_GRU_DESIGN.md §7.2 decision 1) is never trained
    on and is reported as its own benign set; model selection still uses the ordinary
    benign test IPs only, so the P4 selection rule is unchanged.
  * the chosen variant's tabular baseline is saved beside the package
    (baseline_hgb.pkl + .json) so the online evaluation can replay it (P5b baseline B4).

Selection (docs/P3_DATASET_DESIGN.md §4.8). The default rule, `--selection val`, uses the
VALIDATION set only: each probe-gated variant gets its operating point (threshold,
consecutive) from the pre-registered grids at the benign budget (at most 1 % of the
validation's benign entities flagged, ml/p3_prereg.json), and the variant with the highest
validation attack-entity recall at its point wins (tie-break: fewer benign entities
flagged, then lower validation loss). The probes read validation records only. The test
sets (benign_test, held-out families, trained-attack tail, held-out benign) are scored at
the frozen point and reported, never used. `--selection p5c` is the published P4/P5c rule
(held-out family groups and benign_test FP at 0.95 x 3; probes on every record), kept to
reproduce results/2026-10-16_l7-p5c3-train and earlier.

With --val (P3), the positional datasets are the training captures and --val the
validation captures, all schema 2; the disjointness checker (ml/l7_disjoint.py) must pass
before anything is fitted, windows are keyed by entity id, and the run writes split.json
and selection.json (variant, operating point, split sha256) beside the package.

    ./venv/bin/python ml/train_l7.py DATASET_DIR --out ml/l7_models/<name> [--epochs 25]
    ./venv/bin/python ml/train_l7.py TRAIN_DIR... --val VAL_DIR... --out <dir>
    ./venv/bin/python ml/train_l7.py results/2026-10-16_l7-p5c3-capture --selection p5c ...
"""
import argparse
import json
import math
import os
import sys
import time

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "ml"))
import l7_probes

import l7_dataset
import l7_features as F
import l7_ingest

DEFAULT_SEQ = 20
DEFAULT_STRIDE = 3
DEFAULT_MIN_EVENTS = 5
MAX_WIN_PER_GROUP = 400
THRESHOLD = 0.95
CONSECUTIVE = 3


# ───────────────────────────── data ─────────────────────────────

def load_records(dataset_dir):
    """Return (manifest, [records]) with class/family/held_out attached per record."""
    manifest, log_path = l7_dataset.read_dataset(dataset_dir)
    ip_map = manifest["ip_map"]
    recs = []
    with l7_dataset.open_log(log_path) as fh:      # plain or gzipped (schema 2, published)
        for line in fh:
            obj = l7_ingest.parse_l7_line(line)
            if obj is None:
                continue
            rec = l7_ingest.normalise(obj)
            if rec is None:
                continue
            cls, family, held = l7_dataset.label_for(rec["ip"], ip_map)
            if cls == l7_dataset.OTHER:
                continue
            rec["_cls"], rec["_family"], rec["_held"] = cls, family, held
            rec["_entity"] = ip_map[rec["ip"]].get("entity_id", rec["ip"])
            recs.append(rec)
    return manifest, recs


def group_windows(recs, seq_len, cols, stride, min_events, max_per_group=MAX_WIN_PER_GROUP):
    """Sliding windows per (IP, ua_hash) in arrival order. Each item:
    {X, y, ip, ua_h, family, cls, held, t}. t is the window's last request start."""
    groups = {}
    for r in sorted(recs, key=F.start_time):
        groups.setdefault(l7_ingest.key_of(r), []).append(r)
    out = []
    for (ip, ua), seq in groups.items():
        cls = seq[0]["_cls"]
        starts = range(min_events - 1, len(seq))
        picks = [i for n, i in enumerate(starts) if n % stride == 0]
        if len(picks) > max_per_group:
            picks = [picks[i] for i in np.linspace(0, len(picks) - 1, max_per_group).astype(int)]
        for end in picks:
            window = seq[max(0, end - seq_len + 1):end + 1]
            out.append({"X": F.window_matrix(window, seq_len, cols),
                        "y": 1 if cls == l7_dataset.ATTACK else 0, "ip": ip, "ua_h": ua,
                        "family": seq[0]["_family"], "cls": cls, "held": seq[0]["_held"],
                        "t": F.start_time(window[-1]), "n": len(window),
                        "recs": window})
    return out


def split(windows, seed, benign_bounds=(0.67, 0.83), attack_time_bounds=(0.85,)):
    """Split windows. Benign is IP-disjoint (train/val/test); a held-out benign kind's
    windows are their own set (benign_heldout), never trained or selected on. Held-out
    families are a separate eval set. Trained attacks go to train, with a time tail in val
    for early stopping. Returns dict of named window-lists."""
    import random
    rng = random.Random(seed)
    benign_ips = sorted({w["ip"] for w in windows
                         if w["cls"] == l7_dataset.BENIGN and not w["held"]})
    rng.shuffle(benign_ips)
    a = int(len(benign_ips) * benign_bounds[0])
    b = int(len(benign_ips) * benign_bounds[1])
    ben_train, ben_val, ben_test = set(benign_ips[:a]), set(benign_ips[a:b]), set(benign_ips[b:])

    sets = {k: [] for k in ("train", "val", "benign_test", "heldout", "trained_attack_test",
                            "benign_heldout")}
    # time split point for trained-attack windows, per family
    atk = [w for w in windows if w["cls"] == l7_dataset.ATTACK and not w["held"]]
    tmax = {}
    for w in atk:
        tmax.setdefault(w["family"], []).append(w["t"])
    cut = {f: (min(ts), max(ts)) for f, ts in tmax.items()}

    for w in windows:
        if w["cls"] == l7_dataset.BENIGN and w["held"]:
            sets["benign_heldout"].append(w)
        elif w["cls"] == l7_dataset.BENIGN:
            if w["ip"] in ben_train:
                sets["train"].append(w)
            elif w["ip"] in ben_val:
                sets["val"].append(w)
            else:
                sets["benign_test"].append(w)
        elif w["held"]:
            sets["heldout"].append(w)
        else:
            lo, hi = cut[w["family"]]
            frac = (w["t"] - lo) / (hi - lo) if hi > lo else 0.0
            if frac <= attack_time_bounds[0]:
                sets["train"].append(w)
            else:
                sets["val"].append(w)
                sets["trained_attack_test"].append(w)
    return sets, {"benign_train": sorted(ben_train), "benign_val": sorted(ben_val),
                  "benign_test": sorted(ben_test),
                  "benign_heldout": sorted({w["ip"] for w in sets["benign_heldout"]})}


def fit_scaling(train_windows, n_cols):
    """Per-column mean/std over the valid (non-padding) rows of the train windows."""
    rows = []
    for w in train_windows:
        X = w["X"]
        rows.append(X[X[:, 0] > 0])
    stacked = np.concatenate(rows, axis=0) if rows else np.zeros((1, n_cols), np.float32)
    mean = stacked.mean(axis=0)
    std = stacked.std(axis=0)
    std[std == 0] = 1.0
    mean[0], std[0] = 0.0, 1.0
    return mean.astype(np.float32), std.astype(np.float32)


# ───────────────────────────── GRU ─────────────────────────────

def train_gru(train, val, cols, mean, std, *, seed, epochs, hidden, layers, batch=128, threads=None):
    """`threads` caps torch's threads (the learning curves run with 2); None keeps half the CPUs."""
    import torch
    from torch import nn, optim
    from torch.utils.data import DataLoader, TensorDataset

    from GRU_ML_model import GRUDDoSClassifier
    torch.manual_seed(seed)
    torch.set_num_threads(int(threads) if threads else max(1, (os.cpu_count() or 2) // 2))

    def prep(ws):
        X = F.apply_scaling(np.stack([w["X"] for w in ws]), mean, std)
        y = np.array([w["y"] for w in ws], dtype=np.float32)
        return torch.from_numpy(X), torch.from_numpy(y).unsqueeze(1)

    Xtr, ytr = prep(train)
    Xva, yva = prep(val)
    pos = float(ytr.sum())
    neg = float(len(ytr) - pos)
    pos_w = torch.tensor([neg / pos]) if pos > 0 else torch.tensor([1.0])
    model = GRUDDoSClassifier(input_size=len(cols), hidden_size=hidden, num_layers=layers)
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    opt = optim.Adam(model.parameters(), lr=1e-3)
    loader = DataLoader(TensorDataset(Xtr, ytr), batch_size=batch, shuffle=True)
    best_loss, best_state = math.inf, None
    for _ep in range(epochs):
        model.train()
        for xb, yb in loader:
            opt.zero_grad()
            crit(model(xb), yb).backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            vloss = float(nn.BCEWithLogitsLoss(pos_weight=pos_w)(model(Xva), yva))
        if vloss < best_loss:
            best_loss, best_state = vloss, {k: v.clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    model.eval()
    return model, best_loss


def gru_scores(model, windows, mean, std):
    import torch
    if not windows:
        return np.zeros(0, dtype=np.float32)
    X = F.apply_scaling(np.stack([w["X"] for w in windows]), mean, std)
    with torch.no_grad():
        return torch.sigmoid(model(torch.from_numpy(X))).numpy().ravel()


# ───────────────────────────── metrics ─────────────────────────────

def clopper_pearson(k, n, alpha=0.05):
    if n == 0:
        return (0.0, 1.0)
    from scipy import stats
    lo = 0.0 if k == 0 else stats.beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
    return (round(float(lo), 4), round(float(hi), 4))


def policy_detected(group_windows_sorted, scores, threshold, consecutive):
    """True if some run of `consecutive` successive windows all exceed threshold."""
    run = 0
    for p in scores:
        run = run + 1 if p > threshold else 0
        if run >= consecutive:
            return True
    return False


def per_group(windows, scores):
    """Group (window, score) by (ip, ua), each sorted by time."""
    groups = {}
    for w, p in zip(windows, scores):
        groups.setdefault((w["ip"], w["ua_h"]), []).append((w["t"], p, w))
    for g in groups.values():
        g.sort(key=lambda x: x[0])
    return groups


def eval_set(name, windows, scores, threshold, consecutive, by_family=False):
    """Window-level and group-level (policy) stats for a window set."""
    if not windows:
        return {"name": name, "n_windows": 0, "n_groups": 0}
    over = scores > threshold
    rep = {"name": name, "n_windows": len(windows),
           "window_over_rate": round(float(over.mean()), 4)}
    groups = per_group(windows, scores)
    detected = sum(policy_detected(g, [p for _, p, _ in g], threshold, consecutive)
                   for g in groups.values())
    n = len(groups)
    rep["n_groups"] = n
    rep["groups_detected"] = detected
    rep["group_detect_rate"] = round(detected / n, 4) if n else None
    rep["group_detect_ci95"] = clopper_pearson(detected, n)
    if by_family:
        fam = {}
        for g in groups.values():
            f = g[0][2]["family"]
            fam.setdefault(f, []).append(policy_detected(g, [p for _, p, _ in g],
                                                          threshold, consecutive))
        rep["by_family"] = {f: {"groups": len(v), "detected": sum(v)} for f, v in fam.items()}
    return rep


def fp_per_client_hour(benign_windows, scores, threshold):
    """False detections per benign client-hour: windows over threshold / client-hours."""
    if not benign_windows:
        return None
    groups = per_group(benign_windows, scores)
    hours = 0.0
    for g in groups.values():
        ts = [t for t, _, _ in g]
        hours += max(max(ts) - min(ts), 1.0) / 3600.0
    fp_windows = int((scores > threshold).sum())
    return {"fp_windows": fp_windows, "client_hours": round(hours, 4),
            "fp_per_client_hour": round(fp_windows / hours, 3) if hours else None}


# ───────────────────────────── baseline ─────────────────────────────

def summaries(windows, cols):
    rows = [F.window_summary(w["recs"], cols)[0] for w in windows]
    y = np.array([w["y"] for w in windows], dtype=np.int64)
    return np.array(rows, dtype=np.float64), y


def train_baseline(train, cols, seed):
    """HistGradientBoosting on window summaries (sklearn; decision 6)."""
    from sklearn.ensemble import HistGradientBoostingClassifier
    Xtr, ytr = summaries(train, cols)
    clf = HistGradientBoostingClassifier(max_iter=200, random_state=seed)
    clf.fit(Xtr, ytr)
    return clf


def baseline_scores(clf, windows, cols):
    if not windows:
        return np.zeros(0, dtype=np.float32)
    X, _ = summaries(windows, cols)
    return clf.predict_proba(X)[:, 1]


# ───────────────────────────── selection on validation (P3 §4.8) ─────────────────────────────

SELECTIONS = ("val", "p5c")


def _prereg_curve():
    import p3_prereg
    return p3_prereg.load()["learning_curve"]


def entity_flags(windows, scores, threshold, consecutive):
    """{entity: flagged?} where an entity (window "ip") is flagged when any of its keys has
    `consecutive` successive windows over `threshold` (the deployed policy)."""
    out = {}
    for (ent, _ua), g in per_group(windows, scores).items():
        hit = policy_detected(g, [p for _, p, _ in g], threshold, consecutive)
        out[ent] = out.get(ent, False) or hit
    return out


def operating_point(windows, scores, theta_grid=None, k_grid=None, budget=None):
    """The (threshold, consecutive) chosen on VALIDATION windows: among the grid points that flag
    at most floor(budget x benign entities) benign entities, the one with the highest attack-entity
    recall; ties go to fewer benign flags, a smaller k (faster), then a higher threshold. None when
    the set has no attack or no benign entity, or no point fits the budget."""
    lc = _prereg_curve()
    theta_grid = lc["theta_grid"] if theta_grid is None else theta_grid
    k_grid = lc["k_grid"] if k_grid is None else k_grid
    budget = lc["benign_budget"] if budget is None else budget
    cls = {w["ip"]: w["cls"] for w in windows}
    ben = sorted(e for e, c in cls.items() if c == l7_dataset.BENIGN)
    atk = sorted(e for e, c in cls.items() if c == l7_dataset.ATTACK)
    if not ben or not atk:
        return None
    allowed = math.floor(budget * len(ben) + 1e-9)
    best = None
    for k in k_grid:
        for thr in theta_grid:
            flags = entity_flags(windows, scores, thr, k)
            fb = sum(flags.get(e, False) for e in ben)
            if fb > allowed:
                continue
            caught = sum(flags.get(e, False) for e in atk)
            key = (caught, -fb, -k, thr)
            if best is None or key > best[0]:
                best = (key, {"threshold": float(thr), "consecutive": int(k), "val_attack_caught": caught,
                              "val_attack_entities": len(atk), "val_recall": round(caught / len(atk), 4),
                              "val_benign_flagged": fb, "val_benign_entities": len(ben),
                              "benign_allowed": allowed, "budget": budget})
    return best[1] if best else None


def select_variant(candidates, rule):
    """The chosen variant name (or None) from {name: summary}. Rule "val" reads only each summary's
    "operating_point" and "val_loss"; rule "p5c" reads "heldout_detected", "benign_fp" and
    "val_loss" (the published rule). Only probe-gated candidates are eligible."""
    eligible = [n for n, c in candidates.items() if c["probe_gate_pass"]
                and (rule == "p5c" or c.get("operating_point") is not None)]
    if not eligible:
        return None, eligible
    if rule == "val":
        def key(n):
            op = candidates[n]["operating_point"]
            return (op["val_recall"], -op["val_benign_flagged"], -candidates[n]["val_loss"])
    elif rule == "p5c":
        def key(n):
            c = candidates[n]
            fp = c["benign_fp"] or 0.0
            return (fp <= 1.0, c["heldout_detected"], -fp, -c["val_loss"])
    else:
        raise ValueError(f"unknown selection rule {rule!r}")
    return max(eligible, key=key), eligible


def multi_capture_windows(dirs, seq, cols, stride, records=None):
    """Windows of several schema-2 captures, each windowed on its own; a window's "ip" becomes its
    entity id (one address can serve different entities in different captures)."""
    out = []
    for d in dirs:
        recs = records[d] if records is not None else load_records(d)[1]
        for w in group_windows(recs, seq, cols, stride, DEFAULT_MIN_EVENTS):
            w["ip"] = w["recs"][0]["_entity"]
            out.append(w)
    return out


# ───────────────────────────── orchestration ─────────────────────────────

def evaluate_model(score_fn, sets, threshold, consecutive):
    """Run the policy metrics over every evaluation set with a p = score_fn(windows)."""
    out = {}
    for name in ("benign_test", "heldout", "trained_attack_test"):
        ws = sets[name]
        p = score_fn(ws)
        out[name] = eval_set(name, ws, p, threshold, consecutive,
                             by_family=(name in ("heldout", "trained_attack_test")))
    bt = sets["benign_test"]
    out["benign_fp"] = fp_per_client_hour(bt, score_fn(bt), threshold)
    bh = sets.get("benign_heldout") or []
    if bh:                                   # reported, never used for selection
        p = score_fn(bh)
        out["benign_heldout"] = eval_set("benign_heldout", bh, p, threshold, consecutive)
        out["benign_heldout_fp"] = fp_per_client_hour(bh, p, threshold)
    return out


VARIANTS = ("default", "no_size", "no_uri", "no_server_timing", "no_size_no_server_timing")


def variant_groups():
    """Feature-group selection per variant (server_timing: R17, §7.3.2.1)."""
    def without(*drop):
        return tuple(g for g in F.DEFAULT_GROUPS if g not in drop)
    return {"default": F.DEFAULT_GROUPS, "no_size": without("size"), "no_uri": without("uri"),
            "no_server_timing": without("server_timing"),
            "no_size_no_server_timing": without("size", "server_timing")}


def memory_scorer(model, cols, seq, mean, std, threshold, consecutive):
    """An L7Scorer over an in-memory model, for probing a variant before any is saved."""
    import l7_scorer
    model.eval()
    cfg = {"columns": list(cols), "seq_len": int(seq), "mean": [float(x) for x in mean],
           "std": [float(x) for x in std], "threshold": float(threshold),
           "consecutive": int(consecutive)}
    return l7_scorer.L7Scorer(model, cfg)


def run(dataset_dir, out_dir, *, seed=0, epochs=25, hidden=64, layers=2,
        seq=DEFAULT_SEQ, stride=DEFAULT_STRIDE, threshold=THRESHOLD, consecutive=CONSECUTIVE,
        variants=VARIANTS, do_baseline=True, selection="val", val_dirs=None):
    """Train every variant, probe-gate it, select one, save its package. `dataset_dir` is one
    dataset, or with `val_dirs` (P3) a list of training captures. selection="val" (default)
    decides on validation only; "p5c" is the published rule (see the module docstring)."""
    import l7_scorer
    if selection not in SELECTIONS:
        raise ValueError(f"selection must be one of {SELECTIONS}")
    train_dirs = [dataset_dir] if isinstance(dataset_dir, str) else list(dataset_dir)
    if val_dirs:
        import l7_disjoint
        if selection != "val":
            raise ValueError("P3 captures (--val) select on validation only")
        l7_disjoint.require({"train": train_dirs, "val": list(val_dirs), "eval": []})
        loaded = {d: load_records(d) for d in list(train_dirs) + list(val_dirs)}
        manifest = loaded[train_dirs[0]][0]
        recs = [r for d in train_dirs for r in loaded[d][1]]
    elif len(train_dirs) != 1:
        raise ValueError("several training captures need their validation captures (--val)")
    else:
        manifest, recs = load_records(train_dirs[0])

    GROUPS = variant_groups()
    report = {"dataset": os.path.abspath(train_dirs[0]) if len(train_dirs) == 1
              else [os.path.abspath(d) for d in train_dirs],
              "dataset_manifest_sha_families": l7_dataset.families(manifest),
              "held_out_families": l7_dataset.families(manifest, held_out=True),
              "seed": seed, "epochs": epochs, "seq": seq, "stride": stride,
              "threshold": threshold, "consecutive": consecutive, "variants": {}}
    if selection == "val":
        report["selection_rule"] = "val"
    if val_dirs:
        report["val_datasets"] = [os.path.abspath(d) for d in val_dirs]

    FP_BUDGET = 1.0        # benign false detections per client-hour a variant may have (p5c rule)
    trained = {}
    baselines = {}
    val_recs = {}
    for variant in variants:
        cols = F.columns(GROUPS[variant])
        if val_dirs:
            recmap = {d: loaded[d][1] for d in loaded}
            empty = {k: [] for k in ("benign_test", "heldout", "trained_attack_test", "benign_heldout")}
            sets = {"train": multi_capture_windows(train_dirs, seq, cols, stride, recmap),
                    "val": multi_capture_windows(val_dirs, seq, cols, stride, recmap), **empty}
            ip_split = {"train_captures": [os.path.basename(os.path.normpath(d)) for d in train_dirs],
                        "val_captures": [os.path.basename(os.path.normpath(d)) for d in val_dirs]}
        else:
            windows = group_windows(recs, seq, cols, stride, DEFAULT_MIN_EVENTS)
            sets, ip_split = split(windows, seed)
        mean, std = fit_scaling(sets["train"], len(cols))
        model, vloss = train_gru(sets["train"], sets["val"], cols, mean, std,
                                 seed=seed, epochs=epochs, hidden=hidden, layers=layers)

        def gfn(ws, _m=model, _me=mean, _sd=std):
            return gru_scores(_m, ws, _me, _sd)

        op = None
        if selection == "val":
            op = operating_point(sets["val"], gfn(sets["val"]))
        thr_v, k_v = (op["threshold"], op["consecutive"]) if op else (threshold, consecutive)
        gru_eval = evaluate_model(gfn, sets, thr_v, k_v)
        v = {"columns": cols, "val_loss": round(vloss, 5), "ip_split": ip_split,
             "counts": {k: len(s) for k, s in sets.items()}, "gru": gru_eval}
        if selection == "val":
            v["operating_point"] = op
        if do_baseline:
            clf = train_baseline(sets["train"], cols, seed)

            def bfn(ws, _c=clf, _cols=cols):
                return baseline_scores(_c, ws, _cols)
            v["baseline_hgb"] = evaluate_model(bfn, sets, thr_v, k_v)
            baselines[variant] = (clf, cols)
        report["variants"][variant] = v
        trained[variant] = (model, cols, mean, std)
        if selection == "val" and not val_recs:
            seen = {}
            for w in sets["val"]:
                for r in w["recs"]:
                    seen[id(r)] = r
            val_recs = sorted(seen.values(), key=F.start_time)

    # Hard probe gate on EVERY variant (§7.3.2.1): the exact transforms + server_load (R17).
    # Only passing variants are eligible. Rule "val" probes validation records at each
    # variant's own operating point; rule "p5c" probes every record at the fixed policy.
    probe_recs = val_recs if selection == "val" else recs
    probe_windows = l7_probes.windows_from_items(
        [("record", _obj_for(r)) for r in probe_recs], seq, stride=stride)[:2000]
    for name, (model, cols, mean, std) in trained.items():
        op = report["variants"][name].get("operating_point")
        sc = memory_scorer(model, cols, seq, mean, std, op["threshold"] if op else threshold,
                           op["consecutive"] if op else consecutive)
        probes = l7_probes.run_probes(sc, probe_windows, seed=seed)
        report["variants"][name]["probes"] = probes
        report["variants"][name]["probe_gate_pass"] = l7_probes.gate_pass(probes)

    def summary(name):
        v = report["variants"][name]
        ho = v["gru"]["heldout"].get("by_family", {})
        return {"probe_gate_pass": v["probe_gate_pass"], "val_loss": v["val_loss"],
                "operating_point": v.get("operating_point"),
                "heldout_detected": sum(f["detected"] for f in ho.values()),
                "benign_fp": (v["gru"]["benign_fp"] or {}).get("fp_per_client_hour")}
    candidates = {n: summary(n) for n in report["variants"]}
    if selection == "val":
        for c in candidates.values():                  # what rule "val" may read, and nothing else
            c.pop("heldout_detected")
            c.pop("benign_fp")
        rule = ("probe gate first (exact + server_load, validation records); then each variant's "
                "operating point on validation (max attack-entity recall with <= 1 % of benign "
                "entities flagged); then max validation recall, tie-break fewer benign flags, lower "
                "val loss. Test sets are reported at the frozen point, never used")
    else:
        rule = (f"probe gate first (exact + server_load); then max held-out groups detected s.t. "
                f"benign FP/client-hour <= {FP_BUDGET}; tie-break lower FP then lower val loss")
    chosen, eligible = select_variant(candidates, selection)
    os.makedirs(out_dir, exist_ok=True)
    if chosen is None:
        report["selection"] = {"rule": rule, "chosen": None, "eligible": eligible,
                               "caveat": "no variant passed the probe gate: no candidate"}
        if selection == "val":
            report["selection"]["uses"] = ["val"]
            report["selection"]["caveat"] = ("no variant passed the probe gate with an operating point "
                                             "within the benign budget on validation: no candidate")
        report["probe_gate_pass"] = False
        return report, None
    report["selection"] = {"rule": rule, "chosen": chosen, "eligible": eligible,
                           "caveat": "one capture, one seed; confirm on another seed/capture "
                                     "before promotion (P6)"}
    if selection == "val":
        op = report["variants"][chosen]["operating_point"]
        threshold, consecutive = op["threshold"], op["consecutive"]
        report["threshold"], report["consecutive"] = threshold, consecutive
        report["selection"]["uses"] = ["val"]
        report["selection"]["operating_point"] = op

    model, cols, mean, std = trained[chosen]
    l7_scorer.save_package(
        out_dir, model, cols, seq, mean, std, threshold, consecutive,
        hidden_size=hidden, num_layers=layers,
        meta={"dataset": report["dataset"], "seed": seed, "epochs": epochs,
              "variant": chosen, "feature_groups": [g for g in GROUPS[chosen]],
              "trained_families": l7_dataset.families(manifest, False),
              "held_out_families": l7_dataset.families(manifest, True),
              "note": "L7 GRU. Validate online before any promotion (P6)."})
    best = (out_dir, cols, seq)
    if chosen in baselines:
        report["baseline_saved"] = save_baseline(out_dir, *baselines[chosen], seq=seq,
                                                 threshold=threshold, consecutive=consecutive,
                                                 variant=chosen, seed=seed)

    # Confirm on the SAVED package: the same probes must give the same verdict.
    scorer = l7_scorer.L7Scorer.load(out_dir)
    report["probes"] = l7_probes.run_probes(scorer, probe_windows, seed=seed)
    report["probe_gate_pass"] = l7_probes.gate_pass(report["probes"])
    if val_dirs:
        import l7_disjoint
        split_sha = l7_disjoint.write_split(os.path.join(out_dir, "split.json"),
                                            {"train": train_dirs, "val": list(val_dirs), "eval": []})
        sel = {"format": "p3-selection/1", "variant": chosen, "threshold": threshold,
               "consecutive": consecutive, "split_sha256": split_sha,
               "package_config_sha256": l7_scorer_sha(out_dir)}
        with open(os.path.join(out_dir, "selection.json"), "w", encoding="utf-8") as fh:
            json.dump(sel, fh, indent=1, sort_keys=True)
            fh.write("\n")
        report["selection"]["file"] = sel
    return report, best


def l7_scorer_sha(pkg_dir):
    import hashlib
    with open(os.path.join(pkg_dir, "config.json"), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


BASELINE_PKL = "baseline_hgb.pkl"
BASELINE_META = "baseline_hgb.json"


def save_baseline(out_dir, clf, cols, *, seq, threshold, consecutive, variant, seed):
    """Save the chosen variant's HGB baseline for online replay (P5b baseline B4): the
    pickle plus a sidecar with its columns, policy and the pickle's SHA-256, which
    load_baseline() verifies before unpickling (only ever load our own artifact)."""
    import hashlib
    import pickle

    import sklearn
    path = os.path.join(out_dir, BASELINE_PKL)
    with open(path, "wb") as fh:
        pickle.dump(clf, fh)
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    meta = {"format": "l7-hgb-baseline/1", "columns": list(cols), "seq_len": int(seq),
            "threshold": float(threshold), "consecutive": int(consecutive),
            "variant": variant, "seed": seed, "sklearn": sklearn.__version__,
            "sha256": digest}
    with open(os.path.join(out_dir, BASELINE_META), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=1)
        fh.write("\n")
    return meta


def load_baseline(pkg_dir):
    """(clf, meta) for a saved baseline; raises ValueError if the pickle's hash differs."""
    import hashlib
    import pickle
    with open(os.path.join(pkg_dir, BASELINE_META), encoding="utf-8") as fh:
        meta = json.load(fh)
    with open(os.path.join(pkg_dir, BASELINE_PKL), "rb") as fh:
        blob = fh.read()
    if hashlib.sha256(blob).hexdigest() != meta.get("sha256"):
        raise ValueError(f"baseline pickle in {pkg_dir} does not match its recorded SHA-256")
    return pickle.loads(blob), meta          # our own artifact, hash-verified above


def _obj_for(rec):
    """Rebuild a minimal log object from a normalised record for the probe windower
    (it re-normalises). ua_h/uri_h are already hashes; pass them as the raw fields so
    stable_hash32 maps them 1:1-consistently (only equality matters)."""
    return {"ip": rec["ip"], "ua": str(rec["ua_h"]), "uri": str(rec["uri_h"]),
            "msec": rec["msec"], "rt": rec["rt"], "status": int(rec["status"]),
            "method": rec.get("method", "GET"), "rlen": rec["rlen"], "bsent": rec["bsent"],
            "creq": rec.get("creq", 1), "compl": rec.get("compl", "OK"),
            "urt": rec.get("urt", 0.0), "lreq": rec.get("lreq", ""),
            "proto": rec.get("proto", ""), "tls": rec.get("tls", ""),
            "reused": rec.get("reused", "")}


def _variant_table(report):
    rows = ["## Variant comparison — probe gate, held-out detection, benign FP", "",
            ("| variant | probe gate (server_load flips) | held-out groups detected | "
             "benign FP/client-hr | GRU vs baseline (held-out) |"),
            "|---|---|---|---|---|"]
    for name, v in report["variants"].items():
        ho = v["gru"]["heldout"].get("by_family", {})
        det = f"{sum(f['detected'] for f in ho.values())}/{sum(f['groups'] for f in ho.values())}"
        fp = (v["gru"]["benign_fp"] or {}).get("fp_per_client_hour")
        bho = v.get("baseline_hgb", {}).get("heldout", {}).get("by_family", {})
        bdet = (f"{sum(f['detected'] for f in bho.values())}/"
                f"{sum(f['groups'] for f in bho.values())}") if bho else "n/a"
        load = (v.get("probes") or {}).get("server_load", {}).get("flip_rate")
        gate = "PASS" if v.get("probe_gate_pass") else "FAIL"
        rows.append(f"| {name} | {gate} ({load}) | {det} | {fp} | GRU {det} vs HGB {bdet} |")
    return rows


def write_card(out_dir, report):
    card = os.path.join(out_dir, "model_card.md")
    chosen = report["selection"]["chosen"]
    head = [f"# L7 GRU model card ({time.strftime('%Y-%m-%d', time.gmtime())})", "",
            f"Dataset: `{report['dataset']}`  seed={report['seed']} epochs={report['epochs']}",
            f"Held-out (never trained) families: {report['held_out_families']}",
            f"Policy: p > {report['threshold']} in {report['consecutive']} consecutive windows.",
            f"Selection: {report['selection']['rule']}.", ""]
    if chosen is None:
        lines = [*head, "## No candidate", "",
                 f"{report['selection']['caveat']}.", "", *_variant_table(report)]
    else:
        g = report["variants"][chosen]["gru"]
        heldout_benign = (
            (f"- held-out benign kind (never trained, not used for selection): "
             f"{g['benign_heldout'].get('n_groups', 0)} groups, "
             f"{g['benign_heldout'].get('groups_detected')} flagged; FP/client-hour "
             f"{g.get('benign_heldout_fp')}") if g.get("benign_heldout") else
            "- held-out benign kind: none in this dataset")
        lines = [*head, f"## Saved model — variant `{chosen}`",
                 f"Eligible after the probe gate: {report['selection']['eligible']}.",
                 f"Caveat: {report['selection']['caveat']}.", "",
                 (f"- benign test: {g['benign_test'].get('n_groups', 0)} groups, "
                  f"group false-detect rate {g['benign_test'].get('group_detect_rate')} "
                  f"CI {g['benign_test'].get('group_detect_ci95')}"),
                 f"- benign FP/client-hour: {g['benign_fp']}",
                 heldout_benign,
                 f"- held-out families (policy, per group): {g['heldout'].get('by_family')}",
                 f"- in-distribution trained families: {g['trained_attack_test'].get('by_family')}",
                 (f"- probe gate on the saved package (exact + server_load): "
                  f"{report.get('probe_gate_pass')}"), "", *_variant_table(report)]
    with open(card, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return card


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dataset_dir", nargs="+", help="one dataset, or (with --val) the training captures")
    ap.add_argument("--val", nargs="+", default=None, metavar="VAL_DIR",
                    help="P3: the validation captures (schema 2); the disjointness check runs first")
    ap.add_argument("--selection", choices=SELECTIONS, default="val",
                    help="val (default): variant and operating point on validation only; p5c: the "
                         "published held-out/benign_test rule, to reproduce P4/P5c")
    ap.add_argument("--out", required=True, help="model package output dir")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--report", help="write the full metrics report JSON here")
    ap.add_argument("--no-baseline", action="store_true")
    ap.add_argument("--variants", nargs="+", choices=VARIANTS, default=list(VARIANTS),
                    metavar="VARIANT",
                    help=f"feature variants to train and select among (default: all of {VARIANTS})")
    args = ap.parse_args()

    if len(args.dataset_dir) > 1 and not args.val:
        ap.error("several training captures need --val")
    report, _best = run(args.dataset_dir[0] if len(args.dataset_dir) == 1 else args.dataset_dir,
                        args.out, seed=args.seed, epochs=args.epochs,
                        hidden=args.hidden, layers=args.layers, do_baseline=not args.no_baseline,
                        variants=tuple(args.variants), selection=args.selection, val_dirs=args.val)
    card = write_card(args.out, report)
    report_path = args.report or os.path.join(args.out, "metrics.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, default=str)
        fh.write("\n")
    print(f"[+] model package: {args.out if report['selection']['chosen'] else '(none: no eligible variant)'}")
    print(f"[+] model card:    {card}")
    print(f"[+] metrics:       {report_path}")
    print(f"[{'+' if report.get('probe_gate_pass') else '!'}] probe gate (exact + server_load): "
          f"{'PASS' if report.get('probe_gate_pass') else 'FAIL'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
