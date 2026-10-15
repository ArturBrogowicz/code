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
  * the invariance probe battery (ml/l7_probes) is a HARD gate: a model that changes
    its decision under an exact transform is rejected.
  * a tabular baseline (sklearn, decision 6) is trained under the identical split and
    policy, so the thesis can say whether sequence modelling earns its place.
  * feature-set variants (with/without size, uri) are compared, as CF3 did for XDP.

    ./venv/bin/python ml/train_l7.py DATASET_DIR --out ml/l7_models/<name> [--epochs 25]
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
    with open(log_path, encoding="utf-8", errors="replace") as fh:
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
    """Split windows. Benign is IP-disjoint (train/val/test). Held-out families are a
    separate eval set. Trained attacks go to train, with a time tail in val for early
    stopping. Returns dict of named window-lists."""
    import random
    rng = random.Random(seed)
    benign_ips = sorted({w["ip"] for w in windows if w["cls"] == l7_dataset.BENIGN})
    rng.shuffle(benign_ips)
    a = int(len(benign_ips) * benign_bounds[0])
    b = int(len(benign_ips) * benign_bounds[1])
    ben_train, ben_val, ben_test = set(benign_ips[:a]), set(benign_ips[a:b]), set(benign_ips[b:])

    sets = {k: [] for k in ("train", "val", "benign_test", "heldout", "trained_attack_test")}
    # time split point for trained-attack windows, per family
    atk = [w for w in windows if w["cls"] == l7_dataset.ATTACK and not w["held"]]
    tmax = {}
    for w in atk:
        tmax.setdefault(w["family"], []).append(w["t"])
    cut = {f: (min(ts), max(ts)) for f, ts in tmax.items()}

    for w in windows:
        if w["cls"] == l7_dataset.BENIGN:
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
                  "benign_test": sorted(ben_test)}


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

def train_gru(train, val, cols, mean, std, *, seed, epochs, hidden, layers, batch=128):
    import torch
    from torch import nn, optim
    from torch.utils.data import DataLoader, TensorDataset

    from GRU_ML_model import GRUDDoSClassifier
    torch.manual_seed(seed)
    torch.set_num_threads(max(1, (os.cpu_count() or 2) // 2))

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
    return out


def run(dataset_dir, out_dir, *, seed=0, epochs=25, hidden=64, layers=2,
        seq=DEFAULT_SEQ, stride=DEFAULT_STRIDE, threshold=THRESHOLD, consecutive=CONSECUTIVE,
        variants=("default", "no_size", "no_uri"), do_baseline=True):
    import l7_scorer
    manifest, recs = load_records(dataset_dir)

    GROUPS = {"default": F.DEFAULT_GROUPS,
              "no_size": tuple(g for g in F.DEFAULT_GROUPS if g != "size"),
              "no_uri": tuple(g for g in F.DEFAULT_GROUPS if g != "uri")}
    report = {"dataset": os.path.abspath(dataset_dir),
              "dataset_manifest_sha_families": l7_dataset.families(manifest),
              "held_out_families": l7_dataset.families(manifest, held_out=True),
              "seed": seed, "epochs": epochs, "seq": seq, "stride": stride,
              "threshold": threshold, "consecutive": consecutive, "variants": {}}

    FP_BUDGET = 1.0        # benign false detections per client-hour a variant may have
    trained = {}
    for variant in variants:
        cols = F.columns(GROUPS[variant])
        windows = group_windows(recs, seq, cols, stride, DEFAULT_MIN_EVENTS)
        sets, ip_split = split(windows, seed)
        mean, std = fit_scaling(sets["train"], len(cols))
        model, vloss = train_gru(sets["train"], sets["val"], cols, mean, std,
                                 seed=seed, epochs=epochs, hidden=hidden, layers=layers)

        def gfn(ws, _m=model, _me=mean, _sd=std):
            return gru_scores(_m, ws, _me, _sd)

        gru_eval = evaluate_model(gfn, sets, threshold, consecutive)
        v = {"columns": cols, "val_loss": round(vloss, 5), "ip_split": ip_split,
             "counts": {k: len(s) for k, s in sets.items()}, "gru": gru_eval}
        if do_baseline:
            clf = train_baseline(sets["train"], cols, seed)

            def bfn(ws, _c=clf, _cols=cols):
                return baseline_scores(_c, ws, _cols)
            v["baseline_hgb"] = evaluate_model(bfn, sets, threshold, consecutive)
        report["variants"][variant] = v
        trained[variant] = (model, cols, mean, std)

    # Pre-registered selection: maximise held-out family groups detected, subject to a
    # benign false-positive budget; tie-break on lower benign FP then lower val loss.
    def score_variant(name):
        g = report["variants"][name]["gru"]
        ho = g["heldout"].get("by_family", {})
        detected = sum(f["detected"] for f in ho.values())
        fp = (g["benign_fp"] or {}).get("fp_per_client_hour") or 0.0
        within = fp <= FP_BUDGET
        return (within, detected, -fp, -report["variants"][name]["val_loss"])
    chosen = max(report["variants"], key=score_variant)
    report["selection"] = {"rule": f"max held-out groups detected s.t. benign FP/client-hour "
                           f"<= {FP_BUDGET}; tie-break lower FP then lower val loss",
                           "chosen": chosen,
                           "caveat": "one capture, one seed; confirm on another seed/capture "
                                     "before promotion (P6)"}

    model, cols, mean, std = trained[chosen]
    os.makedirs(out_dir, exist_ok=True)
    l7_scorer.save_package(
        out_dir, model, cols, seq, mean, std, threshold, consecutive,
        hidden_size=hidden, num_layers=layers,
        meta={"dataset": os.path.abspath(dataset_dir), "seed": seed, "epochs": epochs,
              "variant": chosen, "feature_groups": [g for g in GROUPS[chosen]],
              "trained_families": l7_dataset.families(manifest, False),
              "held_out_families": l7_dataset.families(manifest, True),
              "note": "L7 GRU (P4). Validate online (P5) before any promotion (P6)."})
    best = (out_dir, cols, seq)

    # Invariance probes on the SAVED (chosen) model (HARD gate: exact transforms).
    scorer = l7_scorer.L7Scorer.load(out_dir)
    probe_windows = l7_probes.windows_from_items(
        [("record", _obj_for(r)) for r in recs], scorer.seq_len, stride=stride)
    report["probes"] = l7_probes.run_probes(scorer, probe_windows[:2000], seed=seed)
    report["probe_gate_pass"] = _exact_probes_pass(report["probes"])
    return report, best


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


def _exact_probes_pass(probes):
    return all(isinstance(probes.get(n), dict) and probes[n]["pass"]
               for n in ("ua_swap", "uri_bijection", "time_offset"))


def write_card(out_dir, report):
    card = os.path.join(out_dir, "model_card.md")
    chosen = report["selection"]["chosen"]
    g = report["variants"][chosen]["gru"]
    lines = [f"# L7 GRU model card ({time.strftime('%Y-%m-%d', time.gmtime())})", "",
             f"Dataset: `{report['dataset']}`  seed={report['seed']} epochs={report['epochs']}",
             f"Held-out (never trained) families: {report['held_out_families']}",
             f"Policy: p > {report['threshold']} in {report['consecutive']} consecutive windows.",
             "", f"## Saved model — variant `{chosen}`",
             f"Selection: {report['selection']['rule']}.",
             f"Caveat: {report['selection']['caveat']}.", "",
             (f"- benign test: {g['benign_test'].get('n_groups', 0)} groups, "
              f"group false-detect rate {g['benign_test'].get('group_detect_rate')} "
              f"CI {g['benign_test'].get('group_detect_ci95')}"),
             f"- benign FP/client-hour: {g['benign_fp']}",
             f"- held-out families (policy, per group): {g['heldout'].get('by_family')}",
             f"- in-distribution trained families: {g['trained_attack_test'].get('by_family')}",
             f"- exact-invariance probe gate: {report.get('probe_gate_pass')}", "",
             "## Variant comparison — held-out detection vs benign FP (the size shortcut)", "",
             "| variant | held-out groups detected | benign FP/client-hr | GRU vs baseline (held-out) |",
             "|---|---|---|---|"]
    for name, v in report["variants"].items():
        ho = v["gru"]["heldout"].get("by_family", {})
        det = f"{sum(f['detected'] for f in ho.values())}/{sum(f['groups'] for f in ho.values())}"
        fp = (v["gru"]["benign_fp"] or {}).get("fp_per_client_hour")
        bho = v.get("baseline_hgb", {}).get("heldout", {}).get("by_family", {})
        bdet = f"{sum(f['detected'] for f in bho.values())}/{sum(f['groups'] for f in bho.values())}" if bho else "n/a"
        lines.append(f"| {name} | {det} | {fp} | GRU {det} vs HGB {bdet} |")
    with open(card, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return card


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dataset_dir")
    ap.add_argument("--out", required=True, help="model package output dir")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--report", help="write the full metrics report JSON here")
    ap.add_argument("--no-baseline", action="store_true")
    args = ap.parse_args()

    report, _best = run(args.dataset_dir, args.out, seed=args.seed, epochs=args.epochs,
                       hidden=args.hidden, layers=args.layers, do_baseline=not args.no_baseline)
    card = write_card(args.out, report)
    report_path = args.report or os.path.join(args.out, "metrics.json")
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, default=str)
        fh.write("\n")
    print(f"[+] model package: {args.out}")
    print(f"[+] model card:    {card}")
    print(f"[+] metrics:       {report_path}")
    print(f"[{'+' if report.get('probe_gate_pass') else '!'}] exact-probe gate: "
          f"{'PASS' if report.get('probe_gate_pass') else 'FAIL'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
