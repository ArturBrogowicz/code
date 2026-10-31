#!/usr/bin/env python3
"""Train and select the L7 v2 arms on validation only (docs/L7V2_DESIGN.md 8, 10, 13; docs/P3_DATASET_DESIGN.md 4.8, 6).
Offline, CPU, at most 2 threads. Every constant comes from ml/l7v2_model_prereg.json, frozen before any capture.

Two steps, so that evaluation is scored only with a selection frozen before (P3's select/score split):

    # select: fits on the training captures, the probe gate and every arm's operating point on the validation
    # captures; writes the artifacts, selection.json and selection.sha256 (and split.json for P3 captures, after the
    # disjointness checker passed). No evaluation log is opened.
    ./venv/bin/python ml/train_l7v2.py select --train T1 T2 T3 T4 --val V1 V2 --out SEL
    # score: refuses unless --selection-sha256 is the recorded hash of SEL/selection.json and every artifact still
    # matches; for P3 captures the checker runs again with rule 10 (split file vs selection) first.
    ./venv/bin/python ml/train_l7v2.py score --train ... --val ... --eval E1 ... --selection SEL/selection.json \
        --selection-sha256 <hash> --out OUT
    # one legacy (schema-1) capture, entity-disjoint benign split, held-out families as validation: mechanics only
    ./venv/bin/python ml/train_l7v2.py select --legacy-capture results/2026-10-16_l7-p5c3-capture --out SEL --smoke

The arms, on identical keys (l7_ingest.key_v2) and, for the view-level arms, identical view windows:
  view_gru      the two-level model (l7_view_model.ViewGRU) over the last max_views complete view tokens
  hgb, lr       HistGradientBoosting and a standardised, class-balanced logistic regression on the token summaries
  request_gru   the per-request GRU over the last 64 requests (V2_REQUEST_GROUPS): the offline ablation
  gru_shuffled  the fitted view GRU scoring windows whose tokens are shuffled; it takes the view GRU's (theta, k)

Selection (design 10): an arm passes the v2 probe gate (l7_probes.GATE_PROBES_V2, on validation records) or gets no
operating point. Its (theta, k) is the grid point with the highest attack-entity recall over the validation captures
among those flagging at most floor(budget x benign units) benign units (l7_dataset.user_units; a flagged key costs one
unit of its entity, at most the entity's units); ties go to fewer benign units flagged, then the lower median time to
decision, then grid order (k_grid, then theta_grid). Recall's denominator is every attack entity with a labelled
request in the validation captures, the same for every arm, so an arm cannot gain by scoring fewer entities.
"""
import argparse
import hashlib
import json
import math
import os
import pickle
import sys
import time

for _var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS"):
    os.environ.setdefault(_var, "2")

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import l7_probes
import l7v2_model_prereg as PRE
import train_l7 as T

import l7_dataset as D
import l7_features as F
import l7_ingest as I

SEL_FORMAT = "l7v2-selection/1"
RESULT_FORMAT = "l7v2-eval/1"
VIEW_ARMS = ("view_gru", "hgb", "lr")
MAX_TRAIN_WIN_PER_KEY = 400          # training windows per key (evenly thinned); validation and evaluation keep all


class SelectionError(RuntimeError):
    """The frozen selection is missing, altered, or does not match the data it would be scored on."""


# ───────────────────────────── data ─────────────────────────────

def load_capture(d, capture=None):
    """(manifest, records, capture id): train_l7.load_records (labels per record, schema 3 by time), plus each
    record's arrival index (file order) and its capture-qualified entity."""
    m, recs = T.load_records(d)
    cap = capture or m.get("capture_id") or os.path.basename(os.path.normpath(d))
    for i, r in enumerate(recs):
        r["_seq"] = i
        r["_cap"] = cap
        r["_ent"] = f"{cap}|{r['_entity']}"
    return m, recs, cap


def benign_units(manifest, recs, cap):
    """{capture|entity: units} of the benign entities: l7_dataset.user_units for P3 manifests (a pool counts by its
    users); for a legacy capture, one unit per benign entity with a request."""
    if manifest.get("format") in D.FORMATS_P3:
        out = {}
        for _unit, ent, role in D.user_units(manifest):
            if role != "attack":
                out[f"{cap}|{ent}"] = out.get(f"{cap}|{ent}", 0) + 1
        return out
    return {r["_ent"]: 1 for r in recs if r["_cls"] == D.BENIGN}


def sessions(seq, idle_s):
    """Split a key's start-ordered records where the gap between two starts exceeds idle_s (the engine evicts such
    a key; ml/l7v2_model_prereg.json ingest.idle_timeout_s)."""
    out, cur, last = [], [], None
    for r in seq:
        s = F.start_time(r)
        if cur and s - last > idle_s:
            out.append(cur)
            cur = []
        cur.append(r)
        last = s
    if cur:
        out.append(cur)
    return out


def _by_key(recs):
    groups = {}
    for r in sorted(recs, key=lambda r: r["_seq"]):
        groups.setdefault(I.key_v2(r), []).append(r)
    return groups


def _window(seq, r_last, X, t, n, key):
    r0 = seq[0]
    return {"X": X, "y": 1 if r0["_cls"] == D.ATTACK else 0, "ip": r0["_ent"], "key": key, "t": t, "n": n,
            "cls": r0["_cls"], "family": r0["_family"], "held": r0["_held"], "kof": r0.get("_kof"),
            "capture": r0["_cap"], "recs": seq}


def view_windows(recs, max_views=F.MAX_VIEWS, min_views=F.MIN_VIEWS, idle_s=None):
    """One window per completed token of each (IP, UA, sid) key and session, once the key has >= min_views complete
    tokens: the last max_views complete tokens plus the request that completed the last one (its opener), encoded with
    l7_features.token_matrix. t is that request's completion (msec): when the engine could score the window."""
    idle_s = PRE.load()["ingest"]["idle_timeout_s"] if idle_s is None else idle_s
    out = []
    for key, seq in _by_key(recs).items():
        for sess in sessions(F.ordered(seq), idle_s):
            opens = F.token_starts(sess)
            for j in range(min_views, len(opens)):
                window = sess[opens[max(0, j - max_views)]:opens[j] + 1]
                out.append(_window(window, sess[opens[j]], F.token_matrix(window, max_views),
                                   sess[opens[j]]["msec"], min(j, max_views), key))
    return out


def request_windows(recs, cols, seq_len, stride, min_events, idle_s=None):
    """The per-request ablation's windows per (IP, UA, sid) key and session, in arrival order: every `stride`-th
    request once the key has >= min_events, the last seq_len requests (l7_features.window_matrix)."""
    idle_s = PRE.load()["ingest"]["idle_timeout_s"] if idle_s is None else idle_s
    out = []
    for key, seq in _by_key(recs).items():
        for sess in sessions(seq, idle_s):
            for n, end in enumerate(range(min_events - 1, len(sess))):
                if n % stride:
                    continue
                window = sess[max(0, end - seq_len + 1):end + 1]
                out.append(_window(window, window[-1], F.window_matrix(window, seq_len, cols), window[-1]["msec"],
                                   len(window), key))
    return out


def thin(windows, cap=MAX_TRAIN_WIN_PER_KEY):
    """Training windows thinned evenly to at most `cap` per key (as train_l7's MAX_WIN_PER_GROUP)."""
    groups = {}
    for w in windows:
        groups.setdefault((w["capture"], w["key"]), []).append(w)
    out = []
    for ws in groups.values():
        if len(ws) > cap:
            ws = [ws[i] for i in np.linspace(0, len(ws) - 1, cap).astype(int)]
        out += ws
    return out


class Split:
    """One split's windows (view and request level) and its common denominators: the attack entities with a labelled
    request, the benign units, and every entity's first request start."""

    def __init__(self, loaded, view=True, request=True):
        pre = PRE.load()
        rl = pre["request_level"]
        self.cols_req = F.columns(tuple(rl["groups"]))
        self.view, self.req, self.attack, self.units, self.first, self.kind = [], [], set(), {}, {}, {}
        for m, recs, cap in loaded:
            if view:
                self.view += view_windows(recs, pre["views"]["max_views"], pre["views"]["min_views"])
            if request:
                self.req += request_windows(recs, self.cols_req, rl["seq_len"], rl["stride"], rl["min_events"])
            self.units.update(benign_units(m, recs, cap))
            for r in recs:
                e = r["_ent"]
                if r["_cls"] == D.ATTACK:
                    self.attack.add(e)
                s = F.start_time(r)
                self.first[e] = min(self.first.get(e, math.inf), s)
                self.kind.setdefault(e, r.get("_kof") or r.get("_family"))


def legacy_split(dataset_dir, seed=0):
    """One schema-1 capture as train and validation (mechanics only, never a claim): benign entities split
    entity-disjoint (two thirds train, seeded); trained attack families train; held-out families validation."""
    import random
    m, recs, cap = load_capture(dataset_dir, capture="legacy")
    ben = sorted({r["_ent"] for r in recs if r["_cls"] == D.BENIGN and not r["_held"]})
    random.Random(seed).shuffle(ben)
    val_ben = set(ben[int(len(ben) * 2 / 3):])
    train, val = [], []
    for r in recs:
        if r["_cls"] == D.BENIGN:
            if not r["_held"]:                      # a held-out benign kind is never fitted or tuned on
                (val if r["_ent"] in val_ben else train).append(r)
        else:
            (val if r["_held"] else train).append(r)
    return [(m, train, cap)], [(m, val, cap)]


# ───────────────────────────── models ─────────────────────────────

def _stack(windows):
    return np.stack([w["X"] for w in windows]) if windows else np.zeros((0, 1, 1), np.float32)


def fit_torch(model, train, val, mean, std, *, seed, epochs, lr, batch, threads):
    """Adam on BCE-with-logits (pos_weight = negatives / positives of the training windows); the epoch with the lowest
    validation loss is kept. Returns (model, best validation loss)."""
    import torch
    from torch import nn, optim
    from torch.utils.data import DataLoader, TensorDataset
    torch.manual_seed(seed)
    torch.set_num_threads(int(threads))
    Xtr = torch.from_numpy(F.apply_scaling(_stack(train), mean, std))
    ytr = torch.tensor([[float(w["y"])] for w in train])
    Xva = torch.from_numpy(F.apply_scaling(_stack(val), mean, std))
    yva = torch.tensor([[float(w["y"])] for w in val])
    pos = float(ytr.sum())
    pos_w = torch.tensor([(len(train) - pos) / pos]) if pos > 0 else torch.tensor([1.0])
    crit = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    opt = optim.Adam(model.parameters(), lr=lr)
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
            vloss = float(crit(model(Xva), yva)) if len(val) else 0.0
        if best_state is None or vloss < best_loss:
            best_loss, best_state = vloss, {k: v.clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    model.eval()
    return model, best_loss


def torch_scores(model, X, mean, std):
    import torch
    if not len(X):
        return np.zeros(0, dtype=np.float32)
    with torch.no_grad():
        return torch.sigmoid(model(torch.from_numpy(F.apply_scaling(np.asarray(X, np.float32), mean, std)))
                             ).numpy().ravel()


def summaries(X):
    """Token summaries of a stack of token matrices (the HGB's and the LR's input)."""
    return np.array([F.token_summary(x)[0] for x in X], dtype=np.float64).reshape(len(X), -1)


def tab_scores(clf, X):
    return clf.predict_proba(summaries(X))[:, 1] if len(X) else np.zeros(0)


def shuffled_stack(windows, seed):
    rng = np.random.default_rng(seed)
    return np.stack([F.shuffle_valid_rows(w["X"], rng) for w in windows]) if windows else _stack(windows)


class ArmScorer:
    """A fitted arm behind the probe harness's scorer interface (level, cols, window length, threshold, score)."""

    def __init__(self, level, cols, length, threshold, fn):
        self.level, self.cols, self.threshold, self.consecutive = level, list(cols), float(threshold), 1
        self.seq_len = length
        self.max_views = length if level == "view" else None
        self.sha256 = None
        self._fn = fn

    def score(self, batch):
        return np.asarray(self._fn(np.asarray(batch, np.float32)), dtype=np.float64)


# ───────────────────────────── operating points (design 10) ─────────────────────────────

def key_runs(windows, scores):
    """{(capture, key): [(t, p, entity)] in time order}: the policy's input."""
    groups = {}
    for i, (w, p) in enumerate(zip(windows, scores, strict=True)):
        groups.setdefault((w["capture"], w["key"]), []).append((w["t"], i, float(p), w["ip"]))
    return {k: [(t, p, e) for t, _i, p, e in sorted(v)] for k, v in groups.items()}


def decisions(runs, thr, k):
    """{(capture, key): (entity, decision time or None)} with p > thr in k consecutive windows of the key."""
    out = {}
    for key, seq in runs.items():
        run, when = 0, None
        for t, p, _e in seq:
            run = run + 1 if p > thr else 0
            if run >= k:
                when = t
                break
        out[key] = (seq[0][2], when)
    return out


def assess(dec, split):
    """Entity-level outcome of key decisions: attack entities caught (with their time to decision) and benign units
    flagged (a flagged key costs one unit of its entity, at most the entity's units), with the common denominators."""
    flagged_keys, caught = {}, {}
    for ent, when in dec.values():
        if when is None:
            continue
        if ent in split.attack:
            ttd = when - split.first[ent]
            caught[ent] = min(caught.get(ent, math.inf), ttd)
        else:
            flagged_keys[ent] = flagged_keys.get(ent, 0) + 1
    ben_flagged = sum(T.unit_cost(n, split.units.get(ent, 1)) for ent, n in flagged_keys.items())
    ttds = sorted(caught.values())
    return {"caught": len(caught), "attack_entities": len(split.attack),
            "recall": round(len(caught) / len(split.attack), 4) if split.attack else None,
            "benign_units_flagged": ben_flagged, "benign_units": sum(split.units.values()),
            "benign_entities_flagged": len(flagged_keys),
            "median_ttd_s": round(ttds[len(ttds) // 2], 3) if ttds else None,
            "_caught": caught, "_flagged": flagged_keys}


def operating_point(windows, scores, split, sel=None):
    """The (theta, k) of design 10 on validation, or None when no grid point fits the budget or the split has no
    attack entity or no benign unit."""
    sel = sel or PRE.selection()
    total = sum(split.units.values())
    if not split.attack or not total:
        return None
    allowed = math.floor(sel["budget"] * total + 1e-9)
    runs = key_runs(windows, scores)
    best = None
    grid = [(k, thr) for k in sel["k_grid"] for thr in sel["theta_grid"]]
    for gi, (k, thr) in enumerate(grid):
        a = assess(decisions(runs, thr, k), split)
        if a["benign_units_flagged"] > allowed:
            continue
        med = a["median_ttd_s"] if a["median_ttd_s"] is not None else math.inf
        rank = (-a["caught"], a["benign_units_flagged"], med, gi)
        if best is None or rank < best[0]:
            best = (rank, {"threshold": float(thr), "consecutive": int(k), "grid_index": gi, "allowed": allowed,
                           "budget": sel["budget"], **{x: v for x, v in a.items() if not x.startswith("_")}})
    return best[1] if best else None


def at_point(windows, scores, split, op):
    """The outcome of a frozen operating point (or nothing caught when op is None)."""
    if op is None:
        return {"caught": 0, "attack_entities": len(split.attack), "recall": 0.0 if split.attack else None,
                "benign_units_flagged": 0, "benign_units": sum(split.units.values()), "note": "no operating point"}
    a = assess(decisions(key_runs(windows, scores), op["threshold"], op["consecutive"]), split)
    return a


# ───────────────────────────── select ─────────────────────────────

def _sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _probe(scorer, windows, seed, max_windows):
    recs = [w["recs"] for w in windows]
    if len(recs) > max_windows:
        recs = [recs[i] for i in np.linspace(0, len(recs) - 1, max_windows).astype(int)]
    rep = l7_probes.run_probes(scorer, recs, transforms=l7_probes.TRANSFORMS_V2, seed=seed)
    rep["gate"] = list(l7_probes.GATE_PROBES_V2)
    rep["gate_pass"] = l7_probes.gate_pass(rep, l7_probes.GATE_PROBES_V2)
    return rep


def select(train, val, out_dir, *, arms=PRE.ARMS, epochs=None, threads=2, seed=None, valid_for_claims, source,
           split_sha256):
    """Fit every arm on `train` (a Split), gate it and choose its operating point on `val` (a Split) only, save the
    artifacts and the frozen selection (selection.json, its sha256 in selection.sha256). Returns (selection, sha)."""
    import torch
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    import l7_scorer as S
    from GRU_ML_model import GRUDDoSClassifier
    from l7_view_model import ViewGRU
    pre = PRE.load()
    mods, sel_rules, views = pre["models"], pre["selection"], pre["views"]
    seed = mods["fit_seed"] if seed is None else seed
    threads = min(int(threads), mods["threads_max"])
    torch.set_num_threads(threads)
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()
    max_views, tok_cols = views["max_views"], list(F.TOKEN_COLUMNS)
    tr_view, tr_req = thin(train.view), thin(train.req)
    Xv_val = _stack(val.view)
    out = {}

    def finish(name, val_scores, windows, scorer, extra=None):
        """The v2 probe gate on validation records, then (if it passes) the operating point on validation."""
        rep = _probe(scorer, windows, seed, pre["probes"]["max_windows"])
        op = operating_point(windows, val_scores, val, sel_rules) if rep["gate_pass"] else None
        out[name] = {"probe_gate_pass": rep["gate_pass"], "probes": rep, "operating_point": op, **(extra or {})}
        return op

    def artifact(name, rel):
        out[name]["artifact"] = rel
        out[name]["artifact_sha256"] = _sha_file(os.path.join(out_dir, rel))

    if {"view_gru", "gru_shuffled"} & set(arms):
        m = mods["view_gru"]
        mean, std = T.fit_scaling(tr_view, len(tok_cols))
        model, vloss = fit_torch(ViewGRU(len(tok_cols), m["embed"], m["hidden"], m["layers"], m["dropout"]),
                                 tr_view, val.view, mean, std, seed=seed, epochs=epochs or m["epochs"], lr=m["lr"],
                                 batch=m["batch"], threads=threads)
        pv = torch_scores(model, Xv_val, mean, std)
        sc = ArmScorer("view", tok_cols, max_views, 0.5,
                       lambda X, _m=model, _me=mean, _sd=std: torch_scores(_m, X, _me, _sd))
        op = finish("view_gru", pv, val.view, sc, {"val_loss": round(vloss, 5)})
        S.save_view_package(os.path.join(out_dir, "view_gru"), model, tok_cols, max_views, mean, std,
                            op["threshold"] if op else 0.5, op["consecutive"] if op else 1,
                            m["embed"], m["hidden"], m["layers"],
                            meta={"arm": "view_gru", "seed": seed, "source": source,
                                  "operating_point": "selection.json" if op else None})
        artifact("view_gru", "view_gru/config.json")
        if "gru_shuffled" in arms:
            ps = torch_scores(model, shuffled_stack(val.view, mods["gru_shuffled"]["shuffle_seed"]), mean, std)
            shuf = val.view
            out["gru_shuffled"] = {"artifact": out["view_gru"]["artifact"],
                                   "artifact_sha256": out["view_gru"]["artifact_sha256"],
                                   "probe_gate_pass": out["view_gru"]["probe_gate_pass"],
                                   "operating_point": op, "rule": mods["gru_shuffled"]["operating_point"],
                                   "val_at_point": {x: v for x, v in at_point(shuf, ps, val, op).items()
                                                    if not x.startswith("_")}}
    for name in ("hgb", "lr"):
        if name not in arms:
            continue
        Xs, ys = summaries(_stack(tr_view)), np.array([w["y"] for w in tr_view])
        if name == "hgb":
            clf = HistGradientBoostingClassifier(max_iter=mods["hgb"]["max_iter"], random_state=seed).fit(Xs, ys)
        else:
            clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=mods["lr"]["max_iter"],
                                                                     class_weight=mods["lr"]["class_weight"]))
            clf.fit(Xs, ys)
        with open(os.path.join(out_dir, f"{name}.pkl"), "wb") as fh:
            pickle.dump(clf, fh)
        sc = ArmScorer("view", tok_cols, max_views, 0.5, lambda X, _c=clf: tab_scores(_c, X))
        finish(name, tab_scores(clf, Xv_val), val.view, sc)
        artifact(name, f"{name}.pkl")
    if "request_gru" in arms:
        m, cols = mods["request_gru"], train.cols_req
        seq_len = pre["request_level"]["seq_len"]
        mean, std = T.fit_scaling(tr_req, len(cols))
        model, vloss = fit_torch(GRUDDoSClassifier(len(cols), m["hidden"], m["layers"], dropout_rate=m["dropout"]),
                                 tr_req, val.req, mean, std, seed=seed, epochs=epochs or m["epochs"], lr=m["lr"],
                                 batch=m["batch"], threads=threads)
        pr = torch_scores(model, _stack(val.req), mean, std)
        sc = ArmScorer("request", cols, seq_len, 0.5,
                       lambda X, _m=model, _me=mean, _sd=std: torch_scores(_m, X, _me, _sd))
        op = finish("request_gru", pr, val.req, sc, {"val_loss": round(vloss, 5)})
        S.save_package(os.path.join(out_dir, "request_gru"), model, cols, seq_len, mean, std,
                       op["threshold"] if op else 0.5, op["consecutive"] if op else 1, m["hidden"], m["layers"],
                       meta={"arm": "request_gru", "seed": seed, "source": source}, level="request")
        artifact("request_gru", "request_gru/config.json")
    sel = {"format": SEL_FORMAT, "source": source, "valid_for_claims": bool(valid_for_claims),
           "prereg_sha256": _sha_file(PRE.PREREG_PATH), "split_sha256": split_sha256, "seed": seed,
           "epochs": epochs or mods["view_gru"]["epochs"], "threads": threads,
           "counts": {"train_view_windows": len(tr_view), "train_request_windows": len(tr_req),
                      "val_view_windows": len(val.view), "val_request_windows": len(val.req),
                      "val_attack_entities": len(val.attack), "val_benign_units": sum(val.units.values())},
           "rule": sel_rules["objective"] + "; ties: " + ", ".join(sel_rules["ties"]),
           "arms": out, "select_wall_s": round(time.time() - t0, 1)}
    data = D.canonical_json(sel) + b"\n"
    with open(os.path.join(out_dir, "selection.json"), "wb") as fh:
        fh.write(data)
    sha = hashlib.sha256(data).hexdigest()
    with open(os.path.join(out_dir, "selection.sha256"), "w", encoding="utf-8") as fh:
        fh.write(f"{sha}  selection.json\n")
    return sel, sha


# ───────────────────────────── score (evaluation, frozen selection only) ─────────────────────────────

def load_selection(path, expected_sha256):
    """The frozen selection, after checking its sha256 against the recorded one and every artifact's sha256."""
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
    for name, arm in sel["arms"].items():
        p = os.path.normpath(os.path.join(base, arm["artifact"]))
        if not p.startswith(base + os.sep) or not os.path.isfile(p) or _sha_file(p) != arm["artifact_sha256"]:
            raise SelectionError(f"refusing to score: the artifact of {name} is missing or altered")
    return sel


def score(ev, sel, sel_path, out_dir, *, threads=2):
    """Apply every arm's frozen operating point to the evaluation Split; recall per family, benign units flagged per
    kind, time to decision. Writes eval.json."""
    import torch

    import l7_scorer as S
    torch.set_num_threads(min(int(threads), 2))
    base = os.path.dirname(os.path.abspath(sel_path))
    pre = PRE.load()
    res = {"format": RESULT_FORMAT, "selection_sha256": _sha_file(sel_path), "source": sel["source"],
           "valid_for_claims": sel["valid_for_claims"], "arms": {}}
    Xv = _stack(ev.view)
    for name, arm in sel["arms"].items():
        op = arm["operating_point"]
        if name in ("view_gru", "gru_shuffled", "request_gru"):
            pkg = os.path.dirname(os.path.join(base, arm["artifact"]))
            sc = S.L7Scorer.load(pkg, level="request" if name == "request_gru" else "view")
            if name == "request_gru":
                windows, p = ev.req, sc.score(_stack(ev.req)) if ev.req else np.zeros(0)
            else:
                X = shuffled_stack(ev.view, pre["models"]["gru_shuffled"]["shuffle_seed"]) if name == "gru_shuffled" \
                    else Xv
                windows, p = ev.view, sc.score(X) if ev.view else np.zeros(0)
        else:
            with open(os.path.join(base, arm["artifact"]), "rb") as fh:
                clf = pickle.load(fh)                     # our own artifact, hash-checked in load_selection
            windows, p = ev.view, tab_scores(clf, Xv)
        a = at_point(windows, p, ev, op)
        fam, kinds = {}, {}
        for e in ev.attack:
            f = ev.kind.get(e)
            fam.setdefault(f, [0, 0])
            fam[f][1] += 1
            fam[f][0] += int(e in a.get("_caught", {}))
        for e, n in a.get("_flagged", {}).items():
            kinds[ev.kind.get(e)] = kinds.get(ev.kind.get(e), 0) + min(n, ev.units.get(e, 1))
        res["arms"][name] = {**{x: v for x, v in a.items() if not x.startswith("_")},
                             "operating_point": op, "by_family": {str(f): {"caught": c, "entities": n}
                                                                  for f, (c, n) in sorted(fam.items(), key=str)},
                             "benign_units_flagged_by_kind": {str(k): v for k, v in sorted(kinds.items(), key=str)}}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "eval.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return res


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("step", choices=("select", "score"))
    ap.add_argument("--train", nargs="*", default=[])
    ap.add_argument("--val", nargs="*", default=[])
    ap.add_argument("--eval", nargs="*", default=[])
    ap.add_argument("--legacy-capture", help="one schema-1 capture: mechanics only, never a claim")
    ap.add_argument("--out", required=True)
    ap.add_argument("--selection")
    ap.add_argument("--selection-sha256")
    ap.add_argument("--arms", nargs="+", choices=PRE.ARMS, default=list(PRE.ARMS))
    ap.add_argument("--smoke", action="store_true", help="select: 3 epochs, a mechanics check (never a claim)")
    ap.add_argument("--threads", type=int, default=2)
    args = ap.parse_args(argv)
    splits = {"train": args.train, "val": args.val, "eval": args.eval}
    if args.legacy_capture and (args.train or args.val or args.eval):
        ap.error("--legacy-capture takes no --train/--val/--eval")
    if args.step == "select":
        os.makedirs(args.out, exist_ok=True)
        if args.legacy_capture:
            tr, va = legacy_split(args.legacy_capture)
            split_sha = hashlib.sha256(D.canonical_json(
                {"format": "l7v2-legacy-split/1", "train": sorted({r["_ent"] for _m, rs, _c in tr for r in rs}),
                 "val": sorted({r["_ent"] for _m, rs, _c in va for r in rs})})).hexdigest()
            valid, source = False, (f"legacy capture {os.path.basename(os.path.normpath(args.legacy_capture))}, "
                                    "benign entity-disjoint, held-out families as validation: mechanics only")
        else:
            import l7_disjoint
            l7_disjoint.require({**splits, "eval": []})
            split_sha = l7_disjoint.write_split(os.path.join(args.out, "split.json"), {**splits, "eval": []})
            tr = [load_capture(d) for d in args.train]
            va = [load_capture(d) for d in args.val]
            valid, source = not args.smoke, "P3 captures" + (" (smoke)" if args.smoke else "")
        _sel, sha = select(Split(tr), Split(va), args.out, arms=tuple(args.arms), epochs=3 if args.smoke else None,
                           threads=args.threads, valid_for_claims=valid, source=source, split_sha256=split_sha)
        print(f"{sha}  {os.path.join(args.out, 'selection.json')}")
        return 0
    if not args.selection:
        ap.error("score needs --selection and --selection-sha256 (the frozen file from select)")
    sel = load_selection(args.selection, args.selection_sha256)
    if args.legacy_capture:
        raise SelectionError("a legacy capture has no evaluation split; score P3 evaluation captures")
    import l7_disjoint
    l7_disjoint.require(splits, split_file=os.path.join(os.path.dirname(os.path.abspath(args.selection)), "split.json"),
                        selection_file=args.selection)
    res = score(Split([load_capture(d) for d in args.eval]), sel, args.selection, args.out, threads=args.threads)
    print(json.dumps({k: {x: v.get(x) for x in ("recall", "benign_units_flagged", "median_ttd_s")}
                      for k, v in res["arms"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
