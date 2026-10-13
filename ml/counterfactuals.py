#!/usr/bin/env python3
"""Counterfactual retraining for the GRU diagnosis (see docs/ML_INVESTIGATION.md).

Offline and in memory only: models are trained on the CPU and probed, never saved;
training_results/ is not touched. Each model is trained by a replica of
train_testbed_gru.py whose seed-42 run is checked to reproduce the deployed weights
bit for bit, so a counterfactual model differs from the deployed one only by the
stated intervention.

  CF1  Is the GRU blind to hping3 floods because of ONE training snapshot? The only
       training row with a low TCP window (init_win 63, a benign flow re-created in
       the LRU map) is removed from training — scaler unchanged, so the input
       encoding is identical — against a control that removes as many random benign
       windows. Probed with the one-packet flows the suite's floods produce.
  CF2  Why does leave-one-family-out R.U.D.Y. fail? Train without R.U.D.Y., then
       score the held-out R.U.D.Y. windows as captured and with their request size
       edited to Slowloris-like (36 B), wrk-like (34 B) and curl-like (72 B) values.
  CF3  Would feature hygiene alone fix it? The CF2 hold-out repeated without the TCP
       window, without the two request-size features, and without both; each variant
       is also probed for the hping3 blind spot and the stalled-handshake false positive.

    venv/bin/python ml/counterfactuals.py [--seeds 42 7 13] [--out ml/diagnosis]
"""
import argparse
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from torch import nn, optim
from torch.utils.data import DataLoader, TensorDataset

warnings.filterwarnings("ignore")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
from GRU_ML_model import GRUDDoSClassifier

# ── replica of train_testbed_gru.py (constants, split, windows, training loop) ──
FEATURES = ["Init_Win_bytes_forward", "Fwd IAT Total", "Fwd Header Length", "Fwd IAT Max",
            "Fwd Packet Length Max", "Fwd IAT Mean", "Fwd Packets/s", "Total Length of Fwd Packets"]
SEQ, HIDDEN, LAYERS, BATCH, EPOCHS, CAP = 15, 64, 2, 128, 25, 800
FAMILY = {"10.0.2.1": "http-flood", "10.0.2.2": "http-flood", "10.0.2.3": "slowloris",
          "10.0.2.4": "slowloris", "10.0.2.5": "rudy", "10.0.2.6": "rudy"}
ATT_SPLIT = {"10.0.2.1": "train", "10.0.2.2": "val", "10.0.2.3": "train", "10.0.2.4": "test",
             "10.0.2.5": "train", "10.0.2.6": "test"}
THR = 0.95
PKT_MAX, TOT_LEN, WIN = (FEATURES.index("Fwd Packet Length Max"),
                         FEATURES.index("Total Length of Fwd Packets"),
                         FEATURES.index("Init_Win_bytes_forward"))


def load_data():
    df = pd.read_csv(os.path.join(REPO, "training_data", "testbed_flows.csv"))
    df = df.sort_values(["src_ip", "poll"]).reset_index(drop=True)
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype(np.float32)
    return df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)


def benign_split(df):
    rng = np.random.default_rng(42)
    ips = list(df[df.y == 0].src_ip.unique())
    rng.shuffle(ips)
    n1, n2 = int(len(ips) * .67), int(len(ips) * .83)
    return {ip: ("train" if i < n1 else ("val" if i < n2 else "test")) for i, ip in enumerate(ips)}


def build(df, split_of, part, feats=FEATURES):
    """Stride-1 windows within each IP (capped per IP, as the trainer does); also returns
    each window's IP and whether it contains a low-window (init_win < 1000) snapshot."""
    X, y, ips, low = [], [], [], []
    for ip, g in df.groupby("src_ip", sort=False):
        if split_of.get(ip) != part:
            continue
        arr, lab = g[feats].to_numpy(), int(g.y.iloc[0])
        starts = list(range(len(arr) - SEQ + 1))
        if len(starts) > CAP:
            step = len(starts) / CAP
            starts = [starts[int(i * step)] for i in range(CAP)]
        for s in starts:
            w = arr[s:s + SEQ]
            low_win = bool((w[:, feats.index(FEATURES[WIN])] < 1000).any()) if FEATURES[WIN] in feats else False
            X.append(w); y.append(lab); ips.append(ip); low.append(low_win)
    return (np.array(X, np.float32).reshape(-1, SEQ, len(feats)), np.array(y, np.float32),
            np.array(ips), np.array(low))


def train(df, split_of, seed, drop_train=None, feats=FEATURES):
    """The trainer's procedure. The scaler is fit on ALL training windows; `drop_train`
    (a boolean mask over training windows) then removes windows from the training set
    only, so the input encoding never changes."""
    torch.manual_seed(seed); np.random.seed(seed); torch.set_num_threads(8)
    Xtr, ytr, iptr, lowtr = build(df, split_of, "train", feats)
    Xva, yva, _, _ = build(df, split_of, "val", feats)
    scaler = StandardScaler().fit(Xtr.reshape(-1, len(feats)))
    if drop_train is not None:
        keep = ~drop_train(ytr, iptr, lowtr)
        Xtr, ytr = Xtr[keep], ytr[keep]

    def sc(X):
        return scaler.transform(X.reshape(-1, len(feats))).reshape(X.shape).astype(np.float32)

    Xtr_s, Xva_s = sc(Xtr), sc(Xva)
    loader = DataLoader(TensorDataset(torch.from_numpy(Xtr_s), torch.from_numpy(ytr).unsqueeze(1)),
                        batch_size=BATCH, shuffle=True)
    model = GRUDDoSClassifier(input_size=len(feats), hidden_size=HIDDEN, num_layers=LAYERS)
    pos_w = torch.tensor([(ytr == 0).sum() / max((ytr == 1).sum(), 1)], dtype=torch.float32)
    crit, opt = nn.BCEWithLogitsLoss(pos_weight=pos_w), optim.Adam(model.parameters(), lr=1e-3)

    def predict(Xs):
        model.eval()
        with torch.no_grad():
            return torch.sigmoid(model(torch.from_numpy(Xs))).numpy().ravel()

    best, best_state = 0, None
    for _ in range(EPOCHS):
        model.train()
        for xb, yb in loader:
            opt.zero_grad(); loss = crit(model(xb), yb); loss.backward(); opt.step()
        f1 = f1_score(yva, (predict(Xva_s) >= .5).astype(int), zero_division=0) if len(yva) else 0
        if f1 >= best:
            best, best_state = f1, {k: v.clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    return model, scaler, (lambda X: predict(sc(np.asarray(X, np.float32))))


def flow_window(values):
    return np.array([[values] * SEQ], np.float32)


PROBES = [("hping3 SYN/ACK flow: win 64, 20-B header", [64, 0, 20, 0, 0, 0, 0, 0]),
          ("same, win 29200", [29200, 0, 20, 0, 0, 0, 0, 0]),
          ("same, win 65535", [65535, 0, 20, 0, 0, 0, 0, 0]),
          ("Linux client SYN: win 64240, 40-B header", [64240, 0, 40, 0, 0, 0, 0, 0]),
          ("stalled handshake: 2 SYNs 1 s apart, no payload", [64240, 1e6, 80, 1e6, 0, 1e6, 2, 0])]


def cf1(df, seeds, deployed):
    split_of = {**ATT_SPLIT, **benign_split(df)}
    rows, r0_identical = [], None
    for seed in seeds:
        variants = {
            "R0 (trainer replica)": None,
            "CF1: without the windows containing the init_win-63 snapshot":
                (lambda y, ips, low: low),
            "control: without as many random benign windows":
                (lambda y, ips, low, s=seed: _random_benign(y, low, s)),
        }
        for name, drop in variants.items():
            model, _, predict = train(df, split_of, seed, drop)
            if seed == 42 and drop is None:
                r0_identical = all(torch.equal(deployed[k], model.state_dict()[k]) for k in deployed)
            rows.append({"seed": seed, "variant": name,
                         **{p: float(predict(flow_window(v))[0]) for p, v in PROBES}})
    return rows, r0_identical


def _random_benign(y, low, seed):
    rng = np.random.default_rng(seed)
    pool = np.flatnonzero((y == 0) & ~low)
    mask = np.zeros(len(y), bool)
    mask[rng.choice(pool, size=int(low.sum()), replace=False)] = True
    return mask


def lofo_rudy_split(df):
    """Leave R.U.D.Y. out of training and validation (split as in the 2026-10-11 review)."""
    split_of = dict(benign_split(df))
    for ip, fam in FAMILY.items():
        split_of[ip] = "test" if fam == "rudy" else ("train" if ATT_SPLIT[ip] == "train" else "val")
    return split_of


def cf2(df, seeds):
    split_of = lofo_rudy_split(df)
    Xte, yte, ipte, _ = build(df, split_of, "test")
    rudy = Xte[yte == 1]
    benign = Xte[yte == 0]

    def with_request(X, size):
        X = X.copy()
        old = X[:, :, PKT_MAX]
        ratio = np.divide(size, old, out=np.ones_like(old), where=old > 0)
        X[:, :, PKT_MAX] = np.where(old > 0, size, 0)
        X[:, :, TOT_LEN] = X[:, :, TOT_LEN] * ratio
        return X

    rows = []
    for seed in seeds:
        _, _, predict = train(df, split_of, seed)
        row = {"seed": seed, "benign test windows > thr": float((predict(benign) > THR).mean())}
        for label, X in (("R.U.D.Y. as captured (51-B requests)", rudy),
                         ("request edited to 36 B (Slowloris-like)", with_request(rudy, 36)),
                         ("request edited to 34 B (wrk-like)", with_request(rudy, 34)),
                         ("request edited to 72 B (curl-like)", with_request(rudy, 72))):
            row[label] = float((predict(X) > THR).mean())
        rows.append(row)
    return rows, {"rudy_windows": len(rudy), "benign_windows": len(benign),
                  "rudy_ips": sorted(set(ipte[yte == 1]))}


VARIANTS = {
    "V0 all 8 features": FEATURES,
    "V1 without the TCP window": [f for f in FEATURES if f != "Init_Win_bytes_forward"],
    "V2 without the request-size features": [f for f in FEATURES if f not in (
        "Fwd Packet Length Max", "Total Length of Fwd Packets")],
    "V3 without both": [f for f in FEATURES if f not in (
        "Init_Win_bytes_forward", "Fwd Packet Length Max", "Total Length of Fwd Packets")],
}
CF3_PROBES = [PROBES[0], PROBES[3], PROBES[4]]   # hping3 flow, Linux SYN, stalled handshake


def cf3(df, seeds):
    split_of = lofo_rudy_split(df)
    rows = []
    for name, feats in VARIANTS.items():
        Xte, yte, _, _ = build(df, split_of, "test", feats)
        for seed in seeds:
            _, _, predict = train(df, split_of, seed, feats=feats)
            row = {"variant": name, "seed": seed,
                   "R.U.D.Y. held out: windows > thr": float((predict(Xte[yte == 1]) > THR).mean()),
                   "benign test windows > thr": float((predict(Xte[yte == 0]) > THR).mean())}
            for pname, v in CF3_PROBES:
                row[f"p({pname})"] = float(predict(flow_window([v[FEATURES.index(f_)] for f_ in feats]))[0])
            rows.append(row)
    return rows


def md(rows, cols, fmt="{:.4f}"):
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for r in rows:
        lines.append("| " + " | ".join(fmt.format(r[c]) if isinstance(r[c], float) else str(r[c])
                                       for c in cols) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 7, 13])
    ap.add_argument("--out", default=os.path.join(REPO, "ml", "diagnosis"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    df = load_data()
    deployed = torch.load(os.path.join(REPO, "training_results", "gru_testbed_model.pth"),
                          map_location="cpu", weights_only=True)
    r1, identical = cf1(df, args.seeds, deployed)
    r2, info2 = cf2(df, args.seeds)
    r3 = cf3(df, args.seeds)
    probe_cols = [p for p, _ in PROBES]
    L = ["# GRU diagnosis: counterfactual retraining", "",
         ("Generated by `ml/counterfactuals.py` (offline; models trained in memory, never saved). "
          f"Trainer replica check: the seed-42 replica reproduces the deployed weights bit for bit: "
          f"**{identical}**."), "",
         "## CF1: is the GRU blind to hping3 floods because of one training snapshot?", "",
         ("Probability of a window of 15 identical one-packet flows. Only the training set "
          "changes; the scaler (input encoding) is the deployed one in every row."), "",
         md(r1, ["seed", "variant"] + probe_cols),
         "", "## CF2: leave-one-family-out R.U.D.Y. and the request size", "",
         (f"Trained without R.U.D.Y. ({', '.join(info2['rudy_ips'])} held out: "
          f"{info2['rudy_windows']} windows) and scored with the request size as captured and edited. "
          f"Values: share of windows with p > {THR}."), "",
         md(r2, ["seed", "benign test windows > thr"] + [k for k in r2[0] if k.startswith(("R.U.D.Y.", "request"))],
            fmt="{:.1%}"),
         "", "## CF3: feature hygiene under the same R.U.D.Y. hold-out", "",
         "Shares of windows with p > 0.95, and p of the probe flows (15 identical snapshots).", "",
         md([{**r, **{k: (f"{v:.1%}" if "windows" in k else f"{v:.4f}") for k, v in r.items()
                      if isinstance(v, float)}} for r in r3], list(r3[0].keys()))]
    with open(os.path.join(args.out, "counterfactuals.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    with open(os.path.join(args.out, "counterfactuals.json"), "w", encoding="utf-8") as fh:
        json.dump({"replica_bit_identical": identical, "cf1": r1, "cf2": r2, "cf2_info": info2, "cf3": r3},
                  fh, indent=1)
        fh.write("\n")
    print(f"[+] replica bit-identical to deployed: {identical}; wrote "
          f"{os.path.relpath(args.out, REPO)}/counterfactuals.md")


if __name__ == "__main__":
    main()
