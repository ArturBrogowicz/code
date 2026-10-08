#!/usr/bin/env python3
"""Phase B — Fixed, de-confounded GRU training pipeline (CIC-IDS2017).

Rewrites the previous confounded pipeline. Key corrections vs. the old version:
  * Single-capture data (CIC-IDS2017) — benign AND attack from one testbed.
  * Top-8 XDP-observable features (feature-selection study), not the SYN-centric 6.
  * Sequences built STRICTLY within a single Source IP (never across IPs).
  * Scaler fit on the TRAIN split ONLY (no leakage).
  * Honest split: benign IP-disjoint (train/val/test by Source IP); attack
    sub-type-stratified random (only ~1 attacker IP exists, so an IP-disjoint
    attack split is impossible — documented limitation).
  * Class imbalance handled with BCEWithLogitsLoss pos_weight.

Capture order is preserved for within-IP sequencing (CIC-IDS2017 timestamps are
unreliable — mixed d/m/Y and ambiguous AM/PM — so we do NOT sort by them; the
rows are already in capture order per day-file).
"""
import json, warnings; warnings.filterwarnings("ignore")
import numpy as np, pandas as pd, torch, torch.nn as nn, joblib
import torch.optim as optim
from collections import defaultdict
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix)
from torch.utils.data import TensorDataset, DataLoader
from GRU_ML_model import GRUDDoSClassifier

torch.manual_seed(42); np.random.seed(42); torch.set_num_threads(8)

DATA = "training_data/cicids2017_dosddos.csv"
MODEL_OUT = "training_results/gru_cicids_model.pth"
SCALER_OUT = "training_results/scaler_cicids.save"
CFG_OUT = "training_results/feature_config.json"

FEATURES = ['Init_Win_bytes_forward', 'Fwd IAT Total', 'Fwd Header Length', 'Fwd IAT Max',
            'Fwd Packet Length Max', 'Fwd IAT Mean', 'Fwd Packets/s', 'Total Length of Fwd Packets']
SEQ = 15; HIDDEN = 64; LAYERS = 2; BATCH = 256; EPOCHS = 15
BENIGN_CAP_PER_IP = 80     # cap sequences per benign IP (stop huge IPs dominating)
BENIGN_TARGET = 180000
ATTACK_TARGET = 120000
TRAIN, VAL = 0.70, 0.15    # test = remainder

print(f"[*] Loading {DATA} ...")
df = pd.read_csv(DATA, low_memory=False)
for c in FEATURES:
    df[c] = df[c].astype(np.float32)
print(f"    {len(df)} flows  benign={(df.y==0).sum()} attack={(df.y==1).sum()}")

# ---------- within-IP sequence builders (preserve capture order) ----------
def windows(arr, cap=None):
    """All SEQ-length sliding windows of a (n,F) row block, optionally strided to <=cap."""
    n = len(arr)
    if n < SEQ:
        return []
    starts = list(range(0, n - SEQ + 1))
    if cap and len(starts) > cap:
        step = len(starts) / cap
        starts = [starts[int(i * step)] for i in range(cap)]
    return [arr[s:s + SEQ] for s in starts]

rng = np.random.default_rng(42)
att_ips = set(df.loc[df.y == 1, 'Source IP'].unique())

# ----- BENIGN: group by IP (benign-only IPs), split IPs 70/15/15 -----
ben = df[(df.y == 0) & (~df['Source IP'].isin(att_ips))]
ben_ips = [ip for ip, g in ben.groupby('Source IP', sort=False) if len(g) >= SEQ]
rng.shuffle(ben_ips)
n_tr = int(len(ben_ips) * TRAIN); n_va = int(len(ben_ips) * (TRAIN + VAL))
split_of = {}
for i, ip in enumerate(ben_ips):
    split_of[ip] = 'train' if i < n_tr else ('val' if i < n_va else 'test')
ben_seq = {'train': [], 'val': [], 'test': []}
for ip, g in ben.groupby('Source IP', sort=False):
    if ip not in split_of:
        continue
    for w in windows(g[FEATURES].to_numpy(), cap=BENIGN_CAP_PER_IP):
        ben_seq[split_of[ip]].append(w)
# subsample benign to target, proportional to split ratios
for sp, frac in [('train', TRAIN), ('val', VAL), ('test', 1 - TRAIN - VAL)]:
    tgt = int(BENIGN_TARGET * frac); L = ben_seq[sp]
    if len(L) > tgt:
        idx = rng.choice(len(L), tgt, replace=False); ben_seq[sp] = [L[i] for i in idx]

# ----- ATTACK: within attacker-IP windows, sub-type-stratified random split -----
att_windows, att_types = [], []
for ip, g in df[df.y == 1].groupby('Source IP', sort=False):
    rows = g[FEATURES].to_numpy(); subs = g['Label'].to_numpy()
    n = len(rows)
    for s in range(0, n - SEQ + 1):
        att_windows.append(rows[s:s + SEQ]); att_types.append(subs[s + SEQ - 1])
att_windows = np.array(att_windows, dtype=np.float32); att_types = np.array(att_types)
if len(att_windows) > ATTACK_TARGET:                      # stride down, keep sub-type mix
    keep = rng.choice(len(att_windows), ATTACK_TARGET, replace=False)
    att_windows, att_types = att_windows[keep], att_types[keep]
att_seq = {'train': [], 'val': [], 'test': []}
att_sub = {'train': [], 'val': [], 'test': []}
for t in np.unique(att_types):                             # stratify by sub-type
    idx = np.where(att_types == t)[0]; rng.shuffle(idx)
    a = int(len(idx) * TRAIN); b = int(len(idx) * (TRAIN + VAL))
    for sp, sl in [('train', idx[:a]), ('val', idx[a:b]), ('test', idx[b:])]:
        for i in sl:
            att_seq[sp].append(att_windows[i]); att_sub[sp].append(t)

def stack(sp):
    Xb = np.array(ben_seq[sp], dtype=np.float32) if ben_seq[sp] else np.empty((0, SEQ, len(FEATURES)), np.float32)
    Xa = np.array(att_seq[sp], dtype=np.float32) if att_seq[sp] else np.empty((0, SEQ, len(FEATURES)), np.float32)
    X = np.concatenate([Xb, Xa], 0)
    y = np.concatenate([np.zeros(len(Xb)), np.ones(len(Xa))]).astype(np.float32)
    sub = np.array(['BENIGN'] * len(Xb) + list(att_sub[sp]))
    return X, y, sub

Xtr, ytr, _ = stack('train'); Xva, yva, _ = stack('val'); Xte, yte, subte = stack('test')
print(f"[*] sequences  train={len(ytr)} (atk {int(ytr.sum())})  "
      f"val={len(yva)} (atk {int(yva.sum())})  test={len(yte)} (atk {int(yte.sum())})")

# ---------- scaler fit on TRAIN ONLY ----------
scaler = StandardScaler().fit(Xtr.reshape(-1, len(FEATURES)))
def scale(X): return scaler.transform(X.reshape(-1, len(FEATURES))).reshape(X.shape).astype(np.float32)
Xtr, Xva, Xte = scale(Xtr), scale(Xva), scale(Xte)

def loader(X, y, shuffle):
    return DataLoader(TensorDataset(torch.from_numpy(X), torch.from_numpy(y).unsqueeze(1)),
                      batch_size=BATCH, shuffle=shuffle)
ltr, lva = loader(Xtr, ytr, True), loader(Xva, yva, False)

device = torch.device('cpu')
model = GRUDDoSClassifier(input_size=len(FEATURES), hidden_size=HIDDEN, num_layers=LAYERS).to(device)
pos_w = torch.tensor([(ytr == 0).sum() / max((ytr == 1).sum(), 1)], dtype=torch.float32)
print(f"[*] pos_weight={pos_w.item():.2f}")
crit = nn.BCEWithLogitsLoss(pos_weight=pos_w); opt = optim.Adam(model.parameters(), lr=1e-3)

def evaluate(X, y):
    model.eval()
    with torch.no_grad():
        p = torch.sigmoid(model(torch.from_numpy(X).to(device))).cpu().numpy().ravel()
    pred = (p >= 0.5).astype(int)
    return (f1_score(y, pred, zero_division=0), precision_score(y, pred, zero_division=0),
            recall_score(y, pred, zero_division=0), accuracy_score(y, pred), pred)

best_f1, best_state = 0.0, None
for ep in range(EPOCHS):
    model.train(); tot = 0.0
    for xb, yb in ltr:
        opt.zero_grad(); loss = crit(model(xb.to(device)), yb.to(device)); loss.backward(); opt.step()
        tot += loss.item()
    f1, pr, rc, ac, _ = evaluate(Xva, yva)
    print(f"  epoch {ep+1:2d}  train_loss={tot/len(ltr):.4f}  val F1={f1:.4f} P={pr:.4f} R={rc:.4f}")
    if f1 > best_f1:
        best_f1 = f1; best_state = {k: v.clone() for k, v in model.state_dict().items()}

model.load_state_dict(best_state)
f1, pr, rc, ac, pred = evaluate(Xte, yte)
print("\n" + "=" * 60 + f"\nHELD-OUT TEST  F1={f1:.4f}  P={pr:.4f}  R={rc:.4f}  Acc={ac:.4f}")
print("Confusion matrix [[TN FP][FN TP]]:\n", confusion_matrix(yte, pred))
print("Per-attack-type RECALL on test:")
for t in sorted(set(subte)):
    if t == 'BENIGN':
        m = subte == t; print(f"  {t:18s} n={int(m.sum()):6d}  false-positive={ (pred[m]==1).mean()*100:5.2f}%")
    else:
        m = subte == t; print(f"  {t:18s} n={int(m.sum()):6d}  recall={ (pred[m]==1).mean()*100:5.1f}%")

torch.save(best_state, MODEL_OUT); joblib.dump(scaler, SCALER_OUT)
json.dump({"features": FEATURES, "seq_length": SEQ, "input_size": len(FEATURES),
           "hidden_size": HIDDEN, "num_layers": LAYERS, "model": MODEL_OUT, "scaler": SCALER_OUT,
           "best_val_f1": round(best_f1, 4), "test_f1": round(f1, 4)}, open(CFG_OUT, "w"), indent=2)
print(f"\n[+] saved model -> {MODEL_OUT}\n[+] saved scaler -> {SCALER_OUT}\n[+] saved config -> {CFG_OUT}")
