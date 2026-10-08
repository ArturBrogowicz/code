#!/usr/bin/env python3
"""Tier-1 T1b — train the GRU on the testbed-native flow dataset.

Trains on testbed_flows.csv (captured via the SAME XDP flow_map used at
inference, so no source confound and no environment domain gap). Sequences are
built strictly within a Source IP; the split is IP-disjoint for BOTH classes
(12 benign IPs, 4 attacker IPs); the scaler is fit on train only.

Note: Init_Win_bytes_forward is constant (64240) in this single-OS testbed, so
it carries no signal here (StandardScaler maps it to 0); it's kept only so the
feature vector matches what XDP computes. The discriminative signal is timing/
volume (Fwd IAT*, Fwd Packets/s, lengths).
"""
import json, warnings; warnings.filterwarnings("ignore")
import numpy as np, pandas as pd, torch, torch.nn as nn, torch.optim as optim, joblib
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score, confusion_matrix
from torch.utils.data import TensorDataset, DataLoader
from GRU_ML_model import GRUDDoSClassifier

torch.manual_seed(42); np.random.seed(42); torch.set_num_threads(8)
DATA = "training_data/testbed_flows.csv"
MODEL_OUT, SCALER_OUT, CFG_OUT = ("training_results/gru_testbed_model.pth",
    "training_results/scaler_testbed.save", "training_results/feature_config_testbed.json")
FEATURES = ["Init_Win_bytes_forward","Fwd IAT Total","Fwd Header Length","Fwd IAT Max",
            "Fwd Packet Length Max","Fwd IAT Mean","Fwd Packets/s","Total Length of Fwd Packets"]
SEQ, HIDDEN, LAYERS, BATCH, EPOCHS, CAP_PER_IP = 15, 64, 2, 128, 25, 800

df = pd.read_csv(DATA)
df = df.sort_values(["src_ip","poll"]).reset_index(drop=True)
for c in FEATURES: df[c] = pd.to_numeric(df[c], errors="coerce").astype(np.float32)
df = df.replace([np.inf,-np.inf], np.nan).dropna(subset=FEATURES)
print(f"[*] {len(df)} rows  benign={(df.y==0).sum()} attack={(df.y==1).sum()}")

rng = np.random.default_rng(42)
def split_ips(ips, a, bnd):
    ips = list(ips); rng.shuffle(ips)
    n1, n2 = int(len(ips)*a), int(len(ips)*bnd)
    return {ip:("train" if i<n1 else ("val" if i<n2 else "test")) for i,ip in enumerate(ips)}
# guarantee each split gets >=1 attacker IP (only 4 exist): 2 train / 1 val / 1 test
att_ips = list(df[df.y==1].src_ip.unique()); rng.shuffle(att_ips)
att_split = {att_ips[0]:"train", att_ips[1]:"train", att_ips[2]:"val", att_ips[3]:"test"} \
            if len(att_ips) >= 4 else split_ips(att_ips, .7, .85)
ben_split = split_ips(df[df.y==0].src_ip.unique(), .67, .83)
split_of = {**att_split, **ben_split}

def build(spname):
    X, y = [], []
    for ip, g in df.groupby("src_ip", sort=False):
        if split_of.get(ip) != spname: continue
        arr = g[FEATURES].to_numpy(); lab = int(g.y.iloc[0])
        starts = list(range(0, len(arr)-SEQ+1))
        if len(starts) > CAP_PER_IP:
            step = len(starts)/CAP_PER_IP; starts = [starts[int(i*step)] for i in range(CAP_PER_IP)]
        for s in starts: X.append(arr[s:s+SEQ]); y.append(lab)
    if not X: return np.empty((0,SEQ,len(FEATURES)),np.float32), np.empty((0,),np.float32)
    return np.array(X,np.float32), np.array(y,np.float32)

Xtr,ytr = build("train"); Xva,yva = build("val"); Xte,yte = build("test")
print(f"[*] sequences train={len(ytr)}(atk {int(ytr.sum())}) val={len(yva)}(atk {int(yva.sum())}) "
      f"test={len(yte)}(atk {int(yte.sum())})")
print(f"[*] attacker IP split: {att_split}")

scaler = StandardScaler().fit(Xtr.reshape(-1,len(FEATURES)))
def sc(X): return scaler.transform(X.reshape(-1,len(FEATURES))).reshape(X.shape).astype(np.float32)
Xtr,Xva,Xte = sc(Xtr),sc(Xva),sc(Xte)

ltr = DataLoader(TensorDataset(torch.from_numpy(Xtr),torch.from_numpy(ytr).unsqueeze(1)),batch_size=BATCH,shuffle=True)
model = GRUDDoSClassifier(input_size=len(FEATURES),hidden_size=HIDDEN,num_layers=LAYERS)
pos_w = torch.tensor([(ytr==0).sum()/max((ytr==1).sum(),1)],dtype=torch.float32)
crit = nn.BCEWithLogitsLoss(pos_weight=pos_w); opt = optim.Adam(model.parameters(),lr=1e-3)
print(f"[*] pos_weight={pos_w.item():.2f}")

def ev(X,y):
    if len(y)==0: return 0,0,0,0,np.array([])
    model.eval()
    with torch.no_grad(): p=torch.sigmoid(model(torch.from_numpy(X))).numpy().ravel()
    pr=(p>=0.5).astype(int)
    return (f1_score(y,pr,zero_division=0),precision_score(y,pr,zero_division=0),
            recall_score(y,pr,zero_division=0),accuracy_score(y,pr),pr)
best,beststate=0,None
for ep in range(EPOCHS):
    model.train(); tot=0
    for xb,yb in ltr:
        opt.zero_grad(); loss=crit(model(xb),yb); loss.backward(); opt.step(); tot+=loss.item()
    f1,pr,rc,ac,_=ev(Xva,yva)
    if f1>=best: best,beststate=f1,{k:v.clone() for k,v in model.state_dict().items()}
    if ep%5==0 or ep==EPOCHS-1: print(f"  epoch {ep+1:2d} loss={tot/len(ltr):.4f} val F1={f1:.4f} P={pr:.4f} R={rc:.4f}")
model.load_state_dict(beststate)
f1,pr,rc,ac,pred=ev(Xte,yte)
print(f"\n{'='*56}\nHELD-OUT TEST (IP-disjoint)  F1={f1:.4f} P={pr:.4f} R={rc:.4f} Acc={ac:.4f}")
print("Confusion [[TN FP][FN TP]]:\n", confusion_matrix(yte,pred) if len(pred) else "n/a")

torch.save(beststate,MODEL_OUT); joblib.dump(scaler,SCALER_OUT)
json.dump({"features":FEATURES,"seq_length":SEQ,"input_size":len(FEATURES),"hidden_size":HIDDEN,
           "num_layers":LAYERS,"model":MODEL_OUT,"scaler":SCALER_OUT,"source":"testbed-native (Tier-1)",
           "val_f1":round(best,4),"test_f1":round(f1,4)}, open(CFG_OUT,"w"), indent=2)
print(f"[+] saved {MODEL_OUT} / {SCALER_OUT} / {CFG_OUT}")
