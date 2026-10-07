#!/usr/bin/env python3
"""Phase A — De-confounded dataset builder (CIC-IDS2017).

Replaces the confounded two-capture merge (merge_datasets.py). Loads all
CIC-IDS2017 'TrafficLabelling' CSVs (benign + attacks from ONE testbed), keeps
Source IP + Timestamp + the selected Top-8 XDP-observable features, restricts the
attack class to the DoS/DDoS families, binary-labels, cleans, and writes a single
unified dataset for the fixed training pipeline (Phase B).

Output columns: Source IP, Timestamp, Label(0=benign,1=dos/ddos), <8 features>.
"""
import glob, os, warnings; warnings.filterwarnings("ignore")
import numpy as np, pandas as pd

SRC_DIR = "TrafficLabelling "          # note: CIC-IDS2017 ships this dir with a trailing space
OUT = "training_data/cicids2017_dosddos.csv"

FEATURES = [
    'Init_Win_bytes_forward', 'Fwd IAT Total', 'Fwd Header Length', 'Fwd IAT Max',
    'Fwd Packet Length Max', 'Fwd IAT Mean', 'Flow Packets/s', 'Total Length of Fwd Packets',
]
META = ['Source IP', 'Timestamp']
ATTACK = {'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest', 'DDoS'}

def norm(s): return str(s).replace('\r', '').strip()

os.makedirs('training_data', exist_ok=True)
frames = []
for fp in sorted(glob.glob(os.path.join(SRC_DIR, "*.csv"))):
    for chunk in pd.read_csv(fp, chunksize=150000, low_memory=False, encoding='latin-1'):
        chunk.columns = [norm(c) for c in chunk.columns]
        chunk = chunk.loc[:, ~chunk.columns.duplicated()]   # drop duplicate 'Fwd Header Length'
        if 'Label' not in chunk.columns:
            continue
        chunk['Label'] = chunk['Label'].map(norm)
        keep = chunk[chunk['Label'].isin(ATTACK | {'BENIGN'})]
        cols = [c for c in META + FEATURES if c in keep.columns]
        if len(cols) < len(META) + len(FEATURES):
            missing = set(META + FEATURES) - set(keep.columns)
            raise SystemExit(f"[!] {fp}: missing columns {missing}")
        sub = keep[cols + ['Label']].copy()
        frames.append(sub)

df = pd.concat(frames, ignore_index=True)
print(f"[*] Raw DoS/DDoS+benign rows: {len(df)}")

for c in FEATURES:
    df[c] = pd.to_numeric(df[c], errors='coerce')
df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES)
df = df[df['Source IP'].astype(str).str.strip() != ''].dropna(subset=['Source IP'])
# Keep the original attack label (for per-type reporting) AND a binary target y.
df['y'] = (df['Label'] != 'BENIGN').astype(int)
print(f"[*] After cleaning: {len(df)} rows  |  benign={int((df.y==0).sum())}  attack={int((df.y==1).sum())}")

df.to_csv(OUT, index=False)
print(f"[+] Wrote {OUT}")

# ---- per-IP structure stats (informs the Phase-B sequence split) ----
SEQ = 15
print("\n=== per-Source-IP structure (SEQ_LENGTH=15) ===")
for name, lab in [("BENIGN", 0), ("ATTACK", 1)]:
    g = df[df.y == lab].groupby('Source IP').size()
    seqs = (g - SEQ + 1).clip(lower=0).sum()
    print(f"  {name:7s}: unique IPs={g.size:6d}  flows={int(g.sum()):8d}  "
          f"median flows/IP={int(g.median())}  p90={int(g.quantile(0.9))}  max={int(g.max())}")
    print(f"           IPs with >={SEQ} flows: {int((g>=SEQ).sum())}  ->  obtainable sequences: {int(seqs)}")
print("  attack sub-type flow counts:", df[df.y==1]['Label'].value_counts().to_dict())
# IP overlap between classes (an IP that is both attacker and benign source?)
ben_ips = set(df[df.y==0]['Source IP']); att_ips = set(df[df.y==1]['Source IP'])
print(f"  IPs appearing in BOTH classes: {len(ben_ips & att_ips)} "
      f"(benign-only={len(ben_ips-att_ips)}, attack-only={len(att_ips-ben_ips)})")
print("[done]")
