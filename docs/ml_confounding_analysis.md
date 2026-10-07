# GRU Training-Data Confounding Analysis

**Date:** 2026-10-07
**Scope:** Read-only empirical analysis of the GRU DDoS classifier's training data.
**Verdict:** The previously reported ~0.9999 F1 is an artifact of **dataset/source
confounding**, not DDoS-detection skill. A de-confounded, single-capture dataset
is required; the realistic honest performance ceiling is ≈0.95–0.97.

---

## 1. Background

The GRU classifier (`GRU_ML_model.py`) is trained by `GRU_ML_init.py` on a merged
dataset built by `merge_datasets.py` from two **different** public captures:

| Class | Source file | Capture | Rows (full file) |
|---|---|---|---|
| **Benign** | `CICFlowMeter.csv` | UNSW-style testbed | 3,450,658 benign |
| **Attack (Syn)** | `Syn.csv` | CIC-DDoS2019 (SYN day) | 1,582,289 Syn |

`merge_datasets.py` takes **benign only from the UNSW capture** and the **Syn attack
only from CIC-DDoS2019**. The entire CIC-DDoS2019 file contains just **392 benign
rows**. Consequently the class label is **almost perfectly correlated with the
capture source** (benign ⇒ UNSW, attack ⇒ CIC-DDoS2019). Any classifier can achieve
near-perfect scores by learning *which capture a flow came from* — a property with
no bearing on real attack detection.

## 2. Method

A `RandomForest` on the **6 production features** (Flow Duration, Total Fwd Packet,
Total Length of Fwd Packet, Fwd Packet Length Mean, Flow Packets/s, SYN Flag Count)
was used as a proxy for the GRU: the confound lives in the *features* the GRU is fed,
so a per-flow classifier is a faithful, fast probe. Balanced samples were drawn:
UNSW benign = 60,000; UNSW real attacks = 60,000; CIC-DDoS2019 Syn = 54,828;
CIC-DDoS2019 benign = 381 (all available). Features were cleaned (inf/NaN dropped).

Three experiments:
- **A — Source/label separability:** reproduce the production split (benign-UNSW=0
  vs Syn-CICDDoS=1); 70/30 stratified split.
- **B — Cross-source generalization (the decisive test):** train exactly as in A,
  then score the UNSW capture's **real** attacks (DoS, Exploits, Fuzzers, …). A true
  attack detector flags them; a *source* detector calls them benign.
- **C — Honest within-capture detection:** benign vs attack **within a single
  capture** (no source confound), via 5-fold CV.

## 3. Results

| Experiment | Setup | Metric |
|---|---|---|
| **A** | benign-UNSW vs Syn-CICDDoS (production split) | Acc **0.9999**, F1 **0.9999**, AUC **1.0000** |
| **B** | train A → score UNSW's *real* attacks | **0.0%** flagged as attack |
| **C1** | within CIC-DDoS2019: benign (n=381) vs Syn | honest F1 **0.976 ± 0.007** |
| **C2** | within UNSW: benign vs real attacks | honest F1 **0.966 ± 0.001** |

**Experiment B, per attack type (all from the UNSW capture, all genuine attacks):**

| Attack type | n | Flagged as attack |
|---|---|---|
| Exploits | 20,696 | 0.0% |
| Fuzzers | 20,109 | 0.1% |
| Reconnaissance | 11,058 | 0.0% |
| Generic | 3,070 | 0.0% |
| DoS | 2,998 | 0.2% |
| Shellcode | 1,387 | 0.0% |
| Backdoor | 291 | 0.0% |
| Analysis | 223 | 0.0% |
| Worms | 168 | 0.0% |

Supplementary (Experiment A): no single feature separates the sources on its own
(max single-feature AUC ≈ 0.78 for *Total Length of Fwd Packet* / *Fwd Packet Length
Mean*), but the **joint** distribution does so perfectly. RandomForest importance is
dominated by timing/rate features — `Flow Packets/s` (0.36) and `Flow Duration`
(0.29) — which are characteristic of the *capture*, not of attack behaviour.

## 4. Interpretation

- **The 0.9999 headline is meaningless.** It measures capture identification. Because
  the two classes come from two different testbeds, the model only needs to recognise
  the testbed.
- **Experiment B is the smoking gun.** A model trained the production way labels
  **every real attack in the UNSW capture as benign (0.0%)** — because those attacks
  carry the UNSW "benign" capture fingerprint. The model learned *which testbed*, not
  *attack vs. benign*.
- **There is genuine signal.** Within a single capture the same 6 features separate
  benign from attack at F1 ≈ 0.97 (C1/C2), so a correctly built single-capture model
  is viable. (C1 is a rough estimate off only 381 benign rows — a benign-rich unified
  capture is needed for a robust figure.)
- **This explains the deployment symptom** recorded in `todo.txt#4` ("classifies
  normal traffic as SYN flood even with zero SYN flags"): at inference the XDP-derived
  features match *neither* training capture, so the confounded model behaves
  unpredictably.

## 5. Conclusion & recommendation

Discard the mixed dataset. Train benign **and** attack from **one capture**. Never
combine two captures. Chosen remediation dataset: **CIC-IDS2017** (benign-majority,
same testbed, contains DoS Hulk/GoldenEye/**slowloris**/**slowhttptest** and DDoS
(LOIC), with Source IP + Timestamp for per-IP sequence construction). Expected honest
performance after de-confounding: ≈0.95–0.97 F1 — lower than the confounded 0.9999,
but a real measurement of attack-detection skill.

---

*Reproducibility:* analysis script `scratchpad/confound_analysis.py` (RandomForest
proxy, scikit-learn 1.9.0). Datasets: `CICFlowMeter.csv` (UNSW), `Syn.csv`
(CIC-DDoS2019).
