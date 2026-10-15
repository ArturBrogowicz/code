# L7 GRU training — P4 gate (2026-10-15)

The P4 gate for `docs/L7_GRU_DESIGN.md` (§6.4): train an L7 request-sequence model on the
P3 dataset and evaluate it honestly. **Offline, CPU, no VM** — `ml/train_l7.py` reads the
published dataset (`results/2026-10-15_l7-p3-capture/`) and writes the model package,
card and metrics here. Branch `feat/l7-gru-design`.

```
./venv/bin/python ml/train_l7.py results/2026-10-15_l7-p3-capture \
    --out results/2026-10-15_l7-p4-train/model --seed 0 --epochs 25
```

**Not promoted.** `model/` is a candidate package, kept here for P5 (online evaluation).
Promotion into the live daemon is P6 and needs your approval; the XDP model in
`training_results/` is untouched.

## Result — PASS

| Gate criterion | Result |
|---|---|
| Benign split IP-disjoint; held-out families family-disjoint | yes (18 benign test groups; `credstuff`, `padded_flood`, `slowread` never trained) |
| Policy metrics per family with Clopper-Pearson CIs, FP/client-hour | yes (`l7_metrics.json`) |
| Exact-invariance probe battery passes (hard gate) | **PASS** — UA swap, URI renaming, time offset all \|Δp\| = 0 |
| GRU vs tabular baseline, feature-set variants | done (below) |

## The headline finding — the size feature is a shortcut; dropping it generalizes

Three feature-set variants, each a GRU + an HGB tabular baseline, under one IP-disjoint
benign split and the deployed policy (p > 0.95 in 3 consecutive windows). "Held-out
detected" counts groups of the **never-trained** families (max 8: `credstuff` ×6,
`padded_flood` ×1, `slowread` ×1):

| variant | GRU held-out detected | GRU benign FP/client-hr | HGB baseline held-out |
|---|---|---|---|
| default (all features) | **1 / 8** | 0.0 | 3 / 8 |
| **no_size (saved)** | **7 / 8** | **0.0** | 6 / 8 |
| no_uri | 7 / 8 | 9.86 | 3 / 8 |

* **Dropping the request-size features takes held-out detection from 1/8 to 7/8 at zero
  benign false positives.** With size in, the GRU keys on it (as the XDP model did,
  `ML_INVESTIGATION.md` §3) and misses `credstuff` — a POST flood it never trained on —
  entirely (0/6). Without size, it catches all 6.
* **URI diversity is a *useful* feature, not a shortcut:** removing it (`no_uri`) still
  detects 7/8 but raises benign FP to 9.86/client-hour (benign clients browse many
  paths). So the two string-derived signals are not equivalent — size is harmful, URI
  diversity is behavioural and helpful.
* **Sequence modelling earns its place (decision 6):** the GRU `no_size` (7/8 at 0 FP)
  beats the HGB tabular baseline on the same features (6/8, and at 4.9 FP/client-hour in
  the full metrics) — better recall at lower FP.
* The saved `no_size` model is **size-invariant by test**: the padding robustness probe
  flips 0 % of decisions (max \|Δp\| = 0), versus 91 % for the P2 untrained model.

## The saved model (`model/`, variant `no_size`)

* benign test: 0 / 18 groups falsely detected; **0 FP per client-hour**.
* held-out families (policy, per group): `padded_flood` 1/1, `credstuff` 6/6,
  `slowread` **0/1**.
* in-distribution trained families: `scraper` 1/1, `subthreshold_flood` 1/1.

**`slowread` 0/1 is the R1 limit, not a training fault.** The low-and-slow family logged
~1 window (§6.5 / `results/2026-10-15_l7-p3-capture/`), so there is almost nothing to
score. The L7-log model's niche is the sub-threshold *fast* families; low-and-slow stays
the deterministic SlowConn/`ss` path's job (design doc §9 R1).

## Caveats (carried to P5)

* One capture, one seed. The variant selection (`no_size`) and these numbers must be
  confirmed on another seed/capture before promotion (P6). `ml/train_l7.py` records the
  pre-registered selection rule in `metrics.json → selection`.
* Per-family group counts are tiny (most families have 1 attacker IP), so group-level CIs
  are wide; window-over-rates are in `l7_metrics.json` but windows overlap and are not
  independent. P5 adds online runs for IP-level evidence.

## Files
* `model/` — the candidate package: `config.json` (feature columns, scaling, policy,
  weights SHA-256, provenance) + `model.pth`. Load with `l7_scorer.L7Scorer.load`.
* `model_card.md` — the generated card.
* `l7_metrics.json` — the full report: every variant, GRU and baseline, all evaluation
  sets, the probe battery, and the selection record.
