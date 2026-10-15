# L7 GRU model card (2026-10-15)

Dataset: `/home/artur/DDoS-mitigation/code/results/2026-10-15_l7-p3-capture`  seed=0 epochs=25
Held-out (never trained) families: ['credstuff', 'padded_flood', 'slowread']
Policy: p > 0.95 in 3 consecutive windows.

## Saved model — variant `no_size`
Selection: max held-out groups detected s.t. benign FP/client-hour <= 1.0; tie-break lower FP then lower val loss.
Caveat: one capture, one seed; confirm on another seed/capture before promotion (P6).

- benign test: 18 groups, group false-detect rate 0.0 CI (0.0, 0.1853)
- benign FP/client-hour: {'fp_windows': 0, 'client_hours': 1.0143, 'fp_per_client_hour': 0.0}
- held-out families (policy, per group): {'padded_flood': {'groups': 1, 'detected': 1}, 'slowread': {'groups': 1, 'detected': 0}, 'credstuff': {'groups': 6, 'detected': 6}}
- in-distribution trained families: {'scraper': {'groups': 1, 'detected': 1}, 'subthreshold_flood': {'groups': 1, 'detected': 1}}
- exact-invariance probe gate: True

## Variant comparison — held-out detection vs benign FP (the size shortcut)

| variant | held-out groups detected | benign FP/client-hr | GRU vs baseline (held-out) |
|---|---|---|---|
| default | 1/8 | 0.0 | GRU 1/8 vs HGB 3/8 |
| no_size | 7/8 | 0.0 | GRU 7/8 vs HGB 6/8 |
| no_uri | 7/8 | 9.859 | GRU 7/8 vs HGB 3/8 |
