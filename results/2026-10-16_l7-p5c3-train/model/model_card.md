# L7 GRU model card (2026-10-16)

Dataset: `/home/artur/DDoS-mitigation/code/results/2026-10-16_l7-p5c3-capture`  seed=0 epochs=25
Held-out (never trained) families: ['credstuff', 'padded_flood', 'slowread']
Policy: p > 0.95 in 3 consecutive windows.
Selection: probe gate first (exact + server_load); then max held-out groups detected s.t. benign FP/client-hour <= 1.0; tie-break lower FP then lower val loss.

## Saved model — variant `no_size_no_server_timing`
Eligible after the probe gate: ['no_size_no_server_timing'].
Caveat: one capture, one seed; confirm on another seed/capture before promotion (P6).

- benign test: 25 groups, group false-detect rate 0.0 CI (0.0, 0.1372)
- benign FP/client-hour: {'fp_windows': 0, 'client_hours': 3.414, 'fp_per_client_hour': 0.0}
- held-out benign kind (never trained, not used for selection): 1 groups, 1 flagged; FP/client-hour {'fp_windows': 385, 'client_hours': 0.1661, 'fp_per_client_hour': 2317.765}
- held-out families (policy, per group): {'slowread': {'groups': 1, 'detected': 0}, 'padded_flood': {'groups': 1, 'detected': 1}, 'credstuff': {'groups': 6, 'detected': 6}}
- in-distribution trained families: {'scraper': {'groups': 1, 'detected': 1}, 'subthreshold_flood': {'groups': 1, 'detected': 1}}
- probe gate on the saved package (exact + server_load): True

## Variant comparison — probe gate, held-out detection, benign FP

| variant | probe gate (server_load flips) | held-out groups detected | benign FP/client-hr | GRU vs baseline (held-out) |
|---|---|---|---|---|
| no_size | FAIL (0.025) | 7/8 | 0.586 | GRU 7/8 vs HGB 1/8 |
| no_size_no_server_timing | PASS (0.0) | 7/8 | 0.0 | GRU 7/8 vs HGB 1/8 |
