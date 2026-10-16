# P5c.3 training — L7 GRU on the full realistic mix (2026-10-16)

Offline, CPU. `ml/train_l7.py` on `results/2026-10-16_l7-p5c3-capture` (gunzip its
`access.log.gz` first), seed 0, 25 epochs, branch `feat/l7-benign-overlap` at `d8bcf90`:

    ./venv/bin/python ml/train_l7.py results/2026-10-16_l7-p5c3-capture \
        --out results/2026-10-16_l7-p5c3-train/model --seed 0 --epochs 25 \
        --report results/2026-10-16_l7-p5c3-train/l7_metrics.json \
        --variants no_size no_size_no_server_timing

## Candidate — `no_size_no_server_timing` [FACT, `model/model_card.md`]

* **Probe gate PASS**, including the strict `server_load` probe (R17) and `pad_request`
  (0 flips: size-invariant, R4).
* **Held-out attack families:** credstuff 6/6, padded_flood 1/1, slowread 0/1 (R1: the
  access log barely sees it). Trained families: subthreshold_flood and scraper detected.
* **Benign test IPs:** 0 false positives (0.0 per client-hour, 25 groups).
* **Held-out benign kind (`api_bulk`, never trained): flagged** (R16). It counts against
  the 5 % benign budget in the P5c.4 verdict.
* GRU 7/8 held-out groups vs the HGB tabular baseline 1/8; the HGB is saved beside the
  package (`baseline_hgb.*`) for baseline B4.

## How the variant was chosen

The first run trained all five variants (`all_variants/`). The strict gate rejected the
three that read server timing; the selection rule then picked `no_server_timing`, which
reads request size and fails `pad_request` (5.05 % flips). That conflicted with the standing
`no_size` decision (§7.2, R4), so — after training, before any evaluation data — P5c.3 was
restricted to the `no_size` family (`docs/L7_GRU_DESIGN.md` §7.3.4). The retrained
`no_size_no_server_timing` reproduces its five-variant numbers exactly (same validation
loss, 0.17387).

## Files

`model/` (package, model card, HGB baseline), `l7_metrics.json`, `train.log`,
`all_variants/` (the five-variant run's metrics and card; its package was not kept).
