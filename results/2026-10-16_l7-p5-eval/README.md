# L7 GRU online evaluation (shadow) — P5 (2026-10-16)

The P5 evaluation for `docs/L7_GRU_DESIGN.md` §7.1. The L7 GRU ran in **shadow mode**: it
scored requests and logged `l7_would_ban`, and never banned. The deterministic engines did
the real banning, as in production, with `XDP_GRU=0`. Four runs on the namespace testbed
(`ml/eval_l7.py`, branch `feat/l7-gru-design` at `ca5d46c`), judged by the
**pre-registered** verdict rule of §7.1 (`ml/p5_report.py`).

| Run | Config | Purpose |
|---|---|---|
| A | full mix, `no_size` candidate (`results/2026-10-15_l7-p4-train/model`), seed 1 | H1, H1b |
| B | full mix, `with-size` model (`models/with_size/`), seed 1 | H2 (fingerprint online) |
| C | benign soak, 10 min + one SYN flood, candidate | H3 (benign FP, suppression) |
| D | as A, seed 2 | reproducibility |

## Verdict — marginal value NOT shown in this testbed

Per family, deterministic engines vs the L7 GRU (would-ban), runs A and D (identical):

| Family | Deterministic | L7 GRU (shadow) | GRU time to detect |
|---|---|---|---|
| sub-threshold floods (2 IPs) | not banned | **2/2** | ~3–4 s |
| scraper | not banned | **1/1** | ~3 s |
| padded flood (held-out) | not banned | **1/1** | ~3.5 s |
| credential stuffing (held-out) | banned (`l7_rate`, error-ratio branch) | — (rule fired first) | — |
| slow families (3, held at 6 connections) | not banned | not flagged | — |
| volumetric flood | banned (`l4_syn`) | — | — |
| **benign (12 clients)** | — | **0 false positives** | — |

The GRU did what the design asked of it: it flagged every fast sub-threshold attacker the
deterministic engines missed, within ~3–4 s, with zero benign false positives, and the
result reproduced across seeds. Flood suppression and the age gate engaged as designed.

**But the pre-registered honest comparison (H1b) went against it.** On the recorded
requests, a static per-IP limit of **10 rps** catches 5 attacker IPs with **0 benign flagged**
— at least as many as the GRU's 4. Under the rule written before the runs, that is "no
marginal value shown" for A, B and D.

**The limitation that decides this [INFERENCE].** In this testbed no benign client exceeds
~10 rps, so a low static threshold has an easy job. Whether a learned model beats a tuned
threshold depends on legitimate traffic that *also* exceeds simple rate limits (busy NAT
gateways, asset-heavy page loads, API clients), which this benign mix does not contain at
that intensity. The defensible thesis claim is therefore: *in this testbed, the L7 GRU is not
shown to add detection value over a tuned static rate threshold.*

## Other findings

* **H3 — benign soak (run C):** 3966 windows scored over 10 minutes, **0 over threshold, 0
  benign would-bans**, including through the flood (14 suppressed polls, 120 age-gated
  windows afterwards).
* **H2 — the `no_size` choice holds online:** the `with-size` model (run B) caught the same
  attackers but produced **1 benign false positive** (the NAT-gateway client); the `no_size`
  candidate produced 0 in runs A, C and D.
* **Calibration gap 1 — coverage:** the three slow families, held below the SlowConn
  connection threshold, were flagged by **neither** layer. As P3 predicted (R1), the
  access-log model barely sees them; sub-threshold low-and-slow is an open gap in the
  current design.
* **Calibration gap 2 — the gate's model of the rules:** `ml/l7_traffic.calibrate()` checks
  the L7 rate ban threshold but not the rate rule's error-ratio branch, so the held-out
  credential family was in fact caught by an existing deterministic rule. Held-out families
  are reported, not enforced, by the gate; the gate should still model that branch.

## Process notes

* A first attempt at run A stopped before sending any traffic (a runner defect: a module
  global; fixed in `ea9e9c8` with a regression test). The runners also leaked their client
  namespaces because the suite's teardown does not know their names (fixed in `ca5d46c`).
  That attempt is excluded; all four published runs tore down cleanly.
* The `with-size` package is the P4 trainer's `default` variant, retrained with the same
  data, seed and settings (it reproduces the P4 offline held-out result exactly).

## Reproduce

    ./venv/bin/python ml/p5_report.py --run A=runA --run B=runB --run C=runC --run D=runD

Each `runX/summary.json` was produced by `ml/eval_l7.py`; `l7_record.jsonl.gz` is the daemon's
exact L7 engine input (gunzip for `ml/replay_l7.py` or the threshold sweep).

## Files

* `p5_report.json` / `p5_report.md` — the aggregate and the verdict per run.
* `runX/` — `summary.json` (analysis + H1b sweep), `manifest.json` (labels, schedule),
  `ban_events.jsonl` (the daemon's events), `l7_record.jsonl.gz`, `daemon.log`, `console.log`.
* `models/with_size/` — the model used in run B.
