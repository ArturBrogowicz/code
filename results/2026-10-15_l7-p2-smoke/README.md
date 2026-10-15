# L7 shadow-engine P2 smoke (2026-10-15)

The P2 verification gate for `docs/L7_GRU_DESIGN.md` (§5.7, §8). It is a gate
artifact, not a comparison campaign. It checks the shadow scoring engine end to end
on live traffic: ingest, windows, batched scoring, decision policy, flood gating and
recording, and it checks that the recording replays to the identical decisions.

**No detection claims.** The engine scored with an **untrained**, seeded GRU package
(`untrained_pkg/`, production size 64×2, threshold 0.5). Its scores and would-bans
mean nothing about attacks; no L7 model is trained before P4. The shadow path never
bans. Recorded at branch `feat/l7-gru-design` (merge `f9d4dd5`).

**How** (`sudo ./venv/bin/python ml/smoke_l7.py --p2`, about 4 min). The daemon
ran with these settings:
* `L7_SHADOW=1`;
* `L7_RECORD` (the engine's exact input stream);
* `L7_MODEL` set to the untrained package;
* `XDP_GRU=0`, to exclude the XDP-fed GRU's known false positive.

Traffic:
* 6 legit curl clients;
* 2 bots ran a `wrk` burst at 60 s;
* a 900 B User-Agent probe at 75 s;
* the 2 *other* bots ran a ~6 s `hping3` SYN flood at 90 s, to arm the L3/L4 flood
  suppression.

## Result — P1 PASS, P2 PASS

| Check | Result |
|---|---|
| P1 transport, steady sub-threshold regime | 0 / 135 drops, 0 truncation, 0 parse errors, 6 windows filled |
| P1 transport, flood burst | 81 % dropped on the socket (peak 3778 in a 2 s interval). This is the rate rule's regime; the file sink kept every line |
| **Replay determinism** (live vs replay of `l7_record.jsonl`) | **exact**: 13/13 would-bans in the same order with the same p; polls 157/157, windows 335/335, suppressed 12/12, too short 26/26, age-gated 57/57, over threshold 314/314 |
| Flood gating observed live | 1 `suppress_on`; 12 suppressed polls; then 57 windows age-gated |
| Bans | `l4_syn` 2 (flood bots), `l7_rate` 2 (burst bots); **no** `gru` ban (`XDP_GRU=0` held); the shadow path banned nothing |
| Exact invariance probes on 155 real windows | UA swap, URI renaming, time offset: \|Δp\| = 0.0 exactly |
| Daemon CPU, scoring with a 64×2 GRU | mean 9.9 %, max 50.9 % of one core (P1, ingest only: 4.6 %) |

Reproduce the replay check from the published files (exit 0 = match):

    ./venv/bin/python ml/replay_l7.py l7_record.jsonl --model untrained_pkg \
        --compare-live ban_events.jsonl

The CLI cuts the replay at the last poll that a written summary covers. The daemon is
stopped with SIGKILL, so its exit summary is never written; 2 of the 949 recorded lines
fall after that point.

## Readings

**Would-bans on all 6 benign clients are expected [FACT, mechanics only].** The
untrained model's scores cluster just above its 0.5 threshold (314 of 335 windows were
"over"). This shows the would-ban path works. It also shows why a model is promoted
only after calibration and the P4/P5 gates.

**Robustness probes need |Δp| as well as flip rates [FINDING for P4].** With 1 kB of
padding, `pad_request` flips 91 % of the decisions, but the largest score change is only
0.015. The flips come from scores sitting at the threshold, not from size sensitivity.
P4 must therefore judge robustness on the |Δp| distribution *and* on flips at the
calibrated threshold. (`iat_jitter`: 0 flips, max |Δp| 1.2e-4.)

**Feature review [FACT, `windows.csv`].** Per-class medians of the window summaries
(332 benign windows from 6 IPs; 3 attack windows from 2 IPs — the burst bots were
banned within a second):

| Feature (window median) | attack (wrk burst) | benign (curl) | Reading |
|---|---|---|---|
| `log_rate` | 9.90 | 0.37 | behavioural: strong signal |
| `log_iat_mean` | 0.00 | 1.14 (≈ 2 s) | behavioural: strong signal |
| `log_rlen_mean` | 3.56 (≈ 34 B) | 4.29 (≈ 72 B) | **tool fingerprint**: the XDP model's shortcut is still present in the traffic |
| `new_conn_mean` | 0 (keep-alive) | 1 (one-shot) | **tool fingerprint**: every benign client is a one-shot curl |
| `uri_distinct_ratio` | 0.05 | 0.05 | no signal: a one-path app |

The behavioural features separate the two classes. But the current testbed traffic
also carries two client-tool fingerprints that an L7 model would learn exactly as the
XDP model did, and URIs carry nothing. This is direct evidence that P3's benign and
attack diversity requirements are needed:
* randomised request sizes;
* keep-alive and HTTP/2 benign sessions;
* a multi-path application (`docs/L7_GRU_DESIGN.md` §5.4, §6.2).

## Files
* `summary.json`: all metrics, the time series and the P2 analysis.
* `ban_events.jsonl`: the daemon's events (`l7_shadow`, `l7_gru_poll`, `l7_would_ban`,
  `suppress_on/off`, bans).
* `l7_record.jsonl`: the engine's exact input (949 lines: request records and poll
  ticks with flood state and banned IPs). It contains the testbed's raw URIs and
  User-Agents.
* `windows.csv`: one feature summary per scored window.
* `probes.json`: the invariance-probe report.
* `untrained_pkg/`: the untrained model package used live (weights SHA-256 in
  `config.json`).
* `console.log`: the run's console output.
