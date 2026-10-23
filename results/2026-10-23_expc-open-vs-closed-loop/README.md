# EXP-C: the HTTP flood at the knee against a closed-loop and an open-loop attacker, ten paired blocks (2026-10-23)

The experiment of `docs/BENCHMARK_HARM_DESIGN.md` 8.5: EXP-A's design on EXP-A's server (scenario 4, the HTTP flood, at the
knee operating point, 30 s in every run) with only the attacker's load model changed, in one campaign so that drift cannot
separate the arms. Three modes (unprotected, Nginx `limit_req` / `limit_conn` only, daemon + XDP) under four load models: EXP-A's
closed-loop `wrk -t2 -c400` per bot, and the in-repo open-loop engine `bench/loadgen.py` at **125, 250 and 500 requests/s per
bot** (1,250, 2,500 and 5,000 in total over the 10 bots; 0.5, 1 and 2 x R50 of `2026-10-23_expc-r50-refinement`). Ten blocks,
`PROFILE_SEED` 101-110 (the legit clients of EXP-A's blocks 1-10), the 12 runs of a block in a random order. 120 runs,
2026-10-23 07:42-11:33 UTC, commit `20e7cb8` (tree clean).

    sudo timeout -s INT 28800 python3 eval/run_campaign.py --operating-point knee --scenarios 4 \
        --attack-duration 30 --modes unprotected,nginxlimits,xdp --runs 10 --seed-base 100 \
        --loads wrk,loadgen:125,loadgen:250,loadgen:500

All 120 runs exited 0, and afterwards no process, network namespace, bridge or listener of the testbed was left (the runner's
check after each run, and by hand); `/usr/bin/wrk` is the pinned binary. Runs took 86-105 s in every cell except the unprotected
flood at 250 and 500 per bot (median 179 s and 188 s, longest 394 s and 423 s); 3.85 h of run time in all. The watcher raised no
anomaly (a non-zero exit, a leftover, a run over 450 s, a run still going after 600 s, the runner gone).

## Fixed before the data

`docs/EXPC_PROTOCOL.md` was committed as `095684d` at 07:33 UTC, nine minutes before the campaign was created, and the analysis
tools as `92c2aef` at 07:31 UTC; the decision rule of `eval/run_level_stats.py` dates from 2026-10-20, before EXP-A. In short:

* **Outcome and contrasts.** The legit success in the suite's "during" period, as in EXP-A. Inside each load cell, `xdp - unprotected`
  and `nginxlimits - unprotected`, paired by `PROFILE_SEED`: 8 contrasts, none adjusted. A contrast is *supported* iff it has at least
  10 blocks, the 95 % t-interval of the mean block difference excludes 0, and at least 80 % of the blocks have the sign of the mean;
  otherwise *not shown*, which is not evidence of no effect.
* **A cell is harmed** iff its unprotected arm averages below 90 % over the 10 blocks; in a cell that is not harmed the contrasts are
  reported but a positive one cannot show a benefit.
* **HYP-5** (limits-only is no worse than unprotected at the same open-loop rate) is contradicted in a harmed open-loop cell iff
  `nginxlimits - unprotected` is "supported (-)". **HYP-6** (the daemon's advantage persists where the per-bot rate exceeds the
  50 rps L7 rule, which is every open-loop cell) holds in a harmed open-loop cell iff `xdp - unprotected` is "supported (+)".
* All three rates are above both per-IP rules (4.2 to 16.7 times the `limit_req` rate of 30 r/s, 2.5 to 10 times the L7 rule), so the
  experiment answers the amplification question and not the sub-threshold one.

## Result

Legit success during the attack, mean of the 10 run percentages (lowest-highest run); this and the tables below are assembled
from `analysis/*.csv` and `run_level_contrasts.csv` (the tools' own output is `analysis/summary.md` and `run_level_contrasts.md`):

| Load cell | Unprotected | Nginx limits only | Daemon + XDP |
|---|---|---|---|
| wrk, closed loop | 77.5 (64-92) | 43.2 (32-78) | 100.0 (100-100) |
| 125 per bot | 100.0 (100-100) | 100.0 (100-100) | 100.0 (100-100) |
| 250 per bot | 42.1 (31-53) | 100.0 (100-100) | 100.0 (100-100) |
| 500 per bot | 11.4 (4-19) | 100.0 (100-100) | 100.0 (100-100) |

The 8 pre-registered contrasts (`run_level_contrasts.md` has p-values and the blocks needed for 80 % power):

| Load cell | Contrast | Mean difference (pp) | 95 % t-interval | Same-sign blocks | Decision | Unprotected arm, mean % | Harm check |
|---|---|---|---|---|---|---|---|
| wrk | xdp - unprotected | +22.5 | [+16.0, +29.0] | 1.00 | supported (+) | 77.5 | harmed |
| wrk | nginxlimits - unprotected | -34.3 | [-45.4, -23.2] | 1.00 | supported (-) | 77.5 | harmed |
| loadgen125 | xdp - unprotected | -0.0 | [-0.1, +0.1] | 0.10 | not shown | 100.0 | not harmed |
| loadgen125 | nginxlimits - unprotected | +0.0 | [+0.0, +0.0] | 0.00 | not shown | 100.0 | not harmed |
| loadgen250 | xdp - unprotected | +57.9 | [+52.6, +63.2] | 1.00 | supported (+) | 42.1 | harmed |
| loadgen250 | nginxlimits - unprotected | +57.9 | [+52.6, +63.2] | 1.00 | supported (+) | 42.1 | harmed |
| loadgen500 | xdp - unprotected | +88.6 | [+84.7, +92.5] | 1.00 | supported (+) | 11.4 | harmed |
| loadgen500 | nginxlimits - unprotected | +88.6 | [+84.7, +92.5] | 1.00 | supported (+) | 11.4 | harmed |

The other outputs the design asks for, per cell and mode (the first 10 s: all clients; latency: served requests of the `perfect`
clients; the bot lines are what Nginx logged for the bot addresses, by arrival second, mean over the 30 s):

| Load cell | Mode | First 10 s, success % | p50 / p95 of the perfect clients, ms | Bot lines /s at the server | of which 503 /s | Nginx CPU % | PPS_Rx |
|---|---|---|---|---|---|---|---|
| wrk, closed loop | unprotected | 91.5 | 911 / 6269 | 1,605 | 0 | 34 | 4,540 |
| wrk, closed loop | Nginx limits only | 24.0 | 7252 / 9507 | 29,638 | 29,585 | 97 | 34,688 |
| wrk, closed loop | daemon + XDP | 100.0 | 1 / 2 | 307 | 289 | 12 | 7,874 |
| 125 per bot | unprotected | 100.0 | 2 / 25 | 1,225 | 0 | 30 | 1,445 |
| 125 per bot | Nginx limits only | 100.0 | 1 / 6 | 1,214 | 889 | 24 | 1,441 |
| 125 per bot | daemon + XDP | 99.9 | 1 / 3 | 19 | 0 | 0 | 6,027 |
| 250 per bot | unprotected | 64.6 | 1227 / 7530 | 1,634 | 0 | 72 | 13,489 |
| 250 per bot | Nginx limits only | 100.0 | 2 / 112 | 2,446 | 2,123 | 48 | 2,951 |
| 250 per bot | daemon + XDP | 100.0 | 1 / 4 | 37 | 5 | 0 | 12,186 |
| 500 per bot | unprotected | 12.2 | 1482 / 8782 | 1,601 | 0 | 83 | 36,358 |
| 500 per bot | Nginx limits only | 100.0 | 642 / 2638 | 4,859 | 4,574 | 82 | 6,263 |
| 500 per bot | daemon + XDP | 100.0 | 1 / 5 | 47 | 24 | 0 | 24,466 |

The daemon in each cell (all runs of the cell):

| Load cell | Bots banned | Time to mitigate, median (range), s | First-ban engine | GRU bans | False positives |
|---|---|---|---|---|---|
| wrk, closed loop | 100/100 | 0.23 (0.06-0.59) | l7_rate:100 | 0 | 0 |
| 125 per bot | 100/100 | 0.65 (0.56-0.89) | l7_rate:100 | 0 | 0 |
| 250 per bot | 100/100 | 0.65 (0.47-0.88) | l7_rate:100 | 0 | 0 |
| 500 per bot | 100/100 | 0.48 (0.30-0.68) | l7_rate:100 | 0 | 0 |

## What it shows

Tags: **[FACT]** read from the published files, **[ARITHMETIC]** computed from them, **[INFERENCE]** a reading of them.

1. **Three of the four cells are harmed, and the one at 125 per bot is not.** [FACT] The unprotected arm averages 77.5 % under `wrk`,
   100.0 % (every block) at 125, 42.1 % at 250 and 11.4 % at 500. At 125 nothing can show a benefit, and nothing shows a cost: all
   three modes serve every legit request in every block bar one failure of a `mobile_bad` client under the daemon.
2. **HYP-5 is not contradicted: under an open-loop attacker, limits-only is far better than unprotected.** [FACT] `nginxlimits -
   unprotected` is +57.9 pp [+52.6, +63.2] at 250 and +88.6 pp [+84.7, +92.5] at 500, supported (+) in 10 of 10 blocks both times.
   Under the closed-loop attacker it is -34.3 pp [-45.4, -23.2], supported (-) in 10 of 10 blocks. **The penalty EXP-A measured
   (-22.5 pp) does not appear with an open-loop attacker.** [INFERENCE] It belongs to the closed-loop load model and not to Nginx's
   limits as such; the evidence is one generator of each kind.
3. **The amplification is visible at the server.** [FACT] Against `limit_req`, the closed-loop flood reaches 29,638 request lines
   per second (29,585 of them 503) and `PPS_Rx` 34,688, against 1,605 and 4,540 unprotected (EXP-A: `PPS_Rx` 33,440 against 3,303);
   the open-loop floods reach their nominal rates, 1,214, 2,446 and 4,859 per second, with `PPS_Rx` 1,441, 2,951 and 6,263.
   [INFERENCE] A closed-loop client that is rejected quickly sends the next request at once; that is what the open-loop client cannot do.
4. **Why limits-only works against an open-loop flood here.** [ARITHMETIC] `limit_req` admits 30 r/s per source plus a burst of 100:
   about 330 requests/s from the 10 bots whatever they send. Nginx answered 325, 323 and 283 bot requests/s with 200 in the three
   open-loop cells and rejected the rest with 503 (889, 2,123 and 4,574 per second), which is far below what the one worker
   serves (1.84 k/s in the refinement ramp). The rejections are not free: Nginx CPU is 24, 48 and 82 % (unprotected 30, 72, 83 %),
   and at 500 per bot the perfect clients' median is 642 ms and the p95 2,638 ms, against 1 ms and 5 ms under the daemon.
5. **HYP-6 holds: the daemon's advantage persists in every harmed open-loop cell.** [FACT] `xdp - unprotected` is +57.9 pp [+52.6, +63.2]
   at 250 and +88.6 pp [+84.7, +92.5] at 500, supported (+) in 10 of 10 blocks; under `wrk` +22.5 pp [+16.0, +29.0]. The two
   mitigations are equal on availability in the open-loop cells (100 % in every block), so the identical contrasts say only that
   the ceiling was reached. They differ in latency (above) and in server load: the daemon leaves Nginx at about 0 % in the open-loop
   cells because XDP drops the bots' packets (`PreStack_Dropped` in `server.csv`).
6. **The daemon bans every bot, fast, and nobody else.** [FACT] 100 of 100 bots banned in each daemon cell, all by the L7 rate rule,
   no GRU ban, no false positive. The median time to mitigate is 0.23 s under `wrk` and 0.48 to 0.65 s under the open-loop engine.
   The two failed legit requests in the daemon cells (`xdp@loadgen125/run6`, 9.9 s after the start, and `xdp/run8`, 17.5 s) are
   timeouts of `mobile_bad` clients, not bans.
7. **The closed-loop cell agrees with EXP-A in direction, not in size.** [FACT] Daemon +22.5 pp [+16.0, +29.0] (EXP-A +33.2 [+26.1,
   +40.2]); limits-only -34.3 [-45.4, -23.2] (EXP-A -22.5 [-32.0, -13.1]); the intervals overlap. The difference is in the unprotected
   arm: 77.5 % here and 66.8 % in EXP-A, with the same legit profile in each block, and per block (here / EXP-A) 92/50, 76/63, 64/72,
   72/65, 84/78, 66/67, 72/75, 83/57, 86/81, 80/60. Limits-only (43.2 and 44.4 %) and the daemon (100 %) agree. There is no rule for
   "replicates"; the closed-loop attacker's effect on the unprotected server varies by tens of points from campaign to campaign.
8. **The open-loop generators delivered about their nominal rate where the server stayed up.** [FACT] In the limits-only cells the
   median second holds 1,250, 2,500 and 5,002 request lines and the mean 97 % of nominal (the shortfall is the second in which
   the generators start). Above the server's limit the log is a floor (unprotected at 250 and 500: 1,634 and 1,601 per second).
9. **A flood that harms the server costs minutes to clean up.** [FACT] In the unprotected cells at 250 and 500 per bot, the runs whose
   post-attack check of 15 legit requests passed 15 of 15 took 90-116 s; those that did not took 127-423 s, and the five with 0 of 15
   took 394-423 s.

## What it does not show

* **The sub-threshold question.** Every rate is above both per-IP rules; a flood below 30 r/s per source, or from many more
  sources, needs another experiment (design section 9).
* **That limits-only is a defence in general.** The open-loop attacker does not adapt; what an adaptive botnet does, and whether the
  closed-loop `wrk` or the constant-rate engine is the better model of one, is a modelling question for the thesis. The result is
  that the measured penalty depends on that choice.
* **A ranking of the two mitigations on availability** in the open-loop cells: both reached 100 % in every block.
* One VM, one 30 s flood, one legit population per block (seeds 101-110), a request about 35 bytes larger than `wrk`'s, constant
  schedules. The generators' own counts are not recorded; above the server's limit what they sent is unknown.
* The 90 % harm threshold is the protocol's, set before the data; the 8 contrasts are not adjusted for their number.

## Files

`campaign.json` and the 12 cell directories (`<mode>[@loadgen<rate>]/run<k>/`, with `server_requests.csv` and, for the daemon runs,
`ban_events.jsonl` and `daemon.log`); `analysis/` (`summary.md`, the CSVs, `figures/availability_<scenario>__<cell>.png` per cell and
`ttm.png`); `run_level_contrasts.md` and `.csv`; `SHA256SUMS`.

## Reproduce

    venv/bin/python eval/analyze_campaign.py results/2026-10-23_expc-open-vs-closed-loop --window 10
    venv/bin/python eval/run_level_stats.py results/2026-10-23_expc-open-vs-closed-loop \
        --md results/2026-10-23_expc-open-vs-closed-loop/run_level_contrasts.md \
        --csv results/2026-10-23_expc-open-vs-closed-loop/run_level_contrasts.csv
    git status        # clean: the analysis and the contrasts regenerate byte for byte
    cd results/2026-10-23_expc-open-vs-closed-loop && sha256sum -c SHA256SUMS

The compact tables of this README are assembled from those files and are not part of the tools' output.
