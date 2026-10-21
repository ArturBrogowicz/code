# Full suite, default settings, XDP mode, after the 2026-10-19 default changes

One run of all 10 scenarios in XDP mode with every setting at its default (`OPERATING_POINT=default`,
gunicorn 8x4, `wrk -c50`, 5 bots, no CPU pinning, `PROFILE_SEED=0`, historical exposure), recorded
2026-10-20 14:01-14:12 UTC by `eval/run_campaign.py` at commit `618b2fc` (branch
`feat/audit-must-do-2-5`, tree clean) on the namespace testbed.

    sudo python3 eval/run_campaign.py --modes xdp --runs 1 --seed-base=-1

(`--seed-base=-1` makes `PROFILE_SEED` 0, the seed of the baseline run below.)

This is the post-change run that the README of `../2026-10-19_baseline-before-audit-defaults/`
announces as still to be recorded: the first complete ten-scenario run on the change set of
2026-10-19 (`XDP_GRU` default 0, no syslog sink in the default nginx confs, the XDP `ihl` check, the
LRU telemetry map; `docs/EVALUATION.md`, "Defaults changed on 2026-10-19"). Against the baseline run
the daemon's `start` events differ in `xdp_gru` (`false`; the baseline had `true`) and in the XDP
program (`1f9e8606...`; baseline `dc215f94...`). The model (`4b8bb940...`), `L7_SHADOW` (off) and the
heuristic profile (`default`) are the same. In `control_plane.py` the change set touches only the
`XDP_GRU` default, so the L4 and L7 rules are the ones of the baseline; commit `618b2fc` also carries
the audit tooling of its branch, whose only change to the daemon is a comment.

**Host state.** The VM had been started at 13:57 UTC, three minutes before the campaign (load average
1.32 at its start, cold page cache). The earlier runs below were taken on warm hosts.

Result: 10/10 PASS. Five of five bots were banned in every scenario, by the same engine(s) as in each
of the three earlier runs; no legitimate client was banned (`FP_IPs` empty), no ban was left
unenforced, there is no GRU event, and the HTTP check from 15 sampled legitimate clients after each
scenario passed (15/15). Legit success was 100 % before, during and after the attack in all 10 scenarios
(19-119 requests per scenario in the "during" window).

## Next to the three earlier runs of the same suite

R2 is `../2026-10-13_regression-default-full-suite/` (`efc5994`, 2026-10-13 08:53), the replicate
`../2026-10-13_regression-default-full-suite-replicate/` (`31058e0`, 14:36), the baseline
`../2026-10-19_baseline-before-audit-defaults/` (`5611d8c`, 2026-10-19 15:32), "after" this run. All
four used the same suite settings and `PROFILE_SEED = 0`.

**Bots banned** (a ! marks a legitimate client banned or a failed legit HTTP check)

| Scenario | R2 | replicate | baseline | after |
|---|---|---|---|---|
| Distributed SYN Flood | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Low & Slow SYN | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed UDP Flood | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed HTTP Flood | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed ACK Flood | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed IP Fragmentation Flood | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Slowloris | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed R.U.D.Y. | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Yo-Yo | 5/5 | 5/5 | 5/5 | 5/5 |
| Multi-Vector Distributed Attack | 5/5 | 5/5 | 5/5 | 5/5 |

Scenarios with every bot banned: R2 10/10, replicate 10/10, baseline 10/10, after 10/10.

**Engines that banned the bots**

| Scenario | R2 | replicate | baseline | after |
|---|---|---|---|---|
| Distributed SYN Flood | L4 SYN | L4 SYN | L4 SYN | L4 SYN |
| Distributed Low & Slow SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN |
| Distributed UDP Flood | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric |
| Distributed HTTP Flood | L7 rate | L7 rate | L7 rate | L7 rate |
| Distributed ACK Flood | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric |
| Distributed IP Fragmentation Flood | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric |
| Distributed Slowloris | L4 SlowConn | L4 SlowConn | L4 SlowConn | L4 SlowConn |
| Distributed R.U.D.Y. | L4 SlowConn | L4 SlowConn | L4 SlowConn | L4 SlowConn |
| Distributed Yo-Yo | L7 rate | L7 rate | L7 rate | L7 rate |
| Multi-Vector Distributed Attack | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 |

**Exact time to mitigate, seconds (median / max over the bots)**

| Scenario | R2 | replicate | baseline | after |
|---|---|---|---|---|
| Distributed SYN Flood | 0.50 / 0.50 | 0.96 / 1.97 | 1.23 / 1.23 | 1.56 / 1.56 |
| Distributed Low & Slow SYN | 3.98 / 3.98 | 3.95 / 3.95 | 3.81 / 3.81 | 3.54 / 3.54 |
| Distributed UDP Flood | 0.48 / 0.48 | 0.74 / 0.74 | 0.81 / 0.81 | 0.78 / 0.78 |
| Distributed HTTP Flood | 0.55 / 0.78 | 0.69 / 0.75 | 0.68 / 0.72 | 1.08 / 1.13 |
| Distributed ACK Flood | 0.97 / 0.97 | 1.06 / 1.06 | 0.88 / 0.88 | 0.89 / 0.89 |
| Distributed IP Fragmentation Flood | 0.49 / 0.49 | 1.25 / 1.25 | 0.83 / 0.83 | 0.97 / 0.97 |
| Distributed Slowloris | 3.72 / 3.75 | 3.63 / 3.66 | 3.72 / 3.74 | 3.55 / 3.57 |
| Distributed R.U.D.Y. | 3.57 / 3.60 | 3.70 / 3.73 | 3.88 / 3.91 | 4.64 / 4.66 |
| Distributed Yo-Yo | 0.52 / 0.59 | 0.57 / 0.72 | 0.53 / 0.59 | 0.57 / 0.80 |
| Multi-Vector Distributed Attack | 0.84 / 0.84 | 0.60 / 0.60 | 0.43 / 1.46 | 0.48 / 1.50 |

**Exact time to mitigate by engine, over every bot of every run above (seconds)**

| Engine | Bots | Min | Median | Max |
|---|---|---|---|---|
| L4 low-SYN | 20 | 3.54 | 3.88 | 3.98 |
| L4 SlowConn | 40 | 3.52 | 3.70 | 4.66 |
| L4 SYN | 24 | 0.50 | 1.23 | 1.97 |
| L4 volumetric | 72 | 0.43 | 0.83 | 1.25 |
| L7 rate | 44 | 0.06 | 0.57 | 1.13 |

Times to mitigate are the exact ones from the ban events (first `ban` of a bot minus the attack start
the harness records), in seconds.

* **Same engines, same bounds.** Every scenario was banned by the same engine(s) in all four runs.
  Over the four runs the bound per rule is 0.06-1.13 s for the L7 rate rule, 0.43-1.25 s for L4
  volumetric and 0.50-1.97 s for L4 SYN; the two rules that wait for consecutive polls need 3.54-3.98 s
  (L4 low-SYN, four polls) and 3.52-4.66 s (L4 SlowConn, three polls).
* **R.U.D.Y. is the value outside the earlier range**: 4.64 s median against 3.57-3.88 s. That is one
  polling interval more [INFERENCE: the first interval after the sockets connect carries the POST
  headers, which is more than the 250 bytes per interval that SlowConn counts as idle, and where the
  connect falls in the 1-s poll decides whether that interval and the next one count]. One run shows
  no more than phase.
* **The HTTP flood took 1.08 s** (median over the 5 bots; per bot 0.37-1.13 s) against 0.55-0.69 s in the
  three earlier runs. The daemon's L7 rule is unchanged, and the one nginx change (the syslog sink,
  which has no listener while `L7_SHADOW` is off, is gone from the default conf) removes work from
  the request path. The host was three minutes old; one run cannot separate warm-up from phase.

### Pre-stack drop of the open-loop floods

Post-ban and sustained phases of the four volumetric scenarios (`metrics.csv`; the 0.5 M pps filter keeps
only the flood phases): packets arriving on the server interface, packets reaching the IP layer, and
the share of arriving packets that XDP did not count as dropped.

| Scenario | `PPS_Rx` | `IP_InReceives` (max) | `PPS_Rx` - `PreStack_Dropped` (max, share of `PPS_Rx`) |
|---|---|---|---|
| UDP flood | 1.35-1.45 M/s | 176 /s | 0.012 % |
| ACK flood | 1.39-1.49 M/s | 164 /s | 0.011 % |
| IP fragmentation flood | 1.53-1.81 M/s | 214 /s | 0.012 % |
| Multi-vector | 0.85-0.89 M/s | 165 /s | 0.019 % |

R2 had at most 227 packets/s at the IP layer on 0.84-1.66 M/s arriving (`docs/THESIS_CLAIMS.md`, M2).

## What this run does not show

* It is one run. A time to mitigate needs a bound per rule, not a single number (see the bounds table).
* At the default operating point legit success is 100 % without any mitigation as well (the addendum
  reports it for the unprotected mode [CLAIMED]), so "mitigated" here means "banned". Where the service
  suffers is the knee, `../2026-10-20_expa-knee-10-blocks/`.

## Check and reproduce

    cd results/2026-10-20_regression-after-audit-defaults && sha256sum -c SHA256SUMS
    ./venv/bin/python eval/suite_compare.py R2=results/2026-10-13_regression-default-full-suite \
        replicate=results/2026-10-13_regression-default-full-suite-replicate \
        baseline=results/2026-10-19_baseline-before-audit-defaults \
        after=results/2026-10-20_regression-after-audit-defaults
    ./venv/bin/python eval/analyze_campaign.py results/2026-10-20_regression-after-audit-defaults   # rewrites analysis/ with identical bytes
