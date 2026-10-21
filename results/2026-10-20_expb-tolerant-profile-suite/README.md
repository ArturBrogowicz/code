# EXP-B: the unchanged suite under the tolerant heuristic profile (2026-10-20)

Three runs of all 10 scenarios in XDP mode with `HEURISTIC_PROFILE=tolerant`, recorded
2026-10-20 14:14-14:47 UTC by `eval/run_campaign.py` at commit `618b2fc` (tree clean), `PROFILE_SEED`
201-203, every other setting at the suite's default.

    sudo env HEURISTIC_PROFILE=tolerant python3 eval/run_campaign.py --modes xdp --runs 3 \
        --seed-base 200 --out /var/tmp/ddos_campaigns/20261020_tolerant-suite

`campaign.json` does not record the profile. The daemon's `start` event does (`heuristic_profile:
"tolerant"`, `slowconn_conns: 180`, `l7_max_rps: 108` in the first event of each run), and so does the
directory name of the source.

The tolerant profile (`docs/L7_GRU_DESIGN.md` 7.3.3) raises two thresholds of the daemon: SlowConn from
8 to 180 concurrent connections per IP, and the L7 rate rule from 50 to 108 requests/s. It exists
because realistic benign clients exceeded the defaults: P5c.1 recorded three false bans under the
default thresholds (a browser with a 60-asset page by the rate rule, two CGNAT gateways by SlowConn;
`../2026-10-16_l7-p5c-baseline/`). The suite's Nginx keeps its own limits (30 r/s), so only these two
daemon thresholds differ here.

**Why this run.** `docs/L7_GRU_DESIGN.md` 7.3.5 announced a table of what the relaxation costs in
security, and none was produced (second audit, G-09). This is that table for the suite's ten attacks.

**Prediction, written down before the run** (audit report, EXP-B): Slowloris and R.U.D.Y. drop below
5/5 banned, because 8 and 10 sockets per bot are below the SlowConn threshold of 180, and every other
scenario stays at 5/5. Any other drop would be reported as unexpected.

## Result: the prediction held

Bots banned out of 5, per scenario: the four default-profile runs of the suite (R2, the replicate, the
baseline and the post-change run of `../2026-10-20_regression-after-audit-defaults/`) next to the three
runs of this campaign.

**Bots banned** (a ! marks a legitimate client banned or a failed legit HTTP check)

| Scenario | R2 | replicate | baseline | after | tolerant/run1 | tolerant/run2 | tolerant/run3 |
|---|---|---|---|---|---|---|---|
| Distributed SYN Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Low & Slow SYN | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed UDP Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed HTTP Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed ACK Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed IP Fragmentation Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Slowloris | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 |
| Distributed R.U.D.Y. | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 |
| Distributed Yo-Yo | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Multi-Vector Distributed Attack | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |

Scenarios with every bot banned: R2 10/10, replicate 10/10, baseline 10/10, after 10/10, tolerant/run1 8/10, tolerant/run2 8/10, tolerant/run3 8/10.

* **Slowloris and R.U.D.Y.: 0 of 5 bots banned in all three runs** (0 of 15 each; no engine acted). The
  suite marks both FAIL (it asks for 80 % banned). In the four default-profile runs both were 5/5, after
  3.52-4.66 s.
* **The other eight scenarios: 5 of 5 in all three runs** (120 of 120 bots), by the same engines as in the
  default-profile runs. No unexpected drop.
* No false positive. The legit HTTP check passed (15/15) in all ten scenarios of all three runs, and legit
  success was 100 % before, during and after every scenario.
* During the two unbanned attacks the legitimate clients were not affected (1019 and 1000 requests, all
  served) while the attacks ran for about 41 s. What the profile costs here is a missed
  detection, not an observed loss of service: the testbed's Nginx (client timeouts, body limit) neutralises
  both attacks by itself [CLAIMED: `docs/REPORT.md` F-10; this campaign shows only that legitimate clients
  were not hurt].
* The times to mitigate of the eight banned scenarios are those of the default profile. One bot is an
  outlier: the SYN bot of the multi-vector scenario took 3.82 s in run 2 (0.61 and 0.76 s in the other two
  runs), the largest time of any flood rule in a complete suite run so far [INFERENCE: it competes with a 0.85 M pps
  flood for the server's CPUs; not examined].

**Exact time to mitigate, seconds (median / max over the bots)**

| Scenario | tolerant/run1 | tolerant/run2 | tolerant/run3 |
|---|---|---|---|
| Distributed SYN Flood | 0.97 / 0.97 | 0.92 / 0.92 | 1.19 / 1.19 |
| Distributed Low & Slow SYN | 3.99 / 3.99 | 3.46 / 3.46 | 3.70 / 3.70 |
| Distributed UDP Flood | 0.73 / 0.73 | 1.18 / 1.18 | 1.01 / 1.01 |
| Distributed HTTP Flood | 0.66 / 0.72 | 0.67 / 0.80 | 0.63 / 0.76 |
| Distributed ACK Flood | 0.58 / 0.59 | 1.12 / 1.12 | 1.00 / 1.00 |
| Distributed IP Fragmentation Flood | 0.98 / 0.98 | 0.51 / 0.51 | 0.54 / 0.54 |
| Distributed Slowloris | — | — | — |
| Distributed R.U.D.Y. | — | — | — |
| Distributed Yo-Yo | 0.28 / 0.56 | 0.70 / 0.89 | 0.76 / 0.81 |
| Multi-Vector Distributed Attack | 0.61 / 0.61 | 0.41 / 3.82 | 0.76 / 0.77 |

**Exact time to mitigate by engine, over every bot of every run above (seconds)**

| Engine | Bots | Min | Median | Max |
|---|---|---|---|---|
| L4 low-SYN | 15 | 3.46 | 3.70 | 3.99 |
| L4 SYN | 18 | 0.61 | 0.97 | 3.82 |
| L4 volumetric | 54 | 0.41 | 0.76 | 1.18 |
| L7 rate | 33 | 0.11 | 0.61 | 0.89 |

## What it shows and what it does not

* The cost is the predicted one and it is deterministic: an IP that holds up to 179 mostly idle
  connections is invisible to SlowConn under this profile, and the suite's slow attacks hold 8 and 10
  (`test_distributed_suite.py` lines 1560 and 1603). Three runs confirm what the code implies; they do
  not measure anything beyond these two attacks.
* It does not measure what the profile gains. The suite's benign clients are `curl`; the three false
  bans it removes were recorded in P5c.1 with realistic clients, not here.
* It does not show whether a slow attack that Nginx's own limits do not stop would harm the service: none
  of the suite's attacks does.

## Check and reproduce

    cd results/2026-10-20_expb-tolerant-profile-suite && sha256sum -c SHA256SUMS
    ./venv/bin/python eval/suite_compare.py tolerant=results/2026-10-20_expb-tolerant-profile-suite
    ./venv/bin/python eval/analyze_campaign.py results/2026-10-20_expb-tolerant-profile-suite   # rewrites analysis/ with identical bytes
