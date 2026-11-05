# EXP-C probe, refinement ramp: R50 on the nominal axis (2026-10-23)

The second part of `2026-10-22_expc-r50-probe/`. Its pre-registered rule, "if the bracketing runs differ by more than 40 pp, a
three-rate refinement ramp is proposed", applied: 160 per bot gave 100 % and 320 gave 19.7 %. Amendment A, written before this
ramp, reads R50 on the nominal axis. The **unprotected** server at the knee operating point under scenario 4 (HTTP flood) for
30 s, `PROFILE_SEED` 101, the open-loop engine `bench/loadgen.py` at **190, 230 and 270 requests/s per bot** (log-spaced between
160 and 320: 160 x 2^(k/4), rounded to a multiple of 10), one run each. A probe: no replicates, no mitigation.

## What was run

    sudo timeout -s INT 1800 python3 eval/run_campaign.py --operating-point knee --scenarios 4 \
        --attack-duration 30 --modes unprotected --runs 1 --seed-base 100 --loads loadgen:190,loadgen:230,loadgen:270

Campaign `20261023T070019Z_knee_s4` in `campaigns/`, commit `cdf5606` (tree clean), 2026-10-23 07:00-07:05 UTC. The runs went in the order 190, 270,
230 (`--order-seed 0`) and exited 0 in 98.7, 112.9 and 101.5 s with no leftover: the runner's check after each run, and by hand
afterwards (no process, network namespace, bridge or listener of the testbed; `/usr/bin/wrk` is the pinned binary). The suite
includes the label fix `78122bc`: its own "before" period is 100 % in all three runs (n = 35, 37 and 34), where the probe's 320 and
640 read 79.6 % and 71.2 %. The `console.log` files have their ANSI colour codes stripped; the generators' working directories
under `attackers/` stayed empty and are not copied.

## Fixed before the data

Amendment A (`docs/EXPC_ATTACKER_SETTING_DESIGN.md`, section 6) is **post hoc** with respect to the first part, whose pre-registered
reading used the measured offered rate; it was written after those eight runs and committed as `cdf5606` at 2026-10-23 06:59:54 UTC,
25 s before this campaign was created: the axis is the nominal total rate; the outcome is the legit success in the first 30 s from `Attack_Start`
(`availability_raw.csv`); R50 is interpolated linearly in log-rate between the two adjacent rates of the ladder 20, 40, 80, 160,
190, 230, 270, 320, 640 per bot, the lower with 50 % or more and the higher below; none is computed if the ladder is not monotone;
the three EXP-C rates are fixed by the user afterwards. The rates 190, 230 and 270 were proposed on 2026-10-22 and approved as
proposed. `eval/expc_probe.py --r50` (`2efb7e4`) was written after the ramp, from that text, which leaves nothing to choose; a hand
calculation from the same two points gives the same value.

## Result

All open-loop runs of both parts, one run per rate (bold: this campaign; Wilson score intervals with z = 1.96 treat requests as
independent, so they are descriptive; "logged" is what nginx wrote down per second, by arrival):

| Per bot | Nominal /s | Legit success | Wilson 95 % | Logged /s | Served 200 /s | p50 / p95 of the answered, ms |
|---|---|---|---|---|---|---|
| 20 | 200 | 100.0 % (246 of 246) | 98.5-100.0 | 195 | 195 | 3 / 556 |
| 40 | 400 | 100.0 % (252 of 252) | 98.5-100.0 | 390 | 390 | 3 / 547 |
| 80 | 800 | 100.0 % (251 of 251) | 98.5-100.0 | 782 | 782 | 7 / 607 |
| 160 | 1,600 | 100.0 % (178 of 178) | 97.9-100.0 | 1,587 | 1,505 | 731 / 3024 |
| **190** | 1,900 | **100.0 % (215 of 215)** | 98.2-100.0 | 1,842 | 1,842 | 572 / 1212 |
| **230** | 2,300 | **65.3 % (64 of 98)** | 55.5-74.0 | 1,897 | 843 | 1270 / 8144 |
| **270** | 2,700 | **36.0 % (27 of 75)** | 26.1-47.3 | 1,710 | 394 | 1555 / 1831 |
| 320 | 3,200 | 19.7 % (12 of 61) | 11.6-31.3 | 1,569 | 98 | 7648 / 9765 |
| 640 | 6,400 | 1.8 % (1 of 57) | 0.3-9.3 | 1,253 | 8 | - |

R50 (amendment A, nominal total rate, linear in log-rate between 2300 requests/s at 65.3 % and 2700 at 36.0 %): 2501 requests/s, 250 per bot. 0.5, 1 and 2 x that, per bot: 125, 250, 500.

The three runs of this campaign in full (`ladder.md` and `ladder.json` hold every run of both parts, with the bot requests of each
second in `ladder.json`):

Load the server received from the bots, by arrival, in the first 30 s of the attack (`Offered` counts every request line of a bot address, `Served` those with status 200; the median leaves out the first second, in which the generators start):

| Campaign | Run | Flood | Nominal /s | Offered /s | Offered /s, median | Served /s | Other statuses | Run time s |
|---|---|---|---|---|---|---|---|---|
| `20261023T070019Z` | `unprotected@loadgen190/run1` | loadgen, 190/s per bot | 1900 | 1842 | 1908 | 1842 | - | 99 |
| `20261023T070019Z` | `unprotected@loadgen230/run1` | loadgen, 230/s per bot | 2300 | 1897 | 2121 | 843 | 499: 8309, 502: 163, 504: 23172 | 102 |
| `20261023T070019Z` | `unprotected@loadgen270/run1` | loadgen, 270/s per bot | 2700 | 1710 | 1558 | 394 | 499: 10107, 502: 64, 504: 29328 | 113 |

What the legit clients saw in the same 30 s, from their own records (percentiles only from 10 or more successes):

| Campaign | Run | Legit n | Success % | Timeouts % | Before the start, success % (n) | First 5 s, % | Last 10 s, % | p50 ok ms | p95 ok ms |
|---|---|---|---|---|---|---|---|---|---|
| `20261023T070019Z` | `unprotected@loadgen190/run1` | 215 | 100.0 | 0.0 | 100.0 (34) | 100.0 | 100.0 | 572 | 1212 |
| `20261023T070019Z` | `unprotected@loadgen230/run1` | 98 | 65.3 | 16.3 | 100.0 (37) | 97.1 | 46.7 | 1270 | 8144 |
| `20261023T070019Z` | `unprotected@loadgen270/run1` | 75 | 36.0 | 52.0 | 100.0 (34) | 75.9 | 0.0 | 1555 | 1831 |

## What it shows

Tags: **[FACT]** read from the published files, **[INFERENCE]** a reading of them, **[UNKNOWN]** not recorded.

1. **R50 is defined on the nominal axis, at 2,501 requests/s in total (250 per bot), and the transition is a slope.** [FACT] The
   legit success is 100 % up to 190 per bot, then 65.3, 36.0, 19.7 and 1.8 % at 230, 270, 320 and 640; the crossing lies between
   230 and 270. The probe's two points (160 and 320) suggested a cliff; with three more they show a steep step between 190 and 230
   (-35 pp) and a slower decline after it (-29, -16 and -18 pp). With one run per rate and 57 to 98 legit requests behind each
   overloaded point, the shape between neighbours is not resolved.
2. **The server's limit is above 1.84 k requests/s.** [FACT] At 190 per bot it answered 55,265 requests with 200 in 30 s (1,842 per
   second, 97 % of nominal; the median second is 1,908), every one of 215 legit requests succeeded, at a median of 572 ms and a p95 of
   1,212 ms. This corrects the probe README's reading that about 1.5 k requests/s is what one worker serves: the 160 run served what
   it was offered (`results/README.md`, Errata).
3. **Past that limit the goodput falls as the load rises.** [FACT] Requests answered with 200 per second: 1,842 (190), 843 (230),
   394 (270), 98 (320), 8 (640). At 270, 11,809 requests got 200 in 30 s and 39,499 ended in 499, 502 or 504 (230: 25,279 and
   31,644). [INFERENCE] Overload spends the one worker on requests whose clients have given up, which is why the legit success falls
   as fast as it does; this probe does not test it.
4. **The collapse starts later the lower the load.** [FACT] Legit success in the first 5 s and in the last 10 s: 230: 34 of 35 and
   7 of 15; 270: 22 of 29 and 0 of 12; (probe) 320: 4 of 21 and 8 of 17; 640: 1 of 20 and 0 of 17. The bots' logged requests per
   second follow the nominal rate for the first seconds and then thin out, from about second 18 at 230 and second 10 at 270 (probe:
   about 6 at 320 and 4 at 640; the arrays are in `ladder.json`). [INFERENCE] A backlog grows at a rate set by the excess over the
   limit, and the log holds what finished.
5. **The logged rate is a floor from 230 per bot on.** [FACT] The mean logged rate is 97, 82 and 63 % of nominal at 190, 230 and 270
   (1,842, 1,897 and 1,710 per second; probe: 49 % at 320 and 20 % at 640). Below the limit it is exact: the median second is 100.4 %
   of nominal at 190.
6. **Latency separates the loads long before the success does.** [FACT] The median of the answered legit requests is 3 ms at 20 and
   40 per bot, 7 ms at 80, then 731 ms (160), 572 ms (190), 1,270 ms (230) and 1,555 ms (270): two orders of magnitude between 80 and
   160, where the success is still 100 %.
7. **What the server's one-second samples show.** [FACT] In the sample taken at the end of the flood (`metrics.csv`, "Phase 3"): packets
   per second at the server 2.1 k (190), 23.8 k (230), 28.4 k (270); Nginx CPU 45.8, 89.8 and 100.5 %; established connections 5,847,
   20,541 and 17,252; CPU 0 at 100 % in the samples of all three runs. The step in packets, about eleven times between 190 and 230,
   coincides with the step in the goodput.
8. **The server recovered.** [FACT] The post-attack check of 15 legit samples passed 15 of 15 in all three runs, and the runs took 99 to
   113 s, where the probe's 640 run failed 15 of 15 and took 395 s.

## For EXP-C

Amendment A's default is 0.5, 1 and 2 x R50, split over the 10 bots: **125, 250 and 500 requests/s per bot** (1,250, 2,500 and 5,000 in
total). 125 lies between the 80 (7 ms) and 160 (731 ms) runs, 250 inside the transition (65.3 % at 230, 36.0 % at 270), 500 beyond 320
(19.7 %) and short of 640 (1.8 %). The user fixes the three rates; nothing is decided here.

## Limits

* One run per rate, one legit profile seed (101), one 30 s window. R50 places the cells and carries no interval; the spread between
  runs of one overloaded cell is unknown (EXP-A's closed-loop unprotected arm gave 50 to 81 % in ten blocks). The step from 190 to 230
  rests on two runs.
* R50 belongs to this server, this legit population and this duration: a longer flood gives a backlog more time, so [INFERENCE] the
  crossing would move to a lower rate.
* The logged rate is a floor above the limit and nothing here records what the generators sent.
* The intervals treat requests as independent, which 20 repeating clients do not make them.

## Reproduce

    python3 eval/expc_probe.py results/2026-10-22_expc-r50-probe/campaigns results/2026-10-23_expc-r50-refinement/campaigns \
        --r50 --md results/2026-10-23_expc-r50-refinement/ladder.md --json results/2026-10-23_expc-r50-refinement/ladder.json
    git status        # clean: the tables regenerate byte for byte

`SHA256SUMS` lists every file of this directory but itself. The Wilson intervals and the compact table above are computed from
`ladder.json` as stated; they are not part of the script's output.
