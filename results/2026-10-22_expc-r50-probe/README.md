# EXP-C probe: where an open-loop HTTP flood hurts the knee server (2026-10-22)

The probe that places the cells of EXP-C (`docs/BENCHMARK_HARM_DESIGN.md`, `docs/EXPC_ATTACKER_SETTING_DESIGN.md`).
The **unprotected** server at the knee operating point (one gunicorn worker with one thread, pinned to CPU 0; 10 bots
on CPUs 1-7) under scenario 4, the HTTP flood, for 30 s. The reference is EXP-A's closed-loop `wrk -t2 -c400`, run
twice; the others are the in-repo open-loop engine `bench/loadgen.py` at 20, 40, 80, 160, 320 and 640 requests/s **per
bot** (200 to 6,400 in total), one run each. `PROFILE_SEED` 101 in every run, the legit clients of EXP-A's block 1.
It is a probe: no replicates, no mitigation, not a comparison campaign.

## What was run

All three campaigns are published in `campaigns/` as they were written (the per-run `console.log` has its ANSI
colour codes stripped; the ten per-bot working directories under `attackers/` were empty and are not copied).

| Campaign | Commit | Command (all with `sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --attack-duration 30 --modes unprotected --runs 1 --seed-base 100`) | Outcome |
|---|---|---|---|
| `20261022T175432Z_knee_s4`, 17:54 UTC | `3f4feea` | `--loads wrk,loadgen:20` | the `wrk` cell ran to its end (`provenance.json` says `completed`); at 17:55:24 the suite's own `pkill -9 -f wrk` killed the **runner** too, whose command line contains `wrk`. No `DONE`, an empty `console.log`, `campaign.json` still `running`; the `loadgen:20` cell never started. Fixed in `8235d39` (`pkill -9 -x wrk`) |
| `20261022T181508Z_knee_s4`, 18:15-18:18 | `8235d39` | `--loads wrk,loadgen:20` | both cells exit 0, no leftover; 90.2 s and 91.9 s |
| `20261022T181845Z_knee_s4`, 18:18-18:31 | `8235d39` | `--loads loadgen:40,loadgen:80,loadgen:160,loadgen:320,loadgen:640` | five cells exit 0, no leftover; run order 160, 80, 40, 640, 320 (`--order-seed 0`); 88-94 s each, 395 s for 640 |

After the last run no process, network namespace, bridge or listener of the testbed was left, and `/usr/bin/wrk` is the
binary pinned in `bench/loadtools.json` (`f6536e3f...`).

## Fixed before the data

The reading of the ramp was written down in the proposal of 2026-10-22, before the first open-loop run, and approved
"as proposed":

* each run is tabulated as nominal rate, measured offered rate (bot request lines per second in the window), served
  rate (status 200), legit success, timeouts, p50 and p95;
* **R50** is the measured total offered rate where legit success crosses 50 %, interpolated in log-rate between the two
  bracketing runs, with the `wrk` run as reference;
* if the bracketing runs differ by more than 40 pp, a three-rate refinement ramp is proposed; if success never crosses
  50 %, or is below it at the lowest rate, that is reported and the ramp extended;
* EXP-C's three rates would then be 0.5, 1 and 2 x R50, split over the 10 bots.

The go/no-go rules for the ramp held, with rule (e) revised after the first, aborted attempt (served `wrk` rate 1.2-8 k/s
became 0.4-4 k/s, and the ramp 40-640 instead of 40-1280, because that run served 0.86 k/s; approved): both cells exit 0
with no leftover and the ten generators pass their launch check; `flood` block in `provenance.json`; `loadgen:20` logged
5,863 bot requests in 30 s (6,000 +- 10 %), all status 200, legit success 100 %; `wrk` legit success 72.1 % (40-90 %)
at 1.03 k/s served (the aborted attempt: 69.5 % at 0.86 k/s).

## Result

Derived by `python3 eval/expc_probe.py campaigns --md table.md --json rows.json` (commit `e1e8247`) from the published
files only; `rows.json` has every figure, including the bot requests of each second.

Load the server received from the bots, by arrival, in the first 30 s of the attack (`Offered` counts every request line of a bot address, `Served` those with status 200; the median leaves out the first second, in which the generators start):

| Campaign | Run | Flood | Nominal /s | Offered /s | Offered /s, median | Served /s | Other statuses | Run time s |
|---|---|---|---|---|---|---|---|---|
| `20261022T175432Z` | `unprotected/run1` | wrk, closed-loop | - | 1057 | 715 | 860 | 499: 1031, 504: 4873 | - |
| `20261022T181508Z` | `unprotected/run1` | wrk, closed-loop | - | 1321 | 1078 | 1029 | 499: 3095, 502: 1, 504: 5672 | 90 |
| `20261022T181508Z` | `unprotected@loadgen20/run1` | loadgen, 20/s per bot | 200 | 195 | 200 | 195 | - | 92 |
| `20261022T181845Z` | `unprotected@loadgen40/run1` | loadgen, 40/s per bot | 400 | 390 | 400 | 390 | - | 88 |
| `20261022T181845Z` | `unprotected@loadgen80/run1` | loadgen, 80/s per bot | 800 | 782 | 800 | 782 | - | 92 |
| `20261022T181845Z` | `unprotected@loadgen160/run1` | loadgen, 160/s per bot | 1600 | 1587 | 1625 | 1505 | 499: 2480 | 90 |
| `20261022T181845Z` | `unprotected@loadgen320/run1` | loadgen, 320/s per bot | 3200 | 1569 | 1023 | 98 | 499: 9923, 504: 34186 | 94 |
| `20261022T181845Z` | `unprotected@loadgen640/run1` | loadgen, 640/s per bot | 6400 | 1253 | 507 | 8 | 499: 4653, 504: 32712 | 395 |

What the legit clients saw in the same 30 s, from their own records (percentiles only from 10 or more successes):

| Campaign | Run | Legit n | Success % | Timeouts % | Before the start, success % (n) | First 5 s, % | Last 10 s, % | p50 ok ms | p95 ok ms |
|---|---|---|---|---|---|---|---|---|---|
| `20261022T175432Z` | `unprotected/run1` | 95 | 69.5 | 14.7 | 100.0 (37) | 96.7 | 55.0 | 1678 | 6791 |
| `20261022T181508Z` | `unprotected/run1` | 104 | 72.1 | 7.7 | 100.0 (37) | 100.0 | 47.6 | 1563 | 7209 |
| `20261022T181508Z` | `unprotected@loadgen20/run1` | 246 | 100.0 | 0.0 | 100.0 (33) | 100.0 | 100.0 | 3 | 556 |
| `20261022T181845Z` | `unprotected@loadgen40/run1` | 252 | 100.0 | 0.0 | 100.0 (33) | 100.0 | 100.0 | 3 | 547 |
| `20261022T181845Z` | `unprotected@loadgen80/run1` | 251 | 100.0 | 0.0 | 100.0 (37) | 100.0 | 100.0 | 7 | 607 |
| `20261022T181845Z` | `unprotected@loadgen160/run1` | 178 | 100.0 | 0.0 | 100.0 (28) | 100.0 | 100.0 | 731 | 3024 |
| `20261022T181845Z` | `unprotected@loadgen320/run1` | 61 | 19.7 | 67.2 | 100.0 (35) | 19.0 | 47.1 | 7648 | 9765 |
| `20261022T181845Z` | `unprotected@loadgen640/run1` | 57 | 1.8 | 87.7 | 97.3 (37) | 5.0 | 0.0 | - | - |

Wilson 95 % intervals for the legit success, which treat requests as independent and so are descriptive: 12 of 61 is
11.6-31.3 %, 1 of 57 is 0.3-9.3 %, 75 of 104 is 62.8-79.8 %; 100 % on 178 to 252 requests is at least 97.9-98.5 %.

## What it shows

Tags: **[FACT]** read from the published files, **[INFERENCE]** a reading of them, **[UNKNOWN]** not recorded.

1. **Below the server's limit the generator offers what it is told to, and nothing is harmed.** [FACT] At 20, 40 and 80
   per bot the median second brings exactly 200, 400 and 800 requests (the 30 s mean is 2-2.5 % lower because the
   generators take about a second to start), every one is answered with 200, and the legit clients see 100 % at a median
   of 3-7 ms.
2. **At 160 per bot (1,600/s) the server is at its limit, and the legit clients still get through.** [FACT] 1,587
   requests/s logged, 1,505 of them answered 200 and 2,480 closed by the client (499); legit 178 of 178, but median 731 ms
   and p95 3.0 s (3 and 556 ms at 20 per bot). [INFERENCE] About 1.5 k requests/s is what one worker on CPU 0 serves:
   CPU 0 was at 100 % in the 1-second sample (`metrics.csv`).
3. **At 320 and 640 per bot the service collapses, and within seconds.** [FACT] At 320 the server answers 98 requests/s
   with 200, while 34,186 requests end in 504 and 9,923 in 499; legit 12 of 61, 67 % timeouts, 4 of 21 already in the first
   5 s. At 640, 1 of 57 (0 of 17 in the last 10 s). After the attack, 0 of 11 legit requests and 0 of the 15 requests of the
   post-attack check succeeded, and the run lasted 395 s. [INFERENCE] A backlog that builds up would leave the first
   seconds healthy, as in the closed-loop runs (29 of 30 and 30 of 30 in the first 5 s); here they are not.
4. **The nominal rate is the axis of load; the logged rate is not.** [FACT] The bots' request lines per second in the
   log are 195, 390, 782, 1,587, 1,569 and 1,253 for 200, 400, 800, 1,600, 3,200 and 6,400 requests/s nominal. A line is
   written when a request finishes, so above the limit the count is a floor of what reached the server: 49 % of the
   nominal count at 320, 20 % at 640. The one-second samples of `metrics.csv` show the packet rate at the server at
   2.0-2.6 k/s (160), 9.3-23.1 k/s (320) and 18.0-41.0 k/s (640), and 12,646-22,742 established connections at 320 and
   640. [UNKNOWN] What the generators sent: a killed generator leaves no summary (below, point 3).
5. **R50 as pre-registered is not defined, and the refinement rule applies.** [FACT] The bracketing runs, 160 (100 %) and
   320 (19.7 %), differ by 80 pp, and their logged rates, 1,587 and 1,569/s, are equal to within 1.2 %: "interpolated in
   log-rate between the two bracketing runs" has nothing to interpolate, and the logged rate is not monotone in the
   nominal one (1,253 at 640). On the nominal axis success crosses 50 % between 1,600 and 3,200 requests/s in total (a
   geometric midpoint of 2,263). The rule asks for a three-rate refinement ramp between 160 and 320. It was not run.
6. **The closed-loop reference moves between identical runs, and its offered load is an outcome.** [FACT] Two runs of the
   same cell logged 1,057 and 1,321 requests/s and answered 860 and 1,029; legit success 69.5 and 72.1 % (the suite's
   own "during" figure: 66.3 and 72.9 %; EXP-A's block 1, the same legit profile: 50 %). Legit success is 29 of 30 and 30
   of 30 in the first 5 s and 11 of 20 and 10 of 21 in the last 10 s. The open-loop 160 arm logs more requests per second
   (1,587) and keeps 100 % throughout. [UNKNOWN] Why the closed-loop flood harms more at the lower logged rate; this
   probe does not explain it.
7. **A run past the limit takes minutes to clean up.** [FACT] The 640 run took 395 s against 88-94 s for the other six
   runs that have a `DONE`; its post-attack check of 15 legit samples failed 15 of 15. [INFERENCE] The check tries each
   sample up to three times with a 15 s limit (`verify_legit_http`), so the extra 300 s are that wait. EXP-C cells at that
   pressure would cost about five minutes per run; the 320 cell cost the usual 94 s.

## What the probe found about the harness

It was the first real run of the open-loop path. The tables above do not use the fields affected by 2 and 3.

1. **The suite killed its own runner** (above). Fixed in `8235d39`, with a test that the exact commands are used and that
   no pattern the suite kills by matches a runner's command line.
2. **The first seconds of an open-loop flood are labelled "before".** `flood_alive` waits two seconds, and only the
   Phase-2 capture after it changes the label to "during". The suite's own "before" success is 79.6 % (n = 49) at 320 and
   71.2 % (n = 52) at 640; counted from the real attack start it is 100 % (35) and 97.3 % (37). The tables above count from
   `Attack_Start`. **Not fixed.**
3. **The server's log is the only record of the offered load, and above the limit it is a floor.** The design note
   (2.3) relies on it because a generator killed at the end of the scenario writes no summary of its own: the engine
   writes it after its 35 s, the suite sends SIGKILL about 32 s after the start, and the `attackers/` working directories
   stay empty. Up to 160 per bot the log holds 97.6-99.2 % of the nominal count (the shortfall is the start-up second);
   at 320 and 640 it holds 49 % and 20 %, so the check on the schedule that the note planned does not work there.
   **Not changed.**

## Limits

* One run per rate, one legit profile seed, and 57-61 legit requests in the overloaded windows; the intervals above treat
  requests as independent, which 20 repeating clients do not make them.
* A single VM. Its idle vCPUs wake late (`results/2026-10-22_loadtool-validation-run2/`, timer probe), so an open-loop
  schedule can slip; the size of the slip in these runs is unknown (point 3).
* The engine's request differs from `wrk`'s by about 35 bytes (the design note accepts it).
* The legit windows are the first 30 s from `Attack_Start`; the attack lasts 32 s in the suite's accounting.

## Reproduce

    python3 eval/expc_probe.py results/2026-10-22_expc-r50-probe/campaigns \
        --md results/2026-10-22_expc-r50-probe/table.md --json results/2026-10-22_expc-r50-probe/rows.json
    git status        # clean: the table regenerates byte for byte

`SHA256SUMS` lists every file of this directory but itself.
