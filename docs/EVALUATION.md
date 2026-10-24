# Evaluation: recording, analysing and publishing campaigns

This is how the measurements behind the thesis are produced, so that every figure can
be regenerated from the repository. The test harness is `test_distributed_suite.py`;
`eval/` turns its runs into campaigns; `results/` holds the published ones.

## Quick start

Reproduce the published analysis of EXP-2a (no root, seconds):

    venv/bin/python eval/analyze_campaign.py results/2026-10-12_exp2a-knee_prototype
    venv/bin/python eval/plot_campaign.py results/2026-10-12_exp2a-knee_prototype
    git status        # clean: the analysis regenerates byte for byte

Record the same experiment again with the current harness (root, ≈ 15 min, side
effects below):

    sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 3
    venv/bin/python eval/analyze_campaign.py /var/tmp/ddos_campaigns/<campaign>
    venv/bin/python eval/plot_campaign.py   /var/tmp/ddos_campaigns/<campaign>
    venv/bin/python eval/publish_campaign.py /var/tmp/ddos_campaigns/<campaign> --name <yyyy-mm-dd_what>
    git add results/<yyyy-mm-dd_what> && git commit

`run_campaign.py --dry-run` prints the plan and the environment of every run without
running anything.

`--loads wrk,loadgen:50,loadgen:100,loadgen:200` makes the load model of the HTTP flood a factor of the
block (EXP-C, `docs/EXPC_ATTACKER_SETTING_DESIGN.md`): a cell is `wrk`, the closed-loop default, or a
`verified` open-loop tool and its requests/s **per bot**. Every block runs every (mode, load) pair once, in a
random order from `--order-seed`, all with the block's `PROFILE_SEED`, so every cell of a block is paired.
Run directories and mode labels are `<mode>` for `wrk` and `<mode>@<tool><rate>` otherwise, e.g.
`xdp@loadgen100/run3`; `campaign.json` records `loads` only when it is not the default, so earlier campaigns
resume as before, and `--loads wrk` alone is the plan it always was. The runner refuses the cells (before
anything starts) when a tool is not `verified` in `bench/loadtools.json` or its binary is not the pinned one.
`--set FLOOD_TOOL=... --set FLOOD_RATE=...` sets one load model for every run; the two options do not
combine. The runner also reports a leftover `bench/loadgen.py` or `k6` process as it does a leftover `wrk`.

`python3 eval/expc_probe.py <campaign dir>... [--md T.md] [--json T.json]` tabulates such runs from the raw
records, for a probe that places the cells: the requests per second the bots offered and the server answered
(`server_requests.csv`, by arrival), and what the legit clients saw in the first 30 s from the attack's real
start (`availability_raw.csv`, not the "during" label, which for an open-loop flood begins about two seconds
after the launch). A percentile is printed only from ten successes. `--r50` adds R50 of amendment A
(`docs/EXPC_ATTACKER_SETTING_DESIGN.md`, section 6): the nominal total rate where the legit success crosses 50 %,
linear in log-rate between the two adjacent open-loop rates of all the directories given, or the reason there is none
(no crossing, not monotone, two runs at one rate).

## Modes

| Mode | Environment of the suite | What runs |
|---|---|---|
| `xdp` | (default) | daemon; bans enforced in the XDP blacklist; `nginx.conf` |
| `iptables` | `MITIGATION_BACKEND=iptables` | daemon; bans as iptables DROP rules (XDP still collects telemetry) |
| `nginxlimits` | `MITIGATION_MODE=none NGINX_PROTECTED=1` | no daemon; `nginx.conf` with `limit_req` / `limit_conn` |
| `unprotected` | `MITIGATION_MODE=none` | no daemon; `nginx_unprotected.conf` |

## Settings

Environment variables of `test_distributed_suite.py`. Every default of the suite's own
settings reproduces its historical behaviour (pinned by `tests/test_suite_harness.py`).
The daemon switches at the end of the table are read by `control_plane.py`; `XDP_GRU`
changed its default on 2026-10-19 (see "Defaults changed on 2026-10-19" below).

| Variable | Default | Meaning |
|---|---|---|
| `OPERATING_POINT` | `default` | named set of the six settings below (table further down) |
| `GUNICORN_WORKERS`, `GUNICORN_THREADS` | 8, 4 | backend capacity |
| `WRK_CONNS`, `WRK_THREADS` | 50, 2 | wrk connections / threads per bot (HTTP flood, Yo-Yo, multi-vector) |
| `BOTNET_COUNT` | 5 | bot namespaces |
| `SERVER_CPUS` | (none) | `taskset` CPU list for nginx and gunicorn |
| `ATTACK_CPUS` | (none) | `taskset` CPU list for every command run in a `bot_*` namespace |
| `NGINX_PROTECTED` | 0 | 1 = keep the protected `nginx.conf` when `MITIGATION_MODE=none` |
| `PROFILE_SEED` | 0 | seed of the client network-profile plan; the same plan in every mode |
| `ATTACK_DURATION` | 0 | > 0: every attack lasts exactly this long in every mode (equal exposure); 0 = stop as soon as the bans are seen (historical) |
| `FLOOD_TOOL` | `wrk` | load model of the HTTP flood (scenario 4 only): `wrk` (closed-loop, as ever) or an open-loop generator that is `verified` in `bench/loadtools.json`, `loadgen` or `k6`; anything else, or an unverified or changed binary, stops the run before it starts |
| `FLOOD_RATE` | (none) | requests/s **per bot** for an open-loop `FLOOD_TOOL`, constant schedule; empty for `wrk`. The mode label becomes `<mode>@<tool><rate>`, e.g. `unprotected@loadgen100` |
| `RESULTS_DIR` | new directory under `RESULTS_ROOT` | where this run's results go |
| `RESULTS_ROOT` | `/var/tmp/ddos_campaigns` | survives reboots, unlike `/tmp`; outside the repository |
| `ONLY_SCENARIOS` | all | e.g. `4` or `4,7,8,9` |
| `GRU_ONLY` | 0 | 1 = only the XDP-fed GRU may ban (isolation tests); implies `XDP_GRU=1` unless that is set explicitly |
| `XDP_GRU` | 0 | 1 = also run the XDP-fed GRU (`flow_map` → GRU feed and drain). Off by default since 2026-10-19; recorded in the daemon's `start` event |

Operating points (a variable of the same name overrides a value):

| | `default` | `knee` |
|---|---|---|
| gunicorn workers × threads | 8 × 4 | 1 × 1 |
| `SERVER_CPUS` / `ATTACK_CPUS` | — / — | 0 / 1-7 |
| `WRK_CONNS` | 50 | 400 |
| `BOTNET_COUNT` | 5 | 10 |

`knee` is the first configuration of the EXP-1d calibration sweep in which the
*unprotected* server degrades under the HTTP flood (addendum §J). With the default
over-provisioned server no attack degrades availability in any mode, so success rate
cannot discriminate between modes there (addendum §H). The volumetric floods need their
own CPU-bound operating point; that calibration has not been done yet.

**Open-loop HTTP flood** (`docs/EXPC_ATTACKER_SETTING_DESIGN.md`, for EXP-C). With `FLOOD_TOOL=loadgen` or
`k6`, scenario 4 starts one generator per bot, `ip netns exec <bot> [taskset -c ATTACK_CPUS] prlimit
--nofile=16384 -- <command of bench/loadtools.py>`, at `FLOOD_RATE` requests/s for as long as wrk would run,
with the settings of the verification (`loadtools.limits_for`: workers = rate x 0.3 s between 100 and 2,000,
at most 5,000 in flight, request timeout 10 s). Two seconds after launch every generator must be alive,
otherwise the run stops with an error. The generators are killed at the end like wrk, so they leave no
summary of their own. `provenance.json` records `settings.FLOOD_TOOL` and `FLOOD_RATE`, a `flood` block (tool,
rate, limits, manifest entry) and the hashes of `bench/loadtools.py`, `bench/loadtools.json` and
`bench/loadgen.py`. Scenarios 9 and 10 keep wrk. The request differs from wrk's by about 35 bytes: the engine
adds `User-Agent` and `Accept`, k6 its own user agent.

`PROFILE_SEED=0` gives 3 perfect, 8 broadband, 5 mobile_3g and 4 mobile_bad clients.
The campaign runner uses seeds 1…N, one per block, so the modes of a block share their
client mix and are compared pairwise.

`ATTACK_DURATION` caps the wait for bans, but in the UDP, ACK, fragmentation and
multi-vector scenarios about 15 s of sustained-stress captures *follow* that wait, so
without a daemon those attacks run for their ban timeout plus 15 s. Exposure is
therefore equal only with `ATTACK_DURATION` ≥ 26 s for UDP / ACK / fragmentation and
≥ 36 s for multi-vector; use ≥ 40 s when running all ten scenarios. For the other
scenarios any value above ≈ 16 s works (30 s for the HTTP flood alone). The report
warns when an attack ran longer than `ATTACK_DURATION`, and the achieved exposure is
recorded per scenario (`Exposure_s`).

## Defaults changed on 2026-10-19

The second independent audit (`/root/project_analysis_v2/REPORT.md`, root-only, SHA-256
`4d37f1dfc6b5f7dd4167afcffa4628f4c9a7713d39eccd7ba6f06d7ae438d3c9`; §10.5, §12 lead 15,
§13 G-16/G-17/G-18/G-23, §14.1 item 1) led to four changes, made together. They change
what a default run executes, so a run recorded before them is not a like-for-like
baseline for one recorded after.

| Change | Before | Now | Why |
|---|---|---|---|
| `XDP_GRU` | 1 | **0** | 0 true bans and 1 false ban (legit 10.0.1.6, P1 smoke `20261014T152428Z`, p = 0.999, 3 hits) in the 39 distinct ban-event logs recorded up to the audit (71 files: 32 were raw copies of published logs; `eval/events_census.py`) [FACT, recounted; with the converted prototype campaigns of 2026-10-12 folded in on 2026-10-21 the census is 52 distinct logs and 710 bans, still that one GRU ban: `results/2026-10-20_audit-derived/events_census.md`]; ≈ 0.065 wrongful 300-s bans per client-hour at least [INFERENCE: one ban in ≈ 15.5 client-hours, audit §6.1]. `XDP_GRU=1` opts in; `GRU_ONLY=1` implies it |
| L7 syslog sink in the nginx confs | `access_log syslog:…` in `nginx.conf` and `nginx_unprotected.conf`, always | only in the copy the L7 runners serve (`ml/eval_l7.py`, `ml/smoke_l7.py`) | with `L7_SHADOW=0` no socket is bound, so nginx logged one `[warn] send() to syslog failed` per request (868 in one second of the P1 flood burst). The file `access_log` and the `l7json` format stay |
| XDP `ihl` check | none | `ihl < 5` → `XDP_PASS`, after the blacklist drop | G-17, in part: the IPv6 / 802.1Q bypass and the `doff`, fragment and `tot_len` handling stay open |
| XDP `telemetry_map` | per-CPU hash, 100 k entries | per-CPU **LRU** hash, 100 k entries | G-18: once a spoofed-source flood had filled the map, new sources went uncounted by the per-IP L4 rules |

What this means for earlier results:

* The 24 distinct daemon logs of 2026-10-12 to 2026-10-14 (EXP-2a, the full-suite runs, the
  R1 and P1 smokes; 38 files with the raw copies) predate the switch: their `start` events have no `xdp_gru` field and
  those runs had the XDP-fed GRU on. To repeat one with the current harness, export
  `XDP_GRU=1`. The campaign runner passes it through, but records it only in the daemon's
  `start` event, not in `campaign.json`. The converted prototype campaigns of 2026-10-12
  (`results/2026-10-12_*_prototype`: 12 further distinct non-empty logs) predate it too.
* The 14 distinct logs of 2026-10-15/16 (27 files; the L7 runners pin it) recorded `xdp_gru: false` and are
  unaffected by that switch. Those runs served `nginx.conf` with the socket sink, as the
  runners still do. The remaining distinct log is empty (the modes without a daemon: 6 identical files).
* A hand-started suite with `L7_SHADOW=1` no longer gets the sink: add the line where the
  marker is (`docs/L7_GRU_DESIGN.md` 4.3).
* Not changed: `L7_SHADOW` stays 0 and `HEURISTIC_PROFILE` stays `default` (audit §10.5).

**Verification, 2026-10-19/20** [FACT unless tagged; raw output under `/var/tmp`, not
versioned: `ddos_verify_20261020/`, `ddos_l7_smoke/20261020T073029Z`,
`ddos_l7_eval/20261020T073642Z`]. All live runs were made on a clean tree (the XDP program,
`control_plane.py` and the confs as committed) on the namespace testbed.

* **Unit tests:** 242 pass, 23 of them new (the `XDP_GRU` default, its opt-in and the
  `GRU_ONLY` coupling, the `xdp_gru` field of the `start` event, the sink in the confs and in
  what the runners write, and the offline helpers of `bench/xdp_test_run.py`).
* **`nginx -t`**, as root with the real paths and `listen 80/443` inside a throw-away network
  namespace: successful for both default confs and for the three confs the runners write.
* **Kernel, `bench/xdp_test_run.py`** (load without attach, then `BPF_PROG_TEST_RUN`;
  `--reference` is the program of 3086e27): 28 of 28 checks. The verifier accepts both
  programs (1896 B translated each). `ihl` 4 is passed on uncounted (the reference counts it
  into garbage flows); a blacklisted source with `ihl` 4 is still dropped. After 150 000
  distinct sources the current table holds 99 988 entries, counts the latest source and a
  newcomer; the reference stops at 100 000 and counts neither. Reading the full table takes
  0.4 s, and 2.3-4.2 s while another thread adds sources, with no duplicates.
* **`ml/smoke_l7.py` (P1 gate, `L7_SHADOW=1`, 180 s):** nginx served the rendered
  `nginx_l7sink.conf`; the daemon ran without `XDP_GRU` (`start.xdp_gru: false`), received
  and parsed 2 563 lines with 0 parse errors and 0 truncation, and banned all four bots with
  `l7_rate`. The runner's verdict is REVIEW (steady-regime gap 13 against its tolerance of 5).
  That is lag, not loss: the gap's minima stay at 7 277-7 283 from 68 s to the end of the
  run, and its saw-tooth is the 5-s `l7_shadow` report interval times about 2.4 requests/s
  (about 12 lines). The published P1 smoke got 3 only because its window edges fell on
  similar phases. The flood burst dropped 7 399
  of 9 407 lines in its interval (74 % overall of 9 816, against 40 % of 2 190 in the
  published run), and nginx logged 7 276 `send() to syslog failed` warnings in those two
  seconds, one per dropped datagram: the sink-off default avoids them, shadow mode does not.
* **`ml/eval_l7.py --benign-only --duration 60 --benign 4`:** nginx served
  `nginx_default.conf`; 113 of the 119 lines of the file log had reached the daemon at its
  last 5-s report (lag), with 0 parse errors, 0 syslog failures, 35 windows scored and no
  would-ban.
* **Suite scenario 4 (HTTP flood) in default mode** (`L7_SHADOW=0`, `XDP_GRU` unset): 5 of 5
  bots banned by `l7_rate`, TTM median 0.455 s (0.680 s in the unreplicated baseline run of
  `main`, 2026-10-19 15:32), no false positive, legit 15 of 15, and 0 `send() to syslog
  failed` among 4 152 `limit_req` rejections in nginx's error log. One run each: no claim on
  TTM.

**Full suite on the change set, 2026-10-20** [FACT]: `results/2026-10-20_regression-after-audit-defaults/`,
one run of all ten scenarios in XDP mode at default settings and `PROFILE_SEED = 0`, taken against
the baseline above at commit `618b2fc` (clean tree), three minutes after a VM restart. 10/10 PASS;
five of five bots banned in every scenario by the same engines as in the baseline; no false positive,
no unenforced ban, no GRU event (`xdp_gru: false`, XDP program `1f9e8606...`); legit success 100 %
before, during and after every scenario; 0.85-1.81 M packets/s arriving on the interface in the
four volumetric scenarios with at most 214 packets/s at the IP layer. R.U.D.Y. took 4.64 s (3.57-3.88 s
in the three earlier runs), one polling interval more; the other scenarios are within the earlier
spread or the 1-s poll. One run each: no claim on TTM.

Still open: a live `hping3 --rand-source` flood with the daemon polling (the kernel map semantics
and the userspace read are covered above, the daemon under a real flood is not); and the remaining
G-17 checks (`doff`, fragments, IPv6 / 802.1Q, `tot_len`), which the program still lacks.

## Outputs of a run (`RESULTS_DIR`)

| File | Content |
|---|---|
| `provenance.json` | status, git commit, branch and dirty state, mode, operating point, settings, client-profile plan, host (uname, CPUs, Python, nginx), SHA-256 of the suite, daemon, XDP program, nginx configs, model, scaler and feature config |
| `scenario_results.csv` | one row per scenario (columns below) |
| `server_requests.csv` | the load as the Nginx server received it: per scenario, second, client class and status, the requests and their mean and largest request time (columns below) |
| `availability.csv` | legit success and latency per period (before / during / after) and client profile |
| `availability_raw.csv` | one row per legit request, with `Client_IP` and `T_Start` (epoch s) |
| `metrics.csv` | server metrics per phase (CPU total / daemon / nginx, PPS, `IP_InReceives`, `PreStack_Dropped`, TCP states) |
| `ban_events.jsonl` | the daemon's events (schema below); absent without a daemon |
| `daemon.log` | the daemon's console, one section per scenario |

The legacy `/tmp/{mitigation_performance,metrics_*,availability_*}.csv` files are still
appended exactly as before. The directory is handed to the user who ran `sudo`.

`server_requests.csv` is aggregated from Nginx's access log at the end of each scenario, before the next
reset truncates the log: `Data_Scenario`, `Mode`, `T_Epoch_s` (the second the request **arrived**: the log's
second, which is when it ended and is truncated, plus half a second, minus its request time; so within half a
second, and a request that waited in an overloaded server counts where it was sent), `T_Rel_s` (seconds from
the second of the attack's start; negative before it), `Client_Class` (`bot` 10.0.2.x, `legit` 10.0.1.x, `other`),
`Status`, `Requests`, `Request_Time_Mean_s`, `Request_Time_Max_s`. It includes the 503s that `limit_req` sends
and the requests the legit clients and the harness's own checks make, so the offered rate of the attack is the
`bot` rows, in every mode; the generator's own report is lost when it is killed. A run recorded before this file
existed has none.

`scenario_results.csv`: `Scenario`, `Data_Scenario` (the name used in the other CSVs),
`Mode`, `Operating_Point`, `Profile_Seed`, `Attack_Duration_s`, `Scenario_T0`,
`Attack_Start`, `Attack_End` (epoch s), `Exposure_s`, `Bots`, `Banned_Harness`,
`Banned_Events`, `TTM_Harness_Mean_s`, `TTM_Exact_Median_s`, `TTM_Exact_Max_s`,
`TTM_Exact_By_Bot` and `Engine_By_Bot` (JSON), `FP_Source`, `FP_IPs`, `FP_Ping_IPs`
(JSON), `Legit_HTTP_OK`, `Legit_HTTP_Total`, `Result`.

## Ban events (`ban_events.jsonl`)

Written by `control_plane.py` through `ban_events.py`: one JSON object per line,
flushed immediately, never truncated. Every event has `t_wall` (epoch s), `t_mono_ns`
(CLOCK_MONOTONIC ns) and `kind`. The path comes from `BAN_EVENTS` (the suite points it
at the run directory; standalone default `/var/log/ddos/ban_events.jsonl`; `""` disables).

| `kind` | Fields |
|---|---|
| `start` | `pid`, `backend`, `gru_only`, `xdp_gru`, `interface`, `model`, `model_sha256`, `scaler_sha256`, `xdp_sha256`, `thresholds` |
| `ban` | `ip`, `engine`, `reason`, `backend`, `enforced`, `ttl_s`, `value`, `threshold`; plus `bytes` (`l4_slowconn`), `error_ratio` (`l7_rate`), `hits` (`gru`) |
| `unban` | `ip`, `backend`, `age_s` |
| `suppress_on`, `suppress_off` | `syn_delta`, `pkt_delta`: the GRU pause during volumetric floods (observed once per 1-s poll) |
| `gru_suppressed` | `ip`, `value` (probability), `hits`: a GRU detection dropped because the pause was active |

Engines: `l4_syn`, `l4_volumetric`, `l4_slowconn`, `l4_lowsyn`, `l7_rate`, `l7_rudy`,
`gru`. The `value` of the L4 engines is a count per poll interval (1 s plus the loop's
work), not a rate normalised by elapsed time (review D5).

## Metrics

* **Availability**: share of legit requests answered `200` within curl's `--max-time 10`,
  counted in the period in which the request *started*.
* **Time to mitigate (exact)**: first `ban` event of a bot minus the attack start the
  harness records right before launching it. The older "Avg TTM" (when the harness's
  0.5-s log poll saw the ban) is kept for comparison; it overestimates by about 0.5 s.
* **False positive**: a `ban` event for a legit client (10.0.1.x) since the scenario
  began. Modes without a daemon cannot ban (`no daemon`); `ping` marks the legacy check,
  used only if a daemon ran without an event log.
* **Equal-exposure window** (analysis `--window`, default 10 s): requests started in the
  first seconds after the attack start, identical in every mode whatever the harness did
  afterwards.
* **Server load**: mean of the ~1-s captures of Phase 2 (Pre-Mitigation, Sustained
  Stress) and Phase 3.

## Statistics

`analysis/summary.md` reports pooled success with a 95 % interval from resampling whole
runs. Compared with the reference mode (default `unprotected`), blocks of runs sharing a
`PROFILE_SEED` are resampled together (paired); otherwise runs are resampled
independently. Fisher's exact test on pooled requests is secondary: it ignores clustering
by run and client. With three runs per mode the intervals only show the spread of those
runs; thesis claims should rest on ≥ 10 interleaved runs per mode (review §6.3).

**Read those intervals as descriptive below about ten blocks (audit G-06).** A bootstrap
over 3 blocks has only 10 distinct resamples, so its "95 % interval" is roughly the range
of the block means, and the pooled Fisher p treats the ~100 requests of one run as
independent. Neither is inference. The tool for that is `eval/run_level_stats.py`:

    ./venv/bin/python eval/run_level_stats.py results/<campaign> [--reference unprotected]

It takes the run as the unit, pairs modes by `PROFILE_SEED` block, and reports the mean
block difference with its t-interval, the paired t p, the exact sign-flip p, the share of
blocks with the sign of the mean and the number of blocks that would give 80 % power. With
n paired blocks the smallest attainable sign-flip p is 2 / 2^n (0.25 for n = 3).
Campaigns without shared seeds (the EXP-2a import) are compared unpaired and carry no
decision.

A campaign recorded with `--loads` (run labels `mode@cell`; a plain label is the closed-loop `wrk` cell) is
analysed inside each load cell: `analyze_campaign.py` and `run_level_stats.py` compare every label with the
reference mode of its own cell, never across load models, and add a `cell` column (`wrk` for the closed-loop
one). `run_level_stats.py` also prints the reference arm's mean success and whether the cell is "harmed", that
mean being below 90 %: a cell in which the unprotected server keeps 90 % or more tests nothing about
mitigation. The decision rule above is unchanged. `analyze_campaign.py` adds `offered.csv` and a summary
section from `server_requests.csv` (the bots' request lines per second at the server, by arrival, and the
answers by status; a floor of the offered load above the server's limit), and `plot_campaign.py` one
availability figure per cell, `availability_<scenario>__<cell>.png`. `publish_campaign.py` copies
`server_requests.csv` with the other run files. Campaigns without cells or without that file are analysed
exactly as before.

The decision rule is fixed in the tool, in the commit that added it, before any 10-block
data exist: a paired contrast is *supported* iff it has ≥ 10 blocks, the 95 % t-interval
of the mean block difference excludes 0, and ≥ 80 % of the blocks have the sign of the
mean; otherwise it is *not shown*, which is not evidence of no effect. On the published
campaigns it gives (exact ok / n per run, so up to 0.6 pp from the rounded figures of the
audit report §9.3):

| Campaign | Contrast (during the flood) | Mean block difference | 95 % t-interval | Sign-flip p |
|---|---|---|---|---|
| R3 (3 blocks) | daemon − unprotected | +21.0 pp | [−5.5, +47.4] | 0.25 |
| R3 | limits only − unprotected | −6.4 pp | [−33.8, +21.0] | 0.50 |
| R4 (3 blocks, 30 s) | daemon − unprotected | +28.0 pp | [−15.3, +71.3] | 0.25 |
| R4 | limits only − unprotected | −34.9 pp | [−85.4, +15.7] | 0.25 |

None of those is significant at run level, and 3 blocks cannot be by the sign-flip test. What
is consistent is the direction: the daemon modes served 100 % in every one of the 9 knee runs
(EXP-2a, R3, R4) and were above unprotected in each. Those are not 9 independent blocks: R3
and R4 reuse the same three `PROFILE_SEED`s and EXP-2a was unseeded, so no sign-test p is
quoted for them. An effect of the size of R3's limits-only difference (−6 pp, block SD
11 pp) would need about 26 paired blocks; one of R4's size, about 5.

**EXP-A** (`results/2026-10-20_expa-knee-10-blocks/`, 2026-10-20) is the first campaign that meets
the rule: ten paired blocks (`PROFILE_SEED` 101-110), recorded six hours after the commit that
fixed the rule. Since then only the helper that formats the table has changed.

| Campaign | Contrast (during the flood) | Mean block difference | 95 % t-interval | Sign-flip p | Decision |
|---|---|---|---|---|---|
| EXP-A (10 blocks, 30 s) | daemon (XDP or iptables) − unprotected | +33.2 pp | [+26.1, +40.2] | 0.002 | supported (+) |
| EXP-A | limits only − unprotected | −22.5 pp | [−32.0, −13.1] | 0.002 | supported (−) |

Every contrast has the same sign in 10 of 10 blocks; 0.002 is the smallest sign-flip p ten blocks
can give. The effect sizes needed 3 and 5 blocks for 80 % power.

**EXP-C** (`results/2026-10-23_expc-open-vs-closed-loop/`, 2026-10-23, protocol `docs/EXPC_PROTOCOL.md` fixed before the
data) repeats EXP-A's design with the attacker's load model as a second factor (`--loads`): the same ten `PROFILE_SEED`s,
three modes, and every contrast drawn inside a load cell, against the unprotected arm of the same cell. The open-loop
cells are `bench/loadgen.py` at 125, 250 and 500 requests/s per bot (10 bots).

| Load cell | Contrast (during the flood) | Mean block difference | 95 % t-interval | Sign-flip p | Decision | Unprotected arm |
|---|---|---|---|---|---|---|
| `wrk`, closed loop | daemon (XDP) − unprotected | +22.5 pp | [+16.0, +29.0] | 0.002 | supported (+) | 77.5 % |
| `wrk`, closed loop | limits only − unprotected | −34.3 pp | [−45.4, −23.2] | 0.002 | supported (−) | 77.5 % |
| 125 per bot | daemon (XDP) − unprotected | −0.0 pp | [−0.1, +0.1] | 1.000 | not shown | 100.0 % (not harmed) |
| 125 per bot | limits only − unprotected | +0.0 pp | [+0.0, +0.0] | 1.000 | not shown | 100.0 % (not harmed) |
| 250 per bot | daemon (XDP) − unprotected | +57.9 pp | [+52.6, +63.2] | 0.002 | supported (+) | 42.1 % |
| 250 per bot | limits only − unprotected | +57.9 pp | [+52.6, +63.2] | 0.002 | supported (+) | 42.1 % |
| 500 per bot | daemon (XDP) − unprotected | +88.6 pp | [+84.7, +92.5] | 0.002 | supported (+) | 11.4 % |
| 500 per bot | limits only − unprotected | +88.6 pp | [+84.7, +92.5] | 0.002 | supported (+) | 11.4 % |

Where both mitigations served 100 % in every block the two contrasts are identical: that is the ceiling, not a tie
that was tested. In the closed-loop cell the contrasts keep EXP-A's signs and differ in size; the difference is in the
unprotected arm (77.5 % against 66.8 %). A cell whose unprotected arm keeps 90 % or more is "not harmed" and tests
nothing about mitigation (`run_level_stats.HARM_BELOW_PCT`).

## Side effects of a suite run (root)

* `pkill` of `control_plane.py`, gunicorn, nginx, hping3, wrk and `_dist_*` scripts (wrk by its exact process
  name, because `pkill -f` matches every command line on the machine that contains the word: a runner started with
  `--loads wrk,...` killed itself that way on 2026-10-22; a test now checks the patterns the suite kills by against
  the runner's command lines);
* deletion and re-creation of `server_ns`, `legit_*`, `bot_*` and the `ddos_br0` bridge;
* XDP attach/detach on `veth_server`, `iptables -F` in `server_ns`;
* truncation of `/var/log/nginx/ddos_ml_access.log` and `error.log`;
* appends to the legacy `/tmp` CSVs, a new directory under `/var/tmp/ddos_campaigns`,
  and a rewrite of `dummy_app.py` (same content).

`run_campaign.py` refuses to start on uncommitted changes to tracked files (results must
map to a commit; `--allow-dirty` overrides and is recorded) or while namespaces or
processes of an earlier run remain. The L7 runners (`ml/capture_l7.py`, `ml/eval_l7.py`,
`ml/smoke_l7.py`) do the same since 2026-10-20 and record `git` (commit, branch, `dirty`,
`dirty_files`) in the manifest or summary of the run, next to the older `git_commit` key.
`--plan` does not check; runs published before that date carry the commit only.

## The harm benchmark's offline tools (HG1b)

`docs/BENCHMARK_HARM_DESIGN.md` (branch `design/benchmark-harm`) asks that an attack cause measurable harm on an
unprotected server before any mitigation is judged against it; `docs/HG1B_MINIMAL_DESIGN.md` is the part built
so far. These tools send no traffic and need no root. The executor that runs a scenario in the namespaces, the
campaign runner and the calibration runner (HG1c) are built and described in the next section, but have not run on
the testbed; until the calibration runner has measured one, the calibration is `bench/calibration/placeholder.json`,
the design's illustrative numbers, and the gate refuses a verdict on it (`--dry-run` allows one and labels everything
it prints). **Nothing in this section is a statement about the testbed.**

| Tool | What it is |
|---|---|
| `bench/origin.py` | a cost-calibrated WSGI origin (`gunicorn --chdir bench origin:app`): `GET /static/<n>` (C0), `/page/<id>` (C1), `/api/item/<id>` (C2), `/search?q=` (C3), `/export` (C5), real work and no sleeps, a per-URL work factor from a hash of the URL. `--routes` prints the table; `--calibrate` and `--check CAL.json` time the routes in process on this host (CPU, no network) |
| `bench/calibration.py` | the calibration record: route costs, knobs, capacity, legit mix, SLOs, the gate's constants, the generator-validity rules, the hash. `check FILE`, `show FILE` (rho, the mean cost, the spare capacity S), `rehash FILE` (placeholders only) |
| `bench/population.py` | seeds, identities and streams: seed namespaces `calib` 1-99, `train` 100-199, `val` 200-299, `test` 300-399; eight benign classes and three attack families (assumptions, labelled); one link-profile distribution for every identity; attack intensity as a cost rate in units of S |
| `bench/scenario.py` | the scenario record (JSON, `bench/scenarios/`) and its plan |
| `eval/harm_gate.py` | Gate A: PASS, FAIL or INVALID from blocks written under the run contract |

    python3 bench/scenario.py --check bench/scenarios/*.json
    python3 bench/scenario.py --plan bench/scenarios/costly_search_sub_threshold.json
    python3 bench/scenario.py --plan --calibration FILE --seed 7 --json SPEC
    ./venv/bin/python eval/harm_gate.py CAMPAIGN --calibration FILE [--dry-run] [--metrics Q,p95] [--md R.md] [--json R.json]
    ./venv/bin/python eval/harm_gate.py --block BLOCK_DIR --calibration FILE      # one block: validity and figures, no verdict

**The plan** prints, for one block of a scenario: the entity seeds; the legit load per behaviour class and its
route mix against the calibration's; the attack's total, per-source and cost rate in units of S; each source's
rate against the deployed per-source rules (`limit_req` 30 r/s, the daemon's L7 rule at 50 r/s) and how many
sources it takes to fall below each; the load on the generator (processes, CPU, descriptors, memory, the
requests a stalled server would hold in flight against the engine's cap); and the gate class the cost-rate model
expects (A of 2 or more likely PASS, 0.5 or less likely FAIL). The deployed thresholds are printed and never
used: no intensity is chosen, moved or clipped by them, and a test scales them to prove it. The three shipped
plans are golden files in `tests/golden/`; a change to the population changes them, and the failure message says
how to regenerate them. A plan with the placeholder calibration carries a banner.

**The run contract** an executor must write (`docs/HG1B_MINIMAL_DESIGN.md` 5.5): per block `block.json`
(scenario, block number, attempt, seed namespace and seed, calibration sha256, timeline, the order the runs were
made in); per run `C`, `Cp` (the placebo, a second attack-free run), `U` and later `M_<mode>` a `run.json`
(role, mode, the executor's verdict on the run, and per stream its id, kind, route class, link profile, summary,
records and offset) and per stream the engine's `--summary` and `--records`.

**The rule** (design section 10, constants in the calibration): `Q` is the share of the legit requests **on the judged
links** intended in the attack window that completed 2xx within their class's SLO, the service time from the actual
send; a request never sent, dropped, timed out or answered non-2xx fails. The judged links are the calibration's
`judged_profiles` (`perfect` and `broadband` by default): the suite's mobile links are 150 to 300 ms with up to 5 %
loss and already exceed the SLOs, so a control that counted them reaches about 89 % and no block could be valid
(`docs/HG1C_DESIGN.md` 4.1). Their `Q` and p95 are reported per link profile and do not vote. Per block `dQ = Q(C) - Q(U)` (pp),
`dL = log2(p95(U) / p95(C))` and, for the placebo, `dQ'` and `dL'`. PASS iff the mean `dQ` reaches the floor
(10 pp), its 95 % t-interval excludes 0 and at least 80 % of the blocks have its sign, or the same holds for
`dL` with a floor of 1; the interval and the sign share are `eval/run_level_stats.py`'s. FAIL otherwise. INVALID
when fewer than ten blocks are valid or the campaign broke the re-run rule: a failed block is re-run once with
its seed, at most twice in a gate, a valid block never. A block is valid when its runs meet the validity profile
of the calibration (`relative`, the default: a gross slip ceiling and a difference to the control; `strict`:
every engine flag clear and slip p99 under 50 ms, computed always), the executor called its runs sound, and its
control is healthy: `Q` at least `control_q_min` and at least 95 % of the requests of every route class within its SLO. The placebo must
not pass and is reported when it does; HRR, with a block-bootstrap interval, exists only after a PASS.

**Limits.** The p95 is over the successes, so a server that fails its slowest requests looks faster (Q counts the
failures and is the primary number); the pooled p95 weighs the route classes by their share of the mix; the
benign classes and the attack families are assumptions; every cost is a placeholder until HG2 measures it; a
population of class-pure streams is coarser than sessions. `docs/HG1B_MINIMAL_DESIGN.md` section 9 lists what the
build found.

## The harm benchmark's runners (HG1c)

`docs/HG1C_DESIGN.md` (decisions D18 to D26 approved; section 14 records what was built and where it departs from the note)
adds the three runners that turn a scenario into the run contract above, the run contract into a verdict, and measurements into a
frozen calibration. **They were built offline and have not run on the testbed.** The first contact is a ladder of four small steps
(S1 to S4, section 10 of the note), each approved on its own with its exact command; what follows says what the code asks of
the machine and what the tests show a simulated machine doing, not what the testbed does.

| Tool | What it does |
|---|---|
| `bench/executor.py` | one run (`C`, `Cp` or `U`) of a plan: preflight (root, venv, descriptors, a clean tree, no leftovers), the environment gate (uptime and load for the first run of a process, the timer on the legit CPU for every run), the topology built with the suite's primitives and read back, gunicorn and Nginx in `server_ns`, the streams on their timeline, telemetry at 1 Hz, collection into the run contract with `executor.ok`, and a teardown that is shielded from a second Ctrl-C |
| `bench/gate_campaign.py` | the blocks of one scenario: `C`, `Cp` and `U` in an order drawn from the scenario, the block and the attempt; the re-run rule through `harm_gate.assess_block`; resume; an unscored warm-up; `gate.json` and `gate.md` beside the data |
| `bench/calibrate.py` | the steps that fill the calibration: `origin`, `capacity`, `ladder` (a screening per family), `reference`, `freeze`, `drift` |
| `bench/sim_host.py` | the machine as a model, with a virtual clock and a server that has a capacity: what the tests and `--simulate` run on |

    python3 bench/executor.py plan SPEC --calibration FILE --kind U --seed 1 [--out DIR] [--json]    # what a run would do; no root
    sudo ./venv/bin/python bench/executor.py run SPEC --kind C --seed 1 --out DIR/C [--rho R --timeline B,A,R]
    ./venv/bin/python bench/executor.py clock-probe SPEC --duration 30 [--attack] --out DIR           # S1: no root, loopback
    sudo ./venv/bin/python bench/executor.py smoke-topology SPEC --out DIR/C                          # S2
    python3 bench/gate_campaign.py plan SPEC --calibration FILE [--blocks N]
    sudo ./venv/bin/python bench/gate_campaign.py run SPEC --calibration FILE --out DIR [--dry-run] [--blocks N] [--no-warmup]
    python3 bench/gate_campaign.py run SPEC --calibration FILE --out DIR --simulate pass|fail|small|latency     # no root, no namespace
    python3 bench/gate_campaign.py status DIR
    python3 bench/calibrate.py plan                                       # the steps, their runs and their time
    sudo ./venv/bin/python bench/calibrate.py origin|capacity|reference --out SESSION                  # then `ladder --family F`
    python3 bench/calibrate.py freeze --dir SESSION --out bench/calibration/<host>-<date>.json         # never touches the VM
    sudo ./venv/bin/python bench/calibrate.py drift --calibration FILE --out DIR

**A run directory** holds `run.json` and `streams/<id>/loadgen.{summary.json,records.csv.gz}` (the run contract), `plan.json` (every
primitive, command and stream), `environment.json` (the commit and whether the tree was dirty, the machine, the timer, the hashes of the
files the result depends on, and the limits and CPUs the stack was actually started with), `executor.log`, `server.csv` (a row a second:
load, busy share of each CPU, steal, CPU of the origin and of Nginx, `ListenOverflows`, `ListenDrops`), `server_requests.csv`
(Nginx's log by arrival second and client class) and the compressed log; `FAILED` names the reason when the run did not complete. A
campaign directory has `campaign.json`, `bNN_aM/` per block attempt with `block.json` and the three runs (a `DONE` in each), `warmup/C`,
`gate.json` and `gate.md`; a calibration session has `origin/`, `capacity/`, `ladder_<family>/`, `reference/` and `drift/`.

**What the executor will not do.** It never kills by pattern: the namespaces' processes are found with `ip netns pids` and the leftover
check reads the process table by what each process runs (a results directory called `gunicorn` cannot match); a listing it cannot read
is not a clean machine. The suite's import-time `atexit` cleanup, a system-wide `pkill -9 -f gunicorn`, is unregistered after the import.
It refuses a directory that holds anything, a tree with uncommitted changes (unless `--allow-dirty`, which is recorded) and leftovers
(`--clean` takes down the namespaces and links of an earlier testbed, and nothing else). A failure before the first stream is retried in
place twice; any error raised after it ends the run, tears down, and writes `FAILED`.

**The clocks of the streams.** The engine writes no absolute time, so the executor estimates when each stream's schedule began from its
exit time less its wall time, and `executor.ok` is false when the legit streams began more than 0.5 s apart, the attack began more than
0.5 s from the end of the baseline, a stream died, left nothing or exited non-zero. The estimate is [UNVERIFIED] until S1 measures it
against an origin's own arrival log; `exit_delay_per_request_s` corrects an exit delay that grows with the request count, if S1 shows one.

**The campaign** runs a block's three runs in a drawn order; a run that fails or is found unsound ends its attempt (finishing an invalid
block spends VM time on nothing), and the block is re-run once with its seed if the gate has re-runs left (`max_reruns`, 2). A campaign
that can no longer reach the gate's `min_blocks` valid blocks stops (`--keep-going` goes on). A refusal, a setup that cannot be built,
Ctrl-C and a leftover stop the campaign without counting as a failed block; the same command resumes, skipping the runs that are `DONE`.
**The calibrator** stops, and says what that means, when the host cannot be calibrated: a first capacity level that is already unhealthy, a
capacity above the range of the probe, no saturation, origin sessions that disagree by more than 10 % twice, a screening whose controls
are unhealthy or more than 2 pp apart. Nothing is tuned to get past a stop.

**Simulation.** `--simulate` runs a whole campaign, or any calibration step, on `bench/sim_host.py`: commands answered from a model of
the testbed, processes on a virtual clock, faults on request (`--simulate-fault NAME[:N]`), and a server that makes a harm of a known
size or has a capacity (requests fail in the share that does not fit it). The directories are marked `SIMULATED`, and on it the capacity,
the knees and the harms that the steps find agree with what the model says they are. That shows the protocol working and says nothing
about any server.

## Tests

    venv/bin/python -m unittest discover -s tests -v

No root and no network. They cover the event log, the daemon's event contract (static,
since importing the daemon attaches XDP), the suite's settings and bookkeeping (the
suite is imported with its atexit cleanup disabled), the analysis, and the published
EXP-2a numbers.

The harm benchmark's runners are tested on a simulated host (`bench/sim_host.py`, `tests/test_executor_run.py`, `tests/test_gate_campaign.py`,
`tests/test_calibrate.py`): a failure injected at each step still tears down and leaves `FAILED`, no command of the executor is a kill
or a lookup by pattern, the re-run rule and resume are exercised on synthetic outcomes, and the calibrator finds a capacity and a knee that
the model has. Mutating each module with textual changes (about 200 in all) makes a test fail for every one that is not equivalent.

The daemon's live rules are tested by running their real code against fakes
(`tests/daemon_harness.py`, `tests/test_daemon_rules.py`; audit G-29). The harness executes
`control_plane.py`'s functions and the bodies of its two loops (the L3/L4 telemetry monitor, the
Nginx-log loop) and `tail_nginx_error_logs` in a private namespace, with a fake clock, a fake
`subprocess` and dict-like BPF tables; it skips every top-level statement that would attach XDP,
load the model or start a thread. The tests pin each rule's thresholds and their strictness
(`>` against `>=`), the resets, the TTL, the iptables commands, the `GRU_ONLY` switch and the
tolerant profile, and they document the known weaknesses as tests named `..._weakness`: a
steady trickle that defeats SlowConn (G-19), a failed iptables call that still counts as a
ban, and a double ban that leaves a rule behind (F-18). They describe what the rules do, not
what they should do; a change to a rule changes its test. Mutating the thresholds of a copy of
the daemon makes at least one test fail for each mutation tried but one, which is equivalent
(`HEURISTIC_MIN_REQUESTS` is redundant under the one-second clamp).

## Campaigns recorded before this harness

`eval/import_legacy_campaign.py` converts the prototype-era campaigns of
`docs/REPORT_ADDENDUM_EXP0_EXP1.md` (several runs appended per CSV, daemon logs captured
by a `tail -F` observer) into this layout. Approximations are recorded in each run's
`provenance.json` and in the campaign's README.
