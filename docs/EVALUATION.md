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
changed its default on 2026-10-19.

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

## Outputs of a run (`RESULTS_DIR`)

| File | Content |
|---|---|
| `provenance.json` | status, git commit, branch and dirty state, mode, operating point, settings, client-profile plan, host (uname, CPUs, Python, nginx), SHA-256 of the suite, daemon, XDP program, nginx configs, model, scaler and feature config |
| `scenario_results.csv` | one row per scenario (columns below) |
| `availability.csv` | legit success and latency per period (before / during / after) and client profile |
| `availability_raw.csv` | one row per legit request, with `Client_IP` and `T_Start` (epoch s) |
| `metrics.csv` | server metrics per phase (CPU total / daemon / nginx, PPS, `IP_InReceives`, `PreStack_Dropped`, TCP states) |
| `ban_events.jsonl` | the daemon's events (schema below); absent without a daemon |
| `daemon.log` | the daemon's console, one section per scenario |

The legacy `/tmp/{mitigation_performance,metrics_*,availability_*}.csv` files are still
appended exactly as before. The directory is handed to the user who ran `sudo`.

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

## Side effects of a suite run (root)

* `pkill` of `control_plane.py`, gunicorn, nginx, hping3, wrk and `_dist_*` scripts;
* deletion and re-creation of `server_ns`, `legit_*`, `bot_*` and the `ddos_br0` bridge;
* XDP attach/detach on `veth_server`, `iptables -F` in `server_ns`;
* truncation of `/var/log/nginx/ddos_ml_access.log` and `error.log`;
* appends to the legacy `/tmp` CSVs, a new directory under `/var/tmp/ddos_campaigns`,
  and a rewrite of `dummy_app.py` (same content).

`run_campaign.py` refuses to start on uncommitted changes to tracked files (results must
map to a commit; `--allow-dirty` overrides and is recorded) or while namespaces or
processes of an earlier run remain.

## Tests

    venv/bin/python -m unittest discover -s tests -v

No root and no network. They cover the event log, the daemon's event contract (static,
since importing the daemon attaches XDP), the suite's settings and bookkeeping (the
suite is imported with its atexit cleanup disabled), the analysis, and the published
EXP-2a numbers.

## Campaigns recorded before this harness

`eval/import_legacy_campaign.py` converts the prototype-era campaigns of
`docs/REPORT_ADDENDUM_EXP0_EXP1.md` (several runs appended per CSV, daemon logs captured
by a `tail -F` observer) into this layout. Approximations are recorded in each run's
`provenance.json` and in the campaign's README.
