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
| `SLOW_PC`, `SLOW_PC_ENFORCE` | 0, 0 | the P4 per-connection slow rule: 1 = run it (in shadow), and 1 = also enforce it. Its other variables are in "P4: the per-connection slow rule and profile R" below |

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

## Defaults changed on 2026-10-30

The orchestrated review of 2026-10-29 (`/home/artur/agent_workspace/final/REPORT.md`, H-03; security
review S11 of task T-007) led to one change in what a suite run executes:

| Change | Before | Now | Why |
|---|---|---|---|
| gunicorn bind in the suite (`_start_web_stack`) | `0.0.0.0:8080` | `127.0.0.1:8080`, nginx's upstream (`proxy_pass http://127.0.0.1:8080` in `nginx.conf` and `nginx_unprotected.conf`) | gunicorn listened on every address of `server_ns`, so a client could reach the backend directly and bypass nginx's limits, its access log (the L7 rate rule and the L7 shadow) and SlowConn, which counts connections to :80 and :443 only |

What this means for earlier results: nothing, as far as the bypass goes. No published campaign's
client used it [FACT]: in every version of `test_distributed_suite.py` (`git log -G8080`), port 8080
appears only in the gunicorn bind; the legit clients, the readiness probe, wrk and the open-loop
generators target `HTTP_URL` (`http://10.0.0.1/`, port 80), hping3 `-p 80`, and the Slowloris and
R.U.D.Y. scripts `PORT = 80`. Not changed: `setup.sh` (the legacy two-namespace topology, still
`0.0.0.0:8080`) and the runners that start their own backend (`capture_testbed_dataset.py`,
`ml/capture_l7.py`, `ml/eval_l7.py`, all `0.0.0.0:8080`); `bench/executor.py` already binds
`127.0.0.1:8080`. The change is checked offline only (the suite's argv and the confs, in
`tests/test_daemon_robustness.py`); it has not been run on the testbed.

## Daemon robustness (2026-10-30)

Three defects from the review of 2026-10-29 (`/home/artur/agent_workspace/final/REPORT.md`) are fixed on
`fix/daemon-robustness`. Detection and enforcement are unchanged, and `tests/test_daemon_rules.py` passes
unchanged.

* **H-01: one request stopped the defence.** nginx's `escape=json` writes bytes ≥ 0x80 as they are, and both
  log tailers decoded strict UTF-8. One request with a non-UTF-8 User-Agent or URI therefore raised
  `UnicodeDecodeError`. In the R.U.D.Y. thread it ended the thread. In the main loop it reached the
  `finally`, which detached XDP and so lifted every ban. A valid multi-byte character cut by a partly
  written line did the same. Now undecodable bytes read as U+FFFD. Any other error from the access-log
  tailer is reported, and the tailer is recreated after 1 s with XDP still attached. Only Ctrl-C or SIGTERM
  reaches the `finally`. SIGTERM goes there through a new handler: before, it killed the daemon and left
  XDP attached. The suite itself uses SIGKILL. The handler and the `finally` ignore any further SIGTERM, so
  a second one cannot deadlock the stop (D-02).
* **H-02: threads died silently.** The telemetry loop had no guard, and no thread had a supervisor. One
  exception ended L4 detection, the TTL sweep and the idle eviction, or ended R.U.D.Y. detection, with no
  event. One such exception is bcc's bare `Exception` when a ban does not fit into the full 100 000-entry
  `blacklist_map`. Now each telemetry poll is guarded, and every worker thread runs under `supervise()`,
  which reports the exception and restarts the target after 1 s. The poll after a failed one only re-takes
  the per-source snapshots and applies no threshold (D-01). Read at once, its deltas would span the whole
  outage and ban sources at their normal rate.
* **H-03: the nginx bypass.** See "Defaults changed on 2026-10-30".

Every error the daemon survives is written as a `daemon_error` event and a console line.

`tests/test_daemon_robustness.py` checks this offline, against fakes:

* `UndecodableBytesTest`: 0xFF, 0x80, truncated sequences, and a character cut at the end of the file, in
  both tailers. Such lines still count for the rate rule.
* `MainLoopTest`: a tailer error keeps XDP attached. Ctrl-C after an error, or SIGTERM, detaches it once,
  even when a SIGTERM arrives inside `stop_event.set()`.
* `TelemetryGuardTest`: after a failed ban the TTL sweep still runs and the rules resume after one
  re-baseline poll. After a 30-poll outage no client is banned at its normal rate, and a flood that began
  during the outage is banned at its one-poll rate.
* `SupervisorTest`: the R.U.D.Y. thread bans again after its restart, every worker is supervised, and a
  worker that ends early is reported.
* `BackendBindTest`: the suite's gunicorn bind.

[NOT RUN] The live path needs the testbed: nginx writing raw bytes, a real full map, a real SIGTERM.

Known limits:

* A recreated tailer opens its log at the end, so lines written during the 1-s backoff are not read.
* After a failed poll, detection resumes one poll later: the next poll only re-takes the snapshots. A
  failed or re-baseline poll neither extends nor resets the SlowConn and low-SYN streaks. A flood that
  starts and ends entirely inside an outage of failed polls is therefore never banned, and every failed
  poll costs one poll of detection, even one that failed after all snapshots were taken (review R1-01).
* Only SIGTERM is ignored while the stop is under way. A second Ctrl-C during the shutdown can still
  interrupt the `finally` before the XDP detach (pre-existing, review R1-02), and subprocesses started
  during the shutdown inherit the ignored SIGTERM, so a hung shutdown needs SIGKILL (review R1-03).
* Because `ml/eval_l7.py` stops the daemon with SIGTERM, which is now graceful, its `l7_gru_poll` totals
  (summed over every record, `ml/eval_l7.py:162-164`) may include one extra, final poll, so compare them
  with P5/P5c with that caveat (D-04).

**H-26, the R.U.D.Y. client field (fixed on `fix/rudy-client-ip`, 2026-10-30).** The error-log rule took the
last `client: <IPv4>` of a line, so an address in the URI, the Host or the Referer was counted and banned
instead of the client. Non-ASCII digits made `ban_ip` raise, which restarted the thread, and a body-timeout
text that the client wrote into another line (a header timeout, an ignored header line) counted as well.
nginx writes the client field right after its message and action, and the request line and the headers only
after it (`ngx_http_log_error`, `src/http/ngx_http_request.c:3918-4007` of nginx 1.28.3). The pattern is now
anchored at the start of the line and takes the field up to the `, server: ` that follows it, and the tailer
ends lines at LF only, as nginx does, so a CR inside a field cannot start a forged line. A field that is not
an IPv4 address is skipped and reported (`daemon_error`, `where` `error_log`). Thresholds, window, keying,
the ban path and the ban event are unchanged. `RudyClientFieldTest` in `tests/test_daemon_rudy_client.py`
checks this offline, and each of its tests fails on the daemon before the fix. [NOT RUN] on the testbed,
where the rule does not fire at all: nginx 1.28.3 never writes "while reading client request body". The
string is in neither its sources nor the installed `/usr/sbin/nginx`, an HTTP/1.1 body timeout ends in a 408
without an error-log line (`src/http/ngx_http_request_body.c:276-282`), and none of the VM's error logs of
2026-10-07 to 2026-10-23 has such a line.

## P4: the per-connection slow rule and profile R (2026-10-30)

Part 1 of P4 (`docs/P4_SLOW_DESIGN.md`, approved 2026-10-30 as recommended) is built offline on
`feat/p4-slow-detector`; nothing of it has run on the testbed. Part 2, the generators' scale and the
runner, comes after the L7 v2 pipeline.

**Profile R**, a named configuration of the system under test (D-S1, D-S2). Every P4 arm runs on it, and in
P4 "unprotected" means R, not the hardened configurations above; results on R do not transfer to them, nor
the reverse.

| File | Arms | What it is |
|---|---|---|
| `nginx_profile_r.conf` | C, C', U | `nginx_l7capture.conf` with the knobs of §4.1 at the distribution's and nginx's defaults: 2 workers x 768 connections (1,536 slots), 60 s header and body timeouts, 75 s keep-alive, 60 s send timeout, `client_max_body_size` 1m (10m on `/upload`), `large_client_header_buffers 4 8k`, `proxy_request_buffering off` on `/upload` only, nginx's default proxy timeouts (60 s, P4-05), no limits. The daemon's access log gains the client port (`json_ml_port`), and `stub_status` listens on 127.0.0.1:8081 |
| `nginx_profile_r_limits.conf` | M_def, M_pc, M_tol | the same plus the deployed `limit_req` (30 r/s, burst 100) and `limit_conn` (50) |
| `gunicorn_profile_r.py` | all | 5 sync workers (2 x 2 CPUs + 1) on 127.0.0.1:8080; gunicorn's defaults otherwise, written out |

`tests/test_profile_r.py` pins every value statically. The proxy timeouts (P4-05) are nginx's own defaults,
60 s for connect, send and read (`ngx_http_proxy_module.c:3716-3723` of nginx 1.28.3), as D-S1 asks of every
value the design note does not set; the harness's 5 s / 10 s / 10 s are hardening, under which a request queued
behind R's five busy sync workers would end in a 504 after 10 s. `nginx -t`, the slot exhaustion and the sha256 in
each run's provenance belong to the runner and the smoke run.

**The per-connection rule** (`slow_pc.py`, engine `l4_slowconn_pc`; D-S4, D-S5, D-S7, D-S8). The deployed
slow rules key on the address, and SlowConn bans every subscriber behind a shared address (the CGNAT pools of
P5c.1). This rule judges each established socket of nginx on :80 and :443 from `ss -tinpH` once a second, in its
own supervised thread (P4-07: a slow or stuck `ss` delays this rule only, never the L4 rules of the telemetry
thread). A socket is suspect when nginx owns it (not one still in the listen
backlog), it is older than T since the first poll that saw it, it is unanswered (:80: `bytes_acked` <= 64;
:443: no request of that client port in the access log during its lifetime, judged only once the log has
shown a client port), it brought fewer than F bytes/s on average, and at least 2 data segments arrived after
that first poll (a request waiting on a slow server is spared). After 3 suspect polls in a row the connection
is closed. An address is banned only after K closes within 60 s and only with fewer than 3 UA keys in the
access log over 10 minutes; the TTL is the daemon's 300 s, and at most 500 closes per poll and 20 bans per
minute are carried out (the rest is logged as capped).

| Variable | Default | Meaning |
|---|---|---|
| `SLOW_PC` | 0 | 1 = run the rule. Alone it runs in shadow: it logs what it would close and ban and does nothing |
| `SLOW_PC_ENFORCE` | 0 | 1 = also close (`ss -K`, one filter per connection, at most 32 per call) and ban (XDP, then `ss -K dst`) |
| `SLOW_PC_KILL_FILE` | `/run/l7v2/kill` | while it exists, the rule runs in shadow (read every poll); so it does with `GRU_ONLY=1` |
| `SLOW_PC_T`, `SLOW_PC_F`, `SLOW_PC_K` | 20, 16, 6 | a point of the frozen grid, or the daemon stops at start. The default is the grid's most conservative point, a placeholder until the validation runs choose |
| `SLOW_PC_RECORD` | (none) | a gzip file that receives every poll's input (the `ss` text, the access-log items, the banned addresses), for `slow_pc.read_record()` and `slow_pc.replay()` |

**Frozen before any data** (§6.4, §13 row 3): the grid T in {5, 10, 15, 20} s, F in {16, 64, 256, 1024} B/s,
K in {2, 3, 4, 6}, the fixed constants, and `slow_pc.select_thresholds()`: on the validation seeds 4001-4002
(C, U_loris and U_post, the rule in shadow, replayed offline), among the points that ban no benign address,
close no slow uploader and close at most 0.1 % of the benign connections, the largest share of attacking
addresses banned within T_mit = 90 s (`slow_pc.DEADLINE_S`) of their first connection wins; ties go to the
larger T, the smaller F, the larger K; if no point qualifies, the rule fails its budget and the grid is not
widened. Its first commit holds
nothing else, and `tests/test_slow_pc_rule.py` pins its text by sha256.

**Re-registration record.** 2026-10-30: T_mit 30 → 90 s, decided by the user BEFORE any data, because the
frozen detector's dribble leg needs 2 data segments after the first poll. At the frozen pacing: W-SLOW's dry
run (T-023, seed 1): median closes 55 s (Slowloris) / 39 s (slow POST); the independent re-simulation (T-029):
52 s / 36 s, with a median ban at 66 s at K = 2. The share within 30 s stays reported as a secondary figure.
`slow_pc.DEADLINE_S` is T_mit for both the selection rule and the outcome of §10 (criterion (a)); the grid,
the constraints and the tie-breaks are unchanged, and the pin was renewed in the same commit. (The sources
were corrected the same day: the first version of this record, 74020b6, attributed all figures to one run.)

**Scoring the validation runs** (P4-03; `eval/p4_validation.py`, committed before any validation run). Each
validation run's manifest names its `SLOW_PC_RECORD` file and the role of every client address (`attack`,
`slow_uploader`, or any other benign kind). The scorer replays each record once, through one detector per grid
point (`Detector.poll_parsed`), counts every point's `slow_pc.Outcome` as the frozen definitions say, sums them
over the six runs (it refuses any other set of runs, and any address without a role) and applies
`slow_pc.select_thresholds()`. Next to each point it reports the share banned within 30 s, the secondary figure
of the re-registration. `tests/test_p4_validation.py` scores a synthetic validation set worked out by hand.

**The pre-registered outcome** (§10; `eval/p4_outcome.py`, written and tested before any evaluation data).
Over run records, one per run of the ten blocks (seeds 3101-3110, arms C, C', U, M_def and M_pc per family,
each run 30 s of baseline, 210 s of attack and 30 s of recovery;
`summarize()` builds a record from `eval/harm_gate.run_metrics` and the ban events), it decides per family
whether the attack is harmful (the harm gate on U against C, at least 10 valid blocks, the placebo not
passing, and at least 9 of 10 blocks harmed on their own) and whether M_pc mitigates it: (a) 5 consecutive
1-s bins back at 0.99 x Q(C) within T_mit = 90 s, (b) the level over [attack start + T_mit, attack end], 120 s
(`LEVEL_WINDOW_S`, 120-240 s of the run), (c)
no benign address banned. M7 is "supported with scope" for the families that pass, else "not supported";
Q(M_pc) - Q(M_def) and the bans per arm and role are reported. Two readings are the code's and are pinned
by tests: (a) starts counting at the first second below the threshold, a reading the user accepted on
2026-10-31 ("P4 recovery + HG4"), and (b)'s window starts at T_mit,
which was the note's "+ 30 s" when T_mit was 30 s. `tests/test_p4_outcome.py` covers each outcome the
note names on synthetic records.

**Re-registration record.** The P4 attack length 120 → 210 s, re-registered 2026-10-31 by the user, before any
data, so that the window of (b), from attack start + T_mit (90 s) to the attack's end, is 120 s long; a run is
now 270 s (`eval/p4_outcome.TIMELINE`). The VM budget of the note's §11 grows with it [ESTIMATE, §11's method:
the traffic plus about 60 s of set-up per run]: about 5.5 min per run instead of 4, so the smoke run (3 runs)
about 0.3 h, the harm ladder (24) 2.2 h, the validation (6) 0.55 h, the campaign (80) 7.3 h and the re-runs (at
most 16) 1.5 h: about 11.8 h in all, 10.4 h without re-runs, against 8.6 h and 7.5 h with the 120-s attack. The
Slowloris-only cut grows by the same factor, from about 5 h to about 6.9 h.

**Re-registration record (D-035, V-04).** 2026-10-31T12:44Z, the user's "Approve all four", before any data: the
validation runs run M_pc's daemon mode without enforcement (HEURISTIC_PROFILE=tolerant, SLOW_PC=1,
SLOW_PC_ENFORCE=0, SLOW_PC_RECORD), recorded under "daemon" in each manifest by `eval/p4_runner.py`;
`eval/p4_validation.py` refuses a manifest with another mode, a poll the rule enforced, and a poll whose banned
set holds an address that is not an attacker's (T-039 V-04: otherwise another engine's ban of a CGNAT pool would
make the benign constraints hold by construction).

**Re-registration record (D-035, V-08).** 2026-10-31T12:44Z, before any data: an M_pc run is valid only if the
per-connection rule logged `slow_pc_poll` at least every 10 s (`eval/p4_runner.py` SLOW_PC_POLL_GAP_S = 10.0; the
daemon logs one every 5 s, so this is two missed reports), with no longer gap from the traffic's start to the first
poll or from the last to the run's end; the runner applies the same bound to the validation runs.

**Re-registration record (D-035, V-01).** 2026-10-31T12:44Z, before any data: the harmed second of (a) is the
first of 5 consecutive 1-s bins below 0.99 x Q(C) inside the attack window, and the recovery the end of the first 5
consecutive bins at or above it after that second (0 when no such harm; `eval/p4_outcome.recovery` reports the
recovery with its onset). With the first reading, one noisy bin made a late recovery pass (T-039 V-01: P(a) per
block 0.68-0.96 for a true recovery at +95 s); seeded binomial fixtures now pin that a recovery at +95 s fails (a)
and one at +60 s passes, at 20 and 50 judged requests a second and Q(C) 99.5 and 99.9.

**Re-registration record (D-035, V-02).** 2026-10-31T12:44Z, before any data: fewer than 10 valid blocks decide
nothing. The family's status is "invalid (k of 10 valid)", never "not harmful" or "harmful but not mitigated"; M7
is "invalid (k of 10 valid)" unless another family qualifies, and then it names the invalid family next to its claim
(T-039 V-02: one block that stayed invalid used to make a family "not harmful").

**Re-registration record (D-035, V-03).** 2026-10-31T12:44Z, before any data: the outcome takes every attempt of
the run index (`eval/p4_runner.py --summarize` writes a record for each, valid or not, and each record names its
attempt): the harm and (a) and (b) are judged on the last valid attempt of each (block, arm), while (c), the benign
connections closed and the bans per arm count ALL attempts, invalid ones included, so that a re-run cannot hide a
ban (T-039 V-03, the recurrence of T-028 F-01).

**Re-registration record (D-041).** 2026-10-31T16:06Z, the user's "Approve as recommended", before any data
(T-023c F3, T-039 V-13: in simulation the deployed limits refuse CGNAT-24 requests in 9 of 10 seeds). Each block gains an attack-free protected control C_M: profile R with
`nginx_profile_r_limits.conf` and M_pc's daemon configuration, no attack, seeded with the block, its validity rules
C's. Criterion (b) compares M_pc's level window with 0.99 x Q(C_M) instead of Q(C); (a) and the harm stay on Q(C). The
limits' own cost, Q(C_M) against Q(C) and the 503s by role with the CGNAT pools named, is reported as a separate
finding and judges nothing. The VM budget by §11's method at about 5.5 min per run: the campaign is 90 runs, 8.25 h
(was 7.3 h), the re-runs at most 18, 1.65 h (was 1.5 h), about 12.9 h in all and 11.3 h without re-runs (were 11.8 h
and 10.4 h); the Slowloris-only cut about 8.0 h (was 6.9 h). These count §11's 3 smoke runs; the P4-S packet as drafted
holds 5 runs and hand steps, about 0.75 h, which would add about 0.5 h. The same decision accepted four readings:
the slow_pc liveness bound also on the validation runs; M7 states its claim and names an invalid family; "seeded
order" is each block's runs in a seeded order; `/upload` is class C6 doing C2's work until a measured C6 cost exists.

**When the limits refuse, by simulation [computed, NOT RUN; T-023c `artifacts/limits_windows.txt`].**
`ml/l7_admissibility`, limit_req at 30 r/s with a burst of 100, 10 seeds of the 270-s run: CGNAT-24 is refused mean 62
and at most 207 of about 3,190 requests in the attack window and none in the level window, 120-240 s; CGNAT-12 none in
either (at most 69 in the baseline). The refusals follow the pools' cold first views, whose arrivals end at 60 s. So in
this simulation the level window carries none of that cost, while Q(C_M), taken over the attack window as Q(C) is,
does: when CGNAT-24 sits on a judged link it lowers the bar of (b) by about 0.7 pp on average and 2.5 pp at worst
[INFERENCE from the counts], and not at all on another link. `limits_cost()` reports C_M's level next to Q(C_M), so
the runs will show it. A simulation of the plan is not a measurement: it has no network or server time.

**Re-registration record (D-046).** 2026-11-01T15:52Z, the user's "Keep, with changes", before any data, told first
that the premise of D-041 was overstated (the paragraph above). C_M stays, and: (1) criterion (b) compares M_pc's level
window with 0.99 x C_M's `q_level` over the same window, not with C_M's Q over the attack window; (2)
`harm_gate.control_health` (Q(C) at least 99 %, each route class at least 95 %) is enforced for a block to count in the
campaign, as §10 cites the harm gate: an unhealthy control makes the block invalid, "invalid (k of 10 valid)", never a
negative verdict; it judges C alone, and C_M keeps no floor; (3) a CGNAT or browser identity banned in C_M, in any
attempt, counts against (c), for both families. The VM budget does not change.

The R.U.D.Y. error-log rule (`l7_rudy`) is unchanged, but it cannot fire on this testbed (see H-26 above):
on profile R the per-connection rule is the only slow-POST detector. Retiring or re-sourcing `l7_rudy` is the
user's decision.

Tests, all offline: `tests/test_slow_pc_rule.py` (the frozen rule), `tests/test_slow_pc.py` (the `ss`
reader and the detector on the cases of §9: CGNAT pools answered on :80 and through the log on :443,
Slowloris, slow POST below F, a slow uploader above F, a waiting request, a backlog socket, a TLS handshake
without a request, the guards, the window, the UA guard, the TTL, the caps), `tests/test_daemon_slow_pc.py`
(the rule in the daemon's real loop: off by default, shadow, enforcement, the kill switch, the caps, a
CGNAT pool that SlowConn bans at 8 and that nothing bans in the new arm, the record and its replay),
`tests/test_profile_r.py`, and `tests/test_l7_admissibility_pc.py` (the admissibility replica: both CGNAT
pools trip SlowConn at the default 8 and the per-connection rule closes none of their connections at any grid
point).

[NOT RUN] on the testbed: the token layout of `ss -tinpH` (F-S3; a fixture recorded in the smoke run will be
a test), the `ss -K` filter closing exactly one socket, the reader's cost at ~2,000 sockets per poll,
`nginx -t` and the harm of profile R.

Known limits:

* A connection's age counts from the first poll that saw it. One that existed before the rule ran (or before
  a ban of its address ended) looks younger than it is, so its average rate looks higher.
* The :443 leg needs a client port in the daemon's access log (profile R's `json_ml_port`). With the deployed
  `json_ml_format` the rule judges :80 only.
* In shadow, a connection is judged closed once and then skipped, so a shadow run's decisions are those an
  enforcing run would have made only until the first close: the attacker's reconnects are not simulated.

## L7 v2: the enforcing arm (2026-10-31)

The enforcing arm of `docs/L7V2_DESIGN.md` section 9 (D-V7, approved 2026-10-30) is built offline on
`feat/l7v2-enforce`; nothing of it has run on the testbed. It is off unless `L7_ENFORCE=1`, so the default daemon,
and the L7 shadow without it, run as before. Modules: `l7_denymap.py` (what may be written into nginx's
configuration, and the raw side table), `l7_enforce.py` (the decision policy and the safeguards), `l7_arms.py` (one
path for every arm), `l7_conf.py` (the P1 runner's conf copies).

**Policy.** The L7 v2 view engine stays observe-only; the arm acts, in its own supervised thread (`l7_enforce`), on
the `l7_would_ban` events the shadow thread logs. No action on an allowlisted address (127.0.0.0/8, the server's
10.0.0.1, `L7_ALLOWLIST`), on a key already acted on, or on an address already banned; a key younger than 20 s
(from its first request seen) waits until it is 20 s old.
* Level 1: the (IP, UA, sid) key gets a line in `<L7_ENFORCE_DIR>/deny.map`, and nginx answers it 429. The map is
  written atomically and nginx reloaded (`nginx -c L7_NGINX_CONF -s reload`) at most once per 10 s, batched. Only
  keys that pass the write rules of 9.4 are written: a canonical IPv4 address, a printable-ASCII UA of at most 256
  bytes without `"`, `\`, `{`, `}`, `$` (a `;` is allowed since D-038), and an empty sid or one in the server's format. Any other key is an
  `l7_enforce_miss` (unenforceable). Keys that differ only in case share a line (nginx matches map strings ignoring
  case and refuses a map that lists one twice).
* Level 2: an XDP ban of the address through `ban_ip` (engine `l7v2`, TTL 300 s), then `ss -K dst`, only if the key
  sent a request at least 30 s after its deny took effect (after the decision, for an unenforceable key) and the
  address had fewer than 3 UA hashes and fewer than 3 sids in the last 10 min. An address with more is never banned
  by the arm (the CGNAT guard; `l7_enforce_skip` reason `cgnat_guard`).
* A deny ends 300 s after it was added, unless it is renewed (D-047, a pre-data change, for every arm): when its TTL ends and its
  key still sends (a request that started in the last 120 s) or its address is XDP-banned, the TTL starts again in place, with
  no new would-ban, no reload and no new line (`l7_deny_renew`, with the arm and the level). A key that stopped sending lets its
  deny expire. The kill switch ends every deny, and nothing renews one afterwards. When an XDP ban has ended, level 2 applies
  again as the first time, its `ban` carrying `renewal`. `tests/test_l7_deny_renewal.py` covers it.

**Safeguards.** The kill switch: while `L7_KILL_FILE` exists (read every step; by default `/run/l7v2/kill`, the same
file as `SLOW_PC_KILL_FILE`) no action is taken, and when it appears the map is emptied with one reload, which keeps the
10-s spacing (T-042 E04: up to 10 s later; a flapping file cannot storm nginx), and the arm's
own XDP bans are lifted (`unban` with `lifted_by` `l7_kill`); every other engine's bans stay. At most 20 level-2 bans
in any 60 s and 2,000 active denies; beyond either, `l7_enforce_capped` and no action. The map is emptied at the
daemon's start (a map an earlier daemon left) and at its stop, after XDP is detached.

**R*** (9.5, 10, 19; T-025e). The best rule arm runs on its own (IP, UA) path, `l7_rule_engine.py`, with the replay's own
statistics and scorer, through this same policy. Its level 1 is a line in `<L7_ENFORCE_DIR>/deny_key.map`, `"ip|ua" 1;`,
which covers every session of the key: a run's conf maps `"$remote_addr|$http_user_agent"` to `$l7_deny_key`
(`l7_conf.protected(text, run_dir, key_map=True)`) and `l7_denymap.prepare_run_dir(run_dir, key_level=True)` creates the
file before nginx starts. The write rules, reload pacing, TTL, caps, kill switch, start and stop are the same; D-040's
guard is not, as a line of R*'s means to hit every user behind its key, and D-043 charges them. Level 2 keeps the CGNAT
guard. `ml/l7v2_replay.RulePath` is the reference for its decisions.

**One path for every arm** (9.5). The arm's detector and its own operating point come from a frozen selection: the view
GRU, the HGB or the LR from `ml/train_l7v2.py select`, behind `score(batch) -> p`, or R* from `ml/l7v2_rules.py select`
(`L7_ARM=R*`), whose calibration record must also be frozen and whose rule spec must be this tree's. A selection that is not the recorded one, an altered artifact, an arm whose operating
point is null (its package carries the placeholder 0.5 x 1), a selection not marked `valid_for_claims` (a smoke run or
a legacy capture; T-042 E05), and the replay-only ablations are refused: the daemon writes why as a `daemon_error`
(`where` `l7_enforce`) and does not start.

| Variable | Default | Meaning |
|---|---|---|
| `L7_ENFORCE` | 0 | 1 = run the arm; needs `L7_SHADOW=1`, `L7_NGINX_CONF`, `L7_SELECTION`, `L7_SELECTION_SHA256`, `L7_ARM`, and `L7_MODEL` unset, or the daemon stops at start. `bench/executor.py` plans it 0 |
| `L7_ENFORCE_DIR` | `/run/l7v2` | the run directory that holds `deny.map`; created 0700, refused if others may write to it |
| `L7_NGINX_CONF` | (none) | the configuration of the nginx the arm reloads (the run's copy, `l7_conf.protected`) |
| `L7_ALLOWLIST` | (none) | comma-separated IPv4 addresses or networks never acted on (the runner's monitoring identities), besides 127.0.0.0/8 and 10.0.0.1 |
| `L7_KILL_FILE` | `/run/l7v2/kill` | the kill switch |
| `L7_SELECTION`, `L7_SELECTION_SHA256`, `L7_ARM` | (none) | the frozen selection, its recorded sha256, and the arm's name (`view_gru`, `hgb`, `lr` from the learned selection; `R*` from the rule selection) |
| `L7_SOCKET_GROUP` | `nogroup` | the group of the L7 socket, bound 0660 instead of 0666 while the arm runs (T-042 E06): a datagram there can drive a ban. Assumption: nginx's workers run as nobody:nogroup, the compiled defaults of the installed nginx 1.28.3 (no `--user`/`--group` in its configure string) with no `user` directive in `nginx.conf` or the runner's copy; with a `user` directive, set its group. Without `L7_ENFORCE=1` the socket stays 0666 as before |

**The runner's confs** (ledger D-028, review L7V2-09): `l7_conf.unprotected(text)` adds `ref`, `sid` and `sid_set` to
the l7json of a run's own copy of `nginx_unprotected.conf` (C, C', U); `l7_conf.protected(text, run_dir)` adds the
deny map, `map_hash_bucket_size 1024`, `map_hash_max_size 8192` and `if ($l7_deny) { return 429; }` to a run's own
copy of `nginx.conf` (the M arms). The tracked files are not changed (`nginx_unprotected.conf` is pinned by the harm
benchmark). nginx refuses a map whose longest key does not fit a hash bucket, and the default bucket (one cache line)
does not fit a testbed browser's key.

Also fixed on this branch: with `L7_SHADOW=1` and an L7 v2 view package, the shadow thread's 5-s `l7_shadow` report
passed `truncated` twice (the ingest's truncated datagrams and the key store's truncated keys), so the thread was
restarted every 5 s with a fresh engine. The key store's count is now `store_truncated`.

Tests, all offline: `tests/test_l7_denymap.py` (hostile UAs and sids against the write rules, the file read back with a
port of nginx's tokenizer), `tests/test_l7_rawkeys.py`, `tests/test_l7_enforce.py` (the policy on fakes),
`tests/test_l7_safeguards.py`, `tests/test_l7_arms.py`, `tests/test_l7_conf.py`, `tests/test_daemon_l7_enforce.py`
and `tests/test_daemon_l7_shadow_v2.py` (the daemon's real L7 shadow thread and the arm's steps on the harness's
fakes), and for R* `tests/test_l7_rstar.py` (its parity with the replay), `tests/test_l7_rstar_map.py` and
`tests/test_l7_rstar_events.py`.

[NOT RUN] on the testbed: R*'s path and its map; `nginx -t` of the rendered copies with a full map, a reload under load, a deny answered
429, the reload's cost and the lingering of old workers (9.2's fallback, `auth_request`, is not built).

Known limits:

* D-038 (2026-10-31, the user: "Allow ';'"): 9.4 as written excluded `;`, which every User-Agent of
  `ml/l7_benign.UA_TABLE` contains, so no testbed browser key could have been denied at level 1. Inside nginx's
  double quotes `;` is an ordinary character; it is now written, and all 17 UA_TABLE entries pass the rules. `"`,
  `\`, `$`, `{`, `}`, other bytes and UAs over 256 bytes stay excluded.
* R*'s parity with the replay holds while `evicted` in `l7_shadow` is 0 (at most 65,536 keys and addresses are kept live).
* `users_seen` counts sessions, not devices: one user can hold several. The run's manifest gives the devices.
* The stop (T-042 E03): `Arm.stop` and the arm's steps hold one lock, and no step runs after the stop, so once the
  stop returns `deny.map` is empty and nginx was told to reload it.
* Hostile field types (T-042 E07): a log record whose text field (ip, ua, uri, sid, ...) holds another JSON type than a
  string, which only a forged datagram can produce, is dropped at ingest (`l7_ingest.normalise`); it used to raise and
  restart the shadow thread with a fresh engine. Numeric fields are coerced as before.
* D-040 (T-042 E02): a key without a session is written as `ip|ua|`, which nginx matches for every cookie-less request
  from that address with that UA (in any case), including the first request of another user's session (a 429 means
  the server never sets that user's sid). So such a key is denied at level 1 only while its address is single-key
  (fewer than 3 UA hashes and 3 sids in 10 min); on a shared address it is a miss (`sid_less_shared`), and a line
  already written is withdrawn (`l7_deny_end` reason `cgnat_guard`) at the next write once the address turns shared;
  nginx keeps the old map until that reload (at most 10 s). Such a key can still reach level 2 only if single-key.
* A bot that sends a fresh well-formed sid with every request gets a new key each time (T-025b F8), and its address
  looks multi-key, so neither level reaches it; the population-level detector is the counter.
* `nginx -s reload`'s exit status says whether the new configuration parsed; that the workers took it is seen only
  in the 429s.

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
| `start` | `pid`, `backend`, `gru_only`, `xdp_gru`, `interface`, `model`, `model_sha256`, `scaler_sha256`, `xdp_sha256`, `thresholds`; since P4 also `slow_pc`, `slow_pc_enforce`, `slow_pc_sha256`, and `slow_pc_t_s`, `slow_pc_f_bps`, `slow_pc_k` in `thresholds`; since L7 v2 also `l7_enforce`, `l7_enforce_sha256`, `l7_arm`, `l7_selection_sha256` |
| `ban` | `ip`, `engine`, `reason`, `backend`, `enforced`, `ttl_s`, `value`, `threshold`; plus `bytes` (`l4_slowconn`), `error_ratio` (`l7_rate`), `hits` (`gru`), `ua_keys` (`l4_slowconn_pc`: `value` is the address's closes within 60 s, `threshold` K) |
| `unban` | `ip`, `backend`, `age_s`; `lifted_by` `l7_kill` when the L7 v2 arm's kill switch lifted it |
| `suppress_on`, `suppress_off` | `syn_delta`, `pkt_delta`: the GRU pause during volumetric floods (observed once per 1-s poll) |
| `gru_suppressed` | `ip`, `value` (probability), `hits`: a GRU detection dropped because the pause was active |
| `daemon_error` | `where`, `error` (type and message, at most 300 characters), `action`: an error the daemon survived and retried (since 2026-10-30; `where` is `access_log` for the main loop's tailer, `telemetry` for one L4 poll, `thread:<name>` for a worker thread's target: `telemetry`, `inference`, `rudy`, `l7_shadow`, `slow_pc`, `l7_enforce`; `l7_enforce` also for a step of the L7 v2 arm that failed, or a deny map not emptied at the stop; `error_log` for a R.U.D.Y. body-timeout line whose client field is not an IPv4 address, skipped with `action` `line skipped`, H-26; `slow_pc` for a failed `ss` read or `ss -K` call of the per-connection rule, `slow_pc_record` for its record file). A run without one had no such error |
| `slow_pc_close` | `ip`, `port`, `local`, `sport`, `age_s`, `bytes_received`, `bytes_acked`, `segs_after`, `streak`, `ua_keys`, `enforced`: a connection the per-connection rule closed (`enforced` true) or would have closed (shadow) |
| `slow_pc_would_ban` | `ip`, `value` (closes within 60 s), `threshold` (K), `ua_keys`: a ban the rule decided in shadow |
| `slow_pc_close_retry` | `ip`, `port`, `local`, `sport`, `attempt`, `gave_up`: a closed connection still there at the next poll, closed again (`attempt` 2 or 3) or, after the last retry, given up (`gave_up` true; P4-06). A connection that ended between the read and the kill is gone, not an error, and the exit status of `ss -K` decides nothing |
| `slow_pc_capped` | `what` (`close` or `ban`), `n`, `cap`, and for bans `ips` (at most 50): decisions held back by the caps of 500 closes per poll and 20 bans per minute |
| `l7_enforce_arm` | `armed`, `reason` (why not), `arm`, `arm_kind`, `model`, `selection_sha256`, `valid_for_claims`, `level`, `threshold`, `consecutive`: the L7 v2 arm attached to the shadow thread's engine (`L7_ENFORCE=1` only, as every kind below). R* adds `rule_arm`, `stat_threshold`, `calibration_sha256`, and every decision event of R* (and its `ban`) adds `rule_arm`, `statistic`, `stat_threshold` and `users_seen` (the session ids seen under the key so far), with `sid_h` null |
| `l7_deny` | `ip`, `ua_h`, `sid_h`, `arm`, `threshold`, `consecutive`, `p`, `t_poll`, `level` (1), `shared` (a case-insensitive twin's line covers it), `key_age_s`, `active`, `ttl_s`: a key denied at nginx |
| `l7_deny_renew` | the key fields, `level` (1), `why` (`sending`, `xdp_banned`), `renewal` (the count), `denied` (false for a tracked miss), `last_request_s`, `ttl_s`, `active`: a deny's TTL started again (D-047) |
| `l7_deny_end` | the key fields, `reason` (`ttl`, `kill`, `stop`, `cgnat_guard`: a sid-less line withdrawn when its address turned shared, D-040), `denied`, `effective`, `age_s` |
| `l7_enforce_skip` | the key fields, `reason` (`not_armed`, `killed`, `ip_format` (not a canonical dotted-quad IPv4 address), `allowlist`, `already_denied`, `ip_banned`, `key_age` with `key_age_s` and `until`, `cgnat_guard` with `ua_keys` and `sid_keys`) |
| `l7_enforce_miss` | the key fields, `rule` (the write rule the key fails, `no_raw`, `ambiguous`, `sid_less_shared`: a key without a session on a shared address, D-040): unenforceable at level 1 |
| `l7_enforce_capped` | `what` (`deny`: the key fields, `cap`, `active`; `ban`: `n`, `cap`, `ips`, at most 50) |
| `l7_reload` | `ok`, `entries`, `changes`, `detail` (nginx's error text with quoted strings blanked) |
| `l7_kill` | `on`; when on, `denies` emptied and `bans_lifted` |
| `l7_enforce_poll` | every 5 s: `armed`, `killed`, `active`, `waiting`, `tracked`, `raw_keys`, `raw_evicted`, `raw_ambiguous`, `ips`, the counters (`would_bans`, `denied`, `renewed`, `missed`, `level2`, `guarded`, `capped`, `reloads`, `reload_failed`, `ended`, `lifted`, `inbox_dropped`, `observe_errors`), `skips`, `first_error` |
| `slow_pc_poll` | every 5 s: `mode` (`shadow` or `enforce`), the counters since the last one (`polls`, `ss_failed`, `suspect`, `closes`, `capped_closes`, `bans`, `capped_bans`, `spared` by the shared-address guard, `skipped_lines`, `close_retries`, `close_failed`: connections given up after the last retry), `sockets`, `owned`, `tracked`, `bad_sample` (the first skipped line), `inbox_dropped`, `note_errors` |

Engines: `l4_syn`, `l4_volumetric`, `l4_slowconn`, `l4_lowsyn`, `l7_rate`, `l7_rudy`,
`gru`, `l4_slowconn_pc` (P4, the per-connection slow rule; only with `SLOW_PC=1 SLOW_PC_ENFORCE=1`), `l7v2` (the L7 v2
arm's level 2, only with `L7_ENFORCE=1`; its `ban` adds `level`, `arm`, `p`, `consecutive`, `ua_h`, `sid_h`,
`ua_keys`, `sid_keys`, `after_s`, `denied`). The `value` of the L4 engines is a count per poll interval (1 s plus the loop's
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
of the calibration (`relative`, the default: a ceiling of 100 ms on the slip p99 pooled over the legit requests and a difference to the
control's of at most 50 ms; `strict`: every engine flag clear and each stream's slip p99 under 50 ms, computed always), the executor called its runs sound, and its
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
| `bench/executor.py` | one run (`C`, `Cp` or `U`) of a plan: preflight (root, venv, descriptors, a clean tree, no leftovers), the environment gate (uptime and load for the first run of a process, the timer on the legit CPU for every run, against the calibration's `validity.timer_p99_ms`), the topology built with the suite's primitives and read back, gunicorn and Nginx in `server_ns`, the streams on their timeline, telemetry at 1 Hz, collection into the run contract with `executor.ok`, and a teardown that is shielded from a second Ctrl-C |
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
place twice, after the files of the failed attempt are removed (those of the last attempt stay); any error raised after it ends the run,
tears down, and writes `FAILED`. Nginx is started like the origin, a process of its own with its stderr in `nginx_start.log`, and not run
to completion with its output captured (S3: that call returned only at its timeout). The teardown logs how long each step took: the processes of
the namespaces, each namespace and each link, and the check for leftovers.

**Smoke tests.** `--rho`, `--timeline` and `--timer-limit-ms` (`executor.py plan|run`, `gate_campaign.py`) shorten or lighten a run, or
loosen the timer gate for it. They are recorded as `overrides` in `plan.json`, `run.json` and `block.json`, and `environment.json` says
the timer limit used (`timer_limit_ms`) and whether a smoke test set it (`timer_limit_is_override`); the timer itself is measured and
recorded as it was. The limit is otherwise the calibration's `validity.timer_p99_ms`, and `gate_campaign.py` needs `--dry-run` with
`--timer-limit-ms`. `eval/harm_gate.py` gives no verdict on a campaign whose runs or blocks carry any override: INVALID, with the reason,
whatever the figures, and the report has a SMOKE TEST banner. Its blocks are assessed all the same, so the reason starts no re-run.
`--allow-overrides` lifts it for a simulated campaign (`gate_campaign.py` passes it itself for a host that says it is simulated) and for
tests, and the report then says that the verdict was allowed and is no result. A stream whose schedule has no request (a small load
over a short run leaves some) is not judged for its CPU share: its microseconds of CPU over its microseconds of wall time came out above
the limit (S3).

**The clocks of the streams.** The engine writes no absolute time, so the executor estimates when each stream's schedule began from its
exit time less its wall time, and `executor.ok` is false when the pack of a group (the most legit streams that began within 0.5 s of one another)
is not a majority of it (14 of 29 may be outside it), or one of the streams outside it is one whose loop ended more than 0.1 s after its last request,
or two streams of a group began more than 2.5 s apart (`executor.stragglers` in `run.json` lists the streams outside the pack; their offsets place
their records), the attack began more than 0.5 s from the end of the baseline, a stream died,
left nothing or exited non-zero. The wall time is first raised to the last request's
`t_done` plus 0.05 s when it is shorter, because an engine that is descheduled between reading its schedule's zero and its wall clock
(29 streams starting together on one CPU) reports too short a wall time; `executor.wall_gap_s` records the raise of each stream. `executor.exit_epoch_s` keeps the exit stamp each start was made from, to the millisecond, so that the time
an engine took to exit can be read against the time its summary was written (docs/HG1C_DESIGN.md, departure 26). Against an
origin's own arrival log on loopback (S1, S1b) the corrected estimate of a legit stream is within -0.03 to 0.06 s; `exit_delay_per_request_s`
corrects the exit delay of the attack streams, which grows with the request count (about 8 us per request, from three points) and is 0 until
S4 has measured it. A stream that really begins up to 2.5 s from the others is placed where it began: against the Nginx
access log its offset is right to 0.07 s at the median (0.21 s at most, 30 streams of 8 S3 runs), and the price is that two runs differ in 2.7 % of
the legit requests of the attack window at the median, 4.2 % at most (docs/HG1C_DESIGN.md, departure 22). The capacity probe reads the middle of each
20 s step (5 to 17 s), 3 s from its edges, so a staged run is judged at 3 s for the spread of a pack, the range of a group and where a later group begins, and not at 0.5 s (departure 24); the legit start-up delay of the settings is 2.9 s (departure 25). An engine exits when its last request is done, so a stream of a few tenths of a request per
second ends long before the timeline does; the executor calls a stream dead only if it exits early with a non-zero code or without its summary and
records.

**The campaign** runs a block's three runs in a drawn order; a run that fails or is found unsound ends its attempt (finishing an invalid
block spends VM time on nothing), and the block is re-run once with its seed if the gate has re-runs left (`max_reruns`, 2). A campaign
that can no longer reach the gate's `min_blocks` valid blocks stops (`--keep-going` goes on). A refusal, a setup that cannot be built,
Ctrl-C and a leftover stop the campaign without counting as a failed block; the same command resumes, skipping the runs that are `DONE`.
**The calibrator** stops, and says what that means, when the host cannot be calibrated: a first capacity level that is already unhealthy, a
capacity above the range of the probe, no saturation, origin sessions that disagree by more than 10 % twice (it keeps the sessions it measured in `origin/stopped_N.json` and names the route and session that disagreed), a screening whose controls
are unhealthy or more than 2 pp apart. Nothing is tuned to get past a stop. The origin step waits for the environment gate of a campaign's start (uptime 30 minutes, load below 0.3, up to `--wait-gate` minutes) and times each route on the calling thread's CPU clock in batches of at least 1 ms with the routes in turn, measurement changes made after HG2b's stops, with the 10 % rule unchanged and the calibration's thresholds that `RulesPinnedTest` lists pinned (docs/HG1C_DESIGN.md, departures 28 and 29); `ladder`, `reference` and `freeze` refuse an origin measured with another estimator, or one whose record does not say which.

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
