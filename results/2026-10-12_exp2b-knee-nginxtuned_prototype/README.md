# EXP-2b: Nginx limits only with a tuned config, HTTP flood at the knee (2026-10-12)

The HTTP flood (`ONLY_SCENARIOS=4`) at the "knee" operating point (now `OPERATING_POINT=knee`:
one gunicorn worker and thread pinned to cpu0, the attack generators pinned to cpus 1–7,
`wrk -c400` from 10 bots), in the mode "Nginx limits only" (`MITIGATION_MODE=none NGINX_PROTECTED=1`:
no daemon, rate limits on) with a tuned Nginx config. Three runs, recorded on 2026-10-12,
13:21–13:25 UTC, four minutes after EXP-2a ended. Reported in
`docs/REPORT_ADDENDUM_EXP0_EXP1.md` §K. The question was whether the collapse of rate limiting
alone in EXP-2a (`../2026-10-12_exp2a-knee_prototype/`) came from the 503 answers and the
per-rejection logging.

The tuned config (`source/nginx_limits_tuned.conf`) differs from `nginx.conf` of commit `6fc27fa`
by five added and two changed lines (**[FACT]**, `diff`): `limit_req_status 429` and
`limit_conn_status 429`; `limit_req_log_level warn` and `limit_conn_log_level warn`; a
`map $status $loggable` that is 0 for 429; `access_log … if=$loggable`; `error_log … error` instead
of `info`.

Tags: **[FACT]** recomputed from the files of this campaign; **[INFERENCE]** reasoned;
**[CLAIMED]** stated in the addendum, no data here.

## Result

**[FACT]** (`analysis/summary.md`)

| Legit success | Before | During the flood | After |
|---|---|---|---|
| pooled, 3 runs | 99.0 % (n = 104) | **62.1 %** (n = 116; run-bootstrap 48.6–77.5) | 100 % (n = 232) |
| per run | 100 / 100 / 97 | 59 / 78 / 49 | 100 / 100 / 100 |

* Latency of the requests that were served during the flood, p50 / p95: 'perfect' clients
  4,112 / 9,931 ms (n = 25), all clients 3,650 / 9,839 ms (n = 72). Requests started in the first
  10 s: 25.0 % served ('perfect', n = 20), 25.4 % (all, n = 59).
* Server (mean over the attack phases): Nginx 96 % of cpu0, total CPU 22 %, 50,333 packets/s
  reaching the server, `IP_InReceives` 53,698/s, 5,036 established TCP connections.
* No daemon, so no ban events; the harness reports 0/10 banned and FAIL in every run (the suite's
  criterion), and the flood lasted 16.3–16.4 s in every run.

**[INFERENCE]** The collapse does not come from the status code or the logging: with the status
changed and the rejection logging suppressed, Nginx still sits at about 96 % of the one core and
the packet rate is high. The bots are closed loop (`wrk`): an answer that is cheap and immediate
lets them fire again at once (addendum §K). A comparison with EXP-2a's untuned config (a different
campaign, recorded just before) is an unpaired comparison of two sets of three runs.

## How it was recorded

Three consecutive runs of `python3 <suite copy>` from the repository root
(`source/run_knee_nginxtuned.sh`) with `GUNICORN_WORKERS=1 GUNICORN_THREADS=1 SERVER_CPUS=0
ATTACK_CPUS=1-7 WRK_CONNS=400 BOTNET_COUNT=10 ONLY_SCENARIOS=4 MITIGATION_MODE=none
NGINX_PROTECTED=1 NGINX_CONF_OVERRIDE=<tuned config>`.

**[FACT] Provenance, checked against this repository**

* The recorded commit is `6fc27fa`. Its suite is not what ran: the suite copy `d/`, SHA-256
  `f11ff9fc…`, is `git show 6fc27fa:test_distributed_suite.py` plus
  `docs/D1_D2_unique_mac_and_nginx_restart.patch` (unique veth MACs, Nginx restart; `9f786908…`),
  plus `source/EXP1c_nginxlimits_mode.diff` (the Nginx-limits mode; `702b514b…`), plus
  `source/EXP1d_calibration_knobs.diff` (the operating-point knobs and the config override).
  Applying the three patches in this order reproduces `f11ff9fc…`.
* The suite copy of EXP-2a is `6e57743a…`. It equals this copy with the one line
  `NGINX_CONF = os.environ.get("NGINX_CONF_OVERRIDE", …)` put back to `NGINX_CONF = f"{PROJECT_DIR}/nginx.conf"`:
  the two campaigns differ in the hook that selects the config, nothing else in the suite.
* The tuned config has SHA-256 `cd59b412…` (`source/provenance.txt`). The daemon was not run
  (`control_plane.py` is not among the recorded inputs).
* End state: 0 Nginx processes, 0 network namespaces.

## Approximations introduced by the import

Imported with `eval/import_legacy_campaign.py` (each run's `provenance.json` is marked `imported`).
The CSV rows are copied verbatim: the three runs' rows concatenate to the source files (9 metrics
rows, 45 availability rows, 452 request rows; SHA-256 of the sources in `source/source_sha256.txt`).

* Attack start = the Phase-1 (baseline) metrics timestamp, written just before the launch; attack
  end = the Phase-3 timestamp, written just before the kill. Request start = completion time − latency.
* Client network profiles were not seeded and their plan was not recorded: runs are independent, and
  the mix differs (run 1: 10 'perfect', 6 broadband, 3 mobile_3g, 1 mobile_bad; run 2: 5, 7, 7, 1;
  run 3: 5, 9, 4, 2).
* The mode name in the directory (`nginxlimits`) is the importer's; the config is the tuned one,
  as stated here and in `provenance.json` (`inputs_sha256`).
* `imported.from` in `provenance.json` is the scratch directory in which the source was assembled,
  not a repository path.

## Reproducing

    cd results/2026-10-12_exp2b-knee-nginxtuned_prototype && sha256sum -c SHA256SUMS
    venv/bin/python eval/analyze_campaign.py results/2026-10-12_exp2b-knee-nginxtuned_prototype
    venv/bin/python eval/plot_campaign.py results/2026-10-12_exp2b-knee-nginxtuned_prototype

regenerate `analysis/` byte for byte. `tests/test_prototype_campaigns.py` pins the numbers above.
The comparison with the addendum is kept in `results/README.md`, not here.

## Limitations

Three runs, one scenario, one operating point, one mode: a descriptive measurement, not a test.
The per-run spread is wide for three runs (49–78 %), so any difference to EXP-2a's three untuned
runs is a statement about three runs against three. The knee is deliberately severe (one worker on
one core), and the attacker is closed loop.
