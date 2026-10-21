# EXP-1, 1b, 1c: the full suite at the default operating point, four modes × 3 runs (2026-10-12)

The ten-scenario suite in four modes, three runs each, on the unique-MAC testbed: XDP + daemon,
iptables + daemon, Nginx limits only (the protected `nginx.conf`, no daemon) and unprotected
(neither). Default operating point: the suite's own server (Nginx + gunicorn, 8 workers × 4
threads, no CPU pinning), 20 legitimate clients, 5 bots per scenario. Recorded on 2026-10-12,
08:11–10:53 UTC, one mode after another (not interleaved). Reported in
`docs/REPORT_ADDENDUM_EXP0_EXP1.md` §C–§I (EXP-1: XDP; EXP-1b: iptables and unprotected;
EXP-1c: Nginx limits only).

Tags: **[FACT]** recomputed from the files of this campaign; **[INFERENCE]** reasoned, not
measured; **[CLAIMED]** stated in the addendum, no data here.

## Result

**[FACT] No attack lowered the legitimate clients' success rate in any mode.** Of 17,363
legitimate requests started during the attacks, 1 failed (an unprotected UDP-flood request, 1 of
555). "Before" and "after" are 100 % in every mode. In the first 10 s after the attack start the
success is 100 % in all 40 scenario × mode cells (`analysis/window.csv`).

| Mode | Requests during the attacks | Failed | Mean exposure per scenario-run |
|---|---|---|---|
| XDP + daemon | 2,318 | 0 | 9.5 s |
| iptables + daemon | 2,273 | 0 | 9.0 s |
| Nginx limits only | 6,665 | 0 | 28.3 s |
| unprotected | 6,107 | 1 | 28.6 s |

Exposure is attack end minus attack start. With a daemon the harness stops the attack once the
bans are seen; without one it runs for the scenario's fixed time, so the "during" periods differ
in length between the two groups.

**[FACT] What the modes differ in is latency, server load and where the packets stop**
(`analysis/summary.md`):

| | XDP | iptables | Nginx limits only | unprotected |
|---|---|---|---|---|
| HTTP flood, 'perfect' clients, p50 / p95 during the attack, ms | 2 / 115 | 3 / 259 | 27 / 208 | 274 / 605 |
| Yo-Yo, same | 2 / 253 | 2 / 263 | 2 / 107 | 2 / 478 |
| HTTP flood, Nginx CPU, % of one core | 52 | 55 | 434 | 112 |
| HTTP flood, packets/s reaching the server | 5.0 k | 7.0 k | 48.7 k | 1.2 k |
| UDP flood, packets/s dropped before the IP stack / reaching it | 1.59 M / 119 k | 0 / 1.27 M | 0 / 1.62 M | 0 / 1.46 M |

The server-load means are over the samples of Phases 2, 2A and 3 (`analysis/server.csv`).

**[FACT] Detection** (`analysis/detection.csv`). In the two daemon modes the rules banned all 5
bots in each of the 60 scenario-runs, with the same engine in both modes in every scenario (L4
SYN, L4 low-SYN, L4 volumetric, L4 SlowConn, L7 rate; the multi-vector scenario: 3 volumetric,
1 SYN, 1 L7 per run). Median time to mitigate by scenario: 0.54–3.94 s with XDP, 0.45–3.78 s
with iptables. The one outlier is the ACK flood of XDP run 2: all five bots were banned in the
same millisecond, 10.32 s after the attack start, and the harness reported 0/5 and FAIL
(addendum §E, finding F-45). The other five protected ACK-flood runs banned within 1.35 s.

**[FACT] False positives and the GRU.** No ban event names a legitimate client (0 of 300 bans; all
bans are of 10.0.2.1–5) and none was made by the XDP-fed GRU (0 of 300). The XDP-fed GRU was
active in the daemon modes: the daemon of commit `6fc27fa` has no switch for it and its log shows
the model being loaded. The harness's own "False Positives" line, which uses a ping check, names
a legitimate client (profile `mobile_bad` each time) in 4 of the 120 scenario-runs: XDP run 3,
ACK flood (10.0.1.9); Nginx limits only run 2, Low & Slow SYN (10.0.1.16); unprotected run 1,
SYN flood (10.0.1.4) and run 2, multi-vector (10.0.1.1). Three of the four are in modes with no
daemon, where nothing can be banned, so that line is an artefact of the ping check, not a ban.
In `scenario_results.csv` the harness's `Result` is FAIL for the XDP stall above, for XDP run 3's
ACK flood (the ping-check line) and for all 60 scenario-runs without a daemon (0/5 banned, by the
suite's own criterion; these include the other three ping-check lines).

## How it was recorded

Each mode ran `python3 <suite copy>` three times in a row from the repository root
(`source/run_exp1.sh`, `run_exp1b.sh`, `run_exp1c.sh`). In the modes with a daemon a `tail -F`
observer wrote a millisecond-timestamped copy of the daemon log, because the suite deletes that
log for every scenario.

| Mode | Recorded (UTC) | Suite copy (SHA-256 prefix) |
|---|---|---|
| XDP + daemon | 08:11:02–08:41:31 | `b/`, 9f786908 |
| iptables + daemon (`MITIGATION_BACKEND=iptables`) | 08:57:46–09:26:49 | `b/` |
| unprotected (`MITIGATION_MODE=none`) | 09:26:49–10:05:38 | `b/` |
| Nginx limits only (`MITIGATION_MODE=none NGINX_PROTECTED=1`) | 10:15:05–10:52:58 | `c/`, 702b514b |

**[FACT] Provenance, checked against this repository** (`source/provenance_<mode>.txt` holds the
recorded files verbatim):

* The recorded commit is `6fc27fac29238a7289263b45c3bd84577f1d86d3` (2026-10-11). The working
  tree had only untracked files under `docs/`.
* The SHA-256 of `control_plane.py`, `xdp_ddos_filter.c`, `nginx.conf`, `nginx_unprotected.conf`
  and `training_results/{gru_testbed_model.pth,scaler_testbed.save,feature_config_testbed.json}`
  equal those of the blobs at `6fc27fa`.
* The suite was not run from the repository but from a patched copy. `b/` is
  `git show 6fc27fa:test_distributed_suite.py` plus `docs/D1_D2_unique_mac_and_nginx_restart.patch`
  (unique veth MACs, Nginx restart and orphan cleanup): `patch -p1` reproduces the recorded
  SHA-256 `9f786908…`. `c/` is `b/` plus `source/EXP1c_nginxlimits_mode.diff` (a switch that keeps
  the protected `nginx.conf` without the daemon): it reproduces `702b514b…`.
* End state of every mode: 0 Nginx processes and 0 network namespaces left behind.
* Host: Linux 7.0.0-38-generic x86_64, VM `ddos-mitigation`.

## Approximations introduced by the import

The runs were converted with `eval/import_legacy_campaign.py` (each run's `provenance.json` is
marked `imported`). The CSV rows are copied verbatim: concatenating the per-run files reproduces the
source files row for row (126 metrics rows, 415 / 440 / 448 / 420 availability rows and
5,617 / 5,788 / 10,004 / 9,146 request rows for XDP, iptables, Nginx limits only and unprotected;
SHA-256 of the sources in `source/source_sha256.txt`).

* Attack start = the Phase-1 (baseline) metrics timestamp, written just before the launch; attack
  end = the Phase-3 timestamp, written just before the kill.
* Ban-event times are the observer's read times. The observer started on a log file left by the
  previous mode, and its replay of that file (iptables: the last scenario of the XDP runs; unprotected:
  the last scenario of the iptables runs, which is all it saw) and its own `tail:` notices were
  removed. Nginx limits only had no observer.
* Request start = completion time − latency.
* Client network profiles were not seeded and their plan was not recorded, so modes are compared
  as independent runs, not paired. The mix differs from run to run: 3 to 11 'perfect' clients and
  0 to 6 `mobile_bad` clients out of 20 (console of each run, "Profile distribution").
* `TTM_Exact_By_Bot` is rounded to the millisecond, so a median can differ in the second decimal
  from the unrounded computation (iptables HTTP flood: 0.96 s here, 0.97 s in the addendum).
* `daemon.log` of a run holds the observer lines between that run's first daemon start and the next
  run's: the startup lines of the first scenario of runs 2 and 3 are filed under the preceding run,
  and the four startup lines of the very first daemon (before run 1) are in no file.
* `FP_Ping_IPs` is empty: the harness's ping-based line is only in `console.log` (ANSI colour codes
  removed).
* `imported.from` in `provenance.json` is the scratch directory in which the source was assembled,
  not a repository path. The `provenance.txt` files of the four modes differ in layout from what
  the importer reads, so a first line `LABEL start TS  HEAD SHA  COMMON:` was written for each mode
  from them and their SHA-256 lines were copied unchanged; each mode was imported on its own (the
  nginx-limits suite copy differs from the others) and the four were merged into this directory.

## Not in this dataset

* The kernel log: the addendum's "0 duplicate-address messages per run" [CLAIMED] cannot be checked
  here. Only a journal cursor was recorded.
* Per-run client-profile plans and seeds, and the phase-by-phase attack timeline of the harness.

The duplicate-MAC baseline of 2026-10-11 that the addendum compares with is a separate dataset,
`../2026-10-11_superseded-dup-mac/` (its CSVs are byte-identical to the snapshot the addendum used).

## Reproducing

    cd results/2026-10-12_exp1-default-4modes_prototype && sha256sum -c SHA256SUMS
    venv/bin/python eval/analyze_campaign.py results/2026-10-12_exp1-default-4modes_prototype
    venv/bin/python eval/plot_campaign.py results/2026-10-12_exp1-default-4modes_prototype

regenerate `analysis/` byte for byte. `tests/test_prototype_campaigns.py` pins the numbers above.
The claim-by-claim comparison with the addendum is kept in `results/README.md`, not here: a
published campaign is not edited afterwards.

## Limitations

* Three runs per mode, ten scenarios, one flood intensity each. The runs are independent (unseeded
  profiles) and the modes ran one after another, so a drift of the VM over the 2.7 hours cannot be
  separated from a mode effect.
* At this operating point the server is over-provisioned (8 cores, a backend that returns a
  constant reply): the success rate saturates at 100 % [FACT above] and cannot show a benefit of
  mitigation. Where it can (a capacity-limited server) is `../2026-10-12_exp2a-knee_prototype/`
  [INFERENCE].
* The closed-loop `wrk` flood and the Nginx-limits-only CPU figures (434 % of a core) belong
  together: a rejecting server is hit by more requests per second [INFERENCE; addendum §I.3].
* Veth pairs in network namespaces on one host, not a physical NIC.
