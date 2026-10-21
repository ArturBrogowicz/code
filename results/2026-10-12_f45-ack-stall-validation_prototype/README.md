# F-45: validation of the GRU-feed-stall fix, six ACK-flood runs (2026-10-12)

The ACK flood alone (`ONLY_SCENARIOS=5`, 5 bots, `hping3 -A`) six times in XDP mode at the default
operating point, with the daemon patched against finding F-45 (a TCP flood that fills the 262k-entry
`flow_map` could stall the telemetry loop for about 10 s, delaying the L4 bans). Recorded on
2026-10-12, 13:26–13:34 UTC. Reported in `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §L; the stall itself
(XDP run 2 of EXP-1, 10.32 s) is in `../2026-10-12_exp1-default-4modes_prototype/`.

Tags: **[FACT]** recomputed from the files of this campaign; **[INFERENCE]** reasoned;
**[CLAIMED]** stated in the addendum, no data here.

## Result

**[FACT]** (`analysis/summary.md`, `scenario_results.csv`)

| Run | Bots banned (ban events) | Exact time to mitigate per bot, s | Harness Avg TTM, s | Harness result |
|---|---|---|---|---|
| 1 | 5/5, L4 volumetric | 0.87 (all five) | 1.11 | PASS |
| 2 | 5/5, L4 volumetric | 0.70 | 1.16 | PASS |
| 3 | 5/5, L4 volumetric | 0.86 | 1.13 | PASS |
| 4 | 5/5, L4 volumetric | 0.73 | 1.16 | FAIL (ping check, see below) |
| 5 | 5/5, L4 volumetric | 1.08 (two bots), 2.10 (three bots) | 1.74 | PASS |
| 6 | 5/5, L4 volumetric | 0.27 | 1.28 | PASS |

* 30 ban events, all of 10.0.2.1–5, all by the L4 volumetric rule: 0 by the GRU, none of a
  legitimate client. Legit success is 100 % before, during (n = 758) and after the flood in every run.
* The slowest run is run 5: the five bots were banned in two polls, 1.08 s and 2.10 s after the
  attack start (the second group sent about 20 k packets/s against 172 k for the first). No run
  came near the 10.32 s of the stall.
* Run 4 is FAIL because the harness's ping-based "False Positives" line named 10.0.1.11 (profile
  `mobile_bad`). There is no ban event for it and no `10.0.1.x` line in the run's daemon log.
* The patched daemon's CPU peaks at 43 % and its resident memory at 482 MB over all samples of all
  runs (`metrics.csv`, `CPU_Daemon_Pct`, `RAM_Daemon_MB`); the stalled run of EXP-1
  (`../2026-10-12_exp1-default-4modes_prototype/xdp/run2/metrics.csv`, ACK flood) showed 182–226 % and
  460 → 611 MB.
* Attack-start convention: times are measured from the Phase-1 metrics timestamp (see
  "Approximations"). The Phase-2 row is written 1.11–1.28 s after the Phase-1 row in every run, and
  the harness's `Avg TTM` equals that gap to the centisecond in runs 1–4 and 6. Times measured from
  the Phase-2 timestamp, as the addendum's §L script did, are about 1.1 s smaller than the ones here:
  the last ban of run 5 is 2.10 s after Phase 1 and 0.97 s after Phase 2, and in the other five runs
  every ban comes before the Phase-2 row, by 0.24 to 1.01 s.

**[INFERENCE]** The harness's `Avg TTM` is mostly the length of its one-second capture window, not a
detection time (addendum finding F-08). Detection by the L4 volumetric rule took between 0.27 and
2.10 s here.

## How it was recorded

Six consecutive runs of `env CONTROL_PLANE_OVERRIDE=<patched daemon> ONLY_SCENARIOS=5 python3
<suite copy>` from the repository root (`source/run_f45_validate.sh`), with a `tail -F` observer
writing a millisecond-timestamped copy of the daemon log.

**[FACT] Provenance, checked against this repository**

* The patched daemon (`cp_f45/control_plane.py`, SHA-256 `11255b03…`) is byte-identical to
  `control_plane.py` at commit `51cc21c` ("unique veth MACs, nginx restart cleanup, GRU-feed stall
  cap"), i.e. to the fix as merged. It differs from `6fc27fa`'s `control_plane.py` (`e3d95ad2…`) by
  `source/F45_gru_feed_stall.diff`: volumetric suppression armed from the current poll before the
  feed, and a cap of 2000 `flow_map` entries visited per poll in the GRU feed.
* The suite copy `g/` (`0b939a05…`) is `51cc21c`'s `test_distributed_suite.py` (equal to
  `6fc27fa`'s plus `docs/D1_D2_unique_mac_and_nginx_restart.patch`) with one line changed so that
  the daemon path can be overridden: `CONTROL_PLANE = os.environ.get("CONTROL_PLANE_OVERRIDE", …)`.
* Recorded commit `6fc27fa`; the repository's `control_plane.py` of the time (`e3d95ad2…`) is also
  hashed in `source/provenance.txt` but was not run. End state: 0 Nginx processes, 0 namespaces.

## Approximations introduced by the import

Imported with `eval/import_legacy_campaign.py` (each run's `provenance.json` is marked `imported`).
The CSV rows are copied verbatim: the six runs' rows concatenate to the source files (36 metrics
rows, 90 availability rows, 1,372 request rows; SHA-256 of the sources in
`source/source_sha256.txt`).

* Attack start = the Phase-1 (baseline) metrics timestamp, written after the baseline window and just
  before the launch; attack end = the Phase-3 timestamp. Ban-event times are the observer's read
  times. Request start = completion time − latency.
* The recorded provenance does not state `ONLY_SCENARIOS`; the line `COMMON: ONLY_SCENARIOS=5` was
  added from the run script before the import so that `provenance.json` records it. The patched
  daemon is visible only through `inputs_sha256` in `provenance.json` and through this README
  (`git.commit` is `6fc27fa`).
* Client network profiles were not seeded and their plan was not recorded (the mix of 'perfect' to
  `mobile_bad` clients differs between runs, console of each run).
* The observer started with no log file present, so there was no replay to remove. Run 6's
  `daemon.log` is shorter (26 lines) because the observer was stopped right after the last ban.
* `imported.from` in `provenance.json` is the scratch directory in which the source was assembled,
  not a repository path.

## Reproducing

    cd results/2026-10-12_f45-ack-stall-validation_prototype && sha256sum -c SHA256SUMS
    venv/bin/python eval/analyze_campaign.py results/2026-10-12_f45-ack-stall-validation_prototype
    venv/bin/python eval/plot_campaign.py results/2026-10-12_f45-ack-stall-validation_prototype

regenerate `analysis/` byte for byte. `tests/test_prototype_campaigns.py` pins the numbers above.
The comparison with the addendum is kept in `results/README.md`, not here.

## Limitations

* Six runs of one scenario. In EXP-1 the stall occurred in 1 of 6 protected ACK-flood runs; if the
  fix did nothing and that rate were the true one, six clean runs would still occur with probability
  (5/6)^6 ≈ 0.33 [INFERENCE]. These runs show that the patched daemon did not stall; the case that it
  cannot stall rests on the mechanism (a bounded per-poll feed) and on the BCC iteration
  micro-benchmark of addendum §L (`outputs/exp5_bcc_iter_bench.txt` of the earlier session, not in the
  repository) [CLAIMED].
* The suite restarts the daemon for every scenario, so these runs cannot show the long-run effect of
  the cap that the addendum's 2026-10-13 correction describes (a daemon that has seen more than 2000
  `flow_map` entries feeds the GRU only a fraction of new flows).
* Veth pairs in network namespaces on one host.
