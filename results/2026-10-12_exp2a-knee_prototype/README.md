# EXP-2a: HTTP flood at a capacity-limited operating point (2026-10-12)

Four modes × 3 runs of the HTTP-flood scenario (`ONLY_SCENARIOS=4`) at the "knee"
operating point (now `OPERATING_POINT=knee`): one gunicorn worker and thread pinned to
cpu0, the attack generators pinned to cpus 1–7, `wrk -c400` from 10 bots. Recorded on
2026-10-12, 13:02–13:17 UTC. Reported in `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §J
(figure `docs/figures/exp2a_knee_4modes.png`).

| Mode | Legit success during the flood | 'perfect'-client latency p50 / p95 |
|---|---|---|
| XDP + daemon | 100 % (n = 68) | 1 / 147 ms |
| iptables + daemon | 100 % (n = 72) | 2 / 418 ms |
| nginx limits only | 52.2 % (n = 113) | 3837 / 4613 ms |
| unprotected | 89.9 % (n = 208) | 1102 / 6395 ms |

Full tables and figures: `analysis/summary.md`, `analysis/figures/`.

## How it was recorded

The runs were made with a prototype copy of `test_distributed_suite.py` (commit
`6fc27fa` plus the unique-MAC fix and the settings that became `OPERATING_POINT=knee`
and `NGINX_PROTECTED=1`), before the reproducible harness existed. They were converted
into this layout with `eval/import_legacy_campaign.py`; each run's `provenance.json` is
marked `imported` and lists the SHA-256 of the inputs used.

Approximations introduced by the import:

* attack start = the Phase-1 (baseline) metrics timestamp, written just before the launch;
  attack end = the Phase-3 timestamp, written just before the kill;
* ban-event times come from a `tail -F` observer of the daemon log (its replay of the
  previous mode's log was removed);
* request start = completion time − latency;
* client network profiles were not seeded and their plan was not recorded, so modes are
  compared as independent runs, not paired.

## Correction to addendum §J

As first published, two §J statistics were computed on run 3 only instead of all three
runs, because of a run-splitting bug in the prototype analysis script. Over all runs
(this dataset, `analysis/summary.md`):

* time-to-mitigate per bot, median (range): XDP 0.22 s (0.07–0.32), iptables 0.31 s
  (0.12–0.49), 30 bots each (published: 0.19 s and 0.34 s);
* requests started 0–10 s after the attack start, 'perfect' clients: XDP 100 % (n = 95),
  iptables 100 % (n = 96), nginx limits only 13.6 % (n = 22), unprotected 97.3 % (n = 73)
  (published: 100 / 100 / 0 / 100 % with n = 35 / 43 / 8 / 23).

The availability, latency, Fisher-test and server-load numbers of §J were not affected,
and none of the conclusions change.

## Reproducing

    venv/bin/python eval/analyze_campaign.py results/2026-10-12_exp2a-knee_prototype
    venv/bin/python eval/plot_campaign.py results/2026-10-12_exp2a-knee_prototype

regenerate `analysis/` byte for byte; `tests/test_campaign_analysis.py` pins the numbers.
To record the experiment again with the current harness:

    sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 3

## Limitations

Three runs per mode, a single scenario, a deliberately severe capacity limit and a
closed-loop attacker (`wrk`). The ordering daemon > unprotected > nginx-limits-only is
the result, not the exact percentages.
