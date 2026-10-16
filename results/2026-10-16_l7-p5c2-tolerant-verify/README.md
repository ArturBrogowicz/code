# P5c.2 verification — tolerant profile vs realistic benign (2026-10-16)

The P5c.2 gate (`docs/L7_GRU_DESIGN.md` §7.3.3.1). Same run as P5c.1
(`results/2026-10-16_l7-p5c-baseline/`), with one change: the daemon and nginx use the
frozen **tolerant** threshold profile (`HEURISTIC_PROFILE=tolerant`; nginx `limit_req`
82 r/s, burst 133). Benign traffic only, 20 IPs, seed 1, 300 s, branch
`feat/l7-benign-overlap` at `07c3794`.

## Result — PASS [FACT, `ban_events.jsonl`, `report.md`]

**0 of 20 benign IPs banned** by the deterministic engines; nginx rejected nothing.

| Benign client | Default profile (P5c.1) | Tolerant profile (this run) |
|---|---|---|
| 60-asset page, perfect | `l7_rate` ban at 7 s, 61 requests | not banned, 371 requests, 1 s peak 61 |
| CGNAT 12 users | `l4_slowconn` ban at 9.3 s, 62 requests | not banned, 2,731 requests, 15.6 rps over 60 s |
| CGNAT 24 users | `l4_slowconn` ban at 265 s | not banned, 4,364 requests, 24.9 rps over 60 s |

The 12-user gateway's measured 60 s rate (15.6 rps) matches the admissibility gate's
simulated median (15.6).

## Not in scope here

The shadow GRU (the P4 candidate) still flags 8 benign IPs. That model reads server timing
(R17) and never trained on these clients; P5c.3 retrains under the strict gate. It never
bans in shadow mode.

## Reproduce

    ./venv/bin/python ml/p5c_baseline_report.py results/2026-10-16_l7-p5c2-tolerant-verify

## Files

`report.json` / `.md` (per-IP table), `ban_events.jsonl`, `l7_record.jsonl.gz`,
`manifest.json`, `summary.json`, `baselines.json`, `nginx_tolerant.conf` (the rendered conf
nginx ran), `daemon.log`, `console.log` (its summary line counts IPs correctly).
