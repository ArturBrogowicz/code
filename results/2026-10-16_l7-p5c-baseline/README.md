# P5c.1 baseline confirmation — default heuristics vs realistic benign (2026-10-16)

The first step of P5c (`docs/L7_GRU_DESIGN.md` §7.3.2). One live run on the namespace
testbed with the **default, unchanged** deterministic heuristics (`control_plane.py`,
`nginx.conf`) and **benign traffic only** — no attacks, no flood. Its purpose is to
document, as empirical evidence, what the static thresholds do to realistic legitimate
traffic.

* Runner: `ml/eval_l7.py --mix overlap --benign-only --duration 300 --seed 1`, branch
  `feat/l7-benign-overlap` at `dae84a6`.
* 20 benign IPs: the 12 P5 clients, plus the 8 P5b kinds (§7.2). Four of those (the
  60-asset page ×2 and both CGNAT gateways) are ones the admissibility gate had predicted
  the default heuristics would ban; this run launches them on purpose.
* Daemon: all deterministic engines enforcing as deployed; `XDP_GRU=0`; the L7 GRU in
  **shadow** with the P4 candidate (`results/2026-10-15_l7-p4-train/model`) — it scores and
  records, never bans.

## Finding 1 — the default heuristics ban realistic benign traffic [FACT, `ban_events.jsonl`]

| IP | Benign client | Netem | Deterministic ban |
|---|---|---|---|
| 10.0.1.16 | browser, 60-asset page | perfect | **`l7_rate` at 7.0 s** — 51 rps: its first page view (61 requests within 1 s) |
| 10.0.1.17 | CGNAT gateway, 12 users | broadband | **`l4_slowconn` at 9.3 s** — 12 established connections, 0 bytes |
| 10.0.1.18 | CGNAT gateway, 24 users | mobile_bad | **`l4_slowconn` at 264.9 s** — 54 established connections, 0 bytes |
| 10.0.1.15 | browser, 60-asset page | mobile_bad | not banned: 300 ms latency spread its first view (1 s peak 20) |

* **The CGNAT ban needed only two users.** By the time of the ban, two of the twelve users
  had loaded one page each (31 requests at 2.9 s and at 5.4 s) and were idle, reading. Two
  browsers' default pools of 6 keep-alive connections = 12 idle connections, above
  SlowConn's 8, for 3 quiet seconds → ban. A two-device household behind one IP meets the
  rule.
* **The admissibility gate's predictions held:** 3 of its 4 predicted bans happened; the
  fourth was missed because the gate assumes the fastest network profile (a worst case),
  and that client drew `mobile_bad`. No client the gate called admissible was banned.
* nginx rejected nothing (`limit_req` and `limit_conn`: 0 everywhere).

Full per-IP table, with the measured rate profiles: `p5c1_report.md`.

## Finding 2 — the shadow GRU's decisions depend on origin load (new risk R17) [FACT, counterfactual replay]

The P4 candidate, which had **0** benign false positives in P5, flagged **11 of 20** benign
IPs here (62 would-ban events; 34 % of scored windows over threshold). Five of the eleven
are P5 clients — same kind, same netem profile — that were clean in P5.

The cause is server-side timing. The extra legitimate load made the origin slower: for
those same clients, `$request_time` rose about tenfold at the 90th percentile (≈ 2 ms in
P5 run A → 18–25 ms here) and doubled at the median. Replaying the recorded input through
the same model:

| Replay | Would-bans | Benign IPs flagged |
|---|---|---|
| as recorded (reproduces the live run exactly) | 62 | 11 |
| server timing (`rt`, `urt`) set to an unloaded server's, 1 ms | 43 | 6 |

With only the server timing changed, **every P5 client's flag disappears.** The model treats
`$request_time` / `$upstream_response_time` — properties of the server's load, not of the
client — as attack evidence: a shortcut, like the request-size one P3/P4 removed (R4). The
six IPs still flagged are kinds the P4 model never saw in training (R16), which P5c.3's
retraining addresses.

## Limits

* One run, one seed. The netem draw matters: one of the two 60-asset browsers escaped.
* A banned IP's traffic is dropped by XDP for the ban TTL, so the measured profiles of
  10.0.1.16 and 10.0.1.17 cover only their first ~7–9 s. This run therefore documents the
  bans but **cannot by itself supply the full benign profile** the pre-registered P5c.2
  rule asked for (§7.3.3); see `docs/L7_GRU_DESIGN.md` §7.3.2 for how that is handled.

## Process notes

* `console.log` prints "benign would-ban IPs: 62 / 20"; 62 is the number of events, not IPs
  (a console-label bug, fixed after this run in `bf7f8d0`; `summary.json` was always right).
* The run tore down cleanly: no namespaces or processes left.

## Reproduce

    ./venv/bin/python ml/p5c_baseline_report.py results/2026-10-16_l7-p5c-baseline \
        --timing-counterfactual results/2026-10-15_l7-p4-train/model

The tool reads the run's own files; the replay uses the gzipped recording and is
deterministic.

## Files

* `p5c1_report.json` / `.md` — the per-IP table, gate-vs-live agreement, counterfactual.
* `ban_events.jsonl` — the daemon's ban and shadow events; `l7_record.jsonl.gz` — the L7
  engine's exact input; `manifest.json`, `summary.json`, `baselines.json`; `daemon.log`,
  `console.log`.
