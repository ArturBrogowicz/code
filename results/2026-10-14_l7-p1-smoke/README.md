# L7 ingestion P1 smoke (2026-10-14)

The P1 verification gate for `docs/L7_GRU_DESIGN.md` — not a comparison campaign.
It checks that the new L7 ingestion transport (nginx → Unix-domain datagram socket →
daemon) is healthy in **shadow mode** before the GRU is wired to it (P2).

**How** (`ml/smoke_l7.py`, run as root): build the testbed with the daemon in
`L7_SHADOW=1`, drive ~180 s of 6 legit clients + one 4-bot `wrk` flood burst + a 900 B
User-Agent truncation probe, and compare the socket's `received` count against the
durable file access_log (the ground truth, since `SOCK_DGRAM` gives the receiver no drop
counter). Shadow mode only observes: it never bans, and the live detection paths are
unchanged. Reproduce: `sudo ./venv/bin/python ml/smoke_l7.py` (settings in
`summary.json`).

## Result — PASS for the GRU's target regime

| Measure | Value | Reading |
|---|---|---|
| Shadow thread bound the socket | yes | transport came up |
| Parsed / received | 1334 / 1334 | every datagram that arrived parsed |
| Parse errors, truncation | 0, 0 | incl. the 900 B User-Agent probe — lines stay under the syslog limit |
| Full `(IP, ua_h)` windows | 6 (6 keys, 6 IPs) | windowing + keying work |
| **Steady sub-threshold drops** | **3 / 137 (≈ 0)** | the GRU's regime; the 3 are 5 s counter-vs-file sampling lag, not loss |
| Flood-burst drops | 40 % overall, 1765 in one 2 s interval | see below |
| Daemon CPU | mean 4.6 %, max 12.5 % | one core, with shadow ingest on |

**Steady regime [FACT].** Across the non-burst intervals the socket received every line
nginx emitted (`received == parsed`, 0 truncation, 0 parse errors). The residual 3-line
"drop" is sampling lag: `received` is read from the 5 s-periodic `l7_shadow` event while
the file count is instantaneous, so the counter trails by the few lines that arrived in
the last < 5 s. At ~2.4 legit req/s there is no mechanism for real loss (4 MB `SO_RCVBUF`,
drain ≈ 200 k lines/s). This is the regime the L7 GRU will operate in.

**Flood burst [FACT].** The 4-bot `wrk` burst dropped ~40 % of its lines on the socket
(peak 1765 in one 2 s interval): a sub-second spike of thousands of datagrams overruns the
datagram queue (`net.unix.max_dgram_qlen = 512` on this VM) faster than the single-thread
reader drains it. This is acceptable by design: (a) a high-rate flood is the
deterministic L7 rate rule's job, and it reads the **file** (unaffected) — it banned all
four bots (`ban_events.jsonl`); (b) the file sink retained **every** line (zero evidence
loss); (c) it is not the GRU's sub-threshold regime. Mitigations if ever needed are in
`docs/L7_GRU_DESIGN.md` §9 R2 (raise `max_dgram_qlen`, batch the drain).

**Incidental [FACT].** An earlier run of this smoke saw the *existing XDP-fed* GRU
false-ban a legit client during the burst (`engine=gru` on a `10.0.1.x` IP) — the
stalled-flow false positive from `docs/ML_INVESTIGATION.md` §2.8, reproduced live. The new
L7 shadow path banned nothing. More evidence for retiring the XDP-fed GRU at P2.

## Files
* `summary.json` — all metrics plus the per-sample time series.
* `ban_events.jsonl` — the daemon's events: 38 `l7_shadow` telemetry snapshots + the bot bans.
* `console.log` — the run's console output.
