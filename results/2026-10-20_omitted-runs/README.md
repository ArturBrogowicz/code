# Omitted runs (recorded 2026-10-13 to 2026-10-16, published 2026-10-20)

Four small runs that were recorded and kept under `/var/tmp` but not published with their
neighbours (second audit, finding G-11, "selective publication"). None of them changes a
published verdict. One is the only place where the XDP-fed GRU banned a client at all, and it was
a legitimate one.

| Directory | Recorded (UTC) | Commit | What it is | Why it matters |
|---|---|---|---|---|
| `p1_smoke_20261014T152428Z/` | 2026-10-14 15:24-15:28 | not recorded; runner between `2fc3747` and `e595137` | second attempt of the P1 smoke (`ml/smoke_l7.py`: 180 s, 6 legit clients, a 4-bot `wrk` burst, L7 shadow on). The XDP-fed GRU was live: the `start` event has no `xdp_gru` field | **the only ban the XDP-fed GRU made in any recorded run: legit client 10.0.1.6, p = 0.999013, 3 hits, 127.2 s after the daemon started.** The four bots had been banned by `l7_rate` at 70.6-71.3 s, 56 s earlier; no `suppress_on` event exists in the run. 10.0.1.6 had the `broadband` profile (no loss; `PROFILE_SEED = 0` plan, recomputed). The ban event holds only p and hits, so the flow behind it cannot be reconstructed. The P1 README mentions this run in prose and attributes it to a "stalled-flow" false positive, which these data do not show |
| `p1_smoke_20261014T153217Z/` | 2026-10-14 15:32 | not recorded | third attempt, same runner | clean: 4 `l7_rate` bans (71.1-71.7 s), no GRU ban. Transport: 3 of 139 lines lost in the steady regime (2.2 %); 1329 of 2407 lines reached the socket overall (the flood burst drops the rest) |
| `p5_first_attempt_20261016T075305Z/` | 2026-10-16 07:53 | runner of `6a03cdf` | first attempt at the P5 evaluation. `ban_events.jsonl` holds the `start` event only; `daemon.log` shows the daemon up with the L7 model `e7ad1b81684f` and `record=on` | aborted before any traffic. The earlier session's notes say the runner raised a `NameError` in `Capture.gen_cmd`, fixed by `ea9e9c8` [not re-verified]. The empty `l7_record.jsonl` (0 bytes) was not copied |
| `r1_smoke_2026-10-13/` | 2026-10-13 08:49-08:52 | `efc5994`, clean | "R1" of addendum §N: suite scenarios 4 and 5 (HTTP and ACK flood), XDP mode, default settings, run to validate the ban-event instrument | the addendum's claim "every `[BAN]` console line has exactly one ban event (10/10, same IP and reason)" can be re-checked here and holds: the 10 `[BAN]` lines of `daemon.log` and the 10 ban events have identical (IP, reason) multisets (5 `l7_rate`, 5 `l4_volumetric`). The other half of R1, the comparison with an independent `tail -F` observer (8 of 10 within 1.2 ms), cannot be repeated: the observer's output was not kept |

Also published today, as campaigns of their own: the unpublished full-suite replicate of R2
(`../2026-10-13_regression-default-full-suite-replicate/`) and the full-suite baseline taken before
the 2026-10-19 default changes (`../2026-10-19_baseline-before-audit-defaults/`).

## Still not published

* The prototype campaigns of 2026-10-12 in the earlier session's working directory
  (`/root/project_analysis/campaigns/`): EXP-1 (XDP), EXP-1b (iptables, unprotected), EXP-1c (nginx
  limits only), the EXP-1d calibration sweep, EXP-2b (tuned nginx limits) and the F-45 validation.
  The default-point cross-mode claims of `docs/REPORT_ADDENDUM_EXP0_EXP1.md` (§C-§I: availability
  100 % in every mode, latency and Nginx CPU under L7 floods, pre-stack drop against iptables)
  rest on them. They could be converted with `eval/import_legacy_campaign.py`; they are not here.
* `p1_smoke_20261014T152342Z` (an empty directory: aborted before any event).

## Check

    cd results/2026-10-20_omitted-runs && sha256sum -c SHA256SUMS
    ./venv/bin/python eval/events_census.py results       # finds the GRU ban of the first run above
