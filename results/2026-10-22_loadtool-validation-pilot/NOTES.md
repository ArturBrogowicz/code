# Notes on the first run of the load-generator verification (a pilot)

Read this before the README of this directory. The README and `results.json` are what
`bench/loadtool_validate.py` computed, with the pass criteria fixed in the design before any
measurement (`docs/BENCHMARK_HARM_DESIGN.md`, 8.4). This file is what the run showed beyond them.
Tags: **[FACT]** read from the files here; **[INFERENCE]** reasoned, not measured.

## What was run

* **[FACT]** Commit `210399c` (clean tree), VM `ddos-mitigation`, loopback only, no root. Started
  2026-10-22 12:32:21 UTC after the gate (uptime 1808 s, load 0.03), finished 12:52:48. 58 jobs,
  18 minutes of load. Exit code 0, no infrastructure error, no process left over, `/usr/bin/wrk`
  unchanged.
* **[FACT]** Timer wake-up lateness (`sleep(10 ms)`, 200 samples): before the run p50 5.6 ms,
  p99 19.0 ms, max 22.1 ms (above the 10 ms limit); after it p50 2.3 ms, p99 9.1 ms, max 14.0 ms.
* A run of V1 alone, 20 minutes earlier, passed for all three tools (3 jobs); it is not published.
* `README.md` and `results.json` here were regenerated offline from the job directories with
  `./venv/bin/python bench/loadtool_validate.py reanalyse results/2026-10-22_loadtool-validation-pilot`
  after commit `00275f5` made the order of a tool's raised flags deterministic. The files written
  during the run (kept in `/var/tmp/loadtool_validation/20261022_loadtool-validation`) differ from
  them only in the order of two flag names in two notes (V5 and V7 of loadgen). Re-analysing again
  reproduces them byte for byte.

## Verdicts as computed

| Tool | V1 | V2 | V3 | V4 | V5 | V6 | V7 |
|---|---|---|---|---|---|---|---|
| vegeta v12.13.0 | pass | pass (9/9) | fail (p99) | pass | fail | pass | held 2k, collapsed from 5k |
| k6 v2.3.0 | pass | fail (7/9) | pass | fail | pass | pass | held 2k, drops from 5k |
| loadgen 1 | pass | pass (9/9) | fail (p50, p99) | pass | pass | pass | schedule held to 10k |
| wrk 4.1.0 (control) | - | - | - | control NOT as expected | - | - | - |

## Do not use these verdicts yet

The run found six faults in my harness and protocol. They are mixed into the verdicts above, so
no manifest status was changed (`bench/loadtools.json` is as before: vegeta and k6 smoke-tested,
wrk and loadgen installed). A corrected re-run has been proposed; it needs its own approval.

1. **Settings were generic, not test-specific.** The protocol says each tool gets the documented
   settings a test needs. k6 ran with 100 pre-allocated VUs and vegeta with an idle pool of 100
   connections in every test.
   * **[FACT]** k6 under-delivered in 2 of 9 V2 runs (19 106 of 20 000 at 1000/s; 96 347 of
     100 000 at 5000/s) and said so: `dropped_iterations` 895 and 3 654 equal the shortfalls.
     In V4 only 621 of the 1 500 requests due during the stall arrived (880 dropped, reported).
   * **[INFERENCE]** k6 starts extra VUs too slowly to keep an arrival schedule when the
     pre-allocated ones are all busy, and the VM's late wake-ups create such moments; a pool of
     2 000 pre-allocated VUs would keep the stall test honest.
2. **V7 counted totals, not schedule adherence.** The design says "highest rate with at least
   99 % schedule adherence". **[FACT]** loadgen delivered all 200 000 requests at 20 000/s, but
   only 16 000/s on schedule, finishing 2.3 s late (its own flags: slip p99 2.2 s, cpu); the
   README's "highest rate held: 20000" is therefore wrong in the sense of the design. Its schedule
   was exact up to 10 000/s (per-second sent counts 9 997-10 003, flag `cpu` at 91 % of a core).
3. **Port and socket hygiene was not monitored.** V7 steps ran back to back.
   * **[FACT]** vegeta at 5000/s sent bursts (3.1k, 3.2k, 5.7k, 8.0k/s), then nothing for 7 s,
     with 1 780 timeouts ("context deadline exceeded awaiting headers") and 15.5 s of duration; at
     10 000 and 20 000/s only ~370 requests/s reached the origin (3 739 and 3 723 in 10 s). Its
     CPU time is mostly system time (13.8 s system against 2.4 s user at 5000/s).
   * **[INFERENCE]** connection churn with an idle pool of 100 and ephemeral-port exhaustion in
     the kernel; TIME_WAIT counts were not sampled, so this is not shown.
4. **CPU per 1000 requests includes the steps after the load** (vegeta's `report` and `encode`,
   loadgen's summary and records), so it is an upper bound: loadgen's 0.074 s per 1000 requests at
   20 000/s is 14.8 s of CPU for a 10 s run on one pinned core.
5. **The negative control is not one.** **[FACT]** wrk 4.1.0 held its 50 connections and sent
   nothing during the stall (0 arrivals inside it: it is closed-loop), but reported p99 2.61 s
   (p50 9.9 ms; thread-stats mean 116 ms, max 3.05 s) against an analytic 2.6075 s.
   **[INFERENCE]** its latency statistics are corrected for coordinated omission after the run.
   The criterion on the control's reported p99 assumed they are not.
6. **V3 does not tell apart tools that report latency from the intended send time** (loadgen)
   **from those that report it from the actual send** (vegeta, k6). **[FACT]** loadgen's latency
   from the actual send agrees with the origin's own service times within 0.4 ms (p50) and
   0.5 ms (p99); the 1.8 ms and 5.0 ms by which its reported figures exceed them are its schedule
   slip (p50 1.2 ms, p99 7.9 ms), which intended-time accounting includes on purpose.

## What the tools did

* **vegeta:** exact on schedule in V2 (all nine runs within one request) and V4 (p99 2.633 s,
  1 499 of 1 500 arrivals during the stall); p99 7.1 ms above the origin's in V3 (tolerance
  1.8 ms); **silent under overload:** in V5 it sent 2 000/s for about five seconds, then 550-750/s,
  with no drop reported (`silent shortfall` 20 289 of 40 000). **[INFERENCE]** it stopped
  starting requests when its 5 000 workers were all busy (`-max-workers 5000`).
* **k6:** the best match to the origin's latency (V3 within tolerance); reports every request it
  does not start (V5: 16 445 dropped, silent shortfall 0); see 1. above for V2 and V4.
* **loadgen:** exact in V2 and V4 (p99 2.667 s, 1 500 of 1 500), reports its drops in V5 (16 600
  at its 5 000-in-flight cap); see 2. and 6. above.
* **All three** parsed from their real output with no change to the readers.

## What was proposed next

Offline: test-specific settings (k6 pre-allocated VUs, vegeta connection pool, loadgen pool);
per-second origin arrivals for V7 (stub_status sampled once a second) and a schedule-adherence
criterion as the design states it; TIME_WAIT sampling and a wait for it to drain between jobs;
CPU time of the load window only. Then a re-run of V2, V4, V5 and V7 (about 12 minutes of load).

Two changes would alter pre-registered criteria, so they are the owner's call and are labelled
post hoc wherever they appear: (A1) judge the closed-loop control by its arrivals during the stall
(none), not by its reported p99; (A2) judge every tool's latency in V3 from the actual send, and
a tool that also reports it from the intended time on both, the difference being the slip, which
the validity limit (p99 below 50 ms) covers.
