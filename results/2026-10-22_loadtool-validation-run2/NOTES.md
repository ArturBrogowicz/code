# Notes on the corrected run of the load-generator verification (run 2)

Read this before the README of this directory. The README and `results.json` are what
`bench/loadtool_validate.py` computed by criteria version 2 (`docs/BENCHMARK_HARM_DESIGN.md`, 8.4 and
Appendix F.4); this file is what the run showed beyond them. It was written after the run and is not
listed in `SHA256SUMS`. It supersedes the pilot (`../2026-10-22_loadtool-validation-pilot/`), whose
verdicts were not used. Tags: **[FACT]** read from the files here; **[INFERENCE]** reasoned, not measured.

## What was run

* **[FACT]** Commit `58412df` (clean tree), VM `ddos-mitigation`, loopback only, no root, approved as
  proposed in Appendix F.6. **C1** (V1 alone, 3 jobs), 13:55:33-13:56:40 UTC: all three tools passed,
  no infrastructure error; not published. **C2** (this directory: the full matrix, 58 jobs, 18.2 min of
  load), 13:57:12-14:24:11 UTC (27 min), started after the gate (uptime 6900 s, load 0.24), exit code 0.
* **[FACT]** No infrastructure error, no process and no listening port left over; `/usr/bin/wrk` and every
  tool binary are unchanged (V0 matched all hashes). The output was copied here unchanged from
  `/var/tmp/loadtool_validation/20261022_loadtool-validation-c2`; `sha256sum -c SHA256SUMS` passes.
* **[FACT]** Timer wake-up lateness (sleep 10 ms, 200 samples; p50 / p99 / max in ms). Unpinned: before the
  run 0.4 / 5.3 / **862.7**, after it 4.2 / 18.2 / 29.2. Pinned to the CPUs in use, before then after: S1
  (0-1) 2.2 / 10.7 / 13.2 then 4.3 / 15.2 / 15.4; S2 (2-3) 1.7 / 10.5 / 14.9 then 2.3 / 13.7 / 22.0; tools
  (4-7) 1.9 / 10.0 / 11.6 then 3.4 / 13.2 / 15.9; V7 tool (4) 3.8 / 26.7 / 40.7 then 2.8 / 12.8 / 14.2.
  Most are above the 10 ms warning; one stall of 0.86 s was caught by the first probe.

## Verdicts as computed (criteria version 2)

| Tool | V1 | V2 | V3 | V4 | V5 | V6 | V7: highest rate held (requests/s, one core) |
|---|---|---|---|---|---|---|---|
| vegeta v12.13.0 | pass | pass (9/9) | fail (p99) | pass | fail | pass | 2000 |
| k6 v2.3.0 | pass | pass (9/9) | pass | pass | pass | pass | 2000 |
| in-repo engine (`loadgen`) | pass | pass (9/9) | pass (A2, post hoc) | pass | pass | pass | 10000 |
| wrk 4.1.0 (control) | - | - | - | control ok (A1, post hoc) | - | - | - |

Statuses the results suggest, **not applied** to `bench/loadtools.json`: k6 verified; the engine verified;
vegeta verified with restrictions (no latency claims, no overload claims); wrk control.

## What changed against the pilot

* **[FACT]** k6: V2 fail (7/9) -> pass (9/9, worst deviation -49 and +89 of 100,000); V4 fail (621 of 1,500
  requests arrived in the stall) -> pass (1,496 of 1,500, p99 2.625 s against 2.6075 s analytic). What
  changed is the pre-allocated pool, 300-1,600 VUs instead of 100 **[INFERENCE: that was the cause; the
  VM's timer noise also differs from run to run, so this is not a controlled comparison]**.
* **[FACT]** Engine V3 fail -> pass and the wrk V4 control "NOT as expected" -> ok are the two post hoc
  amendments, and they are what the re-judged pilot showed. With corrected-harness data: the engine's
  latency from the actual send is 10.5 / 25.9 ms (p50 / p99) against the origin's own 10.0 / 25.4; from the
  intended time 13.0 / 44.1, i.e. 3.0 and 18.7 ms above, the schedule slip being 2.1 / 20.6 ms. wrk
  sent 0 requests into the stall (191,904 in 40 s) and still reported p50 9.6 ms, p99 3.0 s.
* **[FACT]** The engine's V7 "20000" of the pilot is now 10000: at 20,000/s adherence is 0.834, arrivals went
  on about 1.8 s after the end of the schedule, slip p50 1.47 s, CPU share 1.00.
* **[FACT]** Unchanged: vegeta V3 fail, vegeta V5 fail (19,693 arrivals of 40,000, 20,307 missing and
  nothing reported; 20,289 missing in the pilot), vegeta and k6 V7 ceilings 2,000.

## What the tools did

* **vegeta:** exact in V2 (worst -97 of 100,000), V4 (1,500 arrivals in the stall, p99 2.629 s) and V6.
  Silent under overload (V5): 2,000/s for four seconds, then 600-800/s. V7: 1,000 and 2,000/s on schedule
  (0.999); at 5,000/s all 50,000 requests but with a slow start (see 3. below); at 10,000/s 27,159 of
  100,000 with several seconds of no arrivals; at 20,000/s 132,274 of 200,000 at about 17,000/s. It
  saturated the pinned core from 10,000/s (1.04 cores). **[FACT]** The sockets in TIME_WAIT grew by 9.8 k
  during the 5,000/s job and by 14.4 k during the 10,000/s job (15,957 at its end, the highest of the
  run): vegeta opens thousands of connections a second at these rates although its idle pool is as large as
  its workers. No error, and no "cannot assign requested address", was reported, so port exhaustion is
  still not shown **[INFERENCE]**.
* **k6:** within 1 ms of the origin in V3 (p99 18.5 against 17.6 ms), exact in V4 and V6, reports every
  request it fails to start (V5: 16,648 dropped, silent shortfall 0; V7 5,000/s: 2,566 dropped). V7: 1,000 and
  2,000/s on schedule; at 5,000/s 47,376 of 50,000 (0.945) at 0.93 of the core; 10,000 and 20,000/s
  54,511 and 51,838 requests, nearly all the rest reported as dropped. Its steps lasted 10.9-11.6 s for 1,500-2,000
  pre-allocated VUs, so their start took at most 1.6 s **[FACT]**; the 50 ms-per-VU timeout margin added
  in `58412df` was far larger than needed.
* **engine:** exact in V2 (0 deviation in all nine runs), V4 (1,501 in the stall, p99 2.660 s), V6; reports
  every drop (V5: 17,150, exactly 40,000 with the arrivals). V7: on schedule at 1,000, 2,000, 5,000 and
  10,000/s (0.9977, 0.9955, 0.9998, 0.9993), at 0.70 of the core at 5,000/s and **0.95 at 10,000/s**.

## Read with care

1. **V3 is noise-dominated.** **[FACT]** The origin's own p99 service time was 17.6, 25.4 and 152.6 ms
   in the k6, engine and vegeta jobs (maximum 241, 48 and 983 ms), so the tolerance, the larger of 1 ms and
   10 % of the origin's, was 1.8, 2.5 and 15.3 ms. vegeta's job is the one in which the origin itself
   stalled for about a second, and vegeta's p99 (677 ms) is 4.4 times the origin's. A stall of the client
   at the same time would explain it **[INFERENCE]**. With one repeat per tool, V3 cannot tell the tool
   from the VM here, so vegeta's V3 failure is not evidence against vegeta's latency figures.
2. **The engine's slip flag is not reliable on this VM.** **[FACT]** `slip` (p99 above 50 ms) was raised
   in V1 (100/s), in two V2 runs (200 and 1,000/s) and at 2,000, 5,000 and 10,000/s in V7, at rates where
   CPU is no limit; slip p99 was 66-88 ms in the V7 runs. Together with the timer probes this points to the
   VM's late wake-ups, not to the engine **[INFERENCE]**. A single 70-90 ms stall in a 10-second step
   is enough to flag p99. The engine's `--spin-ms` was not used.
3. **V7's adherence measure charges a start-up transient and the burst that makes it up.** **[FACT]** vegeta
   at 5,000/s delivered all 50,000 requests, per second 3,326, 4,435, 7,103, then about 5,000 (a slow
   start, probably connection set-up **[INFERENCE]**); the registered measure gives 0.9538 and fails it. A view by lateness, computed offline on
   the recorded readings and **not part of any verdict** (the share of requests that arrived within 1 s of
   their slot, anchored the same way), gives 100 % with a largest lag of 0.65 s for that job and agrees with
   the registered verdict for every other V7 job. The registered criterion decides here; changing the
   measure would be a third, post hoc decision for the owner.
4. **"Cores used" is the CPU of the load step divided by the nominal 10 s.** For the engine at 20,000/s it
   reads 1.2 because the run lasted 12.1 s; its own CPU share was 1.00. For k6 the load step includes the
   start of its VUs.
5. **Single measurements.** V3-V7 have one repeat; ceilings are for one pinned core on this VM. The engine's
   10,000/s ceiling carries its own `cpu` and `slip` flags, so by its validity limits (CPU below 0.70 of the
   core, slip p99 below 50 ms) the usable rate on one core is lower.

## TIME_WAIT hygiene

**[FACT]** Seven jobs waited 34-62 s for the sockets of the job before to drain (366 s in total); no job
started with 5,000 or more (the highest start was 4,840); the highest count at the end of a job was 15,957
(vegeta at 10,000/s). Jobs that waited: V2/k6/r200_0, V5/k6, V6/vegeta, V7/k6/r1000, V7/loadgen/r1000,
V7/vegeta/r10000 and r20000.

## Left for the owner

Applying the suggested statuses to the manifest by hand (and how to record vegeta's restrictions); what to
do about V3 (more repeats, a tolerance that follows the measured noise: a post hoc change); whether to keep
the strict adherence measure (3. above); whether the engine runs with `--spin-ms` in the harm-gate
benchmark; merging `feat/loadtools-harness` and `design/benchmark-harm`.
