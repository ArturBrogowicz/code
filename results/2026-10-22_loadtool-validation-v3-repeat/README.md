# Verification of the HTTP load generators (V0-V7)

Produced by `bench/loadtool_validate.py` against loopback origins; the tests and the pass criteria are in `docs/BENCHMARK_HARM_DESIGN.md`, 8.4. The criteria are constants of that script, fixed before any measurement.

* Commit: `d373c7d62fbff1e2c38e9f0758cb50533c778720` (dirty: no); host: Linux ddos-mitigation 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 ; created 2026-10-22T15:11:51Z.
* Environment gate (up at least 1800 s, load below 0.3): uptime 11379 s, load 0.28, waited 60 s: met.
* Repeats: the selected tests were run 3 times over, round after round (--repeats 3), so that the tools take turns; the pre-registered matrix has V3 1 -> 3, a protocol change made after it, **post hoc**.
* Warm-up: `V3/vegeta/r500_0` ran once before the scored jobs and is **not scored** (--warmup); its record is in `warmup/` and its checks are listed below.
* Timer wake-up lateness before the run (sleep 10 ms, 200 samples): p50 1.3 ms, p99 21.2 ms, max 26.6 ms. **above the limit: schedules will slip**
* Timer wake-up lateness after the run (sleep 10 ms, 200 samples): p50 3.7 ms, p99 25.1 ms, max 38.4 ms. **above the limit: schedules will slip**

Timer wake-up lateness on the CPUs in use (a probe pinned to them, sleep 10 ms, 200 samples; p50 / p99 / max in ms):

| CPUs | Used for | Before the run | After the run |
|---|---|---|---|
| 0-1 | S1 (Nginx) | 2.1 / 15.3 / 68.9 **above the limit** | 4.6 / 13.6 / 15.0 **above the limit** |
| 2-3 | S2 (scripted origin) | 1.9 / 18.9 / 75.4 **above the limit** | 4.3 / 15.5 / 16.1 **above the limit** |
| 4-7 | tools | 1.1 / 11.9 / 33.7 **above the limit** | 3.3 / 16.3 / 27.4 **above the limit** |
| 4 | the tool in V7 | 1.9 / 9.8 / 31.2 | 4.0 / 13.6 / 14.2 **above the limit** |

## Criteria

Version 2: the pre-registered criteria (version 1) with the changes below. **Post hoc** marks a change decided after the first run; it is labelled the same way next to every check it affects.

* **A1, post hoc** (V4, decided 2026-10-22): The closed-loop control is judged by the requests that arrive at the origin during the stall (fewer than 10 % of rate x stall), not by its reported p99, which is shown but not counted. Why: The first run (pilot) showed that wrk 4.1.0 held its connections and sent nothing during the stall, yet reported p99 2.61 s: its percentiles appear to be corrected for coordinated omission after the run, so they do not tell a closed-loop tool from an open-loop one; its arrivals do.
* **A2, post hoc** (V3, decided 2026-10-22): Latency is judged from the actual send for every tool. A tool that also reports it from the intended time (loadgen) is judged on both: from the actual send within the V3 tolerance, from the intended time within the slip limit above the origin's, the difference being the schedule slip. Why: The first run (pilot) showed that loadgen's latency from the actual send agrees with the origin's own within 0.5 ms; the 5 ms by which its reported p99 exceeded it is its schedule slip, which intended-time accounting includes on purpose and the validity limit (p99 slip below 50 ms) bounds.
* **C1, not post hoc** (V7, decided 2026-10-22): The ceiling needs at least 99 % schedule adherence, read from the origin's counter once a second. Why: This is the design's own V7 criterion; the first run's harness counted totals only. Not an amendment: jobs that recorded no readings are not judged on it.

## Verdict per tool and test

| Tool | V0 | V1 | V2 | V3 | V4 | V5 | V6 | V7 | Suggested status |
|---|---|---|---|---|---|---|---|---|---|
| k6 | yes | n.a. | n.a. | fail | n.a. | n.a. | n.a. | n.a. | incomplete (no latency claims) |
| loadgen | yes | n.a. | n.a. | pass | n.a. | n.a. | n.a. | n.a. | incomplete |
| vegeta | yes | n.a. | n.a. | fail | n.a. | n.a. | n.a. | n.a. | incomplete (no latency claims) |

`control ok` means the closed-loop control failed the stall test the way a closed-loop tool should. The manifest (`bench/loadtools.json`) is edited by hand from these suggestions; nothing here writes it.

## V7: ceiling and cost

| Tool | Highest rate held (requests/s) | Share on schedule, by rate | CPU s per 1000 requests (load step; cores used), by rate |
|---|---|---|---|

A `-` for the share on schedule means no per-second arrivals were recorded for that job, so adherence was not part of its verdict; a `-` for the cores means the cost covers all the tool's steps, not the load step alone (an upper bound). k6's cost includes the start of its virtual users.


## Checks

| Job | Check | Observed | Expected | Tolerance | Pass |
|---|---|---|---|---|---|
| V3/k6/r500_0 | reported p50 against the origin's own | 0.009241 | 0.008616 | 0.001 | yes |
| V3/k6/r500_0 | reported p99 against the origin's own | 0.02705 | 0.02175 | 0.002175 | no |
| V3/k6/r500_1 | reported p50 against the origin's own | 0.009349 | 0.008669 | 0.001 | yes |
| V3/k6/r500_1 | reported p99 against the origin's own | 0.02449 | 0.01856 | 0.001856 | no |
| V3/k6/r500_2 | reported p50 against the origin's own | 0.009299 | 0.008676 | 0.001 | yes |
| V3/k6/r500_2 | reported p99 against the origin's own | 0.02995 | 0.02839 | 0.002839 | yes |
| V3/loadgen/r500_0 | latency from the actual send, p50, against the origin's own [A2, post hoc] | 0.01061 | 0.01015 | 0.001015 | yes |
| V3/loadgen/r500_0 | latency from the actual send, p99, against the origin's own [A2, post hoc] | 0.02916 | 0.02734 | 0.002734 | yes |
| V3/loadgen/r500_0 | latency from the intended time, p50, above the origin's (the schedule slip) [A2, post hoc] | 0.003174 | 0 | 0.05 | yes |
| V3/loadgen/r500_0 | latency from the intended time, p99, above the origin's (the schedule slip) [A2, post hoc] | 0.02044 | 0 | 0.05 | yes |
| V3/loadgen/r500_1 | latency from the actual send, p50, against the origin's own [A2, post hoc] | 0.009522 | 0.00904 | 0.001 | yes |
| V3/loadgen/r500_1 | latency from the actual send, p99, against the origin's own [A2, post hoc] | 0.01938 | 0.01846 | 0.001846 | yes |
| V3/loadgen/r500_1 | latency from the intended time, p50, above the origin's (the schedule slip) [A2, post hoc] | 0.00191 | 0 | 0.05 | yes |
| V3/loadgen/r500_1 | latency from the intended time, p99, above the origin's (the schedule slip) [A2, post hoc] | 0.00978 | 0 | 0.05 | yes |
| V3/loadgen/r500_2 | latency from the actual send, p50, against the origin's own [A2, post hoc] | 0.009991 | 0.009473 | 0.001 | yes |
| V3/loadgen/r500_2 | latency from the actual send, p99, against the origin's own [A2, post hoc] | 0.02548 | 0.02394 | 0.002394 | yes |
| V3/loadgen/r500_2 | latency from the intended time, p50, above the origin's (the schedule slip) [A2, post hoc] | 0.002221 | 0 | 0.05 | yes |
| V3/loadgen/r500_2 | latency from the intended time, p99, above the origin's (the schedule slip) [A2, post hoc] | 0.01985 | 0 | 0.05 | yes |
| V3/vegeta/r500_0 | reported p50 against the origin's own | 0.009292 | 0.008582 | 0.001 | yes |
| V3/vegeta/r500_0 | reported p99 against the origin's own | 0.03347 | 0.01718 | 0.001718 | no |
| V3/vegeta/r500_1 | reported p50 against the origin's own | 0.009298 | 0.008638 | 0.001 | yes |
| V3/vegeta/r500_1 | reported p99 against the origin's own | 0.0236 | 0.01841 | 0.001841 | no |
| V3/vegeta/r500_2 | reported p50 against the origin's own | 0.009301 | 0.008629 | 0.001 | yes |
| V3/vegeta/r500_2 | reported p99 against the origin's own | 0.02627 | 0.01754 | 0.001754 | no |

## Notes

* `V3/k6/r500_0`: percentiles from: k6-trend
* `V3/k6/r500_0`: the origin's own service time: p50 8.6 ms, p99 21.7 ms, max 55.5 ms
* `V3/k6/r500_1`: percentiles from: k6-trend
* `V3/k6/r500_1`: the origin's own service time: p50 8.7 ms, p99 18.6 ms, max 110.0 ms
* `V3/k6/r500_2`: percentiles from: k6-trend
* `V3/k6/r500_2`: the origin's own service time: p50 8.7 ms, p99 28.4 ms, max 110.9 ms
* `V3/loadgen/r500_0`: percentiles from: exact-intended-time
* `V3/loadgen/r500_0`: the tool's schedule slip: p50 2.2 ms, p99 22.0 ms
* `V3/loadgen/r500_0`: the origin's own service time: p50 10.1 ms, p99 27.3 ms, max 91.4 ms
* `V3/loadgen/r500_1`: percentiles from: exact-intended-time
* `V3/loadgen/r500_1`: the tool's schedule slip: p50 1.2 ms, p99 12.3 ms
* `V3/loadgen/r500_1`: the origin's own service time: p50 9.0 ms, p99 18.5 ms, max 63.6 ms
* `V3/loadgen/r500_2`: percentiles from: exact-intended-time
* `V3/loadgen/r500_2`: the tool's schedule slip: p50 1.5 ms, p99 20.7 ms
* `V3/loadgen/r500_2`: the origin's own service time: p50 9.5 ms, p99 23.9 ms, max 165.2 ms
* `V3/vegeta/r500_0`: percentiles from: exact
* `V3/vegeta/r500_0`: the origin's own service time: p50 8.6 ms, p99 17.2 ms, max 41.5 ms
* `V3/vegeta/r500_1`: percentiles from: exact
* `V3/vegeta/r500_1`: the origin's own service time: p50 8.6 ms, p99 18.4 ms, max 49.6 ms
* `V3/vegeta/r500_2`: percentiles from: exact
* `V3/vegeta/r500_2`: the origin's own service time: p50 8.6 ms, p99 17.5 ms, max 75.7 ms

## Warm-up (not scored)

`warmup/V3/vegeta/r500_0` ran once before the scored jobs, to bring the CPUs, the origin and the tool out of idle. Its checks and notes, for the record; they are not part of any verdict:

| Check | Observed | Expected | Tolerance | Pass |
|---|---|---|---|---|
| reported p50 against the origin's own | 0.009301 | 0.00861 | 0.001 | yes |
| reported p99 against the origin's own | 0.02926 | 0.01656 | 0.001656 | no |

* percentiles from: exact
* the origin's own service time: p50 8.6 ms, p99 16.6 ms, max 51.4 ms

## Tools

| Tool | Pinned version | Printed | Manifest status | sha256 |
|---|---|---|---|---|
| k6 | v2.3.0 | k6 v2.3.0 (commit/e088784614, go1.26.8, linux/amd64) | verified | `e001bbf39ba67424...` |
| loadgen | 1 | loadgen 1 | verified | `91aab0837ce68898...` |
| vegeta | v12.13.0 | Version: v12.13.0 | smoke-tested | `c54d905541485153...` |
