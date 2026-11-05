# Verification of the HTTP load generators (V0-V7)

Produced by `bench/loadtool_validate.py` against loopback origins; the tests and the pass criteria are in `docs/BENCHMARK_HARM_DESIGN.md`, 8.4. The criteria are constants of that script, fixed before any measurement.

* Commit: `58412df35cd78a333fb04ca810f2fb15a734273b` (dirty: no); host: Linux ddos-mitigation 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 ; created 2026-10-22T13:57:12Z.
* Environment gate (up at least 1800 s, load below 0.3): uptime 6900 s, load 0.24, waited 0 s: met.
* Timer wake-up lateness before the run (sleep 10 ms, 200 samples): p50 0.4 ms, p99 5.3 ms, max 862.7 ms.
* Timer wake-up lateness after the run (sleep 10 ms, 200 samples): p50 4.2 ms, p99 18.2 ms, max 29.2 ms. **above the limit: schedules will slip**

Timer wake-up lateness on the CPUs in use (a probe pinned to them, sleep 10 ms, 200 samples; p50 / p99 / max in ms):

| CPUs | Used for | Before the run | After the run |
|---|---|---|---|
| 0-1 | S1 (Nginx) | 2.2 / 10.7 / 13.2 **above the limit** | 4.3 / 15.2 / 15.4 **above the limit** |
| 2-3 | S2 (scripted origin) | 1.7 / 10.5 / 14.9 **above the limit** | 2.3 / 13.7 / 22.0 **above the limit** |
| 4-7 | tools | 1.9 / 10.0 / 11.6 | 3.4 / 13.2 / 15.9 **above the limit** |
| 4 | the tool in V7 | 3.8 / 26.7 / 40.7 **above the limit** | 2.8 / 12.8 / 14.2 **above the limit** |

## Criteria

Version 2: the pre-registered criteria (version 1) with the changes below. **Post hoc** marks a change decided after the first run; it is labelled the same way next to every check it affects.

* **A1, post hoc** (V4, decided 2026-10-22): The closed-loop control is judged by the requests that arrive at the origin during the stall (fewer than 10 % of rate x stall), not by its reported p99, which is shown but not counted. Why: The first run (pilot) showed that wrk 4.1.0 held its connections and sent nothing during the stall, yet reported p99 2.61 s: its percentiles appear to be corrected for coordinated omission after the run, so they do not tell a closed-loop tool from an open-loop one; its arrivals do.
* **A2, post hoc** (V3, decided 2026-10-22): Latency is judged from the actual send for every tool. A tool that also reports it from the intended time (loadgen) is judged on both: from the actual send within the V3 tolerance, from the intended time within the slip limit above the origin's, the difference being the schedule slip. Why: The first run (pilot) showed that loadgen's latency from the actual send agrees with the origin's own within 0.5 ms; the 5 ms by which its reported p99 exceeded it is its schedule slip, which intended-time accounting includes on purpose and the validity limit (p99 slip below 50 ms) bounds.
* **C1, not post hoc** (V7, decided 2026-10-22): The ceiling needs at least 99 % schedule adherence, read from the origin's counter once a second. Why: This is the design's own V7 criterion; the first run's harness counted totals only. Not an amendment: jobs that recorded no readings are not judged on it.

## Verdict per tool and test

| Tool | V0 | V1 | V2 | V3 | V4 | V5 | V6 | V7 | Suggested status |
|---|---|---|---|---|---|---|---|---|---|
| k6 | yes | pass | pass | pass | pass | pass | pass | measured | verified |
| loadgen | yes | pass | pass | pass | pass | pass | pass | measured | verified |
| vegeta | yes | pass | pass | fail | pass | fail | pass | measured | verified (no latency claims; no overload claims) |
| wrk | yes | n.a. | n.a. | n.a. | control ok | n.a. | n.a. | n.a. | control |

`control ok` means the closed-loop control failed the stall test the way a closed-loop tool should. The manifest (`bench/loadtools.json`) is edited by hand from these suggestions; nothing here writes it.

## V7: ceiling and cost

| Tool | Highest rate held (requests/s) | Share on schedule, by rate | CPU s per 1000 requests (load step; cores used), by rate |
|---|---|---|---|
| k6 | 2000 | 1000: 0.9993, 2000: 0.9989, 5000: 0.945, 10000: 0.5451, 20000: 0.2592 | 1000: 0.2943 (0.2943), 2000: 0.2333 (0.4666), 5000: 0.1953 (0.9251), 10000: 0.2092 (1.14), 20000: 0.2188 (1.134) |
| loadgen | 10000 | 1000: 0.9977, 2000: 0.9955, 5000: 0.9998, 10000: 0.9993, 20000: 0.8337 | 1000: 0.1335 (0.1335), 2000: 0.1256 (0.2511), 5000: 0.1406 (0.703), 10000: 0.09556 (0.9556), 20000: 0.0601 (1.202) |
| vegeta | 2000 | 1000: 0.9993, 2000: 0.9994, 5000: 0.9538, 10000: 0.2716, 20000: 0.6614 | 1000: 0.2069 (0.2068), 2000: 0.1445 (0.2889), 5000: 0.1403 (0.7013), 10000: 0.382 (1.038), 20000: 0.07283 (0.9633) |

A `-` for the share on schedule means no per-second arrivals were recorded for that job, so adherence was not part of its verdict; a `-` for the cores means the cost covers all the tool's steps, not the load step alone (an upper bound). k6's cost includes the start of its virtual users.


## Checks

| Job | Check | Observed | Expected | Tolerance | Pass |
|---|---|---|---|---|---|
| V1/k6/r100_0 | the tool reports no errors | 0 | 0 | - | yes |
| V1/k6/r100_0 | requests the tool sent | 1001 | 1000 | 0.02 | yes |
| V1/k6/r100_0 | requests the origin counted | 1001 | 1000 | 0.02 | yes |
| V1/loadgen/r100_0 | the tool reports no errors | 0 | 0 | - | yes |
| V1/loadgen/r100_0 | requests the tool sent | 1000 | 1000 | 0.02 | yes |
| V1/loadgen/r100_0 | requests the origin counted | 1000 | 1000 | 0.02 | yes |
| V1/vegeta/r100_0 | the tool reports no errors | 0 | 0 | - | yes |
| V1/vegeta/r100_0 | requests the tool sent | 1000 | 1000 | 0.02 | yes |
| V1/vegeta/r100_0 | requests the origin counted | 1000 | 1000 | 0.02 | yes |
| V2/k6/r200_0 | requests the origin counted | 4001 | 4000 | 0.01 | yes |
| V2/k6/r200_1 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/k6/r200_2 | requests the origin counted | 4001 | 4000 | 0.01 | yes |
| V2/k6/r1000_0 | requests the origin counted | 20001 | 20000 | 0.01 | yes |
| V2/k6/r1000_1 | requests the origin counted | 20008 | 20000 | 0.01 | yes |
| V2/k6/r1000_2 | requests the origin counted | 20001 | 20000 | 0.01 | yes |
| V2/k6/r5000_0 | requests the origin counted | 100001 | 100000 | 0.01 | yes |
| V2/k6/r5000_1 | requests the origin counted | 99951 | 100000 | 0.01 | yes |
| V2/k6/r5000_2 | requests the origin counted | 100089 | 100000 | 0.01 | yes |
| V2/loadgen/r200_0 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/loadgen/r200_1 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/loadgen/r200_2 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/loadgen/r1000_0 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V2/loadgen/r1000_1 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V2/loadgen/r1000_2 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V2/loadgen/r5000_0 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V2/loadgen/r5000_1 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V2/loadgen/r5000_2 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V2/vegeta/r200_0 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/vegeta/r200_1 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/vegeta/r200_2 | requests the origin counted | 4000 | 4000 | 0.01 | yes |
| V2/vegeta/r1000_0 | requests the origin counted | 19999 | 20000 | 0.01 | yes |
| V2/vegeta/r1000_1 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V2/vegeta/r1000_2 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V2/vegeta/r5000_0 | requests the origin counted | 99903 | 100000 | 0.01 | yes |
| V2/vegeta/r5000_1 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V2/vegeta/r5000_2 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V3/k6/r500_0 | reported p50 against the origin's own | 0.00912 | 0.00856 | 0.001 | yes |
| V3/k6/r500_0 | reported p99 against the origin's own | 0.01848 | 0.01759 | 0.001759 | yes |
| V3/loadgen/r500_0 | latency from the actual send, p50, against the origin's own [A2, post hoc] | 0.01048 | 0.01005 | 0.001005 | yes |
| V3/loadgen/r500_0 | latency from the actual send, p99, against the origin's own [A2, post hoc] | 0.02595 | 0.02537 | 0.002537 | yes |
| V3/loadgen/r500_0 | latency from the intended time, p50, above the origin's (the schedule slip) [A2, post hoc] | 0.002933 | 0 | 0.05 | yes |
| V3/loadgen/r500_0 | latency from the intended time, p99, above the origin's (the schedule slip) [A2, post hoc] | 0.01872 | 0 | 0.05 | yes |
| V3/vegeta/r500_0 | reported p50 against the origin's own | 0.009477 | 0.008728 | 0.001 | yes |
| V3/vegeta/r500_0 | reported p99 against the origin's own | 0.6767 | 0.1526 | 0.01526 | no |
| V4/k6/r500_0 | reported p99 against the analytic value | 2.625 | 2.607 | 0.3911 | yes |
| V4/k6/r500_0 | arrivals during the stall (the tool kept sending) | 1496 | 1500 | 0.1 | yes |
| V4/loadgen/r500_0 | reported p99 against the analytic value | 2.66 | 2.607 | 0.3911 | yes |
| V4/loadgen/r500_0 | arrivals during the stall (the tool kept sending) | 1501 | 1500 | 0.1 | yes |
| V4/vegeta/r500_0 | reported p99 against the analytic value | 2.629 | 2.607 | 0.3911 | yes |
| V4/vegeta/r500_0 | arrivals during the stall (the tool kept sending) | 1500 | 1500 | 0.1 | yes |
| V4/wrk/r500_0 | the closed-loop control sends little during the stall [A1, post hoc] | 0 | 1500 | 150 | yes |
| V4/wrk/r500_0 | the closed-loop control reports far below the analytic p99 [A1, post hoc] | 3 | 2.607 | 0.2607 | no (not counted) |
| V5/k6/r2000_0 | arrivals follow the intended rate, or the tool reports the difference | 23354 | 40000 | 0.02 | yes |
| V5/loadgen/r2000_0 | arrivals follow the intended rate, or the tool reports the difference | 22850 | 40000 | 0.02 | yes |
| V5/vegeta/r2000_0 | arrivals follow the intended rate, or the tool reports the difference | 19693 | 40000 | 0.02 | no |
| V6/k6/r500_0 | non-2xx the tool counted against the 503s the origin sent | 1000 | 1000 | 10 | yes |
| V6/k6/r500_0 | requests the tool counted against the origin's arrivals | 10001 | 10001 | 0.01 | yes |
| V6/loadgen/r500_0 | non-2xx the tool counted against the 503s the origin sent | 1000 | 1000 | 10 | yes |
| V6/loadgen/r500_0 | requests the tool counted against the origin's arrivals | 10000 | 10000 | 0.01 | yes |
| V6/vegeta/r500_0 | non-2xx the tool counted against the 503s the origin sent | 1000 | 1000 | 10 | yes |
| V6/vegeta/r500_0 | requests the tool counted against the origin's arrivals | 10000 | 10000 | 0.01 | yes |
| V7/k6/r1000_0 | requests the origin counted | 10001 | 10000 | 0.01 | yes |
| V7/k6/r1000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r1000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9993 | 1 | 0.01 | yes |
| V7/k6/r2000_0 | requests the origin counted | 20004 | 20000 | 0.01 | yes |
| V7/k6/r2000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r2000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9989 | 1 | 0.01 | yes |
| V7/k6/r5000_0 | requests the origin counted | 47376 | 50000 | 0.01 | no |
| V7/k6/r5000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r5000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.945 | 1 | 0.01 | no |
| V7/k6/r10000_0 | requests the origin counted | 54511 | 100000 | 0.01 | no |
| V7/k6/r10000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r10000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.5451 | 1 | 0.01 | no |
| V7/k6/r20000_0 | requests the origin counted | 51838 | 200000 | 0.01 | no |
| V7/k6/r20000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r20000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.2592 | 1 | 0.01 | no |
| V7/loadgen/r1000_0 | requests the origin counted | 10000 | 10000 | 0.01 | yes |
| V7/loadgen/r1000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r1000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9977 | 1 | 0.01 | yes |
| V7/loadgen/r2000_0 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V7/loadgen/r2000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r2000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9955 | 1 | 0.01 | yes |
| V7/loadgen/r5000_0 | requests the origin counted | 50000 | 50000 | 0.01 | yes |
| V7/loadgen/r5000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r5000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9998 | 1 | 0.01 | yes |
| V7/loadgen/r10000_0 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V7/loadgen/r10000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r10000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9993 | 1 | 0.01 | yes |
| V7/loadgen/r20000_0 | requests the origin counted | 200000 | 200000 | 0.01 | yes |
| V7/loadgen/r20000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r20000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.8337 | 1 | 0.01 | no |
| V7/vegeta/r1000_0 | requests the origin counted | 9993 | 10000 | 0.01 | yes |
| V7/vegeta/r1000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r1000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9993 | 1 | 0.01 | yes |
| V7/vegeta/r2000_0 | requests the origin counted | 19993 | 20000 | 0.01 | yes |
| V7/vegeta/r2000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r2000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9994 | 1 | 0.01 | yes |
| V7/vegeta/r5000_0 | requests the origin counted | 50000 | 50000 | 0.01 | yes |
| V7/vegeta/r5000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r5000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.9538 | 1 | 0.01 | no |
| V7/vegeta/r10000_0 | requests the origin counted | 27159 | 100000 | 0.01 | no |
| V7/vegeta/r10000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r10000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.2716 | 1 | 0.01 | no |
| V7/vegeta/r20000_0 | requests the origin counted | 132274 | 200000 | 0.01 | no |
| V7/vegeta/r20000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r20000_0 | intended requests that arrived in their own part of the schedule [C1] | 0.6614 | 1 | 0.01 | no |

## Notes

* `V1/loadgen/r100_0`: the tool's own validity flags: slip
* `V2/k6/r200_0`: the tool counted 4001 and reported 0 errors
* `V2/k6/r200_1`: the tool counted 4000 and reported 0 errors
* `V2/k6/r200_2`: the tool counted 4001 and reported 0 errors
* `V2/k6/r1000_0`: the tool counted 20001 and reported 0 errors
* `V2/k6/r1000_1`: the tool counted 20008 and reported 0 errors
* `V2/k6/r1000_2`: the tool counted 20001 and reported 0 errors
* `V2/k6/r5000_0`: the tool counted 100001 and reported 0 errors
* `V2/k6/r5000_1`: the tool counted 99951 and reported 0 errors
* `V2/k6/r5000_2`: the tool counted 100089 and reported 0 errors
* `V2/loadgen/r200_0`: the tool counted 4000 and reported 0 errors
* `V2/loadgen/r200_0`: the tool's own validity flags: slip
* `V2/loadgen/r200_1`: the tool counted 4000 and reported 0 errors
* `V2/loadgen/r200_2`: the tool counted 4000 and reported 0 errors
* `V2/loadgen/r1000_0`: the tool counted 20000 and reported 0 errors
* `V2/loadgen/r1000_1`: the tool counted 20000 and reported 0 errors
* `V2/loadgen/r1000_1`: the tool's own validity flags: slip
* `V2/loadgen/r1000_2`: the tool counted 20000 and reported 0 errors
* `V2/loadgen/r5000_0`: the tool counted 100000 and reported 0 errors
* `V2/loadgen/r5000_0`: the tool's own validity flags: cpu
* `V2/loadgen/r5000_1`: the tool counted 100000 and reported 0 errors
* `V2/loadgen/r5000_2`: the tool counted 100000 and reported 0 errors
* `V2/loadgen/r5000_2`: the tool's own validity flags: cpu
* `V2/vegeta/r200_0`: the tool counted 4000 and reported 0 errors
* `V2/vegeta/r200_1`: the tool counted 4000 and reported 0 errors
* `V2/vegeta/r200_2`: the tool counted 4000 and reported 0 errors
* `V2/vegeta/r1000_0`: the tool counted 19999 and reported 0 errors
* `V2/vegeta/r1000_1`: the tool counted 20000 and reported 0 errors
* `V2/vegeta/r1000_2`: the tool counted 20000 and reported 0 errors
* `V2/vegeta/r5000_0`: the tool counted 99903 and reported 0 errors
* `V2/vegeta/r5000_1`: the tool counted 100000 and reported 0 errors
* `V2/vegeta/r5000_2`: the tool counted 100000 and reported 0 errors
* `V3/k6/r500_0`: percentiles from: k6-trend
* `V3/loadgen/r500_0`: percentiles from: exact-intended-time
* `V3/loadgen/r500_0`: the tool's schedule slip: p50 2.1 ms, p99 20.6 ms
* `V3/vegeta/r500_0`: percentiles from: exact
* `V4/k6/r500_0`: percentiles from: k6-trend
* `V4/loadgen/r500_0`: percentiles from: exact-intended-time
* `V4/vegeta/r500_0`: percentiles from: exact
* `V4/wrk/r500_0`: percentiles from: wrk-histogram
* `V4/wrk/r500_0`: pass means the control sent almost nothing while its connections waited, as a closed-loop tool does, so the test can tell; its reported p99 is shown, not counted
* `V5/k6/r2000_0`: tool-reported drops: 16648
* `V5/k6/r2000_0`: silent shortfall: 0
* `V5/k6/r2000_0`: tool errors: 44
* `V5/loadgen/r2000_0`: tool-reported drops: 17150
* `V5/loadgen/r2000_0`: silent shortfall: 0
* `V5/loadgen/r2000_0`: tool errors: 0
* `V5/loadgen/r2000_0`: the tool's own validity flags: dropped, sent_short
* `V5/vegeta/r2000_0`: tool-reported drops: 0
* `V5/vegeta/r2000_0`: silent shortfall: 20307
* `V5/vegeta/r2000_0`: tool errors: 0
* `V7/k6/r1000_0`: CPU per 1000 requests: 0.294 s
* `V7/k6/r2000_0`: CPU per 1000 requests: 0.233 s
* `V7/k6/r5000_0`: CPU per 1000 requests: 0.195 s
* `V7/k6/r10000_0`: CPU per 1000 requests: 0.209 s
* `V7/k6/r20000_0`: CPU per 1000 requests: 0.219 s
* `V7/loadgen/r1000_0`: CPU per 1000 requests: 0.133 s
* `V7/loadgen/r2000_0`: CPU per 1000 requests: 0.126 s
* `V7/loadgen/r2000_0`: the tool's own validity flags: slip
* `V7/loadgen/r5000_0`: CPU per 1000 requests: 0.141 s
* `V7/loadgen/r5000_0`: the tool's own validity flags: slip
* `V7/loadgen/r10000_0`: CPU per 1000 requests: 0.096 s
* `V7/loadgen/r10000_0`: the tool's own validity flags: cpu, slip
* `V7/loadgen/r20000_0`: CPU per 1000 requests: 0.060 s
* `V7/loadgen/r20000_0`: arrivals went on for about 1.799 s after the end of the schedule
* `V7/loadgen/r20000_0`: the tool's own validity flags: cpu, slip
* `V7/vegeta/r1000_0`: CPU per 1000 requests: 0.207 s
* `V7/vegeta/r2000_0`: CPU per 1000 requests: 0.145 s
* `V7/vegeta/r5000_0`: CPU per 1000 requests: 0.140 s
* `V7/vegeta/r10000_0`: CPU per 1000 requests: 0.382 s
* `V7/vegeta/r20000_0`: CPU per 1000 requests: 0.073 s

## Tools

| Tool | Pinned version | Printed | Manifest status | sha256 |
|---|---|---|---|---|
| k6 | v2.3.0 | k6 v2.3.0 (commit/e088784614, go1.26.8, linux/amd64) | smoke-tested | `e001bbf39ba67424...` |
| loadgen | 1 | loadgen 1 | installed | `91aab0837ce68898...` |
| vegeta | v12.13.0 | Version: v12.13.0 | smoke-tested | `c54d905541485153...` |
| wrk | debian/4.1.0-4build3 | wrk debian/4.1.0-4build3 [epoll] Copyright (C) 2012 Will Glozer | installed | `f6536e3f9479584f...` |
