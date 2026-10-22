# Verification of the HTTP load generators (V0-V7)

Produced by `bench/loadtool_validate.py` against loopback origins; the tests and the pass criteria are in `docs/BENCHMARK_HARM_DESIGN.md`, 8.4. The criteria are constants of that script, fixed before any measurement.

* Commit: `210399ce4bf755adc2e9f0ab6a1db091b624ef2b` (dirty: no); host: Linux ddos-mitigation 7.0.0-38-generic #38-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep  4 09:10:14 UTC 2026 x86_64 ; created 2026-10-22T12:32:21Z.
* Timer wake-up lateness before the run (sleep 10 ms, 200 samples): p50 5.6 ms, p99 19.0 ms, max 22.1 ms. **above the limit: schedules will slip**
* Timer wake-up lateness after the run (sleep 10 ms, 200 samples): p50 2.3 ms, p99 9.1 ms, max 14.0 ms.

## Verdict per tool and test

| Tool | V0 | V1 | V2 | V3 | V4 | V5 | V6 | V7 | Suggested status |
|---|---|---|---|---|---|---|---|---|---|
| k6 | yes | pass | fail | pass | fail | pass | pass | measured | unfit (no latency claims under stalls) |
| loadgen | yes | pass | pass | fail | pass | pass | pass | measured | verified (no latency claims) |
| vegeta | yes | pass | pass | fail | pass | fail | pass | measured | verified (no latency claims; no overload claims) |
| wrk | yes | n.a. | n.a. | n.a. | control NOT as expected | n.a. | n.a. | n.a. | control |

`control ok` means the closed-loop control failed the stall test the way a closed-loop tool should. The manifest (`bench/loadtools.json`) is edited by hand from these suggestions; nothing here writes it.

## V7: ceiling and cost

| Tool | Highest rate held (requests/s) | CPU s per 1000 requests, by rate |
|---|---|---|
| k6 | 2000 | 1000: 0.2645, 2000: 0.2007, 5000: 0.1651, 10000: 0.1681, 20000: 0.1803 |
| loadgen | 20000 | 1000: 0.1651, 2000: 0.1691, 5000: 0.1303, 10000: 0.1066, 20000: 0.07415 |
| vegeta | 2000 | 1000: 0.2165, 2000: 0.1583, 5000: 0.5047, 10000: 2.792, 20000: 2.825 |

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
| V2/k6/r200_1 | requests the origin counted | 4001 | 4000 | 0.01 | yes |
| V2/k6/r200_2 | requests the origin counted | 4001 | 4000 | 0.01 | yes |
| V2/k6/r1000_0 | requests the origin counted | 19106 | 20000 | 0.01 | no |
| V2/k6/r1000_1 | requests the origin counted | 19972 | 20000 | 0.01 | yes |
| V2/k6/r1000_2 | requests the origin counted | 20002 | 20000 | 0.01 | yes |
| V2/k6/r5000_0 | requests the origin counted | 99844 | 100000 | 0.01 | yes |
| V2/k6/r5000_1 | requests the origin counted | 96347 | 100000 | 0.01 | no |
| V2/k6/r5000_2 | requests the origin counted | 99550 | 100000 | 0.01 | yes |
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
| V2/vegeta/r5000_0 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V2/vegeta/r5000_1 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V2/vegeta/r5000_2 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V3/k6/r500_0 | reported p50 against the origin's own | 0.009113 | 0.008531 | 0.001 | yes |
| V3/k6/r500_0 | reported p99 against the origin's own | 0.01683 | 0.01626 | 0.001626 | yes |
| V3/loadgen/r500_0 | reported p50 against the origin's own | 0.01085 | 0.009046 | 0.001 | no |
| V3/loadgen/r500_0 | reported p99 against the origin's own | 0.02018 | 0.01516 | 0.001516 | no |
| V3/vegeta/r500_0 | reported p50 against the origin's own | 0.009264 | 0.00864 | 0.001 | yes |
| V3/vegeta/r500_0 | reported p99 against the origin's own | 0.02489 | 0.01781 | 0.001781 | no |
| V4/k6/r500_0 | reported p99 against the analytic value | 2.385 | 2.607 | 0.3911 | yes |
| V4/k6/r500_0 | arrivals during the stall (the tool kept sending) | 621 | 1500 | 0.1 | no |
| V4/loadgen/r500_0 | reported p99 against the analytic value | 2.667 | 2.607 | 0.3911 | yes |
| V4/loadgen/r500_0 | arrivals during the stall (the tool kept sending) | 1500 | 1500 | 0.1 | yes |
| V4/vegeta/r500_0 | reported p99 against the analytic value | 2.633 | 2.607 | 0.3911 | yes |
| V4/vegeta/r500_0 | arrivals during the stall (the tool kept sending) | 1499 | 1500 | 0.1 | yes |
| V4/wrk/r500_0 | the closed-loop control reports far below the analytic p99 | 2.61 | 2.607 | 0.2607 | no |
| V5/k6/r2000_0 | arrivals follow the intended rate, or the tool reports the difference | 23558 | 40000 | 0.02 | yes |
| V5/loadgen/r2000_0 | arrivals follow the intended rate, or the tool reports the difference | 23400 | 40000 | 0.02 | yes |
| V5/vegeta/r2000_0 | arrivals follow the intended rate, or the tool reports the difference | 19711 | 40000 | 0.02 | no |
| V6/k6/r500_0 | non-2xx the tool counted against the 503s the origin sent | 1000 | 1000 | 10 | yes |
| V6/k6/r500_0 | requests the tool counted against the origin's arrivals | 10000 | 10000 | 0.01 | yes |
| V6/loadgen/r500_0 | non-2xx the tool counted against the 503s the origin sent | 1000 | 1000 | 10 | yes |
| V6/loadgen/r500_0 | requests the tool counted against the origin's arrivals | 10000 | 10000 | 0.01 | yes |
| V6/vegeta/r500_0 | non-2xx the tool counted against the 503s the origin sent | 1000 | 1000 | 10 | yes |
| V6/vegeta/r500_0 | requests the tool counted against the origin's arrivals | 10000 | 10000 | 0.01 | yes |
| V7/k6/r1000_0 | requests the origin counted | 10002 | 10000 | 0.01 | yes |
| V7/k6/r1000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r2000_0 | requests the origin counted | 20001 | 20000 | 0.01 | yes |
| V7/k6/r2000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r5000_0 | requests the origin counted | 45210 | 50000 | 0.01 | no |
| V7/k6/r5000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r10000_0 | requests the origin counted | 60380 | 100000 | 0.01 | no |
| V7/k6/r10000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/k6/r20000_0 | requests the origin counted | 55851 | 200000 | 0.01 | no |
| V7/k6/r20000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r1000_0 | requests the origin counted | 10000 | 10000 | 0.01 | yes |
| V7/loadgen/r1000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r2000_0 | requests the origin counted | 20000 | 20000 | 0.01 | yes |
| V7/loadgen/r2000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r5000_0 | requests the origin counted | 50000 | 50000 | 0.01 | yes |
| V7/loadgen/r5000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r10000_0 | requests the origin counted | 100000 | 100000 | 0.01 | yes |
| V7/loadgen/r10000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/loadgen/r20000_0 | requests the origin counted | 200000 | 200000 | 0.01 | yes |
| V7/loadgen/r20000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r1000_0 | requests the origin counted | 9999 | 10000 | 0.01 | yes |
| V7/vegeta/r1000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r2000_0 | requests the origin counted | 19996 | 20000 | 0.01 | yes |
| V7/vegeta/r2000_0 | no tool errors and no non-2xx | 0 | 0 | - | yes |
| V7/vegeta/r5000_0 | requests the origin counted | 32140 | 50000 | 0.01 | no |
| V7/vegeta/r5000_0 | no tool errors and no non-2xx | 1780 | 0 | - | no |
| V7/vegeta/r10000_0 | requests the origin counted | 3739 | 100000 | 0.01 | no |
| V7/vegeta/r10000_0 | no tool errors and no non-2xx | 7 | 0 | - | no |
| V7/vegeta/r20000_0 | requests the origin counted | 3723 | 200000 | 0.01 | no |
| V7/vegeta/r20000_0 | no tool errors and no non-2xx | 5 | 0 | - | no |

## Notes

* `V2/k6/r200_0`: the tool counted 4001 and reported 0 errors
* `V2/k6/r200_1`: the tool counted 4001 and reported 0 errors
* `V2/k6/r200_2`: the tool counted 4001 and reported 0 errors
* `V2/k6/r1000_0`: the tool counted 19106 and reported 0 errors
* `V2/k6/r1000_1`: the tool counted 19972 and reported 0 errors
* `V2/k6/r1000_2`: the tool counted 20002 and reported 0 errors
* `V2/k6/r5000_0`: the tool counted 99844 and reported 0 errors
* `V2/k6/r5000_1`: the tool counted 96347 and reported 0 errors
* `V2/k6/r5000_2`: the tool counted 99550 and reported 0 errors
* `V2/loadgen/r200_0`: the tool counted 4000 and reported 0 errors
* `V2/loadgen/r200_1`: the tool counted 4000 and reported 0 errors
* `V2/loadgen/r200_1`: the tool's own validity flags: slip
* `V2/loadgen/r200_2`: the tool counted 4000 and reported 0 errors
* `V2/loadgen/r1000_0`: the tool counted 20000 and reported 0 errors
* `V2/loadgen/r1000_1`: the tool counted 20000 and reported 0 errors
* `V2/loadgen/r1000_2`: the tool counted 20000 and reported 0 errors
* `V2/loadgen/r5000_0`: the tool counted 100000 and reported 0 errors
* `V2/loadgen/r5000_0`: the tool's own validity flags: slip
* `V2/loadgen/r5000_1`: the tool counted 100000 and reported 0 errors
* `V2/loadgen/r5000_2`: the tool counted 100000 and reported 0 errors
* `V2/vegeta/r200_0`: the tool counted 4000 and reported 0 errors
* `V2/vegeta/r200_1`: the tool counted 4000 and reported 0 errors
* `V2/vegeta/r200_2`: the tool counted 4000 and reported 0 errors
* `V2/vegeta/r1000_0`: the tool counted 19999 and reported 0 errors
* `V2/vegeta/r1000_1`: the tool counted 20000 and reported 0 errors
* `V2/vegeta/r1000_2`: the tool counted 20000 and reported 0 errors
* `V2/vegeta/r5000_0`: the tool counted 100000 and reported 0 errors
* `V2/vegeta/r5000_1`: the tool counted 100000 and reported 0 errors
* `V2/vegeta/r5000_2`: the tool counted 100000 and reported 0 errors
* `V3/k6/r500_0`: percentiles from: k6-trend
* `V3/loadgen/r500_0`: percentiles from: exact-intended-time
* `V3/vegeta/r500_0`: percentiles from: exact
* `V4/k6/r500_0`: percentiles from: k6-trend
* `V4/loadgen/r500_0`: percentiles from: exact-intended-time
* `V4/vegeta/r500_0`: percentiles from: exact
* `V4/wrk/r500_0`: percentiles from: wrk-histogram
* `V4/wrk/r500_0`: pass means the control behaved as a closed-loop tool does, so the test can tell
* `V5/k6/r2000_0`: tool-reported drops: 16445
* `V5/k6/r2000_0`: silent shortfall: 0
* `V5/k6/r2000_0`: tool errors: 0
* `V5/loadgen/r2000_0`: tool-reported drops: 16600
* `V5/loadgen/r2000_0`: silent shortfall: 0
* `V5/loadgen/r2000_0`: tool errors: 0
* `V5/loadgen/r2000_0`: the tool's own validity flags: dropped, sent_short
* `V5/vegeta/r2000_0`: tool-reported drops: 0
* `V5/vegeta/r2000_0`: silent shortfall: 20289
* `V5/vegeta/r2000_0`: tool errors: 0
* `V7/k6/r1000_0`: CPU per 1000 requests: 0.265 s
* `V7/k6/r2000_0`: CPU per 1000 requests: 0.201 s
* `V7/k6/r5000_0`: CPU per 1000 requests: 0.165 s
* `V7/k6/r10000_0`: CPU per 1000 requests: 0.168 s
* `V7/k6/r20000_0`: CPU per 1000 requests: 0.180 s
* `V7/loadgen/r1000_0`: CPU per 1000 requests: 0.165 s
* `V7/loadgen/r2000_0`: CPU per 1000 requests: 0.169 s
* `V7/loadgen/r5000_0`: CPU per 1000 requests: 0.130 s
* `V7/loadgen/r10000_0`: CPU per 1000 requests: 0.107 s
* `V7/loadgen/r10000_0`: the tool's own validity flags: cpu
* `V7/loadgen/r20000_0`: CPU per 1000 requests: 0.074 s
* `V7/loadgen/r20000_0`: the tool's own validity flags: cpu, slip
* `V7/vegeta/r1000_0`: CPU per 1000 requests: 0.217 s
* `V7/vegeta/r2000_0`: CPU per 1000 requests: 0.158 s
* `V7/vegeta/r5000_0`: CPU per 1000 requests: 0.505 s
* `V7/vegeta/r10000_0`: CPU per 1000 requests: 2.792 s
* `V7/vegeta/r20000_0`: CPU per 1000 requests: 2.825 s

## Tools

| Tool | Pinned version | Printed | Manifest status | sha256 |
|---|---|---|---|---|
| k6 | v2.3.0 | k6 v2.3.0 (commit/e088784614, go1.26.8, linux/amd64) | smoke-tested | `e001bbf39ba67424...` |
| loadgen | 1 | loadgen 1 | installed | `91aab0837ce68898...` |
| vegeta | v12.13.0 | Version: v12.13.0 | smoke-tested | `c54d905541485153...` |
| wrk | debian/4.1.0-4build3 | wrk debian/4.1.0-4build3 [epoll] Copyright (C) 2012 Will Glozer | installed | `f6536e3f9479584f...` |
