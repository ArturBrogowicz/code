# Notes on the V3 repeat session (3 repeats per tool, with a warm-up)

Read this before the README of this directory. The README and `results.json` are what
`bench/loadtool_validate.py` computed by criteria version 2 (`docs/BENCHMARK_HARM_DESIGN.md`, 8.4 and
Appendix F.4); this file is what the session showed beyond them. It was written after the session and
is not listed in `SHA256SUMS`. It follows `../2026-10-22_loadtool-validation-run2/`, in which V3 ran
once per tool. Tags: **[FACT]** read from the files here; **[INFERENCE]** reasoned, not measured.

## What was run

* **[FACT]** Commit `d373c7d` (clean tree), VM `ddos-mitigation`, loopback only, no root, approved on
  2026-10-22 as proposed: V3 only (500 requests/s for 30 s against the scripted origin), `--repeats 3
  --warmup`: one unscored warm-up job (`V3/vegeta/r500_0`, kept in `warmup/`) and 9 scored jobs in three
  rounds, vegeta, k6 and the in-repo engine taking turns. Started 15:10:51 UTC; the gate waited 60 s (load
  0.76 from my unit tests, 0.28 when it opened); the jobs ran 15:11:51-15:17:35 UTC. Exit code 0, no
  infrastructure error, no process or listening port left over, `/usr/bin/wrk` and every tool binary
  unchanged. The output was copied here unchanged from
  `/var/tmp/loadtool_validation/20261022_loadtool-validation-v3x3`; `sha256sum -c SHA256SUMS` passes.
* The repetition and the rule "all three must pass" were decided after run 2, so they are **post hoc**;
  the README says so. The V3 checks themselves are unchanged (version 2, with A2 for the engine).
* **[FACT]** Timer wake-up lateness (sleep 10 ms; p50 / p99 / max in ms). Unpinned: before the run
  1.3 / 21.2 / 26.6, after it 3.7 / 25.1 / 38.4. Pinned: S2 (CPUs 2-3) 1.9 / 18.9 / 75.4 then 4.3 / 15.5 /
  16.1; tools (4-7) 1.1 / 11.9 / 33.7 then 3.3 / 16.3 / 27.4.

## Verdicts as computed (criteria version 2)

| Tool | Scored jobs passing | V3 |
|---|---|---|
| vegeta v12.13.0 | 0 of 3 (the warm-up fails too) | **fail** |
| k6 v2.3.0 | 1 of 3 | **fail** |
| in-repo engine | 3 of 3 | **pass** (A2, post hoc) |

Per job, in the order they ran. "Excess" is the tool's p99 minus the origin's own p99 (for the engine, its
latency from the actual send); the tolerance is the larger of 1 ms and 10 % of the origin's own p99; the
p50 check passes in every job (excess 0.5-0.7 ms).

| Job | Origin p50 / p99 / max (ms) | Tool p99 (ms) | p99 excess / tolerance (ms) | Verdict |
|---|---|---|---|---|
| warm-up vegeta | 8.6 / 16.6 / 51.4 | 29.3 | +12.7 / 1.66 | not scored |
| vegeta r0 | 8.6 / 17.2 / 41.5 | 33.5 | +16.3 / 1.72 | fail |
| k6 r0 | 8.6 / 21.7 / 55.5 | 27.1 | +5.3 / 2.17 | fail |
| engine r0 | 10.1 / 27.3 / 91.4 | 29.2 (actual send) | +1.8 / 2.73 | pass |
| vegeta r1 | 8.6 / 18.4 / 49.6 | 23.6 | +5.2 / 1.84 | fail |
| k6 r1 | 8.7 / 18.6 / 110.0 | 24.5 | +5.9 / 1.86 | fail |
| engine r1 | 9.0 / 18.5 / 63.6 | 19.4 (actual send) | +0.9 / 1.85 | pass |
| vegeta r2 | 8.6 / 17.5 / 75.7 | 26.3 | +8.7 / 1.75 | fail |
| k6 r2 | 8.7 / 28.4 / 110.9 | 30.0 | +1.6 / 2.84 | pass |
| engine r2 | 9.5 / 23.9 / 165.2 | 25.5 (actual send) | +1.5 / 2.39 | pass |

The engine's latency from the intended time was 20.4, 9.8 and 19.8 ms above the origin's at p99 (its
schedule slip, p99 22.0, 12.3 and 20.7 ms), inside the 50 ms limit of A2.

## What the session showed

1. **[FACT]** No stall in the ground truth this time. The origin's own p99 was 16.6-28.4 ms in all ten jobs
   and its largest response 41-165 ms, against 152.6 ms and 983 ms in run 2's vegeta job. The stalls of 578 and
   983 ms in the two earlier vegeta V3 jobs did not recur and cannot explain these failures.
2. **[FACT]** vegeta's p99 read 5.2-16.3 ms above the origin's in all four jobs, the warm-up included; k6's
   read +5.3 and +5.9 ms in two of three and +1.6 ms in the third; the engine's, from the actual send, within
   1.8 ms. The tolerance was 1.7-2.8 ms, so only the engine meets it at p99 on this VM.
3. **[FACT]** The warm-up did not differ from the scored vegeta jobs (origin maximum 51 ms, p99 excess
   +12.7 ms). The explanation I offered for the earlier vegeta failures, a first job on idle CPUs, is
   therefore neither shown nor ruled out **[INFERENCE]**: the CPUs were not idle for ten minutes before this
   session (my unit tests and the gate's wait came first), so the condition was not reproduced.
4. **[INFERENCE]** The excess is on the tools' side. The pinned timer probes on the tool CPUs read p99
   12-16 ms, the same order as the excess; the Python engine, which is single-threaded, does not show it.
   Not tested directly (nothing here looks inside the Go scheduler).
5. **[FACT]** Over the five runs so far (the pilot, run 2 and this session's three) k6's p99 excess ranged from
   +0.5 to +5.9 ms against a tolerance of about 2 ms, so whether it passes V3 depends on the run; its two
   earlier passes (+0.5 and +0.9 ms) were the lowest values.

## Consequences for the statuses (nothing applied)

The design's rule (8.4): a generator that fails only V3-V6 is verified with restrictions (no latency or
overload claims). Applied to the manifest as it stands:

* **engine:** unchanged, `verified`; V3 passes in 3 of 3.
* **k6:** `verified` since run 2, when V3 passed once. V3 now fails on repeat, so the restriction "no latency
  claims at millisecond precision" applies; V1, V2, V4, V5 and V6 pass.
* **vegeta:** held at `smoke-tested` until V3 was repeated. It fails again, without a stall in the origin, so
  the reason for waiting is gone and the rule gives "verified with restrictions": no latency claims, and no
  overload claims either (V5: a silent shortfall of 20,307 of 40,000). The manifest has no restricted status
  and nothing enforces the notes.

## Left for the owner

The statuses of k6 and vegeta; whether V3 stays as registered (then only the engine can make
millisecond-level latency claims on this VM) or its tolerance follows the measured noise, which would be a
third post hoc change; the remaining open items of the design (the V7 measure, `--spin-ms`, merging).
