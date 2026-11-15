# Re-calibration of the harm benchmark on the laptop (2026-11): departure 1 from the pre-registration (POST HOC)

**Status: approved by the user on 2026-11-15 ("Fix H7 first"; orchestrator ledger D-108). Labelled post hoc.**
- **Why post hoc:** it changes how a rule is applied after data that rule governs exists. Section 3 of
  `docs/RECALIBRATION_2026-11_PREREG.md` calls such a change a departure. Whatever rests on it says so.
- **The pre-registration file is not edited.** Its sha256 stays 5c22334dfb68f88ecb3a33161b91f9848ccdd2819b99e6419b5c715047bd269c.
- **The pinned commit:** the commit that adds this file. Every packet from R2a's resume on runs with `--commit <that commit>`.

## What changed

**One thing changed:** *when* the monitors' records are read for H4-H7 (H3 reads the run's own records, not the monitors'). K22 (tree fee2bcec8be5afe1873eacba48dd7bcb19a94eca, on
feat/recalibration-k) adds `JUDGE_WAIT_S = 2.0` to `bench/hostcheck.py`. Before reading the monitors' records, `HostCheck.judge` now
sleeps until 2 s after the run's window ends.
- The window is unchanged: from the start of the before-probe pair to the end of the after-probe pair.
- If the judge comes later than that, it does not wait.
- It never waits longer than 2 s.

**Its effect on H4-H6 (found by the independent review, T-120).** H4-H6 read the same records, so they too now see a sample written in
those 2 s. Their text already includes such a sample:
- H4: the chrony samples within one interval of the run.
- H5: the mpstat sample after the run's end.
- H6: the pidstat samples that overlap the window.

Read at the window's end, those samples were almost never there yet. So a run can now also fail H4 or H6 on a sample that ends in
those 2 s, and that sample covers mostly the window itself. H5 can change only a verdict that H7 fails anyway.

**Unchanged:**
- H7's wording in section 5.1: "the monitors' records cover the window (fails closed)".
- Its bounds in `rule_evidence`: a sample no earlier than one interval before the end, and the start-side slack.
- The text and bounds of H1 and H3-H6.
- The counting, the holds, the pauses and every threshold.
- A monitor that has stopped still voids the run.

## Why (orchestrator ledger C-156)

R2a ran on 2026-11-15, 18:47:51-19:49:29Z: the cheap_static_flood ladder at 5f3769c. It paused "host unfit" (exit 5).
- Of its 15 judged runs, 4 were set aside, **by H7 alone**. H1 and H3-H6 passed in all four.
- **The rule:** H7 asks each sampling monitor for a sample with t >= t_end - interval (mpstat 5 s, pidstat 10 s, chrony 30 s).
- **The records:** they stamp whole seconds, truncated.
- **The timing:** the judge read the records as soon as the after-probe pair ended.

**How the race happened:** a monitor's next sample was due in the second after t_end.
- The last written sample's stamp then fell 0.20-0.40 s short of the bound.
- The sample that met the bound was not in the file yet.
- In the three runs where this could be checked, that sample was in the record less than 1 s after t_end.
- The fourth run was the packet's last, and its monitors were stopped.
- The monitors were alive and punctual. mpstat wrote a sample every 5 s with no gap.

| set-aside run | t_end | record | last sample written | bound |
|---|---|---|---|---|
| 05_control1/C.hostinvalid1 | 19:06:33.398 | mpstat | 19:06:28 | 19:06:28.398 |
| 05_control1/C.hostinvalid2 | 19:14:48.246 | pidstat | 19:14:38 | 19:14:38.246 |
| 11_L0.125_r2/U.hostinvalid1 | 19:38:39.328 | mpstat | 19:38:34 | 19:38:34.328 |
| 12_L2_r1/U.hostinvalid1 | 19:49:29.201 | mpstat; chrony | 19:49:24; 19:48:59 | 19:49:24.201; 19:48:59.201 |

**Outcome-blind.** The decision was made from the host's records only (windows, sample times, the rules' reasons). It read no Q,
p95 or harm of any run, and nothing of R2a's ladder was read before it. H7 itself reads no outcome.

## What rests on it, and what does not

- **Made at 5f3769c and judged at the window's end:**
  - R1: 3 capacity runs, all host-valid.
  - R2a up to 19:49:29Z: 11 host-valid runs and the 4 set aside.

  They stay as they are, and no run is judged again. The four set-aside runs are kept and published with their reasons, and are
  never used (section 5.1). Their remakes, and the runs still to come, stand in their places.
- **Made at the commit that adds this file, and judged 2 s after the window's end:** every run from R2a's resume on. That is the
  rest of R2a, then R2b, R2c, R3 and R4, then P2-1 and P2-2 as far as they are host-judged.
- **The cost:** at most 2 s per run, between the end of the run's after-probe pair and its verdict. Nothing inside a window changes.
- **Known limit:** the fixed 2 s tolerates a sample due in the second after the end that is written between about 1 s and 2 s late.
  That covers every case above, where it was written less than 1 s after the end. It would not cover a longer stall of that one
  sample, and such a run would still be set aside by H7.
- **Reporting:** the thesis and the published campaign name this departure wherever they report host validity, or a step whose
  runs were judged on both sides of it.
