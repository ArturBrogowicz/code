# AP-5 pre-registration: the quiet repeatability check of the 2026-11-04 record on kernel 7.0.0-42 (D-081)
Written 2026-11-08, after AP-4 (which failed, exit 3) and before any AP-5 run. This is a post hoc rule, made after seeing AP-4's
failure, and it is labelled so wherever it is cited. AP-4's failure stays reported as it is (C-103).

## Design
- **Code:** worktrees/ap4-drift at 1cdda9b (as AP-4). **Command:** `bench/calibrate.py drift`, all three families, `--wait-gate 30`.
- **Repeats:** three invocations back to back, out dirs `/var/tmp/ddos_campaigns/drift_20261108_q1`, `_q2`, `_q3`. Each makes one attempt and,
  only if that attempt fails, the tool's built-in second attempt (`.second`). Every attempt that ran counts, with no exceptions.
- **Quiet:** no worker, reviewer or other agent active; no unittest; the orchestrator idle except to start the script. CPU use per CPU
  (`mpstat -P ALL 5`) and per process (`pidstat -u 10`) are recorded beside the step, so contention on the server's CPUs 0-1 is measured.
- **Seeds:** the tool's own (41 legit, 42-44 attacks), as in AP-4; the spread measured is the host's, not the seeds'.

## Reading (fixed now)
Let A be every attempt of AP-4 (2) and AP-5 (3 to 6). An unsound run that the tool re-ran counts only by its sound re-run, as the tool reads it.
1. **The record stands on 7.0.0-42** if all of these hold:
   - for each family, the mean Q over A is within the record's floor_pp (10 pp) of its reference Q;
   - for each family, the mean of log2(p95 / reference p95) over A is within floor_log2_p95 (1.0);
   - the legit probe's mean Q over A is within 2 pp of the reference, and its mean p95 is within 25 %.
2. **Otherwise the record does not stand.** Re-calibrating on -42 is then the next proposal, as its own packet.
3. **Always reported**, whichever way 1 goes:
   - per family: n, mean, SD, min and max of Q, and the same over AP-5's attempts alone;
   - each attempt's single-run result under the D-062 rule;
   - the CPU use of CPUs 0-1 by non-testbed processes during each run.
4. **The spread:** if any family's SD of Q over A exceeds 5 pp (half the floor), R-025 is confirmed. The knee ladders (2 repeats) and HG3 at the knee
   then need a variance statement before any verdict. That is a further decision, not part of this rule.
5. **No reading:** if a step stops (exit 2, EnvironmentRefused or another stop) before every invocation has made at least its first attempt, AP-5
   gives no reading. Nothing is re-run today.
