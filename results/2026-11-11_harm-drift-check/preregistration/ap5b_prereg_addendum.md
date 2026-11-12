# AP-5b: dated addendum to the AP-5 pre-registration (ap5_prereg.md, sha256 ded45fe9...)
Written 2026-11-10 ~16:20Z, after AP-5 was cut by host reset 6 (no reading, rule 5) and after seeing its q1 attempt 1 (C-107).
Before any AP-5b run. It changes nothing in the design or the reading except what follows.

1. **Out dirs:** `/var/tmp/ddos_campaigns/drift_20261110b_q1`, `_q2`, `_q3`; step labels `ap5b_drift_20261110b_qN`. AP-5's partial
   `drift_20261108_q1` stays untouched.
2. **A** = AP-4's 2 attempts + AP-5's one complete attempt (q1 attempt 1, created 2026-11-10T15:42:50Z) + every AP-5b attempt that runs.
   This follows the prereg's own "every attempt that ran counts, with no exceptions". AP-5 q1's second attempt never produced a result and does not count.
3. **Rule 5 applies to AP-5b's three invocations.** If the host resets or a step stops before each has made its first attempt, AP-5b gives no reading.
4. **Added hold, as already practised:** uptime >= 1800 s and no "Long readout interval" kernel message in the 30 min before the start (checked by hand); after the run the kernel log over the run's window is reported, and a pause > 1 s inside a run is named beside that run's result.
