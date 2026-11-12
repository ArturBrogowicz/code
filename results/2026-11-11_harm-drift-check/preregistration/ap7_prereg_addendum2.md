# AP-7: second dated addendum to the AP-5 pre-registration (ap5_prereg.md, sha256 ded45fe9...; first addendum ap5b_prereg_addendum.md, sha256 bc424344...)
Written 2026-11-11 13:15Z by the execution-phase orchestrator, after AP-5b was cut by host reset 7 (2026-11-10, at or after 16:59:30Z; no
reading under the first addendum's rule 3, C-108, C-110), and before any AP-7 run. It replaces a first draft of 12:45Z (sha256 9baf44d6...,
kept as ap7_prereg_addendum2_v1_superseded.md, never used), which was written before the orchestrator had seen any Q value of AP-5b's runs
(D-085); points 1, 2, 3, 5 and 7 are unchanged from that draft, and points 4 and 6 take in what T-085, T-088 and T-092 found since
(a second draft, sha256 855d2166..., kept as ap7_prereg_addendum2_v2_superseded.md, lacked the time-sync hold; never used).
It changes nothing in the design or the reading except what follows.

1. **Out dirs:** `/var/tmp/ddos_campaigns/drift_20261111c_q1`, `_q2`, `_q3`; step labels `ap7_drift_20261111c_qN`. The label is an identifier:
   it stays the same if the run happens on a later day. Every earlier directory stays untouched.
2. **A** = AP-4's 2 attempts + AP-5's one complete attempt (q1 attempt 1) + every AP-7 attempt that writes a drift.json.
   AP-5b's q1 attempt wrote no drift.json and does not count, exactly as AP-5 q1's cut second attempt does not (first addendum, point 2).
   AP-5b's individual sound runs are reported as descriptive only, beside the reading and never inside it.
3. **Rule 5 applies to AP-7's three invocations.** If the host resets or a step stops before each has made its first attempt, AP-7 gives
   no reading.
4. **Holds before the start, checked by the script:** uptime >= 1800 s; no "Long readout interval" kernel line and no chronyd "Forward time
   jump" line in the 30 min before; no apt, dpkg, apt-daily, apt-daily-upgrade or fwupd-refresh job active; **time sync sane** (chrony's
   system-time offset under 0.1 s and leap status Normal). The last hold is new on 2026-11-11: the guest was suspended for 3 h 50 min
   that day without any kernel or chronyd line (C-122), and while chrony slews such an offset away the guest's clocks run up to 8.3 %
   fast, which no run can see. A 30 s record of chrony's tracking is kept beside the run; an attempt during which that record shows an
   offset of 0.1 s or more is named beside its result (it still counts, as every attempt does). By hand: every agent idle, and no apt-daily,
   apt-daily-upgrade, fwupd-refresh, logrotate, man-db or tmpfiles-clean timer due within 90 min. These holds are start conditions and are
   known to be weak: the kernel prints its line only for a pause longer than twice the boot's longest so far (C-114), so a shorter pause can
   go unseen. **Pause evidence inside a run** is therefore the gaps between the 5 s mpstat samples (resolution about 2 s) and chronyd's
   lines; a gap above 6 s inside a run's window, or a time-jump line, is named beside that run's result. The first addendum's "a pause
   > 1 s" is read at that resolution. Nothing here excludes an attempt: every attempt that writes a drift.json counts.
5. **Guest RAM (C-109, corrected by T-085):** the record and AP-4 were measured with 10 GiB (MemTotal 9426 MiB), AP-5 and AP-5b with 8 GiB
   (7422 MiB, from the boot of 2026-11-10T08:39:24Z). AP-7 runs with what the guest has at its start; the script prints MemTotal, and each
   run's environment.json records it. The reading does not change: every attempt in A counts. The attempts split by RAM size are reported
   as descriptive, beside the reading.
6. **Known limits of this check, stated before the run (C-111, C-118):** each attack reference is one run; the drift check uses other seeds
   than the reference and, through them, other links for the attack sources (cheap: 20 % of the flood over the two judged profiles in the
   reference, 80 % in the drift check); the reference's search p95 is an outlier. A reading of "stands" therefore means the means over A
   are inside the gate's floors, not that single runs reproduce the reference. None of this changes the rule.
7. **Launch and stop rule:** detached (`setsid nohup`), in the same session scope as AP-4 and AP-5, so that a dropped app session does not
   end it; a host reset still ends it, and then rule 5 decides. AP-7 is the third try at this measurement (AP-5, AP-5b, AP-7). If it gives
   no reading either, nothing more is run under this pre-registration without a new decision by the user: the host's stability is then
   the blocker, not the record.
