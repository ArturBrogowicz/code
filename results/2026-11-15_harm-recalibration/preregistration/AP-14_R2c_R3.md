# AP-14: R2c, then R3, at the pin 9c0c25a (revision 2, 2026-11-16T08:00:38Z; approved by the user 2026-11-16T08:02:08Z, "Yes, launch AP-14")

**Approved** (APPROVALS 2026-11-16T08:02:08Z). Checked against AP-13's outcome: R2a and R2b both ended `done (exit 0)` with 0 host-invalid runs, and
both ladders read session valid with a knee (RES-07, RES-08). Revision 1 is kept as `AP-14_R2c_R3.rev1.md`.
- **Pinned commit:** 9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f (D-109). Its gate passed: 3562 tests, the known failure only.
- **Worktree:** `worktrees/run-recal`, at the pin and clean (checked at the launch by the pre-checks).
- **Session:** `/var/tmp/ddos_campaigns/recal_2026-11`.
- **Printed plans:** `packet.sh R2c|R3 --commit <pin> --print` exit 0 (tasks/T-120/artifacts/R2c_print_9c0c25a.txt,
  R3_print_9c0c25a.txt).

## What they do (prereg 4-5, design 6.2)

**R2c:** the ladder of costly_search_flood, the last of the three.
1. A speed hold against R1's origin.json: -10 % to +10 %, two pairs in a row, at most 30 min.
2. 18 runs: 14 attack runs at 7 levels, and 4 controls.
- [ESTIMATE] 50-65 min. R2b, the same size of ladder, took 53 min overnight (its hold 6 min, 18 runs).

**R3:** the reference, made after the three ladders in one session.
1. The same speed hold.
2. 5 rounds. Each round is a 120-s legit probe at rho, then one attack run per family at its knee.
- [ESTIMATE, design 6.2's table] 62-69 min.
- The sample is the first 5 valid rounds, in the order made: no round is added, dropped or replaced because of its values
  (design, prereg 4).
- It starts only if R2c ends `done (exit 0)`.

**Limits for each packet:**
- No run starts after 85 min. The packet then pauses (exit 4) and resumes later.
- The worst case is about 3 h each.
- Host rules H1-H7 are judged per run, with D-108's 2-s wait.

## Timing
- **The pre-check:** it refuses a packet with an apt, dpkg or daily timer due within 190 min.
- **dpkg-db-backup.timer** runs daily at 00:00Z. So a packet cannot start from about 20:50Z to 00:00Z.
- **The weekly fstrim** is next due 2026-11-23T00:50:47Z (systemd), outside any window before then.
- **The best start** is any time from about 00:10Z to 17:30Z, with the laptop awake and on mains power. R3's own pre-check
  runs when R3 starts: it must start before about 20:50Z, and R2c can take up to about 3 h at worst. Together [ESTIMATE]
  about 2 h 5 min to 2 h 20 min (3 min wait, then 50-65 + 62-69 min).
- If R2c ends `done` and R3 is refused or paused, R3 resumes later with the same command: R2c's runs stand.
- [FACT, systemctl list-timers at 08:00Z on 11-16] Due today and not in the pre-check's list: sysstat-collect every 10 min (as in
  every run so far), motd-news 10:26Z, update-notifier-download 14:42Z, systemd-tmpfiles-clean 14:52Z. They are light; H6
  voids any run that one of them actually loads, by its numbers. Nothing is changed for them.

## How
`tasks/T-120/r_launch.sh AP-14 9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f R2c R3`, started by the orchestrator in the background.
1. It waits 180 s, then runs each packet.
2. The next packet starts only after `PACKET <P> done (exit 0):`.

The orchestrator is idle until the last stage ends.

**To stop:** run `sudo kill -TERM <the stage's pid>`. The pid is in the launcher's log. Send it again if the log shows the step still
going a minute later.

## During, side effects, outcomes
As AP-13. In addition, R3 writes `reference/` in the session.

**After R3, the freeze:** offline, under the prereg's rules. It is not part of this packet.

**R4** is the confirmation of 3 rounds. It comes in a later window, after a reboot (design D4), and needs its own packet (AP-15).
