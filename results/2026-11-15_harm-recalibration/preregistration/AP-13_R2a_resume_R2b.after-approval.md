# AP-13: R2a's resume, then R2b, at the pin after D-108 (revision 1, 2026-11-15; approved by the user 21:07:21Z, "ok, I approve runs")

**Approved** (APPROVALS 2026-11-15T21:07:21Z; R2c not included).
- **Pinned commit:** `9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f`, integ/s6 after D-108. It is 5f3769c plus the merge of K22, plus the departure note
  `docs/RECALIBRATION_2026-11_DEPARTURE_1.md`.
- **Its gate:** PASSED 2026-11-15T21:32:10Z: the full suite on its tree c0bd4b4d048bf4ac8c8231a651a43e1034626044, 3562 tests, the known failure only (D-097; tasks/T-120/artifacts/gates/INTEG22_suite.txt).
- **Worktree:** `worktrees/run-recal`, moved to `9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f`, clean.
- **Session:** as R1 and R2a, `/var/tmp/ddos_campaigns/recal_2026-11`.

AP-12 approved R2a then R2b. R2a paused "host unfit" (C-156) and R2b did not start. This packet finishes what AP-12 approved, at
the new pin.

## What is new against AP-12
The pin, and with it D-108:
- After each run's window, the judge waits until 2 s after the window's end (at most 2 s) before it reads the monitors.
- Every run from here on is judged that way, and the reports say so.
- Nothing inside a run changes.
- R2a's 11 finished runs and its 4 set-aside runs stay as they are.

## What they do (prereg 5, design 6.2)

**R2a, resumed:**
1. A speed hold against R1's `origin/origin.json`: -10 % to +10 %, two pairs in a row, at most 30 min.
2. The cheap_static_flood ladder from its 11 finished runs: 7 runs are left. 12_L2_r1 is made again with its seed, then the
   ladder's runs 13-18.
- [ESTIMATE] 25-35 min: the hold, about 6 min, plus 7 runs of about 2.6 min each.

**R2b:** the ladder of costly_export_flood: 18 runs (14 attack runs at 7 levels, and 4 controls), after the same speed hold.
- [ESTIMATE] 50-65 min.
- It starts only if R2a ends `done (exit 0)`.

**Limits for each packet:**
- No run starts after 85 min. The packet then pauses (exit 4) and resumes in a later packet.
- The worst case is about 3 h each.
- Host rules H1-H7 are judged per run. A host-invalid run is set aside and made again (5.1).
- A packet pauses at the third host-invalid run in a row, or at the fourth in the packet.

## How (D-106's way, at the user's word)
`tasks/T-120/r_launch.sh AP-13 9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f R2a R2b`, started by the orchestrator in the background. It is `r2_launch.sh` with the
approval's id and the pin as arguments.
1. It waits 180 s so that the orchestrator's turn has ended.
2. For each packet it runs `sudo bench/packets/packet.sh <P> --commit 9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f` from `worktrees/run-recal`, and checks the stage's
   `/proc` entry once a minute.
3. The next packet starts only after a summary that begins `PACKET <P> done (exit 0):`.

The orchestrator is idle until the last stage ends.

**To stop:** run `sudo kill -TERM <the stage's pid>`. The pid is in the launcher's log, `tasks/T-120/r_launch_<UTC>.log`, and in
the packet's log. Send it again if the log shows the step still going a minute later.

**Before the launch** (done offline):
- `packet.sh R2a --commit 9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f --print` and `packet.sh R2b --commit 9c0c25a77299fd19d169c40c3fae4ca8d7a1d45f --print` in run-recal printed their plans,
  exit 0 (tasks/T-120/artifacts/R2a_print_9c0c25a.txt, R2b_print_9c0c25a.txt).
- The pre-checks run at the launch itself.

## During
- The Claude app stays open but idle: no message, no `/compact`, no session opened or resumed.
- Nothing heavy runs on the laptop, and it stays on mains power.

## Side effects
As AP-12's:
- The executor creates and tears down the testbed's root processes.
- The monitors run during the runs: a new `monitors/<n>` directory.
- Files are written under `/var/tmp/ddos_campaigns/recal_2026-11/`: `ladder_*/`, and `packets/` with logs, tars and sha256.

There are no package, kernel, timer, network or system setting changes. Nothing is pushed or sent anywhere.

## Outcomes (prereg 6, Appendix A)
- **`done (exit 0)`:** the ladder is complete.
- **`not frozen (exit 7)`:** the ladder stopped by its own rule. The step is NOT FROZEN, and nothing is made again.
- **`paused (exit 4)`:** it resumes in a later packet with the same command.
- **`host unfit (exit 5)` and `stopped` (exit 2, 1, 130, 143):** no reading. It resumes later, or the user decides.

After each packet, the orchestrator:
- backs up the tar and the log to `backup/recal_2026-11/`;
- reads the outputs offline;
- reports the step's own verdict.

Nothing is re-run to change an outcome.

**Option (the user's choice):** add R2c (costly_search_flood ladder, [ESTIMATE] 50-65 min more) to the same chain: `... R2a R2b R2c`.
It starts only if R2b ends `done (exit 0)`. Not part of AP-12.
