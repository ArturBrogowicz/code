# AP-12: packets R2a and R2b of the re-calibration (revision 1, 2026-11-15; needs the user's yes)

**Ready, not approved.** Same pinned commit, worktree and session as R1 (AP-11, done: RES-06). The design's window plan puts R1, R2a
and R2b in window 1.

## What they do (prereg 5, design 6.2)
* **R2a**: the ladder of `cheap_static_flood`: 18 runs (14 attack runs at 7 levels, 4 controls), after a speed hold against R1's own
  costs (`origin/origin.json`, -10 % to +10 %, at most 30 min). [ESTIMATE, design 6.2] 50-65 min.
* **R2b**: the same for `costly_export_flood`. [ESTIMATE] 50-65 min. It starts only if R2a ends `done (exit 0)`.
* Each packet: no run starts after 85 min (it then pauses, exit 4, and resumes in a later packet); worst case about 3 h each (gate
  waits and holds, prereg 5.2). Per-run host rules H1-H7; host-invalid runs set aside and made again (5.1).

## How (D-106's way, at the user's word)
`tasks/T-119/r2_launch.sh R2a R2b` (or `R2a` alone), started by the orchestrator in the background: a 180-s wait so that its turn has
ended, then for each packet `sudo bench/packets/packet.sh <P> --commit 5f3769cc8b8f1eaaadfd38fe79d1376ffb9fe3c5` from
`/home/artur/agent_workspace/worktrees/run-recal`, waiting on the stage's `/proc` entry once a minute. The next packet starts only
after a summary that begins `PACKET <P> done (exit 0):` (a TERM note, a pause, a stop or exit 7 ends the chain). The orchestrator is
idle until the last stage ends.

**To stop:** `sudo kill -TERM <the stage's pid>` (in the launcher's log `tasks/T-119/r2_launch_<UTC>.log` and in the packet's log);
send it again if the log shows the step going on a minute later.

## During
The Claude app open but idle: no message, no `/compact`, no session opened or resumed. Nothing heavy on the laptop; mains power on.

## Side effects
As R1's: root processes of the testbed created and torn down by the executor, the monitors during the runs; files under
`/var/tmp/ddos_campaigns/recal_2026-11/` (`ladders/`, `packets/` with logs, tars and sha256). No package, kernel, timer, network or
system setting changes. Nothing is pushed or sent anywhere.

## Outcomes (prereg 6, Appendix A)
`done (exit 0)`: the ladder is complete. `not frozen (exit 7)`: the ladder stopped by its own rule (for example an invalid session
twice): NOT FROZEN, nothing is made again. `paused (exit 4)`: resumes in a later packet with the same command. `host unfit (exit 5)`,
`stopped (exit 2, 1, 130, 143)`: no reading; resumes later or the user decides. After each, the orchestrator backs up the tar and the
log (`backup/recal_2026-11/`), reads the outputs offline and reports the step's own verdict. Nothing is re-run to change an outcome.
