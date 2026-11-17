# AP-11: packet R1 of the re-calibration (revision 4, 2026-11-15: commit pinned; needs the user's yes for a window)

**Ready, not approved.** What had to come first is done:
1. the user approved the pre-registration (revision 3, as recommended: P-1 a rule, P-2 option B, Appendix A as classified, H3 kept;
   D-104); it is committed as `docs/RECALIBRATION_2026-11_PREREG.md`, sha256 `5c22334dfb68f88ecb3a33161b91f9848ccdd2819b99e6419b5c715047bd269c`;
2. `integ/s6` = efa8f54 + thesis/build-fixes, docs/readme-requirements, feat/bench-vm-helpers, feat/recalibration-k (K1..K13,
   K14b..K18b, K19, K20b, K21B, each gated), feat/hs1-check, feat/paired-check, then the pre-registration: **pinned commit
   `5f3769cc8b8f1eaaadfd38fe79d1376ffb9fe3c5`** (tree a042ac11cec39d26298ceabe112ebe95b93e8bba; D-105). Its full gate passed on 2026-11-15T16:37:26Z: 3557 tests, the
   one known failure only (D-097; T-119).

**Nothing runs before the user names a window** of about 3 h with the laptop awake (R1 usually ends within 1.5 h; 3 h is its worst
case) **and says yes to this packet.**

## What R1 does (prereg 5.3; design 6.2)
1. **P-1, the paired check** (2-3 min): 8 probes of the origin's estimator on CPU 0, then CPU 1, in the order A B B A (A = HS1's context
   in the sandbox as uid 1000; B = the hold's context as root). Last line `P-1: GO ON` (exit 0): go on. `P-1: STOP` (exit 6, the
   contexts differ by more than 5 %; or exit 3, a probe unreadable): R1 does not start; tell the orchestrator.
2. **The packet** `bench/packets/packet.sh R1`: it refuses without a fresh GO ON check (K20b), runs the pre-checks,
   then detached: the speed hold against HS1's medians (about 5.5-45 min), the origin step (about 20 s), capacity (3 staged runs of 12 levels,
   about 15-20 min with P-2 option B). Budget: no run starts after 85 min; usually done within 90 min, at worst about 3 h (gate waits
   and holds, prereg 5.2). [ESTIMATE, design 6.2 + K21B] about 28-63 min in all.

## Before the window (the orchestrator, offline, no measurement): done 2026-11-15
* [FACT] A clean worktree of the pinned commit with the venv linked: `/home/artur/agent_workspace/worktrees/run-recal` at `5f3769cc8b8f1eaaadfd38fe79d1376ffb9fe3c5`,
  `venv -> /home/artur/DDoS-mitigation/code/venv` (ignored by `.gitignore`); `git status --short` empty.
* [FACT] The pre-registration's ten file hashes and its own sha256 match `git show 5f3769c:<path> | sha256sum`.
* [FACT] `bench/packets/packet.sh R1 --print --commit 5f3769cc8b8f1eaaadfd38fe79d1376ffb9fe3c5 --medians <MEDIANS> --paired <DIR>` exit 0; its plan is in
  `tasks/T-119/artifacts/R1_print_5f3769c.txt` (budget 85 min, worst case 180 min, the P-1 gate before the pre-checks, the three
  steps, the stop by `sudo kill -TERM`).
* [FACT] `/var/tmp/ddos_campaigns/recal_2026-11` does not exist yet (R1 starts a new session).
* In the window: every agent idle, no suite running, the suite lock free; the orchestrator's last message hands over the commands
  and ends its turn.

## The commands the user types (plain terminal: the VM's console or SSH; not the Claude app)
```
cd /home/artur/agent_workspace/worktrees/run-recal
P=/home/artur/agent_workspace/host/paired_$(date -u +%Y%m%dT%H%M%SZ)
bench/vm/paired_check.py run $P --medians /home/artur/agent_workspace/host/hs1_20261114T155933Z/medians.json
```
If the last line says `P-1: GO ON`, within 30 min:
```
sudo bench/packets/packet.sh R1 --commit 5f3769cc8b8f1eaaadfd38fe79d1376ffb9fe3c5 --medians /home/artur/agent_workspace/host/hs1_20261114T155933Z/medians.json --paired $P
```
It prints the stage's pid and its log, `/var/tmp/ddos_campaigns/recal_2026-11/packets/R1_<UTC>.log`. Optional, to watch: `tail -f` of
that log. **To stop: `sudo kill -TERM <the printed pid>`**: the step is stopped, the testbed taken down, the tar and summary written. If
the log shows the step going on a minute later (the TERM arrived during a run's sub-second teardown), send it again. To resume after more than
30 min: a new paired check in a new directory (`P=...` again, then the check), then the same packet command with the new `$P`.

## During
The Claude app may stay open but idle: no message, no `/compact`, no session opened or resumed. Nobody else logs into the VM. Nothing
heavy on the laptop; mains power on.

## Side effects
* Root processes: the hold's and the origin's probes, the testbed (network namespaces, Nginx, gunicorn, the engines) created and torn
  down by the executor; the monitors (mpstat, pidstat, a chrony sampler at `chrt --fifo 1`, a journal follower) on the executor's CPU
  during the capacity runs.
* Files: `/var/tmp/ddos_campaigns/recal_2026-11/` (root-owned: `speed_reference.json`, `host.json`, `origin/`, `capacity/`, `monitors/`,
  `packets/` with the log, a tar and its sha256); `/home/artur/agent_workspace/host/paired_<UTC>/` (`probes.jsonl`, `paired.json`).
* No package, kernel, timer, network or system setting changes. Nothing is pushed or sent anywhere.

## Outcomes and what follows (the summary is the log's last line)
| Ends with | Meaning (prereg 6, Appendix A) | Next |
|---|---|---|
| P-1 STOP (exit 6 or 3) | R1 not started; published | the user decides (NO READING if no way on) |
| the packet command itself exits 2 (P-1 gate) or 3 (a pre-check) | nothing started; no log, no summary; the terminal says why | fix the cause (e.g. a new paired check), then the same command |
| `done (exit 0)` | origin and capacity complete | R2a in the same window if 1-1.5 h remain, else the next window |
| `not frozen (exit 7)` | a step stopped by its own rule (origin unstable twice; capacity's first level below 99 %, above the range, or not saturated) | **NOT FROZEN**; nothing is made again |
| `paused (exit 4)` | the budget is used; finished runs kept | the same command resumes R1 in a later packet |
| `host unfit (exit 5)` | the hold did not hold within 45 min; 3 host-invalid runs in a row or 4 in the packet; or the 30-min hold after a host-invalid run did not hold | published; a later window resumes |
| `stopped (exit 2, 1, 130 or 143)`, `stopped by TERM` | a refusal (timer, uptime/load, PC), a run unsound twice, a defect, or a stop by hand: **no reading** | the log's last error line says which; resume later, or the user decides |

After the packet the orchestrator copies the tar and the paired-check directory beside the ledger (`backup/recal_2026-11/`, sha256
checked; `/var/tmp` purges files after 30 days), reads the outputs offline, writes RUNS.md (AP-11) and reports the step's own verdict.
Nothing is re-run to change an outcome.
