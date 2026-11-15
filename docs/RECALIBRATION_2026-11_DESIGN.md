# Re-calibrating the harm benchmark on the present host (2026-11): design and pre-registration draft

**Status (2026-11-13): a draft for your approval. Nothing in it has run, and it changes no code and no frozen file.** Written on
`design/recalibration-2026-11` at GitHub main `efa8f54`. The record of 2026-11-04 (`bench/calibration/ddos-mitigation-2026-11-04.json`,
record hash `cff6e515...`) stays frozen and published; nothing is re-run to give it a better outcome, and its five failed drift
attempts stay failures by the rule they were judged under. This note plans a **new** record measured on the host as it is now
(kernel 7.0.0-42, 8 GiB), a reference and a drift check that a noisy host can be judged by, a validity check of the host beside
every run, and the packets that fit the 3-4 hour windows you can arrange in the next 1-3 weeks. "design N" is a section of
`docs/BENCHMARK_HARM_DESIGN.md`; "HG1c N" and "departure N" are sections and departures of `docs/HG1C_DESIGN.md`; "the drift README" is
`results/2026-11-11_harm-drift-check/README.md`; "the prereg of 2026-11-08" is that directory's `preregistration/ap5_prereg.md`
(sha256 `ded45fe9...`) with its two dated addenda; C-, R-, D-, T- and AP- ids are the orchestrator's ledger. Tags: **[FACT]** read
from a file, a log or the code (`path:line` at `efa8f54`), or computed from them by a command named in section 10; **[ARITHMETIC]**;
**[ESTIMATE]**; **[INFERENCE]**; **[CLAIMED]** from the ledger, not re-checked here; **[PROPOSAL]** a value or rule fixed here, to be
frozen before the data it judges; **[RISK]**.

## 1. What I ask you to decide

| # | Decision | Recommendation | What the alternative costs |
|---|---|---|---|
| D1 | The reference and the check (section 4): **n = 5 reference rounds and m = 3 confirmation rounds, both on the drift check's own seeds**; per family, the mean Q within `T_Q = min(10, max(5, 3 s sqrt(1/5 + 1/3)))` pp and the mean log2 p95 within `T_L = min(1.0, max(0.5, ...))` of the reference means, `s` the SD of the 5 reference runs; the legit probe's means within 2 pp and 25 %; read per family | approve as written | n = 8, m = 4 lowers a false fail at a spread of 4 pp from 2.3 % to 1.2 % a family for about 40 min more VM time; today's single-run rule would fail about one attempt in five even at the calibration days' spreads (finding 1) |
| D2 | The host is held fixed for the whole programme: guest RAM 8 GiB (MemTotal 7,422 MiB), kernel 7.0.0-42 kept (no upgrade; unattended upgrades and the daily apt timers off for it), and on the PC sleep and hibernation off and no heavy work during a window. These are changes you make (root, host) | yes | Without it the new record can be measured on a host that changes under it, which is how the old one was lost; K5 (section 7) refuses every step after a change, so a change costs the record |
| D3 | The session-quiet protocol (5.3): you start every packet from a plain terminal and **close the Claude app** while it runs | yes | App open but idle: one `/compact` spoiled an AP-7 attempt (C-129); the non-testbed CPU rule would then void runs, at the cost of VM time |
| D4 | The confirmation runs in a **later window, after a reboot**, not right after the freeze | yes | Right after the freeze saves one 30-min uptime hold, but tests only that the host repeats itself within one session; the old record failed across days |
| D5 | In P2's campaigns, a run that fails the host check (5.1) is made again in place as a run cut by a reset is: no re-run used, the failed run kept and published | yes; the check reads nothing of the outcome | It counts as the block's invalid attempt and uses one of the gate's two re-runs; a host with slow stretches then ends the MVP INVALID, and the record would be applied to runs made outside the conditions it was measured under |
| D6 | A family whose 5 reference runs have an SD of Q above 5 pp (half the floor, the line of rule 4 of the prereg of 2026-11-08): frozen with the spread on record and labelled in every verdict at its knee | freeze and label | Leave that family without a reference: no campaign of it may run at all |
| D7 | The code of section 7 (K1-K8) is built and reviewed on a T2 branch before any run, and section 8 is committed with its hash before R1 | yes | Running on today's code: the multi-run reference has no place in the record's schema, and host validity can only be judged after each packet, so the runs it voids are re-made a packet later |
| D8 | The hard date for the text | tell me | **1 week (2026-11-19): the re-calibration at most, no confirmation and no P2. 2 weeks (2026-11-26): everything, if the host holds through four windows. 3 weeks (2026-12-03): everything with a window to spare** (6.3) |

**What I found while planning, in short.**
1. [FACT] At each knee the three runs of 2026-11-03/04 (two ladder repeats and the reference run, on other seeds) have an SD of Q of 3.17 pp (cheap), 2.37 (export) and 4.14 (search), ranges 6.30, 4.54 and 7.77 pp, and an SD of log2 p95 of 0.114, 0.080 and 0.447; the five complete drift attempts since 2026-11-08 give SDs of Q of 36.7, 13.0 and 8.0 pp (8.4, 14.5 and 4.8 without the disturbed attempt, an exclusion the old rule does not allow; descriptive only). [INFERENCE, normal errors, those SDs taken as true] One run against one run differs with 1.4 times the spread, so even at the calibration days' spreads the single-run rule fails about one attempt in five (search alone: 9 % on Q, 11 % on p95), and at the drift days' most attempts.
2. [FACT] With the guest idle, the speed series of 2026-11-11 puts the mean deviation of the CPU-bound routes C3 and C5 (both CPUs) at -2.0 to +10.8 % of the 2026-11-04 costs at the 8 sample times where both probes passed, and at +18.0 to +38.2 % at the 9 where both were refused. [INFERENCE] So the present kernel's normal state is a few per cent slower than the record, and a slow stretch a further 15-30 %; a band of 10 % around costs measured in the normal state separates the two on this evidence (5.1).
3. [FACT] Nothing compares the record's kernel and memory with the running host (`bench/calibration.py:44` checks the shape of `host` only; T-092 finding 8 [CLAIMED]); the origin's 25 % start-up check (`bench/origin.py:54`, `347-358`) is the only guard and runs before the run, not beside it.
4. [FACT] Rule 2 of the prereg of 2026-11-08 ("Otherwise the record does not stand. Re-calibrating on -42 is then the next proposal, as its own packet") follows a rule 1 that never gave a reading: AP-5, AP-5b and AP-7 each ended under rule 5, and the second addendum's point 7 requires a new decision by you. This re-calibration is labelled accordingly (8.1): the consequence rule 2 names, taken by your decision of 2026-11-12, not a reading of rule 1.
5. [ARITHMETIC] The re-calibration alone takes 4.0-5.4 h of packets, against SCHEDULE 4's "3-4 VM h", because the reference grows from 6 runs to 20 and every run gains a speed bracket; with its confirmation (12 runs, not 4) and P2's smoke and MVP the path is 6.7-8.9 h, about four windows of 3-4 h (6.3).

## 1a. The user's decisions of 2026-11-13 (recorded verbatim in the orchestrator's ledger, APPROVALS.md)

| # | Answer | Effect on this design |
|---|---|---|
| D1, D4, D6, D7 | "Approve as written (Recommended)" | Sections 4, 6 and 7 stand: n = 5, m = 3, the tolerances of section 4, the confirmation in a later window after a reboot, a wide-spread family frozen and labelled, K1-K8 built and reviewed before any run, section 8 committed with its hash before R1. |
| D2, D3 | "Not the app closing" | D2 holds (8 GiB, kernel 7.0.0-42, the PC's sleep and hibernation off, nothing heavy on the PC during a window). D3 takes its alternative: **the Claude app stays open but idle** during a packet (5.3 below, as amended). |
| D5 | "Accept (Recommended)" | In P2's campaigns a host-invalid run is made again in place and uses none of the gate's two re-runs. This is a dated amendment to P2's pre-registered rules (HG4), made on 2026-11-13 before any P2 data exist; the failed run is kept and published. |
| D8 | "2026-12-03" | The hard date for the text: the whole path (re-calibration, confirmation, P2's smoke and MVP) is planned, with one window to spare (6.3). |

## 2. Why the record is measured again

* [FACT] The record was made on kernel 7.0.0-38 with 9,426 MiB (its `host` block); the host now runs 7.0.0-42 with 7,422 MiB (the drift
  README's table; each run's `environment.json`). Route costs, capacity and knees are properties of that host, and every later run is
  judged against them: `rho = 0.5 C_slo` (`bench/calibration.py` `rho_rps`), an attack level is a multiple of the spare capacity
  `S = (C_slo - rho) x mean cost` (`bench/population.py:261-264`), and the origin refuses to start more than 25 % off the costs.
* [FACT] No drift check passed in four tries: 5 of 5 complete attempts fall outside the single-run rule (departure 33), in both
  directions; three tries gave no reading (two host resets; a host too slow for the origin to start) (the drift README).
* [FACT] The record's drift reference is one attack run per family on seeds 34-36 (`bench/calibrate.py:61`, `512-537`: legit probes
  31-33, attacks `31 + 3 + i`), while the check runs seeds 41-44, whose populations place the attack sources on other links (C-111;
  second addendum, point 6). Its search p95 (0.631 s) lies above both ladder repeats at the knee (0.343, 0.419 s).
* [INFERENCE] Whether the kernel, the memory, the host's instability or the spread of single runs made the attempts fail cannot be
  told from them (the drift README). A new record measured on this host, with a reference whose spread is measured, removes the first
  two and the last as explanations for anything that follows; the third is handled by the host check of section 5.

## 3. What is measured again, what is kept, what changes

| Part | 2026-11-04 | Now | Why |
|---|---|---|---|
| Route costs (step 1) | measured, -38 | **measured again**, same procedure (3 sessions x 21 batches on CPU 0, median of medians, 10 % rule; estimator version 2) | the reference of the origin's start-up check and of every speed check; normal state on -42 is a few per cent off (finding 2) |
| Capacity, `rho` (step 2) | `C_slo` 84.5, `C_sat` 241.3 req/s | **measured again**, same levels `50 x 1.3^k`, 20 s steps, 3 repeats, same rules | everything downstream scales with it |
| Knees (steps 3-4) | cheap 2, export 4, search 4 | **measured again**, same ladders (`S x {1/8 .. 8}`, 2 repeats, a control after every 4th run, seeded order), same knee rule (harm >= 1 in both repeats) | levels are in units of `S`, which moves with costs and capacity |
| Drift reference (step 5) | 3 legit probes (median) + 1 attack run per family, seeds 31-36 | **5 rounds on the drift seeds 41-44**, every run kept; per family the mean and SD of Q and of log2 p95, and the tolerances, frozen in the record | section 4 |
| Drift check (step 7) | one attempt (legit + one attack run per family), single-run rule (departure 33), a second attempt on failure | **3 rounds, means against the reference means**, tolerance from the reference's own spread; no second attempt; read per family | section 4 |
| Host validity | executor soundness; timer gate before each run; origin 25 % check at start-up | **plus** a speed bracket (before and after every run), clock, pause and non-testbed CPU, judged per run; the record's kernel and memory compared with the host | section 5 |
| Kept unchanged | | the scenarios and their hashes; the template's knobs, mix, SLOs, judged profiles (A1), gate constants (floor 10 pp, 1.0 in log2 p95, 10 blocks, 80 % same sign, 95 % CI, control 99 %, 2 re-runs) and validity block; the campaign seeds (blocks 1-10, namespace `calib`); the calibration seeds 11 (capacity) and 21 (ladders); the pin plans (`PIN_PLAN` for the calibration, `PIN_PLAN_DAEMON` for HG4); the environment gate (uptime 1,800 s, load below 0.3) and the timer gate (10 ms on CPU 7, re-probe every 30 s, departure 30); the executor's settings; P2's outcome rule (`eval/harm_gate.py:625` `P2_OUTCOME`, H2's 9 of 10, the time to mitigate reported only, "judge up to first ban"); HG4's level rule (cheap at twice its knee, departure 39) | these are the experiment; changing them is not re-measuring the host |

[FACT] The seeds 31-36 of today's reference are not used any more; the new record is a new file (`bench/calibration/ddos-mitigation-<date
of the freeze>.json`, schema 2, section 7 K1), and the old file is never edited. [INFERENCE] The record's `host.origin_sha256` will differ
from the old one's if K3 changes `bench/origin.py`; that is what the field is for.

## 4. The reference and the drift check on means [PROPOSAL]

**A round** is what one drift attempt is today: a 120 s legit probe at `rho` (seed 41, Q and p95 over 10-120 s), then one attack run per
family at its knee in sorted order (cheap 42, export 43, search 44; timeline 30 + 45 + 30 s; Q and p95 over the 45 s of attack), all on
`PIN_PLAN`. The seeds are the drift check's own, so a reference run and a check run of a family send the same schedule from the same
sources over the same links, and **what their spread measures is the host's, not the seeds'** (the prereg of 2026-11-08 says the same of
its repeats).

**The reference (R3).** `n = 5` rounds made after the three ladders, in one session. Per family `f`: the 5 values of Q and of `log2 p95`,
their means `Qbar_f`, `Lbar_f`, and sample SDs `s_f`, `t_f` (n - 1 in the denominator). The legit probe likewise. Every run of the 5 rounds
is in these figures: the sample is the first 5 **valid** rounds (5.1) in the order made, no more and no fewer.

**The tolerances, computed at the freeze and written into the record** (so a later check reads them and does not recompute them):

    k   = 3 * sqrt(1/n + 1/m) = 3 * sqrt(1/5 + 1/3) = 2.19089
    T_Q,f = min(floor_pp,        max(floor_pp / 2,        k * s_f))   = min(10, max(5,   2.19089 s_f))   percentage points
    T_L,f = min(floor_log2_p95,  max(floor_log2_p95 / 2,  k * t_f))   = min(1.0, max(0.5, 2.19089 t_f))  in log2 (1.0 = a factor of 2)

`floor_pp` and `floor_log2_p95` are the record's gate floors (10 and 1.0), read from it as departure 33 does.

**The check (R4, and before every later campaign of a family).** `m = 3` rounds. A family `f` **passes** when
`|mean of its 3 Q - Qbar_f| <= T_Q,f` and `|mean of its 3 log2 p95 - Lbar_f| <= T_L,f`. The legit probe passes when
`|mean of its 3 Q - the reference's mean Q| <= 2 pp` and `0.75 <= 2^(mean of its 3 log2 p95 - the reference's mean log2 p95) <= 1.25`
(design 7.2 step 7's 2 pp and 25 %, unchanged, on means). The record is **confirmed for family f** when the legit probe and `f` pass.
Each inequality includes its bound. A run without a served request has no p95 and fails its family, as `drift_attack_ok` does now.
There is no second attempt.

**Why these numbers.**
* [PROPOSAL] `m = 3` is what a 3-4 h window can afford beside a campaign (about 40 min, 6.2); `n = 5` makes the SD a statement with 4
  degrees of freedom for about 65 min of VM time. The `3` in `k` is a three-standard-error band on the difference of two means.
* [PROPOSAL] The cap is the gate's floor: a shift as large as the floor can turn a verdict at the knee, so no spread may excuse it. The
  lower bound is half the floor, the line of rule 4 of the prereg of 2026-11-08: below it the check would fail on the sampling error of
  `s` itself (an SD from 5 runs comes out below a third of the true one about one time in fifty).
* [FACT, offline simulation, normal errors; `tolerance_sim.py`, section 10] With n = 5 and m = 3 a family with no change fails with
  probability 1.0 % at a true spread of 3 pp, 2.3 % at 4 pp, 3.4 % at 5 pp and 10.2 % at 8 pp; a true shift of 10 pp is caught with
  probability 0.90, 0.73, 0.62 and 0.52, one of 15 pp 1.00, 0.98, 0.94 and 0.82. For log2 p95 at a spread of 0.30 (0.45): 1.0 % (2.9 %)
  false fails, a doubling caught 0.89 (0.66). n = 6 or m = 4 change these by at most 0.05; n = 8 with m = 4 lowers the false fail at
  4 pp to 1.2 %.
* [ARITHMETIC, an illustration only] The calibration days' three runs at each knee would give `T_Q` 6.95 (cheap), 5.19 (export) and
  9.07 pp (search), and `T_L` 0.50, 0.50 and 0.98; the drift days' spreads (4.8-14.5 pp without the disturbed attempt) give 10 pp for each family, with a
  false fail of about 3 % (search) and 10 % or more (cheap, export) a family. On such a host the check fails often, and should.

**What it does not do.** [INFERENCE] `s` is the spread within one session; a shift from one day to the next adds to the difference and
not to `s`, so a day-to-day component larger than the band fails the confirmation. That is intended: the campaigns span windows too. Same
seeds measure the host's noise only; the seed-to-seed spread is the gate's blocks' business. The reference is at the knee; HG4's cheap flood
runs at twice it (departure 39), where no reference exists (T-092 section 5).

## 5. Host validity per run, and the session-quiet protocol

### 5.1 What makes a run invalid [PROPOSAL]

None of these reads a Q, a p95 or a harm: they read the host's records only, so they can be fixed before the data and applied by a tool.

| # | Rule | Threshold | Evidence it rests on |
|---|---|---|---|
| H1 | **Speed bracket.** Before the stack starts and after the teardown, the origin's estimator (`time_routes`, 21 repeats, thread CPU time) on CPU 0 and on CPU 1 with the record's knobs; `d` = the mean over the two CPUs of the mean of C3's and C5's deviations from the reference costs (in the calibration session: R1's costs; afterwards: the record's) | `|d_before| <= 10 %` and `|d_after| <= 10 %` | [FACT] speed series of 2026-11-11: normal -2.0..+10.8 %, slow +18.0..+38.2 % against the 2026-11-04 costs (finding 2). [ARITHMETIC] Against a reference in the middle of the normal band (about +4 %), normal lies within about +-7 % and slow begins near +13 %. [INFERENCE] The slow stretches lasted 6 to 51 min (C-135), so a run of about 2 min inside one has at least one end of its bracket inside it, unless a stretch shorter than the run exists unseen between the series' 5-min samples |
| H2 | Timer gate | as now: p99 below 10 ms on CPU 7 before every run, re-probed every 30 s up to `--wait-gate` | departure 30; a refusal stops, it does not void |
| H3 | Pause in the generators | pooled legit slip p99 at most 100 ms (`validity.slip_pooled_s`, the gate's rule, `eval/harm_gate.py:392-393`); not for the staged capacity runs (amendment of 2026-11-14 below) | [FACT] calibration runs are judged today by the executor's soundness only (`bench/calibrate.py:755-786`); the gate's slip rule never sees them |
| H4 | Clock | every 30-s chrony sample overlapping the run: `|System time| < 0.1 s` and no selected source more than 1 s off; no chronyd "Forward time jump" or "Can't synchronise" line and no kernel "Long readout interval" line in the run's window | second addendum, point 4; R-030 (a slewing clock runs up to 8.3 % fast and no run can see it) |
| H5 | Pause of the guest | no gap above 6 s between consecutive 5-s `mpstat` samples in the run's window | second addendum, point 4 (its resolution) |
| H6 | Non-testbed CPU | the processes that are not the testbed's (`pidstat -u -l 10`; the testbed is Nginx, gunicorn, the engines, the executor, the calibrator, the probes, `ip`, `tc`, `taskset`, `sudo`, the monitors and kernel threads) use **at most 5 % of one CPU on average** over the run's window and **at most 50 % in any 10-s sample** | R-031's 5 % line; [CLAIMED] AP-5's quiet runs had under 0.2 % on CPUs 0-1 (R-025); AP-7's compaction put the app's server and sshd at 40-60 % of a CPU in 15-s bursts (C-129) |
| H7 | Evidence present | the monitors' records cover the run's window | fails closed: a run with no evidence is not valid |

**Amendment to H3 (2026-11-14, D-099, pre-data; K12).** H3 does not judge the staged capacity runs (R1's `capacity` step, the
calibrator's scenario `capacity`). Those runs keep H1 and H4-H7, and their pooled legit slip is still recorded beside the verdict. H3
still judges every ladder, reference, confirmation and P2 run. Why: the three staged runs of 2026-11-03 (`hg2_3/capacity/r1-r3`) had
a pooled legit slip p99 of 255, 179 and 291 ms, and the ladder runs of the same session 25-51 ms (review T-105, finding F1). Under
the rule as first written, every capacity run would have been host-invalid, and R1 would have paused as "host unfit". The user
decided this before any calibration data existed.

The executor's own soundness stays as it is (an unsound run is made once more; a second stops the step: `bench/calibrate.py:755-786`).

**Counting.** [PROPOSAL] A run that fails H1, H3-H7 is **host-invalid**: it is kept beside the run as `<run>.hostinvalid<k>`, published
with its reasons, never used, and made again with the same seed after a **speed hold** (probe pairs every 5 min until two in a row are
within H1's 10 %, at most 30 min). A run host-invalid three times in a row, or the fourth host-invalid run of a packet, **pauses the
packet** ("host unfit"); the step resumes in a later packet from its finished runs. A host-invalid run uses none of a campaign's re-runs
if you approve D5.

**Recorded beside every run, not judged:** the in-run speed index (the origin's CPU seconds from `server.csv` over the frozen cost of the
requests it served, `server_requests.csv`), the probes' raw costs, the timer probes, the executor's CPU's timer probe, `sar`'s 10-min
records.

### 5.2 Host conditions per packet (pre-checks, as T-092's packets have them)

The tree is clean at the pinned commit and the frozen hashes match; the kernel release and MemTotal equal the session's (K5); uptime at
least 1,800 s; chrony synchronised (H4's bounds) against its outside sources; no apt, dpkg or daily timer due within the packet's
length plus 10 min; no namespace, XDP program, Nginx, gunicorn or engine left; no non-testbed process above 5 % of a CPU over a 60-s
sample; for R2 onward a speed hold against R1's costs; for R1 a speed hold against the 2026-11-04 costs: probe pairs every 5 min until
two in a row agree within 5 % and lie between -5 % and +12 % of them (the normal band of finding 2), at most 45 min.

### 5.3 The session-quiet protocol (D3)

1. **Before the window.** The PC's sleep and hibernation are off and nothing heavy runs on it (the VM's 8 vCPUs share the host's 8 cores;
   R-032). The orchestrator and every agent are stopped; no unit suite, no offline job.
2. **Start.** [Amended 2026-11-13, D3's alternative] You open a plain terminal (the VM's console, or SSH from a terminal program) and run the packet script
   (K7), which runs the pre-checks, starts the monitors and the step detached (`setsid nohup`), and prints where its output goes.
3. **During.** [Amended 2026-11-13] The Claude app may stay open but idle: no message is typed into any session, no `/compact`, no session is opened or resumed, and the orchestrator ends its turn right after it has handed over the command. Nobody else logs into the VM; nothing else runs on the PC. (Originally: the app closed. The user chose the alternative; the cost is that runs the app's load reaches are voided by H6 and made again.) If you must stop: `kill -INT` the step's
   process (printed at its start); the testbed is taken down and the same command resumes.
4. **After.** The script ends with a one-line summary (runs made, host-invalid, paused or done). You may open the app again; an agent
   reads the outputs offline and the next packet is yours to start.
5. **What protects the data if a rule is broken:** H6 voids the runs the load reaches, by its numbers; nothing is excluded by hand.

## 6. Packets, order and VM time

### 6.1 What the earlier steps measured

| Step | When (UTC) | Wall time | What ran | Source |
|---|---|---|---|---|
| AP-1 origin | 2026-10-30 11:17:47-11:18:07 | 20 s | 3 sessions | RUNS.md [CLAIMED] |
| AP-2 capacity | 2026-11-01 14:23:38-14:23:57 | 19 s | refused by the timer gate | RUNS.md [CLAIMED] |
| AP-2b capacity | 2026-11-03 08:41:08-08:58:56 | 17.8 min | 3 staged runs + 1 set aside | RUNS.md [CLAIMED] |
| AP-3 ladders | 2026-11-03 09:03:46-10:56:49 | 113.1 min | search 18, export 18, cheap 8 runs, with their set-aside attempts; stopped in cheap's run 9 | RUNS.md [CLAIMED]; run directories [FACT] |
| AP-3b cheap + reference | 2026-11-04 10:32:58-11:14:16 | 41.3 min | cheap runs 9-18 with their set-aside attempts; reference 3 probes + 3 attack runs | as above |
| AP-4 drift x 2 | 2026-11-08 09:32:51-09:55:19 | 22.5 min | 8 runs + 1 set aside | as above |
| AP-5, AP-5b | 2026-11-10 | about 12 and 10 min | each cut by a host reset | as above |
| AP-7 drift | 2026-11-11 18:39:02-19:17:05 | 38.1 min | q1: 8 runs + 1 set aside (q1's two attempts took 25.7 min); q2 stopped | as above |

(AP-6 is no ledger packet: D-084.) Per run [FACT, from every `executor.log` of the calibration session `hg2_3` and of the published drift
directories; section 10]: a run of the 30 + 45 + 30 s timeline takes 119.5 s after its gate when the timer passes at once (n = 51 in
`hg2_3`; 120.5 s, n = 20, in the drift directories) and 131.8 s on average with the timer's re-probes (n = 65; 128.0 s, n = 23); 17 of
those 88 runs waited at least one re-probe of 30 s. A 120 s legit probe takes 134-136 s after its gate, and the first run of an
invocation waits 104-256 s more for the full gate (5 of 7 drift probes). A staged capacity run takes 263 s on average (n = 4). 9 of the 72
run directories of `hg2_3` are attempts the tool set aside as unsound and made again (12.5 %). [ESTIMATE] The speed bracket adds about
15 s a run (two probe pairs; one probe took about 2-3 s in the series).

### 6.2 The packets [PROPOSAL; estimates are ESTIMATE from 6.1]

Every step command carries a time budget (K6): it stops between runs once the packet has used 85 min, so that the run in progress ends
the packet within 90 min; the same command resumes. A run cut by a host reset leaves no `DONE` and is made again on resume (as today:
`bench/calibrate.py:755-770`; T-092 section 4); finished runs are kept; a cut origin step (20 s) is made again whole. After a reset the
next packet waits for the 30-min uptime gate and repeats its pre-checks; a boot into another kernel or memory size stops the programme
(K5, D2).

| Packet | Content | Runs | Minutes | Built from |
|---|---|---|---|---|
| R1 | speed hold against the 2026-11-04 costs (10-45 min); origin step; capacity (3 staged runs) | 3 (+0.4) | 26-61 | AP-1 20 s; 263 s a capacity run; AP-2b 17.8 min |
| R2a, R2b, R2c | one family's ladder each: cheap, export, search (18 runs: 14 attack runs at 7 levels, 4 controls) | 18 (+2.3) | 50-65 each | 18 x (130 + 15) s = 43.5 min, 12.5 % made again, a gate, a 5-10 min hold; AP-3 gave about 2.2 min an attempt |
| R3 | the reference: 5 rounds (legit, cheap, export, search) | 20 (+2.5) | 62-69 | 5 x (135 + 3 x 130 + 4 x 15) s = 48.8 min, 12.5 % again, the full gate, a hold |
| F | the freeze: offline, from R1-R3's directories; tolerances computed; the record committed (T2) before any R4 data; K8 if the cheap knee is not 2 | 0 | offline | `calibrate.py freeze` never touches the VM |
| R4 | the confirmation: 3 rounds, in a later window (D4) | 12 (+1.5) | 40-47 | 3 rounds as R3 |
| P2-1 | AP-8 rebuilt: one `M_xdp` and one `M_limits` smoke run of `cheap_static_flood_hg4` at twice the new cheap knee | 2 | 12-20 | T-092 AP-8 (10-12 min), daemon start up to 60 s |
| P2-2 | AP-9 rebuilt: the MVP campaign, warm-up + 10 blocks of C, Cp, U, `M_xdp`, in two or three packets by the time budget | 41 (+ up to 8) | 110-140 in all | 41 x 145 s = 99 min, 10 daemon starts, re-runs |

[ARITHMETIC] Re-calibration (R1-R3): 238-325 min, **4.0-5.4 h**; confirmation 0.7-0.8 h; P2 2.0-2.7 h; **all: 6.7-8.9 h of packets**, plus
a 30-min uptime hold after every boot. The one large saving would be shorter ladders (for example levels 1/2 to 8, about 30 min less), a
departure from design 7.2 step 3 that I do not recommend: on the old host the levels 1/8 to 1/2 had harm of at most 0.18 [FACT], but a
knee is the lowest level that passes, and only the full ladder shows it.

### 6.3 Windows and dates [ESTIMATE]

| Window (3-4 h, PC awake) | Packets | Hours |
|---|---|---|
| W1 | uptime hold; R1; R2a; R2b | 2.6-3.7 |
| W2 | uptime hold; R2c; R3; then F offline | 2.4-2.7 |
| W3 (after a reboot, D4; the record committed) | uptime hold; R4; P2-1 if legit and cheap are confirmed; P2-2 first packet | 2.4-2.8 |
| W4 | uptime hold; P2-2 to its end | 1.2-1.8 |

Four windows if the host holds; five with one reset or long holds. Before W1: the code of section 7, built and reviewed offline (two to
three days of agent time), and your approval of section 8. **With the earliest W1 on 2026-11-16 or 17, P2's verdict could exist around
2026-11-24 to 26** [ESTIMATE]; hence D8's reading of the three dates. The SCHEDULE's order stands after P2: P4, then P1 (SCHEDULE 3).

## 7. Code changes for a later T2 branch (not written here) [PROPOSAL]

Each is one commit with its tests, gated on the full unit suite and ruff, each new test failing on its parent, as the branches so far.

| # | Change | Tests |
|---|---|---|
| K1 | **Multi-run reference.** `reference` makes `N_REF = 5` rounds on the drift seeds (41; 42, 43, 44 in sorted family order) in the drift's order, keeps every run, and `reference.json` lists each; the record's `drift_reference` gets a second shape (`n`, `seeds`, per run Q and log2 p95, means, SDs, `tol_q_pp`, `tol_log2`, and the rule's constants) in a record of `SCHEMA = 2`; schema 1 stays loadable. The freeze computes the tolerances (section 4) and refuses fewer than 5 valid rounds. An invalid ladder session is moved aside as `ladder_<family>.invalid1` before it is made once more, and a second invalid one stops the step (8.3) | the 2026-11-04 record still loads with its hash `cff6e515`; a schema-2 record round-trips and is refused without any of the new fields, with n below 5 or with seeds other than the drift's; mean, SD and both clamps on fixtures to 1e-12; the reference's plans use the drift's seeds (plan test); `plan_text` counts 20 reference runs; an invalid ladder moved aside and made again, a second invalid one stopping, the freeze reading the valid one |
| K2 | **The check on means.** `drift` makes `M_DRIFT = 3` rounds and judges as section 4, per family, from the tolerances in the record; no `.second`; `drift.json` lists each comparison with its numbers and the runs in the sample; a schema-1 record keeps today's single-run path | bounds inclusive (T passes, T + 1e-9 fails); both clamps; `s = 0`; a missing p95 fails its family only; a failed legit probe confirms no family; the constants pinned in `RulesPinnedTest` (`N_REF` 5, `M_DRIFT` 3, `C_TOL` 3.0, half and whole floor); the five published `drift.json` judged again by the old path give the published verdicts; a cut check resumes with its finished runs; host-invalid runs never enter the sample |
| K3 | **The speed bracket.** A pinned probe (`time_routes`, 21 repeats, the record's knobs) on CPUs 0 and 1 before the stack starts and after the teardown; `run.json` and `DONE` keep both, `d_before`, `d_after` and the in-run index; the deviation against the record's costs (in a calibration session against `origin.json`'s) | the probe's commands and pins on the simulated host; the fields present; the arithmetic of `d`; `SPEED_DEV = 0.10` pinned; a simulated host that slows down during a run makes it host-invalid by its after-probe; the judging function takes no Q, p95 or harm (a signature test) |
| K4 | **Monitors and the host check.** The runner starts `mpstat -P ALL 5`, `pidstat -u -l 10` and a 30-s chrony sampler on the executor's CPU and keeps their files in the session; after each run it judges H1, H3-H7 over the run's window; host-invalid runs as 5.1 (`.hostinvalid<k>`, speed hold, re-make, pause after three in a row or four in a packet, exit code "paused: host unfit") | each rule on fixtures; **AP-7's published monitors as a fixture: the legit and cheap runs of `drift_20261111c_q1` (inside the compaction, C-129) come out host-invalid by H6, the runs of `.second` valid** [INFERENCE that they do; the test settles it]; AP-5's quiet monitors valid; the process classification (the app's server and sshd are not testbed); a dead monitor voids the run; the pause and its resume |
| K5 | **The host against the record.** A VM step refuses when the kernel release or MemTotal (within 1 %) differs from a frozen record's `host`, and a calibration session refuses a step whose kernel or memory differs from its first step's (as departure 31 does for pins) | the refusal texts; the 2026-11-04 record refused on a simulated 7.0.0-42 host; offline commands (`plan`, `freeze`, publishing, judging again) unaffected |
| K6 | **Packets and crash safety.** `--stop-after MIN` for every calibration step, `drift` and `gate_campaign run`: stops between runs, state "paused", not part of a campaign's fingerprint; `write_json` syncs the file and its directory; an empty or unreadable `DONE` or `block.json` is read as absent (made again, logged), an unreadable `campaign.json` refuses with exit 2 and a message (T-092 finding 2) | a stop and resume on the simulated host gives the run list of an uninterrupted session; an empty `DONE` and an empty `block.json` on resume; `os.fsync` called (patched); `campaign.json` empty: exit 2, no traceback |
| K7 | **The packet script** in the repository (`bench/packets/`): 5.2's pre-checks, the monitors, the step with its time budget, a tar and sha256 of the outputs, the summary line; a `--print` mode that runs nothing | `bash -n`; the `--print` output for each packet pinned; each pre-check function on fixture inputs (a chrony record out of bounds, a timer due, a stray process) |
| K8 | **HG4's spec at twice the new knee** (after F, before P2-1): if the cheap knee is not 2, `cheap_static_flood_hg4.json` takes level `2 x knee` (departure 39's rule) and its description the plan's numbers (departure 40's test); the golden plans follow | the existing pins; `gate_campaign plan --modes xdp` exits 0 on the new record |

[FACT] `bench/calibrate.py:929-936` makes the drift's second attempt and `:62` estimates 150 s a run; K2 and K1 replace both (130 s from
6.1). [INFERENCE] K1, K2, K4 and K6 are the minimum: without K4 a host-invalid run is found a packet late; without K6 a reset can leave
an empty `DONE` that ends a resume with a traceback (T-092 finding 2 [CLAIMED]).

## 8. Pre-registration (draft; binding once you approve it and it is committed with its sha256 before R1)

### 8.1 Label and provenance

**Post hoc.** This re-calibration is the dated consequence of **rule 2 of the prereg of 2026-11-08** ("Re-calibrating on -42 is then
the next proposal, as its own packet"), taken up by your decision of 2026-11-12 after the drift check gave no reading three times (rule 5;
second addendum, point 7) and after every complete attempt had failed the single-run rule. It is not a reading of that prereg's rule 1,
which never gave one. It was written after all of AP-4 to AP-7's data were seen; its numbers come from the calibration days' and the drift
days' spreads (sections 1, 4), not from any run of the new calibration, none of which exists.

### 8.2 Fixed before R1

The commit of the code branch (K1-K8 merged) and its tree; the template `bench/calibration/placeholder.json` and its hash; the scenario
specs and their hashes; the seeds (capacity 11, ladders 21, reference and check 41-44, campaign blocks 1-10); the constants of sections 4
and 5.1; the packets of 6.2. Any change before the data it governs is a dated addendum, labelled; any change after it is a departure,
labelled post hoc, and what rests on it says so.

### 8.3 Readings

* **The calibration (R1-R3, F):**
  * **FROZEN** when R1, R2a-c and R3 are complete with valid runs (executor-sound and host-valid), each ladder session valid by its own
    rule (its controls healthy and within 2 pp), and `freeze` accepts the session. A family without a knee is frozen as "cannot harm this
    server within the generator limit" (design 7.2 step 4): a finding, nothing tuned. A family with a reference SD of Q above 5 pp is frozen
    with the spread and labelled (D6).
  * **NOT FROZEN** when a step stops by its own rule: the origin's sessions disagree twice (10 %); the capacity probe's first level is
    below 99 % or no level reaches 50 % (design 7.5); a ladder session is invalid twice (its first invalid session is made once more in a new
    directory, both published; K1).
  * **NO READING** when R1-R3 are not complete after **5 windows or by your hard date (D8)**, whichever comes first.
* **The confirmation (R4), per family f:** **CONFIRMED** for f when the legit probe and f pass section 4's check over the first 3 valid
  rounds; **NOT CONFIRMED** for f otherwise; **NO READING** when 3 valid rounds are not made within 2 windows after the freeze.
* **Later drift checks** (before a campaign of family f that does not start in R4's window): the same rule, the same reading; a
  campaign resumed in a later window needs none, since every run of it is judged by 5.1.

### 8.4 Every attempt counts

The sample of R3 is its first 5 valid rounds and of R4 its first 3, in the order made: no round is added, dropped or replaced because of
any value of Q, p95 or harm. A valid run is never made again. Host-invalid and unsound runs are published beside the reading with their
reasons and their Q and p95, descriptive only. Every step, every packet and every check that starts is published, whatever it gives, the
paused and cut ones included.

### 8.5 What may and may not be made again

* **May**, each with its reason recorded: a run cut by a host reset or stopped by `kill -INT` (it has no result); a run the executor found
  unsound (once, as today; a second stops the packet, and the step resumes in a later packet); a host-invalid run (twice more, 5.1); an
  invalid ladder session (once); a packet that paused or stopped (it resumes).
* **May not:** a valid run; a valid round; a complete step; the reference once complete; the freeze; a complete confirmation, whatever it
  reads; and **no second re-calibration within this programme** after NOT FROZEN or NOT CONFIRMED: one would be a new decision and a new
  pre-registration.

### 8.6 What each outcome means

| Outcome | For the programme | For the thesis |
|---|---|---|
| FROZEN, then CONFIRMED for legit and cheap | P2-1 and P2-2 run on the new record (K8 first); other families as confirmed | "calibrated on the host as it ran, confirmed in a later window within the stated tolerances"; P2's verdict, whatever it is, reported by its pre-registered rule |
| FROZEN, NOT CONFIRMED for cheap (or legit) | no campaign of that family (none at all if legit) may use the record | the benchmark was calibrated twice and did not reproduce across windows on this host: a reported negative result (outline A, RES-01..04), with both records and every attempt |
| NOT FROZEN | nothing runs on it | the step that stopped and why, as a finding about the host or the design |
| NO READING (either) | the host is the blocker; nothing more without a new decision | stated as such; the partial data published as partial |

### 8.7 Always reported

Per family: n, mean, SD, minimum and maximum of Q and log2 p95 in R3 and in R4; the tolerances and each comparison; the new record beside
the old (costs, capacity, `rho`, knees, `S`), descriptive only; every host-invalid run and its reasons; the speed probes and the in-run
index; the timer waits; the windows, boots and resets; anything done outside this text, with its time.

## 9. Risks and limits

| Risk | What it does | Mitigation |
|---|---|---|
| [RISK] The host resets as it did on 2026-11-07..11 (median uptime 53 min; R-027 [CLAIMED]) | packets resume, but a 30-min hold after each boot eats the windows | D2; the windows are yours; 8.3's limit of 5 windows makes the end explicit |
| [RISK] H1's 10 % rests on one evening's 23 sample times | if the normal state is wider, runs are voided and packets pause: VM time lost, not bias | the probes and `d` of every run are kept, so the band can be read against far more data afterwards (descriptive only) |
| [INFERENCE] Valid runs are those made in the host's normal state | the record describes that state | D5 applies the same rule to the campaigns, so they are judged in the state the record describes |
| [INFERENCE] `s` is a within-session spread | a day-to-day shift fails the confirmation | intended (4); D4 makes the confirmation test it |
| [FACT] The calibration runs on `PIN_PLAN`, HG4 on `PIN_PLAN_DAEMON` (T-092 section 5) | "twice the knee" and the reference lean on the calibration's layout | unchanged from today; stated with every P2 result |
| [FACT] The ladders keep 2 repeats a level | the knee can land a level off by noise | R3's 5 runs at the knee give the variance statement rule 4 of the prereg of 2026-11-08 asked for; the neighbouring levels have none |
| [CLAIMED] T-092's open questions on P2 (the 0.99 ratio against the seconds before the first bans makes NOT MET a live outcome with a working daemon; repair rules R-1 to R-5) | carry over unchanged | yours to decide before P2-1, as T-092 section 8 lists them |
| [INFERENCE] The per-source rate at twice the new knee may fall below the L7 rule's 50 req/s (the rate is `level x S / cost`) | the protected arm would ban nothing | F prints it from the plan; if it is below 50, you decide before P2-1, with no outcome seen |

## 10. Sources and how the numbers here were made

* Run durations: every `executor.log` under `/var/tmp/ddos_campaigns/hg2_3` (read only) and under
  `results/2026-11-11_harm-drift-check/drift_*`: the time of "preflight and environment passed" and of the last line (orchestrator
  workspace, `tasks/T-101/artifacts/all_executor_durations.txt`, `duration_summary.txt`).
* Spreads at the knees and of the drift attempts: `hg2_3/ladder_*/ladder.json`, `hg2_3/reference/reference.json` and the five published
  `drift.json` (`tasks/T-101/artifacts/scripts/prior_spread.py`, output `prior_spread.txt`).
* The rule's operating characteristics: a Monte Carlo of 200,000 draws per cell, normal errors, seed 20261113
  (`tasks/T-101/artifacts/scripts/tolerance_sim.py`, output `tolerance_sim.txt`), run offline in the agents' sandbox.
* The speed bands: `results/2026-11-11_harm-drift-check/speed_series/speed_series.txt`, the mean of C3 and C5 per probe and per sample
  time (`tasks/T-101/artifacts/speed_c3c5.txt`).
* Code: `bench/calibrate.py:59-62` (probe, reference count, seeds, run estimate), `512-537` (reference), `660-695` (drift), `718-786`
  (runner), `929-936` (second attempt); `bench/calibration.py:37` (schema), `44` (host shape), `56` (legit tolerances), `288-325` (knee,
  drift rules); `bench/origin.py:54`, `298-358` (estimator, self-check); `bench/executor.py:1129-1227` (timer and environment gates),
  `1231` (sampler), `2046-2145` (a run); `bench/population.py:48`, `56` (pin plans), `261-264` (attack rate); `eval/harm_gate.py:348-399`
  (run validity), `625` (P2's outcome).
* Ledger: C-111, C-128 to C-137; R-025, R-027, R-030 to R-032; RUNS.md; SCHEDULE.md 1-4; T-092's report (sections 2-8).
