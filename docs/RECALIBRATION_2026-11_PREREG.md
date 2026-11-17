# Re-calibration of the harm benchmark on the laptop (2026-11): pre-registration v1

**Status: v1, approved by the user on 2026-11-15 ("Approve as recommended"; ledger D-104). It is revision 3 (2026-11-14, T-106, after
reviews T-115 and T-117) with two changes only: this status paragraph and the record of the decisions at the end of section 11. It binds
from its commit, with its sha256, before R1's first command.** It was written before any data of this re-calibration existed; nothing in it has run. The commit
that adds this file is the **pinned commit**: every packet runs with `--commit <that commit>` from a clean tree of it. The ledger
records the file's sha256 and the commit's tree hash next to each other (`DECISIONS.md`, `APPROVALS.md`).

Where this file and `docs/RECALIBRATION_2026-11_DESIGN.md` (the design) disagree, this file wins. Where this file is silent, the design
at the pinned commit applies. "design N" is a section of the design; "harm design N" is a section of `docs/BENCHMARK_HARM_DESIGN.md`.
"HS1" is `docs/HS1_PREREG.md` (v1 as amended by D-102) and its run of 2026-11-14 (RES-05). `path:line` references are to the code at
the pinned commit as it stood at review (T-115, T-116); C-, D-, R-, T-, AP- and RES- ids are the orchestrator's ledger at
`/home/artur/agent_workspace/ledger/`. Tags: **[FACT]**, **[ARITHMETIC]**, **[ESTIMATE]**, **[INFERENCE]**, **[PROPOSAL]** (a rule
fixed here, before the data it judges).

## 1. Label and provenance

**Post hoc.** This re-calibration is the dated consequence of **rule 2 of the prereg of 2026-11-08** ("Re-calibrating on -42 is then
the next proposal, as its own packet"). The user took it up on 2026-11-12, after the drift check gave no reading three times (rule 5;
second addendum, point 7) and every complete attempt had failed the single-run rule. It is not a reading of that prereg's rule 1, which
never gave one. Its numbers come from the calibration days' and the drift days' spreads (design 1, 4), written after all of AP-4 to
AP-7's data were seen, and from no run of this re-calibration, none of which exists.

**Changes since the design was approved (2026-11-13), all before any of its data:**

| Date (UTC) | Change | Why | Source |
|---|---|---|---|
| 2026-11-14 | The programme runs on the **laptop** (AMD Ryzen 7 7730U, VirtualBox 7.2.10r174163) until 2026-12-03; the desktop never runs the VM in that time | the desktop reset the guest 17 times in 19 boots (C-147) | D-096 |
| 2026-11-14 | A record of schema 2 names its PC (`cpu_model`, `vbox_host_version`); every step refuses on another PC | kernel and MemTotal cannot tell the two PCs apart (C-149) | D-096, K10 |
| 2026-11-14 | R1's speed hold uses **HS1's medians on this PC** instead of the 2026-11-04 costs: -10 % to +10 %, two pairs in a row agreeing within 5 %, at most 45 min | the 2026-11-04 costs are another CPU's; the laptop is 42-50 % slower on C1-C5 (C-152) | D-098, K11 |
| 2026-11-14 | **H3 does not judge staged capacity runs**; they keep H1 and H4-H7 | capacity runs saturate the origin on purpose; hg2_3's three gave 179-291 ms (T-105 F1) | D-099 (1), K12 |
| 2026-11-14 | **H5's line is 10 s**, and the sampling monitors run at `chrt --fifo 1` | AP-7 under load had 21 mpstat gaps of 7-9 s and none above 10 s (T-105 F2) | D-099 (2), K13 |
| 2026-11-14 | The pre-checks fail closed and check the pinned commit's blobs; `--commit` is required. **`freeze` refuses a session in which no family has a knee**, which reads NOT FROZEN (design 8.3 would have frozen three "cannot harm" findings) | T-105 F5-F7 | K14 (K14b, D-103) |
| 2026-11-14 | A step is stopped with **`kill -TERM`** (design 5.3 and 8.5 said `kill -INT`, which the detached stage ignored) | T-105 F3 | K15 (K15b) |
| 2026-11-14 | A TERM to the pid the packet prints is **forwarded by the stage to the running step**; the testbed is taken down and the tar and summary are still written | T-115 H-2: TERM to that pid left the step running orphaned | K16b |
| 2026-11-14 | Resuming R1 **keeps a complete origin step** of the same estimator (it is not made again); an unsound attempt is set aside as the first free `.failed<k>` | T-115 H-3 (a complete step was re-made), M-6 (a resume could crash) | K17b |
| 2026-11-14 | A step's **own-rule stop exits 7, "not frozen"**; refusals and defects stay at 2 (section 6, Appendix A) | T-115 H-1: exit 2 mixed readings with refusals | K18b |
| 2026-11-14 | Every stop text says **`sudo kill -TERM`** (the stage runs as root); the packet's texts state the real worst-case length; the pre-checks look 190 min ahead for timers; the summary says "stopped by TERM" only when the step was interrupted | T-117 N-1, N-2, L-1 | K19 |
| 2026-11-14 | R4's NO READING also falls on 2026-12-03 (design 8.3: two windows only) | the hard date (D8) bounds every reading | this file |
| 2026-11-14 | HS1 **PASSED** on the laptop (RES-05); it is the host this file governs | pre-registered check of the host before R1 | AP-10, C-152, C-153 |
| 2026-11-14 | **[PROPOSAL P-1]** the paired check of the two probe contexts before R1's hold, with a stop rule enforced by the packet | T-105 F8 | this file; tool 3bf3b8e; packet gate K20b (rule) or K20c (recorded only) |
| 2026-11-14 | **[PROPOSAL P-2]** the capacity step's levels on the laptop (section 5.5) | T-115 LOW 14, T-116 | this file; option B = K21B |

## 2. The host, held fixed for the programme

* [FACT, HS1 identity] CPU `AMD Ryzen 7 7730U with Radeon Graphics`, VirtualBox host `7.2.10r174163`, kernel `7.0.0-42-generic`,
  MemTotal 7,600,856 kB (8 GiB guest RAM), 8 vCPUs, clocksource tsc, the VM's disk on the laptop's internal SSD.
* Held (D2, D-086, the user's settings of 2026-11-14): kernel 7.0.0-42 (packages held, apt timers masked); 8 GiB; on the laptop: on
  mains power, Windows "Best performance", lid "Do nothing", sleep and hibernation "Never" on AC, power throttling off for the
  VirtualBox processes, nothing heavy on the laptop during a window. The code checks none of the laptop's settings; the user keeps them.
* A step refuses before any run when the kernel, MemTotal (within 1 %), the CPU model or the VirtualBox version differs from the
  session's first step or from the frozen record (K5, K10). Such a refusal gives no reading; the programme stops until the user decides.
* **HS1's medians** (`/home/artur/agent_workspace/host/hs1_20261114T155933Z/medians.json`, sha256
  `c899bdeee67ff3d6c7d21e149165c0c3e587ea0d72105a570d46ae0402d547eb`) are R1's speed reference. They are valid on this PC whatever the
  boot (the hold compares the PC, not the boot). They are not a reference for H1: in the session H1 compares with R1's own costs
  (`origin/origin.json`), and afterwards with the new record's.

## 3. Fixed before R1

* **The code:** the pinned commit, on `integ/s6`: GitHub main efa8f54 merged with thesis/build-fixes, docs/readme-requirements,
  feat/bench-vm-helpers, feat/recalibration-k (K1..K13, K14b..K18b, K19, then K20b or K20c by P-1, and K21B if P-2 is B),
  feat/hs1-check (85c778c) and
  feat/paired-check (3bf3b8e), then this file. Every file's content is what that commit holds; the packet's pre-checks compare the
  working tree with the commit's blobs (K14). Before each window the orchestrator also checks the table below with
  `git show <PINNED>:<path> | sha256sum`.
* [FACT, sha256 at K15's candidate f72474f and at 85c778c; the fix round changes none of these files]:

| File | sha256 |
|---|---|
| `bench/calibration/placeholder.json` (the template) | `2027790f0f9ad3714d2b53eb3fb1aac980ee67814b7973f8877917421350f85c` |
| `bench/origin.py` (the estimator; HS1's `origin_sha256`) | `4cb5e276c04e8a4c003729170112c8b21000aa5bc89901681f7c07cc268ff2b2` |
| `bench/vm/hs1_probe.py` (P-1's context A; HS1's `probe_sha256`) | `242d754f5709ebadabf668c6f873176add90bdce3a20467c2fe68c04bb0b6ef0` |
| `bench/vm/paired_check.py` (P-1's tool, 3bf3b8e) | `4663db8001e7589d59f6da9c7d83947e89b052e655fb2258f67208a7f0aaefe8` |
| `bench/scenarios/benign_control.json` | `025628ede21f0e89fe836a98b2a3b831591f948854e886ae3463105bb5f11cb8` |
| `bench/scenarios/cheap_static_flood.json` | `e115ed728d957b737770ae36002edfb70248d163d16cde473719b77077a347a5` |
| `bench/scenarios/cheap_static_flood_hg4.json` (K8 may change it after F, before P2-1) | `f343364accc8a27d31da3233212142eb6aa7f5d577ea01e03744b392d10d4f4d` |
| `bench/scenarios/costly_export_sub_threshold.json` | `2d003d9c2143a17d1bb6843b84e1df1aabd3c404b566f05ab7fefec7ed1e203f` |
| `bench/scenarios/costly_search_sub_threshold.json` | `dadab6a869e9c9d0b6014f99bc8bfcdd62dd930912b01a2ff30f73440b74c869` |
| `bench/calibration/ddos-mitigation-2026-11-04.json` (the old record, frozen, unused on the laptop) | `55d84b004d9f61ca0ff1735fa6a7b11192bfe91d2cba2da7aa9c1b12cb72d016` |

* **Seeds:** capacity 11 + repeat (11-13); ladders 21 + the family's index (21-23); reference and check 41 (legit), 42, 43, 44 (cheap,
  export, search, sorted); campaign blocks 1-10.
* **The constants** of sections 4 and 5, which the code at the pinned commit holds: `bench/calibration.py`, `bench/calibrate.py`,
  `bench/hostcheck.py`, `bench/executor.py` (H2), `bench/packets/packet.sh`, `bench/packets/prechecks.py`, `bench/vm/paired_check.py`.
* **The packets** of design 6.2, with R1 as in section 5.3 here and the capacity levels of section 5.5.

Any change before the data it governs is a dated addendum, labelled and approved by the user. Any change after it is a departure,
labelled post hoc, and whatever rests on it says so.

## 4. The reference and the check on means (design 4, D1; unchanged)

* **A round:** a 120 s legit probe at `rho` (seed 41; Q and p95 over 10-120 s), then one attack run per family at its knee in sorted
  order (42, 43, 44; timeline 30 + 45 + 30 s; Q and p95 over the 45 s of attack), on `PIN_PLAN`.
* **The reference (R3):** the first **n = 5** valid rounds in the order made. Per family f: means `Qbar_f`, `Lbar_f` (L = log2 p95) and
  sample SDs `s_f`, `t_f` (n - 1). The legit probe likewise.
* **Tolerances, computed at the freeze and written into the record:**
  `k = 3 sqrt(1/5 + 1/3) = 2.19089`; `T_Q,f = min(10, max(5, k s_f))` pp; `T_L,f = min(1.0, max(0.5, k t_f))`. 10 and 1.0 are the
  record's gate floors.
* **The check (R4, and before every later campaign of a family):** the first **m = 3** valid rounds. Family f passes when
  `|mean Q - Qbar_f| <= T_Q,f` and `|mean L - Lbar_f| <= T_L,f`. The legit probe passes when its mean Q is within 2 pp of the reference's
  and `0.75 <= 2^(mean L - reference mean L) <= 1.25`. Bounds are inclusive. A run with no served request has no p95 and fails its family.
  **Confirmed for f** = the legit probe passes and f passes. There is no second attempt.
* A family whose reference SD of Q is above 5 pp is frozen with its spread and labelled in every verdict at its knee (D6).

## 5. Host validity and packets

### 5.1 Per run (design 5.1, as amended by D-099)

| # | Rule | Applies to |
|---|---|---|
| H1 | speed bracket: `|d_before| <= 10 %` and `|d_after| <= 10 %`; d = mean over CPUs 0 and 1 of the mean of C3's and C5's deviations; reference = R1's `origin.json` in the session, the new record afterwards | every calibration run and every P2-2 run |
| H2 | timer gate: p99 below 10 ms on CPU 7 before every run (re-probed every 30 s, up to 30 min); a refusal stops, it does not void | every run |
| H3 | pooled legit slip p99 at most 100 ms | every ladder, reference, confirmation and P2-2 run; **not** staged capacity runs (their slip is recorded) |
| H4 | clock: every 30-s chrony sample overlapping the run `|System time| < 0.1 s`, leap status not "Not synchronised", no selected source more than 1 s off; no "Forward time jump", "Can't synchronise" or "Long readout interval" line in the window | as H1 |
| H5 | no gap **above 10 s** between consecutive 5-s mpstat samples in the window; mpstat, pidstat and the chrony sampler at `chrt --fifo 1` | as H1 |
| H6 | non-testbed processes at most 5 % of one CPU on average over the window and at most 50 % in any 10-s sample | as H1 |
| H7 | the monitors' records cover the window (fails closed) | as H1 |

**The window** of a run runs from the start of its before-probe pair (taken right after its timer gate passes) to the end of its
after-probe pair. The step's runner starts the monitors at its first run; the speed hold and the origin step run without them.

**Known gap (T-115 M-7).** P2-1's two smoke runs are started by `executor.py run`, which does not judge H1-H7 at the pinned commit.
Before P2-1 they are either moved into a host-checked runner by a reviewed change (a dated addendum) or run and labelled "not
host-checked". P2-1 does not run until the user has chosen.

**Counting (design 5.1).** A run failing H1 or H3-H7 is **host-invalid**: kept as `<run>.hostinvalid<k>`, published with its reasons and
its Q and p95 (descriptive only), never used, and made again with the same seed after a speed hold (a probe pair every 5 min until two
in a row are within H1's 10 %, at most 30 min). The third host-invalid run in a row, or the fourth of a packet, **pauses the packet**
("host unfit", exit 5); the step resumes in a later packet from its finished runs. **Unsound runs:** a run the executor finds unsound is
set aside as the first free `<run>.failed<k>` and made once more; a second unsound attempt stops the packet (exit 2, `RunUnsoundTwice`).
The count starts again in each packet; every `.failed<k>` is kept and published.

### 5.2 Per packet (design 5.2, as amended by K10, K11, K14)

Clean tree at the pinned commit and its blobs match; kernel, MemTotal (1 %), CPU model and VirtualBox version equal the session's;
uptime at least 1,800 s; chrony synchronised within H4's bounds; no apt, dpkg or daily timer due within the packet plus 10 min; no
namespace, XDP program, Nginx, gunicorn or engine left; no non-testbed process above 5 % of a CPU over a 60-s sample.
**R1:** the speed hold against HS1's medians (-10 % to +10 %, two pairs in a row agreeing within 5 %, at most 45 min, at least about
5.5 min; exit 5 when it does not hold). **R2a-R3:** a speed hold against R1's `origin.json` (-10 % to +10 %, two pairs in a row, at most
30 min). **R4, P2-1, P2-2:** the same hold against the new record.

**Budget (K6).** No run starts after 85 min of the packet. The waits after that add up: the first run of each step invocation takes
the full gate (uptime/load up to 30 min, then the timer up to 30 min), a run lasts about 2-5 min, and a host-invalid run is followed by a
speed hold of up to 30 min. A packet therefore usually ends within about 90 min and at worst after about 3 h [ARITHMETIC, T-117 N-2];
the pre-checks look 190 min ahead for timers (K19). The same command resumes a paused packet.

### 5.3 R1, and the paired check of the probe contexts **[PROPOSAL P-1]**

R1 = the paired check, then the speed hold against HS1's medians, the origin step, and capacity (3 staged runs). [ESTIMATE, design
6.2] 26-61 min plus the check's 2-3 min.

[FACT, T-105 F8, T-115] HS1's probe ran `bench/vm/hs1_probe.py` in the sandbox as uid 1000; the hold runs `bench/calibrate.py
origin-session` as root. Both use `time_routes`, thread CPU time, 21 repeats, the same knobs and the same `bench/origin.py`.
[INFERENCE] A systematic offset of a few per cent between the two contexts is possible. It would shift the hold's band by the same
amount.

**P-1.** `bench/vm/paired_check.py run OUT_DIR --medians <HS1's medians.json>` (as the user, in the pinned tree) runs the estimator on
CPU 0, then CPU 1, in the order A B B A (A = HS1's context, B = the hold's). Per CPU and route r in {C3, C5}: `off = mean(B) / mean(A)
- 1`; `D` = the mean over the two CPUs and the two routes. **`|D| <= 5 %` (inclusive): R1 may go on. `|D| > 5 %` (exit 6), or a probe
that cannot be read (exit 3): R1 does not start**, and the user decides (a hold biased by more than half its band). The tool refuses
to start below 1,800 s of uptime. **The packet enforces it (K20b):** `packet.sh R1` refuses (exit 2, before the pre-checks) without
`--paired OUT_DIR` whose `paired.json` has exit 0, this boot's id, a judgement at most 30 min old and the uptime that only `run`
writes (so that a later `judge` of old probes cannot pass); a check older than that is made again in a new directory. The probes' costs and D are published with R1 either way. Nothing of the check enters any reading.

*Alternative for the user (not recommended):* the check is recorded only (K20c instead of K20b): the packet's text describes it as
recorded, `--paired OUT_DIR` is optional and only copies `paired.json` into the session beside the log, and R1 goes on whatever D is.

### 5.4 The session-quiet protocol (design 5.3 as amended on 2026-11-13, by K15b and K16b)

1. Before a window: the laptop awake, plugged in, nothing heavy on it. The orchestrator and every agent are idle (no turn running);
   no unit suite, no offline job on the VM.
2. The user starts each packet from a plain terminal (the VM's console or SSH):
   `sudo bench/packets/packet.sh PACKET --commit <pinned> [--medians FILE --paired DIR (R1)] [--record FILE (R4, P2)] [--session DIR]`.
   `--medians` is required for R1 (an `HS1_MEDIANS=` variable does not survive sudo); the session defaults to
   `/var/tmp/ddos_campaigns/recal_2026-11`. It runs the pre-checks, starts the step(s) detached and prints the stage's pid and its log.
3. During the packet the Claude app may stay open but idle: no message typed, no `/compact`, no session opened or resumed. Nobody else
   logs into the VM. **To stop: `sudo kill -TERM <the printed pid>`**: the stage forwards it to the running step, the testbed is taken
   down, no further step starts, and the tar, sha256 and summary ("stopped by TERM") are written. A TERM that arrives during a run's
   teardown (under a second; the executor shields it) does not interrupt the step, which goes on to its next run: when the log shows
   the step going on a minute after the TERM, the user sends `sudo kill -TERM` again, and the summary notes a TERM that interrupted
   nothing [FACT, T-117 L-1; K19]. The same command resumes.
4. After: the log's last line is the one-line summary. The app may be used again; an agent reads the outputs offline.
5. If a rule is broken anyway, H6 voids the runs the load reached, by its numbers. Nothing is excluded by hand.

### 5.5 The capacity step's levels on the laptop **[PROPOSAL P-2]**

[FACT, `bench/calibrate.py` `capacity_levels`] The levels are 50 x 1.3^k req/s, k = 0..9 (50 to 530.2), 20 s each, 3 staged runs.
C_slo is the last level before the first at which any repeat has Q < 99 %; C_sat the lowest at which 2 repeats have Q < 50 %. They
were set on the desktop (C_slo 84.5 req/s). [ESTIMATE, T-116 capacity_levels_risk.md] With the laptop's costs 1.44 times the desktop's,
its C_slo lies at 50 or 65 req/s, and the chance that the first level (50 req/s) falls below 99 % in at least one repeat is about
5-25 %; that stop reads NOT FROZEN with no second attempt (section 8).

| Option | Levels | Extra VM time | First-level risk [ESTIMATE] |
|---|---|---|---|
| A. keep | 50 x 1.3^k, k = 0..9 | 0 | about 5-25 % |
| **B. add two lower levels (recommended)** | 50 x 1.3^k, k = -2..9 (29.6, 38.5, 50, ..., 530.2) | about +2 min | about 1-5 % |
| C. scale by 1/1.44 | 34.7 x 1.3^k, k = 0..9 | 0 | about 1-5 %; ties the grid to HS1 |

B keeps the desktop's grid at and above 50 req/s, so the two PCs' capacity records stay on one grid. B and C each need a reviewed code
change (the levels are code, `capacity_levels`'s defaults and a pinned test) before the pinned commit; B is built as K21B: 12
levels, 29.6, 38.5, 50, ..., 530.2 req/s (rounded to 0.1 as before), about 15.2 min for the 3 runs against 13.2 min [ARITHMETIC, K21B].

## 6. Readings (design 8.3; stop classes in Appendix A)

* **The calibration (R1-R3, F):**
  * **FROZEN** when R1, R2a-c and R3 are complete with valid runs (executor-sound and host-valid), each ladder session valid by its own
    rule (its controls healthy and within 2 pp), and `freeze` accepts the session. A family without a knee is frozen as "cannot harm
    this server within the generator limit" (harm design 7.2 step 4): a finding, nothing tuned. A family with a reference SD of Q above
    5 pp is frozen with the spread and labelled (D6).
  * **NOT FROZEN** when a step stops by its **own rule**: exit **7**, the summary "not frozen", with the rule's text in the log. The
    own-rule stops are listed in Appendix A (class a). The step, run again, says the same without measuring; the packet's speed hold
    (and, for R1, P-1) still run first.
  * A stop with exit 2, 1 or 130 (a refusal of the host or the environment, a run unsound twice, a defect or an interrupt) is **no
    reading**: the packet resumes later, or, for another host or PC or a defect, the user decides. The log's last error line names
    the class.
  * **NO READING** when R1-R3 are not complete after **5 windows or by 2026-12-03 (D8)**, whichever comes first, or when P-1 stops R1
    and the user does not decide a way on.
* **The confirmation (R4), per family f, in a later window after a reboot (D4):** read from `drift.json`, not from the summary's state
  (drift exits 3 for a NOT CONFIRMED family and the summary then says "stopped (exit 3)"). **CONFIRMED** for f when the legit probe and
  f pass section 4's check over the first 3 valid rounds; **NOT CONFIRMED** for f otherwise; **NO READING** when 3 valid rounds are not
  made within 2 windows after the freeze, or by 2026-12-03.
* **Later drift checks** (before a campaign of family f that does not start in R4's window): the same rule and the same reading. A
  campaign resumed in a later window needs none, since 5.1 judges every run of it.

A window is a period of about 3 h or more (a packet's worst case, 5.2) that the user arranges, with the laptop awake, in which one or more packets run. A packet that a host
reset cuts counts in the window it started in.

## 7. Every attempt counts (design 8.4)

The sample of R3 is its first 5 valid rounds and of R4 its first 3, in the order made: no round is added, dropped or replaced because of
any value of Q, p95 or harm. A valid run is never made again. Host-invalid and unsound runs are published beside the reading with their
reasons and their Q and p95, descriptive only. Every step, packet and check that starts is published, whatever it gives, the paused,
stopped and cut ones included, P-1's checks included (they are outside the packet's tar and are published separately).

## 8. What may and may not be made again (design 8.5, the stop signal corrected)

* **May**, each with its reason recorded: a run cut by a host reset or stopped by `kill -TERM` (it has no result); a run the executor
  found unsound (once more in each packet, 5.1); a host-invalid run (twice more, 5.1); an invalid ladder session (once); a packet that
  paused or stopped without a reading (it resumes); an origin step that was cut (made again whole); P-1's check, in a new directory.
* **May not:** a valid run; a valid round; a complete step (a resumed R1 keeps its origin step, K17b); the reference once complete; the
  freeze; a step that stopped by its own rule (exit 7); a complete confirmation, whatever it reads; and **no second re-calibration
  within this programme** after NOT FROZEN or NOT CONFIRMED. One would be a new decision and a new pre-registration.

## 9. What each outcome means (design 8.6)

| Outcome | For the programme | For the thesis |
|---|---|---|
| FROZEN, then CONFIRMED for legit and cheap | P2-1 and P2-2 run on the new record (K8 first; P2-1 after the 5.1 gap is closed) | "calibrated on the laptop as it ran, confirmed in a later window within the stated tolerances"; P2's verdict, whatever it is, reported by its pre-registered rule |
| FROZEN, NOT CONFIRMED for cheap (or legit) | no campaign of that family (none at all if legit) may use the record | the benchmark was calibrated twice and did not reproduce across windows on this host: a reported negative result (outline A, RES-01..04), with both records and every attempt |
| NOT FROZEN | nothing runs on it | the step that stopped and why, as a finding about the host or the design |
| NO READING (either) | the host is the blocker; nothing more without a new decision | stated as such; the partial data published as partial |

The new record is the laptop's. It says nothing about the desktop or the 2026-11-04 record, which stays frozen and published with its
five failed drift attempts.

## 10. Always reported (design 8.7, extended)

Per family: n, mean, SD, minimum and maximum of Q and log2 p95 in R3 and in R4; the tolerances and each comparison; the new record beside
the old (costs, capacity, `rho`, knees, `S`), descriptive only, with the laptop/desktop difference named; every host-invalid and unsound
run and its reasons; the speed probes, the holds (also a stopped hold's pairs) and the in-run index; P-1's probes and D; HS1's verdict
and medians; the timer waits; the windows, boots and resets; every stop with its exit code and class; the PC identity of every step;
anything done outside this text, with its time.

## 11. What the user approves with this file

1. The file as written, to be committed with its sha256 before R1 (D7).
2. **P-1** (5.3): the stop rule enforced by the packet (K20b), or the alternative, recorded only (K20c).
3. **P-2** (5.5): the capacity levels A, B (recommended; K21B) or C.
4. The judgement calls of Appendix A (marked [JC]), as classified or otherwise.
5. [Recorded, no change proposed] H3 keeps judging the legit probes of the reference and confirmation rounds. [FACT, T-111 K13
   re-judgement of AP-7] Of AP-7's 11 finished runs one failed H3: q2's legit probe, slip p99 114 ms, in the session where the host ran
   26-68 % slower than the record (C-130). The other ten passed (q1's and its second attempt's legit probes: 52 and 60 ms).
   [INFERENCE] H3 removes runs made while the generators stalled, which is the gate's own rule; dropping it would let a stalled run
   enter the reference.

**Decided by the user, 2026-11-15 (ledger APPROVALS.md, D-104), before any data of this re-calibration:**
1. The file is approved as written (revision 3, sha256 `c0ea1a6d5a337f4fd491d889be990500b877402983b6c4819d456aef1a093f72`), with
   this record and the status paragraph added.
2. **P-1 is a rule** enforced by the packet: K20b is on feat/recalibration-k; K20c is not.
3. **P-2 is option B**: K21B is on feat/recalibration-k (12 levels, 29.6 to 530.2 req/s).
4. Appendix A's judgement calls stand **as classified**.
5. H3 keeps judging the legit probes of the reference and confirmation rounds.

## Appendix A. Stop classes (from K18b; full table with `path:line` at the pinned commit: T-116 `K18_stop_classes.md`)

**(a) Own rule: exit 7, NOT FROZEN.**
1. origin: the routes' unloaded cost differs by more than 10 % between sessions, twice.
2. origin, resumed after (1): says so again and measures nothing. [JC]
3. capacity: every level up to the last keeps Q at 99 % or more (the capacity is above the probe's range). [JC]
4. capacity: the first level is below 99 % in a repeat.
5. capacity: no level brings Q below 50 % in 2 of the 3 repeats (the server is not saturated within the range).
6. ladder: the screening of a family is not valid twice.
7. ladder: no level of a family can be run within the generator's limits. [JC]
8. reference: a reference run has no judged request or no successful one. [JC]
9. freeze: no family has a knee (K14).
10. freeze: it refuses for rule reasons only (they repeat 6 and 8). [JC]

**(b) Host or environment refusal: exit 2, no reading, the packet resumes later.** The timer gate (H2); the uptime/load gate; a
testbed still present [JC]; setup failed after its retries [JC]; leftovers after the teardown [JC]; the machine's tables unreadable;
the PC not readable; another host or PC than the session's or the record's (the user decides); the hold's reference from another PC.

**(c) A run unsound twice: exit 2, named `RunUnsoundTwice`.** The step resumes in a later packet (5.1).

**(d) Usage or defect: exit 2 or 1, no reading, the user looks.** Steps out of order or after an own-rule stop [JC]; mixed or smoke
sessions (a smoke `--levels` outside the ladder included, K19); files missing or unreadable; an origin session that gave nothing
readable [JC]; a capacity step window with no judged request [JC]; a freeze refusal that names a defect beside a rule [JC]; a reference
with fewer than 5 complete rounds at the freeze; a reference taken at another rho than the capacity gives; argparse errors [JC].

**Other codes:** 4 paused (budget); 5 host unfit (3 host-invalid in a row, 4 in a packet, or a hold not held); 130 or 143 interrupt
("stopped by TERM" when sent to the stage); 3 from `drift` = NOT CONFIRMED, a reading from drift.json. In the foreground, before
anything starts: 2 when the P-1 gate refuses (K20b), 3 when a pre-check refuses; neither writes a log or a summary.
