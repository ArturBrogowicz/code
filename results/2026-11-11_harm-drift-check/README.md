# The harm benchmark's drift check of the calibration frozen on 2026-11-04: failed, then no reading

Every attempt of the drift check that ran between 2026-11-08 and 2026-11-11, published as recorded. **The check never passed.**
The frozen record is therefore not confirmed on the host as it is now, no confirmation campaign (HG3) or protected-arm campaign
(HG4) has run, and **no harm-benchmark result exists**. A re-calibration is planned (the user's direction of 2026-11-12), with its
own pre-registration.

## What the check is and what it judges

The harm benchmark (`docs/BENCHMARK_HARM_DESIGN.md`, `docs/HG1C_DESIGN.md`) measures the host once and freezes what it found in a
calibration record: here `bench/calibration/ddos-mitigation-2026-11-04.json` (file sha256 `55d84b00...`, record hash, its `sha256`
field, `cff6e515acf6f1969435e8843ea79c0c5338be13170a3dc052049928bf1aa0bf`), created 2026-11-04T11:28:31Z on kernel 7.0.0-38 with
9,426 MiB of guest memory. Every later campaign is judged against that record's route costs, capacity, knees and gate floors. Before
a campaign, `bench/calibrate.py drift` checks that the host still reproduces the record's `drift_reference`:

* a 120 s legit-only probe at rho = 42.25 requests/s (seed 41), against Q 100 % and p95 0.0794 s;
* one attack run per family at its knee (seeds 42, 43, 44, timeline 30 + 45 + 30 s), against one reference run each:
  `cheap_static_flood` at level 2 (Q 95.81 %, p95 0.206 s), `costly_export_flood` at 4 (75.32 %, 0.252 s),
  `costly_search_flood` at 4 (63.37 %, 0.631 s).

Q is the share of the legit requests on the judged links that were answered 2xx within their route's SLO, over the window (the
probe's 10-120 s, an attack run's 45 s of attack); p95 is the service time of those served requests (`eval/harm_gate.py
run_metrics`). The check judges the record, not a
mitigation: if it fails, no campaign may use the record.

## The rules

1. **The tool's single-run rule** (design 7.2 step 7 as changed on 2026-11-04 by departure 33 of `docs/HG1C_DESIGN.md`, ledger
   D-062, chosen post hoc from six same-session repeats before any campaign data): the legit probe passes within 2 pp of Q and 25 %
   of p95; an attack run within the record's `gate.floor_pp` (10 pp) and `gate.floor_log2_p95` (1.0, a factor of 2). A failed check
   is made once more (`<dir>.second`); a second failure stops (exit 3). AP-4 was read by this rule alone.
2. **The quiet repeatability pre-registration** (`preregistration/ap5_prereg.md`, sha256 `ded45fe9...`, written 2026-11-08 after
   AP-4 failed, labelled post hoc) and its two dated addenda (`ap5b_prereg_addendum.md`, `bc424344...`, 2026-11-10;
   `ap7_prereg_addendum2.md`, `343125c4...`, 2026-11-11), each written before the runs it governs: three invocations back to back
   with every agent idle; the set A is every attempt that wrote a `drift.json` (AP-4's two included), and every attempt in A counts,
   with no exceptions; the record stands if, for each family, the mean Q over A is within 10 pp and the mean log2 p95 ratio within
   1.0 of the reference, and the legit probe's means within 2 pp and 25 % (rule 1); **no reading** if a step stops before every
   invocation has made its first attempt (rule 5). `preregistration/sha256.txt` lists the three hashes; the texts are byte for byte.

## Every attempt

Times are the guest's clock as the tool wrote them. RAM is MemTotal from each run's `environment.json`. Q in %, with the change
against the reference in pp; n is the number of judged legit requests of that run. "Judged again" is this publisher's verdict from
the published runs (`analysis/drift.json`); T-088 and T-091 recomputed the same runs by two routes each (`recomputation/`).

| Step | Directory | drift.json | RAM MiB | Recorded verdict | Judged again | Legit Q (n) | cheap Q (n) | export Q (n) | search Q (n) | Outside the rule |
|---|---|---|---|---|---|---|---|---|---|---|
| AP-4, attempt 1 | `drift_20261108` | 2026-11-08 09:43:49Z | 9,426 | ok=false | ok=false, agrees | 99.67 (3,035) | 94.70 (1,095) | **55.25** (1,314) | 65.12 (1,359) | export Q -20.07 pp |
| AP-4, attempt 2 | `drift_20261108.second` | 2026-11-08 09:53:54Z | 9,426 | ok=false | ok=false, agrees | 100.00 (3,037) | **78.54** (1,095) | 78.88 (1,307) | 54.22 (1,361) | cheap Q -17.27 pp |
| AP-5 q1, attempt 1 | `drift_20261108_q1` | 2026-11-10 15:42:50Z | 7,422 | ok=false | ok=false, agrees | 100.00 (3,039) | 95.25 (1,094) | **85.39** (1,314) | 61.95 (1,356) | export Q +10.07 pp |
| AP-5 q1, attempt 2 | `drift_20261108_q1.second` | none | 7,422 | none: cut by host reset 6 in its legit probe | none | – | – | – | – | not in A |
| AP-5b q1, attempt 1 | `drift_20261110b_q1` | none | 7,422 | none: cut by host reset 7 in its search run | none | 100.00 (3,037) | 82.53 (1,093) | 76.24 (1,313) | – | not in A (descriptive) |
| AP-7 q1, attempt 1 | `drift_20261111c_q1` | 2026-11-11 18:51:45Z | 7,422 | ok=false | ok=false, agrees | **97.00** (3,035) | **10.71** (1,092) | 68.67 (1,312) | **74.96** (1,362) | legit Q -3.00 pp; cheap Q -85.09 pp and p95 x2.97; search Q +11.59 pp and p95 /2.12 |
| AP-7 q1, attempt 2 | `drift_20261111c_q1.second` | 2026-11-11 19:04:44Z | 7,422 | ok=false | ok=false, agrees | 100.00 (3,038) | 95.89 (1,096) | **86.06** (1,313) | 57.55 (1,364) | export Q +10.74 pp |
| AP-7 q2, attempt 1 | `drift_20261111c_q2` | none | 7,422 | none: stopped with exit 2 in its search run (the origin refused to start) | none | 100.00 (3,034) | 72.12 (1,094) | 25.13 (1,313) | – | not in A (descriptive) |

In every recorded verdict the legit probe's p95 and every attack run's p95 are inside the rule except where the last column says
otherwise. Recorded and judged-again values agree to full precision, and the verdicts and their reasons are the same text
(`analysis/summary.md`). Runs kept aside by the tool (an unsound run made again once) are in the directories as `U.failed1` and
are not judged: `drift_20261108` (cheap), `drift_20261110b_q1` (export), `drift_20261111c_q1.second` (search) and
`drift_20261111c_q2` (search: the first run unsound when the origin refused its start-up check, the second failed at set-up,
`FAILED`). Q and p95 of the complete runs of a directory without `drift.json` are descriptive only, never a verdict.
`analysis/runs.json` lists every run with its state and the executor's reasons.

## The reading of each step

* **AP-4 (2026-11-08, 9,426 MiB): failed twice** by the tool's rule. Attempt 1: export Q 55.25 against 75.32 (-20.07 pp).
  Attempt 2: cheap Q 78.54 against 95.81 (-17.27 pp). Legit probe and every p95 inside.
* **AP-5 (2026-11-10 from 15:32Z, 7,422 MiB): no reading** (rule 5). Host reset 6 cut q1's second attempt during its legit probe
  (`drift_20261108_q1.second`: 40 files, no `run.json`); q2 and q3 never started. Its one complete attempt fails the single check:
  export Q 85.39 (+10.07 pp).
* **AP-5b (2026-11-10 from 16:49Z, 7,422 MiB): no reading** (first addendum, point 3). Host reset 7 cut q1 in its fourth run, the
  search attack (no `run.json`), so it wrote no `drift.json` and is outside A (second addendum, point 2; ledger D-085); q2 and q3
  never started. Its sound runs (legit 100, cheap 82.53, export 76.24) are descriptive only.
* **AP-7 (2026-11-11 from 18:39Z, 7,422 MiB): no reading** (rule 5, second addendum point 3). q1's two attempts each wrote a
  `drift.json` and each fails the single check; q2 stopped with exit 2 inside its first attempt, when the origin refused its own
  start-up cost check (below), and q3 never started. There was no host reset.

**Why three steps gave none:** two host resets (AP-5, AP-5b) and, in AP-7, a host that ran too slowly for the origin to start.
After AP-7, by the second addendum's point 7, nothing more runs under this pre-registration without a new decision by the user.

## AP-7's two disturbances

1. **Inside q1's first attempt** (ledger C-129). From 18:44:51Z to 18:47:10Z the session that had started AP-7 was compacted by
   hand. In those minutes the app's remote-session processes on the VM and sshd used 40-60 % of a CPU, in bursts every 15 s during
   which all eight CPUs were 80-87 % busy for most of a 5 s sample (`ap7_monitors/mpstat.txt`, `pidstat.txt`). The legit probe
   (18:43:36-18:45:37Z, Q 97.00) and the cheap run (18:45:54-18:47:40Z, Q 10.71: 601 slow and 374 timed out of 1,092) lie in that
   window; the same cheap run, same seed, ten minutes later on a quiet guest gave 95.89. The pre-registration's "quiet" condition
   was not met for that attempt, **and the rule keeps it**: "every attempt that ran counts, with no exceptions". That the
   compaction caused the result is an inference, a strong one.
2. **q2** (ledger C-130). From about 19:10Z the guest ran slower with nothing else active in it: the same plans cost 25 % (cheap)
   and 36 % (export) more CPU than 14-16 minutes earlier; q2's cheap run gave Q 72.12 and its export run Q 25.13 (no `drift.json`:
   descriptive). The origin then refused its own start-up cost check (25 %, thread CPU time) four times: at 19:14:39Z by C2 +59 %,
   C3 +46 %, C5 +34 %, and at 19:17:03Z by all five routes, +26 to +68 % (`ap7_monitors/ap7_console.txt`; the `gunicorn.log` of
   `drift_20261111c_q2/drift/attack_costly_search_flood/U` and `U.failed1`). The guest cannot see the cause; that it lies outside
   the guest (host load, power or thermal state) is an inference.

## The speed series after AP-7 (ledger C-133)

The origin's own self-measurement, alone and offline, every 5 minutes on CPU 0 and on CPU 1 against the frozen route costs, from
19:27:36Z to 21:19:54Z (`speed_series/speed_series.txt`, made by `speed_series.sh` and `speed_probe.py`): of 46 probes the origin's
own 25 % check accepted 22 and refused 24. Both CPUs accepted at 8 sample times, both refused at 9, one of two at 6. The CPU-bound
routes C3 and C5 were +18 to +38 % above the frozen costs where both refused and -2 to +11 % where both accepted: slow until 19:37,
normal at 19:42, slow 19:47-19:53, normal 19:58-20:23, slow 20:28-21:09, normal 21:14-21:19. The guest was idle throughout: its own
10-minute records show 99.76-99.82 % idle and a 1-minute load of at most 0.22 in every interval between 19:40 and 21:10Z
(`speed_series/sar_evening_20261111.txt`). So the host's speed comes and goes for a few minutes to about 50 minutes at a time (the probe times bound the slow stretches
at 27-32, 6-16 and 41-51 minutes; ledger C-135), and a check made before
a run cannot vouch for the run.

## What the result means

* The record of 2026-11-04 is **not confirmed** on kernel 7.0.0-42: no drift check passed, and every complete attempt (5 of 5)
  fails the single-run rule, some above and some below the reference: export -20.07, cheap -17.27, export +10.07, cheap -85.09 (with
  legit -3.00 and search +11.59, the disturbed attempt), export +10.74 pp.
* Rule 1's arithmetic over A (n = 5) is descriptive here, not a reading, because the pre-registration gives no reading: mean Q legit
  99.33, cheap 75.02 (-20.79 pp, outside the 10 pp floor), export 74.85 (-0.47), search 62.76 (-0.61); SD of Q 36.7 / 13.0 / 8.0 pp.
  Without the disturbed attempt, an exclusion the pre-registration does not allow, cheap would be 91.10 (-4.71).
* **No harm-benchmark result exists**: no campaign has been judged against this record, and none may be.
* The host differs from the record's in ways the tool does not compare: kernel 7.0.0-42 against 7.0.0-38 (the record was measured
  on -38; by the ledger, C-115, -42 was installed during the calibration session and first booted on 2026-11-05), and 7,422 MiB
  of memory from AP-5 on. Nothing here tells which of these, the host's instability or the spread of single runs at a knee, made
  the attempts fail.
* Known limits of the check, stated before AP-7 (second addendum, point 6): each attack reference is one run; the drift runs use
  other seeds, and through them other links for the attack sources, than the reference.

## Contents

* `drift_20261108/`, `drift_20261108.second/` (AP-4), `drift_20261108_q1/`, `drift_20261108_q1.second/` (AP-5),
  `drift_20261110b_q1/` (AP-5b), `drift_20261111c_q1/`, `drift_20261111c_q1.second/`, `drift_20261111c_q2/` (AP-7): the tool's
  directories as written, every file, the cut ones included. Each run is a directory of the run contract (`plan.json`, `run.json`,
  `environment.json`, `DONE`, `executor.log`, the Nginx and gunicorn logs, `server.csv`, and per load stream its records and
  summary).
* `steps/`: each step's host snapshots before and after (`*_before/`, `*_after/`), `free -m`, `vmstat` and the step's console
  (`*_output.txt`), as the step helper wrote them. AP-5 and AP-5b have no after-snapshot (the host reset).
* `preregistration/`: the three texts above, byte for byte, and their sha256.
* `ap7_monitors/`: AP-7's `mpstat -P ALL 5`, `pidstat -u 10` and chrony records, and its console.
* `recomputation/T-088/`: an independent recomputation of AP-4, AP-5 and AP-5b from the raw records by two routes (the
  repository's functions at 1cdda9b, and the script's own few lines) and of the reference; `recomputation/T-091/`: the same script
  extended to AP-7's directories, and the script that read the AP-7 monitors. They read the directories under `/var/tmp`, of which
  these are the copies. `recompute_stdout.txt` of T-091 ends in a traceback where it prints q2's search run kept aside (no request
  was served, so it has no p95); its JSON was written before that.
* `speed_series/`: the speed series, its two scripts and the guest's sar records of that evening.
* `analysis/`: written by `eval/publish_campaign.py` from the published files: `runs.json` (each run's state and provenance),
  `drift.json` (each attempt's recorded verdict beside the one judged again), `summary.md`.
* `SHA256SUMS`: every file.

## Provenance and redactions

* Every run was made at commit `1cdda9b` (GitHub main) with a clean tree, against the record named above (`analysis/runs.json`).
* Source: the backup `drift_20261112` made on 2026-11-12 from `/var/tmp/ddos_campaigns` and `/var/tmp/hg1c_scratch`, 3,666 files,
  every one equal to its manifest line when this entry was made.
* Sixteen files under `steps/` differ from the backup: in the eight `links.txt` the hardware addresses of the VM's own network
  cards are replaced by `xx:xx:xx:xx:xx:xx`, and in the eight `ps.txt` the command lines of the Claude app's processes are replaced
  by a marker (PID, PPID and user stay). `steps/REDACTIONS.tsv` gives each file's sha256 in the backup and as published. Nothing
  else is changed or left out.
* Re-check: `sha256sum -c SHA256SUMS`; judge again with
  `venv/bin/python eval/publish_campaign.py results/2026-11-11_harm-drift-check/drift_* --name <scratch>` (it writes `results/<scratch>/`).
