# The laptop re-calibration of the harm benchmark (R1-R4, 2026-11-15/16): FROZEN, then CONFIRMED

The harm benchmark judges a defence against a calibration record of the host it runs on: the cost of each route, the capacity, each
attack family's knee, and a reference that a drift check must reproduce before a campaign. The record of 2026-11-04
(`bench/calibration/ddos-mitigation-2026-11-04.json`) was made on the desktop PC and was never confirmed there: its drift checks
failed or gave no reading (`results/2026-11-11_harm-drift-check/`). When the programme moved to a laptop, the pre-registered host
check HS1 (2026-11-14) found the laptop's route probes 42-50 % slower than that record on routes C1-C5 [ledger RES-05], so the record
could not be used there. The benchmark was therefore calibrated again on the laptop, in one session directory, `recal_2026-11`,
under a pre-registration approved before any of its data. This folder publishes that session whole, every file as the tools wrote it
apart from the gzip and the redactions listed below, with every packet's log, the launcher logs, the paired checks P-1, the approval
packets and the decisions quoted from the ledger, and a recomputation of every step from the published runs.

| Step | What | Packet(s) | Approval | Pin | When (UTC) | Runs | The step's own verdict |
|---|---|---|---|---|---|---|---|
| R1 | speed hold, origin (route costs), capacity | `R1_20261115T180935Z` | AP-11 | `5f3769c` | 2026-11-15 18:09:35-18:32:45 | 3 staged | done (exit 0): C_slo 84.5, C_sat 241.3 req/s |
| R2a | ladder of `cheap_static_flood`, seed 21 | `R2a_20261115T184751Z`, `R2a_20261116T004408Z` | AP-12, AP-13 | `5f3769c` (runs 01-11), `9c0c25a` (12-18) | 2026-11-15 18:47:51-19:49:29; 2026-11-16 00:44:08-01:08:28 | 18, and 4 set aside | packet 1: host unfit (exit 5); packet 2: done (exit 0): session valid, knee 4.0 |
| R2b | ladder of `costly_export_flood`, seed 22 | `R2b_20261116T011009Z` | AP-13 | `9c0c25a` | 2026-11-16 01:10:09-02:04:01 | 18 | done (exit 0): session valid, knee 4.0 |
| R2c | ladder of `costly_search_flood`, seed 23 | `R2c_20261116T080612Z` | AP-14 | `9c0c25a` | 2026-11-16 08:06:12-09:00:05 | 18 | done (exit 0): session valid, knee 2.0 |
| R3 | the reference, 5 rounds, seeds 41-44 | `R3_20261116T090112Z` | AP-14 | `9c0c25a` | 2026-11-16 09:01:12-10:01:11 | 20 | done (exit 0) |
| F | the freeze (`bench/calibrate.py freeze`, offline) | none | "Yes, freeze now" | `9c0c25a` | 2026-11-16 10:05:07 (the record's `created_utc`) | none | FROZEN [ledger RES-11]: record `7005a2ed` |
| R4 | the confirmation, 3 rounds, after a reboot | `R4_20261116T115437Z` | AP-15 | `ec819fb` (`9c0c25a` + the record) | 2026-11-16 11:54:37-12:33:08 | 12 | done (exit 0): "drift: within the frozen reference"; **CONFIRMED** for legit and every family, `costly_export_flood` with the D6 label |

The times are each packet's log, from its first line to its last exit line; a packet's first 5-6 minutes are its speed hold. The runs
are counted from the run directories (`run.json`), and the pins from each run's `environment.json` (`git.commit`, every run with a
clean tree). Every run of all seven packets is executor-sound and, but for the four set aside, host-valid by its own `DONE`.

## The pre-registration, before the data

* **`docs/RECALIBRATION_2026-11_PREREG.md`** (sha256 `5c22334dfb68f88ecb3a33161b91f9848ccdd2819b99e6419b5c715047bd269c` at
  `c6579fd`, the same file as at the pin `5f3769c`, which added it). Approved by the user on 2026-11-15 at 15:57:03Z ("Approve as
  recommended", ledger D-104), before any command of R1 (its first paired check began at 17:24:54Z,
  `packets/r1_launch_20261115T172154Z.log`). It fixed the code (the pinned
  commit), the seeds, the steps, the host rules H1-H7, the readings and what may be made again. With it the user chose P-1 as a rule
  (the paired check of the two probe contexts before R1, enforced by the packet) and P-2 option B (the capacity levels 29.6-530.2 req/s,
  12 levels); its section 11 records the decisions.
* **`docs/HS1_PREREG.md`** (sha256 `c977b47d53974c45307dcebbbdc7e449e63af4de7128066b4386c2fe8857a246` at `c6579fd`): the host check
  whose medians are R1's speed reference (`recal_2026-11/speed_reference.json` names them).
* **`docs/RECALIBRATION_2026-11_DEPARTURE_1.md`** (sha256 `947ca1c733787d560d562b487ac86e05f34a50016d9baf4f98c3582e9a0b1b93` at
  `c6579fd`): departure 1, below.
* **The rules the readings use** (prereg 4 and 6): FROZEN when R1, R2a-c and R3 are complete with valid runs, every ladder session is
  valid by its own rule (four healthy controls within 2 pp of each other) and `freeze` accepts the session; the reference is the first
  5 valid rounds, each a 120-s legit probe at rho (Q and p95 over 10-120 s) and one attack run per family at its knee (Q and p95 over
  the 45 s of attack); per family the tolerances are T_Q = min(10, max(5, k s)) pp and T_L = min(1.0, max(0.5, k t)) on log2 p95, s
  and t the reference's SDs and k = 3 sqrt(1/5 + 1/3) = 2.19089; a family whose SD of Q is above 5 pp is frozen with its spread and
  labelled in every verdict at its knee (D6). R4 reads the first 3 valid rounds: a family is CONFIRMED when the legit probe passes
  (mean Q within 2 pp, 2^(difference of the mean log2 p95) within 0.75-1.25) and the family's |mean Q - reference| <= T_Q and
  |mean log2 p95 - reference| <= T_L; bounds inclusive; no second attempt. A run's harm is the larger of dQ / 10 pp and
  log2(p95 / the controls' mean p95), dQ being the controls' mean Q less the run's, so that 1 is the gate's floor (`bench/calibrate.py`
  `harm`); a ladder's knee is the lowest level whose harm reaches 1 in both repeats (`bench/calibration.py` `knee`).
* **The approval packets and the ledger's rows** are in `preregistration/` (below). Done outside the pre-registration's text, and
  recorded with their times [ledger]: the orchestrator, not the user, started each packet's launcher on the user's word (D-106); the
  guest's unattended-upgrades service was disabled before R1's second attempt, because the pre-check's job test had refused the first
  (D-107, `packets/r1_launch_20261115T172154Z.log`: "NO  jobs: a package job runs", exit 3, nothing started).

## Departure 1 (post hoc): the end-of-window check H7 waits 2 s

**Labelled post hoc** (prereg section 3: a change after data it governs). R2a's first packet paused "host unfit" (exit 5) at
19:49:29Z: 4 of its runs had been set aside, each by H7 alone, because the judge read the monitors' records as soon as the run's window
ended and a sample due in the next second was not in the file yet (`docs/RECALIBRATION_2026-11_DEPARTURE_1.md`, ledger C-156). On
the user's "Fix H7 first" (D-108), K22 made the judge wait until 2 s after the window's end before it reads the monitors' records; H7's
text, its thresholds and every other rule are unchanged. The new pin `9c0c25a` (D-109) is `5f3769c` plus K22 and the departure note.

* **Judged at the window's end, at `5f3769c`:** R1's 3 capacity runs, R2a's runs 01-11 and the 4 set-aside runs.
* **Judged 2 s after the window's end, at `9c0c25a` or `ec819fb`:** R2a's runs 12-18, all of R2b, R2c, R3 and R4. So R2a's ladder
  spans both sides of the departure, and everything that rests on runs after it (the knees, the reference, the record and R4) rests on
  the departure.
* **The four set-aside runs** (`HOSTINVALID` in each; prereg 5.1 and 7: kept, published with their reasons and their Q and p95,
  descriptive only, never used; the Q and p95 are recomputed in `recomputation/recompute_from_runs.out`):

  | Run (`recal_2026-11/ladder_cheap_static_flood/`) | Reason (`HOSTINVALID`; the run's window, UTC) | Q, p95 (descriptive) |
  |---|---|---|
  | `05_control1/C.hostinvalid1` | H7: the mpstat record does not cover the run (19:03:58-19:06:33) | 100.00 %, 79.8 ms |
  | `05_control1/C.hostinvalid2` | H7: the pidstat record does not cover the run (19:12:11-19:14:48) | 100.00 %, 82.7 ms |
  | `11_L0.125_r2/U.hostinvalid1` | H7: the mpstat record does not cover the run (19:36:06-19:38:39) | 99.91 %, 83.6 ms |
  | `12_L2_r1/U.hostinvalid1` | H7: the mpstat and the chrony records do not cover the run (19:46:56-19:49:29) | 99.56 %, 138.7 ms |

  Each was made again with the ladder's seed (21): the first three in packet 1 (at `5f3769c`), `12_L2_r1` in packet 2 (at
  `9c0c25a`). The ladder uses the remakes only.

## The steps

**R1** (RES-06). The speed hold against HS1's medians held after 2 probe pairs (+1.09 %, +0.71 %; 336 s). The origin step (estimator
version 2, CPU 0, 21 repeats) measured the route costs C0 0.005547, C1 5.113, C2 2.651, C3 42.712 and C5 231.960 ms
(`origin/origin.json`). The capacity step ran 3 staged runs (seeds 11-13) through 12 levels, 20 s each, Q read over 5-17 s of each step
(`capacity/capacity.json`):

| level (req/s) | 29.6 | 38.5 | 50.0 | 65.0 | 84.5 | 109.9 | 142.8 | 185.6 | 241.3 | 313.7 | 407.9 | 530.2 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Q % repeat 1 | 100.0 | 100.0 | 100.0 | 100.0 | 99.80 | 98.18 | 97.17 | 69.32 | 0.06 | 0.0 | 0.0 | 0.0 |
| Q % repeat 2 | 100.0 | 100.0 | 100.0 | 100.0 | 99.69 | 98.53 | 96.86 | 67.83 | 0.10 | 0.0 | 0.0 | 0.0 |
| Q % repeat 3 | 100.0 | 100.0 | 100.0 | 99.80 | 100.0 | 99.63 | 97.65 | 71.62 | 10.02 | 0.0 | 0.0 | 0.0 |

C_slo is the last level before the first at which any repeat is below 99 % (109.9): **84.5 req/s**; C_sat the lowest at which at
least 2 repeats are below 50 %: **241.3 req/s**. rho, the legit load of every later run, is half of C_slo: 42.25 req/s. (Every repeat
keeps Q at 99.69 % or more up to 84.5 req/s; the ledger's RES-06 rounds this to 99.7 %. Where a ledger figure and a file differ in
the last digit, as also 0.047 in RES-07 for the 0.0465 of `cheap_static_flood` at 0.25, repeat 1, the files' figures are given here.)

**R2a** (RES-07), `cheap_static_flood`. Two packets: the first made runs 01-11 and set 4 aside (above), then paused; the second, after
departure 1 and AP-13, made 12_L2_r1 again and runs 13-18. Session valid; **knee 4.0** (passing 4 and 8), dose-response monotone.
Controls Q 100 / 100 / 100 / 100 %, p95 80.2-82.0 ms.

**R2b** (RES-08), `costly_export_flood`. Session valid; **knee 4.0** (passing 4 and 8). The dose-response is **not monotone**, at the
bottom only: mean harm 0.016 at 0.125, 0.011 at 0.25, 0.015 at 0.5 (reported beside the verdict, not a rule). Controls Q 100 % x 4,
p95 84.7-85.7 ms.

**R2c** (RES-09), `costly_search_flood`. Session valid; **knee 2.0** (passing 2, 4 and 8), monotone. Controls Q 100 / 100 / 100 /
99.92 %, p95 74.8-79.3 ms.

The harm of each attack run (1 = the floor; repeat 1 / repeat 2), from each `ladder_<family>/ladder.json`:

| level | 0.125 | 0.25 | 0.5 | 1 | 2 | 4 | 8 |
|---|---|---|---|---|---|---|---|
| cheap_static_flood | 0.006 / 0.029 | 0.046 / 0.026 | 0.100 / 0.120 | 0.235 / 0.249 | 0.538 / 0.524 | **9.62 / 9.59** (Q 3.8 / 4.1 %) | 9.91 / 9.91 (Q 0.9 / 0.9 %) |
| costly_export_flood | 0.000 / 0.032 | 0.009 / 0.013 | 0.008 / 0.023 | 0.164 / 0.204 | 0.479 / 0.409 | **6.83 / 6.37** (Q 31.7 / 36.3 %) | 9.42 / 9.62 (Q 5.8 / 3.8 %) |
| costly_search_flood | 0.154 / 0.083 | 0.273 / 0.184 | 0.365 / 0.506 | 0.655 / 0.604 | **1.53 / 1.33** (p95 222 / 193 ms; Q 97.1 / 97.3 %) | 7.18 / 7.10 (Q 28.1 / 28.9 %) | 9.14 / 9.70 (Q 8.6 / 2.9 %) |

**R3** (RES-10), the reference: rounds 1-5, the first 5 made, all 20 runs host-valid and sound (none added, dropped or replaced), at
rho 42.25 req/s and the knees 4 / 4 / 2. Per probe (`reference/reference.json`; Q in %, SD in pp; p95 as the geometric mean in ms and
the SD of log2 p95):

| | n | Q mean | Q SD | Q min-max | p95 (geometric mean) | SD log2 p95 | log2 p95 min-max |
|---|---|---|---|---|---|---|---|
| legit probe | 5 | 99.99 | 0.01 | 99.97-100.0 | 80.6 ms | 0.027 | -3.671 to -3.603 |
| cheap_static_flood @ 4 | 5 | 4.66 | 1.58 | 2.65-7.04 | 871.9 ms | 0.118 | -0.354 to -0.063 |
| costly_export_flood @ 4 | 5 | 45.48 | **5.77** | 38.14-54.09 | 585.2 ms | 0.278 | -1.148 to -0.386 |
| costly_search_flood @ 2 | 5 | 98.12 | 0.60 | 97.21-98.75 | 197.2 ms | 0.044 | -2.388 to -2.287 |

`costly_export_flood`'s SD of Q, 5.77 pp, is above 5 pp: by D6 it is frozen with its spread and labelled ("wide spread") in every
verdict at its knee.

**F, the freeze** (RES-11). `bench/calibrate.py freeze --dir <the session> --out bench/calibration/ddos-mitigation-2026-11-16.json`
once, at `9c0c25a`, on the user's "Yes, freeze now" (FROZEN, exit 0 [ledger]). The record is cited, not copied:
**`bench/calibration/ddos-mitigation-2026-11-16.json`**, file sha256 `e6b88a8564bbd67c507e1489aae9084ff550fabcb063865e5fd3dd230950bef4`,
record hash (its `sha256` field) `7005a2edfcbf0acae1737b0a384f52aaa28169f6193fdd56e53eb48d4f2fb01c`, schema 2, `created_utc`
2026-11-16T10:05:07+00:00; committed at `ec819fb` (D-110) and the same file at `c6579fd`. Recomputed from this folder below.

**R4** (RES-12), the confirmation, after the user rebooted the guest (the launcher saw an uptime of 91 s at 11:21:06Z,
`packets/r4_launch_20261116T112106Z.log`): rounds 1-3, the first 3 made, 12 runs, all host-valid and sound, at `ec819fb` on the
frozen record (`confirmation/drift/drift.json` names `7005a2ed`). **CONFIRMED for legit and for every family**; `drift` exit 0:

| | Q per round % | mean Q against the reference (difference; T_Q) | mean log2 p95 against the reference (difference; T_L) | reading |
|---|---|---|---|---|
| legit probe | 100 / 100 / 100 | 100.00 against 99.99 (+0.007 pp; 2 pp) | p95 ratio 1.019 (band 0.75-1.25) | passes |
| cheap_static_flood @ 4 | 6.04 / 2.83 / 4.20 | 4.36 against 4.66 (-0.30 pp; 5) | -0.274 against -0.198 (-0.076; 0.5) | CONFIRMED |
| costly_export_flood @ 4 | 45.46 / 49.73 / 48.70 | 47.97 against 45.48 (+2.48 pp; 10) | -1.200 against -0.773 (-0.427; 0.609) | CONFIRMED, **wide spread (D6)** |
| costly_search_flood @ 2 | 95.44 / 96.84 / 97.06 | 96.45 against 98.12 (-1.67 pp; 5) | -2.277 against -2.343 (+0.065; 0.5) | CONFIRMED |

`costly_export_flood`'s p95 difference uses 70 % of its tolerance, toward lower latency. By prereg 9 (FROZEN, then CONFIRMED for
legit and cheap) P2 could run on the record; it is published as `results/2026-11-16_harm-p2-hg4/`.

## The record (`bench/calibration/ddos-mitigation-2026-11-16.json`)

* **Route costs (ms):** C0 0.005547, C1 5.113, C2 2.651, C3 42.712, C5 231.960 (R1's origin step).
* **Capacity:** C_slo 84.5 req/s, C_sat 241.3 req/s; rho 42.25 req/s.
* **Knees:** `cheap_static_flood` 4, `costly_export_flood` 4, `costly_search_flood` 2.
* **Drift reference (schema 2):** n 5, m 3, c 3, k 2.19089; per family the means and SDs of the table above and the tolerances
  `cheap_static_flood` 5 pp / 0.5, `costly_export_flood` 10 pp / 0.609 (**wide_spread true, D6**: SD of Q 5.77 pp),
  `costly_search_flood` 5 pp / 0.5; the legit probe within 2 pp and its p95 within 25 %. Seeds: legit 41, attacks 42 / 43 / 44.
* **Host:** the laptop, CPU `AMD Ryzen 7 7730U with Radeon Graphics`, VirtualBox host `7.2.10r174163`; the guest with 8 vCPUs,
  7,422 MiB, kernel `7.0.0-42-generic` (`uname` as in every run's `environment.json`); Nginx 1.28.3, gunicorn 26.2.0 (2 workers x 8
  threads), pins server 0-1, daemon 2, attack 3-6, legit 7. `recal_2026-11/host.json` (written at the session's first step) names the
  same CPU, VirtualBox, kernel and memory.
* **Beside the record of 2026-11-04 (the desktop; descriptive only, prereg 10):** costs C1 3.407, C2 1.774, C3 29.838, C5 159.705 ms
  there against 5.113, 2.651, 42.712, 231.960 here (+50, +49, +43, +45 %); C_slo and C_sat the same two points of the level grid
  (84.5, 241.3); knees cheap 2 there and 4 here, export 4 and 4, search 4 there and 2 here. The old record stays frozen and unused on
  the laptop.

## Recomputation (`recomputation/`)

Everything above was recomputed offline from a copy of this published folder, in a sandbox without network, with the project's own
functions at `c6579fd`: `recompute_from_runs.py`, its output `recompute_from_runs.out`, and the records it wrote. `bench/calibrate.py`,
`bench/calibration.py`, `bench/calibration/placeholder.json` (the template) and all of `eval/` are the same files at `c6579fd` as at
the freeze's pin `9c0c25a`; `bench/executor.py` differs (K23, for P2) but not in the two constants the freeze reads from it
(`ORIGIN_SEED`, `GUNICORN`).

* **Capacity:** the Q of all 36 steps from the 3 staged runs (`metrics_by_step`), and C_slo, C_sat from them (`capacity_of`).
* **Ladders:** every run's Q and p95 from its request records (`harm_gate.run_metrics`), then `analyse_ladder`: the controls, every
  attack run's harm, the session's validity and the knee, for all three families.
* **Reference:** every round's legit probe and attack runs (`probe_metrics`, `attack_metrics`).
* **Freeze:** `freeze_step` on the copy with the committed record's `created_utc`, written with `calibration.dump`: **byte-identical
  to the committed record** (record hash `7005a2ed...`). The command itself (`bench/calibrate.py freeze --dir <copy> --out ...`) was
  run too: `freeze_cli_record.json`, which differs from the committed record only in `created_utc` (the time it ran) and therefore
  in its `sha256` field (`freeze_cli_compare.txt`).
* **R4:** every round's Q and p95 from the runs under the frozen record, then the verdict judged again (`judge_rounds`, and
  `judge_drift` on `drift.json`'s own rows): ok, every family confirmed, no reason.

Result: **0 mismatches**. What is compared, and only that: `capacity.json`'s `q_pct`, `c_slo_rps`, `c_sat_rps` and
`first_unhealthy_rps`; each `ladder.json`'s `controls`, `levels` (every attack run's Q, p95, harm and its two parts), `valid`,
`reasons` and `knee`; `reference.json`'s `rounds` (Q, p95, requests, level, seed and run of every probe); every field of the committed
record, and its bytes; `drift.json`'s `rounds` and its `check`, `confirmed`, `ok` and `reasons`. The other fields of the steps'
files (among them `waits`, `created_utc`, `sequence`, `pins`, `under` and the capacity's `stack_cost`) are not compared. All 737
numbers compared are bit-equal. The figures come from the request records (`loadgen.records.csv.gz`), `run.json`, `plan.json` and the
stream summaries; the compressed logs do not enter them.

## Contents

* `recal_2026-11/`: the session directory as it stood after R4, the files of R3's tar and R4's tar:
  * `host.json`, `speed_reference.json` (R1's speed hold against HS1's medians), `origin/origin.json`;
  * `capacity/` (`capacity.json`, `r1`-`r3/C`: the staged runs);
  * `ladder_<family>/` (`ladder.json`, and per run `NN_L<level>_r<repeat>/U` or `NN_control<k>/C`; the set-aside runs beside their
    remakes as `C.hostinvalid<k>`, `U.hostinvalid1`);
  * `reference/` (`reference.json`, `r1`-`r5`, each `legit/C` and `attack_<family>/U`);
  * `confirmation/drift/` (`drift.json`, `r1`-`r3`) and `confirmation/monitors/1/` (R4);
  * `monitors/1`-`6`: `mpstat`, `pidstat`, chrony and the journal over each packet of R1-R3 (1: R1, 2 and 3: R2a's two packets, 4:
    R2b, 5: R2c, 6: R3).

  Each run is a directory of the run contract: `plan.json`, `run.json`, `environment.json`, `DONE` (the host check), `executor.log`,
  the Nginx and gunicorn logs, `nginx.conf`, `server.csv`, `server_requests.csv`, and per load stream its request records
  (`loadgen.records.csv.gz`, compressed by the tool) and summary.
* `packets/`: each packet's log and its tar's `.sha256` (R1, R2a's two, R2b, R2c, R3, R4), the six launcher logs
  (`r1_launch_*` twice: the first refused by the pre-check, `r2_launch_*`, `after_timers_launch_*`: AP-13's waiter and launch after
  the midnight timers, `r_launch_*`: AP-14, `r4_launch_*`), and two checks of this publication: `prefix_chain_check.txt` and
  `live_comparison.txt` (below).
* `paired/`: the two paired checks P-1 (`paired.json`, `probes.jsonl`): 17:24:54Z, D +0.14 % (GO ON; R1 then refused by the
  pre-check), and 18:07:27Z, D +0.03 % (GO ON; R1 ran), each within the 5 % limit.
* `preregistration/`: the approval packets AP-11 to AP-15 (`sha256.txt`; `approved_revisions.tsv` says, per file, whether it is the
  revision the ledger records for the yes; for AP-13 both the approved revision and the file as later filled in, see below), and
  `decisions.md`, which quotes verbatim the ledger rows D-104, D-106, D-107, D-108, D-109 and D-110 and the approval rows of the
  pre-registration, AP-11, the unattended-upgrades change, AP-12, "Fix H7 first", AP-13, AP-14, the freeze and AP-15, each with the
  user's answer.
* AP-13's approved revision was no longer kept as a file: the packet was filled in 25 min after the yes. Both are published.
  `preregistration/AP-13_R2a_resume_R2b.md` is the approved revision, byte for byte (sha256 `af1d1517c20f25cd...`, the hash the
  ledger records for the yes): the text the orchestrator wrote at 2026-11-15T20:17:59Z, recovered on 2026-11-17 from its session
  record of that write. It carries `<PIN>` and `<GATE>` placeholders, as the approval says ("pin and gate to be filled in").
  `preregistration/AP-13_R2a_resume_R2b.after-approval.md` is the file as last written (2026-11-15T21:32:42Z), **not** the approved
  revision. `AP-13_approved_vs_after-approval.diff` shows what changed: the pin `9c0c25a...` and its gate filled in, the plans printed
  with that pin recorded, and the status lines changed to approved. Nothing else changed.
* `recomputation/`: above.
* `analysis/`: written by `eval/publish_campaign.py` from the published files: `runs.json` (each run's state and provenance) and
  `summary.md`. The publisher judges only drift checks of the older layout (a `drift/` directory at the top of a source, schema 1),
  so it gives these runs no verdict; R4 is judged again in `recomputation/`. It lists `plan.json` as absent for the three capacity
  runs, whose `plan.json` is published as `plan.json.gz`.
* `GZIPPED.tsv`, `REDACTIONS.tsv`, `SHA256SUMS`.

## Provenance, size and redactions

* **Source:** the backup `recal_2026-11` of the agent workspace, equal to its manifest (`sha256sum -c`, 32 files) when this folder was
  made, and each packet tar equal to its own `.sha256` (published in `packets/`).
* **One directory, seven snapshots.** Each packet's tar is a snapshot of the same session directory at the end of its packet: R1-R3's
  hold the whole directory but its `packets/`; R4's holds `confirmation/` but its `packets/`. `packets/prefix_chain_check.txt`
  compares them file by file: every file of R1's tar is byte-identical in R2a's first, and so on through R2a's second, R2b, R2c and
  R3, **no file differs and none is missing** along the chain (no resume rewrote a file: a ladder writes its `ladder.json` only when
  it completes); R4's tar shares no path with R3's. The published `recal_2026-11/` is R3's tar plus R4's, 13,736 files;
  `packets/live_comparison.txt` compares it with the session directory still on the VM: **all 13,736 files byte-identical, none
  missing or extra**, and the VM's `packets/` and `confirmation/packets/` (the tars, logs and sha256 files) equal to the backup. The
  tars themselves are not published.
* **Compression, lossless:** the 19 text files over 1 MB (1,000,000 bytes) are stored as `<name>.gz` (`gzip -n -9`): the seven
  `pidstat.txt` (after their redaction), the `nginx_error.log` of the 3 capacity runs and of the 6 attack runs at level 8, and the
  3 capacity runs' `plan.json`; 119.6 MB become 12.0 MB. `GZIPPED.tsv` gives each one's original size and sha256
  (`gzip -dc <file> | sha256sum` returns it) and the published sha256. Nothing else is changed. The request records and the
  access logs were compressed by the tools themselves.
* **Size:** the folder is 13,783 files (with `SHA256SUMS`) and 92,765,995 bytes (88.5 MiB); its largest file is `SHA256SUMS`
  (2,252,869 bytes); the largest data file is `recal_2026-11/monitors/6/pidstat.txt.gz` (1.8 MB). It is under 95 MB with the
  1-MB threshold, so the lower threshold the publication's brief allowed (64 KiB) was not used. The publisher warns above 20 MiB
  and refuses over 100 MiB.
* **Redactions:** in the seven `pidstat.txt` (before their compression) the command of every line naming a path under `~/.claude`,
  the Claude app's processes on the VM with their session ids, socket paths and token-file names, is replaced by a marker; the time,
  UID, PID and CPU columns stay (2,135 lines). `REDACTIONS.tsv` gives each file's sha256 in the packet tar, after the redaction and as
  published. The host-check records (`DONE`) keep the process names as the tool cut them to 60 characters, such as
  `/home/artur/.claude/remote/ccd-cli/2.1.325-1ef04b37a794 --ou` and `/home/artur/.claude/remote/srv/87375cc7c944eb9d45c8d9267edc7`
  (a program version and an install directory: no session id, socket or token), as in `results/2026-11-16_harm-p2-hg4/`.
  `speed_reference.json` and the paired checks keep the guest's boot id of 2026-11-15 (a random number per boot, already in
  `tests/test_paired_check.py`). No MAC address or e-mail address occurs in any file, and no public IP address but five of Ubuntu's NTP
  servers (in chrony's records and in one chronyd line of `monitors/5/journal.txt`), which earlier published folders hold too. The host's CPU model and VirtualBox version are those of the committed record.

## Not published here

* The packet tars themselves (their content is `recal_2026-11/`, checked above; their sha256 are in `packets/*.sha256`).
* HS1's own run of 2026-11-14 (RES-05 [ledger]): only its medians appear, as R1's speed reference copied them into
  `speed_reference.json`, and as the P-1 checks compare with them.
* AP-13's first launch on 2026-11-15, refused by the timers pre-check at 21:38:39Z with nothing measured [ledger]: its launcher log is
  not in the backup. The waiter that then launched AP-13 after the midnight timers is `packets/after_timers_launch_20261115T213900Z.log`.
* The thesis text that reports this re-calibration, and the ledger itself (outside this repository).

## How to re-check

    cd results/2026-11-15_harm-recalibration && sha256sum -c SHA256SUMS
    (cd preregistration && sha256sum -c sha256.txt)
    ../../venv/bin/python -B recomputation/recompute_from_runs.py ../.. recal_2026-11 \
        ../../bench/calibration/ddos-mitigation-2026-11-16.json /tmp \
        | diff - recomputation/recompute_from_runs.out
    cmp /tmp/freeze_record_created_utc_as_committed.json ../../bench/calibration/ddos-mitigation-2026-11-16.json

The script only reads `recal_2026-11/` and writes its two outputs to the last argument. The `diff` and the `cmp` print nothing when
the recomputation reproduces. `gzip -dc` any `.gz` and compare with `GZIPPED.tsv`. To rebuild `analysis/`, run `venv/bin/python eval/publish_campaign.py
results/2026-11-15_harm-recalibration/recal_2026-11 --name <scratch>` (it writes `results/<scratch>/`).
