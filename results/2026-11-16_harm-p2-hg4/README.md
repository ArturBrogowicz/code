# P2 of the harm benchmark (HG4 at level 8, Nginx limits plus the daemon banning into XDP): gate PASS, P2 outcome NOT MET

P2 asks whether the protected server (`M_xdp`: Nginx's limits plus `control_plane.py` banning into XDP) keeps the legit clients'
service while the HG4 cheap static flood harms the unprotected one. Three runs of it are published here, every file as the tools
wrote it, apart from the gzip and the redactions listed below:

| | Directory | Approval | Pin | When (UTC, 2026-11-16) | Runs | Reading |
|---|---|---|---|---|---|---|
| P2-1 | `hg4_mvp_xdp_recal.smoke/` | AP-16 | `688594a` | 14:23:15-14:29:17 | 2 smoke runs, seed 1: `M_xdp`, `M_limits` | evidence list passed; **not host-checked; not a result** |
| P2-2 | `hg4_mvp_xdp_recal/` | AP-17 | `688594a` | 14:44:17-15:47:27 | 23 | **INVALID**: 4 valid blocks of the 10 the gate needs |
| P2-2b | `hg4_mvp_xdp_recal2/` | AP-18 | `18386ed` (`688594a` + K23) | 17:38:26-19:40:31, two packets | 41 | **gate PASS; P2 outcome of `M_xdp` NOT MET** |

**The result is P2-2b**, labelled **"after a post hoc fix of the attack's launch (K23, `docs/HG1C_DESIGN.md` departure 42, ledger
D-114)"**: P2-2 was INVALID because its attack began too early, the launch was changed after its data, and P2-2b is the one repeat
the rules allow. The daemon banned all 50 attack identities (median 0.868 s after the attack began, at most 1.723 s) and no legit
one, but the protected arm kept only 93.7-97.4 % of the control's Q, below the pre-registered 99 %, in all 10 blocks.

## The pre-registered rule

* **Spec and record.** `bench/scenarios/cheap_static_flood_hg4.json` (sha256 `aa43c844...`) at level 8, twice the cheap knee of 4
  of the record `bench/calibration/ddos-mitigation-2026-11-16.json` (file sha256
  `e6b88a8564bbd67c507e1489aae9084ff550fabcb063865e5fd3dd230950bef4`, record hash, its `sha256` field,
  `7005a2edfcbf0acae1737b0a384f52aaa28169f6193fdd56e53eb48d4f2fb01c`, frozen 2026-11-16T10:05:07Z). Every run of all three
  directories names that record and that spec, on kernel 7.0.0-42 with 7,422 MiB, from a clean tree (`analysis/runs.json`).
* **The campaign** (`bench/gate_campaign.py run ... --modes xdp`): an unscored warm-up control at seed 1, then 10 blocks, seeds
  1-10, each of four runs in a drawn order: `C` (the control, no attack), `Cp` (the placebo, a second attack-free run), `U` (the
  attack, unprotected) and `M_xdp` (the attack, protected). A run is 30 s baseline, 45 s attack, 30 s recovery. Q is the share of
  the legit requests on the judged links (perfect, broadband) intended in the 45 s of the attack that were answered 2xx within their
  route class's SLO; p95 is the service time of those. A failed block is re-run once with its seed and a new order, at most 2
  re-runs in the whole campaign (the record's `gate.max_reruns`); a valid block is never re-run. Every run is host-checked (H1,
  H3-H7).
* **The gate** (`eval/harm_gate.py`, criteria from the record's `gate` block): 10 valid blocks; dQ = Q(C) - Q(U) and dL = log2 of
  p95(U)/p95(C), each passes when its mean over the blocks is at least its floor (10 pp; 1.0), the lower end of its 95 % interval
  is above 0 and at least 80 % of the blocks have its sign; the gate PASSes when either dQ or dL passes (here both did), FAILs
  otherwise, and is INVALID with fewer than 10 valid blocks or a broken re-run rule. The placebo (Cp against C) must not pass.
* **The P2 outcome** (`harm_gate.P2_OUTCOME`, fixed on 2026-10-30 in `029a202` before any protected run, the same at `688594a` and
  `18386ed`; quoted in `preregistration/decisions.md`): "the unprotected server fails" when, in at least 9 of 10 blocks, dQ >= 10 pp
  or p95(U) >= 2 x p95(C); "the protected server works" when Q(M) >= 0.99 x Q(C) in at least 9 of 10 blocks **and** no legit
  identity is banned in any `M_xdp` attempt, valid or not. MET needs both; fewer than 10 blocks give INVALID. The time to mitigate
  (TTM: an attack identity's first ban after the attack began) is reported, not judged. Neither the gate nor `P2_OUTCOME` changed
  between the approval packets and the data.
* **Known before any data** (AP-17, AP-18): with the 0.99 ratio NOT MET is a live outcome even for a daemon that works as designed:
  the ratio lets the protected arm lose about 0.45 s of the 45-s window (1 % of it), while no source can be banned before it has
  sent enough requests to cross the rate rule. AP-17 adds that "the rule cannot ban before about 1 s"; at level 8 that is wrong
  (found by an independent review, T-129, after this folder was first written). The L7 rate rule (`l7_rate`,
  `control_plane.py:1528` at `18386ed`, default profile) bans a source when its requests in the 10-s window divided by
  max(elapsed, 1 s) exceed 50, elapsed being the time since the oldest of them: within its first second a source is banned at its
  51st request, which a source planned at 119.25 requests/s sends about 0.42 s after its first. In P2-2b 49 of the 50 first bans
  carry the value 51.0 (the other 50.779, the last of them), 36 of the 50 TTMs are under 1 s, and they run from 0.603 to 1.723 s
  (median 0.868 s); the protected arm's loss lies almost wholly in seconds 0-2 of the attack (below). The rule's other branch
  (an error ratio above 0.8 at more than 10 requests/s) could ban earlier, but it fired for no first ban: every first ban in
  P2-2b (50), P2-2 (30) and P2-1 (5) has an error ratio of 0.0.
* **Rules carried from D-086** (D-113, D-116): no reading before `gate.json` exists (R-2); NO READING if the kernel, MemTotal, HEAD
  or a frozen hash changes, a run overlaps |System time| >= 0.1 s, there are more than 6 resumes or 72 h, or a legit ban falls in
  a run with a pause of 10 s or more (R-3); after INVALID at most one repeat, decided before any arm figure of the invalid campaign
  is looked at, and none after FAIL or NOT MET (R-5).

## P2-2b: the result

**Gate: PASS.** 10 valid blocks of 10, 0 re-runs, 41 runs (warm-up and 40), 0 unsound, 0 host-invalid. dQ +98.49 pp
[+98.17, +98.81], dL +3.33 [+2.92, +3.75], both the same sign in 100 % of the blocks. The placebo did not pass, as it must not:
dQ' -0.00 pp [-0.03, +0.03], dL' +0.01 [-0.03, +0.05]. The block table of `hg4_mvp_xdp_recal2/gate.md`:

| block | seed | attempt | valid | Q C | Q C' | Q U | dQ | dL | dQ' | p95 C ms | p95 U ms | degraded s | first degraded s | recovery s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | yes | 100.0 | 100.0 | 1.3 | 98.7 | 3.45 | 0.0 | 84 | 916 | 71 | 0.0 | n/a |
| 2 | 2 | 1 | yes | 100.0 | 100.0 | 2.2 | 97.8 | 3.24 | 0.0 | 84 | 798 | 72 | 0.0 | n/a |
| 3 | 3 | 1 | yes | 100.0 | 100.0 | 1.2 | 98.8 | 4.88 | 0.0 | 87 | 2554 | 70 | 0.0 | 25.0 |
| 4 | 4 | 1 | yes | 100.0 | 100.0 | 1.0 | 99.0 | 3.27 | 0.0 | 87 | 840 | 72 | 0.0 | n/a |
| 5 | 5 | 1 | yes | 100.0 | 99.9 | 1.7 | 98.3 | 2.68 | 0.1 | 75 | 480 | 73 | 0.0 | n/a |
| 6 | 6 | 1 | yes | 100.0 | 100.0 | 2.2 | 97.8 | 3.21 | 0.0 | 86 | 800 | 71 | 0.0 | n/a |
| 7 | 7 | 1 | yes | 100.0 | 100.0 | 0.9 | 99.1 | 3.11 | 0.0 | 88 | 759 | 71 | 0.0 | n/a |
| 8 | 8 | 1 | yes | 100.0 | 100.0 | 1.7 | 98.3 | 3.10 | 0.0 | 85 | 725 | 74 | 0.0 | n/a |
| 9 | 9 | 1 | yes | 99.9 | 100.0 | 1.2 | 98.7 | 3.03 | -0.1 | 92 | 745 | 74 | 0.0 | n/a |
| 10 | 10 | 1 | yes | 100.0 | 100.0 | 1.6 | 98.4 | 3.38 | 0.0 | 82 | 851 | 72 | 0.0 | n/a |

**P2 outcome of `M_xdp`: NOT MET.**

* **The unprotected server fails: 10 of 10 blocks** (needs 9). Q(U) 0.90-2.21 % against Q(C) 99.91-100 %.
* **The protected server works: 0 of 10 blocks** (needs 9). Q(M)/Q(C) against the rule's 0.99:

  | block | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
  |---|---|---|---|---|---|---|---|---|---|---|
  | Q(M) % | 97.38 | 95.71 | 95.95 | 96.90 | 95.58 | 96.90 | 93.68 | 97.21 | 95.05 | 96.38 |
  | Q(M)/Q(C) | 0.9738 | 0.9571 | 0.9595 | 0.9690 | 0.9558 | 0.9690 | 0.9368 | 0.9721 | 0.9513 | 0.9638 |

* **Legit identities banned in any `M_xdp` attempt: 0** (the ban files of all 10 attempts). Attack identities banned: **50 of
  50**, every ban by the L7 rate rule (`l7_rate`) into XDP. **TTM** (reported, not judged): median **0.868 s**, max **1.723 s**
  (n 50). Legit requests refused (503/429) in the window: 0.
* HRR, the share of the harm the protected arm takes back (descriptive): 0.96 [0.95, 0.97] on Q, 0.92 [0.88, 0.96] on log2 p95.
* The strict generator-validity profile (every stream's slip p99 under 50 ms) is computed and not judged (the record's profile is
  `relative`): `gate.md` reports that 4 runs would fail it, the four of block 1, each on stream `L-poisson-C5-mobile_bad-3` with a
  slip p99 of 54-55 ms (`gate.json`, `blocks[0].runs.*.validity.strict`).

**R-3 (NO READING) does not apply.** Kernel 7.0.0-42, MemTotal 7,422 MiB, HEAD `18386ed` with a clean tree and the record
`7005a2ed` are the same in all 41 runs; chrony's 226 tracking samples from 17:38:27Z to 19:40:00Z are all "Normal", with a largest
|System time| of 2.98 ms; one resume (two packets, 17:38-19:40Z); no legit ban.

**The runs.** Every run is sound (`executor.ok`, no reasons) and host-valid (H1, H3-H7 in each `block.json`). K23's watch set
the launch in all 41 runs by its rule `seen` (in `C` and `Cp` it runs too, with no attack to launch): every legit engine watched
(29-32 per run) was seen to start its loop, the loops' median start 3.06-3.46 s after their launch, and the attack's start error in
the 20 attack runs was -0.004 to +0.052 s (limit 0.5 s); the largest gap between two looks was 0.068 s, and the exit-based zero
fell 0.014-0.055 s after the watch's. All 10 daemons were ready 3.56-3.58 s after their start and stopped on SIGINT with exit 0
and XDP detached.

**Where the protected arm loses (descriptive, ledger C-161; not judged, read after the outcome).** Per-second Q of the judged links
in the `M_xdp` runs, from the attack's start: second 0 31.4-59.1 %, second 1 17.0-78.6 %, second 2 91.9-100 %, and 100 % from
second 3 to 44 in every run except two single seconds (block 1, second 33: 96.3 %; block 9, second 30: 94.7 %). Before the attack
all 10 runs had 100 %. The lost requests, 31-77 per run (487 in all), were every one answered 2xx but over its class's SLO; none
was refused or failed. That the shortfall is the transient before and just after the bans, and the backlog it leaves, is an
inference (C-161).

## P2-2: INVALID

23 runs (the warm-up and blocks 1-5), 0 host-invalid. Three runs were unsound by the executor's attack-start check, the attack
having begun more than 0.5 s before the end of the baseline: `b03_a1/U` -0.516 s, `b05_a1/M_xdp` -0.516 s, `b05_a2/M_xdp`
-0.510 s. Blocks 3 and 5 each used a re-run, block 5 failed again, and with 4 valid blocks the campaign stopped (exit 2) when 10
could no longer be reached: the gate is **INVALID** and the P2 outcome is INVALID, neither MET nor NOT MET. The attack began early
in every one of the 12 attack runs (-0.516 to -0.158 s). **Cause** (ledger C-159): the attack was launched on a fixed delay that
assumes the legit engines take 2.9 s to start their schedules; with 29-32 engines on one vCPU they took about 0.2-0.5 s longer
(the start errors are facts of the runs; the engines' slower start-up, their cause, is an inference). K23 (`18386ed`) launches
the attack from the legit engines' loops as they are seen to start instead.

**By the ledger (RES-14, D-114, D-116) its arm figures were not read until P2-2b had ended**; they are descriptive, an INVALID
campaign's: in the 4 valid blocks Q(M)/Q(C) 0.9624, 0.9555, 0.9672, 0.9785; Q(U) 0.09-0.73 % against Q(C) 100 %; 20 of 20
attack identities banned, TTM median 0.857 s, max 1.602 s (n 20); no legit identity banned in any of the 6 `M_xdp` attempts, the
two unsound ones included. The same picture as P2-2b. Its block table is in `hg4_mvp_xdp_recal/gate.md`.

## P2-1: two smoke runs, not host-checked

P2-1 (AP-16) checked that the real daemon starts, bans the attack and only the attack, and stops cleanly at the pin, and that Nginx's
limits act, before P2-2. It is **not a result**: there is no control or unprotected run beside it, and the user chose to label it
"not host-checked" (D-112) because `bench/executor.py run` does not judge H1-H7. `P2-1_evidence.md` is the orchestrator's evidence
list (E1-E10, L1-L4): all passed (ledger RES-13). Read again from the files: `M_xdp` was sound, the daemon was ready after 4.07 s
with XDP program 86 attached until the end, banned 5 of 5 attack identities (`l7_rate`, 51 > 50 requests/s) with TTM median
0.818 s (0.758-1.606 s), banned no legit identity, and stopped on SIGINT with exit 0 and XDP detached; `M_limits` was sound with
no daemon. Descriptive only: Q 96.04 % (`M_xdp`) and 89.81 % (`M_limits`) of about 1,490 judged requests, p95 117 and 186 ms. The
two runs have no `DONE` file because `bench/executor.py run` writes none (it is the campaign runner's marker), so
`analysis/runs.json` lists them as "ended without DONE"; both have a complete `run.json`.

## The precondition: R4 confirmed the record

R4 (AP-15, 2026-11-16 11:54:37-12:33:08Z) ran `bench/calibrate.py drift` against the frozen record: 12 runs, 0 host-invalid, and
all three families confirmed ("drift: within the frozen reference"; `costly_export_flood` with a wide spread at its knee, D6).
Published: `precondition/confirmation/drift/drift.json` (the verdict, naming record `7005a2ed`), the packet's log and its tar's
sha256. R4's runs and the earlier re-calibration steps R1-R3 are not published here. P2-2 and P2-2b ran in the window the user
arranged from the reboot at 11:19:37Z through their packets that day (D-113, D-116), so no later drift check was needed.

## Pre-data decisions and the recomputation

* `preregistration/`: the approval packets AP-16, AP-17 and AP-18 byte for byte (`sha256.txt`: `0fdd428c...`, `651c7e36...`,
  `f8f914ce...`), and `decisions.md`, which quotes verbatim the ledger rows D-086, D-112, D-113, D-114 and D-116, the approval rows
  of AP-16, AP-17 and AP-18 (each with the user's answer), and `P2_OUTCOME` at the pin.
* `recomputation/recompute_p22b.py`: an independent recomputation of P2-2b in pure Python that imports nothing of the project.
  From each run's request records, `run.json`, `plan.json`, `block.json` and ban files it recomputes per block Q(C), Q(Cp), Q(U),
  Q(M), dQ, dL, the two halves of the outcome, the legit bans and the TTM. It compares dQ, dL, Q(C) and Q(M) of every block with
  `gate.json` (**0 mismatches**) and prints the rest, which equals `gate.json` too (checked by the independent review T-131); it
  does not compute the placebo's dQ'.
  `recompute_p22b.out` is its output when it was first run on the campaign directory on the VM; `recompute_p22b_published.out` is
  its output on this published copy, byte-identical to it.
* `recomputation/rejudge_harm_gate/`: the project's own judge run again. `eval/harm_gate.py <P2-2b dir> --calibration
  bench/calibration/ddos-mitigation-2026-11-16.json --json gate.json --md gate.md` at `18386ed`, on the raw campaign directory on
  the VM (orchestrator's task T-126), gave rc 0 and "PASS: 10 valid blocks of 10"; its `gate.md` is byte-identical to the
  campaign's and its `gate.json` identical but for one trailing newline (184,076 against 184,075 bytes: the command line writes
  one, the campaign runner does not). `RESULT.txt` says so; the three files are copied byte for byte. The same command on this
  published copy (in a sandbox, at the same code) also gave rc 0 and "PASS: 10 valid blocks of 10", with `gate.md` and
  `gate.json` byte-identical to these: the compressed logs do not matter, since the judge reads the request records, `run.json`,
  `plan.json`, `block.json` and the ban files.

## Contents

* `hg4_mvp_xdp_recal2/` (P2-2b), `hg4_mvp_xdp_recal/` (P2-2), `hg4_mvp_xdp_recal.smoke/` (P2-1): the tools' directories. A
  campaign holds `campaign.json`, `gate.json`, `gate.md`, `warmup/C`, one `bNN_aM/` per block attempt (`block.json` and its runs),
  and `monitors/<packet>/` (`mpstat`, `pidstat`, chrony and the journal over each packet). Each run is a directory of the run
  contract: `plan.json`, `run.json`, `environment.json`, `DONE`, `executor.log`, the Nginx and gunicorn logs, `server.csv`,
  `server_requests.csv`, and per load stream its request records and summary; an `M_xdp` run adds `daemon.log`,
  `ban_events.jsonl` and `feed_before/` (the host's Nginx logs, moved aside at its start; they hold the lines written since the
  previous move, the testbed's own traffic).
* `packets/`: the log and the tar's `.sha256` of every packet (P2-1; P2-2; P2-2b's two), the three launcher logs, and
  `P2-2b_packet1_prefix_check.txt`. P2-2b ran in two packets of one campaign directory; packet 2's tar holds the whole directory and
  is the one published. Packet 1's tar (`P2-2_20261116T173249Z`) is not: its 3,169 files were compared one by one with packet
  2's, 3,168 are byte-identical and the one that differs is `campaign.json`, which the campaign runner rewrites when it resumes and
  at the end (packet 1: state paused, 7 attempts; packet 2: complete, 10 attempts, its first 7 equal to packet 1's, and the gate).
* `P2-1_evidence.md`, `precondition/`, `preregistration/`, `recomputation/`: above.
* `analysis/`: written by `eval/publish_campaign.py` from the published files: `runs.json` (each run's state and provenance) and
  `summary.md`. The publisher judges only drift checks, so these campaigns get no verdict from it; their verdicts are `gate.json`'s,
  recomputed above.
* `GZIPPED.tsv`, `REDACTIONS.tsv`, `SHA256SUMS`.

## Provenance, size and redactions

* Source: the backup `p2_2026-11` (16 files) and, for R4, `recal_2026-11`, each equal to its manifest (`sha256sum -c`) when this
  entry was made; each tar equal to its own `.sha256`, which is published.
* **Compression, lossless:** the 36 text files over 1 MB are stored as `<name>.gz` (`gzip -n -9`): the `U` runs' `nginx_error.log`
  (about 7.9 MB each), the `M_xdp` runs' `feed_before/ddos_ml_access.log` (about 1.1 MB each), P2-1's `M_limits/nginx_error.log`
  and the three `pidstat.txt`. `GZIPPED.tsv` gives each one's original size and sha256 (`gzip -dc <file> | sha256sum` returns it)
  and the published sha256. The request records and access logs were compressed by the tools themselves. Nothing else is changed.
  The folder is 7,292 files (with `SHA256SUMS`) and about 76 MB; the publisher warns above 20 MB and refuses over 100 MB.
* **Redactions:** in the three `pidstat.txt` (before their compression) the command of every line naming a path under `~/.claude`,
  the Claude app's processes on the VM with their session ids, socket paths and token-file names, is replaced by a marker; the time,
  UID, PID and CPU columns stay. `REDACTIONS.tsv` gives each file's sha256 in the packet tar, after the redaction and as published.
  The host-check records (`DONE`, `block.json`, `campaign.json`) keep the process names as the tool cut them to 60 characters, such
  as `/home/artur/.claude/remote/ccd-cli/2.1.325-1ef04b37a794 --ou` and `/home/artur/.claude/remote/srv/87375cc7c944eb9d45c8d9267edc7`
  (a program version and an install directory, no session id, socket or token). The host's CPU model and VirtualBox version in
  `environment.json` are those of the committed record. No MAC address or e-mail address occurs in any file.

## How to re-check

    cd results/2026-11-16_harm-p2-hg4 && sha256sum -c SHA256SUMS
    python3 -I recomputation/recompute_p22b.py hg4_mvp_xdp_recal2 ../../bench/calibration/ddos-mitigation-2026-11-16.json \
        | diff - recomputation/recompute_p22b_published.out
    cd ../.. && venv/bin/python eval/harm_gate.py results/2026-11-16_harm-p2-hg4/hg4_mvp_xdp_recal2 \
        --calibration bench/calibration/ddos-mitigation-2026-11-16.json --json /tmp/gate.json --md /tmp/gate.md
    cmp /tmp/gate.md results/2026-11-16_harm-p2-hg4/recomputation/rejudge_harm_gate/gate.md
    cmp /tmp/gate.json results/2026-11-16_harm-p2-hg4/recomputation/rejudge_harm_gate/gate.json

The second prints nothing when the recomputation reproduces (it needs only Python 3); the judge (at `18386ed`) prints "PASS: 10
valid blocks of 10" and both `cmp` print nothing. `gzip -dc` any `.gz` and compare with
`GZIPPED.tsv`. To rebuild `analysis/`, run `venv/bin/python eval/publish_campaign.py results/2026-11-16_harm-p2-hg4/hg4_mvp_xdp_recal2
results/2026-11-16_harm-p2-hg4/hg4_mvp_xdp_recal results/2026-11-16_harm-p2-hg4/hg4_mvp_xdp_recal.smoke --name <scratch>` (it
writes `results/<scratch>/`).
