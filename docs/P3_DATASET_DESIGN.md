# P3: multi-seed, entity-disjoint L7 datasets and learning curves (design note, written before the code)

**Status (2026-10-30): a design for approval. Nothing in it is built or run.** It is on `design/priority-p1-p4`, branched from
`feat/hg1c` at e413a34, and changes no code. It details priority P3 of the approved direction
(`/home/artur/agent_workspace/final/PRIORITY_PLAN.md` §5), refining T-005's learning-curve protocol
(`S1:T-005/learning_curve_protocol.md`). It supplies P1's training and validation data (`docs/L7V2_DESIGN.md`). The tags and
citation forms are those of `docs/L7V2_DESIGN.md` (header): `path:line` refers to e413a34, `S1:T-00x/<file>` is an accepted S1
artifact, and `VR:Vn` is a verification row.

## 1. Decisions for the user, and what I found

**What I found** (each finding fixes a requirement below):
- **F-D1: one role map serves every run.** [FACT]
  - Addresses are positional: benign clients are `10.0.1.{i+1}` (`ml/l7_traffic.py:294`) and attackers `10.0.2.{j+1}` (`:302`).
    The P5b kinds sit at fixed positions after them (`:328`).
  - The seed changes only start times and client seeds (`:303-310`).
  - P5c.4 run A1 replays the P5c.3 training capture: netem 29/29, benign UA sets 20/20, attacker UA sets 8/9, first-30 URIs of
    attackers 7/8 [VR:V10].
- **F-D2: the attackers have no netem; the benign clients are spread over four profiles.** `assign_profiles` is applied to
  benign clients only (`ml/capture_l7.py:65-74`, `:213-219`) [FACT]. That is the "no netem = attacker" confound
  (`S1:T-005/p3_inventory.csv`, the P3 and P5c.3 rows).
- **F-D3: the trainer splits attacks in time and selects on test sets.** [FACT]
  - Attacks are split by time within the same address (85/15). Benign addresses are split 67/16/17 (`ml/train_l7.py:106-151`).
  - The variant is selected on the held-out families and on `benign_test` (`ml/train_l7.py:403-416`).
- **F-D4: raw captures default to `/var/tmp/ddos_l7_datasets`** (`ml/capture_l7.py:42`), which the 30-day tmpfiles purge
  empties. The existing raw data were backed up under `/home/artur/agent_workspace/backup` (ledger D-011) [FACT].
- **F-D5: today's data cannot rank the models.** The "attack" class was learned from 3 addresses. Swapping the benign split seed
  moves the GRU's online benign flags from 9 to 6, and the HGB's from 3 to 8 [FACT, `S1:T-005/p1_baseline_facts.md` §3].
- **F-D6: the volume fits on disk.** P5c.3 logged 31,623 lines from 29 addresses in 600 s: 11.7 MB raw, 0.66 MB gzipped [FACT,
  `S1:T-005/p3_inventory.csv`]. That is ~670 B per address-second [ARITHMETIC].
  - At 300 addresses for 900 s, one capture is ~180 MB raw and ~10 MB gzipped [ESTIMATE]; the 16 captures of section 5 are ~3.1 GB raw.
  - The root file system has 49 GB free [FACT, T0 `df -h`, 2026-10-30].
- **F-D7: T-005's replicate design is ambiguous at 100 %.** "5 draws × 3 training-seed sets" (`S1:T-005/learning_curve_protocol.md`
  §2) leaves the 100 % fraction undefined with 4 training seeds. Section 6 resolves it.

**Decisions requested.**

| # | Decision | Recommendation | Why, and what the alternative costs |
|---|---|---|---|
| D-D1 | Raw data are stored under `/home/artur/datasets/l7/<version>/`, outside git and outside `/var/tmp`, with a `SHA256SUMS`. `results/` keeps only the manifests and samples (section 4.5) | accept | The purge (F-D4). It uses ~3 GB of your home directory, which needs your consent |
| D-D2 | Disjoint seed lists for every role in the three notes (section 5) | accept | VR:V10: seed 1 was used for both training and evaluation |
| D-D3 | Volume per capture: 900 s; ≥ 200 benign users; ≥ 50 entities per core attack family; families in staggered phases at drawn intensities (section 5) | accept | T-005's minimum (`S1:T-005/learning_curve_protocol.md` §1), fitted to the ~300-address limit |
| D-D4 | Two server configurations, alternating by seed: A, the P1 stack; B, gunicorn 4 × 4 (section 5) | accept | Server timing leaks load (R17). A second configuration stops one stack's queueing from becoming a label |
| D-D5 | The learning-curve protocol as refined in section 6: fractions, replicates, models, thresholds, the two-level bootstrap, decision rules | accept | It resolves F-D7 and adds the uncertainty between fits |
| D-D6 | Budget: ~5.7 VM h of captures and ~5 h of sandboxed CPU (+4 h if the per-request ablation is fitted) (section 7) | accept | The plan said ~1 VM day (`final/PRIORITY_PLAN.md` §5), which matches |
| D-D7 | P1 trains on P3's training seeds and tunes on P3's validation seeds. P3's evaluation captures serve P3's curves and P1's detection replays. P1's harm verdicts use their own live seeds (section 5) | accept | It keeps one data pipeline for P1 and P3, with no reuse across roles |

## 2. Scope

| In | Out |
|---|---|
| The capture pipeline's changes (pools, netem, per-entity parameters, manifests, storage, rebuild, disjointness, selection); seeds and volume; the learning-curve protocol; compute and VM budget | The traffic content (classes, benign mix, navigation model), which is defined in `docs/L7V2_DESIGN.md` §7 and §12 and frozen with it; P4's connection snapshots (`docs/P4_SLOW_DESIGN.md`), which reuse the manifest and the storage; the XDP datasets (`S1:T-005/p3_inventory.csv` rows 2-4: out of the current pipeline) |

## 3. What exists (facts)
- **The capture** (`ml/capture_l7.py`) stands up the testbed with the multi-path app behind the capture nginx. The log goes to a
  lossless file (`nginx_l7capture.conf:7-8`, `:49`). Labels come from the namespace plan, never from a model
  (`ml/capture_l7.py:1-24`).
  - It refuses a dirty tree unless told otherwise. The manifest records the commit, the branch and the dirty state
    (`ml/capture_l7.py:21-22`, `:182-203`).
  - It records the sha256 of its provenance inputs (`ml/capture_l7.py:49`).
- **The dataset reader** is `l7_dataset.py`. The trainer is `ml/train_l7.py`: windows of 20 with stride 3, min events 5
  (`:52-55`), feature variants (`:333`) and a hard probe gate (`:19-22`).
- **Published captures** [FACT, `S1:T-005/p3_inventory.csv`]:
  - P3: seed 1, 300 s, 9,012 lines;
  - P5c.3: seed 1, 600 s, 31,623 lines, 20 benign addresses and 9 attacker addresses;
  - the P5c.4 evaluation records: seeds 1-5, with seed 1 reused.
- **What the S1 audit called P3** (`final/PRIORITY_PLAN.md` §1): one 29-address role map in every run; seed reuse; selection on
  test sets; raw data in `/var/tmp`.

## 4. Capture pipeline changes [PROPOSAL]

### 4.1 Per-seed pools and role maps
These follow `docs/L7V2_DESIGN.md` §6:
- **The pool.** Each seed draws its pool from 10.0.16.0/20 and assigns roles by a seeded permutation. The address does not
  reveal the role.
- **No address-to-role map is shared between seeds.** A test checks that, for any two seeds, the role maps differ in more than
  90 % of positions [PROPOSAL; a random permutation of ~300 addresses from 4,094 makes this almost certain].
- **Sub-seeds.** Every entity's sub-seed is derived as `blake2b("p3|<version>|<seed>|<entity index>")`. No random stream is
  shared across seeds or roles.

### 4.2 Netem for every entity
- **Every entity, benign or attacking, draws its netem profile** from the same distribution over `perfect`, `broadband`,
  `mobile_3g` and `mobile_bad` (`ml/capture_l7.py:48`). The draw is balanced within each role.
- **Entities are grouped onto namespaces by profile** (aliases), because netem belongs to an interface
  (`bench/executor.py:334-336`).
- **The confound check, descriptive and on validation only:** the share of each profile per role is reported.

### 4.3 Per-entity parameters
- **Each entity draws its parameters from its kind's or family's distribution, frozen with the generators.** Examples: a
  browser's page level and visit gaps; a bot's rate, dwell bounds and mimicry level.
- **The draws are recorded.** Today a kind's parameters are one fixed dict per kind (`ml/l7_traffic.py:94-147`), plus the
  client's seed.

### 4.4 The manifest (one per capture; schema 2)
- **Identity:**
  - `schema`, `dataset_version` and `capture_id`;
  - `seed` and `seed_role` (`train`, `val`, `eval` or `pilot`);
  - `started_utc` and `ended_utc`.
- **Code:** generator commit and branch, `dirty: false` (required), and the sha256 of every provenance input
  (`ml/capture_l7.py:49`).
- **Server:**
  - the configuration id (A or B, section 5);
  - the sha256 of the nginx configuration;
  - the sha256 and status of the calibration record. A placeholder is allowed for captures and is recorded.
- **Host:** as `HOST_SHAPE` of the calibration record (`bench/calibration.py:44`).
- **Pool:** the range, the permutation seed, and the full role map.
- **Entities.** One row per entity:
  - `entity_id`: globally unique, `<version>:<seed>:<n>`. A CGNAT user is an entity, and the pool is its cluster;
  - `role`, `kind_or_family`, `held_out`;
  - `address`, `namespace` and `netem`;
  - the drawn `params` and the sub-seed;
  - the `schedule` (start and stop, attack phase);
  - `plan_sha256`, the hash of the entity's exact plan.
- **Files:** path, size, sha256 and line count for each of the access log, the error log, the engine record if any, and the
  client harm records if any.
- **Hashes:**
  - `plan_set_sha256`, the hash of the sorted `plan_sha256` values. It is what the disjointness test compares (4.7);
  - `manifest_sha256`, computed over the canonical JSON without this field.

### 4.5 Storage outside git and outside `/var/tmp` (D-D1)
- **Layout.** `/home/artur/datasets/l7/<version>/<capture_id>/` holds `manifest.json`, `access.log.gz`, `error.log.gz` and the
  other files. `/home/artur/datasets/l7/<version>/SHA256SUMS` covers every file. The version is a date plus a tag, for example
  `2026-11-v1`.
- **No purge.** The capture writes there directly. If a step must stage in `/var/tmp`, it copies at the end, checks the
  hashes, and only then deletes the staged copy.
- **Ownership.** The capture runs as root. The directory is created by user artur beforehand, and the files are handed back to
  artur at the end.
- **Permissions.** Logs are no longer world-writable. The capture currently does `chmod 0o666` (`ml/capture_l7.py:286`;
  `S1:T-007/security.md` S8). The nginx master process opens its logs as root [CLAIMED, nginx behaviour; checked in the smoke
  capture].
- **What git keeps.** `results/` holds only the manifests, a 1 % sample of each log, and the learning-curve outputs.

### 4.6 Rebuild from the manifests
A new tool, `ml/rebuild_l7_dataset.py <version dir>`:
1. verifies `SHA256SUMS` and every manifest's own hash, and stops on any mismatch;
2. re-derives the labels from the manifests alone;
3. re-derives the windows and view tokens with the code at a recorded commit (`docs/L7V2_DESIGN.md` §8);
4. writes the split file (entity → split) with its sha256.

A test asserts that two rebuilds are byte-identical, and that a single flipped byte in any input stops the rebuild.

### 4.7 Disjointness tests that fail closed
**One checker, two uses:**
- a unit test on fixture manifests;
- a `--check` mode that the trainer and the curve tool call before every fit. They refuse to fit unless it passes.

**The checker fails when any of these holds:**
1. a required manifest field is missing (unknown means fail);
2. entity ids intersect across train, validation and evaluation;
3. an evaluation seed appears in a training or validation manifest;
4. the `plan_set_sha256` of an evaluation capture equals any training or validation capture's (the seed-1 replay of VR:V10);
5. any single `plan_sha256` is shared across roles;
6. an evaluation capture started before the last training capture ended;
7. the generator commit differs within a version;
8. a file's sha256 does not match;
9. a held-out kind or family occurs in a training or validation capture;
10. the split file's hash differs from the one the selection file records.

### 4.8 Selection on validation seeds only
- **Validation decides.** Variant selection, the architecture choice (at 100 % only), and every operating point (θ, k) use the
  **validation captures** only.
- **The trainer's current rule changes.** Today it selects on held-out families and `benign_test` (`ml/train_l7.py:403-416`).
  Under this note, both become evaluation-only.
- **Evaluation is scored by a separate command.** It refuses to run without a frozen selection file (variant, θ and k per fit,
  sha256), which is committed before the evaluation captures are opened for scoring.
- **Splits are by entity.** The time split of one attacker's traffic into train and test (F-D3) is abolished: attack entities
  in validation and evaluation come from other seeds.

## 5. Seeds and volume targets [PROPOSAL, D-D2, D-D3, D-D4, D-D7]

**Seed lists, disjoint across all three notes:**

| Role | Seeds | Used by |
|---|---|---|
| P3 training captures | 1001-1004 | P3 curves; P1 training |
| P3 validation captures | 2001-2004 (D-052, 2026-11-02, from 2001-2002, before any capture) | P3 thresholds and selection; P1 tuning of every arm |
| P3 evaluation captures | 3201-3210 | P3 curves; P1 detection replays (not harm) |
| P1 live evaluation | 3001-3010 | `docs/L7V2_DESIGN.md` §11 |
| P4 validation and evaluation | 4001-4002, 3101-3110 | `docs/P4_SLOW_DESIGN.md` §6.4, §10 |
| pilots and ladders | 9001-9008 (P1), 9101-9106 (P4), 9201-9202 (P3 smoke) | harm ladders, smoke |

**Per capture:** 900 s on the L7 v2 runner, unmitigated (no daemon), with the costed backend (`docs/L7V2_DESIGN.md` §4).
- **Timeline:** 60 s benign only; then three attack phases of 240 s, one per core family (C2, C3a, C3b at M2) in a seeded
  order; then 120 s benign only.
  - Each phase's intensity is drawn from {0.5, 1, 2} × that family's knee from the P1 ladder. The models therefore see each
    class under more than one load (R17).
    - **As built (D-076, `ml/p3_sizing_prereg.json`, 2026-11-07, before any capture):** each core family takes its own knee from P1's
      knees file. A family without one takes its top tested level, marked; one with neither is refused.
    - The target m × K is carried as far as the capture carries it. C2 uses its per-entity rate. C3a uses its registered entities and
      then its pace, at most 2 × P1's per-source pace. C3b uses its registered bots only.
    - Target, realized, shortfall and excess are recorded per phase in the plan's intensity and on the phase in its timeline, which
      the manifest keeps.
    - **Dated note, 2026-11-08 (D-079, before any P1 data):** P1's knees file now gives each class a status. A plan takes a family's
      knee only at status knee and its top tested level only at no_knee; incomplete, not_tested and no_sound_level are refused by name.
  - C3b at M1 joins the C3b phase with 10 entities.
  - **Evaluation captures only:** C3b at M3 (held out) runs in a fourth slot, with the 120 s tail extended to 240 s (1,020 s in
    all), together with the held-out benign kinds.
    - **Pinned reading** (`ml/p3_prereg.json`, `eval_tail_note`): the M3 slot and the held-out benign kinds share the final
      240 s window, so 60 + 3 × 240 + 240 = 1,020 s. Confirmed by the user on 2026-10-30, before any data.
- **Benign:** ≥ 200 users, the mix of `docs/L7V2_DESIGN.md` §7.2-§7.3. The two CGNAT pools hold 36 users on two addresses.
- **Attack:** ≥ 50 entities per core family.
  - Each entity is active only in its family's phase. A C3b entity sees about 240 / 7 ≈ 34 views, which covers the 32-view
    window [ARITHMETIC].
  - The addresses fit the verified ~300-alias range: ~160 attacking (3 × 50, plus 10 at M1) and ~130 benign.
  - In evaluation captures, the M3 phase reuses the C2 phase's addresses. The role stays the same, and the entity ids, UAs
    and cookies are new. The manifest's time-indexed role map records the reuse.
- **Server configurations:** A (the P1 stack: gunicorn 2 × 8 on loopback) on odd seeds; B (4 × 4 on loopback) on even seeds.
  Every split holds both.
- **The optional classes C4 and C1** are not in the v1 captures. If they are approved, a v1.1 adds 4 training, 2 validation and
  6 evaluation captures (≈ +3.6 VM h) [ESTIMATE].
- **The minimum per family is met by every training seed alone**, as T-005 asked: ≥ 50 bot entities per family and ≥ 200
  benign users per capture seed (`S1:T-005/learning_curve_protocol.md` §1).

## 6. The learning-curve protocol (T-005's, refined) [PROPOSAL, D-D5]

**The question** (unchanged): as the training data grow, does detection at a fixed benign budget keep improving, and does the
ranking of GRU, HGB and LR change? It separates "the GRU loses because the data are small" from "the GRU loses because the
signal is rate-separable" (`S1:T-005/learning_curve_protocol.md`).

### 6.1 Design
- **Fractions.** f ∈ {10, 25, 50, 100} % of the training entities, stratified by kind or family and by training seed, with ≥ 1
  entity per stratum. Nested within a replicate: 10 % ⊂ 25 % ⊂ 50 % ⊂ 100 %.
- **Replicates (resolving F-D7).**
  - For f < 100 %: 5 subsample draws × 3 initialisation seeds = 15 fits per (f, model).
  - For f = 100 %: 1 draw × 15 initialisation seeds = 15 fits.
  - The between-fit spread is reported at every fraction. At 100 % it is pure initialisation and optimisation noise.
- **Models, on identical windows and view tokens** (`docs/L7V2_DESIGN.md` §8):
  - the view-level GRU;
  - HGB on token summaries;
  - LR on standardised summaries, with balanced class weights;
  - the shuffled-GRU: the view-level GRU with the tokens shuffled within each window **at scoring**, at every fraction;
  - optional: the per-request GRU with seq 64, which adds 60 fits.
- **Training.** Fixed epochs (25, the trainer's default: `ml/train_l7.py:32`, `:355`), hidden 64, 2 layers (`ml/train_l7.py:355`).
  No early stopping on any evaluation data. An architecture search, if any, happens once, on validation at f = 100 %, and is
  frozen before the curves.
- **The operating point of each fit.** (θ, k) is chosen on the **validation** entities at the benign budget (≤ 1 % of
  validation benign users flagged; grid θ ∈ {0.5, …, 0.999}, k ∈ {1, 2, 3, 5, 8}). It is applied unchanged to the evaluation
  captures.

### 6.2 Metrics and intervals
- **Primary:** entity recall per core family on the evaluation captures (3201-3210), at each fit's frozen operating point.
- **Secondary:**
  - benign FP per client-hour per kind, held-out kinds included;
  - time to decision from the entity's first request;
  - the gap between the GRU and the shuffled-GRU;
  - recall on the held-out family (C3b at M3).
- **Interval: a two-level bootstrap, B = 2000, 95 % percentile.** Each draw resamples the 15 fits with replacement, and the
  evaluation seeds and the entities within each seed (clusters). The estimate is the mean over fits of the pooled recall.
  - T-005 resampled the evaluation clusters only. That ignores the spread between fits, which F-D5 shows is large.
- **Clopper-Pearson per cell** only as a descriptive aside: the units are not independent.

### 6.3 Decision rules (fixed before the data; T-005 §4, unchanged in substance)
- **Flattened at f:** the 95 % interval of recall(100 %) − recall(f) includes 0 **and** its upper bound is < 5 pp.
- **Still learning:** recall(100 %) − recall(50 %) ≥ 5 pp, with the interval excluding 0. Then no ranking is claimed, and "more
  data needed" is the result.
- **A ranking**, model A over model B, is claimed only at a fraction where both curves have flattened, by ≥ 10 pp, with the
  interval of the difference excluding 0.
- **"Sequence helps"** further needs GRU > shuffled-GRU by ≥ 10 pp at that fraction.
- **Readings.**
  - GRU < HGB at small fractions and ≈ at 100 % means the GRU is the data-hungrier model: "learning, not sequence".
  - A GRU that overtakes only beyond 100 % is inconclusive. No extrapolation.
- **Fixtures.** The curve tool is unit-tested on synthetic fixtures for "flattened", "still learning", "ranking" and "no
  ranking" before any evaluation capture is scored (section 8).

### 6.4 Precision check before the freeze
- **The expected half-width** of a recall difference at 10 evaluation seeds is ±8-12 pp [INFERENCE, review 2 §10.6 via
  `S1:T-005/learning_curve_protocol.md` §1].
- **Recomputed before the freeze.** The intra-cluster correlation is recomputed from the two validation captures.
- **If the predicted half-width exceeds 10 pp**, evaluation captures are added: n_eval = ceil(10 × (hw_pred / 8)²), capped
  at 20. The new seeds continue 3211, 3212, …
- **Only the count may change, and it changes before any evaluation capture is scored.**

## 7. Compute and VM budget [ESTIMATE, D-D6]

| Item | Amount | Time |
|---|---|---|
| smoke capture (9201-9202; checks pools, netem, manifest, storage, rebuild) | 2 × 900 s | 0.6 VM h |
| captures: 4 training + 4 validation (D-052) + 10 evaluation | 8 × 900 s + 10 × 1,020 s, plus ~3 min of set-up each | 5.7 VM h |
| re-capture allowance | 2 | 0.6 VM h |
| **VM total** | | **~6.9 h** (6.3 h without the smoke) |
| GRU fits: 4 fractions × 15 | 60 fits at ~4 min on 2 threads (T-005's estimate at ~10× today's data, `S1:T-005/learning_curve_protocol.md` §5) | ~4 h CPU |
| HGB, LR | 2 × 60 fits | minutes |
| shuffled-GRU and evaluation scoring | ~30 s per fit over 10 captures | ~0.5 h CPU |
| optional per-request GRU | +60 fits | +4 h CPU |
| storage | ~3.1 GB raw, ~0.2 GB gzipped [ESTIMATE, F-D6] | – |

**How the work runs:**
- **The captures are T3**, approved one step at a time, after the L7 v2 runner and these pipeline changes are built and tested.
- **The fits are T1**, in the sandbox (`skills/sandboxed-offline-run/sbx.sh`), with ≤ 2 threads and only while no VM workload
  runs.

## 8. Pre-registration: what is frozen, and before what [PROPOSAL]

| # | Frozen | Before |
|---|---|---|
| 1 | this note, as approved | any P3 code |
| 2 | the pipeline code, the manifest schema, the disjointness checker and its fixture tests, the rebuild tool | the smoke capture |
| 3 | the generators, the benign mix and the class parameters (`docs/L7V2_DESIGN.md` §13 item 3), the seed lists, the timeline and the phase intensities | the first training capture |
| 4 | the curve tool, with fixtures for every decision rule; the bootstrap; the precision rule | the validation captures are analysed |
| 5 | the selection file: variant, (θ, k) per fit, and the split file's sha256 | any evaluation capture is scored |
| 6 | the capture index: every attempt with its outcome (valid, invalid and why) | reported with the results |

## 9. Risks

| Risk | Mitigation |
|---|---|
| The purge deletes raw data | Storage outside `/var/tmp` (4.5); `SHA256SUMS`; a rebuild test |
| More than ~300 addresses are needed | The phase layout keeps ~280 addresses; C4 and C1 go to a later version |
| Closed-loop clients slow down under attack, so benign windows shift with load | Intensities drawn per phase (R17); two server configurations; `server_timing` stays out of the default features (`docs/L7V2_DESIGN.md` §8.2) |
| A trivial artefact separates the classes (netem, address range, start times) | Netem drawn for every entity; shared address space; staggered phases with drawn intensities; the probe gates (`docs/L7V2_DESIGN.md` §8.5) |
| The intervals are too wide to rank | The precision rule (6.4); the "still learning" and "no ranking" outcomes are reported as results |
| Root-owned or world-writable files | Pre-created directory, ownership handed back, no `0o666` (4.5) |

## 10. As built: address reuse waits for schema 3 (T-024, review T-029 P3-09)

- **Schema 2, as built on `feat/p3-dataset-pipeline`, maps one address to one entity for the whole capture.** The labels,
  `ip_map` and the trainer's entity key are keyed by address.
- **Two cases in this note need more:** a CGNAT pool, whose 12-24 users are each an entity with the pool as their
  cluster (4.4), and the M3 phase of evaluation captures, which reuses the C2 phase's addresses (5).
- **Schema 3 provides it.** It is a time-indexed entity ↔ address map in which a CGNAT pool's users are separate
  entities. It is being built on `feat/l7v2-traffic`. Schema 2 is not changed here.
- **Until then the checker refuses both, with the reason "address reuse needs schema 3":**
  - two entities on one address fail rule 1 (`l7_dataset.manifest_problems`);
  - an entity carrying several users on one address (`params.users` > 1: `cgnat_browsers`, `nat_gateway`) fails
    rule 13 (`ml/l7_disjoint.py`).

  This matters because under schema 2 a flagged 24-user pool would cost one unit of the 1 % benign budget.
- **The smoke population still contains such entities.** That is allowed, because pilot captures are never fitted on
  (rule 11).

## 11. As built: the curves at the view level (T-025b, 2026-10-30)

- **The models of 6.1 run at the view level.** `ml/learning_curve.py --level view` fits them on identical view
  windows keyed by (IP, UA, sid), built by `ml/train_l7v2.py`: the view GRU, the HGB and LR on token summaries, and the
  shuffled-GRU. `--level view` is the default for L7 v2 (schema 3) captures; `request` stays the default otherwise, so
  every earlier command reproduces.
- **Operating points (6.1)** use the grids and the budget of `ml/p3_prereg.json`, with L7 v2's unit cost and tie rules
  (`ml/l7v2_model_prereg.json`, pinned equal to this protocol's grids and budget). Recall counts every evaluation attack
  entity with a request; an entity without a window counts as missed.
- **The shuffled-GRU is scored at its GRU's (θ, k)**, at both levels. This is the user's decision of 2026-10-31, the
  rule `docs/L7V2_DESIGN.md` section 10 gives the P1 arm. Before that decision, the request level chose the
  shuffled-GRU's own validation point. With the shared point, the gap measures order, not a re-tuned threshold.

## 12. As built: key lifetimes and the evaluation capture's tail (T-041, 2026-10-31, D-034)

- **Re-registered post hoc, before any capture; the user confirmed it on 2026-10-31 ("Confirm 1140 s", D-036)**
  (`ml/p3_prereg.json` `eval_tail_label`). It was committed in the D-034 round, whose text does not cover the capture's
  length. An evaluation or pilot capture now ends with the same 120 s benign tail after the 240 s C3b@M3 slot that every capture has after its
  last slot: 60 + 3 × 240 + 240 + 120 = 1,140 s, instead of 1,020 s. Every key's lifetime now comes from one law
  (`docs/L7V2_DESIGN.md` section 17). Without the tail, the M3 bots' lifetimes and window ages are cut short: window-age
  AUC 0.31 at seed 3201, outside the pre-registered 0.5 ± 0.15.
- **Cost:** +120 s for each of the 10 evaluation and 8 pilot captures, about 36 min of VM time.
- **The curves.** At the view level, the HGB of 6.1 is balanced and runs without early stopping, as the L7 v2 arms do.
  The request level is unchanged: its GRU still keeps its best validation epoch (`ml/train_l7.py`). This is labelled
  here as a residual departure from 6.1's "fixed epochs".
- **The request-level curves are labelled (D-040, T-042 F01).** They key by (IP, UA), and a benign device keeps its address
  and UA for the whole capture, so (IP, UA) key age can carry the role. An (IP, UA)-key age-only baseline now runs beside
  them (`learning_curve.age_only_ip_ua` in `ml/p3_prereg.json`). Unless it reads near chance on validation (AUC
  0.5 ± 0.15), every request-level result is labelled **age-assisted**: expect the label, since the replayed plans read
  0.724 (`docs/L7V2_DESIGN.md` section 18). The view level keys by (IP, UA, sid) and has its own baseline.
