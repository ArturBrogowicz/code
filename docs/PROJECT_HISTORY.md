# What was done: the project's history

A chronological record of the project from the first commit (2026-09-05) to the merge of pull request #5 (2026-11-17,
`4f31066`): for each phase, what was built or measured, the outcome in the evidence's own words, the dates and where the
evidence is. Every date and number below comes from a file of this repository or from its git history at `4f31066`
(`git log --first-parent 4f31066`; dates are author dates, most in UTC, some early ones in UTC+2, the five pull-request
merges in UTC+1). Nothing is softened: where a check failed or a hypothesis was not supported, it says so. How to run
anything named here is in [`GUIDE.md`](GUIDE.md); what each result may be cited for is in
[`THESIS_CLAIMS.md`](THESIS_CLAIMS.md); the published data are indexed in [`results/README.md`](../results/README.md).

| Phase | Dates | In one line |
|---|---|---|
| [0](#phase-0-the-prototype-2026-09-05-to-10-03) | 2026-09-05 to 10-03 | prototype daemon, CIC-IDS2017 GRU, the first suites |
| [1](#phase-1-hardening-and-the-testbed-native-gru-2026-10-05-to-10-11) | 10-05 to 10-11 | rule fixes, the confounded GRU retrained on testbed flows, the availability metric |
| [2](#phase-2-the-first-review-and-its-experiments-2026-10-11-to-10-12) | 10-11 to 10-12 | first independent review: a duplicate-MAC defect; EXP-0 to EXP-2b |
| [3](#phase-3-a-reproducible-harness-and-the-gru-diagnosis-2026-10-13) | 10-13 | ban events, campaign runner, published campaigns; why the GRU never banned |
| [4](#phase-4-the-l7-gru-track-p1-to-p5c4-2026-10-14-to-10-16) | 10-14 to 10-16 | a GRU on Nginx's request log, pre-registered: no advantage |
| [5](#phase-5-the-second-review-new-defaults-exp-a-2026-10-19-to-10-21) | 10-19 to 10-21 | second review, new defaults, run-level statistics, EXP-A, claims page |
| [6](#phase-6-load-generators-exp-c-and-the-harm-benchmarks-offline-tools-2026-10-22-to-10-23) | 10-22 to 10-23 | verified load generators, EXP-C (open-loop attacker), HG1b |
| [7](#phase-7-the-harm-benchmarks-runners-p1-p4-designs-and-the-first-calibration-2026-10-23-to-11-05) | 10-23 to 11-05 | HG1c runners, first VM contact, P1, P3, P4 and HG4 built offline, record of 2026-11-04 |
| [8](#phase-8-the-drift-check-fails-2026-11-05-to-11-12) | 11-05 to 11-12 | the drift check of that record fails, then gives no reading |
| [9](#phase-9-the-laptop-re-calibration-and-p2-2026-11-13-to-11-17) | 11-13 to 11-17 | HS1, re-calibration R1-R4, P2: gate PASS, outcome NOT MET |

## Phase 0: the prototype (2026-09-05 to 10-03)

**Built.** The first commit (`2229aa7`, 2026-09-05) and the CIC-IDS2017 line: `GRU_ML_init.py`, `merge_datasets.py` and
a model in `training_results/` (2026-09-07). A single-attacker suite, `test_mitigation_suite.py`, with scenarios A to M
added one by one from 2026-09-08 to 09-10 (among them Slowloris, a UDP flood, an ACK flood, R.U.D.Y., Yo-Yo and
fragmentation), and from 2026-09-13 the namespace testbed `test_distributed_suite.py` with legit clients and bots on a
bridge. Then the iptables backend (`eee8824`, 2026-09-23), the mode without a daemon (`MITIGATION_MODE=none`, 09-24),
the unprotected Nginx configuration (09-25), performance metrics and softirq/hot-core metrics (09-23 to 10-01), and
multi-queue veth pairs (10-03). An early two-VM layout (`server/`, `attacker/`) was last changed on 2026-10-03.

**Outcome.** Console logs and CSVs only; nothing of this phase is a published result. The README calls these files
legacy ([`README.md`](../README.md), "Repository layout").

## Phase 1: hardening and the testbed-native GRU (2026-10-05 to 10-11)

**Built.** Thread-safe per-IP state (`d72f28f`, 10-05); drift-free slow-connection detection from the socket table
(`f46a485`, 10-06); measurement-phase fixes in the suite (10-06); an end to false bans of lossy legit clients
(`461e646`, 10-07); low-and-slow SYN detection (`8abd515`, 10-09); flow-age gating after floods (10-10); the continuous
availability metric before, during and after each attack (`00c0685`, 10-10).

**The GRU.** [`ml_confounding_analysis.md`](ml_confounding_analysis.md) (2026-10-07): "The previously reported ~0.9999
F1 is an artifact of **dataset/source confounding**, not DDoS-detection skill." The pipeline was rewritten on a
de-confounded CIC-IDS2017 capture (`acdbf92`, 10-07, which added `build_cicids2017_dataset.py`) and then replaced by a
testbed-native ("Tier-1") GRU trained on flows captured with the same XDP map that feeds it at inference (`2e93e0e`,
10-08; `capture_testbed_dataset.py`, `train_testbed_gru.py`, `b1f1ff0`, 10-09). That model is the one in
`training_results/` today.

**Measured.** A campaign of 3 modes x 3 runs x 10 scenarios on 2026-10-11, published as
[`results/2026-10-11_superseded-dup-mac/`](../results/2026-10-11_superseded-dup-mac/), **superseded** by the defect
found next.

## Phase 2: the first review and its experiments (2026-10-11 to 10-12)

**The review** ([`REPORT.md`](REPORT.md), 2026-10-11, at `6fc27fa`). XDP drops banned traffic before the IP stack, and
the Tier-1 training reproduces bit for bit, "However, the comparative results do not measure what the thesis figures say
they measure". Its top risks: a **testbed L2 defect** (every client and bot interface had the same name and therefore
the same udev-derived MAC address on one bridge, so legit responses were delivered into bot namespaces); an availability
metric not comparable across modes; n = 3 runs per mode (a minimum detectable difference of 43-55 pp for most
scenarios); a GRU that "learned tool/OS fingerprints and has no demonstrated marginal value"; lost daemon logs and
harness defects (the R.U.D.Y. detector "never fired once").

**The experiments** ([`REPORT_ADDENDUM_EXP0_EXP1.md`](REPORT_ADDENDUM_EXP0_EXP1.md), 2026-10-12). EXP-0 reproduced the
duplicate MAC. The fix (`51cc21c`, 2026-10-12: unique veth MACs, an Nginx restart fix and a cap on the GRU feed, F-45)
"alone takes legit availability from ≈ 32-36 % to **100 %** under every flood". Then EXP-1/1b/1c (the full suite, 4
modes x 3 runs), EXP-1d (a calibration sweep), EXP-2a (the HTTP flood at a capacity-limited "knee"), EXP-2b (Nginx
limits with a tuned configuration) and the F-45 validation. Published on 2026-10-13 (EXP-2a) and 2026-10-21 (the rest):

| Entry | Outcome (the entry's own words) |
|---|---|
| [`2026-10-12_exp1-default-4modes_prototype`](../results/2026-10-12_exp1-default-4modes_prototype/) | legit success 100 % in every mode (17,363 requests during the attacks, 1 failed); the modes differ in L7 latency, Nginx CPU and pre-stack drop; 300 bans, all of bots, none by the GRU |
| [`2026-10-12_exp1d-calibration-sweep_raw`](../results/2026-10-12_exp1d-calibration-sweep_raw/) | only 1 worker x 1 thread on cpu0 with `wrk -c400` from 10 bots lost legit requests (76.7 % during): this became the "knee" |
| [`2026-10-12_exp2a-knee_prototype`](../results/2026-10-12_exp2a-knee_prototype/) | during the flood: XDP + daemon 100 %, iptables + daemon 100 %, Nginx limits only 52.2 %, unprotected 89.9 % |
| [`2026-10-12_exp2b-knee-nginxtuned_prototype`](../results/2026-10-12_exp2b-knee-nginxtuned_prototype/) | Nginx limits only, tuned: 62.1 %, Nginx at 96 % of cpu0 |
| [`2026-10-12_f45-ack-stall-validation_prototype`](../results/2026-10-12_f45-ack-stall-validation_prototype/) | 30 of 30 bots banned by the L4 volumetric rule 0.27-2.10 s after the Phase-1 timestamp, none by the GRU |

Checked later against these data ([`2026-10-21_prototype-claims-check`](../results/2026-10-21_prototype-claims-check/)):
139 comparisons with the addendum, 129 match, 4 differ, 6 cannot be checked (the four are in the errata of
[`results/README.md`](../results/README.md)).

## Phase 3: a reproducible harness and the GRU diagnosis (2026-10-13)

**Built** in one day: machine-readable ban events (`ban_events.py`, `033d4b6`, `0563c0d`); a reproducible, ground-truth
evaluation harness in the suite (`fddc4a1`: a results directory per run, time to mitigate and false positives from the
ban events, the `default` and `knee` operating points, the fourth mode `NGINX_PROTECTED=1`, `PROFILE_SEED`,
`ATTACK_DURATION`); the campaign runner, analysis, figures and publisher (`c55049d`); [`EVALUATION.md`](EVALUATION.md)
(`efc5994`).

**Measured and published.** EXP-2a imported; R3 (EXP-2a re-recorded, interleaved and paired) and R4 (the same with 30 s
of equal exposure); R2, one run of all ten scenarios in XDP mode for regression. At run level none of the knee contrasts
is significant with 3 blocks (R3: daemon +21.0 pp [-5.5, +47.4]; R4: daemon +28.0 pp [-15.3, +71.3]); what is consistent
is the direction ([`EVALUATION.md`, "Statistics"](EVALUATION.md#statistics)).

**The GRU** ([`ML_INVESTIGATION.md`](ML_INVESTIGATION.md), 2026-10-13, final 2026-10-14). "**Zero GRU bans.** The GRU
never reaches a decision before a heuristic bans the same IP"; it is "the slowest engine for every attack in the suite",
paused by floods, blind to hping3 flows and not fed UDP. The model separates R.U.D.Y. by request size, "a tool
fingerprint, not by behavior"; the CIC-IDS2017 AUC of about 0.1 "depends on how benign hosts are sampled". The proposed
experiment EXP-3 was put on hold on 2026-10-14 (`3842efc`) and never ran.

## Phase 4: the L7 GRU track, P1 to P5c.4 (2026-10-14 to 10-16)

**Designed and built** ([`L7_GRU_DESIGN.md`](L7_GRU_DESIGN.md)): Nginx writes an extended JSON request log to a datagram
socket; the daemon's shadow engine (`L7_SHADOW=1`) scores per-(IP, User-Agent) request windows with a GRU and logs what
it would ban, never banning. Each phase had a gate and the evaluation a pre-registered verdict.

| Phase | Entry | Outcome |
|---|---|---|
| P1 ingestion | [`2026-10-14_l7-p1-smoke`](../results/2026-10-14_l7-p1-smoke/) | gate PASS (socket transport in shadow mode) |
| P2 scoring | [`2026-10-15_l7-p2-smoke`](../results/2026-10-15_l7-p2-smoke/) | gate PASS (scoring, replay determinism, probes) |
| P3 capture | [`2026-10-15_l7-p3-capture`](../results/2026-10-15_l7-p3-capture/) | gate PASS (labelled dataset) |
| P4 training | [`2026-10-15_l7-p4-train`](../results/2026-10-15_l7-p4-train/) | held-out 7/8 at 0 FP, exact-probe gate PASS; candidate not promoted |
| P5 shadow evaluation | [`2026-10-16_l7-p5-eval`](../results/2026-10-16_l7-p5-eval/) | the GRU flagged the fast sub-threshold attackers at 0 benign FP, "but a static 10 rps limit matched it": **marginal value NOT shown** |
| P5c.1 baseline | [`2026-10-16_l7-p5c-baseline`](../results/2026-10-16_l7-p5c-baseline/) | the default rules banned a 60-asset page load (`l7_rate`) and both CGNAT gateways (`l4_slowconn`) |
| P5c.2 tolerant profile | [`2026-10-16_l7-p5c2-tolerant-verify`](../results/2026-10-16_l7-p5c2-tolerant-verify/) | gate PASS: 0 of 20 benign IPs banned |
| P5c.3 capture, training | [`..._l7-p5c3-capture`](../results/2026-10-16_l7-p5c3-capture/), [`..._l7-p5c3-train`](../results/2026-10-16_l7-p5c3-train/) | candidate `no_size_no_server_timing`, held-out attacks 7/8, 0 benign-test FP |
| P5c.4 evaluation | [`2026-10-16_l7-p5c4-eval`](../results/2026-10-16_l7-p5c4-eval/) | tolerant rules 0/20, GRU 20/20 at 9 % benign flagged, per-(IP, UA) rate rules and the tabular model 20/20 at 2 %: **pre-registered verdict: no advantage** (`3086e27`) |

P6 (promotion) was not proposed. The second review later found that the labelled attackers "cause no measurable harm"
(benign success 1.0 and median server time 2.0 ms with and without them) and that the "GRU beats the tabular baseline"
claim rests on one held-out attacker; both are in the errata of [`results/README.md`](../results/README.md).

## Phase 5: the second review, new defaults, EXP-A (2026-10-19 to 10-21)

**The review** ([`project_analysis_v2/REPORT.md`](project_analysis_v2/REPORT.md), 2026-10-19, at `3086e27`). Every
published analysis, verdict, diagnosis and model reproduced bit for bit, but "the deployed default runs a ban-capable
model with no true positives and one recorded false positive" (the XDP-fed GRU banned a legit client once), "the L7
evaluation measures label classification, not mitigation", comparisons rested on 3 runs per mode, and the deployed
detection code had no behavioural tests.

**Changed, 2026-10-19** ([`EVALUATION.md`, "Defaults changed on
2026-10-19"](EVALUATION.md#defaults-changed-on-2026-10-19)): `XDP_GRU` defaults to 0; the L7 syslog sink only where the
shadow engine runs; XDP rejects `ihl < 5`; `telemetry_map` becomes an LRU hash. Then a run-level statistics tool with a
decision rule fixed before any 10-block data (`8d26335`, 2026-10-20: a contrast is *supported* with at least 10 paired
blocks, a 95 % t-interval excluding 0 and 80 % of blocks with the sign), characterization tests of the daemon's live
rules (`618b2fc`), and [`THESIS_CLAIMS.md`](THESIS_CLAIMS.md) (`a9788fd`, 2026-10-20).

**Measured, 2026-10-20** (published 2026-10-21):

| Entry | Outcome |
|---|---|
| [`2026-10-19_baseline-before-audit-defaults`](../results/2026-10-19_baseline-before-audit-defaults/) | full suite, XDP-fed GRU still on: 10/10 PASS (one run) |
| [`2026-10-20_regression-after-audit-defaults`](../results/2026-10-20_regression-after-audit-defaults/) | full suite on the new defaults: 10/10 PASS, the same engines (one run) |
| [`2026-10-20_expb-tolerant-profile-suite`](../results/2026-10-20_expb-tolerant-profile-suite/) | EXP-B, tolerant profile, 3 runs: Slowloris and R.U.D.Y. 0/5 banned in every run, the other 8 scenarios 5/5 |
| [`2026-10-20_expa-knee-10-blocks`](../results/2026-10-20_expa-knee-10-blocks/) | EXP-A, HTTP flood at the knee, 4 modes x 10 paired blocks: daemon (XDP or iptables) 100 % in all 10 blocks against 66.8 % unprotected (+33.2 pp [+26.1, +40.2]); Nginx limits only 44.4 % (-22.5 pp [-32.0, -13.1]); all three contrasts meet the rule |
| [`2026-10-20_omitted-runs`](../results/2026-10-20_omitted-runs/), [`2026-10-20_audit-derived`](../results/2026-10-20_audit-derived/) | four small runs not published before (among them the GRU's only ban, a false one); the derived analyses behind the review |

On 2026-10-21 the prototype campaigns of 2026-10-12 were published and checked (phase 2), and the ban-event census was
folded together: **52 distinct logs, 710 bans, one GRU ban, a false one**
([`2026-10-20_audit-derived/events_census.md`](../results/2026-10-20_audit-derived/events_census.md)).

## Phase 6: load generators, EXP-C and the harm benchmark's offline tools (2026-10-22 to 10-23)

**The harm benchmark's design** ([`BENCHMARK_HARM_DESIGN.md`](BENCHMARK_HARM_DESIGN.md), approved by 2026-10-22): an
attack must be shown to harm an unprotected server before any mitigation is judged against it, with open-loop load and a
calibration of the host.

**HG1a, the load generators** (2026-10-22). A wrapper and verification harness (tests V0-V7) for vegeta, k6 and the
in-repo engine `bench/loadgen.py`. The pilot exposed six harness faults and is not used; run 2: "k6 and the engine pass
V1-V6, vegeta fails V3 ... and V5 (silent shortfall of 20,307 of 40,000)"; the V3 repeat: engine 3 of 3, k6 1 of 3,
vegeta 0 of 3. k6 and the engine were marked `verified`, vegeta stays `smoke-tested` (criteria version 2 and two
amendments labelled post hoc). Entries:
[`..._loadtool-validation-pilot`](../results/2026-10-22_loadtool-validation-pilot/),
[`..._loadtool-validation-run2`](../results/2026-10-22_loadtool-validation-run2/),
[`..._loadtool-validation-v3-repeat`](../results/2026-10-22_loadtool-validation-v3-repeat/).

**EXP-C** ([`EXPC_ATTACKER_SETTING_DESIGN.md`](EXPC_ATTACKER_SETTING_DESIGN.md), [`EXPC_PROTOCOL.md`](EXPC_PROTOCOL.md),
2026-10-22/23). The HTTP flood's load model became a setting; a probe and a refinement ramp placed the open-loop cells
(R50 = 250 requests/s per bot, under amendment A); then 120 runs, protocol committed first:

> Closed loop: daemon +22.5 pp, limits only -34.3 pp against unprotected (77.5 %). Open loop (unprotected 100, 42.1 and
> 11.4 %): daemon and limits only both serve 100 % in every block, +57.9 and +88.6 pp where the server is harmed; HYP-5
> not contradicted and HYP-6 held.

(the index row of [`results/README.md`](../results/README.md) for
[`2026-10-23_expc-open-vs-closed-loop`](../results/2026-10-23_expc-open-vs-closed-loop/))

So EXP-A's "rate limiting alone is worse than no protection" holds for the closed-loop attacker only (claim M4).

**HG1b** ([`HG1B_MINIMAL_DESIGN.md`](HG1B_MINIMAL_DESIGN.md), built 2026-10-23, offline): the cost-calibrated origin,
the calibration record, the population, the scenario record and its plan, and the harm gate (`eval/harm_gate.py`, Gate
A).

## Phase 7: the harm benchmark's runners, P1-P4 designs and the first calibration (2026-10-23 to 11-05)

**HG1c** ([`HG1C_DESIGN.md`](HG1C_DESIGN.md), written 2026-10-23, built from 2026-10-24): the executor (one run in the
namespaces, the run contract), the gate campaign (blocks of `C`, `Cp`, `U`, re-run rule, resume, `--simulate`), the
calibrator, and the simulated host. **First contact with the VM**, S1 to S4 (2026-10-24 to 10-28), and HG2a/HG2b (the
first capacity and origin steps, 2026-10-28/29) found clock, start-up, Nginx-start and straggler problems; each fix is a
dated departure in section 14 of the note, five of them (16, 21-24) marked POST HOC.

**An orchestrated phase** began with a review on 2026-10-29 (cited in [`EVALUATION.md`](EVALUATION.md)); from then on
the commit messages name the orchestrator's tasks (T-0xx, T-1xx) and its ledger's decisions (D-0xx, D-1xx). The review
led to the daemon robustness fixes of 2026-10-30 (H-01: one non-UTF-8 request stopped the defence and lifted every ban;
H-02: worker threads died silently; H-03: Gunicorn reachable around Nginx; H-26: the R.U.D.Y. rule's client field),
[`EVALUATION.md`, "Daemon robustness"](EVALUATION.md#daemon-robustness-2026-10-30), all checked offline only.

**P1, P3, P4 designed and built offline** (designs approved 2026-10-30): [`L7V2_DESIGN.md`](L7V2_DESIGN.md) (P1: a
costed, enforcing L7 harness and its arms), [`P3_DATASET_DESIGN.md`](P3_DATASET_DESIGN.md) (entity-disjoint datasets and
learning curves), [`P4_SLOW_DESIGN.md`](P4_SLOW_DESIGN.md) (a per-connection slow rule, `slow_pc.py`, on a realistic
profile R). Each has pre-registration records (`ml/*prereg*.json`, `eval/p4_outcome.py`, frozen grids pinned by tests)
with dated re-registrations, all "before any data". **HG4**, the harm benchmark's protected arms (`M_xdp`, `M_limits`),
was built the same week, and P2's outcome rule was fixed before any protected run (`029a202`, 2026-10-30).

**The first calibration record**, `bench/calibration/ddos-mitigation-2026-11-04.json`, was frozen on 2026-11-04 on the
desktop host (kernel 7.0.0-38, 9,426 MiB; record hash `cff6e515...`; committed in `a2143a1`): knees cheap 2, export 4,
search 4. **PR #1** (394 commits, 2026-10-22 to 11-05) merged on 2026-11-05 (`fb314e9`).

## Phase 8: the drift check fails (2026-11-05 to 11-12)

**PR #2** (review fixes of P1 and P4, 40 commits) merged on 2026-11-07 (`1cdda9b`). Before any campaign may use a
record, `bench/calibrate.py drift` must reproduce its reference.
[`2026-11-11_harm-drift-check`](../results/2026-11-11_harm-drift-check/): "**The check never passed.**" AP-4
(2026-11-08) failed twice (export Q -20.07 pp, then cheap Q -17.27 pp); the quiet repeats AP-5 and AP-5b (2026-11-10)
were cut by host resets and AP-7 (2026-11-11) stopped when the origin refused its own start (routes 26-68 % above the
frozen costs on a slowed host). All 5 complete attempts fall outside the single-run rule, in both directions. "The
record is not confirmed ... and **no harm-benchmark result exists**." The guest's kernel (7.0.0-42 against the record's
-38) and memory (7,422 MiB from AP-5 on) had also changed. Claim HB1: **not confirmed**; no claim rests on that record.

The thesis' practical chapters had been written just before this phase (2026-11-04 and 05,
[`PROJECT_ROADMAP.md`](PROJECT_ROADMAP.md)), P1 and P4 gained ladder extensions and further review fixes, and **PR #3**
(87 commits) merged on 2026-11-12 (`efa8f54`), with the second review's report added at the path the evaluation manual
cites (`c2b0324`).

## Phase 9: the laptop re-calibration and P2 (2026-11-13 to 11-17)

**The host.** The VM moved from the desktop to a laptop (AMD Ryzen 7 7730U, VirtualBox 7.2.10). HS1, a pre-registered
3-h stability check of the idle laptop ([`HS1_PREREG.md`](HS1_PREREG.md)), passed on 2026-11-14; its route-cost medians
became the re-calibration's speed reference. The laptop's route probes were 42-50 % slower than the 2026-11-04 record on
C1-C5, so that record could not be used there
([`2026-11-15_harm-recalibration/README.md`](../results/2026-11-15_harm-recalibration/README.md)).

**The re-calibration** ([`RECALIBRATION_2026-11_DESIGN.md`](RECALIBRATION_2026-11_DESIGN.md) of 2026-11-13;
pre-registration [`RECALIBRATION_2026-11_PREREG.md`](RECALIBRATION_2026-11_PREREG.md) approved 2026-11-15, committed at
`5f3769c` before R1), 2026-11-15 18:09Z to 2026-11-16 12:33Z, one session, every step its own approval:

| Step | Outcome |
|---|---|
| R1 | route costs C1 5.113, C2 2.651, C3 42.712, C5 231.960 ms; C_slo 84.5, C_sat 241.3 req/s |
| R2a-c | knees: cheap 4, export 4 (dose-response not monotone at the bottom), search 2; R2a's first packet paused "host unfit" after 4 runs were set aside by a race in the end-of-window check H7 |
| departure 1 | H7 reads the monitors 2 s after a run's window (K22, **post hoc**, `9c0c25a`); everything after R2a's resume rests on it |
| R3 | the reference, 5 rounds; the export flood's SD of Q 5.77 pp, above 5, so it is frozen "wide spread" (D6) |
| F | record `bench/calibration/ddos-mitigation-2026-11-16.json`, hash `7005a2ed...`, created 10:05:07Z, committed at `ec819fb` |
| R4 | after a reboot: **CONFIRMED** for legit and every family, the export flood with the D6 label |

Claim HB2: **supported with scope** (the laptop only, one confirmation window, departure 1 post hoc). Raw data, every
packet log and a recomputation with 0 mismatches (the freeze byte-identical):
[`results/2026-11-15_harm-recalibration/`](../results/2026-11-15_harm-recalibration/).

**P2** ([`results/2026-11-16_harm-p2-hg4/`](../results/2026-11-16_harm-p2-hg4/)): HG4's cheap static flood at level 8
(twice the new cheap knee, about 119 requests/s from each of 5 sources), blocks of `C`, `Cp`, `U` and `M_xdp` (Nginx's
limits plus the daemon banning into XDP), on 2026-11-16:

* **P2-1** (two smoke runs): passed its evidence list; "not host-checked; not a result".
* **P2-2**: **INVALID**, 4 valid blocks of the 10 the gate needs; in 3 runs the attack began 0.51-0.52 s before the
  baseline's end (limit 0.5 s), because it was launched on a fixed delay that the legit engines' start-up outran.
* **K23** (post hoc, `18386ed`, [`HG1C_DESIGN.md`](HG1C_DESIGN.md) departure 42): the attack is launched from the legit
  engines' observed start. The fix and one repeat were decided before any arm figure of P2-2 was read; that is a post
  hoc decision, since rule R-5 allowed a repeat after INVALID only for environmental reasons
  ([`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), HB3).
* **P2-2b**, 41 runs: **gate PASS** (dQ +98.49 pp [+98.17, +98.81], dL +3.33 [+2.92, +3.75]; the placebo did not pass);
  **P2 outcome of `M_xdp`: NOT MET**. The unprotected server failed in 10 of 10 blocks; the protected one held Q(M) >=
  0.99 x Q(C) in **0 of 10** (Q(M)/Q(C) 0.937-0.974). No legit identity was banned, all 50 attack identities were
  (`l7_rate`; time to mitigate median 0.868 s, max 1.723 s). Descriptively, the loss fell in the attack's first two to
  three seconds, as answers over the SLO.

Claim HB3: **contradicted at the pre-registered 0.99 ratio** (gate PASS, outcome NOT MET), for one family, one level,
one host and `M_xdp` only, after a post hoc fix of the attack's launch. No further P2 campaign runs after NOT MET (rule
R-5).

**Published and merged.** P2 and the thesis update went into **PR #4** (54 commits), merged on 2026-11-17 (`c6579fd`);
the re-calibration's raw data, a `.gitattributes` that keeps published results byte-exact, and the thesis' citations of
them into **PR #5** (9 commits), merged on 2026-11-17 (`4f31066`).

## What exists

| Kind | What | Where |
|---|---|---|
| Code | the daemon and its XDP program, six deterministic engines, the tolerant profile; optional XDP-fed GRU, L7 shadow engine, L7 v2 enforcing arm, per-connection slow rule (all off by default) | `control_plane.py`, `xdp_ddos_filter.c`, `l7_*.py`, `slow_pc.py` |
| Code | the namespace suite (10 scenarios, 4 modes) and the campaign tools | `test_distributed_suite.py`, `eval/` |
| Code | the harm benchmark: origin, load generator, population, scenarios, executor, gate campaign, harm gate, calibrator, host check, packets, simulated host | `bench/`, `eval/harm_gate.py` |
| Code | the L7 and P1/P3/P4 pipelines and their pre-registrations | `ml/`, `eval/p1_*.py`, `eval/p4_*.py` |
| Tests | about 3,600 offline unit tests (3,579 at `18386ed`), one known environmental failure | `tests/`, [`GUIDE.md`](GUIDE.md) 11.5 |
| Published results | 36 entries, 35 with `SHA256SUMS` (all pass at `4f31066`), one superseded | [`results/README.md`](../results/README.md) |
| Claims | M1-M7, L1-L4, Q1-Q2, HB1-HB3, each with its strongest supported wording and verdict | [`THESIS_CLAIMS.md`](THESIS_CLAIMS.md) |
| Thesis | `thesis/main.tex` (Polish), a slide deck | `thesis/`, `presentation/` |

The verdicts, as [`THESIS_CLAIMS.md`](THESIS_CLAIMS.md) gives them at `4f31066`: M1 supported with scope; M2 partly
supported; M3 supported with scope; M4 supported with scope (closed-loop attacker only); M5 contradicted as a general
claim; M6 supported as bounds per rule; M7 not supported; L1 contradicted for the suite's attacks in the deployed
configuration; L2 not supported; L3 not supported; L4 partly supported; Q1 supported for what is published; Q2 supported
with scope; HB1 not confirmed; HB2 supported with scope; HB3 contradicted at the pre-registered 0.99 ratio.

## What has not run

| Item | Status | Why, as far as the repository says |
|---|---|---|
| P1, the L7 v2 arms ([`L7V2_DESIGN.md`](L7V2_DESIGN.md)) | built, pre-registered, tested offline; no run on the VM | its status line: "no P1 run exists"; the VM time from 2026-11-08 went to the drift check, the move to the laptop, the re-calibration and P2 (phases 8 and 9) [inference from the dates] |
| P3, entity-disjoint datasets and learning curves ([`P3_DATASET_DESIGN.md`](P3_DATASET_DESIGN.md)) | built offline; "no capture has run on the VM" | as P1 |
| P4, the per-connection slow rule ([`P4_SLOW_DESIGN.md`](P4_SLOW_DESIGN.md)) | built offline; "no P4 run exists" | as P1; its own VM budget is about 12.9 h ([`EVALUATION.md`](EVALUATION.md#p4-the-per-connection-slow-rule-and-profile-r-2026-10-30)) |
| P2 beyond `M_xdp` on the cheap flood at level 8 | not run | other families and levels, `M_limits` and the GRU arms are outside P2-2b; after NOT MET no further P2 campaign runs (R-5); a later campaign needs a drift check first ([`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), HB3) |
| HG3, the gate at the knee without protected arms | not run | the 2026-11-04 record was never confirmed; on the laptop only P2 (HG4) ran |
| EXP-3, the XDP-GRU experiment | on hold since 2026-10-14, never run | the focus moved to the L7 track ([`ML_INVESTIGATION.md`](ML_INVESTIGATION.md)) |
| P6, promotion of the L7 model | not proposed | P5c.4's verdict: no advantage |
| A time-to-mitigate distribution over 10 or more default runs (M6); slow attacks around the SlowConn threshold (M7); a live `hping3 --rand-source` flood with the daemon polling; the remaining XDP parser checks (G-17) | not run | listed as open in [`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), "What was run on 2026-10-20 and what remains" |
| The failure paths of the daemon's robustness fixes (raw bytes from Nginx, a full blacklist map, a real SIGTERM) and the L7 v2 arm on live traffic | checked offline only ([NOT RUN] in [`EVALUATION.md`](EVALUATION.md)) | no suite run since 2026-10-23; P2's `M_xdp` ran the fixed daemon in normal operation, with the L7 arm and the slow rule off |
| An operating point at which the volumetric floods degrade the unprotected server | "that calibration has not been done yet" ([`EVALUATION.md`, "Settings"](EVALUATION.md#settings)) | |
| vegeta as a verified generator | stays `smoke-tested` | it passed V3 in 0 of 3 repeats ([`bench/loadtools.json`](../bench/loadtools.json)) |
