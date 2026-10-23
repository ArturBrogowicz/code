# Published results

One directory per evaluation campaign. A published campaign is not edited afterwards:
a new measurement is a new campaign.

| Campaign | Content | Status |
|---|---|---|
| [`2026-10-23_expc-r50-refinement`](2026-10-23_expc-r50-refinement/) | The refinement ramp of the EXP-C probe (190, 230 and 270 requests/s per bot, unprotected knee server, 30 s, one run each) and R50 under amendment A, read on the nominal axis: the legit success is 100 % at 190, 65.3 % at 230, 36.0 % at 270 (19.7 % at 320, 1.8 % at 640, from the first part), so R50 is 2,501 requests/s in total, 250 per bot; the default cells would be 125, 250 and 500 per bot. The server answered 1,842 requests/s at 190 | pilot: one run per rate, no replicates; the three EXP-C rates are the user's to fix; corrects two statements of the first part (Errata) |
| [`2026-10-22_expc-r50-probe`](2026-10-22_expc-r50-probe/) | The probe that places the EXP-C cells: the unprotected knee server under the HTTP flood (30 s), closed-loop `wrk` twice and the open-loop engine at 20-640 requests/s per bot, one run each (8 runs). Up to 80 per bot (800/s) the legit clients see 100 % at a median of 3-7 ms; at 160 (1,600/s) 100 % at 731 ms; at 320 and 640 19.7 % and 1.8 %. R50 as pre-registered (a measured offered rate) is not defined, because the logged rate stops near 1.6 k/s, so the refinement rule applies | pilot: one run per rate, no replicates; includes the aborted first attempt (the suite killed its own runner); its README lists two harness defects |
| [`2026-10-22_loadtool-validation-v3-repeat`](2026-10-22_loadtool-validation-v3-repeat/) | V3 (latency accuracy) of the load-generator verification repeated 3 times per tool, with an unscored warm-up job, on loopback: the in-repo engine passes 3 of 3, k6 1 of 3, vegeta 0 of 3 (the warm-up fails too). The origin's own tail was calm (p99 16.6-28.4 ms), and vegeta's p99 read 5.2-16.3 ms above it, k6's up to 5.9 ms, the engine's within 1.8 ms (tolerance about 2 ms): on this VM only the engine meets V3 at p99. Criteria version 2, repeats and the all-must-pass rule post hoc; read `NOTES.md` first | valid; a single session; the consequences for the manifest statuses of k6 and vegeta are for the owner to decide |
| [`2026-10-22_loadtool-validation-run2`](2026-10-22_loadtool-validation-run2/) | Corrected run of the load-generator verification (tests V0-V7 of `docs/BENCHMARK_HARM_DESIGN.md` 8.4, criteria version 2: the pre-registered criteria plus two amendments labelled post hoc, A1 and A2, and the design's own V7 adherence criterion): vegeta v12.13.0, k6 v2.3.0, the in-repo engine `bench/loadgen.py` and a closed-loop wrk control against loopback origins, 58 jobs, 27 min wall, no infrastructure error. k6 and the engine pass V1-V6, vegeta fails V3 (a job in which the origin itself stalled for a second) and V5 (silent shortfall of 20,307 of 40,000); highest rate held on one core 2,000 (vegeta), 2,000 (k6), 10,000 (engine, above its own CPU limit); the VM's late timer wake-ups dominate V3 and flag the engine's slip gate; read `NOTES.md` first | valid; a single run; on 2026-10-22 the owner applied its suggested statuses to the manifest for k6 and the engine (`verified`); vegeta stays `smoke-tested` until V3 is repeated |
| [`2026-10-22_loadtool-validation-pilot`](2026-10-22_loadtool-validation-pilot/) | First run of the load-generator verification (tests V0-V7 of `docs/BENCHMARK_HARM_DESIGN.md` 8.4): vegeta v12.13.0, k6 v2.3.0, the in-repo engine `bench/loadgen.py` and a closed-loop wrk control against loopback origins, 58 jobs, 18 minutes of load; no infrastructure error, every tool's real output parsed. The run exposed six faults of the harness and protocol (generic settings, a V7 criterion that counted totals, no socket hygiene, a control that corrects for coordinated omission itself, ...), so its verdicts are not used and no tool status was changed; read `NOTES.md` first | pilot; superseded by `2026-10-22_loadtool-validation-run2`; its README and `results.json` were produced by the harness at `00275f5` and reproduce byte for byte only there (later: `reanalyse --rejudge-into`, never in place) |
| [`2026-10-21_prototype-claims-check`](2026-10-21_prototype-claims-check/) | The addendum of 2026-10-12 (sections A-I, K, L, M) against the published prototype campaigns: 139 comparisons, 129 match, 4 differ, 6 cannot be checked; the ban events of the converted campaigns: 330 bans, none by the GRU | derived, not a measurement; `regenerate.sh` rebuilds it byte for byte |
| [`2026-10-20_expa-knee-10-blocks`](2026-10-20_expa-knee-10-blocks/) | EXP-A: the HTTP flood at the knee, 4 modes × 10 paired blocks, 30 s exposure: the daemon (XDP or iptables) served 100 % of the legit requests in all 10 blocks against 66.8 % unprotected (+33.2 pp [+26.1, +40.2]); Nginx limits only 44.4 % (-22.5 pp [-32.0, -13.1]); all three contrasts meet the pre-registered run-level rule | valid; 10 paired runs per mode; one scenario, a closed-loop attacker; see its README |
| [`2026-10-20_expb-tolerant-profile-suite`](2026-10-20_expb-tolerant-profile-suite/) | EXP-B: the full suite (10 scenarios, XDP) under the tolerant heuristic profile, 3 runs: Slowloris and R.U.D.Y. 0/5 banned in every run (the predicted cost of SlowConn 180), the other 8 scenarios 5/5 | valid; 3 runs; the security-cost table the L7 track never produced; see its README |
| [`2026-10-20_regression-after-audit-defaults`](2026-10-20_regression-after-audit-defaults/) | The full suite (10 scenarios, XDP, default settings) on the 2026-10-19 change set, XDP-fed GRU off: 10/10 PASS, the same engines as the baseline | a single run, taken 3 minutes after a VM restart; the post-change run the baseline README announces; see its README |
| [`2026-10-20_audit-derived`](2026-10-20_audit-derived/) | Derived analyses behind the second audit, from published data only: order-shuffle ablation of the L7 GRU, harm / per-role flags / realised rates of P5c.4, run-level statistics of the knee campaigns, ban-event census (52 distinct logs, 710 bans, the converted prototype campaigns included; 1 GRU ban, a false one) | derived, not a measurement; `regenerate.sh` rebuilds it byte for byte |
| [`2026-10-20_omitted-runs`](2026-10-20_omitted-runs/) | Four small runs recorded in 2026-10-13..16 and not published then: the P1 smoke with the XDP-fed GRU's only ban (a false one), a clean P1 repeat, the aborted first P5 attempt, the R1 ban-event smoke | valid evidence runs, not comparison campaigns; see its README |
| [`2026-10-19_baseline-before-audit-defaults`](2026-10-19_baseline-before-audit-defaults/) | Full suite (10 scenarios, XDP, default settings) before the 2026-10-19 default changes, XDP-fed GRU still on: 10/10 PASS | a single run; the baseline for the post-change run; see its README |
| [`2026-10-16_l7-p5c4-eval`](2026-10-16_l7-p5c4-eval/) | P5c.4: 5 seeds + soak, tolerant heuristics, realistic benign mix: tolerant rules caught 0/20 fast sub-threshold attackers; GRU 20/20 but 9 % benign flagged; per-(IP, UA) rate rules and the tabular model also 20/20 at 2 % → pre-registered verdict: no advantage | valid; see its README |
| [`2026-10-16_l7-p5c3-train`](2026-10-16_l7-p5c3-train/) | P5c.3 training: candidate `no_size_no_server_timing`, probe gate PASS (strict server_load, pad_request); held-out attacks 7/8, 0 benign-test FP; held-out API client flagged (R16) | P5c.4 candidate (not promoted); see its README |
| [`2026-10-16_l7-p5c3-capture`](2026-10-16_l7-p5c3-capture/) | P5c.3 training dataset: full realistic benign mix + calibrated sub-threshold attacks under the tolerant profile; 31,623 lines, all kinds/families present, 0 nginx rejections | gate artifact + P5c.3 training input; see its README |
| [`2026-10-16_l7-p5c2-tolerant-verify`](2026-10-16_l7-p5c2-tolerant-verify/) | P5c.2 gate: the same benign-only run under the frozen tolerant profile: 0 of 20 benign IPs banned (the 60-asset page and both CGNAT gateways now run in full) | valid; gate PASS; see its README |
| [`2026-10-16_l7-p5c-baseline`](2026-10-16_l7-p5c-baseline/) | P5c.1: default heuristics vs realistic benign only (1 run): `l7_rate` banned a 60-asset page load, `l4_slowconn` banned both CGNAT gateways (one after only two users); the shadow GRU's flags on P5 clients came from load-driven server timing (R17) | valid; evidence run, not a comparison campaign; see its README |
| [`2026-10-16_l7-p5-eval`](2026-10-16_l7-p5-eval/) | L7 GRU online evaluation in shadow (P5): 4 runs; GRU flagged all fast sub-threshold attackers at 0 benign FP, but a static 10 rps limit matched it → pre-registered verdict: marginal value NOT shown in this testbed | valid; see its README |
| [`2026-10-15_l7-p4-train`](2026-10-15_l7-p4-train/) | L7 GRU training (P4 gate): candidate model package + metrics; dropping size features → held-out 7/8 at 0 FP, GRU beats tabular baseline, exact-probe gate PASS | gate artifact + P5 candidate (not promoted); see its README |
| [`2026-10-15_l7-p3-capture`](2026-10-15_l7-p3-capture/) | L7 capture dataset (P3 gate): labelled l7json access log + manifest; feature review confirms size/URI now behavioural (R4), low-and-slow barely logs (R1) | gate artifact + P4 training input; see its README |
| [`2026-10-15_l7-p2-smoke`](2026-10-15_l7-p2-smoke/) | L7 shadow-engine P2 verification-gate smoke: scoring, flood gating, record→replay determinism, probes, feature review (untrained model) | gate artifact, **not a comparison campaign**; see its README |
| [`2026-10-14_l7-p1-smoke`](2026-10-14_l7-p1-smoke/) | L7 ingestion P1 verification-gate smoke (`docs/L7_GRU_DESIGN.md`): socket-transport health in shadow mode | gate artifact, **not a comparison campaign**; see its README |
| [`2026-10-13_regression-default-full-suite`](2026-10-13_regression-default-full-suite/) | R2: one run of all 10 scenarios in XDP mode at default settings; the regression check of the harness and the event source of the GRU diagnosis | valid; a single run, for regression and diagnosis, not for comparisons between modes |
| [`2026-10-13_regression-default-full-suite-replicate`](2026-10-13_regression-default-full-suite-replicate/) | A second run of R2's design, recorded the same day (14:36) and not published then: 10/10 PASS, L4 flood times to mitigate 0.7-1.3 s (R2: 0.5-1.0 s) | a single run; for regression and for the spread between identical runs |
| [`2026-10-13_exp2a-knee_equal-exposure-30s`](2026-10-13_exp2a-knee_equal-exposure-30s/) | R4: as R3, but every attack runs 30 s in every mode (equal exposure) | valid; 3 paired runs per mode |
| [`2026-10-13_exp2a-knee_reproduction`](2026-10-13_exp2a-knee_reproduction/) | R3: EXP-2a re-recorded with the reproducible harness (interleaved, paired by `PROFILE_SEED`) | valid; 3 paired runs per mode |
| [`2026-10-12_f45-ack-stall-validation_prototype`](2026-10-12_f45-ack-stall-validation_prototype/) | F-45: six ACK-flood runs with the daemon patched against the GRU-feed stall (byte-identical to `control_plane.py` of `51cc21c`): 30 of 30 bots banned by the L4 volumetric rule 0.27-2.10 s after the Phase-1 timestamp, none by the GRU, no 10 s stall (addendum §L) | valid; prototype harness, imported; 6 independent runs; the addendum's 0.97 s is measured from the Phase-2 row (see its README) |
| [`2026-10-12_exp2b-knee-nginxtuned_prototype`](2026-10-12_exp2b-knee-nginxtuned_prototype/) | EXP-2b: Nginx limits only with a tuned config (429, no rejection log) at the knee, HTTP flood, 3 runs: legit success 62.1 % (59 / 78 / 49), Nginx at 96 % of cpu0 (addendum §K) | valid; prototype harness, imported; independent unseeded runs; the tuned config and the suite patches are in its `source/` |
| [`2026-10-12_exp2a-knee_prototype`](2026-10-12_exp2a-knee_prototype/) | HTTP flood at the capacity-limited operating point, 4 modes × 3 runs (addendum §J) | valid; recorded with the prototype harness and imported; 3 runs per mode |
| [`2026-10-12_exp1d-calibration-sweep_raw`](2026-10-12_exp1d-calibration-sweep_raw/) | EXP-1d: five single unprotected HTTP-flood runs with different server capacity and attack intensity; only 1 worker x 1 thread on cpu0 with `wrk -c400` from 10 bots lost legit requests (76.7 % during, 14 of 60 failed) (addendum §J, §M) | **raw files, not converted** (five operating points with one run each; the suite copy of the time is not recorded); see its README |
| [`2026-10-12_exp1-default-4modes_prototype`](2026-10-12_exp1-default-4modes_prototype/) | EXP-1, 1b, 1c: the full suite (10 scenarios) at the default operating point, 4 modes × 3 runs: legit success 100 % in every mode (17,363 requests during the attacks, 1 failed); the modes differ in L7 latency, Nginx CPU and pre-stack drop; 300 bans, all of bots, none by the GRU (addendum §C-§I) | valid; prototype harness, imported (approximations in its README); independent unseeded runs |
| [`2026-10-11_superseded-dup-mac`](2026-10-11_superseded-dup-mac/) | 3 modes × 3 runs, all 10 scenarios, on the duplicate-MAC testbed | **superseded**, see its README |

## Prototype campaigns of 2026-10-12

The experiments of `docs/REPORT_ADDENDUM_EXP0_EXP1.md` were recorded with a prototype copy of the
suite, before the reproducible harness existed. Their data are published (index above):
`2026-10-12_exp1-default-4modes_prototype` (EXP-1, 1b, 1c: sections C-I), `..._exp2b-knee-nginxtuned_prototype`
(K), `..._f45-ack-stall-validation_prototype` (L), `..._exp1d-calibration-sweep_raw` (raw files, not
converted) and, since 2026-10-13, `2026-10-12_exp2a-knee_prototype` (J). Each README states the
approximations of the import and the provenance, checked against this repository.

`2026-10-21_prototype-claims-check/` recomputes each number of the addendum from those files, with the
definitions of the earlier session's scripts:

| Addendum | Comparisons | Match | Differ | Cannot be checked |
|---|---|---|---|---|
| A, B: run times, end state, EXP-0 | 7 | 5 | 0 | 2 |
| C: EXP-1 against the duplicate-MAC baseline | 27 | 26 | 0 | 1 |
| D: exact detection data | 25 | 25 | 0 | 0 |
| E: the F-45 stall in EXP-1 | 11 | 10 | 0 | 1 |
| H: EXP-1b | 40 | 36 | 3 | 1 |
| I: EXP-1c | 19 | 19 | 0 | 0 |
| K: EXP-2b | 3 | 3 | 0 | 0 |
| L: F-45 validation | 5 | 3 | 1 | 1 |
| J, M: calibration sweep, totals | 2 | 2 | 0 | 0 |
| **All** | **139** | **129** | **4** | **6** |

The four that differ (details in `2026-10-21_prototype-claims-check/claims_check.md` and the Errata below):
L-3, the F-45 "TTM ≤ 0.97 s" is measured from the Phase-2 row (2.10 s from the attack start); H-25, the
"constant 512 in all modes" holds for the unprotected mode only; H-26, "58 %" is the mean of three run
percentages (pooled 62.7 %); H-2, "every run is 100 %" except one unprotected UDP-flood run (99.4 %).
The six that cannot be checked rest on data that was not recorded or published: the VM reboot (A-6), EXP-0
(B-1), the kernel's duplicate-address messages (C-26), the EXP-5 benchmark (L-5), and two [INFERENCE]
statements (E-11, H-27).

## Layout of a campaign

    <campaign>/
      campaign.json            how the campaign was run (settings, plan, per-run status)
      README.md                what it is and how to cite it
      <mode>/run<k>/           one suite run
        provenance.json        commit, settings, client-profile plan, host, SHA-256 of inputs
        scenario_results.csv   one row per scenario: attack timeline, bans, exact TTM, FPs
        availability.csv       legit success per period and client profile
        availability_raw.csv   one row per legit request (incl. client IP and start time)
        metrics.csv            server metrics per phase
        ban_events.jsonl       the daemon's ban / unban / suppression events
        daemon.log, console.log
      analysis/                summary.md, tables (CSV), figures/ — derived, see below
      SHA256SUMS

A published single run (R2) keeps the run files directly in its directory.

## Checking and reproducing

    cd results/<campaign> && sha256sum -c SHA256SUMS      # data and analysis are intact
    venv/bin/python eval/analyze_campaign.py results/<campaign>
    venv/bin/python eval/plot_campaign.py results/<campaign>

The analysis is deterministic, so the last two commands rewrite `analysis/` with
identical bytes (`git status` stays clean). How campaigns are recorded and published:
`docs/EVALUATION.md`.

## Errata

A published campaign is not edited afterwards, so corrections to what a campaign README says
are collected here. Evidence: `2026-10-20_audit-derived/` and the second audit of 2026-10-19; for the rows
on the addendum and the prototype campaigns, `2026-10-21_prototype-claims-check/`.

| Campaign | What its README says | Correction |
|---|---|---|
| `2026-10-14_l7-p1-smoke` | an earlier run saw the XDP-fed GRU false-ban a legit client, "the stalled-flow false positive … reproduced live" | the ban (10.0.1.6, `broadband`, p = 0.999, 3 hits) came 56 s after the burst's bans and the event carries no flow, so a stalled flow is not shown. Data: `2026-10-20_omitted-runs/p1_smoke_20261014T152428Z/` |
| `2026-10-15_l7-p4-train`, `2026-10-16_l7-p5c3-train` | the GRU beats the tabular baseline ("GRU 7/8 vs HGB 1/8") | the gap is the held-out `credstuff` attacker: one IP that changes its User-Agent on every request and so counts as 6 (IP, UA) groups (P4: 6/6 vs 5/6; P5c.3: 6/6 vs 0/6). In the online comparison, which excludes it, GRU and HGB tie |
| `2026-10-16_l7-p5-eval`, `2026-10-16_l7-p5c4-eval` | 20 attackers, 100 benign IPs, five seeds | the same 4 attacker and 20 benign roles recur in every seed; evaluation seed 1 reuses the capture's plans (P3 and P5 runs A-C; P5c.3 and P5c.4 run A1); attackers have no netem profile. `2026-10-20_audit-derived/l7_roles_p5c4.md` |
| `2026-10-16_l7-p5c4-eval` | the GRU flagged "one browser client in 4 of 5 runs" | two different IPs in four runs; a 60-asset browser was flagged exactly when its netem profile was `perfect` (4 of 4 such runs, 0 of 6 others) |
| `2026-10-16_l7-p5c4-eval` | "the dilemma, measured" | true for per-IP peak and connection-count rules. The evasion side holds by construction (attacks at most 45 rps against a tolerant rule of 108); per-(IP, UA) sustained-rate rules and the tabular model escape it (20/20 at 2 benign flags) |
| `2026-10-16_l7-p5-eval`, `2026-10-16_l7-p5c4-eval` | attackers are "sub-threshold abusers" the heuristics miss | they cause no measurable harm: benign success 1.0 and median server time 2.0 ms with and without them (`2026-10-20_audit-derived/l7_harm_p5c4.md`) |
| `2026-10-12_exp2a-knee_prototype`, `2026-10-13_exp2a-knee_reproduction`, `2026-10-13_exp2a-knee_equal-exposure-30s` | "95 % interval", Fisher p | a bootstrap over 3 blocks and a pooled-request test are descriptive. Run-level contrasts: `docs/EVALUATION.md` "Statistics" and `2026-10-20_audit-derived/run_level_*.md`. Ten paired blocks, which meet the pre-registered rule, are in `2026-10-20_expa-knee-10-blocks/` |
| `2026-10-19_baseline-before-audit-defaults` | "The post-change run is still to be recorded" | recorded on 2026-10-20: `2026-10-20_regression-after-audit-defaults/` (10/10 PASS, the same engines in every scenario) |
| `2026-10-20_omitted-runs` ("Still not published"), `docs/THESIS_CLAIMS.md` Q1, M1, M2 | the prototype campaigns of 2026-10-12 behind the addendum's cross-mode claims are not published | published on 2026-10-21: `2026-10-12_exp1-default-4modes_prototype`, `..._exp2b-knee-nginxtuned_prototype`, `..._f45-ack-stall-validation_prototype`, `..._exp1d-calibration-sweep_raw`; 129 of 139 comparisons with the addendum match (`2026-10-21_prototype-claims-check/`) |
| `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §L (F-45) | "exact last-ban TTM ≤ 0.97 s", "Max TTM across all 6 patched runs = 0.97 s" | measured from the Phase-2 metrics row, written 1.1-1.3 s after the Phase-1 row. From the attack start (the Phase-1 timestamp) the slowest run is 2.10 s; in five of six runs every ban precedes the Phase-2 row. No run approached the 10.32 s stall: `2026-10-12_f45-ack-stall-validation_prototype/README.md` |
| `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §H.4 | "The constant 512 seen in all modes on 2026-10-11 was a product of the L2 defect" | constant only for the unprotected mode (512-513 in 15 of 15 flood samples). XDP and iptables show 512 in Phase 2 and 2A (1/3) and about 255 afterwards, with unique MACs too: `claims_check.md` H-23 to H-25 |
| `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §H.1 | "yesterday's unprotected HTTP 58 %"; "Every run is 100 %" | the 2026-10-11 unprotected HTTP flood is 62.7 % pooled (58 % is the mean of the runs 70, 33, 72); one unprotected UDP-flood run of EXP-1b is 99.4 %: `claims_check.md` H-26, H-2 |
| `2026-10-16_l7-p5c4-eval`, `docs/L7_GRU_DESIGN.md` 7.3.5 | the cost of the tolerant profile in security is to be tabulated | measured on 2026-10-20 for the suite's ten attacks: `2026-10-20_expb-tolerant-profile-suite/` (Slowloris and R.U.D.Y. unbanned in 3 of 3 runs, nothing else lost) |
| `2026-10-21_prototype-claims-check` (README, "Ban events of the converted campaigns") | the prototype census is kept apart from the audit-derived one, which "names the campaigns published until the morning of 2026-10-20"; folding it in "changes its totals from 380 bans ... to 710" | folded in on 2026-10-21 at the user's request: `2026-10-20_audit-derived/events_census.md` now covers 52 distinct logs and 710 bans, with the same single GRU ban (a false one). `events_census_prototype.md` stays as the prototype-only view |
| `2026-10-22_expc-r50-probe` (README, point 2; the index row above it) | at 160 per bot "the server is at its limit", "about 1.5 k requests/s is what one worker on CPU 0 serves"; the index row says the logged rate "stops near 1.6 k/s" | the next ramp, `2026-10-23_expc-r50-refinement/`, answered 1,842 requests/s with 200 at 190 per bot and every one of 215 legit requests succeeded, so the limit is above 1.84 k/s and the 160 run served what it was offered. The logged rate is 1.84 k/s at 190 and 1.90 k/s at 230; the measured axis fails because it is a floor above the limit and not monotone (1,897, 1,710, 1,569 and 1,253 at 230, 270, 320 and 640), not because it stops at 1.6 k/s |
