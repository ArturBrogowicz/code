# Published results

One directory per evaluation campaign. A published campaign is not edited afterwards:
a new measurement is a new campaign.

| Campaign | Content | Status |
|---|---|---|
| [`2026-10-20_expa-knee-10-blocks`](2026-10-20_expa-knee-10-blocks/) | EXP-A: the HTTP flood at the knee, 4 modes × 10 paired blocks, 30 s exposure: the daemon (XDP or iptables) served 100 % of the legit requests in all 10 blocks against 66.8 % unprotected (+33.2 pp [+26.1, +40.2]); Nginx limits only 44.4 % (-22.5 pp [-32.0, -13.1]); all three contrasts meet the pre-registered run-level rule | valid; 10 paired runs per mode; one scenario, a closed-loop attacker; see its README |
| [`2026-10-20_expb-tolerant-profile-suite`](2026-10-20_expb-tolerant-profile-suite/) | EXP-B: the full suite (10 scenarios, XDP) under the tolerant heuristic profile, 3 runs: Slowloris and R.U.D.Y. 0/5 banned in every run (the predicted cost of SlowConn 180), the other 8 scenarios 5/5 | valid; 3 runs; the security-cost table the L7 track never produced; see its README |
| [`2026-10-20_regression-after-audit-defaults`](2026-10-20_regression-after-audit-defaults/) | The full suite (10 scenarios, XDP, default settings) on the 2026-10-19 change set, XDP-fed GRU off: 10/10 PASS, the same engines as the baseline | a single run, taken 3 minutes after a VM restart; the post-change run the baseline README announces; see its README |
| [`2026-10-20_audit-derived`](2026-10-20_audit-derived/) | Derived analyses behind the second audit, from published data only: order-shuffle ablation of the L7 GRU, harm / per-role flags / realised rates of P5c.4, run-level statistics of the knee campaigns, ban-event census (40 distinct logs; 1 GRU ban, a false one) | derived, not a measurement; `regenerate.sh` rebuilds it byte for byte |
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
| [`2026-10-12_exp2a-knee_prototype`](2026-10-12_exp2a-knee_prototype/) | HTTP flood at the capacity-limited operating point, 4 modes × 3 runs (addendum §J) | valid; recorded with the prototype harness and imported; 3 runs per mode |
| [`2026-10-11_superseded-dup-mac`](2026-10-11_superseded-dup-mac/) | 3 modes × 3 runs, all 10 scenarios, on the duplicate-MAC testbed | **superseded**, see its README |

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
are collected here. Evidence: `2026-10-20_audit-derived/` and the second audit of 2026-10-19.

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
| `2026-10-16_l7-p5c4-eval`, `docs/L7_GRU_DESIGN.md` 7.3.5 | the cost of the tolerant profile in security is to be tabulated | measured on 2026-10-20 for the suite's ten attacks: `2026-10-20_expb-tolerant-profile-suite/` (Slowloris and R.U.D.Y. unbanned in 3 of 3 runs, nothing else lost) |
