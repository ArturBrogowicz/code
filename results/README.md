# Published results

One directory per evaluation campaign. A published campaign is not edited afterwards:
a new measurement is a new campaign.

| Campaign | Content | Status |
|---|---|---|
| [`2026-10-16_l7-p5c2-tolerant-verify`](2026-10-16_l7-p5c2-tolerant-verify/) | P5c.2 gate: the same benign-only run under the frozen tolerant profile: 0 of 20 benign IPs banned (the 60-asset page and both CGNAT gateways now run in full) | valid; gate PASS; see its README |
| [`2026-10-16_l7-p5c-baseline`](2026-10-16_l7-p5c-baseline/) | P5c.1: default heuristics vs realistic benign only (1 run): `l7_rate` banned a 60-asset page load, `l4_slowconn` banned both CGNAT gateways (one after only two users); the shadow GRU's flags on P5 clients came from load-driven server timing (R17) | valid; evidence run, not a comparison campaign; see its README |
| [`2026-10-16_l7-p5-eval`](2026-10-16_l7-p5-eval/) | L7 GRU online evaluation in shadow (P5): 4 runs; GRU flagged all fast sub-threshold attackers at 0 benign FP, but a static 10 rps limit matched it → pre-registered verdict: marginal value NOT shown in this testbed | valid; see its README |
| [`2026-10-15_l7-p4-train`](2026-10-15_l7-p4-train/) | L7 GRU training (P4 gate): candidate model package + metrics; dropping size features → held-out 7/8 at 0 FP, GRU beats tabular baseline, exact-probe gate PASS | gate artifact + P5 candidate (not promoted); see its README |
| [`2026-10-15_l7-p3-capture`](2026-10-15_l7-p3-capture/) | L7 capture dataset (P3 gate): labelled l7json access log + manifest; feature review confirms size/URI now behavioural (R4), low-and-slow barely logs (R1) | gate artifact + P4 training input; see its README |
| [`2026-10-15_l7-p2-smoke`](2026-10-15_l7-p2-smoke/) | L7 shadow-engine P2 verification-gate smoke: scoring, flood gating, record→replay determinism, probes, feature review (untrained model) | gate artifact, **not a comparison campaign**; see its README |
| [`2026-10-14_l7-p1-smoke`](2026-10-14_l7-p1-smoke/) | L7 ingestion P1 verification-gate smoke (`docs/L7_GRU_DESIGN.md`): socket-transport health in shadow mode | gate artifact, **not a comparison campaign**; see its README |
| [`2026-10-13_regression-default-full-suite`](2026-10-13_regression-default-full-suite/) | R2: one run of all 10 scenarios in XDP mode at default settings; the regression check of the harness and the event source of the GRU diagnosis | valid; a single run, for regression and diagnosis, not for comparisons between modes |
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
