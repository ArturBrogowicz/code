# Published results

One directory per evaluation campaign. A published campaign is not edited afterwards:
a new measurement is a new campaign.

| Campaign | Content | Status |
|---|---|---|
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
