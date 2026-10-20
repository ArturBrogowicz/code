# Full suite, default settings, XDP mode: a replicate of R2 (recorded 2026-10-13)

One run of all 10 scenarios in XDP mode with every setting at its default (`OPERATING_POINT=default`,
gunicorn 8x4, `wrk -c50`, 5 bots, no CPU pinning, `PROFILE_SEED=0`, historical exposure), recorded
2026-10-13 14:36-14:46 UTC at commit `31058e0` (branch `feat/ml-investigation`, clean tree). It
repeats R2 (`../2026-10-13_regression-default-full-suite/`, commit `efc5994`, 08:53-09:03 UTC).

    sudo python3 test_distributed_suite.py        # default RESULTS_DIR, as for R2

It was not published with R2 and no document of the time refers to it; why is not recorded. It is
published now (second audit, finding G-11) because it is the only repeat of R2 and shows how far
identical runs differ. Every pass criterion held again: 10/10 PASS, 5 of 5 bots banned in every
scenario, no false positive, no GRU ban. Legit success during the attack was 100 % in all 10 scenarios (16-119 requests per scenario).

The daemon of this run predates the 2026-10-19 default changes (`docs/EVALUATION.md`, "Defaults
changed on 2026-10-19"): its `start` events carry no `xdp_gru` field, and the XDP-fed GRU was on. It
was suppressed with the first L4 ban of each flood scenario (5 `suppress_on` events) and banned
nothing.

## Time to mitigate next to R2 and to the 2026-10-19 baseline

| Scenario | R2 (`efc5994`, 2026-10-13 08:53) | Replicate (`31058e0`, 2026-10-13 14:36) | Baseline (`5611d8c`, 2026-10-19 15:32) | First-ban engine, replicate |
|---|---|---|---|---|
| SYN flood | 0.50 / 0.50 | **0.96 / 1.97** | 1.23 / 1.23 | L4 SYN |
| Low & slow SYN | 3.98 / 3.98 | **3.95 / 3.95** | 3.81 / 3.81 | L4 low-SYN |
| UDP flood | 0.48 / 0.48 | **0.74 / 0.74** | 0.81 / 0.81 | L4 volumetric |
| HTTP flood | 0.55 / 0.78 | **0.69 / 0.75** | 0.68 / 0.72 | L7 rate |
| ACK flood | 0.97 / 0.97 | **1.06 / 1.06** | 0.88 / 0.88 | L4 volumetric |
| Fragmentation flood | 0.49 / 0.49 | **1.25 / 1.25** | 0.83 / 0.83 | L4 volumetric |
| Slowloris | 3.72 / 3.75 | **3.63 / 3.66** | 3.72 / 3.74 | L4 SlowConn |
| R.U.D.Y. | 3.57 / 3.60 | **3.70 / 3.73** | 3.88 / 3.91 | L4 SlowConn |
| Yo-Yo | 0.52 / 0.59 | **0.57 / 0.72** | 0.53 / 0.59 | L7 rate |
| Multi-vector | 0.84 / 0.84 | **0.60 / 0.60** | 0.43 / 1.46 | L4 SYN / L4 volumetric / L7 rate |

Times to mitigate are the exact ones from the ban events (first `ban` of a bot minus the
attack start the harness records), in seconds, median / maximum over the 5 bots. The three runs
used the same harness settings and the same `PROFILE_SEED = 0`, and the same XDP program
(`dc215f94…`) and model (`4b8bb940…`). The L4 flood medians move between 0.5 and 1.3 s from run to
run: a ban comes at the first 1-s poll after the onset, so the number mostly reflects where in the
poll interval the flood started. The slow attacks need three or four polls and stay within
3.6-4.0 s. One run each is not a basis for a claim about a time to mitigate; a statement should
give the bound per rule (one to four polling intervals), not a single number.

## Check and reproduce

    cd results/2026-10-13_regression-default-full-suite-replicate && sha256sum -c SHA256SUMS
    ./venv/bin/python eval/analyze_campaign.py results/2026-10-13_regression-default-full-suite-replicate     # rewrites analysis/ with identical bytes
    ./venv/bin/python eval/plot_campaign.py results/2026-10-13_regression-default-full-suite-replicate
