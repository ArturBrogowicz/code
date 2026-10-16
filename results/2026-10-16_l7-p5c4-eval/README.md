# P5c.4 evaluation — tolerant heuristics vs L7 GRU vs baselines (2026-10-16)

The pre-registered P5c evaluation (`docs/L7_GRU_DESIGN.md` §7.3.5, verdict rule §7.2).
Five seeds (runA1–A5, 360 s each) and a 600 s benign soak (runC), all with
`--mix overlap --heuristics tolerant`: the full realistic benign mix (20 IPs) and the
calibrated sub-threshold attacks; the deterministic engines enforce the tolerant profile;
the L7 GRU (the P5c.3 candidate, `results/2026-10-16_l7-p5c3-train/model`) runs in shadow.
Branch `feat/l7-benign-overlap` at `90d260f`. Every run tore down cleanly.

## Verdict — no advantage [FACT, `p5c4_report.md`, computed by `ml/p5b_report.py`]

| | Fast sub-threshold attackers caught (of 20) | Benign IPs flagged (of 100) |
|---|---|---|
| Deterministic engines, tolerant profile | 0 | 0 |
| L7 GRU (shadow) | **20** | **9** |
| B2: per-(IP, UA) mean rate over 60 s > 10 rps | 20 | 2 |
| B3: per-(IP, UA) token bucket r = 10, b = 100 | 20 | 2 |
| B4: HGB tabular baseline, p > 0.99 × 3 | 20 | 2 |
| B0 / B1: per-IP / per-(IP, UA) 1 s peak | 0 | — |

* **V0 informative — yes.** With realistic benign traffic, a per-IP rate limit at 0 benign
  flags caught none of the 4 fast attackers in any run. The overlap the experiment needed
  was achieved.
* **The dilemma, measured.** The tolerant thresholds ban none of the realistic benign
  clients and none of the fast sub-threshold attackers; they still ban credential stuffing
  (error-ratio branch) and the SYN flood in every run.
* **V2 usable — no.** The GRU flagged 9 % of benign IPs (budget 5 %) and 1.8 benign
  would-bans per client-hour in the soak (budget 1.0). Its benign flags: the held-out API
  client in every run (a client type it never trained on, R16) and one browser client in
  4 of 5 runs.
* **V3 — no.** At the GRU's benign cost, three simpler baselines catch all 20 attackers too,
  with fewer benign flags (2): a per-(IP, UA) sustained-rate rule, a per-(IP, UA) token
  bucket, and the tabular model. Under the §7.2 ladder this would read "advantage from
  keying or burst handling, not learning" if V2 had passed; it did not.

**What the evidence supports [INFERENCE].** In this testbed, what separates the fast
sub-threshold attackers from realistic high-rate benign traffic is per-(IP, UA) keying plus
a sustained-rate view, which a simple rule captures. The sequence model adds no detection
over those rules and costs more benign flags.

## Reproduce

    ./venv/bin/python ml/p5b_report.py --run A1=results/2026-10-16_l7-p5c4-eval/runA1 \
        --run A2=.../runA2 --run A3=.../runA3 --run A4=.../runA4 --run A5=.../runA5 \
        --soak C=results/2026-10-16_l7-p5c4-eval/runC

## Files

`p5c4_report.json` / `.md` — the verdict. `runX/`: `summary.json`, `manifest.json`,
`baselines.json` (B0–B4 flagged IPs per setting), `ban_events.jsonl`,
`l7_record.jsonl.gz`, `nginx_tolerant.conf`, `daemon.log`, `console.log`.
