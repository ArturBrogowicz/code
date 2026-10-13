# 2026-10-11 campaign — SUPERSEDED, do not use as thesis evidence

The 3 modes × 3 runs campaign (XDP, iptables, unprotected; all 10 scenarios) run on
2026-10-11, 12:15–14:06 UTC, at commit `6fc27fa`. Until 2026-10-13 its figures and
CSVs lived at the repository root; they are kept here for provenance only.

| File | Content |
|---|---|
| `availability_phases.png/.pdf` | XDP availability before / during / after, per scenario (`plot_availability.py`) |
| `availability_crossmode.png/.pdf` | "during" availability, XDP vs iptables vs unprotected |
| `availability_<performance\|iptables\|unprotected>.csv` | availability per period and client profile |
| `availability_raw_<…>.csv` | one row per legit request |
| `mitigation_performance.csv`, `metrics_iptables.csv`, `metrics_unprotected.csv` | server metrics per phase |
| `test_console_logs.txt` | console of the 9 runs |

The availability CSVs were never committed before (`*.csv` was ignored); the copies
here are byte-identical to the SHA-256-verified snapshot taken in the 2026-10-11 review.

## Why these results are invalid

1. **Testbed L2 defect (review F-01).** Every client and bot interface was named
   `veth_in`, and udev derived the same MAC (`12:af:eb:2d:8a:f2`) from that name, so the
   bridge delivered server→client frames to whichever namespace had last sent from that
   MAC — usually a bot. Legit availability under floods measured this bridge fault, not
   the defence: per-run flood availability tracked the number of colliding interfaces
   (Spearman ρ = −0.84, p = 0.005), not the mode. With unique MACs and otherwise
   identical code (EXP-1), availability under floods went from 32–36 % to 100 % in every
   scenario. Fixed in `51cc21c` (merged in `6d12167`).
2. **Unequal exposure (F-02).** The harness stopped the attack once bans were seen in
   the protected modes but only at the timeout in unprotected mode, so the "during"
   windows differed 1.5–8× between modes.
3. **Too few runs (F-03).** Three runs per mode with an unseeded client-profile mix give
   a minimum detectable difference of 43–55 percentage points for the floods.
4. **Harness defects (F-07, F-09).** Nginx was never restarted between scenarios, and the
   daemon log of every protected run was deleted, so bans cannot be attributed.

Evidence: `docs/REPORT.md` §8 and `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §B–§C.

## What to use instead

* `results/2026-10-12_exp2a-knee_prototype/`: the cross-mode comparison at a
  capacity-limited operating point (addendum §J).
* New campaigns recorded with `eval/run_campaign.py` (see `docs/EVALUATION.md`).

## Regenerating the old figures

    venv/bin/python plot_availability.py results/2026-10-11_superseded-dup-mac/availability_performance.csv /tmp/phases.png

reproduces `availability_phases.png` byte for byte (checked 2026-10-13). The
cross-mode figure reads fixed `/tmp/availability_*.csv` paths; it was verified
byte-identical in the review (`docs/REPORT.md` §8.1).
