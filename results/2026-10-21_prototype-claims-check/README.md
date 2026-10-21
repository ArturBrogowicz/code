# The 2026-10-12 addendum against the published prototype campaigns (derived, 2026-10-21)

`docs/REPORT_ADDENDUM_EXP0_EXP1.md` reports the prototype experiments of 2026-10-12. Their data
were not in the repository until 2026-10-21 (`../2026-10-12_exp1-default-4modes_prototype/`,
`../2026-10-12_exp2b-knee-nginxtuned_prototype/`, `../2026-10-12_f45-ack-stall-validation_prototype/`,
`../2026-10-12_exp1d-calibration-sweep_raw/`). This directory compares the numbers of the addendum
(sections A-I, K, L, M) with the values recomputed from those files. It is derived, not a
measurement: each file is computed from `results/` alone.

    PYTHON=... sh results/2026-10-21_prototype-claims-check/regenerate.sh       # ./venv/bin/python by default
    (cd results/2026-10-21_prototype-claims-check && sha256sum -c SHA256SUMS)

Two runs give byte-identical files.

| File | Tool | Content |
|---|---|---|
| `claims_check.md`, `claims_check.csv` | `eval/check_addendum.py` | one row per line of an addendum table or per sentence: what the addendum says, the recomputed value, match / differs / cannot be checked |
| `events_census_prototype.{md,json}` | `eval/events_census.py` | who banned whom in the ban events of the three converted campaigns |

## Result

**[FACT]** 139 comparisons: **129 match**, **4 differ**, **6 cannot be checked**
(`claims_check.md`). The numbers of the addendum are reproduced from the published files to the
digit they are quoted at, in particular the whole availability table (30 cells, percentage and
request count), the exact time to mitigate of ten scenarios in two modes, the latency of the
first 2.5 s, the server-load tables of sections C, H and I, the stall of EXP-1 run 2 (the quiet
period of the daemon, the ban rates, CPU and memory) and the totals of EXP-2b. **[INFERENCE]** The
earlier session computed its numbers from the unconverted CSVs with its own scripts, so agreement
to the digit is evidence that the conversion kept what these numbers need.

The four that differ:

* **L-3, the F-45 validation.** The addendum says the exact last-ban time to mitigate of the six
  patched runs is at most 0.97 s. That is run 5's last ban measured from the Phase-2 metrics row,
  which the harness writes 1.1-1.3 s after the Phase-1 row; in the other five runs every ban precedes
  the Phase-2 row (negative values). From the Phase-1 timestamp, the attack start used for every
  other campaign, the slowest run is 2.10 s. "No run came near the 10.3 s stall" holds either way;
  "all bans under 2 s" (the run script's pass criterion) does not hold from the attack start.
* **H-25, the SYN-RECV cap.** The addendum says the constant 512 seen in all modes on 2026-10-11
  was a product of the L2 defect. In the fragmentation flood of that campaign the unprotected mode
  is at 512-513 in all 15 flood samples, but XDP and iptables are at 512 only in Phase 2 and
  Phase 2A (1/3) (40 % of their samples) and at about 255 afterwards. With unique MACs the two
  protected modes show the same 512 then about 255, so for them the pattern is not an artefact of
  the defect; only the unprotected mode changed (512 to about 2).
* **H-26, yesterday's unprotected HTTP flood.** The addendum says 58 %. Pooled over the three
  runs it is 62.7 %; 58 % is the mean of the three run percentages (70, 33, 72). Yo-Yo (77 %)
  is the same either way.
* **H-2, "every run is 100 %".** One unprotected UDP-flood request failed (run 2, 99.4 %); the
  addendum's own table shows it (99.8 %), the sentence does not.

The six that cannot be checked: the VM reboot at about 08:06 (A-6), EXP-0's MAC listing (B-1),
the kernel's duplicate-address messages (C-26), the mechanism of the F-45 stall (E-11, an
[INFERENCE]), the forwarding-database flapping (H-27, an [INFERENCE]) and the BCC iteration
benchmark (L-5). The first, second, third and sixth need data that was not recorded or not
published; the other two are readings of code, not measurements, and are not rated.

Some comparisons carry a tolerance because the addendum says "about" or quotes a coarser number
(C-27, E-1, H-6, H-8, H-12, H-13, H-23, I-5, I-12 to I-15, K-2): they are the calls with `tol=` in
`eval/check_addendum.py`, and the Notes of `claims_check.md` give the reason where it matters.

## How the check was built

* The definitions come from the earlier session's analysis scripts (`exp1_compare.py`,
  `exp1b_compare.py`, `exp1c_compare.py` and `f45_analyze.py`, in `/root/project_analysis/scripts/` on
  the testbed VM, outside the repository). They were read, and `eval/check_addendum.py` re-implements
  them: a request belongs to the attack by its start time measured from the
  Phase-1 timestamp; "after the bans" is a request started in [Phase 2, Phase 3 - 1 s); the server
  metrics are the means of the Phase 2, 2A (2/3) and 3 rows (2A (2/3) and 3 for the section C table);
  the time to mitigate is the first ban of a bot minus the Phase-1 timestamp. Where the published
  `analysis/` of a campaign uses another convention (it averages all Phase 2A samples), the check
  follows the addendum, not `analysis/`.
* **Provenance of the suite copies, checked by hand** (commands in the campaigns' READMEs and
  commit messages): `git show 6fc27fa:test_distributed_suite.py` plus
  `docs/D1_D2_unique_mac_and_nginx_restart.patch` gives SHA-256 `9f786908…`, the copy of EXP-1,
  1b; plus `EXP1c_nginxlimits_mode.diff` gives `702b514b…` (EXP-1c); plus `EXP1d_calibration_knobs.diff`
  gives `f11ff9fc…` (EXP-2b); EXP-2a's `6e57743a…` is that without one line; the F-45 daemon equals
  `control_plane.py` at `51cc21c`. The recorded hashes of `control_plane.py`, `xdp_ddos_filter.c`, the
  Nginx configs and the model files equal the blobs of `6fc27fa`.

## Ban events of the converted campaigns

**[FACT]** (`events_census_prototype.md`) 330 bans in 13 distinct logs (EXP-1/1b/1c: 300, F-45: 30;
EXP-2b has no daemon): `l4_volumetric` 138, `l7_rate` 66, `l4_slowconn` 60, `l4_syn` 36,
`l4_lowsyn` 30. **0 by the GRU, 0 of a legitimate client**: every ban is of one of the bots
10.0.2.1-5. The XDP-fed GRU was active in those runs (the daemon of `6fc27fa` has no switch for
it). These are not in the ban-event census of `../2026-10-20_audit-derived/`, which names the
campaigns published until the morning of 2026-10-20; adding them changes its totals from 380 bans
(one by the GRU, a false one) to 710 bans with the same one GRU ban [INFERENCE: the sum, not
regenerated there].

## Limits

The check recomputes the addendum's numbers with the addendum's own definitions; it does not ask
whether those definitions are the right ones (the 0.97 s of L-3 is correct arithmetic from a
reference point that is not the attack start). Interpretations and mechanisms are not rated.
