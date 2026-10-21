# Derived analyses behind the second audit's findings (2026-10-20)

Descriptive re-analyses of campaigns that are already published. They add no new measurement:
each file is computed from `results/` alone by a tool in the repository, so the numbers the
audit report and the thesis quote can be regenerated here.

    sh results/2026-10-20_audit-derived/regenerate.sh          # PYTHON=... if ./venv is elsewhere
    (cd results/2026-10-20_audit-derived && sha256sum -c SHA256SUMS)

Two runs of the script give byte-identical files. The probabilities of the ablation come from a
CPU forward pass (one torch thread); on another CPU the last digits can differ.

| Files | Tool | Question |
|---|---|---|
| `order_ablation.{md,json}` | `ml/order_ablation.py` | does the L7 GRU use the order of the requests in a window? |
| `l7_harm_p5c4.{md,json}` | `ml/l7_run_audit.py harm` | do the labelled P5c.4 attackers harm benign clients? |
| `l7_roles_p5c4.{md,json}` | `ml/l7_run_audit.py roles` | who do the GRU and the baselines flag, per run and per role? |
| `l7_rates_p5c4.{md,json}` | `ml/l7_run_audit.py rates` | what request rates did the plan actually produce? |
| `run_level_<campaign>.{md,csv}` | `eval/run_level_stats.py` | EXP-2a, R3, R4 and EXP-A with the run as the unit of analysis |
| `suite_compare.md` | `eval/suite_compare.py` | the five complete full-suite campaigns side by side: bans, engines, time to mitigate, and the bound per engine |
| `events_census.{md,json}` | `eval/events_census.py` | which engine banned whom in the 52 distinct published ban-event logs of the runs up to 2026-10-21, the converted prototype campaigns of 2026-10-12 included? |

## What they show

1. **Order is not what the model reads** (`order_ablation.md`). Replaying the five P5c.4 runs and the
   soak through the published P5c.3 model, with the requests of every scored window shuffled
   (same per-request features, order destroyed) flags the same IPs in every run: 20 of 20
   attackers and 11 benign flags, as recorded. Reversing the order also catches 20 of 20 and flags
   9 benign: the two 60-asset browsers lose their flag (10.0.1.16 in runA2, 10.0.1.15 in runA3)
   and no IP gains one. At window level, 60 of 29 171 (0.21 %) change their over/under-threshold
   decision when shuffled and 47 (0.16 %) when reversed. Single windows can still move a lot (the
   maximum |dp| per run is in the JSON, up to 0.98), and the mean is 0.003. So order has a
   negligible effect on this model's decisions here: none on the attackers, 2 of the 11 benign
   flags under reversal. It is not literally zero.
2. **The attackers do not hurt anyone** (`l7_harm_p5c4.md`). Benign success is 1.0 and the median
   server time 2.0 ms in all five runs both while a fast attacker is active and while none is
   (p95 10-42 ms in both). `docs/L7_GRU_DESIGN.md` section 7 admits a scenario only if it causes
   measurable harm.
3. **The same roles recur in every seed** (`l7_roles_p5c4.md`). The 20 "attackers" are 4 roles in
   5 seeds, the 100 "benign IPs" 20 roles in 5 seeds. Pooled: the GRU catches 20/20 and flags 9/100
   benign IPs; B2, B3 and B4 (oracle settings of the verdict) catch 20/20 and flag 2/100; B4 at the
   deployed 0.95 x 3 flags 3/100; the deterministic engines catch 0/20. The GRU's benign flags: the
   API client (`api_bulk`) in 5 of 5 runs, and the 60-asset browsers (10.0.1.15, 10.0.1.16) in 4
   runs, exactly the 4 of their 10 browser-runs that had the `perfect` netem profile (the rates
   table lists every run's profile). Attackers have no netem profile in any run.
4. **The hard negative is not the one that was specified** (`l7_rates_p5c4.md`). `api_bulk`,
   specified at 15-20 rps, ran at a 60-s mean of 2.5-4.4 rps in the four runs where it had a mobile
   profile and 11.5 rps with `broadband`. Realised rates of the fast attackers: 11-25 rps sustained
   against a nominal 20-45.
5. **The three-block knee campaigns do not meet the decision rule; EXP-A does** (`run_level_*.md`;
   the rule needs at least 10 paired blocks, `docs/EVALUATION.md`, "Statistics"). R3, daemon -
   unprotected: +21.0 pp [-5.5, +47.4], limits only -6.4 pp [-33.8, +21.0]; R4: +28.0 [-15.3, +71.3]
   and -34.9 [-85.4, +15.7]. Three paired blocks cannot give a sign-flip p below 0.25. EXP-2a had no
   shared seeds, so it is compared unpaired and only describes: +10.2 [+2.7, +17.6] and limits only
   -37.6 [-44.6, -30.7] (Welch p 0.028 and 0.001; the exact permutation p cannot go below 0.10 with
   3 runs per arm). EXP-A (`../2026-10-20_expa-knee-10-blocks/`, ten blocks, recorded after the rule
   was committed): XDP and iptables minus unprotected +33.2 pp [+26.1, +40.2] and limits only minus
   unprotected -22.5 pp [-32.0, -13.1], the same sign in 10 of 10 blocks: all three *supported*.
6. **One GRU ban in 52 distinct logs** (`events_census.md`): the false ban of legit 10.0.1.6 in
   `../2026-10-20_omitted-runs/p1_smoke_20261014T152428Z/`. Bans in total (710): `l7_rate` 300,
   `l4_volumetric` 197, `l4_slowconn` 92, `l4_syn` 75, `l4_lowsyn` 45, `gru` 1. Of the 52 logs, 37
   come from daemons that had the XDP-fed GRU on (36 recorded before the `xdp_gru` field existed,
   when it was the default, and the pre-change baseline), 14 are the L7 track's logs of 2026-10-15/16
   (`xdp_gru: false`) and 1 is empty. The four bans of legitimate clients are the same as before:
   three by the deterministic rules in the P5c.1 run, one by the GRU.
   The census covers the logs published up to 2026-10-21. The converted prototype campaigns of
   2026-10-12 (`../2026-10-12_exp1-default-4modes_prototype/`, `..._exp2b-...`, `..._f45-...`) were
   folded in on 2026-10-21 at the user's request: 12 more non-empty logs and 330 bans, every one of a
   bot (10.0.2.1-5) and none by the GRU (`../2026-10-21_prototype-claims-check/events_census_prototype.md`
   is the prototype-only view). The three campaigns recorded on 2026-10-20 after the default change
   (`2026-10-20_regression-after-audit-defaults`, `_expb-...`, `_expa-...`) ran with `xdp_gru: false`;
   they could not add evidence about the XDP-fed GRU and are left out.

## What changed in the audit report because of this

* "71 ban-event logs" (and 529 bans) were file counts. A published log and its raw copy were
  both counted; by content there were 39 distinct logs at audit time, 40 with the omitted runs and
  52 with the prototype campaigns.
* "Daemon above unprotected in 9 of 9 runs, sign test p = 0.002" is withdrawn as inference: R3 and
  R4 use the same three `PROFILE_SEED`s and EXP-2a was unseeded, so those are not nine
  independent blocks. EXP-A has since supplied ten independent paired blocks (item 5).
* "The GRU does not use order" becomes: order has a negligible effect on its decisions (0.21 % of
  windows flip when shuffled and no IP-level decision changes; reversing the order drops 2 of
  the 11 benign flags).
