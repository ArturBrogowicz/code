# EXP-A: HTTP flood at the knee, ten paired blocks (2026-10-20)

The knee comparison of R3 and R4 with enough blocks to decide it. Scenario 4 (distributed HTTP flood) at
the knee operating point (one gunicorn worker with one thread, pinned to CPU 0; 10 bots, each running
`wrk -t2 -c400`, on CPUs 1-7), attack duration 30 s in every mode, four modes (XDP + daemon, iptables + daemon, Nginx
limits only, unprotected) in ten blocks of four runs. Block k has `PROFILE_SEED` 100+k for all four modes,
so the legitimate clients' netem profiles match inside a block; the order of the modes inside a block is
shuffled (`--order-seed 0`). 40 runs, 2026-10-20 14:47-15:50 UTC, commit `618b2fc` (tree clean).

    sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 10 \
        --attack-duration 30 --seed-base 100

**Decision rule, fixed before the data.** `eval/run_level_stats.py` (commit `8d26335`, 2026-10-20 08:46
UTC, six hours before the first run) compares each mode with the unprotected one inside the blocks, on
one number per run: the legit success percentage during the attack. A contrast is *supported* iff it has
at least 10 blocks, the 95 % t-interval of the mean block difference excludes 0, and at least 80 % of the
blocks have the sign of the mean; otherwise it is *not shown*. Since that commit only `_fmt`, a helper
that prints the table, has changed (`99c3c84`, needed to print the "before" period); the rule and its
constants are as committed.

## Result

**Run-level contrasts**

| Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | Blocks for 80 % power |
|---|---|---|---|---|---|---|---|---|---|
| Distributed HTTP Flood | xdp vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | +33.2 | [+26.1, +40.2] | 0.000 | 0.0020 | 1.00 | supported (+) | 3 |
| Distributed HTTP Flood | iptables vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | +33.2 | [+26.1, +40.2] | 0.000 | 0.0020 | 1.00 | supported (+) | 3 |
| Distributed HTTP Flood | nginxlimits vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | -22.5 | [-32.0, -13.1] | 0.000 | 0.0020 | 1.00 | supported (-) | 5 |

Success of the legitimate clients during the flood, and what else the campaign recorded
(`analysis/summary.md`):

| Mode | Success per block 1-10 | Mean of the 10 | Requests | Served requests, all clients p50 / p95 | 'perfect' clients p50 / p95 | Nginx CPU | Time to mitigate, median (range) |
|---|---|---|---|---|---|---|---|
| XDP + daemon | 100 in all 10 | **100 %** | 2541 | 42 / 602 ms | 1 / 5 ms | 11 % | 0.21 s (0.08-0.36), 100/100 bots |
| iptables + daemon | 100 in all 10 | **100 %** | 2503 | 42 / 612 ms | 1 / 11 ms | 16 % | 0.27 s (0.09-0.55), 100/100 bots |
| nginx limits only | 32/56/38/34/33/50/38/48/67/48 | 44.4 % | 581 | 6579 / 9952 ms | 7317 / 9979 ms | 96 % | no daemon |
| unprotected | 50/63/72/65/78/67/75/57/81/60 | 66.8 % | 1128 | 1026 / 6542 ms | 883 / 6446 ms | 33 % | no daemon |

The run-level table above is the inference. `analysis/summary.md` pools requests and resamples blocks
for its difference against unprotected (+32.7 pp for the daemon, -22.9 pp for limits only) and prints
pooled Fisher p-values; those are descriptions, not tests of independent requests.

## What it shows

* **The daemon keeps the service up at the knee, and the effect is decided.** XDP and iptables each served
  100 % of the legitimate requests in all ten blocks, against 50-81 % unprotected: +33.2 pp [+26.1, +40.2],
  the same sign in 10 of 10 blocks, exact sign-flip p = 0.002 (the smallest value ten blocks can give).
  R3 and R4 could only say that the direction was robust; their three-block intervals spanned zero.
* **Rate limiting alone is worse than no protection here.** Nginx `limit_req`/`limit_conn` without the
  daemon served 44.4 % on average against 66.8 % unprotected: -22.5 pp [-32.0, -13.1], again 10 of 10
  blocks. Its served requests were also far slower (all-client p50 6.6 s against 1.0 s) and its Nginx CPU
  was 96 % against 33 %. The earlier campaigns disagreed on the size (-37.6, -6.4 and -34.9 pp, three runs
  each); ten blocks put it at about -22 pp. The attacker is closed-loop, see the caveats.
* **XDP and iptables are equal on availability, and XDP bans sooner.** Both served 100 % in every block;
  XDP minus limits is +55.7 pp [+47.5, +63.9]. Descriptive, not part of the rule: the per-block median
  time to mitigate was 0.215 s for XDP and 0.290 s for iptables on average, a difference of +0.075 s
  [+0.030, +0.120] with XDP faster in 8 of 10 blocks (sign-flip p = 0.008). The latency of served requests
  is the same (all-client p95 602 and 612 ms).
* **Detection.** All 200 bots of the two daemon modes were banned, 97 (XDP) and 77 (iptables) of 100 by the
  L7 rate rule and the others by the L4 SYN rule as the first ban of the bot. No GRU ban, no false
  positive.
* **Before and after the attack.** Before it all four modes served 99.4-100 % (limits only: one failed
  request in each of two blocks); the contrasts are zero or not shown. In the 10-s window after the attack
  the other three modes served 100 % of 65-86 requests per run, but the unprotected server completed 43,
  1, 0, 0, 20, 20, 0, 11, 5 and 7 requests in blocks 1-10: it had not recovered when the window closed
  (pooled success 79.4 %). The after-period contrasts have only 7 blocks with data and carry no decision.

## Caveats

* One scenario, one operating point (a deliberately severe capacity limit), ten bots with a closed-loop
  client (`wrk`). The size and even the sign of the limits-only effect may differ for an open-loop
  attacker, whose offered rate does not fall when the server answers slowly [INFERENCE; EXP-C, not run].
* "During" counts each legit request by the period in which it started (curl `--max-time 10`; a timeout
  is a failure). The unprotected after-window is incomplete, as described above.
* The same 8-CPU VM as the other campaigns; kernel, nginx and Python versions are in each run's
  `provenance.json`. The VM had been restarted at 13:57 UTC that day, about 50 minutes before the first
  run.

## Check and reproduce

    cd results/2026-10-20_expa-knee-10-blocks && sha256sum -c SHA256SUMS
    ./venv/bin/python eval/run_level_stats.py results/2026-10-20_expa-knee-10-blocks
    ./venv/bin/python eval/run_level_stats.py results/2026-10-20_expa-knee-10-blocks --reference nginxlimits
    ./venv/bin/python eval/analyze_campaign.py results/2026-10-20_expa-knee-10-blocks   # rewrites analysis/ with identical bytes
