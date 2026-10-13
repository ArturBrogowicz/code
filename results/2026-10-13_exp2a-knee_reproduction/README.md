# R3: EXP-2a reproduced with the reproducible harness (2026-10-13)

The design of EXP-2a (addendum §J), recorded again with the current harness: the HTTP
flood (scenario 4) at the capacity-limited `knee` operating point, four modes × 3 runs,
historical exposure. Attacks stop as soon as all bots are seen banned; the two modes
without a daemon run until the 15 s ban timeout.

What differs from the original EXP-2a recording (`../2026-10-12_exp2a-knee_prototype/`):
it uses `eval/run_campaign.py` at commit `efc5994` (branch `feat/reproducible-eval`). The
modes are interleaved in randomised blocks, and the four runs of a block share their
client-profile plan (`PROFILE_SEED` 1–3), so modes are compared pairwise. Ban events,
provenance and the exact attack timeline are recorded.

    sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 3 \
        --out /var/tmp/ddos_campaigns/2026-10-13_exp2a-knee_reproduction

## Results (`analysis/summary.md`)

| Mode | Legit success during the flood (per run) | Δ vs unprotected [95 % CI, paired] | 'perfect' p50 / p95 | Time to mitigate, median (range) |
|---|---|---|---|---|
| XDP + daemon | **100 %** (100/100/100), n = 65 | **+21.4 pp** [+12.3, +32.9] | 1 / 156 ms | 0.20 s (0.06–0.31), 30/30 bots |
| iptables + daemon | **100 %** (100/100/100), n = 69 | **+21.4 pp** [+12.3, +32.9] | 1 / 357 ms | 0.34 s (0.11–0.60), 30/30 bots |
| nginx limits only | 72.6 % (73/78/67), n = 113 | −6.1 pp [−15.6, +5.8], Fisher p = 0.27 | 4173 / 9848 ms | no daemon |
| unprotected | 78.6 % (67/88/82), n = 206 | — | 894 / 6657 ms | no daemon |

All 30 bots in each daemon mode were first banned by the L7 rate rule, with no GRU bans
and no false positives. After the flood stopped, the unprotected server reached only
94.8 % in the 10-s "after" window, because its single backend was still draining queued
attacker requests; every other mode recovered to 100 %.

## Compared with EXP-2a

* **Reproduced:** both daemon modes hold 100 %, while the modes without a daemon lose
  service. The daemon's advantage over unprotected is larger here (+21 pp vs +10 pp).
  Time to mitigate is ~0.2 s with XDP and ~0.3 s with iptables. In nginx-limits-only
  mode nginx uses ~99 % of its CPU and receives ~10× the packets of unprotected mode.
* **Not reproduced:** nginx limits only was 52.2 % vs 89.9 % unprotected in EXP-2a
  (−38 pp, Fisher p = 1e-13). Here it is 72.6 % vs 78.6 % (−6 pp, CI includes 0). The
  run-to-run spread (unprotected 67–88 %) is far larger than EXP-2a's tightly clustered
  runs suggested. EXP-2a ran each mode's three runs back to back with unseeded client
  mixes, so it could not separate a mode effect from run and time effects, and its
  pooled Fisher test ignored that clustering.

## Caveats

Three runs (blocks) per mode: a block bootstrap over three blocks has very few distinct
resamples, so the intervals are indicative. One scenario, a deliberately severe capacity
limit and a closed-loop attacker (`wrk`). See also the equal-exposure companion
campaign `../2026-10-13_exp2a-knee_equal-exposure-30s/`.
