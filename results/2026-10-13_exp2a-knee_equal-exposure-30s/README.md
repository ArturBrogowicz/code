# R4: equal exposure, a 30-s attack in every mode (2026-10-13)

As R3 (`../2026-10-13_exp2a-knee_reproduction/`), but with `ATTACK_DURATION=30`: no mode
stops the attack early. Banned bots keep attacking, and the modes without a daemon get
the same 30 s instead of 16 s. The measured exposure was 31.1 s in every mode. This is
the test the review asked for (finding F-02): is the daemon's advantage an artefact of
the harness stopping the attack once the bans are seen?

    sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 3 \
        --attack-duration 30 --out /var/tmp/ddos_campaigns/2026-10-13_exp2a-knee_equal-exposure-30s

## Results (`analysis/summary.md`)

| Mode | Legit success during the flood (per run) | Δ vs unprotected [95 % CI, paired] | 'perfect' p50 / p95 | Time to mitigate, median (range) |
|---|---|---|---|---|
| XDP + daemon | **100 %** (100/100/100), n = 758 | **+26.7 pp** [+8.0, +40.0] | 1 / 2 ms | 0.19 s (0.05–0.32), 30/30 bots |
| iptables + daemon | **100 %** (100/100/100), n = 755 | **+26.7 pp** [+8.0, +40.0] | 1 / 2 ms | 0.36 s (0.11–0.74), 30/30 bots |
| nginx limits only | 37.2 % (33/34/44), n = 172 | **−36.1 pp** [−58.0, −19.9] | 7372 / 9907 ms | no daemon |
| unprotected | 73.3 % (60/92/64), n = 363 | — | 898 / 6331 ms | no daemon |

All bans came from the L7 rate rule, with no GRU bans and no false positives. Recovery in
the 10-s window after the attack: unprotected 85.7 %, every other mode 100 %.

## What it shows

* **The daemon's advantage is not an artefact of stopping the attack early.** With the
  flood running the full 30 s in every mode, both daemon modes serve 100 % of legit
  requests at 1–2 ms. After the bans the banned bots no longer reach the server.
* **XDP's pre-stack drop fades for this attack.** `PreStack_Dropped` at Phase 3 (30 s)
  is 0, against 3,506 pps in R3's Phase 3 about 2 s after the bans. `wrk` is a
  closed-loop TCP client, so once blackholed its connections back off and the bots send
  almost nothing. The sustained pre-stack drop of XDP shows with open-loop floods (UDP,
  ACK, fragmentation; addendum §H), not with this one.
* **Rate limiting alone was clearly worse than no protection in this campaign**
  (37 % vs 73 %), as in EXP-2a, while R3 found no significant difference. The direction
  is consistent across the three campaigns (never better than unprotected), but the
  size is not resolved with three runs per mode.

## Caveats

Three runs (blocks) per mode, so the intervals are indicative; the unprotected runs
spread from 60 % to 92 %. One scenario, a deliberately severe capacity limit and a
closed-loop attacker.
