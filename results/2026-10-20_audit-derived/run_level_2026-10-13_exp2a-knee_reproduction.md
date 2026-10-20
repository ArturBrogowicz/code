**Run-level contrasts**

| Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | Blocks for 80 % power |
|---|---|---|---|---|---|---|---|---|---|
| Distributed HTTP Flood | xdp vs unprotected (during) | paired by PROFILE_SEED (3 blocks) | +21.0 | [-5.5, +47.4] | 0.077 | 0.2500 | 1.00 | too few blocks (3 < 10) | 5 |
| Distributed HTTP Flood | iptables vs unprotected (during) | paired by PROFILE_SEED (3 blocks) | +21.0 | [-5.5, +47.4] | 0.077 | 0.2500 | 1.00 | too few blocks (3 < 10) | 5 |
| Distributed HTTP Flood | nginxlimits vs unprotected (during) | paired by PROFILE_SEED (3 blocks) | -6.4 | [-33.8, +21.0] | 0.422 | 0.5000 | 0.67 | too few blocks (3 < 10) | 26 |
