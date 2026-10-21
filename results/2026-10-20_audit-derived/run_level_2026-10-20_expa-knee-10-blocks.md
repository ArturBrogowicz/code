**Run-level contrasts**

| Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | Blocks for 80 % power |
|---|---|---|---|---|---|---|---|---|---|
| Distributed HTTP Flood | xdp vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | +33.2 | [+26.1, +40.2] | 0.000 | 0.0020 | 1.00 | supported (+) | 3 |
| Distributed HTTP Flood | iptables vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | +33.2 | [+26.1, +40.2] | 0.000 | 0.0020 | 1.00 | supported (+) | 3 |
| Distributed HTTP Flood | nginxlimits vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | -22.5 | [-32.0, -13.1] | 0.000 | 0.0020 | 1.00 | supported (-) | 5 |
