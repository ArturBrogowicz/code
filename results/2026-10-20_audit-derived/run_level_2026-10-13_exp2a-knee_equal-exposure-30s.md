**Run-level contrasts**

| Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | Blocks for 80 % power |
|---|---|---|---|---|---|---|---|---|---|
| Distributed HTTP Flood | xdp vs unprotected (during) | paired by PROFILE_SEED (3 blocks) | +28.0 | [-15.3, +71.3] | 0.108 | 0.2500 | 1.00 | too few blocks (3 < 10) | 6 |
| Distributed HTTP Flood | iptables vs unprotected (during) | paired by PROFILE_SEED (3 blocks) | +28.0 | [-15.3, +71.3] | 0.108 | 0.2500 | 1.00 | too few blocks (3 < 10) | 6 |
| Distributed HTTP Flood | nginxlimits vs unprotected (during) | paired by PROFILE_SEED (3 blocks) | -34.9 | [-85.4, +15.7] | 0.097 | 0.2500 | 1.00 | too few blocks (3 < 10) | 5 |
