**Run-level contrasts**

| Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | Blocks for 80 % power |
|---|---|---|---|---|---|---|---|---|---|
| Distributed HTTP Flood | xdp vs unprotected (during) | unpaired (3 vs 3 runs) | +10.2 | [+2.7, +17.6] | 0.028 | 0.1000 | — | unpaired: descriptive only | — |
| Distributed HTTP Flood | iptables vs unprotected (during) | unpaired (3 vs 3 runs) | +10.2 | [+2.7, +17.6] | 0.028 | 0.1000 | — | unpaired: descriptive only | — |
| Distributed HTTP Flood | nginxlimits vs unprotected (during) | unpaired (3 vs 3 runs) | -37.6 | [-44.6, -30.7] | 0.001 | 0.1000 | — | unpaired: descriptive only | — |
