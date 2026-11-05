**Run-level contrasts**

| Load cell | Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | Paired t p | Sign-flip / permutation p | Same-sign blocks | Decision | Blocks for 80 % power | Reference mean (%) | Harm check |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| wrk | Distributed HTTP Flood | xdp vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | +22.5 | [+16.0, +29.0] | 0.000 | 0.0020 | 1.00 | supported (+) | 4 | 77.5 | harmed |
| wrk | Distributed HTTP Flood | nginxlimits vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | -34.3 | [-45.4, -23.2] | 0.000 | 0.0020 | 1.00 | supported (-) | 4 | 77.5 | harmed |
| loadgen125 | Distributed HTTP Flood | xdp@loadgen125 vs unprotected@loadgen125 (during) | paired by PROFILE_SEED (10 blocks) | -0.0 | [-0.1, +0.1] | 0.343 | 1.0000 | 0.10 | not shown | 81 | 100.0 | not harmed |
| loadgen125 | Distributed HTTP Flood | nginxlimits@loadgen125 vs unprotected@loadgen125 (during) | paired by PROFILE_SEED (10 blocks) | +0.0 | [+0.0, +0.0] | 1.000 | 1.0000 | 0.00 | not shown | — | 100.0 | not harmed |
| loadgen250 | Distributed HTTP Flood | xdp@loadgen250 vs unprotected@loadgen250 (during) | paired by PROFILE_SEED (10 blocks) | +57.9 | [+52.6, +63.2] | 0.000 | 0.0020 | 1.00 | supported (+) | 3 | 42.1 | harmed |
| loadgen250 | Distributed HTTP Flood | nginxlimits@loadgen250 vs unprotected@loadgen250 (during) | paired by PROFILE_SEED (10 blocks) | +57.9 | [+52.6, +63.2] | 0.000 | 0.0020 | 1.00 | supported (+) | 3 | 42.1 | harmed |
| loadgen500 | Distributed HTTP Flood | xdp@loadgen500 vs unprotected@loadgen500 (during) | paired by PROFILE_SEED (10 blocks) | +88.6 | [+84.7, +92.5] | 0.000 | 0.0020 | 1.00 | supported (+) | 4 | 11.4 | harmed |
| loadgen500 | Distributed HTTP Flood | nginxlimits@loadgen500 vs unprotected@loadgen500 (during) | paired by PROFILE_SEED (10 blocks) | +88.6 | [+84.7, +92.5] | 0.000 | 0.0020 | 1.00 | supported (+) | 4 | 11.4 | harmed |
