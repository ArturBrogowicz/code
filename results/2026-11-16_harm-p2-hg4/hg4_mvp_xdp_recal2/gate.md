# Harm gate: cheap_static_flood_hg4 (calib)

**Verdict: PASS**

10 valid blocks of 10, 0 re-run(s); calibration frozen `7005a2ed`; validity profile `relative`; metrics Q, p95; judged links perfect, broadband.

| criterion | blocks | mean | 95 % interval | same sign | floor | passed |
|---|---|---|---|---|---|---|
| dQ (pp) | 10 | +98.49 | [+98.17, +98.81] | 100% | 10 pp | yes |
| dL (log2 p95 ratio) | 10 | +3.33 | [+2.92, +3.75] | 100% | 1 | yes |
| dQ' (pp), placebo | 10 | -0.00 | [-0.03, +0.03] | 10% | 10 pp | no |
| dL' (log2 p95 ratio), placebo | 10 | +0.01 | [-0.03, +0.05] | 60% | 1 | no |

The placebo (a second attack-free run) did not pass, as it must not.

## Per link profile

Only the judged profiles vote on the verdict. The others are shown because the harm to them is real, and their own links already exceed the SLOs (docs/HG1C_DESIGN.md 4.1). Q in %, means over the valid blocks.

| profile | judged | share of requests | Q C | Q C' | Q U | dQ |
|---|---|---|---|---|---|---|
| perfect | yes | 31.1% | 100.0 | 100.0 | 1.5 | 98.5 |
| broadband | yes | 34.6% | 100.0 | 100.0 | 1.5 | 98.5 |
| mobile_3g | no | 24.5% | 50.0 | 50.0 | 0.7 | 49.4 |
| mobile_bad | no | 9.8% | 25.2 | 26.7 | 0.2 | 25.0 |

## Blocks

| block | seed | attempt | valid | Q C | Q C' | Q U | dQ | dL | dQ' | p95 C ms | p95 U ms | degraded s | first degraded s | recovery s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | yes | 100.0 | 100.0 | 1.3 | 98.7 | 3.45 | 0.0 | 84 | 916 | 71 | 0.0 | n/a |
| 2 | 2 | 1 | yes | 100.0 | 100.0 | 2.2 | 97.8 | 3.24 | 0.0 | 84 | 798 | 72 | 0.0 | n/a |
| 3 | 3 | 1 | yes | 100.0 | 100.0 | 1.2 | 98.8 | 4.88 | 0.0 | 87 | 2554 | 70 | 0.0 | 25.0 |
| 4 | 4 | 1 | yes | 100.0 | 100.0 | 1.0 | 99.0 | 3.27 | 0.0 | 87 | 840 | 72 | 0.0 | n/a |
| 5 | 5 | 1 | yes | 100.0 | 99.9 | 1.7 | 98.3 | 2.68 | 0.1 | 75 | 480 | 73 | 0.0 | n/a |
| 6 | 6 | 1 | yes | 100.0 | 100.0 | 2.2 | 97.8 | 3.21 | 0.0 | 86 | 800 | 71 | 0.0 | n/a |
| 7 | 7 | 1 | yes | 100.0 | 100.0 | 0.9 | 99.1 | 3.11 | 0.0 | 88 | 759 | 71 | 0.0 | n/a |
| 8 | 8 | 1 | yes | 100.0 | 100.0 | 1.7 | 98.3 | 3.10 | 0.0 | 85 | 725 | 74 | 0.0 | n/a |
| 9 | 9 | 1 | yes | 99.9 | 100.0 | 1.2 | 98.7 | 3.03 | -0.1 | 92 | 745 | 74 | 0.0 | n/a |
| 10 | 10 | 1 | yes | 100.0 | 100.0 | 1.6 | 98.4 | 3.38 | 0.0 | 82 | 851 | 72 | 0.0 | n/a |

Strict profile (design 8.3 as written), computed and not judged unless chosen: 4 run(s) of the final blocks would fail it.

## HRR

The share of the harm the protected arm takes back, from block means: on Q, (Q(M) - Q(U)) / (Q(C) - Q(U)); on p95, the same on log2 p95, (L(U) - L(M)) / (L(U) - L(C)).

| mode | blocks | HRR on Q | 95 % block-bootstrap interval | HRR on p95 | 95 % block-bootstrap interval |
|---|---|---|---|---|---|
| xdp | 10 | 0.96 | [0.95, 0.97] | 0.92 | [0.88, 0.96] |

## Protected arms: the pre-registered P2 outcome

Fixed before any protected run (PRIORITY_PLAN 3, `harm_gate.P2_OUTCOME`): the unprotected server fails when, in at least 90% of the blocks, dQ >= 10 pp or p95 >= 2 x the control's; the protected one works when Q(M) >= 0.99 x Q(C) in as many blocks and no legit identity is blocked; at least 10 blocks. The time to mitigate (TTM: an attack identity's first ban after the attack began) and the refused requests are reported, not judged.

| arm | P2 outcome | unprotected fails | protected works | legit identities blocked | refused in the window | attack identities banned | TTM median s | TTM max s |
|---|---|---|---|---|---|---|---|---|
| M_xdp | NOT MET | 10 of 10 (needs 9) | 0 of 10 (needs 9) | 0 | 0 | 50 of 50 | 0.87 | 1.72 |

## Timer waits (recorded, not judged)

Refused probes / seconds waited before each run, in the order made, and its zero after the block's first. A pass after refusals means less than a pass at the first probe (docs/HG1C_DESIGN.md departure 30), and a block's arms lie further apart.

| block | attempt | t0 span s | runs |
|---|---|---|---|
| 1 | 1 | 496 | Cp 0/2 s at +0 s, M_xdp 0/2 s at +170 s, U 0/2 s at +334 s, C 0/2 s at +496 s |
| 2 | 1 | 492 | C 0/2 s at +0 s, M_xdp 0/2 s at +166 s, Cp 0/2 s at +329 s, U 0/2 s at +492 s |
| 3 | 1 | 495 | Cp 0/2 s at +0 s, C 0/2 s at +163 s, U 0/2 s at +327 s, M_xdp 0/2 s at +495 s |
| 4 | 1 | 493 | Cp 0/2 s at +0 s, U 0/2 s at +162 s, M_xdp 0/2 s at +329 s, C 0/2 s at +493 s |
| 5 | 1 | 495 | M_xdp 0/2 s at +0 s, C 0/2 s at +166 s, U 0/2 s at +330 s, Cp 0/2 s at +495 s |
| 6 | 1 | 496 | Cp 0/2 s at +0 s, M_xdp 0/2 s at +169 s, U 0/2 s at +332 s, C 0/2 s at +496 s |
| 7 | 1 | 495 | M_xdp 0/2 s at +0 s, C 0/2 s at +167 s, Cp 0/2 s at +330 s, U 0/2 s at +495 s |
| 8 | 1 | 497 | Cp 0/2 s at +0 s, M_xdp 0/2 s at +168 s, U 0/2 s at +334 s, C 0/2 s at +497 s |
| 9 | 1 | 496 | C 0/2 s at +0 s, U 0/2 s at +165 s, M_xdp 0/2 s at +333 s, Cp 0/2 s at +496 s |
| 10 | 1 | 488 | M_xdp 0/2 s at +0 s, Cp 0/2 s at +164 s, U 0/2 s at +325 s, C 0/2 s at +488 s |

Limits: p95 is over successes (Q counts the failures and is the primary number); the pooled p95 weighs route classes by their share of the mix; the SLOs, floors and judged links are the calibration's.
