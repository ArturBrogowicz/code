# Harm gate: cheap_static_flood_hg4 (calib)

**Verdict: INVALID**

4 valid blocks of 5, 2 re-run(s); calibration frozen `7005a2ed`; validity profile `relative`; metrics Q, p95; judged links perfect, broadband.

Why INVALID:

* 4 valid blocks, fewer than the 10 the gate needs

| criterion | blocks | mean | 95 % interval | same sign | floor | passed |
|---|---|---|---|---|---|---|
| dQ (pp) | 4 | +99.50 | [+99.04, +99.96] | 100% | 10 pp | yes |
| dL (log2 p95 ratio) | 4 | +4.13 | [+3.10, +5.16] | 100% | 1 | yes |
| dQ' (pp), placebo | 4 | +0.00 | [+0.00, +0.00] | 0% | 10 pp | no |
| dL' (log2 p95 ratio), placebo | 4 | +0.02 | [-0.07, +0.11] | 50% | 1 | no |

The placebo (a second attack-free run) did not pass, as it must not.

## Per link profile

Only the judged profiles vote on the verdict. The others are shown because the harm to them is real, and their own links already exceed the SLOs (docs/HG1C_DESIGN.md 4.1). Q in %, means over the valid blocks.

| profile | judged | share of requests | Q C | Q C' | Q U | dQ |
|---|---|---|---|---|---|---|
| perfect | yes | 29.6% | 100.0 | 100.0 | 0.5 | 99.5 |
| broadband | yes | 35.9% | 100.0 | 100.0 | 0.5 | 99.5 |
| mobile_3g | no | 24.9% | 43.8 | 43.0 | 0.2 | 43.6 |
| mobile_bad | no | 9.6% | 23.1 | 23.1 | 0.2 | 22.9 |

## Blocks

| block | seed | attempt | valid | Q C | Q C' | Q U | dQ | dL | dQ' | p95 C ms | p95 U ms | degraded s | first degraded s | recovery s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 1 | yes | 100.0 | 100.0 | 0.7 | 99.3 | 4.20 | 0.0 | 90 | 1654 | 71 | 0.0 | n/a |
| 2 | 2 | 1 | yes | 100.0 | 100.0 | 0.7 | 99.3 | 3.98 | 0.0 | 85 | 1337 | 75 | 0.0 | n/a |
| 3 | 3 | 2 | yes | 100.0 | 100.0 | 0.1 | 99.9 | 4.95 | 0.0 | 84 | 2586 | 72 | 0.0 | n/a |
| 4 | 4 | 1 | yes | 100.0 | 100.0 | 0.5 | 99.5 | 3.39 | 0.0 | 89 | 926 | 76 | 0.0 | n/a |
| 5 | 5 | 2 | no | n/a | n/a | 0.2 | n/a | n/a | n/a | n/a | 319 | 75 | 0.0 | n/a |

## Blocks and attempts that are not valid

* block 3 attempt 1 (seed 3): U: executor: the attack began -0.52 s from the end of the baseline (limit 0.5 s)
* block 5 attempt 1 (seed 5): run C is missing; run Cp is missing; run U is missing
* block 5 attempt 2 (seed 5): run C is missing; run Cp is missing

Strict profile (design 8.3 as written), computed and not judged unless chosen: 6 run(s) of the final blocks would fail it.

HRR is not computed: its denominator is the gate-passed harm and the gate did not pass.

## Protected arms: the pre-registered P2 outcome

Fixed before any protected run (PRIORITY_PLAN 3, `harm_gate.P2_OUTCOME`): the unprotected server fails when, in at least 90% of the blocks, dQ >= 10 pp or p95 >= 2 x the control's; the protected one works when Q(M) >= 0.99 x Q(C) in as many blocks and no legit identity is blocked; at least 10 blocks. The time to mitigate (TTM: an attack identity's first ban after the attack began) and the refused requests are reported, not judged.

| arm | P2 outcome | unprotected fails | protected works | legit identities blocked | refused in the window | attack identities banned | TTM median s | TTM max s |
|---|---|---|---|---|---|---|---|---|
| M_xdp | INVALID | 4 of 4 (needs 4) | 0 of 4 (needs 4) | 0 | 0 | 20 of 20 | 0.86 | 1.60 |
* M_xdp, no verdict: 4 blocks valid for the gate, fewer than the 10 the outcome needs; 4 blocks with a valid M_xdp run, fewer than the 10 the outcome needs

## Timer waits (recorded, not judged)

Refused probes / seconds waited before each run, in the order made, and its zero after the block's first. A pass after refusals means less than a pass at the first probe (docs/HG1C_DESIGN.md departure 30), and a block's arms lie further apart.

| block | attempt | t0 span s | runs |
|---|---|---|---|
| 1 | 1 | 498 | Cp 0/2 s at +0 s, M_xdp 0/2 s at +167 s, U 0/2 s at +333 s, C 0/2 s at +498 s |
| 2 | 1 | 495 | C 0/2 s at +0 s, M_xdp 0/2 s at +167 s, Cp 0/2 s at +330 s, U 0/2 s at +495 s |
| 3 | 1 | 330 | Cp 0/2 s at +0 s, C 0/2 s at +165 s, U 0/2 s at +330 s |
| 3 | 2 | 496 | Cp 0/2 s at +0 s, M_xdp 0/2 s at +169 s, U 0/2 s at +332 s, C 0/2 s at +496 s |
| 4 | 1 | 496 | Cp 0/2 s at +0 s, U 0/2 s at +162 s, M_xdp 0/2 s at +333 s, C 0/2 s at +496 s |
| 5 | 1 | 0 | M_xdp 0/2 s at +0 s |
| 5 | 2 | 168 | U 0/2 s at +0 s, M_xdp 0/2 s at +168 s |

Limits: p95 is over successes (Q counts the failures and is the primary number); the pooled p95 weighs route classes by their share of the mix; the SLOs, floors and judged links are the calibration's.
