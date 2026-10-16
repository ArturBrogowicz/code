**Outcome: no advantage** (pre-registered rule, docs/L7_GRU_DESIGN.md §7.2)

Runs: runA1, runA2, runA3, runA4, runA5. Comparison set 20 attacker IPs; 100 benign IPs (pooled).

- GRU: 20/20 caught, 9 benign IPs flagged
- V0 informative: True (B0 at 0 benign per run: [0, 0, 0, 0, 0] of [4, 4, 4, 4, 4])
- V2 usable: False (benign share 0.09, soak 1.8 FP/client-hour)

| Baseline | Oracle setting | Caught | Benign flagged | GRU-only / baseline-only | McNemar p | GRU beats |
|---|---|---|---|---|---|---|
| B0 | `None` | 0 | 0 | 20 / 0 | 0.0 | True |
| B1 | `peak1s>50` | 0 | 9 | 20 / 0 | 0.0 | True |
| B2 | `key:mean60s>10` | 20 | 2 | 0 / 0 | 1.0 | False |
| B3 | `key:r=10,b=100` | 20 | 2 | 0 / 0 | 1.0 | False |
| B4 | `p>0.99x3` | 20 | 2 | 0 / 0 | 1.0 | False |

V1 exclusions: none
