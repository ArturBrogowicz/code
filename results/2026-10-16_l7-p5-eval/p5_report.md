| Run | Model | Soak | Benign would-bans | Fast sub-threshold: det-banned / GRU would-ban / IPs | Held-out GRU would-ban | Slow: det / GRU | Best static thr @ 0 benign | Verdict |
|---|---|---|---|---|---|---|---|---|
| A | 2026-10-15_l7-p4-train/model | False | 0 / 12 IPs | 0 / 3 / 3 | 1 / 3 | 0 / 0 | 10 rps → 5 IPs | no marginal value |
| B | scratchpad/l7_model_withsize | False | 1 / 12 IPs | 0 / 3 / 3 | 1 / 3 | 0 / 0 | 10 rps → 5 IPs | no marginal value |
| C | 2026-10-15_l7-p4-train/model | True | 0 / 12 IPs | 0 / 0 / 0 | 0 / 0 | 0 / 0 | — | — |
| D | 2026-10-15_l7-p4-train/model | False | 0 / 12 IPs | 0 / 3 / 3 | 1 / 3 | 0 / 0 | 10 rps → 5 IPs | no marginal value |
