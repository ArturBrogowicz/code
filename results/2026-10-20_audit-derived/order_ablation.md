**Order-shuffle ablation** (`l7-order-ablation/1`, seed 7, model `7f6040a5c7dd`, threshold 0.95 x 3)

| Run | Windows | Mode | Attackers flagged | Benign flagged | Windows over thr. | Flips | mean abs dp | corr(p) |
|---|---|---|---|---|---|---|---|---|
| runA1 | 4528 | recorded | 4/4 | 2/20 | 0.126104 | — | — | — |
| runA1 | 4528 | shuffled | 4/4 | 2/20 | 0.126767 | 0.001988 | 0.003706 | 0.991755 |
| runA1 | 4528 | reversed | 4/4 | 2/20 | 0.126104 | 0.001767 | 0.003092 | 0.993846 |
| runA2 | 4503 | recorded | 4/4 | 2/20 | 0.125472 | — | — | — |
| runA2 | 4503 | shuffled | 4/4 | 2/20 | 0.126138 | 0.00111 | 0.002838 | 0.99437 |
| runA2 | 4503 | reversed | 4/4 | 1/20 | 0.125028 | 0.000888 | 0.002814 | 0.995271 |
| runA3 | 4282 | recorded | 4/4 | 2/20 | 0.116067 | — | — | — |
| runA3 | 4282 | shuffled | 4/4 | 2/20 | 0.116534 | 0.002802 | 0.004111 | 0.98849 |
| runA3 | 4282 | reversed | 4/4 | 1/20 | 0.1156 | 0.002335 | 0.003943 | 0.99052 |
| runA4 | 4384 | recorded | 4/4 | 1/20 | 0.121122 | — | — | — |
| runA4 | 4384 | shuffled | 4/4 | 1/20 | 0.121578 | 0.000456 | 0.003513 | 0.994249 |
| runA4 | 4384 | reversed | 4/4 | 1/20 | 0.120438 | 0.000684 | 0.003401 | 0.993572 |
| runA5 | 4115 | recorded | 4/4 | 2/20 | 0.123937 | — | — | — |
| runA5 | 4115 | shuffled | 4/4 | 2/20 | 0.127096 | 0.004617 | 0.004075 | 0.990092 |
| runA5 | 4115 | reversed | 4/4 | 2/20 | 0.125638 | 0.004131 | 0.003559 | 0.992777 |
| runC | 7359 | recorded | 0/0 | 2/20 | 0.073108 | — | — | — |
| runC | 7359 | shuffled | 0/0 | 2/20 | 0.074331 | 0.001767 | 0.002457 | 0.992039 |
| runC | 7359 | reversed | 0/0 | 2/20 | 0.073244 | 0.000679 | 0.002478 | 0.99207 |

Pooled: recorded 20/20 attackers, 11 benign flags; shuffled 20/20 attackers, 11 benign flags; reversed 20/20 attackers, 9 benign flags

Against the recorded replay, shuffled: 60 of 29171 windows (0.21 %) change their decision; reversed: 47 of 29171 windows (0.16 %) change their decision.

**Verdict: order-free** (order-free = identical flagged IPs in every run and a window flip rate below 0.01).
