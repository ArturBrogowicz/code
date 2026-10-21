**Bots banned** (a ! marks a legitimate client banned or a failed legit HTTP check)

| Scenario | R2 | replicate | baseline | after | tolerant/run1 | tolerant/run2 | tolerant/run3 |
|---|---|---|---|---|---|---|---|
| Distributed SYN Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Low & Slow SYN | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed UDP Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed HTTP Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed ACK Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed IP Fragmentation Flood | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Distributed Slowloris | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 |
| Distributed R.U.D.Y. | 5/5 | 5/5 | 5/5 | 5/5 | 0/5 | 0/5 | 0/5 |
| Distributed Yo-Yo | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |
| Multi-Vector Distributed Attack | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |

Scenarios with every bot banned: R2 10/10, replicate 10/10, baseline 10/10, after 10/10, tolerant/run1 8/10, tolerant/run2 8/10, tolerant/run3 8/10.

**Engines that banned the bots**

| Scenario | R2 | replicate | baseline | after | tolerant/run1 | tolerant/run2 | tolerant/run3 |
|---|---|---|---|---|---|---|---|
| Distributed SYN Flood | L4 SYN | L4 SYN | L4 SYN | L4 SYN | L4 SYN | L4 SYN | L4 SYN |
| Distributed Low & Slow SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN | L4 low-SYN |
| Distributed UDP Flood | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric |
| Distributed HTTP Flood | L7 rate | L7 rate | L7 rate | L7 rate | L7 rate | L7 rate | L7 rate |
| Distributed ACK Flood | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric |
| Distributed IP Fragmentation Flood | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric | L4 volumetric |
| Distributed Slowloris | L4 SlowConn | L4 SlowConn | L4 SlowConn | L4 SlowConn | — | — | — |
| Distributed R.U.D.Y. | L4 SlowConn | L4 SlowConn | L4 SlowConn | L4 SlowConn | — | — | — |
| Distributed Yo-Yo | L7 rate | L7 rate | L7 rate | L7 rate | L7 rate | L7 rate | L7 rate |
| Multi-Vector Distributed Attack | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 | L4 SYN 1, L4 volumetric 3, L7 rate 1 |

**Exact time to mitigate, seconds (median / max over the bots)**

| Scenario | R2 | replicate | baseline | after | tolerant/run1 | tolerant/run2 | tolerant/run3 |
|---|---|---|---|---|---|---|---|
| Distributed SYN Flood | 0.50 / 0.50 | 0.96 / 1.97 | 1.23 / 1.23 | 1.56 / 1.56 | 0.97 / 0.97 | 0.92 / 0.92 | 1.19 / 1.19 |
| Distributed Low & Slow SYN | 3.98 / 3.98 | 3.95 / 3.95 | 3.81 / 3.81 | 3.54 / 3.54 | 3.99 / 3.99 | 3.46 / 3.46 | 3.70 / 3.70 |
| Distributed UDP Flood | 0.48 / 0.48 | 0.74 / 0.74 | 0.81 / 0.81 | 0.78 / 0.78 | 0.73 / 0.73 | 1.18 / 1.18 | 1.01 / 1.01 |
| Distributed HTTP Flood | 0.55 / 0.78 | 0.69 / 0.75 | 0.68 / 0.72 | 1.08 / 1.13 | 0.66 / 0.72 | 0.67 / 0.80 | 0.63 / 0.76 |
| Distributed ACK Flood | 0.97 / 0.97 | 1.06 / 1.06 | 0.88 / 0.88 | 0.89 / 0.89 | 0.58 / 0.59 | 1.12 / 1.12 | 1.00 / 1.00 |
| Distributed IP Fragmentation Flood | 0.49 / 0.49 | 1.25 / 1.25 | 0.83 / 0.83 | 0.97 / 0.97 | 0.98 / 0.98 | 0.51 / 0.51 | 0.54 / 0.54 |
| Distributed Slowloris | 3.72 / 3.75 | 3.63 / 3.66 | 3.72 / 3.74 | 3.55 / 3.57 | — | — | — |
| Distributed R.U.D.Y. | 3.57 / 3.60 | 3.70 / 3.73 | 3.88 / 3.91 | 4.64 / 4.66 | — | — | — |
| Distributed Yo-Yo | 0.52 / 0.59 | 0.57 / 0.72 | 0.53 / 0.59 | 0.57 / 0.80 | 0.28 / 0.56 | 0.70 / 0.89 | 0.76 / 0.81 |
| Multi-Vector Distributed Attack | 0.84 / 0.84 | 0.60 / 0.60 | 0.43 / 1.46 | 0.48 / 1.50 | 0.61 / 0.61 | 0.41 / 3.82 | 0.76 / 0.77 |

**Exact time to mitigate by engine, over every bot of every run above (seconds)**

| Engine | Bots | Min | Median | Max |
|---|---|---|---|---|
| L4 low-SYN | 35 | 3.46 | 3.81 | 3.99 |
| L4 SlowConn | 40 | 3.52 | 3.70 | 4.66 |
| L4 SYN | 42 | 0.50 | 0.97 | 3.82 |
| L4 volumetric | 126 | 0.41 | 0.82 | 1.25 |
| L7 rate | 77 | 0.06 | 0.57 | 1.13 |
