Load the server received from the bots, by arrival, in the first 30 s of the attack (`Offered` counts every request line of a bot address, `Served` those with status 200; the median leaves out the first second, in which the generators start):

| Campaign | Run | Flood | Nominal /s | Offered /s | Offered /s, median | Served /s | Other statuses | Run time s |
|---|---|---|---|---|---|---|---|---|
| `20261022T175432Z` | `unprotected/run1` | wrk, closed-loop | - | 1057 | 715 | 860 | 499: 1031, 504: 4873 | - |
| `20261022T181508Z` | `unprotected/run1` | wrk, closed-loop | - | 1321 | 1078 | 1029 | 499: 3095, 502: 1, 504: 5672 | 90 |
| `20261022T181508Z` | `unprotected@loadgen20/run1` | loadgen, 20/s per bot | 200 | 195 | 200 | 195 | - | 92 |
| `20261022T181845Z` | `unprotected@loadgen40/run1` | loadgen, 40/s per bot | 400 | 390 | 400 | 390 | - | 88 |
| `20261022T181845Z` | `unprotected@loadgen80/run1` | loadgen, 80/s per bot | 800 | 782 | 800 | 782 | - | 92 |
| `20261022T181845Z` | `unprotected@loadgen160/run1` | loadgen, 160/s per bot | 1600 | 1587 | 1625 | 1505 | 499: 2480 | 90 |
| `20261022T181845Z` | `unprotected@loadgen320/run1` | loadgen, 320/s per bot | 3200 | 1569 | 1023 | 98 | 499: 9923, 504: 34186 | 94 |
| `20261022T181845Z` | `unprotected@loadgen640/run1` | loadgen, 640/s per bot | 6400 | 1253 | 507 | 8 | 499: 4653, 504: 32712 | 395 |

What the legit clients saw in the same 30 s, from their own records (percentiles only from 10 or more successes):

| Campaign | Run | Legit n | Success % | Timeouts % | Before the start, success % (n) | First 5 s, % | Last 10 s, % | p50 ok ms | p95 ok ms |
|---|---|---|---|---|---|---|---|---|---|
| `20261022T175432Z` | `unprotected/run1` | 95 | 69.5 | 14.7 | 100.0 (37) | 96.7 | 55.0 | 1678 | 6791 |
| `20261022T181508Z` | `unprotected/run1` | 104 | 72.1 | 7.7 | 100.0 (37) | 100.0 | 47.6 | 1563 | 7209 |
| `20261022T181508Z` | `unprotected@loadgen20/run1` | 246 | 100.0 | 0.0 | 100.0 (33) | 100.0 | 100.0 | 3 | 556 |
| `20261022T181845Z` | `unprotected@loadgen40/run1` | 252 | 100.0 | 0.0 | 100.0 (33) | 100.0 | 100.0 | 3 | 547 |
| `20261022T181845Z` | `unprotected@loadgen80/run1` | 251 | 100.0 | 0.0 | 100.0 (37) | 100.0 | 100.0 | 7 | 607 |
| `20261022T181845Z` | `unprotected@loadgen160/run1` | 178 | 100.0 | 0.0 | 100.0 (28) | 100.0 | 100.0 | 731 | 3024 |
| `20261022T181845Z` | `unprotected@loadgen320/run1` | 61 | 19.7 | 67.2 | 100.0 (35) | 19.0 | 47.1 | 7648 | 9765 |
| `20261022T181845Z` | `unprotected@loadgen640/run1` | 57 | 1.8 | 87.7 | 97.3 (37) | 5.0 | 0.0 | - | - |
