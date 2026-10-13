# R2: full suite at default settings (2026-10-13)

One run of all 10 scenarios in XDP mode with every setting at its historical default
(`OPERATING_POINT=default`, gunicorn 8×4, `wrk -c50`, 5 bots, no CPU pinning,
historical exposure, `PROFILE_SEED=0`). It was recorded at commit `efc5994` as the
regression check of the reproducible harness (addendum §N). It is published here
because it is the only post-fix full-suite run with ban **and** GRU-suppression
events, which the GRU diagnosis (`docs/ML_INVESTIGATION.md`) relies on.

    sudo python3 test_distributed_suite.py        # default RESULTS_DIR

| Scenario | Legit success during | Banned | Time to mitigate, median | First-ban engine |
|---|---|---|---|---|
| SYN flood | 100 % | 5/5 | 0.50 s | L4 SYN |
| Low & Slow SYN | 100 % | 5/5 | 3.98 s | L4 Low-SYN |
| UDP flood | 100 % | 5/5 | 0.48 s | L4 volumetric |
| HTTP flood | 100 % | 5/5 | 0.55 s | L7 rate |
| ACK flood | 100 % | 5/5 | 0.97 s | L4 volumetric |
| IP fragmentation flood | 100 % | 5/5 | 0.49 s | L4 volumetric |
| Slowloris | 100 % | 5/5 | 3.72 s | L4 SlowConn |
| R.U.D.Y. | 100 % | 5/5 | 3.57 s | L4 SlowConn |
| Yo-Yo | 100 % | 5/5 | 0.52 s | L7 rate |
| Multi-vector | 100 % | 5/5 | 0.84 s | L4 SYN / volumetric / L7 rate |

10/10 PASS, no false positives (ban events), no GRU bans and no suppressed GRU
detections. A single run: use it for regression and diagnosis, not for comparisons
between modes.
