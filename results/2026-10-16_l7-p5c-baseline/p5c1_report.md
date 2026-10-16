Run `2026-10-16_l7-p5c-baseline` (seed 1, 300 s): 3 of 20 benign IPs banned by the default deterministic heuristics.

| IP | Kind | Spec | Netem | Gate | Deterministic ban | Requests | Peak 1 s | Sus 10 s | Sus 60 s | nginx 503 (req/conn) | GRU would-bans |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 10.0.1.1 | curl_oneshot | — | mobile_3g | ok | — | 121 | 1 | 0.6 | 0.45 | 0/0 | 0 |
| 10.0.1.2 | curl_oneshot | — | perfect | ok | — | 140 | 1 | 0.7 | 0.517 | 0/0 | 0 |
| 10.0.1.3 | keepalive | — | broadband | ok | — | 201 | 2 | 1.0 | 0.767 | 0/0 | 2 |
| 10.0.1.4 | keepalive | — | mobile_bad | ok | — | 125 | 1 | 0.7 | 0.5 | 0/0 | 0 |
| 10.0.1.5 | http2 | — | broadband | ok | — | 998 | 6 | 4.2 | 3.6 | 0/0 | 1 |
| 10.0.1.6 | api_poll | — | broadband | ok | — | 272 | 2 | 1.2 | 0.967 | 0/0 | 3 |
| 10.0.1.7 | downloader | — | mobile_3g | ok | — | 26 | 1 | 0.2 | 0.117 | 0/0 | 0 |
| 10.0.1.8 | uploader | — | mobile_3g | ok | — | 40 | 1 | 0.3 | 0.167 | 0/0 | 0 |
| 10.0.1.9 | nat_gateway | users=8 | perfect | ok | — | 1213 | 11 | 5.3 | 4.267 | 0/0 | 4 |
| 10.0.1.10 | curl_oneshot | — | mobile_bad | ok | — | 99 | 1 | 0.5 | 0.383 | 0/0 | 0 |
| 10.0.1.11 | curl_oneshot | — | mobile_bad | ok | — | 86 | 1 | 0.4 | 0.333 | 0/0 | 0 |
| 10.0.1.12 | keepalive | — | perfect | ok | — | 206 | 2 | 1.0 | 0.767 | 0/0 | 2 |
| 10.0.1.13 | browser_page | level=30 | broadband | ok | — | 200 | 33 | 7.8 | 1.867 | 0/0 | 2 |
| 10.0.1.14 | browser_page | level=30 | mobile_3g | ok | — | 254 | 26 | 4.2 | 1.95 | 0/0 | 2 |
| 10.0.1.15 | browser_page | level=60 | mobile_bad | trips {'l7_rate': 20} | — | 271 | 20 | 8.2 | 2.45 | 0/0 | 2 |
| 10.0.1.16 | browser_page | level=60 | perfect | trips {'l7_rate': 20} | **l7_rate** @ 7.0 s (value 51.0) | 61 | 61 | 6.1 | 1.017 | 0/0 | 0 |
| 10.0.1.17 | cgnat_browsers | users=12,level=30 | broadband | trips {'slowconn': 20, 'l7_rate': 9, 'limit_req': 3} | **l4_slowconn** @ 9.3 s (value 12, bytes 0) | 62 | 31 | 6.2 | 1.033 | 0/0 | 0 |
| 10.0.1.18 | cgnat_browsers | users=24,level=30 | mobile_bad | trips {'l7_rate': 17, 'limit_req': 20, 'slowconn': 20} | **l4_slowconn** @ 264.9 s (value 54, bytes 0) | 4002 | 72 | 33.7 | 24.033 | 0/0 | 41 |
| 10.0.1.19 | api_bulk | rps=[15.0, 20.0] | mobile_3g | ok | — | 1166 | 7 | 4.8 | 4.217 | 0/0 | 2 |
| 10.0.1.20 | crawler_polite | rps=[2.0, 5.0],level=30 | perfect | ok | — | 1013 | 5 | 3.8 | 3.65 | 0/0 | 1 |

Gate prediction vs live:
- predicted ban, banned: ['10.0.1.16', '10.0.1.17', '10.0.1.18']
- predicted ban, NOT banned: ['10.0.1.15']
- predicted ok, but banned: []
- predicted ok, not banned: 16 IPs

Shadow GRU, server-timing counterfactual (R17):
| Replay | Windows | Over threshold | Would-bans | IPs flagged |
|---|---|---|---|---|
| as_recorded | 3480 | 1177 | 62 | 11: {'10.0.1.12': 2, '10.0.1.13': 2, '10.0.1.14': 2, '10.0.1.15': 2, '10.0.1.18': 41, '10.0.1.19': 2, '10.0.1.20': 1, '10.0.1.3': 2, '10.0.1.5': 1, '10.0.1.6': 3, '10.0.1.9': 4} |
| unloaded_timing | 3480 | 958 | 43 | 6: {'10.0.1.13': 2, '10.0.1.14': 2, '10.0.1.15': 2, '10.0.1.18': 34, '10.0.1.19': 2, '10.0.1.20': 1} |
