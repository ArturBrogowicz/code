Run `2026-10-16_l7-p5c2-tolerant-verify` (seed 1, 300 s): 0 of 20 benign IPs banned by the tolerant deterministic heuristics.

| IP | Kind | Spec | Netem | Gate | Deterministic ban | Requests | Peak 1 s | Sus 10 s | Sus 60 s | nginx 503 (req/conn) | GRU would-bans |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 10.0.1.1 | curl_oneshot | — | mobile_3g | ok | — | 122 | 1 | 0.6 | 0.45 | 0/0 | 0 |
| 10.0.1.2 | curl_oneshot | — | perfect | ok | — | 144 | 1 | 0.7 | 0.517 | 0/0 | 0 |
| 10.0.1.3 | keepalive | — | broadband | ok | — | 206 | 2 | 1.0 | 0.8 | 0/0 | 0 |
| 10.0.1.4 | keepalive | — | mobile_bad | ok | — | 127 | 1 | 0.6 | 0.483 | 0/0 | 0 |
| 10.0.1.5 | http2 | — | broadband | ok | — | 1038 | 6 | 4.2 | 3.6 | 0/0 | 0 |
| 10.0.1.6 | api_poll | — | broadband | ok | — | 278 | 2 | 1.2 | 0.967 | 0/0 | 0 |
| 10.0.1.7 | downloader | — | mobile_3g | ok | — | 26 | 1 | 0.2 | 0.117 | 0/0 | 0 |
| 10.0.1.8 | uploader | — | mobile_3g | ok | — | 41 | 1 | 0.3 | 0.167 | 0/0 | 0 |
| 10.0.1.9 | nat_gateway | users=8 | perfect | ok | — | 1237 | 10 | 5.4 | 4.35 | 0/0 | 0 |
| 10.0.1.10 | curl_oneshot | — | mobile_bad | ok | — | 103 | 1 | 0.5 | 0.383 | 0/0 | 0 |
| 10.0.1.11 | curl_oneshot | — | mobile_bad | ok | — | 86 | 1 | 0.4 | 0.317 | 0/0 | 0 |
| 10.0.1.12 | keepalive | — | perfect | ok | — | 212 | 2 | 1.0 | 0.8 | 0/0 | 0 |
| 10.0.1.13 | browser_page | level=30 | broadband | ok | — | 242 | 33 | 8.3 | 1.867 | 0/0 | 2 |
| 10.0.1.14 | browser_page | level=30 | mobile_3g | ok | — | 267 | 29 | 4.4 | 2.017 | 0/0 | 2 |
| 10.0.1.15 | browser_page | level=60 | mobile_bad | ok | — | 292 | 19 | 8.2 | 2.45 | 0/0 | 2 |
| 10.0.1.16 | browser_page | level=60 | perfect | ok | — | 371 | 61 | 8.4 | 3.467 | 0/0 | 2 |
| 10.0.1.17 | cgnat_browsers | users=12,level=30 | broadband | ok | — | 2731 | 82 | 29.4 | 15.583 | 0/0 | 19 |
| 10.0.1.18 | cgnat_browsers | users=24,level=30 | mobile_bad | ok | — | 4364 | 69 | 40.5 | 24.917 | 0/0 | 37 |
| 10.0.1.19 | api_bulk | rps=[15.0, 20.0] | mobile_3g | ok | — | 1256 | 7 | 4.9 | 4.433 | 0/0 | 2 |
| 10.0.1.20 | crawler_polite | rps=[2.0, 5.0],level=30 | perfect | ok | — | 1072 | 5 | 3.9 | 3.7 | 0/0 | 1 |

Gate prediction vs live:
- predicted ban, banned: []
- predicted ban, NOT banned: []
- predicted ok, but banned: []
- predicted ok, not banned: 20 IPs
