# L7 capture dataset — P3 gate (2026-10-15)

The P3 verification gate for `docs/L7_GRU_DESIGN.md` (§6). It is the labelled L7
request dataset the P4 trainer will read, and the evidence that the P2 feature
findings are addressed. Recorded at `feat/l7-gru-design` commit `4020c01` with
`sudo ./venv/bin/python ml/capture_l7.py --duration 300 --benign 12 --seed 1`.

**No daemon, no XDP during capture.** Attacks were recorded unmitigated; the l7json log
went to a lossless file. The sub-threshold calibration (§7) is what makes these
scenarios meaningful once the daemon is on (P5); here every trained attack was verified
below the ban thresholds before the run (`manifest.json` → `provenance.calibration`).

## Result — PASS, with one sharp finding (R1)

| Check | Result |
|---|---|
| Capture completed, topology cleaned up | yes; 9012 access-log lines |
| Manifest valid; labels from the plan | yes (`l7-dataset/1`); 12 benign IPs, 9 attacker IPs |
| Every benign kind and attack family present | yes (table below) |
| **R4 — request size no longer a fingerprint** | **addressed**: window `log_rlen_mean` benign 5.02 vs attack 5.35 (overlapping; P2 was benign 4.29 vs attack 3.56, i.e. attacks *smaller* — the curl-vs-wrk tell). URI diversity now separates behaviourally: benign `uri_distinct_ratio` 0.60 vs attack 0.05 |
| **R1 — low-and-slow barely logs** | **confirmed, see below** |

## R4 addressed — benign now carries the signal the model needs [FACT, `windows.csv`]

Per-class medians of the window summaries (2083 benign windows from 12 IPs; 593 attack
windows from the fast families):

| Window feature | attack | benign | Reading |
|---|---|---|---|
| `log_rlen_mean` (request size) | 5.35 | 5.02 | **overlap** — the P2 size fingerprint is gone |
| `uri_distinct_ratio` | 0.05 | 0.60 | benign browses many paths; attacks hammer or cache-bust |
| `uri_repeat_mean` | 0.95 | 0.40 | same, per request |
| `new_conn_mean` | 0.00 | 0.15 | benign has keep-alive **and** one-shot; not the P2 100 %-one-shot tell |
| `log_rate` | 1.60 | 0.51 | behavioural |
| `s4xx_mean` / `s2xx_mean` | 1.0 / 0.0 | 0.0 / 1.0 | credstuff 401s and rate-limited floods vs served benign — behavioural, not a tool tell |
| protocols (benign) | — | HTTP/1.1 **and** HTTP/2 | the multi-path app + HTTP/2 benign client worked |

The classes now separate on **behaviour** (rate, URI pattern, status mix, connection
reuse), not on client-tool fingerprints. This is the P2 R4 finding closed.

## R1 confirmed — a request-sequence model cannot see sub-threshold low-and-slow [FACT]

Windows produced per attack family (a window needs ≥ 5 logged requests):

| Family | mechanism | windows |
|---|---|---|
| credstuff | rate 20 rps | 332 |
| subthreshold_flood | rate 20/45 rps | 130 |
| padded_flood | rate 30 rps | 70 |
| scraper | rate 25 rps | 58 |
| **slowloris** | 6 conns, header/3 s | **1** |
| **slowpost** | 6 conns, byte/3 s | **1** |
| **slowread** | 6 conns, read/3 s | **1** |

A Slowloris/slow-POST/slow-read tuned *below* nginx's 5 s timeout (a header or byte
every 3 s) keeps its connections open and **never completes a request and never times
out**, so nginx logs it only once, at connection close. Six connections give ~six log
lines and essentially no windows. The access-log path is therefore blind to well-behaved
low-and-slow, exactly as R1 (§5.5) warned — now measured.

**Implication (for P4/P5, design doc §5.5, §9 R1).** The L7-log GRU's real niche is the
sub-threshold **fast** families that do log (low-rate floods, scraping, credential
stuffing). For low-and-slow, the detector must be the `$request_completion`/timeout
signal (only if the attack trips the timeout) or the deterministic SlowConn rule
(`ss`-based), or the capture must also feed the `ss` in-flight snapshot (decision 4
fallback). P4 trains and reports per-family, so this shows up as low slow-family recall
rather than a hidden gap.

## Coverage (all lines)

benign 3588 (400 distinct URIs, 7 User-Agents, HTTP/1.1 + HTTP/2); subthreshold_flood
2371; padded_flood 1089; scraper 988 (988 distinct URIs — cache-busting); credstuff 957
(all 401); slowloris/slowpost/slowread 6 each; one `other` line (an unmapped readiness
request, dropped from training).

## Files
* `manifest.json` — the dataset manifest: provenance (git commit, seeds, input SHA-256s,
  the calibration report), the IP→label map, and the ground-truth attack schedule.
* `access.log` — the extended l7json access log (9012 lines; the P4 training input).
  Contains the testbed's synthetic raw URIs and User-Agents.
* `windows.csv` — window summaries used for the feature review above.
* `console.log` — the capture run's output.
