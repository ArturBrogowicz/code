# Design & implementation plan: moving the GRU to Nginx request logs (L7)

**Status (2026-10-15):** approved. **P1 (ingestion, shadow mode) is complete.** Its gate, a
3-minute smoke capture on the VM, **PASSED** (`results/2026-10-14_l7-p1-smoke/`):
* In the GRU's sub-threshold regime the socket transport is clean: 0 real drops, 0
  truncation, 0 parse errors, and the windows fill.
* Under a flood burst it drops datagrams instead of blocking nginx, and the file sink
  keeps every line.

**P2 (the shadow scoring engine) is complete (§5.7).** Its gate, a VM smoke run with an
*untrained* model, **PASSED** (`results/2026-10-15_l7-p2-smoke/`):
* **Determinism:** replaying the recording reproduced the live run exactly: 13/13
  would-bans and every counter.
* **Flood gating:** it engaged live, with 12 suppressed polls and then 57 age-gated
  windows.
* **Exact invariance probes:** |Δp| = 0 on real windows.
* **Bans:** only the deterministic engines banned.

No detection claims are made before P4 trains a model. The run produced two findings
that P3 and P4 must act on:
* **Tool fingerprints in the traffic:** the current testbed traffic still carries
  request-size and connection-reuse fingerprints (§9 R4).
* **Probe metric:** decision-flip rates must be read together with |Δp| (§5.7).

Later phases stay gated (§8, §9).

**Confirmed decisions (§10).** (1) Scope: GRU owns L7 sub-threshold abuse only. (2)
Transport: Unix-domain datagram syslog primary + durable file sink. (3) Keying: **IP +
`ua_h` from the start**, bans map to the source IP for XDP. (4) Slow signal:
`$request_completion` + timeout lines first, `ss` in-flight snapshot kept as a fallback.
(5) Keep the deterministic L7 rate and R.U.D.Y. rules alongside the GRU. (6) Keep the GRU
as primary, **and** train a tabular baseline (LightGBM / logistic regression on window
summaries) at P4 to test whether sequence modelling earns its place.

**P1 implementation map.** `l7_ingest.py` (parser, `(IP, ua_h)` window store,
`SyslogDatagramReader`); shadow thread in `control_plane.py` (`l7_shadow_monitor`, off
unless `L7_SHADOW=1`, never bans); `l7json` format + socket sink in both nginx confs
(both pass `nginx -t`); `tests/test_l7_ingest.py` (16) and two contract tests that pin
shadow mode to never-ban and guarded-start.

**P2 implementation map (details in §5.7).**
* `l7_features.py`: features, window matrices, scaling and summaries (numpy only).
* `l7_scorer.py`: model packages and batched scoring.
* `l7_engine.py`: the shadow engine, gating, recording format and `build_engine`.
* `control_plane.py`: wiring (`L7_MODEL`, `L7_RECORD`, and the `XDP_GRU` switch,
  default on).
* `ml/replay_l7.py`: deterministic offline replay and the features CSV.
* `ml/l7_probes.py`: the invariance-probe harness.
* `ml/smoke_l7.py --p2`: the gate runner.
* Tests: 44 new, 114 in total. 41 are unit tests. 3 are contract tests checking that
  the L7 modules cannot reach the ban path, that `XDP_GRU` guards the feed and the
  drain, and that every `l7_*` attribute `control_plane.py` uses exists.

**Origin:** REPORT.md §9 ("should the production GRU be fed from XDP telemetry or from
Nginx logs?") recommends the move at ≈ 70 % confidence. `docs/ML_INVESTIGATION.md` then
showed the XDP-fed GRU never banned after the MAC fix and learned tool fingerprints; its
§6 lists the lessons this plan must honour.

**Tags:** [FACT] verified by file:line, command output or a reproducible measurement;
[INFERENCE] reasoned; [DECISION] a design choice with its rationale; [RISK] a hazard with
mitigation and a gate. Overhead numbers come from `bench/l7_ingest_bench.py` (offline, CPU
only), reproducible on this VM.

---

## 1. Objective and scope

Give the learned model one job it can actually own, and measure whether it adds value
there.

**In scope — the GRU's target role.** Layer-7 application abuse that stays *below* the
deterministic thresholds and so is invisible to the current heuristics:
* low-and-slow connection abuse (Slowloris-style headers, slow-body / R.U.D.Y. POSTs);
* sub-threshold request floods (< 50 rps per IP, under the L7 rate rule and nginx's
  `limit_req`);
* scraping and cache-busting (high URI diversity, normal rate);
* credential-stuffing-style POST patterns (status-code mix against auth endpoints).

**Out of scope — unchanged.** Volumetric and protocol floods (SYN/ACK/UDP/fragment) and
high-rate L7 floods stay with the deterministic L3/L4 kernel heuristics and the L7 rate /
R.U.D.Y. rules. These are faster and sufficient (`ML_INVESTIGATION.md` §2.3), and most of
their traffic never reaches Nginx.

**Enforcement is unchanged and stays decoupled.** Detection moves to L7 (Nginx request
logs, read where TLS terminates). Enforcement stays in XDP: a ban writes the source IP to
`blacklist_map`, and XDP drops it at ingress before the IP stack (`xdp_ddos_filter.c:64`,
`XDP_DROP` at `:67`) [FACT]. This is already how the L7 rate rule and the R.U.D.Y.
detector enforce today (`control_plane.py:ban_ip → block_ip_in_xdp`) [FACT], so the move
changes the GRU's *input*, not the enforcement path.

**Boundary condition [FACT, REPORT §9.4].** The plan assumes TLS terminates on the Nginx
host (true here: `listen 443 ssl; http2 on`, `nginx.conf:39-40`). Behind an L4 load
balancer or TLS passthrough, Nginx would not see plaintext L7 and the recommendation would
not hold; the thesis should state this.

---

## 2. Target architecture

```
          packets                     ┌──────────────────────────────┐
  client ──────────▶ veth_server ────▶│ XDP (xdp_ddos_filter.c)      │
                         │            │  • blacklist_map → XDP_DROP  │◀── enforcement
                         │            │  • telemetry_map, flow_map   │    (unchanged)
                         │            └───────────────┬──────────────┘
                         │                            │ per-IP L3/L4 counters
                         ▼                            ▼
                   ┌──────────┐              ┌─────────────────────────┐
                   │  Nginx   │  JSON log    │ control_plane.py daemon │
                   │ TLS term.│─────────────▶│  L3/L4 heuristics  ─────┼─▶ ban_ip()
                   │ http2 on │  (transport  │  (volumetric/SYN/slow)  │     │
                   └────┬─────┘   §4)        │                         │     ▼
                        │                    │  L7 request ingest ─────┼─▶ blacklist_map
                        ▼                    │   → per-IP req windows  │   (XDP)
                   gunicorn :8080            │   → GRU (L7 abuse) ─────┼─▶ ban_ip()
                                             └─────────────────────────┘
```

* **Two detection inputs, one enforcement.** XDP counters drive the deterministic L3/L4
  rules; Nginx request logs drive the L7 request-window features and the GRU. Both call
  the same `ban_ip()`, which enforces in XDP.
* **The GRU no longer reads `flow_map`** (target state). The XDP→GRU feed and its F-45
  cap defect (`ML_INVESTIGATION.md` §2.9) are retired once the L7 GRU is promoted (P6).
  * P2 adds the switch: `XDP_GRU=0` skips that feed and its drain. It defaults to
    **on**, so production behaviour is unchanged, and contract tests pin the guards.
    Evaluation arms (P2 gate, P5) run with it off: the XDP-fed GRU false-banned a
    legit client in the P1 smoke.
  * Flipping the default before P6 is your call.
  * `flow_map` may stay for the L4 rules or be simplified later; that is a separate
    change.
* **TLS/HTTP2 become visible.** Today clients use `http://` only (REPORT §4.3); the L7
  model works on decrypted requests regardless of TLS, including HTTP/2 streams, because
  Nginx logs one line per request after decryption [FACT].

---

## 3. Extended Nginx log format

Build on D10 (REPORT §11.1). One JSON object per request, compact field names to bound
datagram size (§4), fingerprint-prone fields hashed (§5.4).

```nginx
log_format l7json escape=json
  '{'
    '"msec":$msec,'                              # float wall-clock, ms resolution
    '"ip":"$remote_addr",'                       # ban key; XDP enforces on this
    '"port":$remote_port,'                       # with ip+msec, a per-request id
    '"conn":$connection,'                        # TCP/TLS connection id
    '"creq":$connection_requests,'               # request # on this connection (keep-alive/H2)
    '"proto":"$server_protocol",'                # HTTP/1.1, HTTP/2.0
    '"tls":"$ssl_protocol",'                      # "" on :80
    '"reused":"$ssl_session_reused",'            # r = resumed TLS
    '"method":"$request_method",'
    '"uri":"$request_uri",'                        # P1: raw; the daemon hashes it on ingest (§5.4)
    '"status":$status,'
    '"compl":"$request_completion",'             # "OK" or "" (incomplete → slow attack, no wait)
    '"rt":$request_time,'                         # total request time (s)
    '"uct":"$upstream_connect_time",'
    '"urt":"$upstream_response_time",'            # backend processing (slow-path abuse)
    '"rlen":$request_length,'                      # request bytes (header+body)
    '"bsent":$bytes_sent,'                         # response bytes
    '"lreq":"$limit_req_status",'                  # PASSED / DELAYED / REJECTED (sub-threshold signal)
    '"lconn":"$limit_conn_status",'
    '"ua":"$http_user_agent"'                      # P1: raw; daemon hashes to ua_h (keying, §5.3)
  '}';
```

* **`$request_completion` is the key addition for slow attacks** [INFERENCE]. It is `""`
  for a request Nginx closed before completion (header/body timeout), so a Slowloris or
  slow-body connection appears in the log *at the timeout* with an explicit incompleteness
  flag, instead of only as a 408/413/400 whose meaning must be inferred.
* **`$limit_req_status` exposes the sub-threshold boundary** [FACT]. A client that Nginx's
  `limit_req` is already shaping (`DELAYED`/`REJECTED`) is near the rate limit; the model
  sees this without re-deriving the rate.
* **`$upstream_response_time`** surfaces requests that are cheap to send but expensive to
  serve (search endpoints, regex, large renders) — a class the packet counters cannot see.
* **URI and User-Agent hashing [DECISION, P1 reality].** The anti-fingerprint rule (§5.4)
  is that the *model* never sees raw URI/UA. P1 logs them raw over the socket and the
  daemon hashes them immediately on ingest (`l7_ingest.stable_hash32`, blake2b/32-bit),
  dropping the raw strings — because this nginx build has **no njs** (`nginx -V`) to hash
  in the log. Moving the hash into nginx (njs, needs an apt install with approval) is a P2
  option; the P1 smoke test measures whether raw URI/UA on the wire causes datagram
  truncation (§9 R2).

The same format goes into **both** `nginx.conf` and `nginx_unprotected.conf`, so captures
and evaluation runs are schema-identical (REPORT §9.5 prerequisite) [FACT].

**Verified [FACT].** The 16 standard variables above, plus `limit_req`/`limit_conn` and
the §4.3 socket sink, pass `nginx -t` on this build (nginx 1.28.3): "configuration file …
test is successful". `$uri_hash` and `$ua_hash` are **not** built-in and were not in that
test; they are the one part that needs a `map` or `njs` to produce (decided at P2, §5.4).
`nginx -t` only validates config — it starts no server and sends no traffic.

---

## 4. Ingestion transport and overhead

### 4.1 What Nginx can emit [FACT]
`access_log` supports three sinks: a file, `syslog:server=…` (UDP, TCP, or a Unix-domain
socket), and an in-memory buffer. Open-source Nginx has no piped-log directive (unlike
Apache's `|command`), so "pipe to the daemon" is not an option; the realistic choices are
**file + tail** (current) or **syslog to a Unix-domain datagram socket**. (A named pipe
given as the `access_log` *file* path is possible but fragile — the writer blocks or the
log is lost when no reader is attached — so it is not considered.)

### 4.2 Options

| | File + tail (current) | Unix-domain datagram syslog | UDP syslog to localhost |
|---|---|---|---|
| Nginx blocks if the daemon is slow? | No (writes to disk) | **No** — `SOCK_DGRAM` drops when the socket buffer is full, never blocks the worker | No (same) |
| Disk I/O under flood | **Yes** — ≈ 11 MB/s if the extended format (341 B/line [FACT, bench]) ran at the peak observed 31 k lines/s (REPORT §7 [FACT]) [INFERENCE] | None | None |
| Loss mode | None, but logrotate truncates mid-run (REPORT §7) | Datagrams dropped past `SO_RCVBUF`; **measurable** | Same, plus loopback |
| Message size limit | None | Nginx may truncate long syslog messages [RISK §9] | Same |
| Complexity | Lowest (already built) | One `AF_UNIX`/`SOCK_DGRAM` reader thread | Socket + syslog framing |
| Evidence retention | Full log on disk | Needs a separate durable sink if kept | Same |

### 4.3 [DECISION] Unix-domain datagram syslog, with file as the durable sink
* `access_log syslog:server=unix:/run/ddos_l7.sock,nohostname,tag=l7 l7json;` plus a second
  `access_log` to a file for evidence.
* The daemon binds the socket, raises `SO_RCVBUF`, and reads datagrams in a thread that
  replaces `tail_nginx_logs`.
* **Why:** under an L7 flood the worker must never block on a slow consumer; a datagram
  socket drops instead (bounded by `SO_RCVBUF` and `max_dgram_qlen=512` on this VM), so
  overload degrades gracefully rather than stalling Nginx. Disk still holds the full log
  for evidence and offline replay.
* **Measuring drops [DECISION].** `SOCK_DGRAM` does not report drops to the receiver, so
  the daemon counts what it *received* and the P1 smoke test compares that against the
  file sink's line count (the file gets every line): drops = file lines − received. This
  is the concrete R2 gate, not an in-kernel counter.
* **P1 smoke result [FACT, `results/2026-10-14_l7-p1-smoke/`].** In the GRU's sub-threshold
  regime (~2.4 req/s) the socket received every line (0 real drops, 0 truncation, 0 parse
  errors). Under a 4-bot `wrk` flood burst it dropped ~40 % (peak 1765 in one 2 s interval):
  a sub-second spike of thousands of datagrams overruns `net.unix.max_dgram_qlen = 512`
  before the single-thread reader drains it. Acceptable here — the flood is the rate rule's
  job (file-based, unaffected; it banned the bots) and the file sink kept every line — but
  R2 (§9) carries the mitigations. **Operational note:** nginx starts before the daemon
  binds the socket, so the first few lines miss the socket until the daemon is up; the file
  sink has them, and the smoke measures steady state after the shadow thread reports ready.
* **Fallback:** if P1's smoke test shows unacceptable truncation or drops, fall back to
  file + tail with a per-run log dir (no logrotate) — the current code path, already
  proven.

### 4.4 Overhead [FACT, `bench/l7_ingest_bench.py`, this VM, CPU, 1 thread]

Ingestion (synthetic 341 B/line JSON, Python 3.14):

| Step | per line | lines/s/core |
|---|---|---|
| `json.loads` + one field | 3.3 µs | ≈ 300 k |
| + per-IP rate/error window (today's L7 rule) | 3.9 µs | ≈ 254 k |
| + 8 request-sequence features (blake2b URI hash) | 5.0 µs | ≈ 199 k |

Inference (deployed GRU architecture, the L7 model differs only in `input_size`, which
barely moves GRU cost):

| Batch | per window | windows/s |
|---|---|---|
| 1 (today, unbatched) | 538 µs | ≈ 1.9 k |
| 64 | 32 µs | ≈ 32 k |
| 256 | 29 µs | ≈ 34 k |

**Reading [INFERENCE].**
* One core parses and featurises ≈ 200 k request-lines/s. The heaviest observed L7 log
  rate was ≈ 31 k lines/s under flood (REPORT §7), so a single ingest thread has ~6× head
  room — and under the target regime (sub-threshold L7) the rate is far lower.
* Unbatched inference (538 µs/window) is the dominant cost and today's bottleneck. [DECISION]
  Score once per poll in one batch: at batch 64–256 the cost is ~30 µs/window, a 16–18×
  speedup, and the GIL is held far less. This is the L7 analogue of the batched-inference
  recommendation (REPORT F-29).
* Memory is bounded by per-IP window state: a `deque(maxlen=N)` of small float tuples per
  active client, evicted on idle (the existing `evict_idle_clients`). At N = 20 and
  thousands of active IPs this is a few MB [INFERENCE].

---

## 5. Feature engineering: from packet counters to request sequences

### 5.1 The unit
Today a GRU step is a *flow* snapshot (cumulative forward packet counters). The L7 unit is
a **request**: one log line = one completed or timed-out HTTP request. A sequence is the
client's last N requests, in arrival order, keyed per IP (§5.3).

### 5.2 Candidate features (per request, within the window)
Grouped by what they catch. Final selection and the feature-set variants are decided at
P2/P4 with the probe battery (§6), not fixed here.

| Group | Features | Catches |
|---|---|---|
| Inter-request timing | IAT mean / max / min / stddev; requests per window | sub-threshold floods, bursty vs human cadence |
| Completion & slowness | `$request_completion` empty-rate; `request_time` mean/max; `upstream_response_time` mean/max | Slowloris, slow-body, slow-path abuse |
| Status mix | share of 2xx / 3xx / 4xx / 5xx / 499 | scraping, credential stuffing, scanning |
| URI behaviour | distinct `uri_h` / requests; repeat-rate of one `uri_h` | cache-busting (high diversity) vs hammering one path |
| Method mix | GET / POST / other shares | slow-POST, write abuse |
| Connection reuse | `connection_requests` mean; new-connection rate; keep-alive share | Slowloris (many conns, few requests), H2 multiplexing |
| Volume asymmetry | `bytes_sent` / `request_length` ratios; means | tiny-request/large-response amplification, uploads |
| Rate-limit signal | `limit_req_status=REJECTED/DELAYED` count | proximity to the deterministic threshold |

### 5.3 Keying [DECISION 3 + RISK]
* **Key: (IP, `ua_h`) from the start** — the window and the model separate concurrent
  clients behind one NAT IP by User-Agent. Implemented in P1 (`l7_ingest.key_of`).
* **Enforcement still maps to the IP.** A ban decided on an `(IP, ua_h)` key bans the
  source IP, because XDP's `blacklist_map` is keyed on IP (`xdp_ddos_filter.c:64`). So a
  confident detection on one UA behind a NAT still blocks the whole IP — a deliberate,
  documented trade-off.
* [RISK] **NAT** therefore remains a false-positive and over-block hazard: `ua_h` splits
  the *windows* but not the *enforcement*, and a spoofable UA is a weak separator.
  Mitigations evaluated at P4: an `(IP, connection)` key for connection-scoped abuse; a
  NAT'd benign profile in the capture (§6) with its false-positive rate reported
  separately (§9 R3).

### 5.4 Anti-fingerprint discipline [DECISION, from `ML_INVESTIGATION.md` §6.3]
The XDP model keyed on request size and TCP window — tool fingerprints, trivially evaded
(`ML_INVESTIGATION.md` §3). To avoid repeating this at L7:
* **No raw strings as features.** `request_uri` and `user_agent` enter only as a hash used
  for *diversity/repeat* statistics, never as identity. Raw size (`request_length`,
  `bytes_sent`) is a behavioural ratio, not the dominant absolute feature; feature-set
  variants with and without it are compared (as CF3 did).
* **Invariance tests are acceptance gates.** For each candidate model, a battery of
  edits-that-should-not-change-the-decision: pad requests, swap User-Agent, change the URI
  strings (keeping the access pattern), shift absolute timing within human range. A model
  that flips on these is rejected, however good its F1 (this is what the XDP model failed).
* **Randomise fingerprints in training data** (§6): vary request sizes, UA strings, and
  header counts across both benign and attack clients so they carry no label signal.

### 5.5 The sparse-signal problem [RISK — the central technical risk]
A slow attacker emits **very few log lines**: one per completed or timed-out request. A
Slowloris connection may produce a single line every 5 s (at the header timeout), and a
patient slow-body POST similarly. So a request-sequence model may need many seconds to fill
a window, or may barely see the attacker at all — the same latency trap the XDP model fell
into (`ML_INVESTIGATION.md` §2.3), in a new form.

Mitigations, to be evaluated (not assumed to work):
* `$request_completion=""` and the 408/400/413 lines give an *early, explicit* slow-attack
  signal at each timeout, without waiting for 15 completed requests.
* Keep the deterministic SlowConn (`ss`-based) and error-log R.U.D.Y. detectors as the
  fast path for the clearly-abusive case; the GRU targets the *sub-threshold* slow attacker
  that those rules miss.
* Consider a periodic in-flight snapshot (open connections and their age, from `ss`) as an
  additional, non-log input for slow attacks — a design option flagged for P2, not a
  commitment.
* **Verification gate:** P5 must report the GRU's time-to-detect per family; if it cannot
  beat the heuristics' latency in its own niche, the honest conclusion (per
  `ML_INVESTIGATION.md` §6.1) is that it adds no value there.

### 5.6 Load awareness at L7 [DECISION, from `ML_INVESTIGATION.md` §6.5]
During a volumetric flood, legit clients' L7 lines turn into 499/503/timeout bursts with
inflated `request_time` — exactly the stalled-handshake false-positive mechanism, at L7.
So the L7 engine needs the XDP model's two guards, re-expressed:
* **Flood suppression:** while the L3/L4 engines report an active volumetric flood
  (`volumetric_active_until`), pause L7 GRU bans and clear/!trust per-IP request windows.
* **A completion/age gate:** do not score windows dominated by requests that overlapped a
  suppression interval.

### 5.7 P2 implementation: the shadow scoring engine [FACT: code + 114 green tests]

**Columns** (`l7_features.FEATURE_GROUPS`).
* One row per request. A window holds the last `seq_len` = 20 requests of one
  `(IP, ua_h)` key, ordered by **request start** (`msec − rt`).
* Shorter windows are left-padded with zero rows, so the newest request sits in the
  last time step, which `GRUDDoSClassifier` reads. Column 0 is `valid` (0 on padding).
* The default selection has 20 columns; the protocol group adds 3.

| Group | Columns | Definition |
|---|---|---|
| timing | `log_iat`, `log_rt`, `log_urt` | gap since the previous request's start (0 for the first); request time; upstream time (summed over retries `a, b` and redirects `a : b`) |
| completion | `incomplete`, `s_timeout` | `$request_completion` ≠ `OK`; status 408 / 444 / 499 |
| status | `s2xx` … `s5xx` | status class |
| method | `m_get`, `m_post`, `m_other` | request method |
| size | `log_rlen`, `log_bsent`, `size_ratio` | request bytes, response bytes, response/request (log scale) |
| connection | `log_creq`, `new_conn` | request number on the connection; first request on it |
| uri | `uri_repeat` | the path occurred earlier in the window (hash equality only) |
| ratelimit | `lreq_limited` | `$limit_req_status` DELAYED or REJECTED |
| protocol (**off by default**) | `is_h2`, `is_tls`, `tls_reused` | client capability, a fingerprint risk (§5.4) |

**Scaling.** `apply_scaling` is shared with the P4 trainer: standardisation, `valid`
left untouched, padding left at exactly zero. So training and serving cannot drift.

**Model package** (`l7_scorer`).
* Contents: `config.json` (format `l7-gru-package/1`, columns, `seq_len`, GRU size,
  mean/std, threshold, consecutive, weights SHA-256, metadata) and `model.pth`.
* Loading refuses unknown or duplicate columns, `valid` not first, bad shapes or
  policy values, and tampered weights.
* Windows are scored in one batch.

**Decision policy (shadow).**
* Every poll (1 s), each key that received requests and holds ≥ 5 of them is encoded
  and scored in one batch.
* p > threshold in `consecutive` successive *scored* windows of a key gives one
  `l7_would_ban`. It is logged, never enforced.
* The event records whether another engine had already banned the IP, which shows
  P5 who got there first.
* A key is scored only when it has new requests, so a slow attacker's streak advances
  once per request (R1, §5.5).

**Load awareness (§5.6), as built.**
* While the L3/L4 engines report a flood (`volumetric_active_until`), nothing is
  scored and hit streaks are forgotten.
* When the flood ends, `trust_after` is set to that instant. Windows whose requests
  mostly (> 50 %) started earlier are skipped until fresh requests dominate.

**Telemetry** (event kinds, pinned by the contract test).
* `l7_gru_poll` every 5 s and at exit: polls, suppressed polls, windows scored, too
  short, age-gated, over threshold, would-bans, evicted, max p, top-5 keys, model
  SHA-256, `t_last_poll`.
* `l7_would_ban` as it happens.
* `l7_shadow`: the P1 ingest counters.

**Determinism and replay.**
* Windows are scored in sorted key order, and eviction runs inside `poll()`.
* With `L7_RECORD`, the daemon writes the engine's exact input: every record, plus
  every poll tick with the flood state and the banned IPs.
* `ml/replay_l7.py` replays it through a fresh engine and reproduces the live
  decisions. `--compare-live` checks this.
* Verified offline by a simulated session with a flood and a SIGKILL-ed daemon
  (`tests/test_smoke_p2_analysis.py`), and to be verified live at the P2 gate.

**Invariance probes** (`ml/l7_probes.py`).
* Exact transforms must give |Δp| ≤ 1e-5: User-Agent swap, consistent URI renaming,
  time offset.
* Robustness transforms report decision-flip rates: +50–500 B padding, ±10 % IAT
  jitter. The bar for these is set at P4.
  * **The P2 gate showed that flip rates alone mislead.** The untrained model flipped
    91 % of its decisions under padding, yet its largest score change was 0.015: its
    scores sat at the threshold.
  * P4 therefore judges robustness on the |Δp| distribution *and* on flips at the
    calibrated threshold.
* In the tests, a size-keyed stub model *fails* the padding probe (flip rate > 50 %).
  The harness catches exactly the XDP model's shortcut.

**Measured cost [FACT, `bench/l7_ingest_bench.py`].**
* A full poll (encode + one batched score, GRU 64×2, 20-step windows) costs ≈ 110–125 µs
  per updated window.
* 256 updated windows take ≈ 28 ms per poll (≈ 3 % of a core at 1 poll/s); 1024 take
  ≈ 117 ms (≈ 12 %).
* Encoding (≈ 70 µs/window, pure Python) costs more than the batched GRU
  (≈ 45 µs/window). Caching per-request static features at ingest is an optimisation
  lead, if P5 shows it matters.

**P1 fixes that landed with P2.** `normalise` now sums multi-value upstream times
(P1 coerced them to 0), keeps `tls`, `reused` and `conn`, and maps the legacy
`json_ml_format` field names.

---

## 6. Dataset re-capture and training pipeline

The capture is the hard part: the XDP model's failures were data failures
(`ML_INVESTIGATION.md` §4, §6.4). This reuses the capture-mirrors-deployment principle
(the capture imports the suite, so topology/nginx/gunicorn match serving) and the
trainer-v2 principles from `ML_INVESTIGATION.md` §5 (A5/A6), re-aimed at L7.

### 6.1 Dual-label capture (`ml/capture_l7.py`, built at P3)
* Records the **extended JSON access log** (§3), labelled by `$remote_addr` → namespace
  map (benign `10.0.1.x`, attack `10.0.2.x`), with a provenance manifest, seeds, and an
  attack-schedule log (ground-truth start/stop per bot) — as in A5.
* Native XDP; a new dataset directory, never overwriting `training_data/`.
* Captures both `:80` and `:443` (the L7 model should be TLS-agnostic).

### 6.2 Benign diversity (the FP budget) [FACT: tooling present/absent on this VM]
From REPORT §9.5, constrained to what is installed (`curl` 8.18 with HTTP/2 via nghttp2;
`wrk`; Python `requests`; **no** `wrk2`, `h2load`, `ab`, `slowhttptest`):
* one-shot curl (as today), plus **keep-alive sessions** with think-time (a Python
  `requests.Session` loop — `requests` is present);
* **HTTP/2 over TLS** with parallel streams (`curl --http2 --parallel`);
* varied request sizes, header counts and **User-Agent strings** per client;
* large downloads (add a ≥ 1 MB endpoint to `dummy_app`) and 60 KB uploads;
* **NAT'd namespaces** (several users behind one IP);
* small-request API/health-check clients;
* all four netem profiles, ≥ 50 % of clients on `:443`.
Missing tools (`wrk2` for open-loop rate, `h2load`) are flagged as capture-fidelity gaps
to either install (apt, with approval) or substitute in Python at P3.

### 6.3 Sub-threshold L7 attacks (calibrated, §7)
Trained families: sub-threshold request floods (20/45 rps < 50), Slowloris (6 sockets),
slow-body POST (Content-Length ≤ 64 k so Nginx does not 413 it immediately), URI-randomised
scraping < 50 rps. **Held-out families** (evaluation only): padded request floods,
credential-stuffing POSTs against a 401/403 endpoint, slow-read, an HTTP/2 multiplexing
abuse if tooling allows. Each capture also runs a concurrent volumetric flood so the model
learns the suppressed/contaminated regime (§5.6).

### 6.4 Trainer (`ml/train_l7.py`, built at P4) [from `ML_INVESTIGATION.md` §5 A6]
* Reads dataset manifests; writes a model package + model card; **never** touches
  `training_results/`.
* Splits grouped by IP and by capture, plus **leave-one-family-out**.
* Metrics at the deployed policy (threshold × consecutive): per-IP detection with
  Clopper-Pearson CIs, time-to-detect from the ground-truth attack start, **false
  positives per benign client-hour per profile** (NAT separately).
* The **invariance probe battery** (§5.4) as regression tests; loss/AUC-based selection;
  feature-set variants (with/without size, UA, URI-diversity).
* Reports window-level *and* IP-level numbers, always stating the sampling
  (`ML_INVESTIGATION.md` §3.4 showed why).
* **Tabular baseline [DECISION 6].** Alongside the GRU, train a non-sequential baseline
  (LightGBM or logistic regression on per-window summary statistics — mean/max/stddev of
  the §5.2 features) under the identical splits, policy metrics and probe battery. If the
  GRU does not beat it on held-out-family recall at equal FP, the thesis reports that
  sequence modelling adds nothing here and the simpler model is preferred. (LightGBM is
  not yet installed; P4 either adds it with approval or uses scikit-learn's gradient
  boosting / logistic regression, which are present.)

---

## 7. Calibrated sub-threshold scenarios (demonstrating marginal value)

The point of the whole move: a niche where the heuristics are blind. Calibration must be
**honest**, or the result is circular.

* [DECISION] **Calibrate on the thresholds and on service impact — never on the model's
  score.** A scenario is admissible only if it (a) provably does **not** trip any
  deterministic rule (verified from the ban-event log: zero heuristic bans) and (b) causes
  a measurable harm — degraded legit availability/latency, or real backend cost — so it is
  a genuine threat the heuristics miss. Rate/socket counts are set as a fraction of each
  threshold (e.g. 0.4× and 0.8× of 50 rps; 6 of 8 SlowConn sockets).
* **The honest comparison** (`ML_INVESTIGATION.md` §6.2): GRU vs simply lowering the
  heuristic thresholds. If a lower static threshold catches the same scenarios at the same
  FP, the model earns nothing. The pre-registered hypothesis is that the model separates
  sub-threshold *abuse* from sub-threshold *benign* (e.g. a slow mobile client, a polite
  scraper) where a lower threshold would false-ban the benign client.
* These scenarios extend the suite as new entries (S11–S15 in `ML_INVESTIGATION.md` §5 A4)
  and only become meaningful once the L7 model is wired (P2+).

---

## 8. Step-by-step roadmap with verification gates

Each phase ends at a **gate**: an artifact you review and approve before the next phase.
Build steps (P1–P2, P4, P6) touch code only, on a feature branch; capture/eval steps
(P3, P5) are VM workloads requiring explicit approval with duration and side effects, per
the working protocol.

| Phase | Work | Output | Gate (approval needed to pass) |
|---|---|---|---|
| **P0** ✓ | This design | `docs/L7_GRU_DESIGN.md` | **Approved 2026-10-14** with the six §10 decisions. |
| **P1** ✓ | Extended `log_format` (both confs); Unix-dgram syslog reader (`l7_ingest.py`); **shadow mode only** (`l7_shadow_monitor`, parse + `(IP, ua_h)` windows, no GRU, no bans); counters; unit + contract tests; smoke runner (`ml/smoke_l7.py`) | `l7_ingest.py`, `control_plane.py` shadow thread, both nginx confs, `tests/test_l7_ingest.py`, `ml/smoke_l7.py` | **PASSED 2026-10-14**: 70 tests green, lint clean, `nginx -t` ok; smoke (`results/2026-10-14_l7-p1-smoke/`) shows steady-regime drops ≈ 0, 0 truncation, CPU mean 4.6 % |
| **P2** ✓ | Request-sequence features (§5.2); L7 GRU wired in **shadow mode** (`l7_gru_poll` / `l7_would_ban` events, never bans); load-aware suppression + age gate (§5.6); batched inference; recording + deterministic replay; invariance-probe harness; `XDP_GRU` switch | §5.7; `results/2026-10-15_l7-p2-smoke/` | **PASSED 2026-10-15** (`ml/smoke_l7.py --p2`, untrained model): P1 transport still clean (0/135 steady drops); live run replayed exactly (13/13 would-bans, 335/335 windows); flood gating live (12 suppressed polls, 57 age-gated windows); exact probes \|Δp\| = 0; only deterministic engines banned. No detection claims: the model is untrained |
| **P3** | `ml/capture_l7.py`: dual-label capture, diverse benign (§6.2), sub-threshold + held-out attacks (§6.3) | capture tool + manifest schema | **Smoke capture (VM, approval);** manifest, labels, schedule complete; benign diversity verified in the data |
| **P4** | `ml/train_l7.py`: grouped/LOFO splits, policy metrics, probe battery, feature-set variants; **offline, CPU** | model package + model card + metrics report | Metrics review: held-out-family recall, FP/client-hour per profile, probe-battery pass, GRU-vs-lower-threshold comparison |
| **P5** | Online evaluation: arms (L7-GRU-only / heuristics-only / hybrid), sub-threshold scenarios (§7), benign soak; current + candidate model | published campaign in `results/` | **Each VM run approved individually;** pre-registered hypotheses judged; honest verdict on marginal value |
| **P6** | `ml/promote_l7.py`: install a vetted model, with hashes and metrics | promoted model | **Explicit approval;** only if P5 shows value at acceptable FP |

Verification threads through every phase: shadow mode (P1–P2) means the L7 engine can be
observed on real/replayed traffic *before* it is ever allowed to ban, which directly
answers the "built observability in from day one" lesson (`ML_INVESTIGATION.md` §6.6).

---

## 9. Risk assessment

| # | Risk | Likelihood / impact | Mitigation and gate |
|---|---|---|---|
| R1 | **Slow attacks emit too few log lines** to fill a window in useful time (§5.5) | High / high — this is the core risk | `$request_completion` + timeout lines as early signal; keep deterministic SlowConn/R.U.D.Y. as fast path; optional `ss` in-flight snapshot; **gate: P5 time-to-detect must beat heuristics in the niche, else report no value** |
| R2 | **Syslog datagram truncation / drops** under flood corrupt features | Medium / medium — **measured at P1**: 0 in the sub-threshold regime; ~40 % only under a flood burst (`max_dgram_qlen=512` bound) | 0 truncation seen (incl. a 900 B UA); drops are flood-only and that is the rate rule's regime (file-based) with the file sink retaining all. If ever needed for the GRU: raise `net.unix.max_dgram_qlen` (sysctl, needs approval), batch the reader's drain (`recvmmsg`), or fall back to file+tail (§4.3) |
| R3 | **NAT** mixes users on one IP; a ban over-blocks (§5.3) | Medium / high | IP+UA or IP+connection keys; NAT'd benign profile in capture; **gate: P4 reports NAT FP separately** |
| R4 | **Fingerprint shortcut recurs** via UA/size (the XDP failure) | **High / high — evidence at P2:** in the current testbed traffic, request size (wrk ≈ 34 B vs curl ≈ 72 B) and connection reuse (curl one-shot vs wrk keep-alive) separate the classes, and URIs carry nothing (one-path app) | Hash-only strings, size as its own droppable group, protocol off by default (done in P2); **P3 must randomise request sizes, add keep-alive and HTTP/2 benign sessions, and serve a multi-path app**; **gate: the invariance probe battery is a hard P4 acceptance test** (\|Δp\| and flips) |
| R5 | **No genuine niche:** a lower static threshold matches the GRU (§7) | Medium / high (to the thesis claim) | Pre-registered GRU-vs-lower-threshold comparison; **gate: P5 must show separation of sub-threshold abuse from benign** |
| R6 | **Benign diversity still insufficient** → FP on real clients (the recurring data failure) | Medium / high | §6.2 mix incl. keep-alive, H2, NAT, mobile netem; **gate: FP/client-hour per profile at P4 and the soak at P5** |
| R7 | **HTTP/2 multiplexing** makes connection-level features ambiguous (many requests per conn) | Low / medium | Per-request logging is unaffected (one line each); connection features use `connection_requests`; validate on an H2 benign profile |
| R8 | **TLS passthrough / L4 LB** in a real deployment removes L7 visibility (§1) | N/A here / high elsewhere | Documented boundary condition; thesis states the architecture's assumption |
| R9 | **Daemon CPU/GIL** under combined L7 ingest + inference + L4 polling | Low / medium | Batched inference (§4.4); single ingest thread has ~6× head room; **gate: P1/P5 measure daemon CPU/RSS** |

---

## 10. Decisions (resolved 2026-10-14)

All six were confirmed by the user when the plan was approved; the status block at the top
restates them. For the record:

1. **Scope** — L7 sub-threshold abuse only; L3/L4 and high-rate L7 stay deterministic. ✓
2. **Transport** — Unix-domain datagram syslog primary + durable file sink. ✓
3. **Keying** — IP + `ua_h` **from the start**; bans map to the source IP for XDP. ✓
4. **Slow signal** — `$request_completion` + timeout lines first; `ss` in-flight snapshot
   kept as a fallback if P1/P2 shows signal starvation. ✓
5. **Coexistence** — keep the deterministic L7 rate and R.U.D.Y. rules; the GRU adds only
   the sub-threshold niche. ✓
6. **Model family** — GRU primary **and** a tabular baseline (LightGBM / logistic) at P4
   to test whether sequence modelling earns its place (§6.4). ✓

Each later VM step (P1 smoke, P3 capture, P5 evaluation) is still approved on its own.
