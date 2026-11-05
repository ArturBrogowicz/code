# Targeted Literature Selection: Hybrid XDP + L7 Architecture (Phase 2)

Thesis: *Badanie skuteczności i implementacja rozwiązań w obronie przed różnymi technikami ataków DDoS*.
This document builds on the Phase 1 review (`docs/sota_broad_review.md`) and the corpora in `docs/sota/`.

> **Status (2026-10-28): 12 papers (5 new, 7 retained from Phase 1), 24 verbatim quotes, all verified.**
> Every quote below was found in the stored text of its paper by
> `python3 docs/sota/fetch_sota.py --corpus docs/sota/corpus_l7 verify --review docs/targeted_literature_selection.md --with-corpus docs/sota/corpus`
> (0 failures; the run is in `docs/sota/corpus_l7/logs/`). L7-xx quotes come from `docs/sota/corpus_l7/`,
> P-xx quotes from the Phase 1 corpus. Citations were resolved by Crossref. Every number about a paper
> comes from its stored text; every number about this repository names its source file.
> Nothing in the thesis draft, the presentation or the simulation code was changed.

---

## 0. Summary table

| Paper ID | Authors & Year | Attack Vector | Defense Tech | Key Metric | Maps to (§4) |
|---|---|---|---|---|---|
| L7-01 | Tripathi, 2024 | Slow-rate DoS against HTTP/2 (5 attacks) | Anomaly detection on HTTP/2 frame-event sequences, learned from benign traffic only | FPR 1.71–1.83% per request at 100% recall; all attacks detected in <30 s; CPU <≈7% | GRU detector, Nginx monitor |
| L7-02 | Sood & Hubballi, 2024 | Slowloris (50–5,000 sockets, random UA, proxy) | 8 server-side behavioural parameters + majority vote / decision tree (Python, psutil, log parsing) | Recall 99.92%, precision 99.66% (48 h live server); single count threshold loses ≈10% recall | Python daemon, Nginx monitor |
| L7-03 | Sikora et al., 2021 | 11 slow DoS attacks (HTTP/1.1 and HTTP/2) | Attack generator tested against Apache, Nginx, lighttpd, IIS | Nginx 1.14.0 resisted 9 of 11; Slow Read DoS'd it with ≈1,900 connections | Testbed, Nginx monitor |
| L7-04 | Almaraz-Rivera et al., 2022 | HTTP (GoldenEye), TCP and UDP DoS/DDoS in Bot-IoT | RNN, LSTM, GRU vs DT, RF, MLP, SVM; feature-set ablation | Without timestamps: GRU 96.23% vs DT 99.862% accuracy; DT 30,362 vs GRU 2,864 flows/s | GRU detector |
| L7-05 | Kostopoulos et al., 2026 | eBPF security (DDoS, IDS, app-layer DoS) | PRISMA SLR of 54 studies | Median CPU overhead 2.4%; map update 5–20 µs, 0.5–2 ms for hybrid ML; 81.4–87% testbed-only | XDP filter, daemon↔XDP interface |
| P2-01 | Scholz et al., 2018 | Floods / spoofed traffic at the host | XDP source-IP blacklist vs iptables/nftables | XDP 7.2 Mpps/core vs ≤1.5 Mpps netfilter | XDP filter |
| P2-02 | Feraudo et al., 2024 | IoT-botnet SYN flood | XDP/eBPF map rules vs iptables | eBPF map update ≈4.5 µs; average-based limits drop >80% of a hub's benign traffic | XDP filter, daemon |
| P2-04 | Karrakchou et al., 2025 | CIC-DDoS2019 vectors + SYN flood | P4 CNN early exit + controller GRU | F1 99.91/99.90 (NS-3, 1.5 Mbps links) | Fast/slow path split |
| P3-01 | Doriguzzi-Corin et al., 2020 | HTTP/IRC-botnet DDoS (UNB datasets) | Lightweight CNN on time-windowed flow arrays | >55,000 samples/s, 40× faster than LSTM at equal F1 | GRU detector (baseline) |
| P3-04 | Arp et al., 2022 | ML in security (NIDS case: Mirai) | Pitfall taxonomy; packet-rate IQR baseline | Baseline TPR 0.996 vs Kitsune 0.882 at FPR 0.001 | Defense formulation (§6) |
| P4-01 | Cantone et al., 2024 | CIC-IDS2017/2018 incl. Slowloris, Slowhttptest | DT, RF, XGBoost, LDA; within vs cross-dataset | MCC 83.86% within vs 14.91% cross-dataset | Defense formulation (§6) |
| P4-02 | Goldschmidt & Chudá, 2025 | DoS in 74% of 89 NIDS datasets | Dataset SLR + recommendations | CIC-IDS2017 used by only 29% of top-tier papers | Defense formulation, testbed |

---

## 1. Codebase audit (read-only)

### 1.1 What runs where

| Layer | Code | What it does | Default state |
|---|---|---|---|
| Fast path | `xdp_ddos_filter.c` | XDP program on the server interface. Drops sources found in `blacklist_map` (hash, 100k entries) with `XDP_DROP`. Passes everything else, after updating per-source counters (`telemetry_map`, LRU per-CPU hash, 100k) and per-flow forward features (`flow_map`, LRU hash, 262,144). | On (`xdp` mode) |
| Control plane | `control_plane.py` | Python daemon with one thread each for the L3/L4 monitor (1 s polls of the XDP maps and `ss`), the Nginx access log, the Nginx error log, and the optional GRU feeds. `ban_ip` (`:286`) writes the source into `blacklist_map` (or an iptables DROP), with a TTL of 300 s, then kills the source's sockets with `ss -K` (`:389`). | Rules on |
| Deterministic rules | `control_plane.py:84-146` | `l4_syn` >200 SYN/s. `l4_volumetric` >5,000 pkts/s. `l4_slowconn`: ≥8 ESTABLISHED connections and <250 B per interval for 3 consecutive polls. `l4_lowsyn`: SYNs with no completed handshake for 4 polls. `l7_rate`: >50 rps over 10 s, or >80% errors. `l7_rudy`: ≥3 Nginx body-read timeouts in 60 s. Global SYN >5,000 turns on syncookies. The tolerant profile raises the rps limit to 108 and the SlowConn limit to 180. | Default profile |
| Nginx | `nginx.conf` | `client_header_timeout 5s` and `client_body_timeout 5s` (nginx defaults: 60 s). `limit_req` 30 r/s, burst 100. `limit_conn` 50. JSON access log (`l7json`) and an error log; the error log is the R.U.D.Y. rule's input. | On |
| Tier-1 GRU | `train_testbed_gru.py`, `control_plane.py:84` | Reads 8 CICFlowMeter-named forward-flow features from `flow_map`. Windows of 15 polls; 2 layers × 64 units. Policy: p > 0.95 in 3 consecutive windows. | **Off** (`XDP_GRU=0` since the 2026-10-19 audit) |
| L7 GRU | `ml/train_l7.py`, `ml/l7_*.py`, `control_plane.py:521` | Windows of 20 requests (stride 3) per (IP, UA-hash), built from the `l7json` stream; 2 layers × 64 units. The scorer "NEVER bans" (`:531`). | **Shadow only**, and off unless `L7_SHADOW=1` |
| Testbed | `test_distributed_suite.py` | Network namespaces, veth pairs, a bridge and netem profiles. 20 legitimate curl clients (`--max-time 10`) and 5 bots (10 at the "knee" operating point). 10 scenarios: SYN, slow SYN, UDP, HTTP flood (`wrk`), ACK, fragmentation, Slowloris, R.U.D.Y., Yo-Yo, multi-vector. | — |
| Statistics | `eval/run_level_stats.py` | Paired blocks, t-interval, sign-flip p-value and the pre-registered decision rule. | — |

### 1.2 End-to-end pipeline, as built

1. **Attack scenario.**
   - Slowloris (`scenario_slowloris`): each bot keeps N = 8 sockets open. Each socket sends a partial GET; every SLEEP = 5 s the bot adds one `X-a` header line to each socket and reopens any that closed.
   - R.U.D.Y. (`scenario_rudy`): N = 10 sockets per bot. Each sends a POST with `Content-Length: 1000000`, then one body byte every 7 s.
   - The flood scenarios use hping3 and `wrk`.
2. **Telemetry.** Four sources feed the daemon:
   - XDP per-source counters and per-flow features.
   - The kernel socket table, read with `ss` (connections per source and bytes per interval).
   - The Nginx access log (one line per *completed* request).
   - The Nginx error log (`client timed out ... while reading client request body`, `control_plane.py:465`).

   The shadow GRU additionally reads the `l7json` stream.
3. **Detection.** Only the deterministic rules in §1.1 decide. The Tier-1 GRU is off. The L7 GRU, when enabled, logs would-bans and nothing else.
4. **Mitigation.** `ban_ip` puts the source into `blacklist_map`, so later packets are dropped before the network stack. `ss -K` frees the source's existing sockets, which matters for slow attacks because they hold sockets rather than send packets. The ban expires after 300 s.
5. **Measurement.** The harness records:
   - legitimate clients' availability,
   - exact time to mitigate (TTM) per bot,
   - p95 latency,
   - pre-stack drop (`PreStack_Dropped` against `PPS_Rx`),
   - Nginx CPU.

   Run-level paired statistics decide the claims.

**Headline results** (`docs/THESIS_CLAIMS.md`; every line names its campaign there):

| Claim | Result |
|---|---|
| M3 availability | EXP-A, 10 paired blocks: the daemon served +33.2 pp more than no protection [+26.1, +40.2] at the HTTP-flood knee |
| M2 XDP vs iptables | Median TTM 0.215 s vs 0.290 s (EXP-A, post hoc, descriptive) |
| Pre-stack drop | 0.84–1.66 Mpps on the interface while `IP_InReceives` stayed ≤227 pps |
| M6 time to mitigate | `l7_rate` 0.06–1.13 s; `l4_volumetric` 0.41–1.25 s; `l4_syn` 0.50–3.82 s; SlowConn and low-SYN 3.5–4.7 s |
| M7 slow attacks mitigated | **Not supported.** SlowConn bans the suite's Slowloris (8 sockets) and R.U.D.Y. (10 sockets) only at its default threshold of 8. Under the tolerant profile it banned 0 of 15 bots in each scenario (EXP-B). |
| L1 XDP-fed GRU adds value | **Contradicted.** 0 true bans and 1 false ban among 710 recorded bans |
| L2 Nginx-log GRU adds value | **Not supported.** Pre-registered verdict "no advantage": GRU 20/20 attackers with 9 benign IPs flagged; rules and HGB baseline 20/20 with 2 flagged |
| L3 sequence model needed | **Not supported.** Shuffling request order changed 0.21% of window decisions and no IP-level decision |

### 1.3 The two GRU training pipelines

| | Tier-1 GRU (XDP flow features) | L7 GRU (Nginx request windows) |
|---|---|---|
| Data | Testbed captures (`capture_testbed_dataset.py`); labels by bot IP and scheduled family | Scripted roles (`ml/l7_traffic.py`). Trained families: `subthreshold_flood`, `scraper`, `slowloris` (6 conns), `slowpost` (6 conns). Held-out families: `padded_flood`, `credstuff`, `slowread` |
| Features | 8 forward-flow features (`Init_Win_bytes_forward`, IATs, header length, packet length max, rate, total bytes) | Groups: timing, completion, status, method, size, connection, URI, rate-limit, protocol. The chosen variant drops size and server timing (`no_size_no_server_timing`) |
| Windowing | 15 consecutive polls per source | 20 requests, stride 3, per (IP, UA-hash) |
| Split | IP-disjoint. The test set holds *new intensities* of Slowloris (N = 30) and R.U.D.Y. (N = 20) | Benign IP-disjoint, attack families held out. The trained attack families share too few IPs for an IP-disjoint split, so their recall is in-distribution (`ml/train_l7.py:11-15`) |
| Loss curves | **Not persisted.** Loss is printed every 5 epochs to stdout only | **Not persisted.** Only the final `val_loss` (0.17387) is saved |
| Offline metric | val F1 1.0, test F1 0.9963 (`training_results/feature_config_testbed.json`) | Held-out groups: credstuff 6/6, padded_flood 1/1, slowread 0/1 (`results/2026-10-16_l7-p5c3-train`) |
| Live result | Never banned before a heuristic did. Earliest possible GRU ban: Slowloris 16 s vs SlowConn 3.72 s; R.U.D.Y. 8 s vs 3.57 s (`docs/ML_INVESTIGATION.md`). Changing only the request size moves held-out R.U.D.Y. detection from 19–29% to 100% | "No advantage" (L2). The slow families yield about one window each, against 58–332 for fast families (`results/2026-10-15_l7-p3-capture/`), and were caught by no engine (`docs/L7_GRU_DESIGN.md`, audit note 8) |

The thesis cannot show training curves for either model without re-running training with per-epoch
logging. Re-running training is out of scope here, because the brief rules out changes to simulation code.

### 1.4 The brief's premise against the repository's evidence

The Phase 2 brief describes the slow path as "a machine learning model (GRU) trained directly on runtime
traffic synthesized in our own laboratory testbed, specifically engineered to detect and mitigate
application-layer low-and-slow attacks (e.g., R.U.D.Y., Slowloris) alongside Nginx L7 telemetry".

The **design intent** fits the Tier-1 GRU: its held-out test set is exactly Slowloris and R.U.D.Y. at
unseen intensities. The **measured behaviour** does not fit the premise:

* **No GRU mitigates anything by default.** The Tier-1 GRU is off (`control_plane.py:84`) after 0 true
  bans in the recorded runs (L1). The L7 GRU is shadow-only by construction (`control_plane.py:531`).
* **The L7 GRU is blind to low-and-slow, by the project's own finding.** Nginx writes an access-log line
  only when a request completes or times out, so a slow connection produces about one line. The design
  document states this directly: "The access-log GRU is blind to well-behaved low-and-slow" (R1,
  `docs/L7_GRU_DESIGN.md`). Its confirmed scope is "GRU owns L7 sub-threshold abuse only" (decision 1).
* **Slow attacks are handled by two deterministic rules that depend on thresholds.**
  - SlowConn (`ss`): ≥8 sockets, <250 B per interval, 3 polls.
  - R.U.D.Y. (error log): this rule fires only when Nginx's 5 s body timeout fires, i.e. only for a
    R.U.D.Y. that is already too slow to hold its sockets (§5, L7-02).

  A client holding 7 sockets passes SlowConn. Under the tolerant profile neither slow scenario is banned
  (M7, EXP-B). The 6-socket slow families of the L7 track were caught by nothing.

**Consequence for this document.** The matrix (§4) maps papers to the architecture as built and measured.
The defense (§6) is therefore a *methodological* argument, why testbed-native training is the right
design and what it exposed, together with a scoped negative result. It is not a claim that the GRU
mitigates low-and-slow attacks; `docs/THESIS_CLAIMS.md` (M7, L1–L3) would contradict such a claim. §6.4
lists what would have to change for the premise to become true.

---

## 2. Down-selection of the Phase 1 papers

| ID | Decision | Reason |
|---|---|---|
| P2-01 Scholz | **Retain** | Same blacklist-map design as `xdp_ddos_filter.c`; the yardstick for M2 |
| P2-02 Feraudo | **Retain** | Map-update cost (≈4.5 µs) separates ban latency from detection latency (M6); average- versus peak-based rate limits (L4) |
| P2-04 Karrakchou | **Retain** | The published fast-path (data plane) + slow-path (controller GRU) split closest to this architecture; simulated at 1.5 Mbps |
| P3-01 LUCID | **Retain** | Windowed-flow input and a CNN that matches an LSTM at 40× throughput: the cheap baseline for L3 |
| P3-04 Arp | **Retain** (reframed, §6) | Pitfall taxonomy the testbed design answers; a simple baseline beats a deep model |
| P4-01 Cantone | **Retain** (reframed, §6) | Cross-dataset collapse of public-dataset models, including the CIC Slowloris/Slowhttptest classes |
| P4-02 Goldschmidt | **Retain** (reframed, §6) | Dataset recommendations the testbed design follows (single environment, multiple runs, significance tests) |
| P1-01 Bock, P1-02 Nawrocki, P1-04 Hiesgen | Drop | Reflection/amplification and Internet-scale trends; outside the slow path. P1-01 still bounds M1 (per-source bans under spoofing) |
| P1-03 QUICsand | Drop | QUIC handshake floods; the testbed serves no QUIC |
| P2-03 Jaqen, P2-05 Rizvi | Drop | Switch hardware and BGP/anycast placement; not host-based |
| P3-02 Ding | Drop | Volumetric entropy in P4. Its 36% TPR at a 5% attack share stays useful context for M7 in the Phase 1 review |
| P3-03 Panggabean | Drop | A GRU on mixed public datasets with no live, latency or slow-attack evaluation. In Phase 1 it served as a caution tied to the legacy cross-dataset pipeline, which the brief says to disregard |
| P4-03 MoonGen | Drop | High-rate packet generation; slow attacks need connection-level control, which L7-03 covers |

The Phase 1 review has been corrected in the same commit. The applicability notes of P2-04, P3-03, P4-01
and P4-02 no longer base critique on `merge_datasets.py`, static cross-dataset merging or `todo.txt`
item 4. Their quotes are unchanged and re-verified.

---

## 3. Targeted retrieval: method and flow

**Search.**
- Profile: `docs/sota/profile_l7.json`. Three pillars:
  - L7: low-and-slow application-layer attacks.
  - SEQ: recurrent models for L7 DoS.
  - HYB: eBPF/XDP coupled with application-layer intelligence.
- 18 queries plus one seed (the thesis draft's slow-DoS generator), years 2019–2026.
- Sources: arXiv (19 requests, all answered), Crossref (19) and Europe PMC (18), which was added in this
  phase for full JATS text of open-access journals.
- OpenAlex refused every request and Semantic Scholar all but one (HTTP 429), as in Phase 1. The log is
  `docs/sota/corpus_l7/logs/search_20261028T123055Z.log`.

| Step | Count | Where |
|---|---|---|
| Records before merging (arXiv 79, Crossref 448, Europe PMC 39, Semantic Scholar 25, seed 1) | 592 | search log |
| Unique records after merging by DOI, arXiv id and title | 458 (L7 231, SEQ 151, HYB 114; pillars overlap) | `corpus_l7/candidates.json` |
| Shortlisted on title and abstract | 10 | below |
| Full text fetched and read | 8 | `logs/fetch_20261028T123408Z.log` |
| Included | 5 (L7 3, SEQ 1, HYB 1) | `corpus_l7/selected.json` (one reason per paper) |

**Screening criteria.** The Phase 1 criteria apply (Appendix B of `docs/sota_broad_review.md`: venue
quality, period, retrievable full text, de-duplication). Two topical criteria were added:

- **T1:** the paper's main subject is a slow or low-rate L7 attack, a recurrent model for L7 DoS, or
  kernel/application-layer coupling.
- **T2:** the paper reports at least one of detection latency, FPR or CPU/memory cost.

**Read in full and excluded:**
- *Reed et al., Sensors 2024* (Guardian Node, slow DoS in IoT). Strong on two points: data synthesised in
  a live lab, and a two-attribute rule that beats ML. Both are made by L7-01 and L7-02 in a web-server
  setting closer to this one.
- *Dawadi et al., Sensors 2023* (LSTM web application firewall). Its DDoS model is trained on LOIC
  floods; the distinguishing features it reports (TTL, Don't-Fragment flag, protocol) are tool/OS
  artefacts of the kind §6 warns about. No slow attack is covered.
- *Brandner et al., arXiv 2026* (Beeline). eBPF fast path for service-mesh L7 policies with a proxy
  fallback. Architecturally analogous, but a preprint without a DoS evaluation.

**Shortlisted, not fetched:**
- Wu et al., arXiv 2026 (eBPF/XDP NIDS): a preprint.
- Pascoal et al., Computer Networks 2020 (slow DoS against SDN switch tables): outside the host/web
  setting.

**Coverage gaps.** These relevant papers failed only on retrieval and can be added if the PDFs are
supplied:

* Xie et al., *Int. J. Intelligent Systems* 2023, doi: 10.1155/2023/2632678: an explicit-duration
  recurrent network over application-layer protocol keywords and the time between them, with
  campus-network data. This is the closest SEQ paper found. It is CC BY 4.0, but the publisher answered
  the scripted download with HTTP 403 (`logs/fetch_20261028T124532Z.log`), and the block was not
  circumvented.
* Gogoi et al., IEEE INDICON 2022, "HTTP Low and Slow DoS Attack Detection using LSTM based deep
  learning" (paywalled).

**Finding for the SEQ pillar.** Among the 458 screened records, no retrievable peer-reviewed paper
applies a recurrent model *with a sequence length above one* to slow HTTP attacks. L7-04's RNN, LSTM and
GRU use sequence length 1. L7-01's sequence model is not neural. Published, open evidence that recurrent
models help against low-and-slow HTTP attacks is therefore thin. That is the gap the thesis's L7 GRU
entered, and its negative result (L2, L3) is a contribution to it.

**Verified copy versus version of record.**

| Paper | Copy verified | Relation to the cited version |
|---|---|---|
| L7-01 | arXiv v1 (31 Mar 2022) | Author version of the TDSC paper; wording and tables may differ |
| L7-02 | Research Square preprint v1 (posted 30 Dec 2022) | **Pre-review** version of the J. Supercomputing paper |
| L7-03, L7-04 | Europe PMC full text (JATS XML) of the MDPI article | Version of record; no page numbers, so locations are sections |
| L7-05 | arXiv v1 (27 Aug 2026) | Author version; the IJIS article is CC BY 4.0 |
| P-xx | As listed in §3 of `docs/sota_broad_review.md` | — |

---

## 4. Architectural Mapping Matrix

Rows are the components of the system as built (§1.1). ● = the paper supplies direct evidence or a method
for this component; ○ = indirect support (context, a measurement method or a caveat).

| Component | L7-01 | L7-02 | L7-03 | L7-04 | L7-05 | P2-01 | P2-02 | P2-04 | P3-01 | P3-04 | P4-01 | P4-02 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| XDP filter (`xdp_ddos_filter.c`) | | | | | ● | ● | ● | ○ | | | | |
| Python daemon: rules, `ban_ip`, map writes (`control_plane.py`) | ○ | ● | ○ | | ● | | ● | ● | | ● | | |
| Nginx monitor: timeouts, limits, logs (`nginx.conf`, log tails) | ● | ● | ● | | | | | | | | | |
| GRU detector: Tier-1 and L7 (`train_testbed_gru.py`, `ml/`) | ● | ○ | | ● | ○ | | | ● | ● | ● | ● | ○ |
| Testbed and evaluation (`test_distributed_suite.py`, `eval/`) | ● | ● | ● | ○ | ● | ● | ○ | ○ | | ● | ● | ● |

What each mapping says, per component:

* **XDP filter.**
  - *P2-01:* the same blacklist design; benchmark it with rule-count sweeps, not 5 bans.
  - *P2-02, L7-05:* a map write costs microseconds (≈4.5 µs measured; 5–20 µs in the review). The
    3.5–4.7 s slow-attack TTM is therefore detection, not enforcement.
  - *L7-05:* the eBPF security literature reports a 2.4% median CPU overhead. It is 81.4–87%
    testbed-only, which applies equally to this work.
* **Python daemon.**
  - *L7-02:* the closest published analogue of SlowConn (socket counts, log status codes, Python and
    psutil). It shows that a single count threshold is evadable (L4), and offers a multi-parameter vote
    as a deterministic upgrade.
  - *L7-05:* "hybrid ML architectures" pay 0.5–2 ms per kernel/user-space coordination, which is
    negligible at 1 s polls.
  - *P2-04:* escalate only uncertain flows from the fast path.
  - *P3-04:* the rules are the mandatory baseline.
* **Nginx monitor.**
  - *L7-03:* Nginx alone resisted Slowloris and Slow POST, and fell only to Slow Read and Slowcomm, at
    thousands of connections.
  - *L7-02:* an attacker whose inter-packet gap exceeds the server timeout holds sockets only part of the
    time. That is why the suite's R.U.D.Y. (7 s gap against a 5 s `client_body_timeout`) triggers the
    error-log rule, and why a tuned R.U.D.Y. would not.
  - *L7-01:* detection needs in-flight protocol events, which a completed-request access log cannot
    provide (R1).
* **GRU detector.**
  - *L7-01:* a sequence model of in-flight events, trained on benign traffic only, detects slow attacks
    the access-log GRU cannot see.
  - *L7-04, P3-01:* recurrent models lose to trees and CNNs on cost, and on accuracy once
    timestamp-like features are removed. This is published support for L1–L3.
  - *P2-04:* the published shape of the fast/slow split.
  - *P3-04, P4-01:* why public-dataset numbers do not transfer (§6).
* **Testbed and evaluation.**
  - *L7-03:* how many connections a slow attack needs to deny service to Nginx, and an outage-based
    success criterion.
  - *L7-01, L7-02:* the same detectors evaluated on live servers (the P9 remedy).
  - *L7-05:* the domain is mostly testbed-only.
  - *P4-02:* the testbed's multi-run statistics follow the survey's advice.

---

## 5. Paper profiles

### 5.1 New papers (targeted retrieval)

### L7-01: Delays Have Dangerous Ends: Slow HTTP/2 DoS Attacks Into the Wild and Their Real-Time Detection Using Event Sequence Analysis
- **Citation (IEEE Style)**: N. Tripathi, "Delays Have Dangerous Ends: Slow HTTP/2 DoS Attacks Into the Wild and Their Real-Time Detection Using Event Sequence Analysis," *IEEE Transactions on Dependable and Secure Computing*, vol. 21, no. 3, pp. 1244–1256, May 2024, doi: 10.1109/tdsc.2023.3276062.
- **Target Attack Vector & Threat Model**: Slow-rate DoS against HTTP/2. Five attacks send incomplete requests to occupy the server's connection queue, e.g. Attack-1 advertises a zero flow-control window. An Internet-wide measurement scanned the top 500K Alexa sites (about 71% support HTTP/2) and then attacked live HTTP/2 servers:
  - about 50% of servers kept an Attack-1 connection open for more than 360 s;
  - about 3% did so for Attack-3.
- **Defense Architecture & Technology Stack**: Anomaly detection on event sequences.
  - **Events:** deep packet inspection turns each HTTP/2 flow into a sequence of frame events (HEADERS with end-of-stream/end-of-headers flags, SETTINGS variants such as a zero initial window, WINDOW_UPDATE with zero or non-zero increment, GOAWAY, CONTINUATION, connection end, …).
  - **Learning phase:** builds a database of "lookahead pairs" (event[i] followed by event[j] within window n) and of maximum normal delays, from **benign traffic only**.
  - **Detection phase:** after every new event, a mismatch score (the fraction of the request's lookahead pairs absent from the database) is compared with a threshold θ, so a request can be flagged before it completes.
  - **Deployment:** a reverse TLS proxy (PolarProxy) forwards cleartext to an out-of-band "interceptor" host that runs detection.
- **Experimental Setup & Testbed**:
  - **Server:** an academic server (Apache 2.4.51, Ubuntu 20.04, Xeon E3, 64 GB) hosting quiz assignments. Students used it remotely during COVID-19, so the benign traffic is real.
  - **Learning data:** about 5 GB of HTTP/2 between 8 and 14 Oct 2021. 14,094 flows yielded 7,221 unique sequences, and 227/377/471/621/737 lookahead pairs for n = 3–7. New pairs stopped appearing after about 9,400 flows.
  - **Detection runs:** an Internet attacker sent a small number of Attack-1–5 requests at regular intervals, closing each after 100 s. Five intervals varied θ at n = 5, and four 8-hour intervals varied n. The interceptor was an AMD Ryzen 7 5800H.
- **Empirical Results & Benchmark Metrics**:
  - **θ = 0.01:** accuracy 98.55%, FPR 1.83%, recall 100%, precision 93.46%.
  - **θ = 0.02:** 98.65%, 1.71%, 100%, 93.83%.
  - **Larger θ:** recall falls to 74.71% at θ = 0.03 and 6.08% at θ = 0.05.
  - **Varying n (3–9):** accuracy stays at 98.35–98.89% with FPR 1.37–2.04%. Larger n costs extraction time.
  - **Latency:** all anomalous sequences were detected in under about 30 s.
  - **CPU:** below ≈7% most of the time, with peaks of ≈16% (1.5 h, sampled every 1 s with psutil).
  - **FPR unit:** FPR is per request flow; 1.71% of the 12,423 benign flows in that interval is about 212 flagged benign requests (derived here).
- **Verbatim Verification Quotes**:
  > "There are no publicly available dataset for clear-text HTTP/2 traffic (h2c) [24]. Thus, we created a testbed similar to the one shown in Figure 3 to capture clear-text normal HTTP/2 traffic during the learning phase and subsequently used it to build the lookahead pairs, and maximum delay databases"
  > *Location: §7.1 Learning Phase — PDF p. 8 of the verified copy*
  >
  > "We can notice from the figure that the detection scheme could detect all anomalous sequences in virtually less than 30 seconds."
  > *Location: §7.2.3 Detection latency and computational overhead — PDF p. 10 of the verified copy*
- **Applicability to My Implementation**:
  - **Shared premise.** The first quote is the thesis's own: no public dataset fits, so the traffic is generated in-house.
  - **Where the designs differ.** Tripathi learns *benign behaviour only*, from real users, and injects attacks only at detection time. The thesis's L7 GRU is supervised on scripted attack families, and its held-out `slowread` was missed (0/1). One-class training does not need the attacker's family in the training set.
  - **The signal R1 says is missing.** Tripathi scores *in-flight* events. Nginx's access log emits nothing until a request ends, which is why the access-log GRU is blind to slow attacks. The HTTP/1.1 analogue in this architecture is a per-connection event stream: handshake, first header bytes, gaps between reads, timeout, close. It could come from the `ss` snapshots the daemon already takes, or from the XDP `flow_map`.
  - **How much benign traffic is enough.** The saturation of new lookahead pairs (≈9,400 flows) is a principled stopping rule. A curve of new patterns per added benign session would answer that question for the testbed captures.
  - **Comparison of numbers.** Detection in under 30 s is slower than SlowConn's 3.5–4.7 s, and 1.7% FPR per request would be large in per-client terms. Compare like units (§6.3).
  - **Caveats.** HTTP/2 needs TLS interception, and the quotes come from the arXiv v1.

### L7-02: SlowTrack: Detecting Slow Rate Denial of Service Attacks against HTTP with Behavioral Parameters
- **Citation (IEEE Style)**: S. Sood and N. Hubballi, "SlowTrack: detecting slow rate Denial of Service attacks against HTTP with behavioral parameters," *The Journal of Supercomputing*, vol. 80, no. 2, pp. 1788–1817, Jan. 2024 (published online Jul. 2023), doi: 10.1007/s11227-023-05453-3.
- **Target Attack Vector & Threat Model**: Slowloris against Apache, via the Slowloris tool from a single attacker. Variants include 50–5,000 sockets, randomised user agents and a SOCKS5 proxy. The authors' premise is that per-IP or per-window connection-count rules are easy to evade.
- **Defense Architecture & Technology Stack**: Eight behavioural parameters are measured per window by Python scripts:
  - incomplete requests (scapy `AsyncSniffer`);
  - response time (a probe script on a designated client);
  - response messages;
  - context switches and inbound sockets on the web port (psutil);
  - 2xx and 4xx counts (regex over the server log);
  - the server's process count.

  Three detectors use them:
  - **Majority vote:** attack if incomplete requests exceed an upper threshold. When they lie between the lower and upper thresholds, attack if ≥5 of the other 7 parameters breach thresholds set at the attack-free average ±25%.
  - **Decision tree** and **association rules** (Weka; top 6 rules), hard-coded as if/else.
- **Experimental Setup & Testbed**:
  - **Experiment 1:** 4 VMs (Apache; response-time probe; Kali with Slowloris; JMeter for normal load), 10 h with attacks in hours 5–6 and 8–9, 15 s windows, thresholds from the first 4 h.
  - **Experiment 2:** a live university web server with the attacker on AWS, 48 h (24 h to set thresholds, then 24 h including 11:05:45 of attack).
  - **Further runs:** 84 h live with sockets swept from 50 to 5,000; a 5–60 s window sweep; a 1.5 h Nginx portability test.
- **Empirical Results & Benchmark Metrics**:
  - **Testbed (Experiment 1):** majority vote reached recall 100%, precision 99.79%, F1 99.89% (1,440 test windows).
  - **Live (Experiment 2):** majority vote 99.92 / 99.66 / 99.79%; decision tree 100 / 99.85 / 99.92%; association rules 99.62 / 99.70 / 99.66% (5,760 windows).
  - **Single threshold:** an incomplete-request threshold alone (72) loses nearly 10% recall against the majority vote, and the gap widens at 200.
  - **Window length:** detection rate exceeds 95% from a 15 s window.
  - **Evasion variants:** majority vote misclassified 6 of 1,600 windows with a random user agent.
  - **Nginx:** 3 of 240 test windows misclassified.
  - **Detection unit:** detection is per window and per server, not per source IP.
- **Verbatim Verification Quotes**:
  > "Simple detection methods which use x number of such connections in y time can be easily evaded."
  > *Location: Abstract — PDF p. 2 of the verified copy*
  >
  > "A sleeptime larger than 15 seconds (more than Apache server connection timeout period) will generate the attack only for a fraction of time at the beginning."
  > *Location: §4.5 Effect of Slowloris Attack Configuration Parameters — PDF p. 14 of the verified copy*
- **Applicability to My Implementation**:
  - **The closest published analogue of the daemon's slow path.** It uses the same inputs (socket table, server logs), the same language and the same polling design. The first quote and the ≈10% recall loss of a single threshold are the published form of L4 and of M7's "a client with 7 sockets passes the rule".
  - **A deterministic upgrade.** Without ML, a multi-signal vote could combine the SlowConn count, the error-log 408 rate, the Nginx active-connection count and the harness's response-time probe. It would detect a distributed slow attack that stays below the per-IP threshold. The cost is attribution: SlowTrack flags the server, while XDP needs source IPs, so per-source scoring stays necessary.
  - **The second quote explains the testbed.**
    - R.U.D.Y. sends one byte every 7 s against `client_body_timeout 5s`. Nginx times the connection out between reads, so the bots hold their sockets only part of the time, and those very timeouts are what the `l7_rudy` rule counts.
    - nginx documents `client_header_timeout` as a limit on transmitting the *entire* header, so Slowloris sockets also live at most 5 s.

    This matches `docs/REPORT.md` F-10 ("Nginx's own timeouts … neutralise both scenarios", marked [CLAIMED]) and EXP-B (legitimate clients unharmed while the attacks ran unbanned). A slow-attack claim needs attacks tuned *below* the timeouts, or a server at nginx's default 60 s.
  - **Evaluation and caveats.** Its 48 h live-server evaluation is the remedy for Arp's P9. Detection granularity is 15 s windows, slower than SlowConn. The quotes are from the **pre-review** Research Square preprint.

### L7-03: Generator of Slow Denial-of-Service Cyber Attacks
- **Citation (IEEE Style)**: M. Sikora, R. Fujdiak, K. Kuchar, E. Holasova, and J. Misurec, "Generator of Slow Denial-of-Service Cyber Attacks," *Sensors*, vol. 21, no. 16, p. 5473, Aug. 2021, doi: 10.3390/s21165473.
- **Target Attack Vector & Threat Model**: Eleven slow DoS attacks.
  - **HTTP/1.x:** Slowloris, Slow POST, Slow Read, SlowDrop, Slowcomm, Slow Next.
  - **HTTP/2:** Slow Read, Slow POST, Slow Preface, Slow Headers, Slow Settings.
  - Slowloris, Slow POST and Slow Read also have distributed variants, with bots simulated by ARP spoofing on a /8 subnet.
- **Defense Architecture & Technology Stack**:
  - **Generator:** an attack generator (Python ≥3.8 console application using requests, threading, sockets, hyper-h2, and iptables for SlowDrop). It re-establishes connections the server closes.
  - **Servers tested in default configurations:** Apache 2.4.17 and 2.4.29, Nginx 1.14.0, lighttpd 1.4.55 and IIS 10.0.
  - **Guidance:** a discussion section gives detection and mitigation advice per attack.
- **Experimental Setup & Testbed**: VMware virtual machines with a server subnet and a client subnet. One legitimate client requests a page every second, each over a new TCP connection. An attack counts as successful if that client sees a continuous outage longer than 6 s.
- **Empirical Results & Benchmark Metrics**:
  - **Successful attacks per server:** Apache 2.4.17 11 of 11; Apache 2.4.29 7 of 11; lighttpd 6 of 6 applicable; IIS 0 of 6 applicable; Nginx 1.14.0 2 of 11 (Slow Read and Slowcomm).
  - **Slow Read against Nginx:** about 1,900 of 2,500 attempted connections exhausted the server for the whole attack.
  - **Slowcomm against Nginx:** Nginx began closing connections at about 800, and interrupted the legitimate client in doing so.
  - **Slowloris and lighttpd:** a DoS at about 1,500 connections.
  - **A factual caveat:** the paper states that Nginx's `client_header_timeout` and `client_body_timeout` default to 5 s. The nginx documentation gives 60 s for both. The resistance it reports is attributed by the authors to Nginx's event-driven architecture.
- **Verbatim Verification Quotes**:
  > "Slowloris, Slow POST, and Slow Next attacks were ineffective against this web server due to the event-driven architecture of the web server."
  > *Location: §4.2.5 Other Attacks (Nginx) — Europe PMC full text, no page numbers*
  >
  > "Approximately 1900 connections were established, and then all the server resources were exhausted."
  > *Location: §4.2.1 Slow Read (Nginx) — Europe PMC full text, no page numbers*
- **Applicability to My Implementation**:
  - **Why Nginx survives the suite's slow scenarios.** The first quote is independent evidence for EXP-B. 5 bots × 8 (Slowloris) or × 10 (R.U.D.Y.) sockets is 40–50 connections, against roughly 1,900 needed for Slow Read to deny service to an unhardened Nginx.
  - **What M7 needs.** M7 needs the attack that actually works against Nginx: Slow Read, which keeps a tiny TCP receive window. The L7 track held `slowread` out of training and nothing caught it.
  - **Detection signal for Slow Read.** The paper's detection advice ("extremely small size of the TCP window", together with transfer rate and connection count) names a feature both XDP and `ss` can supply. `Init_Win_bytes_forward` is already a Tier-1 feature, but it only records the window at connection start.
  - **Availability metric.** The 6 s outage criterion is a concrete, citable availability threshold to set beside the harness's per-request availability and its 10 s client timeout.
  - **Caveat.** MDPI venue.

### L7-04: Transport and Application Layer DDoS Attacks Detection to IoT Devices by Using Machine Learning and Deep Learning Models
- **Citation (IEEE Style)**: J. G. Almaraz-Rivera, J. A. Perez-Diaz, and J. A. Cantoral-Ceballos, "Transport and Application Layer DDoS Attacks Detection to IoT Devices by Using Machine Learning and Deep Learning Models," *Sensors*, vol. 22, no. 9, p. 3367, Apr. 2022, doi: 10.3390/s22093367.
- **Target Attack Vector & Threat Model**: DoS and DDoS over HTTP (GoldenEye), TCP and UDP (hping3) in the Bot-IoT dataset, as Argus flow records. Two tasks: binary (normal vs attack) and multiclass (protocol).
- **Defense Architecture & Technology Stack**:
  - **Models:** SVM, Decision Tree and Random Forest (scikit-learn); RNN, LSTM, GRU and MLP (PyTorch). The recurrent models use 3 layers × 128 units with **sequence length 1**; 100 epochs, Adam.
  - **Feature sets:** (1) with timestamps and the Argus sequence number, (2) with neither, (3) with the sequence number only.
- **Experimental Setup & Testbed**:
  - **Data:** class-balanced Bot-IoT subsets, 9,085 normal flows, 36,340 samples in all.
  - **Throughput:** measured as flows per second on a MacBook Pro M1 (16 GB).
- **Empirical Results & Benchmark Metrics**:
  - **Feature set 1, multiclass:** RF 99.945%, DT 99.917%, LSTM/GRU/MLP 99.862%, RNN 99.807%, SVM 94.056%.
  - **Feature set 2 (no timestamps, no sequence number), multiclass:** RF 99.89%, DT 99.862%, MLP 96.34%, GRU 96.23%, LSTM 96.01%, RNN 95.019%, SVM 75.482%.
  - **Effect of removing timestamp-like features:** the GRU loses 3.6 pp, the decision tree 0.06 pp.
  - **Throughput (feature set 2, multiclass):** DT 30,362 flows/s, MLP 9,319, RNN 4,742, GRU 2,864, LSTM 2,702, RF 1,954, SVM 651.
- **Verbatim Verification Quotes**:
  > "The second feature set removed the timestamps because we argue that the model could memorize these features, which may lead to poor generalization in a real-time scenario."
  > *Location: §3 Methodology (feature sets) — Europe PMC full text, no page numbers*
  >
  > "From these results, it can be seen that Decision Tree and Random Forest have the best performance for both classification tasks in the three distinct feature sets, outperforming the DL models."
  > *Location: §4 Experimental Results and Discussion — Europe PMC full text, no page numbers*
- **Applicability to My Implementation**:
  - **Why this paper.** It is the retrievable SEQ representative. What it shows is narrower than its title suggests: with sequence length 1 its "recurrent" models see one flow at a time, so it tests the architectures, not sequence modelling.
  - **Support for L1–L3.** Its two robust findings are published support for the thesis's negative results:
    - On the same features, trees match or beat GRU and LSTM at about 10× the throughput.
    - The recurrent models depended more on timestamp-like artefacts: they lost 3.6 pp when those were removed, the tree 0.06 pp.
  - **The same pattern in this repository.** The XDP GRU's apparent R.U.D.Y. skill rested on request size (`docs/ML_INVESTIGATION.md`). The L7 track removed size features by rule and passed invariance probes before selection (`ml/train_l7.py`). Of Arp's ten pitfalls, this paper addresses P4 (spurious correlations) and the testbed design addresses P4 by construction; §6 gives the full mapping.
  - **Caveats.** Bot-IoT is a public, simulated dataset of the kind §6 argues against, and the venue is MDPI.

### L7-05: eBPF-Based Cybersecurity Mechanisms: A Systematic Literature Review
- **Citation (IEEE Style)**: S. Kostopoulos, P. Tsakonas, and E. K. Markakis, "eBPF-based cybersecurity mechanisms: a systematic literature review," *International Journal of Information Security*, vol. 25, no. 5, Art. no. 150, Aug. 2026, doi: 10.1007/s10207-026-01326-x. *(Survey.)*
- **Target Attack Vector & Threat Model**: eBPF-based security across seven domains: DDoS mitigation, intrusion detection, IoT, containers, microservices, networking, and tools. The DDoS domain includes application-layer resource exhaustion (Coda; FineLame).
- **Defense Architecture & Technology Stack**: A PRISMA review. 3,735 records from six databases yield 54 peer-reviewed primary studies (2018–2026). Results are synthesised into a taxonomy plus quality and limitation tables. The intrusion-detection section describes the split architecture used here: a kernel-side eBPF module filters packets, and a user-space module performs deeper analysis.
- **Experimental Setup & Testbed**: Literature synthesis; no experiments of its own.
- **Empirical Results & Benchmark Metrics**:
  - **Overhead and accuracy:** median overhead 2.4% of average CPU (range 1.1–8.6%; 10–20% on kernel hot paths); detection accuracy 94–99% across domains.
  - **Coordination cost:** 5–20 µs per eBPF map update, and 0.5–2 ms for hybrid ML architectures.
  - **Methodology gaps:** 85.1% of studies (46/54) need low-level programming expertise; 96.2% (52/54) ignore eBPF's own security; adversarial ML robustness is unaddressed in 100% of ML studies; verifier limits keep in-kernel ML to 2 of 11 ML studies.
  - **An inconsistency in the paper:** production validation is reported as missing in 81.4% (44/54) in one place and 87% (47/54) in another.
- **Verbatim Verification Quotes**:
  > "5-20µs per map update, 0.5-2ms for hybrid ML architectures"
  > *Location: §5.2 Limitations of eBPF in Security Applications — PDF p. 20 of the verified copy*
  >
  > "Studies use synthetic traffic generators and benchmark applications rather than production workloads."
  > *Location: §5.2 Limitations of eBPF in Security Applications — PDF p. 20 of the verified copy*
- **Applicability to My Implementation**:
  - **What it positions.** It places the thesis's design (XDP enforcement, user-space ML, maps as the only interface) within a literature where that split is the dominant pattern for ML-backed eBPF.
  - **Detection, not enforcement, sets the TTM.** The first quote, with P2-02's measured ≈4.5 µs, shows that the daemon's coordination cost is microseconds to milliseconds. The 3.5–4.7 s slow-attack TTM is therefore set by the 3-poll persistence rule, not by the kernel interface.
  - **Placing the testbed limitation.** The second quote, and the 81.4–87% testbed-only share, put the thesis's main external-validity limit in context rather than excusing it: it is the norm in the field, and it is the gap L7-01 and L7-02 close with live servers.
  - **An open item.** Adversarial robustness is unaddressed in every ML study the review covers. The thesis's own analogue is L4 (attackers tuned below thresholds).
  - **Caveat.** The quotes are from the arXiv v1.

### 5.2 Retained Phase 1 papers

The other schema fields of these papers (threat model, stack, testbed, metrics) are in
`docs/sota_broad_review.md`. They are not repeated here. Below: the citation, the two quotes (re-verified
against the Phase 1 corpus), and the applicability rewritten for the active architecture.

### P2-01: Performance Implications of Packet Filtering with Linux eBPF
- **Citation (IEEE Style)**: D. Scholz, D. Raumer, P. Emmerich, A. Kurtz, K. Lesiak, and G. Carle, "Performance Implications of Packet Filtering with Linux eBPF," in *Proc. 30th International Teletraffic Congress (ITC 30)*, Sep. 2018, pp. 209–217, doi: 10.1109/itc30.2018.00039.
- **Verbatim Verification Quotes**:
  > "XDP can process up to 7.2 Mpps in the case of 90 % packets dropped, a 28 % performance loss compared to the basic drop example."
  > *Location: §V.B.2 Maximum Processing Rate — PDF p. 4 of the verified copy*
  >
  > "XDP offers a tradeoff. While performance is not as good as dedicated high-performance frameworks that bypass the kernel, it offers flexibility."
  > *Location: §V.C Discussion — PDF p. 6 of the verified copy*
- **Applicability to My Implementation**:
  - **The fast path's reference.** `xdp_ddos_filter.c` implements the same source-IP blacklist the paper benchmarks.
  - **What M2 still needs.** EXP-A's TTM difference (0.215 vs 0.290 s) measures mostly the daemon, not the filter. A fair M2 test sweeps the number of banned sources into the thousands, includes ipset as a baseline, and reports Mpps at the drop point on one pinned core, all on veth.
  - **What the slow path does not need.** Slow attacks send almost no packets, so the fast path's throughput is not what limits them. There, the ban path's value is `ss -K` freeing the held sockets, plus XDP dropping the bot's reconnection attempts.

### P2-02: Mitigating IoT Botnet DDoS Attacks through MUD and eBPF based Traffic Filtering
- **Citation (IEEE Style)**: A. Feraudo, D. A. Popescu, P. Yadav, R. Mortier, and P. Bellavista, "Mitigating IoT Botnet DDoS Attacks through MUD and eBPF based Traffic Filtering," in *Proc. 25th International Conference on Distributed Computing and Networking (ICDCN '24)*, Jan. 2024, pp. 164–173, doi: 10.1145/3631461.3631549.
- **Verbatim Verification Quotes**:
  > "The transaction rate is 2714 transactions/s for baseline, 2892.51 transactions/s with iptables, and 2915.91 transactions/s with eBPF-IoT-MUD."
  > *Location: §V.B Rule management via eBPF — PDF p. 7 of the verified copy*
  >
  > "For eBPF-IoT-MUD, when the rate-limit is reached, the firewall starts dropping the incoming packets."
  > *Location: §V.D Rate limiting impact on abnormal traffic — PDF p. 8 of the verified copy*
- **Applicability to My Implementation**:
  - **Enforcement is not the bottleneck.** A map write takes about 4.5 µs (with L7-05: 5–20 µs). Every second of the slow-path TTM is therefore detection; the thesis can report detection time and enforcement time separately.
  - **Calibrating thresholds.** The paper's average- versus peak-based calibration result is the collateral-damage half of L4. Thresholds such as SlowConn's 8 sockets and `l7_rate`'s 50 rps should be set from high quantiles of benign behaviour, which is what the tolerant profile tried (×1.3 the simulated benign worst case).
  - **The cost of tolerance.** EXP-B measured that cost: both slow scenarios went unbanned.
  - **Caveat.** The quotes are from arXiv v1.

### P2-04: Collaborative P4-SDN DDoS Detection and Mitigation with Early-Exit Neural Networks
- **Citation (IEEE Style)**: O. Karrakchou, A. Zniber, A. Sebbar, and M. Ghogho, "Collaborative P4-SDN DDoS Detection and Mitigation with Early-Exit Neural Networks," in *Proc. 2025 IEEE Global Communications Conference (GLOBECOM)*, Dec. 2025, pp. 6081–6086, doi: 10.1109/globecom59602.2025.11431920.
- **Verbatim Verification Quotes**:
  > "the CNN frontend and intermediate classifier are quantized and implemented in P4 using integer arithmetic, allowing them to operate at line rate, while the GRU backend is hosted in the SDN controller."
  > *Location: §I Introduction — PDF p. 2 of the verified copy*
  >
  > "All network links are configured with a bandwidth of 1.5 Mbps and a propagation delay of 10 ms."
  > *Location: §IV.B Network-Level Evaluation in NS-3 Simulation — PDF p. 5 of the verified copy*
- **Applicability to My Implementation**:
  - **The closest published design.** A cheap data-plane stage plus a GRU in the control plane is the hybrid's published template. The Tier-1 GRU follows the paper's first principle (train only on features the data plane computes at runtime: `flow_map`, captured in the testbed).
  - **The second principle, not yet adopted.** Escalate only *uncertain* flows to the slow path. The daemon runs rules and GRU in parallel rather than in a cascade, which is why the GRU could never ban first (L1).
  - **Caveat.** The second quote: the evidence is a 1.5 Mbps simulation, so it does not contradict the testbed's negative result.

### P3-01: LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection
- **Citation (IEEE Style)**: R. Doriguzzi-Corin, S. Millar, S. Scott-Hayward, J. Martínez-del-Rincón, and D. Siracusa, "Lucid: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection," *IEEE Transactions on Network and Service Management*, vol. 17, no. 2, pp. 876–889, Jun. 2020, doi: 10.1109/tnsm.2020.2971776.
- **Verbatim Verification Quotes**:
  > "we can estimate that the maximum number of packets per second (pps) that the device can process without the GPU and using a batch size of 1024 samples is approximately 1.9 Mpps."
  > *Location: §VII.A Detection (edge use case) — PDF p. 12 of the verified copy*
  >
  > "We acknowledge that the speed of this process will influence the overall system performance. However, as we have not focused on optimising our preprocessing tool, rather on optimising detection, its evaluation is left as future work."
  > *Location: §VII.A Detection (edge use case) — PDF p. 12 of the verified copy*
- **Applicability to My Implementation**:
  - **The non-recurrent baseline.** LUCID's time-windowed per-flow arrays are the same input shape as the Tier-1 GRU's 15-poll snapshots and the L7 GRU's 20-request windows. Its CNN matched an LSTM's F1 at over 40× the throughput. With L7-04 and the order ablation (L3), that is the case for a CNN or tabular baseline. The open-source code makes it cheap to run.
  - **Measurement scope.** The second quote warns that LUCID's throughput excludes feature extraction. The thesis's TTM includes it (log parsing, `ss` polling), so the two numbers are not comparable.

### P3-04: Dos and Don'ts of Machine Learning in Computer Security
- **Citation (IEEE Style)**: D. Arp et al., "Dos and Don'ts of Machine Learning in Computer Security," in *Proc. 31st USENIX Security Symposium (USENIX Security 22)*, Aug. 2022, pp. 3971–3988. [Online]. Available: https://www.usenix.org/conference/usenixsecurity22/presentation/arp
- **Verbatim Verification Quotes**:
  > "The most prevalent pitfalls are sampling bias (P1) and data snooping (P3), which are at least partly present in 90 % and 73 % of the papers, respectively."
  > *Location: §3 Prevalence Analysis — PDF p. 8 of the verified copy*
  >
  > "In the Mirai dataset the infection is overly conspicuous; an attack in the wild would likely be represented by a tiny proportion of network traffic."
  > *Location: §4.4 Network Intrusion Detection — PDF p. 13 of the verified copy*
- **Applicability to My Implementation**:
  - **Reframed for the active architecture.** Arp et al. show how public, lab-built datasets let models score well for the wrong reasons. Training on the project's own testbed traffic removes several of those reasons by construction. It also makes the remaining ones *testable*, because the generator, labels and splits are under the author's control. §6.2 goes pitfall by pitfall.
  - **The second quote applies to the testbed too.** Its attacks are conspicuous by design (5–10 bots against 20 clients). Results therefore have to be read per client and per hour, not as accuracy over windows.

### P4-01: Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study
- **Citation (IEEE Style)**: M. Cantone, C. Marrocco, and A. Bria, "Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study," *IEEE Access*, vol. 12, pp. 144489–144508, 2024, doi: 10.1109/access.2024.3472907.
- **Verbatim Verification Quotes**:
  > "Compared to the experiments employing the original feature set, also in this case within-dataset experiments achieved significantly better performance with respect to cross-dataset experiments with an average MCC of 83.86% and 14.91%, respectively."
  > *Location: §4.3 Feature selection — PDF p. 12 of the verified copy*
  >
  > "We found that training a ML model on a single publicly available dataset is not sufficient to create a robust NIDS capable of working in different datasets and real-world applications."
  > *Location: §5 Conclusions — PDF p. 15 of the verified copy*
- **Applicability to My Implementation**:
  - **Reframed.** This is the quantitative reason the project trains on its own runtime traffic. Models trained on CIC-IDS2017/2018, including their Slowloris and Slowhttptest classes, drop from about 84% to about 15% MCC when moved to another dataset. The paper traces this to dataset-specific constants (one feature can carry 69.7% MCC). A detector trained on a public dataset would meet the testbed's traffic as a new dataset.
  - **The same mechanism at small scale.** The repo's own audits found it inside the testbed: request size alone reproduced the Tier-1 GRU's F1 (0.994 vs 0.996, `docs/REPORT.md` §1).
  - **The lesson for the thesis.** Owning the data does not remove dataset artefacts. It lets the author find and remove them, as the L7 track did with the size features.
  - **Caveat.** The quotes are from arXiv v1.

### P4-02: Network Intrusion Datasets: A Survey, Limitations, and Recommendations
- **Citation (IEEE Style)**: P. Goldschmidt and D. Chudá, "Network intrusion datasets: A survey, limitations, and recommendations," *Computers & Security*, vol. 156, p. 104510, Sep. 2025, doi: 10.1016/j.cose.2025.104510. *(Survey.)*
- **Verbatim Verification Quotes**:
  > "While CIC-IDS2017 emerged as the most popular, its utilization only in 29% of papers brings it far from being a "standardized" benchmark in the domain."
  > *Location: §5.4 Dataset Popularity — PDF p. 23 of the verified copy*
  >
  > "Since their data come from different networks and time periods, their traffic patterns will likely differ. Therefore, combining datasets is incorrect by design since bias would likely be introduced."
  > *Location: §6.3 Using a Dataset — PDF p. 30 of the verified copy*
- **Applicability to My Implementation**:
  - **Reframed.** The active pipeline follows the survey's central rule: benign and attack traffic come from the same environment and the same runs, so there is no cross-source bias to introduce.
  - **The rest of its advice the repo already follows:** several runs and seeds with significance tests (`eval/run_level_stats.py`, five seeds in P5c.4); IP- and family-disjoint splits; published manifests per campaign.
  - **One open item.** "Only one dataset in five contains real traffic." The testbed's traffic is scripted, and that limit stays (§6.3).
  - **Writing aid.** Its dataset-creation checklist (objective, scenario design, labelling, validation, publication) can structure the thesis's description of the captures.

---

## 6. Academic Defense Formulation

### 6.1 The claim the evidence supports

> *Training the slow-path detectors on traffic generated and labelled inside the project's own testbed
> avoids the cross-dataset and labelling pitfalls documented for public intrusion datasets
> [Cantone et al.; Goldschmidt & Chudá]. Because the generator, labels and splits are under the author's
> control, it also makes the remaining pitfalls of learning-based security [Arp et al.] measurable. Under
> those controls neither GRU added detection value over deterministic rules in this testbed (L1–L3), and
> low-and-slow attacks were handled, within the tested range, by the connection-state rule and Nginx's
> timeouts, not by the GRU (M7, R1).*

This formulation defends the *design decision* (testbed-native training) and reports the *outcome*
honestly. A claim that the GRU detects and mitigates Slowloris or R.U.D.Y. is not defensible from this
repository; §1.4 gives the evidence.

### 6.2 Pitfall by pitfall

| Pitfall (Arp et al. / Goldschmidt & Chudá) | How testbed-native training addresses it | Evidence in the repo | What remains open |
|---|---|---|---|
| **Combining datasets from different sources** (P4-02: "incorrect by design") | Benign and attack traffic are captured in the same runs, network and server | `capture_testbed_dataset.py`; `ml/l7_traffic.py` manifests | — |
| **Cross-dataset collapse** (P4-01: MCC 83.86% → 14.91%) | Train and serve on the same feature extractor and environment, with no transfer step | Tier-1 trained on `flow_map` fields; L7 on `l7json` fields | Transfer to a *real* server is untested (P9) |
| **P2 Label inaccuracy** (CIC-IDS2017 errors, P4-02) | Labels come from the generator's schedule (bot IP, family), not from post-hoc rules | `ATTACK_FAMILY` in `train_testbed_gru.py`; L7 manifests | Collateral traffic inside an attack window still carries the attack label |
| **P1 Sampling bias** | Benign roles (browsers, API clients, CGNAT pools) and netem profiles are designed to cover benign variety | `ml/l7_traffic.py`; netem profiles in the suite | Benign is scripted. Attackers ran without netem while benign clients had it: a confound the GRU exploited (flagged a browser exactly when its profile was `perfect`, L2) |
| **P3 Data snooping** | IP-disjoint benign splits; family-disjoint held-out attacks; pre-registered selection and verdict rules | `ml/train_l7.py:11-15, :406`; `docs/L7_GRU_DESIGN.md` §7.2 | Trained attack families are not IP-disjoint (in-distribution recall only); sliding windows overlap |
| **P4 Spurious correlations** | Invariance probes as a hard gate; feature ablations | Size shortcut found and removed (P4: 1/8 → 7/8 held-out groups); R.U.D.Y. detection rode on request size (19–29% → 100%) | Probes cover the artefacts someone thought of. Tool and TCP-stack fingerprints were found only after training (L1) |
| **P5 Biased parameter selection** | Pre-registered selection rule and verdict | `ml/p5b_report.py` written before the runs | Baselines tuned on evaluation runs (oracle), which favours the baselines (L2 scope note) |
| **P6 Inappropriate baseline** | Deterministic rules and a tabular HGB trained under the identical split and policy | Per-(IP, UA) sustained-rate rules and the HGB baseline (B4) in P5c.4 | The baselines won; that is the result |
| **P7 Inappropriate performance measures** | Per-client false positives per hour, a benign-IP budget (5%), availability and TTM rather than window accuracy | `docs/EVALUATION.md`; P5c.4 report | Window-level F1 (0.9963) is still in `training_results/` and must not be quoted as performance |
| **P8 Base-rate fallacy** | Rates reported per client-hour in a soak, against a pre-set budget | P5c.4 soak: the GRU made 1.8 FP per client-hour against a budget of 1.0 | The testbed's attacker share (20 attacker IPs against 100 benign across five seeds) is far above any real base rate |
| **P9 Lab-only evaluation** | — | — | **Open.** The whole evaluation is in network namespaces. L7-01 and L7-02 evaluated on live servers; L7-05 finds 81.4–87% of eBPF security work testbed-only |
| **P10 Inappropriate threat model** | Held-out families and intensities; an evasion budget (tolerant profile) | EXP-B | Adaptive slow attackers below the thresholds (7 sockets; gaps under 5 s) were not tested (M7) |
| **"Once? not enough"** (P4-02: several runs, significance tests) | Paired blocks, t-intervals, sign-flip tests, five seeds | `eval/run_level_stats.py`; EXP-A (10 blocks) | — |

### 6.3 Where the defense stops

1. **Owning the data moves the shortcut problem; it does not remove it.** The testbed produced its own
   artefacts: request size, tool and TCP-stack fingerprints, and the netem-profile confound. The defense
   is that these were *found*, because the data were controllable. P4-01 (CIC Slowloris constants) and
   L7-04 (timestamps) document the public-data versions of the same mechanism.
2. **The slow-attack threat model is narrower than the premise.**
   - The suite's Slowloris and R.U.D.Y. use 40–50 connections in total, and gaps at or above Nginx's 5 s
     timeouts.
   - L7-03 needed about 1,900 connections for Slow Read to deny service to an unhardened Nginx.
   - L7-02 shows that a gap above the server timeout disables the attack for most of its run.
   - The suite's slow scenarios therefore test whether the *rules fire*, not whether a *harmful* slow
     attack is stopped (EXP-B: legitimate clients unharmed while unbanned).
3. **Units must match before any comparison.** L7-01 reports FPR per request flow. L7-02 reports
   precision per 15 s server window. The thesis reports false bans per client and per client-hour. None
   of these can be compared directly.
4. **The access-log GRU cannot see in-flight connections (R1).** This is a property of the input, not of
   the model. L7-01 shows what a detector with in-flight events can do.

### 6.4 What would make the low-and-slow premise true

These are proposals grounded in the papers above. None of them was run in this phase.

* **Give the slow path in-flight inputs.** Per-connection event sequences from the `ss` snapshots the
  daemon already takes (bytes read, idle time, header-complete flag, receive window) or from `flow_map`.
  Either a one-class model learned from benign sessions only (L7-01's design; stopping rule:
  new-pattern saturation) or a small CNN or tabular model (P3-01, L7-04) scores them.
* **Test harmful slow attacks.** Inter-packet gaps below `client_body_timeout`; header trickles that stay
  within `client_header_timeout`, or the nginx default 60 s; Slow Read with a tiny receive window; and
  socket counts swept through and below SlowConn's 8 per bot, up to the hundreds or thousands L7-03
  needed. Success is defined as an outage longer than 6 s for a polling client (L7-03) next to the
  existing availability metric.
* **Add a server-level vote.** L7-02's multi-parameter majority vote, built from signals already
  available (SlowConn counts, error-log 408 rate, active connections, probe latency), with per-source
  attribution kept for XDP bans.
* **Close P9 partly.** One campaign against a server outside the namespaces, or replayed real benign
  traffic, would move the evaluation from "testbed-only" toward L7-01 and L7-02's standard.

---

## Appendix A. Reproduction

```bash
python3 docs/sota/fetch_sota.py --profile docs/sota/profile_l7.json --corpus docs/sota/corpus_l7 search
python3 docs/sota/fetch_sota.py --corpus docs/sota/corpus_l7 fetch
python3 docs/sota/fetch_sota.py --corpus docs/sota/corpus_l7 verify --review docs/targeted_literature_selection.md --with-corpus docs/sota/corpus
```

`fetch` reads `corpus_l7/selected.json`. Downloaded PDFs, JATS XML and extracted text are not committed
(`corpus_l7/.gitignore`). Their SHA-256 hashes are in `corpus_l7/manifest.json`, so a re-download can be
checked against the verified copy. The search results depend on what the open APIs return on the day.
