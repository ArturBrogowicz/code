# State-of-the-Art Review — Defences Against DDoS Attack Techniques (Phase 1)

Thesis: *Badanie skuteczności i implementacja rozwiązań w obronie przed różnymi technikami ataków DDoS*
("Evaluating the Effectiveness and Implementation of Defense Solutions Against Various DDoS Attack Techniques").

> **Status (2026-10-28): 16 papers included, 32 verbatim quotes, all verified.**
> Every quote below was found in the downloaded text of its paper by `docs/sota/fetch_sota.py verify`
> (0 failures; the run is in `docs/sota/corpus/logs/`). Every citation was resolved by Crossref or by
> the publisher's page. Every number in the *Empirical Results* fields comes from the stored text.
> Where the downloadable copy is a preprint rather than the publisher's version, the entry says so.
> Retrieval limits and the coverage gaps they cause are in §3.

---

## 1. Summary table

| Paper ID | Authors & Year | Attack Vector | Defense Tech | Key Metric |
|---|---|---|---|---|
| P1-01 | Bock et al., 2021 | TCP reflected amplification via middleboxes | Attack study: Geneva GA + modified ZMap; host/middlebox countermeasures | 386,187 IPs amplify ≥100×; some >700,000× or unbounded |
| P1-02 | Nawrocki et al., 2021 | DNS reflection-amplification | Passive IXP detection (sFlow 1:16k, two thresholds) | 96% of IXP-seen attacks invisible to honeypots |
| P1-03 | Nawrocki et al., 2021 | QUIC handshake (state-exhaustion) floods | Network-telescope backscatter + NGINX lab test (RETRY) | NGINX, 4 workers: 7% of requests answered at 1,000 pps |
| P1-04 | Hiesgen et al., 2024 | Direct-path vs reflection-amplification trends | 10-dataset longitudinal comparison (telescopes, honeypots, IXP, industry) | 4 of 5 direct-path observatories trend upward 2019–2023 |
| P2-01 | Scholz et al., 2018 | Generic floods / spoofed traffic at the host | XDP source-IP blacklist vs iptables/nftables | XDP 7.2 Mpps/core vs ≤1.5 Mpps netfilter (~10×) |
| P2-02 | Feraudo et al., 2024 | IoT-botnet SYN flood (egress) | MUD rules enforced by XDP/eBPF maps vs iptables | eBPF map update ≈4.5 µs; average-based limits drop >80% of a smart hub's benign traffic |
| P2-03 | Liu et al., 2021 | Volumetric (SYN, ICMP, UDP, DNS/NTP amplification), dynamic | P4/Tofino switch-native detection + mitigation | 380 Gbps mitigated; reaction ≤15 s; FP/FN ≤0.073 |
| P2-04 | Karrakchou et al., 2025 | 12 CIC-DDoS2019 vectors + SYN flood | P4 INT8 CNN early exit + SDN-controller GRU | F1 99.91/99.90 (NS-3, 1.5 Mbps links) |
| P2-05 | Rizvi et al., 2022 | Volumetric & polymorphic floods on anycast services | BGP playbook: prepending, communities, poisoning | Catchment shift 69%→33%; changes ≥5 min apart |
| P3-01 | Doriguzzi-Corin et al., 2020 | HTTP/IRC-botnet DDoS (ISCX2012, CIC2017, CSE-CIC2018) | Lightweight CNN on time-windowed flow arrays | >55,000 samples/s, 40× faster than LSTM at equal F1 |
| P3-02 | Ding et al., 2022 | Volumetric (Booter) & internal-botnet DDoS | Normalised-entropy detection in P4 (integer log/exp) | FPR 8%; TPR 36% when attack is 5% of traffic |
| P3-03 | Panggabean et al., 2024 | DoS/DDoS (Bot-IoT) vs normal (UNSW) | GRU(64,32) + Neural Turing Machine | 99% accuracy, 0 errors on random split; no real-time test |
| P3-04 | Arp et al., 2022 | ML in security (NIDS case: Mirai) | Pitfall taxonomy; Kitsune vs packet-rate IQR baseline | Baseline TPR 0.996 vs 0.882 at FPR 0.001 |
| P4-01 | Cantone et al., 2024 | CIC-IDS2017/2018 attacks incl. Slowloris, Hulk, LOIC | LDA, DT, RF, XGBoost; within- vs cross-dataset | MCC 83.86% within vs 14.91% cross-dataset |
| P4-02 | Goldschmidt & Chudá, 2025 | DoS in 74% of 89 NIDS datasets | Dataset SLR + usage recommendations | CIC-IDS2017 used by only 29% of top-tier papers |
| P4-03 | Emmerich et al., 2015 | Any flood (scriptable generator) | DPDK + LuaJIT; NIC timestamping and rate control | 14.88 Mpps/core; 178.5 Mpps at 120 Gbit/s |

## 2. Review questions

| RQ | Pillar | Question | Thesis point it informs (`docs/THESIS_CLAIMS.md`) |
|---|---|---|---|
| RQ1 | P1 | Which volumetric, state-exhaustion and application-layer techniques dominate in 2021–2026, and which of their properties (rate, spoofing, per-connection state, request asymmetry) set the requirements for a defence? | Choice of the 10 testbed scenarios; M7 (slow attacks are not mitigated) |
| RQ2 | P2 | Where can mitigation sit (upstream/edge, SDN controller, programmable switch, host kernel via eBPF/XDP), and what does each placement cost in throughput, latency and collateral damage? | M2 (XDP versus iptables); M4 (rate limiting alone); M6 (time to mitigate) |
| RQ3 | P3 | Which detection methods reach which accuracy and false-positive rate at which inference cost, and how well do dataset results transfer to live traffic? | L1–L3 (the GRU adds no detection value); L4 (static-threshold dilemma) |
| RQ4 | P4 | How do credible evaluations build testbeds, generate traffic, choose datasets and report metrics? | Q1 (reproducibility); availability metric and power (`docs/REPORT.md` §6, §8) |

## 3. Method, screening and coverage

**Sources actually used.** arXiv (search, title lookup, PDFs), Crossref (search, metadata, open
licences) and publishers' open-access pages (usenix.org; the TUM group page for P2-01). OpenAlex
refused every request: the keyless daily budget shared by this network was exhausted, and a key
needs an e-mail address, which was not sent. Semantic Scholar answered HTTP 429 to every request.
dblp is behind an anti-bot challenge. dl.acm.org (Cloudflare) and IEEE Xplore (bot check) refuse
scripted downloads, including of their CC-BY papers. None of these protections was bypassed.

**Flow (PRISMA-style).**

| Step | Count | Where |
|---|---|---|
| Records returned by 50 keyword queries (arXiv 225, Crossref 1,244), plus the matches of 24 resolved seeds | 1,469 + seeds | `corpus/logs/search_20261028T103454Z.log` |
| Unique records after merging by DOI, arXiv id and title | 1,214 | `corpus/candidates.json` |
| Title screening against I1–E2 (Appendix B), then full-text availability probed (I4) | 152 | "Coverage gaps" below |
| Included | 16 (P1 4, P2 5, P3 4, P4 3) | `corpus/selected.json` (one reason per paper) |

The protocol changed twice, both times during this session and both recorded in the retrieval log:
Crossref was added as a search source when OpenAlex and Semantic Scholar refused service, and 17
targeted queries were added after the first screening found no retrievable papers on
application-layer floods, SYN-flood defence or dataset quality.

**Exemptions from I1 (2021–2026).** P2-01 (2018) and P4-03 (2015) are foundational: the testbed's
XDP blacklist design and its traffic-generation problem. P3-01 (2020, 378 citations) is a landmark
just outside the window.

**Verified copy versus version of record.** Quotes are checked against the copy that could be
downloaded:

| Paper | Copy verified | Relation to the cited version |
|---|---|---|
| P1-01, P2-03, P2-05, P3-04 | USENIX open-access PDF | Version of record |
| P2-01 | Authors' copy from the TUM publication page | Same paper; publisher pagination differs |
| P1-02, P1-03, P1-04 | arXiv (stated by the authors as the IMC paper) | Author version |
| P3-01, P3-02, P3-03, P2-04, P4-02, P4-03 | arXiv author version | May differ from the version of record in wording |
| P2-02 | arXiv v1, "in review, May 2023" | Precedes the ICDCN 2024 version |
| P4-01 | arXiv v1, titled *On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection*, submitted to JISA | arXiv links it to the IEEE Access DOI; the published text may differ |

**Coverage gaps (honest limits of this review).** The screening found relevant, top-tier papers
that fail only I4 (no downloadable full text from this environment). They are in
`corpus/candidates.json` with Crossref metadata, and can be added if you supply the PDFs (library
access):

* *Application-layer and slow attacks (P1)*: N. Tripathi and N. Hubballi, ACM Computing Surveys 2021
  (survey); Rios et al., ACM SAC 2024 (Slowloris, ML); Sood et al., J. Supercomputing 2023
  (SlowTrack); Kapourchali et al., Cluster Computing 2024 (P4httpGuard); Ramírez-Martínez et al.,
  Computer Networks 2025 (P4, Slowloris); Ming et al., IEEE Access 2024 (HTTP/2). **No included paper
  studies HTTP floods, Slowloris, R.U.D.Y. or HTTP/2 Rapid Reset as its main subject.** P1-04
  reports industry observations of rising L7 attacks; P1-03 covers handshake-state exhaustion; P4-01
  reports Slowloris/Slowhttptest classes in CIC data.
* *Upstream scrubbing, blackholing and FlowSpec (P2)*: Wagner et al., ACM CCS 2021 (CC BY);
  Wichtlhuber et al., ACM SIGCOMM 2022.
* *SDN/OpenFlow controller defence (P2)*: Ravi et al., IEEE TNSM 2021 (AEGIS, SYN floods on the
  controller). P2-04 covers SDN only as P4 + controller.
* *Datasets (P4)*: Sharafaldin et al., ICCST 2019 (CIC-DDoS2019); Engelen et al., IEEE SPW 2021 and
  Liu et al., IEEE CNS 2022 (CIC-IDS2017 errors); Moustafa, Sustainable Cities and Society 2021
  (TON_IoT).
* *XDP itself*: Høiland-Jørgensen et al., ACM CoNEXT 2018 (CC BY-SA). P2-01 benchmarks XDP instead.

---

## Pillar 1 — Modern Attack Vectors & Dynamics

### P1-01: Weaponizing Middleboxes for TCP Reflected Amplification
- **Citation (IEEE Style)**: K. Bock, A. Alaraj, Y. Fax, K. Hurley, E. Wustrow, and D. Levin, "Weaponizing Middleboxes for TCP Reflected Amplification," in *Proc. 30th USENIX Security Symposium (USENIX Security 21)*, Aug. 2021, pp. 3345–3361. [Online]. Available: https://www.usenix.org/conference/usenixsecurity21/presentation/bock
- **Target Attack Vector & Threat Model**: Volumetric reflected amplification over TCP. The attacker spoofs the victim's address and sends short TCP packet sequences (e.g. a SYN followed by a PSH+ACK carrying an HTTP GET for a censored URL) towards hosts whose path crosses a non-compliant middlebox (national censors, corporate firewalls). The middlebox injects block pages or RSTs without having seen a valid handshake. Two "infinite" variants: routing loops, and *victim-sustained* amplification, in which the victim's own RSTs re-trigger the middlebox.
- **Defense Architecture & Technology Stack**: An attack-discovery study. The Geneva genetic algorithm is trained on live censoring middleboxes (209 destinations from Censored Planet's Quack data of 28 March 2020). ZMap gets a custom probe module that sends multi-packet probes. Countermeasures are proposed for middleboxes (inject only after seeing both directions, keep injected responses small, censor only in-network requests) and for end hosts (drop outbound RSTs probabilistically).
- **Experimental Setup & Testbed**: Repeated IPv4-wide ZMap scans with 5 discovered packet sequences. The authors estimate that scanning each of Quack's 1,052 trigger URLs would take over 6 weeks at 1 Gbps per strategy, so they scanned a minimal covering URL set instead. TTL-limited traceroutes towards the top million amplifiers check that the responses come from middleboxes on the path.
- **Empirical Results & Benchmark Metrics**: 386,187 IPv4 addresses amplify by ≥100×. 97,079 exceed NTP's 556.9×, and over 192 exceed Memcached's 51,000×. Across all scans, over 200 million addresses amplify from 1× to over 700,000×. Block-page duplication raises some middleboxes to 301×, and some hosts amplify without bound. As an attack paper, it reports no mitigation time or throughput.
- **Verbatim Verification Quotes**:
  > "We find 386,187 IP addresses that yield an amplification factor of at least 100×; 97,079 IP addresses that elicit a larger amplification factor than the infamous NTP attack [32], and over 192 IP addresses that responded with a higher amplification factor than Memcached [8]."
  > *Location: §1 Introduction — PDF p. 3 of the verified copy*
  >
  > "Hosts that drop outbound RST packets are more susceptible to TCP handshake-based attacks, but hosts that do not are susceptible to sustaining a packet storm from a victim-sustained amplifier."
  > *Location: §9.2 End Hosts — PDF p. 15 of the verified copy*
- **Applicability to My Implementation**: The testbed's bots send from their own namespace addresses, so the XDP source-IP blacklist works by construction. Under reflected TCP amplification the sources the victim sees are the reflectors, i.e. third-party middleboxes. A per-source ban would then block infrastructure while the attacker stays hidden, and the thesis should state this boundary of claim M1. A lab version needs no Internet scanning: add a namespace "middlebox" that injects a large HTTP block page when it sees a spoofed GET for a forbidden URL. Then compare per-IP bans with an XDP rule that drops inbound TCP segments matching no local connection, which needs a connection-state BPF map. The paper's end-host advice (probabilistic dropping of outbound RSTs) is a server-side setting the testbed could measure.

### P1-02: The Far Side of DNS Amplification: Tracing the DDoS Attack Ecosystem from the Internet Core
- **Citation (IEEE Style)**: M. Nawrocki, M. Jonker, T. C. Schmidt, and M. Wählisch, "The far side of DNS amplification: tracing the DDoS attack ecosystem from the internet core," in *Proc. 21st ACM Internet Measurement Conference (IMC '21)*, Nov. 2021, pp. 419–434, doi: 10.1145/3487552.3487835.
- **Target Attack Vector & Threat Model**: DNS reflection-amplification over UDP. Spoofed queries go to open resolvers and forwarders for a small set of "misused" names, including DNSSEC-signed .gov names whose double-signature key rollovers inflate responses. Attackers rotate reflectors quickly, and one entity dominates.
- **Defense Architecture & Technology Stack**: Passive detection at an Internet Exchange Point from sampled traffic. A (client IP, day) pair counts as under attack if misused names make up over 90% of its DNS traffic and it has at least 10 sampled packets. Protocol parsing uses tshark. Results are correlated with a honeypot platform, open-resolver scans, DNS measurement data and a cache-snooping analysis.
- **Experimental Setup & Testbed**: A large regional European IXP (over 100 members, 600 Gbps peaks), observed 2019-06-01 to 2019-08-31. Sampling is 1:16k with packets truncated to 128 bytes, giving 33 million sampled DNS packets. One attack entity is followed for 9 months.
- **Empirical Results & Benchmark Metrics**: 96% of IXP-inferred attacks are invisible to the honeypots. With the 10-packet floor, over 24k new attack events are found, and detection of known attacks converges at 99% with 29 names per selector. Only 22% of visible ground-truth attacks reach the 10-packet floor (the visibility versus false-positive trade-off). Attackers could get 14× more amplification by choosing names better. One entity carries out 59% of attacks. 1.25% of unencrypted DNS packets use TCP.
- **Verbatim Verification Quotes**:
  > "Surprisingly, IXPs and honeypots observe mostly disjoint sets of attacks: 96% of IXP-inferred attacks were invisible to a sizable honeypot platform."
  > *Location: Abstract — PDF p. 1 of the verified copy*
  >
  > "Our traces involve 1:16k packet sampling and packets are truncated after 128 bytes, which can be challenging with respect to analysis of higher-layer (e.g., application-level) protocols."
  > *Location: §3.1 Traces from a Large, Regional IXP — PDF p. 3 of the verified copy*
- **Applicability to My Implementation**: The detector pairs a ratio test (share of misused names ≥90%) with a volume floor (≥10 sampled packets). That is the same shape as the testbed's L7 rule (request rate plus error ratio), and the paper shows the floor is what keeps low-volume clients from becoming false positives. Its validation (detection rate against selector size, on ground-truth attacks) is a template for calibrating the daemon's thresholds. A DNS-amplification scenario would show the victim inbound UDP from source port 53 with no matching query. Banning those sources bans resolvers, not attackers. Its finding that single vantage points see different attacks supports stating the testbed's single-host scope.

### P1-03: QUICsand: Quantifying QUIC Reconnaissance Scans and DoS Flooding Events
- **Citation (IEEE Style)**: M. Nawrocki, R. Hiesgen, T. C. Schmidt, and M. Wählisch, "QUICsand: quantifying QUIC reconnaissance scans and DoS flooding events," in *Proc. 21st ACM Internet Measurement Conference (IMC '21)*, Nov. 2021, pp. 283–291, doi: 10.1145/3487552.3487840.
- **Target Attack Vector & Threat Model**: Protocol/state-exhaustion floods against QUIC servers. Spoofed Initial packets make the server run TLS cryptography and keep connection state for unverified clients during the first round trip, the QUIC analogue of a TCP SYN flood. These floods are observed as part of multi-vector attacks alongside TCP/ICMP floods.
- **Defense Architecture & Technology Stack**: Backscatter analysis at a network telescope. Packets are grouped into sessions with a 5-minute timeout, and Moore et al.'s DoS thresholds are applied (>25 packets, >60 s, maximum rate >0.5 pps). Results are correlated with active QUIC scans, GreyNoise and PeeringDB. Lab mitigation test: NGINX with QUIC and eBPF optimisations, RETRY (address validation) on and off.
- **Experimental Setup & Testbed**: The UCSD telescope (a /9, 1/512 of IPv4) over 1–30 April 2021, capturing 92 million QUIC packets. Lab: a 128-core server with 512 GB RAM on Gigabit Ethernet. 500,000 client packets were recorded with quiche 0.9.0, and Initial messages were replayed at fixed rates (1,024 connections per worker).
- **Empirical Results & Benchmark Metrics**: 2,905 attacks (11% of response sessions) on 394 victims, 98% of them well-known QUIC servers (58% Google, 25% Facebook). Median flood duration is 255 s for QUIC versus 1,499 s for TCP/ICMP, at similar maximum intensity. 51% of QUIC floods are concurrent with TCP/ICMP floods, 40% sequential, 9% isolated. NGINX with 4 workers answers 7% of requests at 1,000 pps. Extrapolation suggests attacks above 10,000 pps are happening. RETRY mitigates at the cost of one round trip.
- **Verbatim Verification Quotes**:
  > "With four worker processes even small packet rates can lead to significantly reduced service availability. At 1,000 probes per second (pps) only 7% of our requests are answered."
  > *Location: §5.2 QUIC DoS Traffic — PDF p. 6 of the verified copy*
  >
  > "In our benchmarks, RETRY packets successfully mitigate these attacks but they come at the high cost of an additional round trip."
  > *Location: §5.2 QUIC DoS Traffic — PDF p. 6 of the verified copy*
- **Applicability to My Implementation**: The NGINX test uses a fixed replay rate with the share of answered requests as the outcome. That is the same metric family as the testbed's availability measure, and it shows that the Nginx worker count (4 versus automatic, 128) moves the collapse point by an order of magnitude. Worker settings therefore belong next to every availability result, especially the knee experiments (EXP-A). The testbed has no QUIC/HTTP3 service. An XDP rule could rate-limit QUIC Initial packets on UDP/443, but spoofed floods defeat per-source bans, which is why RETRY (QUIC's counterpart of SYN cookies) exists. The 51% concurrency figure supports keeping a multi-vector scenario in the suite.

### P1-04: The Age of DDoScovery: An Empirical Comparison of Industry and Academic DDoS Assessments
- **Citation (IEEE Style)**: R. Hiesgen et al., "The Age of DDoScovery: An Empirical Comparison of Industry and Academic DDoS Assessments," in *Proc. 2024 ACM Internet Measurement Conference (IMC '24)*, Nov. 2024, pp. 259–279, doi: 10.1145/3646547.3688451.
- **Target Attack Vector & Threat Model**: Two dominant classes: direct-path attacks (spoofed and non-spoofed, e.g. SYN floods and sustained connection floods) and reflection-amplification attacks, with trends over 2019–2023. The industry reports reviewed add application-layer (L7) attacks.
- **Defense Architecture & Technology Stack**: A measurement-methodology study rather than a defence. It compares ten observatories: network telescopes (UCSD, ORION), honeypots (AmpPot, Hopscotch), an IXP, and industry data (e.g. Akamai, Netscout). It also reviews 24 industry reports from 22 vendors. Methods are EWMA smoothing (12-week span), linear regression, Spearman correlation and target-overlap analysis. Industry partners join an aggregated academic target list with their proprietary data.
- **Experimental Setup & Testbed**: Four years of normalised attack counts (2019–2023) across the ten data sets, published with an archive of the industry reports.
- **Empirical Results & Benchmark Metrics**: Four of the five direct-path observatories trend upward over the full period. All five reflection-amplification vantage points rise in 2020 and fall in 2021. The data sets show "more differences than similarities", with low target overlap: UCSD observes over 26% of targets uniquely, and each honeypot about 21%. Several vendors report substantial increases in L7 attacks, and the reports agree that UDP flooding dominates.
- **Verbatim Verification Quotes**:
  > "The linear regressions show that four of the five observatories experienced an upward trend over the full measurement period."
  > *Location: §6.1 Direct-path Attacks — PDF p. 8 of the verified copy*
  >
  > "These divergent observations across vantage points reflect the limited and disparate coverage of each sensor instrumentation (§7)."
  > *Location: §6.1 Direct-path Attacks — PDF p. 8 of the verified copy*
- **Applicability to My Implementation**: Supports the testbed's mix of direct-path floods (SYN, ACK, UDP) and application-layer attacks, and shows its gap: it has no reflection-amplification scenario. The finding that each vantage point sees a different slice of the attack population is the empirical case for stating the testbed's scope (one host, one bridge, one bot population). The same finding argues for publishing raw campaign data, as `results/` already does, so others can validate the results.

## Pillar 2 — Mitigation Paradigms & Architectures

### P2-01: Performance Implications of Packet Filtering with Linux eBPF
- **Citation (IEEE Style)**: D. Scholz, D. Raumer, P. Emmerich, A. Kurtz, K. Lesiak, and G. Carle, "Performance Implications of Packet Filtering with Linux eBPF," in *Proc. 30th International Teletraffic Congress (ITC 30)*, Sep. 2018, pp. 209–217, doi: 10.1109/itc30.2018.00039.
- **Target Attack Vector & Threat Model**: Traffic that is unwanted by the host in general, such as DoS floods and spoofed sources, to be dropped as early as possible on the end host.
- **Defense Architecture & Technology Stack**: An XDP program based on the kernel sample `xdp_ddos01_blacklist`. It parses Ethernet/IPv4, drops the packet if the source IP is in a blacklist map, and otherwise checks layer-4 ports. eBPF JIT is compared against the interpreter, and the baselines are iptables and nftables rule sets. A second case study attaches eBPF filters to sockets via systemd socket activation. DPDK is the kernel-bypass reference.
- **Experimental Setup & Testbed**: Two hosts back to back over 10 GbE, with MoonGen sending 64 B packets. The device under test is an Intel Xeon E3-1230 (4 cores, 3.2 GHz) with 16 GB RAM and an Intel X540-T2, running Debian Stretch on Linux 4.12. Traffic is pinned to one core with Turbo Boost and Hyper-Threading off, 30 s per workload, and profiled with perf.
- **Empirical Results & Benchmark Metrics**: iptables/nftables reach at most 1.5 Mpps with few rules and decline as rules are added. With 3,000 rules at 0.03 Mpps, iptables raises latency fivefold. XDP drop-all reaches 10 Mpps with JIT (+45%). The XDP filter handles 7.2 Mpps with 90% of packets dropped, about 10× netfilter on one core; the authors estimate a lower bound of about 300 CPU cycles per packet for the JIT-compiled XDP code. Median latency is ~50 µs in steady state and 800–1,500 µs under overload, with outliers up to 20× higher.
- **Verbatim Verification Quotes**:
  > "XDP can process up to 7.2 Mpps in the case of 90 % packets dropped, a 28 % performance loss compared to the basic drop example."
  > *Location: §V.B.2 Maximum Processing Rate — PDF p. 4 of the verified copy*
  >
  > "XDP offers a tradeoff. While performance is not as good as dedicated high-performance frameworks that bypass the kernel, it offers flexibility."
  > *Location: §V.C Discussion — PDF p. 6 of the verified copy*
- **Applicability to My Implementation**: This is the same design as `xdp_ddos_filter.c` (a source-IP blacklist map checked before the stack), so the paper's method is the right yardstick for claim M2 (XDP versus iptables, currently "partly supported"). That means one pinned core, fixed 64 B packets, Mpps at the drop point, latency percentiles, and a sweep over the number of installed rules. The sweep matters most. iptables' cost grows with linear rule traversal, while the testbed bans at most 5 bots per scenario, the regime where iptables is close to its best. Sweeping to thousands of banned sources (and including ipset as a fair baseline) would separate the mechanisms. The paper's figures come from a physical NIC driver (ixgbe); the testbed attaches XDP to a veth in a namespace, so absolute rates do not transfer and must be reported as veth figures.

### P2-02: Mitigating IoT Botnet DDoS Attacks through MUD and eBPF based Traffic Filtering
- **Citation (IEEE Style)**: A. Feraudo, D. A. Popescu, P. Yadav, R. Mortier, and P. Bellavista, "Mitigating IoT Botnet DDoS Attacks through MUD and eBPF based Traffic Filtering," in *Proc. 25th International Conference on Distributed Computing and Networking (ICDCN '24)*, Jan. 2024, pp. 164–173, doi: 10.1145/3631461.3631549.
- **Target Attack Vector & Threat Model**: Compromised IoT devices flooding from inside a home network (outbound botnet DDoS). The evaluation uses SYN-flood traces from TON_IoT replayed from an emulated IoT device.
- **Defense Architecture & Technology Stack**: The osMUD manager parses Manufacturer Usage Description (RFC 8520) files, extended with per-device rate limits. Two enforcement backends run on the home gateway. The first, eBPF-IoT-MUD, is an XDP program with allowlists in eBPF maps; it drops packets once the rate is exceeded. The second uses iptables with `--limit-burst` (5 packets). Traces are replayed with tcpreplay/tcprewrite, and overhead is measured with netperf TCP_RR.
- **Experimental Setup & Testbed**: Virtual machines on a MacBook Pro (Intel Core i5, 8 GB), with the gateway VM bridging an IoT network and a server network. Micro-benchmarks run in a Lubuntu 20.04 VirtualBox VM on a quad-core i7 with 16 GiB. Benign profiles come from public traces of 28 IoT devices (a Wi-Fi printer and an Amazon Echo were used); attacks come from TON_IoT.
- **Empirical Results & Benchmark Metrics**:
  - eBPF map rule insertion averages 4,533.43 ns and deletion 4,576.58 ns over 255 rules; the datapath averages 556.15 ns.
  - netperf minimum latency is 186 µs with no firewall, 187 µs with iptables and 188 µs with eBPF. Transaction rates are 2,714, 2,892.51 and 2,915.91 per second respectively.
  - Rate limits calibrated on *average* rates drop over 80% of a smart hub's benign traffic and about 11% of an appliance's. *Peak*-based limits drop below 1.5% and 0.05%.
- **Verbatim Verification Quotes**:
  > "The transaction rate is 2714 transactions/s for baseline, 2892.51 transactions/s with iptables, and 2915.91 transactions/s with eBPF-IoT-MUD."
  > *Location: §V.B Rule management via eBPF — PDF p. 7 of the verified copy*
  >
  > "For eBPF-IoT-MUD, when the rate-limit is reached, the firewall starts dropping the incoming packets."
  > *Location: §V.D Rate limiting impact on abnormal traffic — PDF p. 8 of the verified copy*
- **Applicability to My Implementation**: A map update of ~4.5 µs means writing a ban into an XDP map is negligible next to detection windows of seconds. The testbed's time to mitigate (M6) is therefore almost entirely detection, and the thesis can say so if it measures the two parts separately. The average-versus-peak result is an independent measurement of the collateral-damage side of L4 and M4: per-source limits calibrated on average benign rates block most legitimate traffic, so calibration should use high quantiles. The rigid eBPF limiter (no burst allowance) versus iptables' burst option is the same design choice the daemon faces. Their evaluation is VM-on-laptop, the same class as the namespace testbed. Their netperf TCP_RR check is a cheap way to measure what the XDP program costs legitimate traffic.
  The quotes are from arXiv v1 ("in review", May 2023), not the ICDCN version.

### P2-03: Jaqen: A High-Performance Switch-Native Approach for Detecting and Mitigating Volumetric DDoS Attacks with Programmable Switches
- **Citation (IEEE Style)**: Z. Liu et al., "Jaqen: A High-Performance Switch-Native Approach for Detecting and Mitigating Volumetric DDoS Attacks with Programmable Switches," in *Proc. 30th USENIX Security Symposium (USENIX Security 21)*, Aug. 2021, pp. 3829–3846. [Online]. Available: https://www.usenix.org/conference/usenixsecurity21/presentation/liu-zaoxing
- **Target Attack Vector & Threat Model**: ISP-scale volumetric DDoS: SYN floods with random sources, ICMP floods, TCP/UDP elephant flows, and DNS and NTP amplification (seven representative attacks). Attacks may be hybrid and change dynamically.
- **Defense Architecture & Technology Stack**: Detection and mitigation run entirely inline on Barefoot Tofino switches (P4-14), with no out-of-band collector. Detection is sketch-based. Mitigation uses switch-optimised building blocks behind an API (e.g. SYN-flood tests with Bloom filters, blocklists, rate limits). A network-wide resource manager uses a mixed-integer program with a heuristic 3–4 orders of magnitude faster. A Python controller polls detection results every 5 s.
- **Experimental Setup & Testbed**: One 6.5 Tbps Tofino switch and eleven Dell R230 servers (Intel Xeon E2620 v4, 64 GB RAM, 40 Gbps Intel NICs) running DPDK. Legitimate traffic is one-hour CAIDA traces replayed at 59 Mpps, with up to 1,048,576 legitimate TCP connections. Attacks are generated with MoonGen (SYN, ICMP, ACK/UDP via Lua) or from real-world attack traces.
- **Empirical Results & Benchmark Metrics**: Attack type is detected and volume estimated with 97% accuracy when the attack exceeds 1.5% of 380 Gbps, with volume errors under 3%. Reaction takes at most 15 s, including a 10 s detection period. False-positive/false-negative rates are 0.0–0.072 (introduction) and 0.0–0.073 (§8 summary). Mitigation runs at 380 Gbps, the testbed's ceiling. Poseidon's single hash table loses 25% of connections to collisions at 2M legitimate connections. In simulation, the resource manager returns near-optimal placements within 1 s.
- **Verbatim Verification Quotes**:
  > "Our experiments show that Jaqen is orders of magnitude more performant than existing systems: Jaqen can handle large-scale hybrid and dynamic attacks within seconds, and mitigate them effectively at high line-rates (380 Gbps)."
  > *Location: Abstract — PDF p. 2 of the verified copy*
  >
  > "Second, Jaqen needs a few seconds to react to the attacks. An advanced attacker who smartly and frequently changes the attack types (e.g., <5s) can evade the defense."
  > *Location: §3, "Potential limitations" — PDF p. 6 of the verified copy*
- **Applicability to My Implementation**: Jaqen's loop (5 s polling, 10 s detection, ≤15 s end to end) is a published reference point for the testbed's per-rule time-to-mitigate bounds (M6). Its stated evasion by switching attack type in under 5 s motivates a pulse/switching scenario against the daemon's fixed windows. Its SYN-flood building blocks rely on legitimate clients retransmitting a dropped first SYN. That idea can be implemented in XDP with a BPF map or Bloom filter and compared with per-IP bans under spoofed SYN floods, where per-IP bans fail. The collision result is a reason to justify, and stress-test, the size of the XDP program's LRU `flow_map`.

### P2-04: Collaborative P4-SDN DDoS Detection and Mitigation with Early-Exit Neural Networks
- **Citation (IEEE Style)**: O. Karrakchou, A. Zniber, A. Sebbar, and M. Ghogho, "Collaborative P4-SDN DDoS Detection and Mitigation with Early-Exit Neural Networks," in *Proc. 2025 IEEE Global Communications Conference (GLOBECOM)*, Dec. 2025, pp. 6081–6086, doi: 10.1109/globecom59602.2025.11431920.
- **Target Attack Vector & Threat Model**: The 12 TCP- and UDP-based DDoS types of CIC-DDoS2019, plus a SYN flood generated with Scapy as a pattern absent from the training data.
- **Defense Architecture & Technology Stack**:
  - **Data plane:** a P4 switch computes 28 per-flow features inspired by CICFlowMeter (header lengths, inter-arrival times, TCP flag counts) in registers, min-max quantised to 8 bits. An INT8 1D-CNN (16 filters, kernel 3) with an early-exit classifier decides at the switch, using integer logit thresholds.
  - **Escalation:** for uncertain flows, the last 10 feature maps go to the SDN controller, where a 64-dimensional GRU and a two-layer classifier decide. The controller installs allow/drop rules, and flows are re-checked after 500 packets.
  - **Training:** end to end with quantisation-aware training.
- **Experimental Setup & Testbed**: CIC-DDoS2019, with 1 December data for training and validation and 3 November PCAPs replayed as attacks. The network is an NS-3 simulation of two EP4 switches and four hosts on links of 1.5 Mbps with 10 ms delay, run for 30 s: a benign 2 Mbps TCP upload from t = 0 s, a CIC-DDoS2019 replay from t = 10 s, and a Scapy SYN flood from t = 20 s.
- **Empirical Results & Benchmark Metrics**: Table I reports F1-scores of 99.91 and 99.90 for the two exits (INT8 switch, FP32 controller). Most test flows exit at the switch at a 90% confidence threshold, and raising the threshold moves more flows to the controller. In simulation, benign throughput is preserved through both attacks, with controller contact mainly at t = 2 s and t = 10 s.
- **Verbatim Verification Quotes**:
  > "the CNN frontend and intermediate classifier are quantized and implemented in P4 using integer arithmetic, allowing them to operate at line rate, while the GRU backend is hosted in the SDN controller."
  > *Location: §I Introduction — PDF p. 2 of the verified copy*
  >
  > "All network links are configured with a bandwidth of 1.5 Mbps and a propagation delay of 10 ms."
  > *Location: §IV.B Network-Level Evaluation in NS-3 Simulation — PDF p. 5 of the verified copy*
- **Applicability to My Implementation**: This is the published design closest to the thesis system: per-flow features computed in the data plane (XDP `flow_map` here, P4 registers there) feeding a GRU in the control plane, trained on CIC data, with an out-of-distribution SYN-flood test. Two transferable ideas:
  - Compute at runtime only features the data plane can produce, and train on exactly those. This addresses the train/serve skew in `todo.txt` item 4.
  - Use a cheap in-kernel first stage with confidence thresholds that escalates only uncertain flows to the GRU, which bounds controller load.

  The caveat is in the second quote: the evidence is an NS-3 simulation at 1.5 Mbps, not line rate. It therefore does not contradict the testbed's negative GRU result (L1).

### P2-05: Anycast Agility: Network Playbooks to Fight DDoS
- **Citation (IEEE Style)**: A. S. M. Rizvi, L. Bertholdo, J. Ceron, and J. Heidemann, "Anycast Agility: Network Playbooks to Fight DDoS," in *Proc. 31st USENIX Security Symposium (USENIX Security 22)*, Aug. 2022, pp. 4201–4218. [Online]. Available: https://www.usenix.org/conference/usenixsecurity22/presentation/rizvi
- **Target Attack Vector & Threat Model**: Volumetric and polymorphic floods against anycast services (DNS, CDN). The attack size is only partly visible from any one site.
- **Defense Architecture & Technology Stack**: An upstream/edge routing defence: a precomputed BGP playbook of traffic-engineering actions (AS-path prepending and negative prepending, BGP communities, path poisoning) that shifts catchments between anycast sites. Catchments are mapped with Verfploeter. A new method estimates the true attack size from per-site observations.
- **Experimental Setup & Testbed**: Two real anycast testbeds, Peering and Tangled, using sites such as AMS, BOS, CNF, SEA, SLC, LHR, MIA and POA. Four real attacks (B-root 2017, the Dutch National Scrubbing Center, an enterprise network) are replayed in simulation on a three-site network. Routing takes effect 300 s after each change, and each site has an assumed capacity (e.g. 60k packets/s, about 30 Mb/s, for the B-root event).
- **Empirical Results & Benchmark Metrics**: AS prepending is available almost everywhere but coarse, shifting nearly all or nearly no traffic. Communities are finer but unevenly supported; on Tangled, LHR's catchment moves from 69% to 33%. Path poisoning is often filtered, especially for Tier-1 ASes. The playbook defends against the replayed volumetric and polymorphic events. No change is made faster than every 5 minutes.
- **Verbatim Verification Quotes**:
  > "This paper describes several methods to use BGP to shift traffic when under DDoS, and shows that a response playbook can provide a menu of responses that are options during an attack."
  > *Location: Abstract — PDF p. 2 of the verified copy*
  >
  > "First, Internet routing is distributed, requiring time to converge. The effects of routing defenses cannot be seen until convergence. We do not make changes faster than 5 minutes."
  > *Location: §9 Limitations and Future Work — PDF p. 14 of the verified copy*
- **Applicability to My Implementation**: Places the thesis's host-level XDP defence in the hierarchy. Upstream routing works on a scale of minutes and protects link capacity. Host filtering works within seconds but cannot relieve a saturated access link. The thesis should therefore say that its XDP results assume the bottleneck is the server (CPU, application), not the uplink. The capacity-based evaluation (traffic per site against target capacity) mirrors the testbed's knee experiments, and supports expressing attack rates relative to the measured server capacity. Multi-site anycast cannot be reproduced on a single-host testbed, so this paper informs the thesis's framing rather than its experiments.

## Pillar 3 — Detection Algorithms & ML/DL Models

### P3-01: LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection
- **Citation (IEEE Style)**: R. Doriguzzi-Corin, S. Millar, S. Scott-Hayward, J. Martínez-del-Rincón, and D. Siracusa, "Lucid: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection," *IEEE Transactions on Network and Service Management*, vol. 17, no. 2, pp. 876–889, Jun. 2020, doi: 10.1109/tnsm.2020.2971776.
- **Target Attack Vector & Threat Model**: Binary benign/DDoS classification on UNB traces: ISCX2012-Tue15 (IRC-botnet DDoS), CIC2017-Fri7PM (HTTP DDoS with LOIC) and CSECIC2018-Wed21 (HTTP DDoS with HOIC).
- **Defense Architecture & Technology Stack**: A CNN (one convolutional layer, max pooling, sigmoid output) applied to per-flow arrays of up to *n* packets × 11 features, collected in time windows of *t* seconds. It includes a kernel-activation analysis for explanation. The comparison model is 3LSTM (six 64-unit LSTM layers). Implementation is TensorFlow; code is at github.com/doriguzzi/lucid-ddos.
- **Experimental Setup & Testbed**: Training and the speed comparison run on an Intel Xeon server. The edge test runs on an NVIDIA Jetson TX2 (quad-core Cortex-A57 at 2 GHz, 8 GB RAM, 256-core Pascal GPU) with TensorFlow 1.9.0. Hyper-parameters are swept over t = 1–100 s and n up to 100, and results are reported on held-out test splits of the combined UNB201X data.
- **Empirical Results & Benchmark Metrics**: F1 is around 0.99 across the test sets; during tuning, kernel height moved F1 only from 0.9934 (h = 1) to 0.9950 (h = 3). LUCID classifies over 55,000 samples/s against about 1,300 for 3LSTM (over 40× slower) at comparable F1. The Jetson handles about 1.9 Mpps without GPU at batch size 1024. Memory is 8,800 bytes per sample, so a t = 100 s window at about 23K samples/s would need about 20 GB RAM.
- **Verbatim Verification Quotes**:
  > "we can estimate that the maximum number of packets per second (pps) that the device can process without the GPU and using a batch size of 1024 samples is approximately 1.9 Mpps."
  > *Location: §VII.A Detection (edge use case) — PDF p. 12 of the verified copy*
  >
  > "We acknowledge that the speed of this process will influence the overall system performance. However, as we have not focused on optimising our preprocessing tool, rather on optimising detection, its evaluation is left as future work."
  > *Location: §VII.A Detection (edge use case) — PDF p. 12 of the verified copy*
- **Applicability to My Implementation**: LUCID's input (time-windowed, per-flow packet arrays) poses the same problem as the testbed's 15-step XDP flow snapshots. Its result that a small CNN matches an LSTM's F1 at over 40× the throughput is published support for claim L3 ("a sequence model is not needed"). The open-source LUCID code is a ready 1D-CNN baseline. The second quote marks a measurement boundary: LUCID's throughput excludes flow aggregation (preprocessing). The testbed's ban latency includes feature extraction, so the two sets of numbers must not be compared directly. LUCID trains and tests within the same UNB datasets, so its accuracy says nothing about transfer to new traffic (see P4-01).

### P3-02: Tracking Normalized Network Traffic Entropy to Detect DDoS Attacks in P4
- **Citation (IEEE Style)**: D. Ding, M. Savi, and D. Siracusa, "Tracking Normalized Network Traffic Entropy to Detect DDoS Attacks in P4," *IEEE Transactions on Dependable and Secure Computing*, vol. 19, no. 6, pp. 4019–4031, Nov. 2022, doi: 10.1109/tdsc.2021.3116345.
- **Target Attack Vector & Threat Model**: Volumetric DDoS from Booter (DDoS-for-hire) traces at four packet rates plus a mixed trace, and internal botnet DDoS making up 5–30% of traffic. Detection relies on a drop in normalised destination-IP entropy.
- **Defense Architecture & Technology Stack**: Everything runs in the P4 data plane:
  - P4LogLog estimates flow cardinality, and P4NEntropy estimates normalised entropy with a Count Sketch (5 × 2,000).
  - P4Log and P4Exp approximate logarithms and exponentials in integer arithmetic.
  - P4DDoS compares entropy against an EWMA-based adaptive threshold (α = 0.13, ε = 0.01) over 1 s intervals, and contacts the controller only to raise an alarm.
- **Experimental Setup & Testbed**: Mininet with the bmv2 software switch in an OpenStack VM (4 × 2.7 GHz cores, 4 GB RAM). Legitimate traffic is a 50 s CAIDA 2018 passive trace; attack traffic is Booter DDoS traces. The estimators' accuracy is simulated in Python. A Tofino implementation was attempted but did not fit the hardware's resources.
- **Empirical Results & Benchmark Metrics**: P4LogLog reaches acceptable error with 80 B and about 1% error with 1,280 B registers. P4DDoS raises 4 false alarms in 50 benign intervals (FPR 8%). TPR/accuracy reaches 100%/96% on Booter traces, comparable to or better than a state-of-the-art entropy detector. TPR is 36% when the botnet is 5% of traffic. FPR falls to zero for ε > 0.04, at a cost in TPR.
- **Verbatim Verification Quotes**:
  > "In the first 50 time intervals, four false alarms are detected by P4DDoS, being thus the false-positive rate 8%."
  > *Location: §7.2.1 Comparison with the state of the art — PDF p. 12 of the verified copy*
  >
  > "When the attack traffic rate is low, i.e., 5%, the true-positive rate of P4DDoS is 36%. This is the drawback of most normalized entropy-based DDoS detection strategies: they struggle to detect low-packet-rate DDoS attacks since the normalized entropy may not significantly decrease."
  > *Location: §7.3 Detection performance (Botnet DDoS attacks) — PDF p. 13 of the verified copy*
- **Applicability to My Implementation**:
  - **Portability:** eBPF, like P4, has no floating point. Integer-only cardinality and entropy estimators therefore port directly into an XDP program, e.g. a LogLog register array for per-interval distinct-source counts. That gives a victim-side signal that still works when spoofed floods blind per-IP counters (REPORT EXP-7).
  - **What does not transfer:** on a single server, destination-IP entropy is degenerate because there is one destination. Source-IP or port entropy would be the signal there.
  - **Support for M7:** the 36% TPR at a 5% attack share is independent evidence that volume and distribution statistics miss low-rate attacks.
  - **Metric definitions:** the paper's FPR is per time interval, while the thesis reports false bans per client. The two must not be compared as if they were the same quantity.

### P3-03: Intelligent DoS and DDoS Detection: A Hybrid GRU-NTM Approach to Network Security
- **Citation (IEEE Style)**: C. Panggabean, C. Venkatachalam, P. Shah, S. John, P. Renuka Devi, and S. Venkatachalam, "Intelligent DoS and DDoS Detection: A Hybrid GRU-NTM Approach to Network Security," in *Proc. 5th International Conference on Smart Electronics and Communication (ICOSEC)*, Sep. 2024, pp. 658–665, doi: 10.1109/icosec61587.2024.10722438.
- **Target Attack Vector & Threat Model**: Three classes: normal traffic (UNSW), and DoS and DDoS (Bot-IoT). The introduction lists low-and-slow and application-layer attacks as motivation, but the evaluation covers only these dataset classes.
- **Defense Architecture & Technology Stack**: GRU(64) → GRU(32) → Neural Turing Machine (GRU controller, external memory, read/write heads) → Dense(16, ReLU) → softmax(3). Training uses Adam (lr 0.001), categorical cross-entropy, early stopping (patience 4), min-max scaling and 10-step sliding windows.
- **Experimental Setup & Testbed**: UNSW normal-traffic and Bot-IoT DoS/DDoS data are split into 80,000-sample chunks, merged and shuffled. 20% of the training data is sampled at random, trained with batch size 16 for up to 20 epochs, and evaluated on a 20% validation split. There is no hardware, latency or online evaluation.
- **Empirical Results & Benchmark Metrics**: 99% accuracy; the confusion matrix has no errors (1,796 DDoS, 1,790 DoS, 1,812 normal). AUC is 1.00 for every class and validation accuracy 0.9996. Real-time performance is not measured.
- **Verbatim Verification Quotes**:
  > "Notably, the matrix demonstrates impeccable classification accuracy with zero misclassifications observed across all categories. Specifically, the model correctly identifies 1796 instances of DDoS attacks, 1790 instances of DoS attacks, and 1812 instances of Normal traffic."
  > *Location: §IV.A Confusion Matrix — PDF p. 6 of the verified copy*
  >
  > "While our study does not explicitly test real-time performance, the high accuracy and the nature of RNNs suggest potential for real-time application"
  > *Location: §IV.F Discussion — PDF p. 7 of the verified copy*
- **Applicability to My Implementation**: Included as the representative recurrent-model result, and as a caution. The benign class comes from one dataset and the attack classes from another. P4-02 calls that kind of mixing "incorrect by design", and P3-04 classifies it as sampling bias and spurious correlation. Shuffling windows cut from chunked data also lets temporally adjacent samples leak between training and validation. The repo's `merge_datasets.py` builds its training set the same way (benign flows from `CICFlowMeter.csv`, attack flows from `Syn.csv`). The testbed-captured data (`capture_testbed_dataset.py`, `train_testbed_gru.py`) is the corrective. The paper's GRU (64/32 units, 10-step windows) is no larger than the thesis's 2×64 GRU on 15 steps. Model capacity is therefore not a plausible explanation for the thesis GRU's lack of value; the data are.

### P3-04: Dos and Don'ts of Machine Learning in Computer Security
- **Citation (IEEE Style)**: D. Arp et al., "Dos and Don'ts of Machine Learning in Computer Security," in *Proc. 31st USENIX Security Symposium (USENIX Security 22)*, Aug. 2022, pp. 3971–3988. [Online]. Available: https://www.usenix.org/conference/usenixsecurity22/presentation/arp
- **Target Attack Vector & Threat Model**: Learning-based security systems in general. The network-intrusion case study is Mirai botnet activation and propagation traffic (the Kitsune dataset).
- **Defense Architecture & Technology Stack**: A taxonomy of ten pitfalls, P1 (sampling bias) to P10 (inappropriate threat model), and a prevalence study of 30 top-tier papers. The NIDS case study compares Kitsune (an ensemble of autoencoders over 115 features, 12 autoencoders plus a final one) with a "boxplot" baseline: packet count per 10 s sliding window, flagged outside [Q1 − 1.5·IQR, Q3 + 1.5·IQR] calibrated on clean traffic.
- **Experimental Setup & Testbed**: 30 papers from top-tier security conferences over 10 years, plus an author survey. The Mirai capture covers 119 minutes of Wi-Fi traffic from three PCs and nine IoT devices; the attack begins after 74 minutes.
- **Empirical Results & Benchmark Metrics**: Sampling bias is at least partly present in 90% of papers and data snooping in 73%; every paper has at least three pitfalls. Kitsune versus the baseline: AUC 0.968 versus 0.998; TPR at FPR 0.001 is 0.882 versus 0.996; TPR at FPR 0.000 is 0.873 versus 0.996.
- **Verbatim Verification Quotes**:
  > "The most prevalent pitfalls are sampling bias (P1) and data snooping (P3), which are at least partly present in 90 % and 73 % of the papers, respectively."
  > *Location: §3 Prevalence Analysis — PDF p. 8 of the verified copy*
  >
  > "In the Mirai dataset the infection is overly conspicuous; an attack in the wild would likely be represented by a tiny proportion of network traffic."
  > *Location: §4.4 Network Intrusion Detection — PDF p. 13 of the verified copy*
- **Applicability to My Implementation**: The NIDS case study is the published counterpart of the thesis's central ML finding (L1–L3: the GRU never beat a simple rule). A one-feature packet-rate threshold beats a deep autoencoder ensemble on lab data. Three adoptions follow:
  - Treat the rule engine as the mandatory baseline, and report TPR at fixed low FPR rather than accuracy.
  - Add the IQR detector (10 s windows) to `control_plane.py` as a second, calibration-free baseline; it is a few lines.
  - Audit the GRU for P4 (spurious correlations), which REPORT §5.3 already found as tool/OS fingerprints, and P9 (lab-only evaluation).

  The second quote is the warning about lab data that applies directly to the testbed's attacks.

## Pillar 4 — Empirical Evaluation, Testbeds & Benchmarks

### P4-01: Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study
- **Citation (IEEE Style)**: M. Cantone, C. Marrocco, and A. Bria, "Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study," *IEEE Access*, vol. 12, pp. 144489–144508, 2024, doi: 10.1109/access.2024.3472907.
- **Target Attack Vector & Threat Model**: The attack classes of CIC-IDS2017 and CSE-CIC-IDS2018, including DoS GoldenEye, Slowloris, Hulk and Slowhttptest, DDoS LOIC-HTTP, SSH/FTP-Patator, Bot, web attacks and infiltration.
- **Defense Architecture & Technology Stack**: Four classifiers (LDA, Decision Tree, Random Forest, XGBoost) with mRMR feature selection, evaluated by MCC, plus PCA/KDE views of the feature space. A new dataset, LycoS-UnicasIDS2018, is CSE-CIC-IDS2018 re-extracted with LycoStand using the LycoS-IDS2017 corrections.
- **Experimental Setup & Testbed**: Four datasets (CIC17, CIC18, LycoS17, LycoS18) in within-dataset and cross-dataset configurations, with multi-attack (binary) and single-attack experiments over three runs. CIC18 has 13,691,268 instances and CIC17 1,837,498.
- **Empirical Results & Benchmark Metrics**:
  - Within-dataset MCC is around 99%.
  - Cross-dataset MCC averages 40.24% when training on CIC18 and 31.27% on CIC17; the best cross result is 60.41% (LDA, LycoS18 → LycoS17).
  - With feature selection, MCC averages 83.86% within datasets and 14.91% across them. One feature alone gives 69.7% within-dataset MCC (91.22% accuracy), and 34 of 64 experiments exceed 85% MCC with four or fewer features.
  - The data are extremely redundant: DoS Slowhttptest has 56 distinct instances among 105,550 samples in LycoS18.
- **Verbatim Verification Quotes**:
  > "Compared to the experiments employing the original feature set, also in this case within-dataset experiments achieved significantly better performance with respect to cross-dataset experiments with an average MCC of 83.86% and 14.91%, respectively."
  > *Location: §4.3 Feature selection — PDF p. 12 of the verified copy*
  >
  > "We found that training a ML model on a single publicly available dataset is not sufficient to create a robust NIDS capable of working in different datasets and real-world applications."
  > *Location: §5 Conclusions — PDF p. 15 of the verified copy*
- **Applicability to My Implementation**: This quantifies the data-drift problem in `todo.txt` item 4 and behind claim L1. A model trained on CIC-IDS2017 flows should be expected to fall towards chance on testbed traffic, which is effectively a new dataset. The few-features result explains how such a model can look near-perfect offline: in this data the labels are separable by dataset-specific constants (e.g. LOIC's packet-length mean is fixed at 140.571429 in LycoS18). The repo's own audit found the same pattern: a single feature (maximum request size) reproduces the GRU's F1, 0.994 against 0.996 (`docs/REPORT.md` §1, item 4). For the thesis: report MCC alongside the current metrics, add a train-on-CIC/test-on-testbed cell, and use the corrected LycoS releases if CIC data stay in the pipeline. Quotes are from the arXiv v1 preprint (see §3), which may differ from the IEEE Access text.

### P4-02: Network Intrusion Datasets: A Survey, Limitations, and Recommendations
- **Citation (IEEE Style)**: P. Goldschmidt and D. Chudá, "Network intrusion datasets: A survey, limitations, and recommendations," *Computers & Security*, vol. 156, p. 104510, Sep. 2025, doi: 10.1016/j.cose.2025.104510. *(Survey; the one survey allowed in this pillar.)*
- **Target Attack Vector & Threat Model**: NIDS datasets in general; DoS appears in 74% of the surveyed datasets.
- **Defense Architecture & Technology Stack**: A systematic literature review of 89 public NIDS datasets, compared on 13 properties. It includes a popularity analysis of 45 papers from top-tier security conferences (2020–2023) and best practices for choosing, creating and using datasets.
- **Experimental Setup & Testbed**: An SLR rather than experiments. The paper list and analysis are on the authors' GitHub.
- **Empirical Results & Benchmark Metrics**: CIC-IDS2017 is the most used dataset, yet appears in only 29% of papers, most of which use the original version with its known errors. Most work collects its own unpublished data. Only one dataset in five contains real traffic. Recommendations:
  - Use temporal splits, with training timestamps strictly before evaluation data.
  - Evaluate on several datasets and runs, with significance tests (t-test, Mann–Whitney U).
  - Do not mix datasets from different sources; if unavoidable, replay them in one environment (tcpreplay).
- **Verbatim Verification Quotes**:
  > "While CIC-IDS2017 emerged as the most popular, its utilization only in 29% of papers brings it far from being a "standardized" benchmark in the domain."
  > *Location: §5.4 Dataset Popularity — PDF p. 23 of the verified copy*
  >
  > "Since their data come from different networks and time periods, their traffic patterns will likely differ. Therefore, combining datasets is incorrect by design since bias would likely be introduced."
  > *Location: §6.3 Using a Dataset — PDF p. 30 of the verified copy*
- **Applicability to My Implementation**: By this paper's criteria `merge_datasets.py`, which combines benign flows from one source with SYN-flood flows from another, is biased by design. `build_cicids2017_dataset.py` takes the better route (benign and attack traffic from one testbed) but reads the original CIC-IDS2017 CSVs, which carry known labelling errors. A corrected release would remove that objection. The repo's run-level statistics (multiple runs, exact permutation tests, block bootstrap in `eval/run_level_stats.py`) already follow the survey's "once? not enough" advice, which is citable support. Its dataset-creation checklist (objective, scenario design, labelling, validation, publication) can structure the thesis's description of the testbed capture.

### P4-03: MoonGen: A Scriptable High-Speed Packet Generator
- **Citation (IEEE Style)**: P. Emmerich, S. Gallenmüller, D. Raumer, F. Wohlfart, and G. Carle, "MoonGen: A Scriptable High-Speed Packet Generator," in *Proc. 2015 Internet Measurement Conference (IMC '15)*, Oct. 2015, pp. 275–287, doi: 10.1145/2815675.2815692.
- **Target Attack Vector & Threat Model**: A tool rather than an attack. Lua scripts craft any packet stream, including floods with randomised source addresses; P2-01 and P2-03 use it to generate their attack traffic.
- **Defense Architecture & Technology Stack**: Built on DPDK and LuaJIT, scaling across cores via NIC queues. It uses NIC hardware timestamping (PTP) for latency, hardware rate control for constant-bit-rate traffic, and a new software rate control that fills gaps with invalid-CRC packets, enabling Poisson or bursty patterns.
- **Experimental Setup & Testbed**: Intel 82599/X520/X540 (10 GbE) and 82580 (1 GbE) NICs, with up to twelve 2 GHz cores. It is compared with Pktgen-DPDK 2.5.1 and zsend.
- **Empirical Results & Benchmark Metrics**:
  - One core reaches 14.88 Mpps, 10 GbE line rate with 64 B packets; twelve cores reach 178.5 Mpps at 120 Gbit/s.
  - MoonGen hits line rate at 1.5 GHz, where Pktgen-DPDK needs 1.7 GHz.
  - Timestamp precision is 6.4 ns on 10 GbE and 64 ns on 1 GbE.
  - Hardware rate control behaves non-linearly above about 9 Mpps on X520/X540, and latency can only be measured for PTP-EtherType and UDP frames.
- **Verbatim Verification Quotes**:
  > "Linear multi-core scaling allows for even higher rates: We have tested MoonGen with up to 178.5 Mpps at 120 Gbit/s."
  > *Location: Abstract — PDF p. 1 of the verified copy*
  >
  > "The latency measurements are restricted to Ethernet frames with the PTP EtherType and UDP packets. MoonGen cannot measure latencies of other protocols."
  > *Location: §6.4 Limitations — PDF p. 8 of the verified copy*
- **Applicability to My Implementation**: The paper's central point is that a generator's own rate control and timing shape the result. The testbed generates attacks with processes in network namespaces that share the CPU of the host under test. Two consequences: offered rates must be measured at the receiver, and the generator's CPU use is a confound for defence-overhead measurements. MoonGen needs DPDK-capable physical NICs, so in a namespace testbed the realistic upgrade is a second machine. The alternative is to state the limit of veth-based generation. The constant-bit-rate versus Poisson distinction is the same generator property behind the repo's open-loop versus closed-loop attacker result (EXP-C, claim M4). Hardware timestamping is unavailable on veth, so latency must be measured at application level, as the harness already does.

---

## Appendix A — Search protocol (`python3 docs/sota/fetch_sota.py plan`)

Keyword queries are limited to publication years 2021–2026, with 25 results per query and source.
The last 17 rows were added after the first screening (§3).

| Pillar | arXiv query (cs.CR, cs.NI, cs.LG) | Crossref / OpenAlex / Semantic Scholar query |
|---|---|---|
| P1 | `all:"reflection" AND all:"amplification" AND all:"DDoS"` | `reflection amplification DDoS` |
| P1 | `all:"DNS amplification" AND all:"DDoS"` | `DNS amplification DDoS` |
| P1 | `all:"carpet bombing" AND all:"DDoS"` | `carpet bombing DDoS` |
| P1 | `all:"SYN flood" AND all:"TCP"` | `SYN flood TCP` |
| P1 | `all:"state exhaustion" AND all:"denial of service"` | `state exhaustion denial of service` |
| P1 | `all:"application layer" AND all:"DDoS" AND all:"HTTP flood"` | `application layer DDoS HTTP flood` |
| P1 | `all:"slow HTTP" AND all:"denial of service"` | `slow HTTP denial of service` |
| P1 | `all:"Slowloris"` | `Slowloris` |
| P1 | `all:"HTTP/2" AND all:"denial of service"` | `HTTP/2 denial of service` |
| P2 | `all:"XDP" AND all:"DDoS"` | `XDP DDoS` |
| P2 | `all:"eBPF" AND all:"DDoS" AND all:"mitigation"` | `eBPF DDoS mitigation` |
| P2 | `all:"P4" AND all:"programmable switch" AND all:"DDoS"` | `P4 programmable switch DDoS` |
| P2 | `all:"programmable data plane" AND all:"DDoS" AND all:"mitigation"` | `programmable data plane DDoS mitigation` |
| P2 | `all:"software-defined networking" AND all:"DDoS" AND all:"mitigation"` | `software-defined networking DDoS mitigation` |
| P2 | `all:"OpenFlow" AND all:"DDoS" AND all:"controller"` | `OpenFlow DDoS controller` |
| P2 | `all:"BGP FlowSpec" AND all:"DDoS"` | `BGP FlowSpec DDoS` |
| P2 | `all:"blackholing" AND all:"DDoS"` | `blackholing DDoS` |
| P2 | `all:"anycast" AND all:"DDoS"` | `anycast DDoS` |
| P2 | `all:"scrubbing" AND all:"DDoS"` | `scrubbing DDoS` |
| P3 | `all:"entropy" AND all:"DDoS detection"` | `entropy DDoS detection` |
| P3 | `all:"machine learning" AND all:"DDoS detection" AND all:"CIC-DDoS2019"` | `machine learning DDoS detection CIC-DDoS2019` |
| P3 | `all:"deep learning" AND all:"DDoS detection" AND all:"LSTM"` | `deep learning DDoS detection LSTM` |
| P3 | `all:"autoencoder" AND all:"DDoS detection"` | `autoencoder DDoS detection` |
| P3 | `all:"transformer" AND all:"DDoS detection"` | `transformer DDoS detection` |
| P3 | `all:"in-network" AND all:"machine learning" AND all:"DDoS"` | `in-network machine learning DDoS` |
| P3 | `all:"lightweight" AND all:"DDoS detection" AND all:"real-time"` | `lightweight DDoS detection real-time` |
| P4 | `all:"DDoS" AND all:"testbed" AND all:"evaluation"` | `DDoS testbed evaluation` |
| P4 | `all:"Mininet" AND all:"DDoS"` | `Mininet DDoS` |
| P4 | `all:"CICIDS2017" AND all:"dataset" AND all:"errors"` | `CICIDS2017 dataset errors` |
| P4 | `all:"intrusion detection dataset" AND all:"flaws"` | `intrusion detection dataset flaws` |
| P4 | `all:"TON_IoT" AND all:"dataset"` | `TON_IoT dataset` |
| P4 | `all:"DPDK" AND all:"traffic generator"` | `DPDK traffic generator` |
| P4 | `all:"DDoS" AND all:"dataset" AND all:"benchmark"` | `DDoS dataset benchmark` |
| P1 | `all:"low-rate" AND all:"DDoS"` | `low-rate DDoS` |
| P1 | `all:"slow rate" AND all:"denial of service"` | `slow rate denial of service` |
| P1 | `all:"HTTP/2" AND all:"rapid reset"` | `HTTP/2 rapid reset` |
| P1 | `all:"SYN flood" AND all:"mitigation"` | `SYN flood mitigation` |
| P1 | `all:"DDoS" AND all:"measurement" AND all:"Internet"` | `DDoS measurement Internet` |
| P2 | `all:"XDP" AND all:"packet filtering"` | `XDP packet filtering` |
| P2 | `all:"eBPF" AND all:"firewall"` | `eBPF firewall` |
| P2 | `all:"SYN cookies"` | `SYN cookies` |
| P2 | `all:"iptables" AND all:"DDoS"` | `iptables DDoS` |
| P3 | `all:"recurrent neural network" AND all:"DDoS"` | `recurrent neural network DDoS` |
| P3 | `all:"GRU" AND all:"DDoS"` | `GRU DDoS` |
| P3 | `all:"concept drift" AND all:"intrusion detection"` | `concept drift intrusion detection` |
| P4 | `all:"NIDS" AND all:"dataset"` | `NIDS dataset` |
| P4 | `all:"CIC-IDS-2017" AND all:"CSE-CIC-IDS-2018"` | `CIC-IDS-2017 CSE-CIC-IDS-2018` |
| P4 | `all:"intrusion detection" AND all:"machine learning" AND all:"generalization"` | `intrusion detection machine learning generalization` |
| P4 | `all:"DDoS" AND all:"emulation"` | `DDoS emulation` |
| P4 | `all:"packet generator" AND all:"high-speed"` | `packet generator high-speed` |

**Seed titles** are lookup queries, not citations. A seed is kept only when Crossref, arXiv, the
publisher's page, OpenAlex or Semantic Scholar returns a record whose title matches it (similarity
≥ 0.92). All 24 resolved; six of them through usenix.org pages, because USENIX registers no DOIs.

| Pillar | Seed title |
|---|---|
| P1 | Amplification Hell: Revisiting Network Protocols for DDoS Abuse |
| P1 | Understanding the Mirai Botnet |
| P1 | Weaponizing Middleboxes for TCP Reflected Amplification |
| P1 | The Far Side of DNS Amplification: Tracing the DDoS Attack Ecosystem from the Internet Core |
| P1 | Application Layer Denial-of-Service Attacks and Defense Mechanisms: A Survey |
| P1 | The Age of DDoScovery: An Empirical Comparison of Industry and Academic DDoS Assessments |
| P2 | The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel |
| P2 | Performance Implications of Packet Filtering with Linux eBPF |
| P2 | United We Stand: Collaborative Detection and Mitigation of Amplification DDoS Attacks at Scale |
| P2 | Jaqen: A High-Performance Switch-Native Approach for Detecting and Mitigating Volumetric DDoS Attacks with Programmable Switches |
| P2 | Ripple: A Programmable, Decentralized Link-Flooding Defense Against Adaptive Adversaries |
| P2 | Anycast Agility: Network Playbooks to Fight DDoS |
| P2 | Aggregate-Based Congestion Control for Pulse-Wave DDoS Defense |
| P3 | LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection |
| P3 | Euclid: A Fully In-Network, P4-Based Approach for Real-Time DDoS Attack Detection and Mitigation |
| P3 | IXP Scrubber: Learning from Blackholing Traffic for ML-Driven DDoS Detection at Scale |
| P3 | Dos and Don'ts of Machine Learning in Computer Security |
| P3 | A flow-based IDS using Machine Learning in eBPF |
| P4 | Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy |
| P4 | Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization |
| P4 | Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study |
| P4 | Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018 |
| P4 | A new distributed architecture for evaluating AI-based security systems at the edge: Network TON_IoT datasets |
| P4 | MoonGen: A Scriptable High-Speed Packet Generator |

## Appendix B — Inclusion and exclusion criteria

| # | Criterion |
|---|---|
| I1 | Published 2021–2026. Exempt: foundational datasets, tools and mechanisms the testbed or an included paper uses, and landmarks just outside the window (§3). |
| I2 | Peer-reviewed journal or conference of IEEE, ACM, USENIX, ISOC (NDSS), Springer or Elsevier. Other peer-reviewed venues only when no such paper covers the sub-topic. arXiv-only preprints only when they are landmarks (at least 50 citations, or the reference artefact of an included paper). |
| I3 | Reports quantitative empirical results. Surveys are context only: at most one per pillar, marked as such. |
| I4 | Text retrievable for verification: the abstract at minimum, and the full text for the extraction fields. |
| E1 | Generic intrusion detection with no DDoS relevance is excluded, unless it concerns dataset quality or evaluation method (P4, P3-04). |
| E2 | Duplicates: the peer-reviewed version replaces its preprint; records are merged by DOI, then arXiv id, then normalised title. |

## Appendix C — Reproduction

```bash
python3 docs/sota/fetch_sota.py plan      # the protocol in Appendix A
python3 docs/sota/fetch_sota.py search    # -> docs/sota/corpus/candidates.json
python3 docs/sota/fetch_sota.py fetch     # texts and citations for docs/sota/corpus/selected.json
python3 docs/sota/fetch_sota.py verify    # exit code 0 only if every quote is found
```

PDFs and their extracted text (`corpus/pdf/`, `corpus/fulltext/`) are not committed. `fetch`
downloads them again from the URLs in `corpus/manifest.json`, which also records each file's SHA-256.
Optional settings: `OPENALEX_API_KEY` and `S2_API_KEY` (environment), and `search --mailto`.

## Appendix D — Retrieval log

| Date (UTC) | Step | Result | Log |
|---|---|---|---|
| 2026-10-28 09:52 | `search` | 0 records: all source hosts refused by the session's network policy (HTTP 403 on CONNECT). | `search_20261028T095208Z.log` |
| 2026-10-28 10:12 | `search` | Network opened. OpenAlex blocked (keyless budget exhausted), Semantic Scholar blocked (429); Crossref added. 810 records; 17/24 seeds (ACM subtitles and USENIX were missed). Superseded. | `search_20261028T101210Z.log` |
| 2026-10-28 10:18 | `search` | Seed fixes (Crossref subtitles, usenix.org pages): 24/24 seeds, 799 records. Superseded. | `search_20261028T101838Z.log` |
| 2026-10-28 10:34 | `search` | 17 targeted queries added: 1,214 unique records. **Basis of this review.** | `search_20261028T103454Z.log` |
| 2026-10-28 10:53–11:03 | `fetch` | 16/16 papers stored; P2-01 retried over HTTPS, P3-04 retried for the USENIX copy. | `fetch_20261028T105351Z.log`, `fetch_20261028T105909Z.log`, `fetch_20261028T110300Z.log` |
| 2026-10-28 11:18 | `verify` | 16 papers, 32 quotes, 0 failures (31 exact, 1 after typographic normalisation). | `verify_20261028T111844Z.log` |
| 2026-10-28 11:20 | `verify` | Same result after proofreading edits outside the quotes. **Final run.** | `verify_20261028T112002Z.log` |
