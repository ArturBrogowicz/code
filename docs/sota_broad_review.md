# State-of-the-Art Review — Defences Against DDoS Attack Techniques (Phase 1)

Thesis: *Badanie skuteczności i implementacja rozwiązań w obronie przed różnymi technikami ataków DDoS*
("Evaluating the Effectiveness and Implementation of Defense Solutions Against Various DDoS Attack Techniques").

> **Status (2026-10-28): not populated — 0 papers included.**
> The retrieval step ran but returned no records. The session's network policy refused every
> source host (`export.arxiv.org`, `api.openalex.org`, `api.semanticscholar.org`: HTTP 403 on
> CONNECT; `arxiv.org` and `api.crossref.org` were refused in the same way when probed). No paper
> entry, citation or quote in this file is written from memory. An entry is added only after
> `fetch_sota.py fetch` has stored the paper's text and `fetch_sota.py verify` has found each of
> its quotes in that text. Sections 1–4 (the protocol) are complete and can be reviewed now.

---

## 1. Review questions

Each question serves one pillar and one open point of this repository's evaluation
(`docs/THESIS_CLAIMS.md`).

| RQ | Pillar | Question | Thesis point it informs |
|---|---|---|---|
| RQ1 | P1 Attack vectors | Which volumetric, state-exhaustion and application-layer techniques dominate in 2021–2026, and which of their properties (rate, spoofing, per-connection state, request asymmetry) set the requirements for a defence? | Choice and calibration of the 10 testbed attack scenarios; M7 (slow attacks are not mitigated) |
| RQ2 | P2 Mitigation | Where can mitigation sit (upstream/edge, SDN controller, programmable switch, host kernel via eBPF/XDP), and what does each placement cost in throughput, latency and collateral damage? | M2 (XDP versus iptables, partly supported); M6 (time to mitigate) |
| RQ3 | P3 Detection | Which detection methods reach which accuracy and false-positive rate at which inference cost, and how well do results obtained on datasets transfer to live traffic? | L1–L3 (the GRU adds no detection value in the testbed); L4 (static-threshold dilemma); the CIC-IDS2017 data drift in `todo.txt` item 4 |
| RQ4 | P4 Evaluation | How do credible evaluations build testbeds, generate traffic, choose datasets and report metrics (drop rate, FPR, response time, CPU/memory, throughput)? | Q1 (reproducibility); the availability metric and statistical power issues in `docs/REPORT.md` §6 and §8 |

## 2. Sources and search strategy

**Sources.** arXiv API (categories cs.CR, cs.NI, cs.LG), OpenAlex, and the Semantic Scholar
Graph API for search; Crossref for citation metadata (volume, issue, pages, month); open-access
PDFs (arXiv, OpenAlex `best_oa_location`, Semantic Scholar `openAccessPdf`) for full text.

**Tool.** `docs/sota/fetch_sota.py` (Python standard library for HTTP; `pdftotext` for PDFs).
The tables below are the output of `python3 docs/sota/fetch_sota.py plan`.

**Keyword queries (publication years 2021–2026, 25 results per query and source).**

| Pillar | arXiv query (cs.CR, cs.NI, cs.LG) | OpenAlex / Semantic Scholar query |
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

**Seed titles (lookup queries, not citations).** Keyword ranking can miss foundational work
(datasets, XDP itself, traffic generators) and landmark papers. These titles are looked up with
no year filter. A seed enters the corpus only when OpenAlex or Semantic Scholar returns a record
whose title matches it (similarity ≥ 0.92). Unresolved seeds are logged and dropped. None has
been confirmed yet.

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

## 3. Inclusion and exclusion criteria

| # | Criterion |
|---|---|
| I1 | Published 2021–2026. Exempt: foundational datasets, tools and mechanisms that the testbed or an included paper uses (for example XDP, CIC-DDoS2019, CIC-IDS2017, MoonGen). |
| I2 | Peer-reviewed journal or conference of IEEE, ACM, USENIX, ISOC (NDSS), Springer or Elsevier (tier `top` in `candidates.json`). Other peer-reviewed venues only when no `top` paper covers the sub-topic. arXiv-only preprints only when they are landmarks: at least 50 citations, or the reference artefact of an included paper. |
| I3 | Reports quantitative empirical results (detection metrics, throughput, latency, response time, resource cost or measured attack properties). Surveys are context only: at most one per pillar, marked as a survey. |
| I4 | Text retrievable for verification: the abstract at minimum, and the open-access full text for the extraction fields. |
| E1 | Generic intrusion detection with no DDoS evaluation is excluded, unless it concerns dataset quality (P4). |
| E2 | Duplicates: the peer-reviewed version replaces its preprint. The merge uses DOI, then arXiv id, then normalised title. |
| Target | 3–4 papers per pillar, 12–15 in total. |

## 4. Screening, extraction and verification

1. **Search** (`fetch_sota.py search`) writes `docs/sota/corpus/candidates.json`. Every record
   carries its source hits, venue tier, citation count and a ranking score (citations per year,
   weighted by tier, plus cross-source agreement).
2. **Screening.** Title and abstract against I1–I4 and E1–E2. Each decision is recorded with
   its reason in `docs/sota/corpus/selected.json` (`paper_id`, `key`, `pillar`, `reason`).
3. **Fetch** (`fetch_sota.py fetch`) stores, for each selected paper:
   - the abstract (`corpus/abstracts/`);
   - the open-access full text (`corpus/fulltext/`, kept out of git);
   - the source URL, retrieval time and SHA-256 of the PDF and its text (`corpus/manifest.json`);
   - an IEEE citation built from Crossref.
4. **Extraction** into the entry schema below. Numbers in *Empirical Results* come from the
   stored text, not from memory.
5. **Verification gate** (`fetch_sota.py verify`). Every quote must occur contiguously in the
   stored text of its paper. The check accepts an exact match up to whitespace, or a match after
   typographic normalisation (ligatures, curly quotes, dashes, line-end hyphenation); either can
   be found with Ctrl+F in the PDF. The script reports the PDF page of the match, and each
   entry's *Location* field must agree with it. The review is handed over only with 0 failures.

**Entry schema.**

```
### P<pillar>-<nn>: <Full official title>
- **Citation (IEEE Style)**: ...
- **Target Attack Vector & Threat Model**: ...
- **Defense Architecture & Technology Stack**: ...
- **Experimental Setup & Testbed**: ...
- **Empirical Results & Benchmark Metrics**: ...
- **Verbatim Verification Quotes**:
  > "<quote 1: architecture, formulation or benchmark>"
  > *Location: <section / page>*
  >
  > "<quote 2: limitation, evaluation constraint or trade-off>"
  > *Location: <section / page>*
- **Applicability to My Implementation**: ...
```

---

## Pillar 1 — Modern Attack Vectors & Dynamics

*No entries: retrieval blocked (see Status).*

## Pillar 2 — Mitigation Paradigms & Architectures

*No entries: retrieval blocked (see Status).*

## Pillar 3 — Detection Algorithms & ML/DL Models

*No entries: retrieval blocked (see Status).*

## Pillar 4 — Empirical Evaluation, Testbeds & Benchmarks

*No entries: retrieval blocked (see Status).*

---

## Reproduction

```bash
python3 docs/sota/fetch_sota.py plan      # the search protocol above
python3 docs/sota/fetch_sota.py search    # -> docs/sota/corpus/candidates.json
python3 docs/sota/fetch_sota.py fetch     # needs docs/sota/corpus/selected.json
python3 docs/sota/fetch_sota.py verify    # exit code 0 only if every quote is found
```

Optional: `S2_API_KEY` (environment) raises the Semantic Scholar rate limit; `search --mailto`
joins the OpenAlex polite pool.

## Retrieval log

| Date (UTC) | Step | Result | Log |
|---|---|---|---|
| 2026-10-28 09:52 | `search` | 0 records; 0/24 seeds resolved. `export.arxiv.org`, `api.openalex.org` and `api.semanticscholar.org` refused by the session's network policy (403 on CONNECT). `candidates.json` not written. | `docs/sota/corpus/logs/search_20261028T095208Z.log` |
