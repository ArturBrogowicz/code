# Thesis Refactoring Plan: State-of-the-Art Chapters (Phase 3)

Draft audited: `thesis/main.tex` (986 lines, commit `c26009e`). **Nothing in `thesis/` was modified.**
All compile tests in this document ran on scratch copies outside the repository.

Inputs:
- `docs/sota_broad_review.md` (Phase 1: P-IDs, 32 verified quotes)
- `docs/targeted_literature_selection.md` (Phase 2: L7-IDs, 24 verified quotes)
- primary pages of the draft's web sources and standards, fetched on 2026-10-28 (§1.3)

> **Summary.**
> - **The draft's bibliography is almost entirely web pages.** It has 21 `\bibitem`s:
>   - 2 are peer-reviewed papers: L7-03 (Sensors) and a 4-page conference paper whose claim cannot be checked.
>   - 1 is a peer-reviewed paper that does not contain the claim attributed to it.
>   - 1 is an arXiv preprint whose statistics come from other sources.
>   - 1 is an AI-generated summary site standing in for P2-04.
>   - The other 16 are blogs, vendor pages, Wikipedia, a CVE record and conference slides.
> - **The plan:** 4 entries are retained (reformatted to IEEE), 14 replaced by verified Phase 1–2 papers or
>   standards, and 3 removed.
> - **23 claim-level corrections** are listed (§1.4). They cover factual errors, numbers their cited
>   source does not contain, and overclaims.
> - **New structure:** the SotA chapters are reorganised into the four requested themes, and the empty
>   section 4 is filled with a synthesis.
> - **Bibliography:** a 50-entry IEEE `thebibliography` block is proposed (§5). It compiles: 0 undefined
>   citations, 0 duplicate labels, 0 missing glyphs, and no new errors (§6).

---

## 0. Summary table

| Existing Citation / Draft Section | Action | Target Paper ID | Proposed Thematic Role in SotA |
|---|---|---|---|
| *Detecting and Mitigating DDoS Attacks with AI: A Survey* (arXiv preprint; §2 intro, l.72) | **Replace** | P1-04 | Taxonomy & vectors: attack trends from multi-source measurement |
| *SYN flood DDoS attack – Cloudflare* (`\bibitem` never cited) | **Remove** | — (RFC 9293, RFC 4987 for §2.1.1) | — |
| *DDoS Protection and Mitigation: A 2026 Guide* (Kentik; l.137, 147, 214) | **Replace** | P1-04, P1-02, RFC 7011/3954, RFC 8955; Rapid Reset report | Flow telemetry and vantage points; Rapid Reset mitigation |
| *DNS amplification attack* (Cloudflare Learning; l.151) | **Replace** | P1-02, P1-01 (+ RFC 6891, 8482, 5358, 2827) | Reflection-amplification (DNS and TCP middleboxes) |
| *Slowloris DDoS attack* (Cloudflare Learning; l.174) | **Replace** | L7-03 | Low-and-slow: attack definition |
| *Slowloris attack* (Invicti; l.187) | **Replace** | L7-03, L7-02 (+ nginx docs) | Low-and-slow: timeout trade-off, why count rules fail |
| *Generator of Slow Denial-of-Service Cyber Attacks* (PMC link; l.200) | **Retain** (IEEE format; claim realigned) | L7-03 | Low-and-slow: server-dependent impact, detection guidance |
| *CVE-2023-44487* (NVD; l.202) | **Retain** (IEEE format) | — (+ RFC 9113) | Asymmetric request-cost L7 attack (Rapid Reset) |
| *HTTP/2 Rapid Reset: deconstructing…* (Cloudflare; l.205) | **Retain** (grey literature, authors added) | — | Rapid Reset mechanics and mitigation |
| *How Cloudflare auto-mitigated world record 3.8 Tbps…* (l.238) | **Retain** (grey literature, labelled) | — (paired with P1-04) | Scale context for the defence chapter |
| *How to Set Up Rate Limiting with iptables* (oneuptime; l.261) | **Replace** | P2-02 (+ iptables-extensions(8)) | In-kernel filtering: rate limits and their calibration |
| *Building a … Pipeline with nftables and XDP* (dev.to; l.263) | **Replace** | kernel docs (nf_conntrack) + P2-01 | Netfilter state cost (conntrack exhaustion) |
| *How to use eBPF XDP for DDoS protection…* (oneuptime; l.267) | **Replace** | P2-01 | XDP acts before `sk_buff` allocation |
| *Anycast* (Wikipedia; l.272) | **Replace** | P2-05 (+ RFC 4786) | Defence placement: upstream/anycast |
| *Top F5 Alternatives for WAF in 2026* (Indusface; l.274) | **Remove** | — | Vendor marketing; the 197 Tbps claim is dropped |
| *Linux ACL Performance Analysis* (Netdev 0x15 slides; l.320) | **Replace** as primary evidence; keep as supplementary | P2-01, L7-05 | XDP vs iptables benchmarks |
| *Cloud-based DDoS detection … DRL* (Sci. Rep. 2025; l.344) | **Remove** (claim not in source) | — (optional DRL sentence, §3.3) | — |
| *Enhanced DDoS Attack Detection Using Advanced DL* (ICAECOT 2024, 4 pp.; l.346) | **Replace** | L7-04, P3-01, L7-01 | Sequential models: accuracy and cost trade-offs |
| *collaborative-p4-sdn-…* (themoonlight.io AI summary; l.354) | **Replace** | P2-04 | Hybrid data-plane + control-plane ML |
| *Carpet-bombing Attacks Highlight…* (A10 blog; l.221) | **Replace** | P1-04, P3-02 (+ RFC 7999) | Multi-target attacks; limits of entropy detection |
| *The ultimate weapon against DDoS — BGP Flowspec* (APNIC blog; l.227) | **Replace** | RFC 8955 (P2-05 for context) | Upstream filtering standards |
| §2.1.1 SYN cookies, "RFC 793", "RFC 1323" (uncited, l.82–124) | **Add** citations, fix 2 errors | RFC 9293, 4987, 7323, Linux source | SYN flood and its standard mitigation |
| §3.4 L4Drop / Gatebot (uncited numbers, l.323–327) | **Add** citation, correct numbers | Fabre 2018 (grey) | Industrial XDP deployment |
| §3.5 datasets, "RF + GridSearchCV > 99%" (uncited, l.331–342) | **Reframe** | P4-02, P4-01, L7-04, L7-02 | Classical baselines; within- vs cross-dataset scores |
| New: low-and-slow HTTP/2 and Slow Read (absent) | **Add** | L7-01, L7-03 | Low-and-slow dynamics |
| New: evaluation methodology subsection (absent) | **Add** | P3-04, P4-01, P4-02, L7-05 | Testbeds and evaluation pitfalls |
| New: taxonomy paragraph and table (absent) | **Add** | P1-01, P1-02, P1-04, L7-03, RFC 4732 | Taxonomy of modern vectors |

---

## 1. Audit of the draft

### 1.1 Structure as found

| § | Heading (as in draft) | Lines | State |
|---|---|---|---|
| 1 | Wprowadzenie | 70 | **Empty** |
| 2 | Analiza stanu wiedzy o najbardziej dotkliwych atakach DDoS | 71–236 | Intro (l.72) + L3/L4 (SYN flood, UDP flood, DNS amplification) + L7 (Slowloris, R.U.D.Y., HTTP/2 Rapid Reset) + multi-vector (Carpet Bombing) |
| 3 | Analiza stanu wiedzy o metodach obrony przed atakami DDoS | 237–354 | Intro (l.238) + iptables/nftables, reverse proxy/anycast, WAF (+JA3/JA4), eBPF/XDP (+L4Drop), ML/DL |
| 4 | Wnioski z przeanalizowanych przykładów | 355 | **Empty** |
| 5 | Koncepcja rozwiązania… | 356–923 | Concept, architecture, components, 6 code listings (out of scope here; see §1.5) |
| 6–8 | Testy / Ocena / Wnioski | 924–926 | Empty |
| — | `thebibliography{9}` | 927–985 | 21 entries |

The document class is `article`, so the "chapters" are `\section`s. The plan keeps that hierarchy, so the
numbering of sections 5–8 does not move.

### 1.2 Build baseline (scratch copies, TeX Live 2023)

| Engine | Result on the unmodified draft |
|---|---|
| `pdflatex` (2 passes, nonstopmode) | 37 pages. **12 errors, all pre-existing:** "Invalid UTF-8 byte" from Polish letters inside the `GRU_ML_init.py` listing (l.633, l.636), because `listings` does not accept multi-byte UTF-8. With `-halt-on-error` no PDF is produced. Polish text in the body renders correctly. |
| `lualatex` (2 passes) | 0 errors, but **2,373 "Missing character" warnings**: `fontenc[T1]` without `fontspec` drops every Polish diacritic ("rosnca" for "rosnąca"). Not a usable engine for this preamble. |

Other findings from the build:
* `\label{fig:placeholder}` is defined twice (l.87, l.134), giving a "multiply defined" warning. Neither
  label is referenced, so renaming them is safe.
* The `\bibitem` "SYN flood DDoS attack – Cloudflare" is never cited.
* `\begin{thebibliography}{9}` sets the label width for 1-digit numbers, but the list has 21 entries.
* Citation keys contain spaces, colons, a slash, an em-dash and a line break (`\cite{Linux ACL⏎Performance
  Analysis}`). They work, but are fragile under hyperref and in editors.
* **IEEE numbering is violated.** The checker in Appendix A reports
  `order mismatch at [9]` and `\bibitem never cited: SYN flood DDoS attack - Cloudflare`. With
  `thebibliography`, numbers follow `\bibitem` order, while IEEE requires order of first citation.
* **Images:** the directory is `thesis/images/`, not `thesis/image/`. All 7 referenced files exist:
  - `TCP-3-way-handshake.png`, `UDP-flood.png`, `DNS-Amplification.png`, `SlowLoris.png`, `RUDY.png`,
    `HTTP2-Rapid-Reset.png`;
  - `Architektura-DDoS-mitigation.pdf` (via `\includepdf`).

  Unused: `TCP-3-way-handshake (1).png` (a byte-identical duplicate) and `Architektura-DDoS-mitigation.png`.
* `\label{Netflow}` sits inside a paragraph (l.139). `\ref{Netflow}` (l.263, l.350) therefore prints the
  number of §2.1.2. The output is correct; only the placement is unusual. No change is required.

### 1.3 Citation catalogue

Type: **P** = peer-reviewed, **S** = standard or official record, **G** = grey literature (vendor or
engineering blog, conference slides), **W** = web page (encyclopaedia, marketing, tutorial),
**X** = AI-generated summary site.

| # | Draft key (abbr.) | Cited at | Type | What was checked (2026-10-28) | Verdict |
|---|---|---|---|---|---|
| 1 | Detecting and Mitigating DDoS Attacks with AI: A Survey | l.72 | arXiv preprint | arXiv 2503.17867 (Apostu et al.), no journal reference. Its "55%" comes from Shroff et al. [95] and "75.60%" from [67]; the market figures come from Markets&Markets. The draft cites a third-hand chain. | Replace → P1-04 |
| 2 | SYN flood DDoS attack – Cloudflare | never | W | Orphan `\bibitem` | Remove |
| 3 | DDoS Protection and Mitigation: A 2026 Guide | l.137, 147, 214 | G (vendor) | Kentik encyclopaedia page | Replace |
| 4 | DNS amplification attack | l.151 | W | Cloudflare Learning Center | Replace |
| 5 | Slowloris DDoS attack | l.174 | W | Cloudflare Learning Center | Replace |
| 6 | Slowloris attack | l.187 | W | Invicti marketing page | Replace |
| 7 | Generator of Slow Denial-of-Service Cyber Attacks | l.200 | **P** | = L7-03. It does **not** support l.200's claims about proxy buffering or cloud-WAF behavioural analysis (§1.4, F15) | Retain, realign |
| 8 | CVE-2023-44487 | l.202 | S | NVD record, published 2023-10-10 | Retain |
| 9 | HTTP/2 Rapid Reset: deconstructing… | l.205 | G (primary) | Cloudflare, L. Pardue and J. Desgats, 2023-10-10. Supports a 201 M rps peak, counting resets per connection with GOAWAY above a threshold, stream concurrency reduced to 64, and "IP Jail" | Retain |
| 10 | How Cloudflare auto-mitigated world record 3.8 Tbps… | l.238 | G (primary) | M. Arora et al., 2024-10-02. Supports 3.8 Tbps and 2.14 Bpps. It does **not** contain the draft's ">100 M rps" (that figure is in #9) | Retain, labelled |
| 11 | How to Set Up Rate Limiting with iptables… | l.261 | W (tutorial) | oneuptime blog | Replace |
| 12 | Building a High-Performance DDoS Mitigation Pipeline… | l.263 | W (tutorial) | dev.to post | Replace |
| 13 | How to use eBPF XDP for DDoS protection… | l.267 | W (tutorial) | oneuptime blog | Replace |
| 14 | Anycast | l.272 | W | Wikipedia | Replace |
| 15 | Top F5 Alternatives for WAF in 2026 | l.274 | W (marketing) | Indusface page about competitors | Remove |
| 16 | Linux ACL Performance Analysis | l.320 | G (conference slides) | J. Hadi Salim and N. Bitar, Netdev 0x15 (Jul. 2021). The slides confirm the Xeon Gold 6230R testbed and that "TC/XDP ebpf did better than IPtables/IPSet". The draft's "**24 Mpps per core in UDP-flood tests**" is not in the slide text (the figures are charts), so it is unverified. The slides also report "No difference between XDP and TC because packets go to stack" | Replace as primary (→ P2-01); optional supplementary |
| 17 | Cloud-based DDoS detection … (DRL) | l.344 | **P** | Satpathy et al., *Sci. Rep.* 15:36546 (2025). The full text (Europe PMC) contains no "Extra Trees" and no "IIoT", and no federated-learning result. The cited claim (Extra Trees + federated learning in IIoT, about 98%) is **not in this paper**. Its topic (TD3, SHAP) matches the *uncited* sentences in l.346 instead | Remove (optional: cite for the DRL sentence only) |
| 18 | Enhanced DDoS Attack Detection Using Advanced DL | l.346 | P (low tier) | Abdelkarim et al., ICAECOT 2024, pp. 1–4, IEEE Xplore (paywalled). The 99.54% cannot be verified from here | Replace |
| 19 | collaborative-p4-sdn-… | l.354 | **X** | themoonlight.io is an AI-generated paper-review site; the real paper is P2-04 (GLOBECOM 2025) | Replace → P2-04 |
| 20 | Carpet-bombing Attacks Highlight… | l.221 | G (vendor) | A10 Networks blog | Replace |
| 21 | The ultimate weapon against DDoS — BGP Flowspec | l.227 | G | APNIC blog. The standard itself is RFC 8955 | Replace |

**Additional sources verified for the proposed bibliography:**
- *RFC metadata* (rfc-editor.org JSON): RFC 793 → obsoleted by 9293; 1323 → obsoleted by 7323; 5575 →
  obsoleted by 8955; and 4987, 4732, 2827, 6891, 5358, 8482, 3954, 7011, 7999, 9113, 4786, 8701.
- *RFC 4987 Appendix A:* the cookie layout of 5 bits counter / 3 bits MSS / 24 bits hash, with a 64 s
  counter.
- *Linux `net/ipv4/syncookies.c`:* `TS_OPT_WSCALE_MASK 0xf`, `TS_OPT_SACK BIT(4)`, `TS_OPT_ECN BIT(5)`,
  `TSBITS 6`. This matches the draft's 26/1/1/4-bit description.
- *nginx documentation:* `client_header_timeout` covers the *entire* header (default 60 s);
  `client_body_timeout` applies between successive reads; `proxy_request_buffering` defaults to `on`.
- *Other pages:* `iptables-extensions(8)` (`limit`, `hashlimit`, `connlimit`), the kernel
  `nf_conntrack_max` docs, the L4Drop and Gatebot blog posts, and Crossref for Hochreiter & Schmidhuber
  (1997) and Cho et al. (2014).

### 1.4 Claim-level corrections

| ID | Line | Draft says (abridged) | Problem | Correction and source |
|---|---|---|---|---|
| F1 | 72 | +55% (2020–21), +75% (H1 2022); market USD 3.9 → 7 bn | Third-hand statistics; market numbers from a commercial report | Use P1-04 (four of five direct-path observatories trend upward 2019–2023; vantage points diverge; vendors report rising L7). Drop the market sentence |
| F2 | 72 | ML "jest koniecznością" | Overclaim | "motivates evaluating learning-based detection alongside deterministic rules" (P3-04, §3.4) |
| F3 | 86 | Caption cites RFC 793 | Obsoleted | RFC 9293 |
| F4 | 89 | SYN flood "tworzy pole" for TCP session hijacking | Unrelated mechanism | Remove the sentence |
| F5 | 91 | Cookies avoid allocation "po odebraniu segmentu ACK"; sentence ends "…oraz jego kolejce SYN." | Should be *SYN*; the sentence is unfinished | See proposed wording below; RFC 4987 §3.6, App. A |
| F6 | 115 | TCP Timestamps "zdefiniowanej w RFC 1323" | Obsoleted | RFC 7323 |
| F7 | 154 | ANY/TXT forces "zrzut wszystkich informacji powiązanych ze strefą" | ANY returns the records of one *name*, not a zone dump (that is AXFR); since 2019 servers may answer ANY minimally | RFC 8482; P1-02 (misused names, DNSSEC-signed responses) |
| F8 | 164 | Gatebot as the anycast absorption mechanism | Gatebot is Cloudflare's automatic detection/mitigation bot; absorption comes from anycast | Rephrase; P2-05, RFC 4786 |
| F9 | 166, 201 | Rapid Reset sits under "low and slow" | Rapid Reset is a high-rate request-cost attack | Taxonomy split (§2) |
| F10 | 174 | "Robert Hansen, 2009" | No source | Drop the name and year, or add a primary source (not verified here) |
| F11 | 177 | Each slow request forces "alokacji oddzielnego wątku" | True only for thread- or process-per-connection servers. Event-driven Nginx resisted Slowloris and Slow POST in L7-03 | Qualify with L7-03 (Nginx 1.14.0: 2 of 11 slow attacks effective, Slow Read and Slowcomm) |
| F12 | 198 | Idle-timeout defences "są nieskuteczne" against R.U.D.Y. | Per-read timeouts are evaded only if the attacker writes within the timeout | L7-03 §2.1.2; L7-02 §4.5 (a sleep time above the server timeout makes the attack effective only part of the time); nginx docs (body timeout between reads; header timeout for the whole header) |
| F13 | 238 | ">100 mln rps" attributed to the 3.8 Tbps report | Not in that report | Cite the Rapid Reset report (201 M rps) |
| F14 | 261 | `connlimit` presented as an L7 defence | It limits parallel TCP connections per client address (L4), which is still relevant to low-and-slow | iptables-extensions(8) |
| F15 | 200 | Proxy body buffering and cloud-WAF behavioural analysis, cited to L7-03 | L7-03 says neither | Keep buffering, cited to nginx `proxy_request_buffering`; use L7-03's actual advice (limit connection time and connections per IP, set a tolerance for slow legitimate users, NAT caveat) |
| F16 | 265 | iptables O(n) vs nftables "O(1) w pojedynczej operacji" | Oversimplified. P2-01 measured both at ≤1.5 Mpps, both declining with rule count; constant-time lookups need sets/maps | P2-01 (3,000 rules: 5× latency); nftables sets |
| F17 | 320 | XDP "do 24 milionów pakietów na sekundę" on one core | Not verifiable in the cited slides | P2-01: 7.2 Mpps per core with 90% dropped, versus ≤1.5 Mpps for netfilter |
| F18 | 327 | L4Drop dropped ">8 mln złośliwych żądań/s", "40-krotny wzrost", stable "x86 i ARM" | The source says ">8 million **packets** per second"; "40×" and the x86/ARM stability claim are not in it | Fabre 2018; keep only what it states |
| F19 | 337 | "średni czas trwania sesji (ang. Time-to-Live)" | TTL is the IP hop limit, not session duration | "czas trwania przepływu" (flow duration) |
| F20 | 340–342 | RF + GridSearchCV > 99%; ensembles "demaskują" low-and-slow | Uncited; within-dataset scores do not transfer | P4-01 (MCC 83.86% within vs 14.91% across datasets); L7-04 (trees are strong baselines); L7-02 (decision tree on behavioural parameters for Slowloris) |
| F21 | 344 | Extra Trees + federated learning, IIoT, about 98% | Not in the cited paper (§1.3 #17) | Remove |
| F22 | 350 | P4 stage extracts "5-krotki" | P2-04 computes 28 per-flow features in registers | P2-04 |
| F23 | 354 | Hybrid P4-SDN "dowodzą…bez degradacji opóźnień" | NS-3 simulation on 1.5 Mbps links | P2-04 with its verified 1.5 Mbps quote |

Typos to fix in the same pass:
- "powszechoność" (l.72); "(DNS).W" (l.149); "odzielnego/pamieci" (l.177); "systmeów" (l.200);
- "NGNIX", "powolonych" (l.278); "botentu" (l.289, l.369); "neurownowe" (l.330 heading).

**Proposed wording for F5** (replaces the second half of l.91):
> „…polega na rezygnacji z alokacji zasobów na serwerze po odebraniu segmentu SYN — nie jest tworzony
> wpis w kolejce backlog [rfc4987]. […] W systemie Linux mechanizm ten jest aktywowany dopiero wtedy, gdy
> kolejka połączeń półotwartych zostaje przepełniona (parametr `net.ipv4.tcp_syncookies=1`).”

### 1.5 Consistency notes outside the SotA chapters (for a later phase)

These are recorded so that the SotA rewrite does not contradict them. Nothing is changed now.

* **l.359, l.376–377, l.391.** These describe the GRU as the detector that triggers mitigation, using
  three features (request duration, header size, bytes). In the current code:
  - the bans come from deterministic rules (`control_plane.py`);
  - the Nginx-log GRU is evaluated in shadow mode on feature groups that no longer include request size;
  - the XDP-fed GRU is behind `XDP_GRU`.

  The solution chapter should describe the GRU as the experimental component it is in the code.
* **l.383.** Two namespaces (`attacker_ns`, `server_ns`). The current testbed has 20 legitimate clients
  and 5–10 bots in separate namespaces (`test_distributed_suite.py`).
* **Listings (l.397–923).** They predate the current code. They also contain the UTF-8 characters that
  break `pdflatex` (§6.3).

---

## 2. Target structure of the State-of-the-Art chapters

The four requested themes map onto the existing `\section`s 2–4. Sections 5–8 keep their numbers.

```
2  Analiza stanu wiedzy o technikach ataków DDoS                         [Theme A: taxonomy & vectors]
   (intro: trends, P1-04)
   2.1  Taksonomia współczesnych wektorów DDoS              NEW (paragraph + Table 1)
   2.2  Ataki wolumetryczne i protokołowe (L3/L4)           = old 2.1
        2.2.1 SYN flood                                     old 2.1.1, corrected
        2.2.2 UDP flood                                     old 2.1.2
        2.2.3 Ataki odbiciowo-wzmacniające (DNS, TCP)       old 2.1.3 + Bock (new paragraph)
        2.2.4 Ataki wielocelowe (Carpet Bombing)            old 2.3, condensed
   2.3  Asymetryczne ataki w warstwie aplikacyjnej (L7)     old 2.2, re-split
        2.3.1 Ataki typu low-and-slow: mechanizm i zależność od architektury serwera   NEW
        2.3.2 Slowloris                                     old 2.2.1
        2.3.3 R.U.D.Y. (Slow POST)                          old 2.2.2
        2.3.4 Slow Read i warianty HTTP/2                   NEW (Sikora, Tripathi)
        2.3.5 HTTP/2 Rapid Reset (atak kosztem żądań)       old 2.2.3, reclassified
   2.4  Wymagania wobec mechanizmów obrony                  NEW (closing paragraph)
3  Analiza stanu wiedzy o metodach obrony przed atakami DDoS
   (intro: scale, defence in depth)
   3.1  Umiejscowienie obrony: sieć operatora, anycast, WAF old 3.2 + 3.3 + parts of 2.3, condensed
   3.2  Filtrowanie pakietów w jądrze: od Netfilter do eBPF/XDP   [Theme B]  old 3.1 + 3.4 merged
   3.3  Uczenie maszynowe i modele sekwencyjne w detekcji DDoS    [Theme C]  old 3.5, rebuilt
   3.4  Metodyka ewaluacji, środowiska testowe i pułapki          [Theme D]  NEW
4  Wnioski z przeglądu stanu wiedzy                                NEW content (heading exists, empty)
```

**Narrative guardrails applied throughout:**
* **XDP/eBPF** is the established L4 defence baseline, with measured benchmarks: P2-01, P2-02, L7-05.
* **Low-and-slow** is framed through L7-03 and L7-02: count- and volume-based rules are evadable, and
  impact depends on the server architecture and its timeouts. This motivates the dual-plane
  (heuristic + ML) exploration.
* **Recurrent models** (L7-01, L7-04, P2-04, P3-01) are presented as the theoretical and empirical
  baseline for the thesis's *ongoing* GRU pipeline. The chapter discusses:
  - open trade-offs (sequence unit, supervision, inference cost);
  - feature-extraction challenges;
  - how ML coexists with deterministic heuristics.
* **Boundary.** The SotA chapters make **no claim about the thesis's own GRU results**. Those belong in
  section 7 and must match the measured evidence (`docs/THESIS_CLAIMS.md`).

---

## 3. Paragraph-by-paragraph blueprint

Columns: draft paragraph (lines) → action → content change → citations *before* → *after* (new keys,
§5). "Keep" means the prose stays, with typo fixes only.

### Section 2 intro and §2.1 Taxonomy (Theme A)

| ¶ (lines) | Action | Content change | Before → After |
|---|---|---|---|
| 72 | Rewrite | Replace the growth and market statistics with P1-04's multi-source trends: direct-path attacks rise in 4 of 5 observatories over 2019–2023; vantage points see different slices; vendors report rising L7. End with the move from bandwidth saturation to resource asymmetry (keep). Drop "ML jest koniecznością" (F2). | Survey → `hiesgen2024age` |
| new | Add | **Taxonomy paragraph** framing DoS as resource exhaustion at link, state, or application level, in five classes:<br>(a) direct-path volumetric floods;<br>(b) reflection-amplification: DNS (P1-02), TCP middleboxes ≥100× (P1-01);<br>(c) protocol/state exhaustion: SYN backlog (RFC 4987), optionally QUIC handshake floods (P1-03);<br>(d) asymmetric request-cost L7: HTTP floods, Rapid Reset;<br>(e) low-and-slow connection holding (L7-03, L7-02, L7-01). | — → `rfc4732`, `nawrocki2021far`, `bock2021weaponizing`, `rfc4987`, (`nawrocki2021quicsand`), `pardue2023rapidreset`, `sikora2021generator`, `sood2023slowtrack`, `tripathi2024delays` |
| new | Add | **Table 1** (`tabularx` + `booktabs`, both already loaded). Columns: class, exhausted resource, typical rate, source spoofable?, per-source attribution possible?, primary detection signal. Its key row: reflection makes per-source blacklists ban reflectors, not attackers (P1-01, P1-02). | as above |

### §2.2 Volumetric and protocol attacks (old 2.1)

| ¶ (lines) | Action | Content change | Before → After |
|---|---|---|---|
| 74–80 | Keep | — | — |
| 82 | Keep | Add a source for the handshake | — → `rfc9293` |
| 83–88 fig. | Keep | Caption "RFC 793" → "RFC 9293"; `\label{fig:placeholder}` → `\label{fig:tcp_handshake}` | — |
| 89 | Edit | Delete the session-hijacking sentence (F4) | — → `rfc4987` |
| 91 | Edit | F5 wording; attribute SYN cookies to Bernstein via RFC 4987 §3.6 | — → `rfc4987` |
| 93–109 | Keep | Note that the cookie is XOR-ed with the client's ISN (RFC 4987 App. A) | — → `rfc4987` |
| 111–113 | Keep | Drawbacks (window scaling lost) match RFC 4987 | — → `rfc4987` |
| 115 | Edit | RFC 1323 → RFC 7323 (F6) | — → `rfc7323` |
| 117–124 | Keep | The 26/1/1/4-bit layout is verified against the kernel source | — → `linux_syncookies` |
| 126–128 | Keep | — | — |
| 130–135 fig. | Keep | `\label{fig:placeholder}` → `\label{fig:udp_flood}` | — |
| 137 | Rewrite | Drop the DPI-cost generalisation. Instead: reports agree UDP flooding dominates (P1-04) | Kentik → `hiesgen2024age` |
| 139–146 | Keep | NetFlow 5-tuple; cite the standards. Keep `\label{Netflow}` | — → `rfc3954`, `rfc7011` |
| 147 | Rewrite | Flow telemetry at an IXP: sampled 1:16k, a ratio test plus a volume floor; 96% of IXP-seen attacks are invisible to honeypots (P1-02, verified quote). FlowSpec and scrubbing become a forward reference to §3.1 | Kentik → `nawrocki2021far`, `rfc8955` |
| 149 | Keep | Fix "(DNS).W" | — → `nawrocki2021far` |
| 151–157 | Edit | Steps keep their order. Fix ANY (F7); cite EDNS(0) and open resolvers | Cloudflare → `nawrocki2021far`, `rfc6891`, `rfc8482`, `rfc5358` |
| 158–163 fig. | Keep | — | — |
| new | Add | **TCP reflected amplification** via middleboxes: 386,187 IPs amplify ≥100× (P1-01, verified quote). Consequence: host-level per-source bans cannot target the attacker | — → `bock2021weaponizing` |
| 164 | Edit | Ingress filtering (BCP 38) and anycast absorption. Fix the Gatebot sentence (F8) or drop it. RRL stays as a generic statement | — → `rfc2827`, `rizvi2022anycast`, `rfc4786` |
| 217–221 | Condense | Keep the 200 Gbps / 2,000-IP arithmetic (own illustration). Add that single sensors miss carpet-bombing events, which must be aggregated across sensors (P1-04) | A10 → `hiesgen2024age` |
| 223 | Edit | Temper "błyskawicznie identyfikują": in-network entropy detection gives FPR 8%, and only 36% TPR when the attack is 5% of traffic (P3-02, verified quotes) | — → `ding2021tracking`, `rfc7011` |
| 225 | Keep | RTBH community 666 | — → `rfc7999` |
| 227–235 | Keep | RFC 5575 → "RFC 8955 (obsoletes RFC 5575)" | APNIC → `rfc8955` |

### §2.3 Asymmetric application-layer attacks (old 2.2)

| ¶ (lines) | Action | Content change | Before → After |
|---|---|---|---|
| 166–172 | Rewrite | Split L7 into (i) request-cost attacks and (ii) low-and-slow connection holding. Slow attacks resemble legitimate slow clients (L7-03, abstract) | — → `sikora2021generator` |
| new §2.3.1 | Add | **Why volume-based detection struggles.** Count-in-window rules are evadable (L7-02, verified abstract quote). Impact depends on server architecture (L7-03 Table 7: Nginx 1.14.0 fell to only 2 of 11 slow attacks, Apache 2.4.17 to 11 of 11). Servers tolerate incomplete requests for minutes (L7-01: about 50% waited >360 s under Attack-1). This motivates the dual-plane exploration (heuristic + ML). | — → `sood2023slowtrack`, `sikora2021generator`, `tripathi2024delays` |
| 174 | Edit | Definition from L7-03 §2.1.1 (Slow GET/Slow Header; the `\r\n\r\n` mechanism). Hansen 2009 (F10) | Cloudflare → `sikora2021generator` |
| 176–180 | Edit | Step 2 qualified for thread-per-connection servers (F11) | — → `sikora2021generator` |
| 181–186 fig. | Keep | — | — |
| 187 | Rewrite | The timeout trade-off is kept and grounded:<br>• nginx `client_header_timeout` bounds the whole header, default 60 s;<br>• a sleep time above the server timeout leaves the attack effective only part of the time (L7-02 §4.5, verified quote);<br>• event-driven servers resist (L7-03);<br>• NAT caveat on per-IP limits (L7-03 §5).<br>Load balancing is kept as stated. | Invicti → `nginx_core`, `sood2023slowtrack`, `sikora2021generator` |
| 189–191 | Keep | Name it Slow POST = R.U.D.Y. (L7-03 §2.1.2) | — → `sikora2021generator` |
| 192–197 fig. | Keep | — | — |
| 198 | Edit | F12: per-read timeouts are defeated only by an attacker writing within the timeout | — → `sikora2021generator`, `nginx_core` |
| 200 | Rewrite | F15: buffering cited to `proxy_request_buffering`; L7-03's actual recommendations; per-server multi-signal detection as a deterministic alternative to count rules (L7-02: 99.92% recall on a live server, 15 s windows) | Sikora (misattributed) → `nginx_proxy`, `sikora2021generator`, `sood2023slowtrack` |
| new §2.3.4 | Add | **Slow Read** (small TCP receive window) is the slow attack that also took down Nginx (about 1,900 connections). Detection needs transport-level signals: window size, transfer rate, connection count (L7-03 §5). **HTTP/2 slow variants** and server tolerance in the wild (L7-01). Use Sikora's >6 s continuous-outage criterion as a definition of a successful attack. | — → `sikora2021generator`, `tripathi2024delays` |
| 202–203 | Keep | Reclassify (F9). HTTP/2 semantics from the current RFC | CVE → `nvd2023cve44487`, `rfc9113` |
| 205 | Keep | Add the 201 M rps peak | Cloudflare → `pardue2023rapidreset` |
| 206–211 fig. | Keep | — | — |
| 212 | Keep | Add: Cloudflare cut stream concurrency to 64 | — → `pardue2023rapidreset` |
| 214 | Edit | Mitigation as reported: count resets per connection, close with GOAWAY above a threshold, IP Jail | Kentik → `pardue2023rapidreset` |
| new §2.4 | Add | **Requirements** (one paragraph). Per-source attribution works for direct-path and low-and-slow attacks, not for reflection. Low-and-slow needs connection-state signals. Mitigation must act before the stack (§3.2). | (no new keys) |

### Section 3 intro and §3.1 Defence placement

| ¶ (lines) | Action | Content change | Before → After |
|---|---|---|---|
| 238 | Edit | Keep the 3.8 Tbps / 2 Bpps figures, labelled as vendor data, with a P1-04 caveat (industry and academic views differ). The ">100 M rps" goes to the Rapid Reset report (F13) | Cloudflare → `arora2024tbps`, `pardue2023rapidreset`, `hiesgen2024age` |
| 270–272 | Condense | Anycast definition and BGP mechanics | Wikipedia → `rfc4786`, `rizvi2022anycast` |
| 274 | Rewrite | Replace the 197 Tbps marketing figure with P2-05: BGP playbooks shift catchments, but changes take minutes (verified quote: no changes faster than 5 min). Host filtering works in seconds and cannot relieve a saturated uplink. | Indusface → `rizvi2022anycast` |
| 276 | Keep | Two-tier edge architecture. Optional: in-network line-rate mitigation (Jaqen, 380 Gbps) | — → (`liu2021jaqen`) |
| 278–283 | Keep | Fix typos. Add that event-driven Nginx resists connection-holding attacks | — → `sikora2021generator` |
| 285–289 | Condense | WAF concept and cloud behavioural WAFs, 2 paragraphs → 1. No numeric claims. | — |
| 291–307 | Condense or decide | JA3/JA4 are not part of the implemented system: condense to 2–3 sentences. Cite RFC 8701 for GREASE. If the detail stays, the primary JA3/JA4 sources must be added and verified first (decision D3). | — → (`rfc8701`) |

### §3.2 In-kernel packet filtering (Theme B; old 3.1 + 3.4)

| ¶ (lines) | Action | Content change | Before → After |
|---|---|---|---|
| 240–260 | Keep | Netfilter tables and chains | — |
| 261 | Edit | Modules described per the man page (F14). Add P2-02: limits calibrated on *average* rates drop >80% of a smart hub's benign traffic; peak-based limits drop <1.5% | oneuptime → `iptables_ext`, `feraudo2024mitigating` |
| 263 | Edit | Conntrack exhaustion via `nf_conntrack_max` | dev.to → `kernel_conntrack` |
| 265 | Rewrite | F16: measured scaling — ≤1.5 Mpps for iptables/nftables; with 3,000 rules latency rises 5× | — → `scholz2018performance` |
| 267 | Keep | `sk_buff` argument, now with a peer-reviewed source (P2-01 §V) | oneuptime → `scholz2018performance` |
| 310 | Keep | Add the review's synthesis: verifier constraints; median 2.4% CPU overhead across 54 studies | — → `kostopoulos2026ebpf` |
| 312–319 | Keep | Note that native-driver figures do not transfer to `veth` | — → `scholz2018performance` |
| 320–321 | Rewrite | F17: 7.2 Mpps per core vs ≤1.5 Mpps (P2-01, verified quote). Supplementary: Netdev 0x15 found eBPF at TC/XDP ahead of iptables/ipset, and no XDP/TC difference when packets go to the stack | Netdev → `scholz2018performance`, `hadisalim2021acl` |
| 323–327 | Condense | L4Drop as an industrial example of the same split (centralised detection, XDP enforcement): ELF rewriting, perf ring-buffer sampling, the verifier's loop limit, >8 M pps dropped on one server (F18). Gatebot named with its source or dropped. | — → `fabre2018l4drop`, (`majkowski2017gatebot`) |
| 329 | Edit | Keep the O(1)-maps argument. Add enforcement cost: a map update takes ≈4.5 µs (P2-02), or 5–20 µs (L7-05). Coordination in hybrid ML architectures costs 0.5–2 ms (L7-05, verified quote). Conclude that XDP is the established L4 baseline, and that detection latency, not enforcement, dominates the time to mitigate. | — → `feraudo2024mitigating`, `kostopoulos2026ebpf` |

### §3.3 Machine learning and sequential models (Theme C; old 3.5)

| ¶ (lines) | Action | Content change | Before → After |
|---|---|---|---|
| 331–338 | Edit | Keep the dataset names, cited through the survey. Fix TTL (F19). Move the critique to §3.4. | — → `goldschmidt2025network` |
| 340 | Rewrite | Within-dataset scores of about 99% are typical. Across datasets, MCC falls to 14.91% (P4-01, verified quote) | — → `cantone2024machine` |
| 342 | Rewrite | Classical baselines with evidence (F20). Trees beat or match DL on Bot-IoT DoS flows at about 10× the throughput (L7-04). A decision tree / majority vote on 8 server-side behavioural parameters detects Slowloris at 99.92% recall on a live server (L7-02). | — → `almarazrivera2022transport`, `sood2023slowtrack` |
| 344 | Remove | F21 | Sci. Rep. → — |
| 346 | Rewrite | LSTM/GRU definitions with their primary sources. Replace the 99.54% with L7-04: GRU 99.862% with timestamp features, 96.23% without; the recurrent models use sequence length 1. Introduce L7-01 as the sequence-of-events exemplar for slow L7: anomaly detection on frame-event sequences, learned from benign traffic, 100% recall at FPR 1.71–1.83%, detection in under 30 s, CPU below ≈7%. Optional DRL sentence. | ICAECOT → `hochreiter1997long`, `cho2014learning`, `almarazrivera2022transport`, `tripathi2024delays`, (`satpathy2025cloud`) |
| 348 | Keep + cite | Inference cost: LUCID's CNN classifies >55,000 samples/s, 40× faster than an LSTM at comparable F1. GRU at 2,864 flows/s versus DT at 30,362 (L7-04). | — → `doriguzzicorin2020lucid`, `almarazrivera2022transport` |
| 350–352 | Edit | F22: 28 per-flow features, INT8 CNN with early exit, 64-unit GRU in the controller | — → `karrakchou2025collaborative` |
| 354 | Rewrite | F1 99.91/99.90 kept. Scope: NS-3 on 1.5 Mbps links (F23, verified quote). Add L7-05: verifier limits keep in-kernel ML to 2 of 11 ML studies. This is the published rationale for user-space inference plus kernel enforcement, i.e. the thesis's dual-plane design. | themoonlight → `karrakchou2025collaborative`, `kostopoulos2026ebpf` |
| new | Add | **Open trade-offs for sequential L7 detection.** This positions the thesis's ongoing GRU work; Polish draft below. | `tripathi2024delays`, `doriguzzicorin2020lucid`, `almarazrivera2022transport`, `sood2023slowtrack`, `arp2022dos` |

**Proposed wording (new paragraph, §3.3):**
> „W niniejszej pracy model rekurencyjny GRU jest rozwijany jako eksperymentalny komponent płaszczyzny
> sterowania i oceniany względem reguł deterministycznych, co odpowiada zaleceniu porównywania modeli
> uczonych z prostymi punktami odniesienia [arp2022dos]. Przegląd literatury wskazuje cztery otwarte
> kompromisy projektowe. Po pierwsze, jednostka sekwencji: zakończone żądania odczytywane z logów
> serwera albo zdarzenia obserwowane w trakcie trwania połączenia — wykrywanie powolnych ataków HTTP/2
> w czasie rzeczywistym opiera się na sekwencjach zdarzeń protokołu, rejestrowanych zanim żądanie
> zostanie zakończone [tripathi2024delays]. Po drugie, sposób uczenia: model nadzorowany na znanych
> rodzinach ataków albo model normalnego zachowania uczony wyłącznie na ruchu legalnym
> [tripathi2024delays]. Po trzecie, koszt wnioskowania: modele rekurencyjne przetwarzają o rząd
> wielkości mniej próbek na sekundę niż sieci konwolucyjne i drzewa decyzyjne
> [doriguzzicorin2020lucid, almarazrivera2022transport]. Po czwarte, współpraca z heurystykami:
> wieloparametrowe reguły behawioralne osiągają wysoką czułość dla ataku Slowloris na serwerze
> działającym w sieci uczelnianej [sood2023slowtrack], dlatego model sekwencyjny musi wnosić
> informację, której reguły nie mają.”

### §3.4 Evaluation methodology (Theme D; new)

| ¶ | Content | Keys |
|---|---|---|
| 1 | Pitfalls of ML in security. Sampling bias in 90% and data snooping in 73% of 30 top-tier papers (verified quote). A one-feature packet-rate baseline beats Kitsune (TPR 0.996 vs 0.882 at FPR 0.001). | `arp2022dos` |
| 2 | Cross-dataset generalisation collapses (MCC 83.86% → 14.91%), including CIC Slowloris and Slowhttptest classes; dataset-specific constants. | `cantone2024machine` |
| 3 | Dataset practice:<br>• CIC-IDS2017 is used by only 29% of papers;<br>• combining datasets is "incorrect by design";<br>• only 1 in 5 datasets has real traffic;<br>• use temporal splits, multiple runs and significance tests. | `goldschmidt2025network` |
| 4 | Testbeds and live evaluation:<br>• 81.4–87% of eBPF security studies are testbed-only (verified quote on synthetic traffic generators);<br>• L7-01 and L7-02 evaluated on live servers;<br>• L7-03's generator and its outage criterion;<br>• optional: MoonGen for high-rate generation;<br>• optional: Panggabean as an example of 0-error results on mixed datasets. | `kostopoulos2026ebpf`, `tripathi2024delays`, `sood2023slowtrack`, `sikora2021generator`, (`emmerich2015moongen`), (`panggabean2024intelligent`) |

### Section 4 Wnioski z przeglądu stanu wiedzy (fills the empty heading, l.355)

Five short paragraphs or bullets, without new citations (they summarise §2–3):
1. Host-level XDP filtering is mature and measured. Its limits are reflection attacks and saturated uplinks.
2. Low-and-slow detection in the literature relies on connection- or server-state signals and on
   protocol-event sequences, not on volume.
3. Open, peer-reviewed evidence that recurrent models help against slow HTTP attacks is thin. This is the
   finding of the targeted search (`docs/targeted_literature_selection.md` §3).
4. Credible evaluation needs simple baselines, controlled data generation and live or multi-run
   validation.
5. Positioning: a dual-plane system, with XDP enforcement plus deterministic heuristics and an
   experimental sequential model, evaluated against each other under these rules.

---

## 4. Paper-to-subsection mapping

● = primary source for a claim in that subsection; ○ = supporting.

| Paper | 2 intro | 2.1 | 2.2 | 2.3 | 3 intro / 3.1 | 3.2 | 3.3 | 3.4 | Anchoring fact (verified in Phase 1/2 text) |
|---|---|---|---|---|---|---|---|---|---|
| P1-01 Bock | | ● | ● | | | | | | ≥100× amplification from 386,187 IPs |
| P1-02 Nawrocki | | ● | ● | | | | | | 96% of IXP-seen attacks invisible to honeypots; 1:16k sampling |
| P1-03 Nawrocki (opt.) | | ○ | | | | | | | QUIC handshake floods |
| P1-04 Hiesgen | ● | ○ | ● | | ○ | | | | 4 of 5 direct-path observatories trend upward; vantage points diverge |
| L7-03 Sikora | | ● | | ● | ○ | | | ○ | Nginx: 2 of 11 slow attacks effective; Slow Read at about 1,900 connections; >6 s outage criterion |
| L7-02 Sood & Hubballi | | ● | | ● | | | ● | ○ | Count rules evadable; 99.92% recall live; sleep time above timeout |
| L7-01 Tripathi | | ● | | ● | | | ● | ○ | Event sequences; FPR 1.71–1.83%; <30 s; CPU <≈7% |
| P2-05 Rizvi | | | ○ | | ● | | | | BGP playbooks; ≥5 min per change |
| P3-02 Ding | | | ● | | | | | | FPR 8%; TPR 36% at a 5% attack share |
| P2-01 Scholz | | | | | | ● | | | 7.2 Mpps vs ≤1.5 Mpps; before `sk_buff` |
| P2-02 Feraudo | | | | | | ● | | | Map update ≈4.5 µs; average-based limits drop >80% of a hub's benign traffic |
| L7-05 Kostopoulos | | | | | | ● | ● | ● | Median 2.4% CPU; 0.5–2 ms hybrid ML; in-kernel ML 2/11; 81.4–87% testbed-only |
| L7-04 Almaraz-Rivera | | | | | | | ● | | Trees ≥ DL; GRU 96.23% without timestamps; sequence length 1 |
| P3-01 LUCID | | | | | | | ● | | >55,000 samples/s; 40× faster than LSTM |
| P2-04 Karrakchou | | | | | | | ● | | F1 99.91/99.90; NS-3 on 1.5 Mbps links |
| P3-04 Arp | ○ | | | | | | ○ | ● | 90% / 73% pitfall prevalence; baseline beats Kitsune |
| P4-01 Cantone | | | | | | | ● | ● | MCC 83.86% → 14.91% |
| P4-02 Goldschmidt | | | | | | | ○ | ● | 29%; "incorrect by design" |
| P2-03 Jaqen (opt.) | | | | | ○ | | | | 380 Gbps, in-network |
| P4-03 MoonGen (opt.) | | | | | | | | ○ | High-rate generation |
| P3-03 Panggabean (opt.) | | | | | | | | ○ | 0 errors on mixed datasets |

All 12 papers selected in Phase 2 are used. The non-peer-reviewed sources that remain are standards (S)
and four labelled grey-literature items: the Rapid Reset report, the 3.8 Tbps report, L4Drop, and the
Netdev slides as supplementary evidence.

---

## 5. Proposed bibliography

### 5.1 Key migration (old → new)

| Old key | New key(s) |
|---|---|
| Detecting and Mitigating DDoS Attacks with AI: A Survey | `hiesgen2024age` |
| SYN flood DDoS attack - Cloudflare | *(removed)* |
| DDoS Protection and Mitigation: A 2026 Guide… | l.137 `hiesgen2024age`; l.147 `nawrocki2021far`, `rfc7011`, `rfc8955`; l.214 `pardue2023rapidreset` |
| DNS amplification attack | `nawrocki2021far`, `rfc6891` |
| Slowloris DDoS attack | `sikora2021generator` |
| Slowloris attack | `sikora2021generator`, `sood2023slowtrack`, `nginx_core` |
| Generator of Slow Denial-of-Service Cyber Attacks | `sikora2021generator` |
| CVE-2023-44487 | `nvd2023cve44487`, `rfc9113` |
| HTTP/2 Rapid Reset: deconstructing… | `pardue2023rapidreset` |
| How Cloudflare auto-mitigated world record 3.8 Tbps… | `arora2024tbps` |
| How to Set Up Rate Limiting with iptables… | `iptables_ext`, `feraudo2024mitigating` |
| Building a High-Performance DDoS Mitigation Pipeline… | `kernel_conntrack` |
| How to use eBPF XDP for DDoS protection… | `scholz2018performance` |
| Anycast | `rfc4786`, `rizvi2022anycast` |
| Top F5 Alternatives for WAF in 2026 | *(removed)* |
| Linux ACL Performance Analysis | `scholz2018performance`, `hadisalim2021acl` |
| Cloud-based DDoS detection … (DRL) | *(removed; optional `satpathy2025cloud` for the DRL sentence only)* |
| Enhanced DDoS Attack Detection Using Advanced DL… | `almarazrivera2022transport`, `doriguzzicorin2020lucid` |
| collaborative-p4-sdn-… | `karrakchou2025collaborative` |
| Carpet-bombing Attacks Highlight… | `hiesgen2024age` |
| The ultimate weapon against DDoS — BGP Flowspec | `rfc8955` |

Keys are ASCII. Paper keys are the corpus keys from `docs/sota/corpus*/selected.json`, so every entry can
be traced to its verified text.

### 5.2 Rules for the block

* **Mechanism.** Keep `thebibliography`, since the draft has no BibTeX toolchain. Use `{99}` for the label
  width.
* **Order.** IEEE order is the order of first citation in §2–3. The block below already follows the
  blueprint's planned order. After the rewrite, the Appendix A checker must report `OK`.
* **Optional entries.** Entries marked `% OPCJONALNE` are removed if the corresponding sentence is not
  written, because `thebibliography` prints uncited items.
* **Formatting.** IEEE abbreviations are in English (vol., no., pp., Art. no., accessed). DOIs are links,
  web sources carry an access date, and en-dashes `--` are used in page ranges.
* **Characters.** Diacritics (Wählisch, Chudá, Martínez-del-Rincón, Merriënboer, Gallenmüller) are typed
  as UTF-8. They render correctly under the draft's `inputenc` + `T1` with pdfLaTeX (checked visually).

### 5.3 The block (50 entries; 43 core and 7 optional, tested in §6)

```latex
\begin{thebibliography}{99}
% Kolejność pozycji = kolejność pierwszego cytowania w tekście (styl IEEE).
% Pozycje oznaczone "OPCJONALNE" usunąć, jeśli nie zostaną zacytowane
% (thebibliography drukuje wszystkie pozycje, także niecytowane).

\bibitem{hiesgen2024age}
R.~Hiesgen \textit{et al.}, ``The Age of DDoScovery: An Empirical Comparison of Industry and Academic DDoS Assessments,'' in \textit{Proc. 2024 ACM Internet Measurement Conference (IMC '24)}, Nov. 2024, pp.~259--279, doi: \href{https://doi.org/10.1145/3646547.3688451}{10.1145/3646547.3688451}.

\bibitem{rfc4732}
M.~Handley, Ed., E.~Rescorla, Ed., and IAB, ``Internet Denial-of-Service Considerations,'' RFC~4732, Internet Engineering Task Force, Dec. 2006, doi: \href{https://doi.org/10.17487/RFC4732}{10.17487/RFC4732}.

\bibitem{nawrocki2021far}
M.~Nawrocki, M.~Jonker, T.~C.~Schmidt, and M.~Wählisch, ``The Far Side of DNS Amplification: Tracing the DDoS Attack Ecosystem from the Internet Core,'' in \textit{Proc. 21st ACM Internet Measurement Conference (IMC '21)}, Nov. 2021, pp.~419--434, doi: \href{https://doi.org/10.1145/3487552.3487835}{10.1145/3487552.3487835}.

\bibitem{bock2021weaponizing}
K.~Bock, A.~Alaraj, Y.~Fax, K.~Hurley, E.~Wustrow, and D.~Levin, ``Weaponizing Middleboxes for TCP Reflected Amplification,'' in \textit{Proc. 30th USENIX Security Symposium (USENIX Security 21)}, Aug. 2021, pp.~3345--3361. [Online]. Available: \url{https://www.usenix.org/conference/usenixsecurity21/presentation/bock}

\bibitem{rfc4987}
W.~Eddy, ``TCP SYN Flooding Attacks and Common Mitigations,'' RFC~4987, Internet Engineering Task Force, Aug. 2007, doi: \href{https://doi.org/10.17487/RFC4987}{10.17487/RFC4987}.

\bibitem{nawrocki2021quicsand}
% OPCJONALNE (taksonomia: wyczerpanie stanu w nowych protokołach)
M.~Nawrocki, R.~Hiesgen, T.~C.~Schmidt, and M.~Wählisch, ``QUICsand: Quantifying QUIC Reconnaissance Scans and DoS Flooding Events,'' in \textit{Proc. 21st ACM Internet Measurement Conference (IMC '21)}, Nov. 2021, pp.~283--291, doi: \href{https://doi.org/10.1145/3487552.3487840}{10.1145/3487552.3487840}.

\bibitem{pardue2023rapidreset}
L.~Pardue and J.~Desgats, ``HTTP/2 Rapid Reset: deconstructing the record-breaking attack,'' \textit{Cloudflare Blog}, Oct. 10, 2023. [Online]. Available: \url{https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/} (accessed: Oct. 28, 2026).

\bibitem{sikora2021generator}
M.~Sikora, R.~Fujdiak, K.~Kuchar, E.~Holasova, and J.~Misurec, ``Generator of Slow Denial-of-Service Cyber Attacks,'' \textit{Sensors}, vol.~21, no.~16, Art. no.~5473, Aug. 2021, doi: \href{https://doi.org/10.3390/s21165473}{10.3390/s21165473}.

\bibitem{sood2023slowtrack}
S.~Sood and N.~Hubballi, ``SlowTrack: Detecting Slow Rate Denial of Service Attacks against HTTP with Behavioral Parameters,'' \textit{The Journal of Supercomputing}, vol.~80, no.~2, pp.~1788--1817, Jan. 2024, doi: \href{https://doi.org/10.1007/s11227-023-05453-3}{10.1007/s11227-023-05453-3}.

\bibitem{tripathi2024delays}
N.~Tripathi, ``Delays Have Dangerous Ends: Slow HTTP/2 DoS Attacks Into the Wild and Their Real-Time Detection Using Event Sequence Analysis,'' \textit{IEEE Transactions on Dependable and Secure Computing}, vol.~21, no.~3, pp.~1244--1256, May 2024, doi: \href{https://doi.org/10.1109/TDSC.2023.3276062}{10.1109/TDSC.2023.3276062}.

\bibitem{rfc9293}
W.~Eddy, Ed., ``Transmission Control Protocol (TCP),'' RFC~9293, Internet Engineering Task Force, Aug. 2022, doi: \href{https://doi.org/10.17487/RFC9293}{10.17487/RFC9293}.

\bibitem{rfc7323}
D.~Borman, B.~Braden, V.~Jacobson, and R.~Scheffenegger, Ed., ``TCP Extensions for High Performance,'' RFC~7323, Internet Engineering Task Force, Sep. 2014, doi: \href{https://doi.org/10.17487/RFC7323}{10.17487/RFC7323}.

\bibitem{linux_syncookies}
The Linux Kernel Developers, ``net/ipv4/syncookies.c (\texttt{cookie\_init\_timestamp}),'' Linux kernel source tree. [Online]. Available: \url{https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/syncookies.c} (accessed: Oct. 28, 2026).

\bibitem{rfc3954}
B.~Claise, Ed., ``Cisco Systems NetFlow Services Export Version 9,'' RFC~3954, Internet Engineering Task Force, Oct. 2004, doi: \href{https://doi.org/10.17487/RFC3954}{10.17487/RFC3954}.

\bibitem{rfc7011}
B.~Claise, Ed., B.~Trammell, Ed., and P.~Aitken, ``Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information,'' RFC~7011, Internet Engineering Task Force, Sep. 2013, doi: \href{https://doi.org/10.17487/RFC7011}{10.17487/RFC7011}.

\bibitem{rfc8955}
C.~Loibl, S.~Hares, R.~Raszuk, D.~McPherson, and M.~Bacher, ``Dissemination of Flow Specification Rules,'' RFC~8955, Internet Engineering Task Force, Dec. 2020, doi: \href{https://doi.org/10.17487/RFC8955}{10.17487/RFC8955}.

\bibitem{rfc6891}
J.~Damas, M.~Graff, and P.~Vixie, ``Extension Mechanisms for DNS (EDNS(0)),'' RFC~6891, Internet Engineering Task Force, Apr. 2013, doi: \href{https://doi.org/10.17487/RFC6891}{10.17487/RFC6891}.

\bibitem{rfc8482}
J.~Abley, O.~Gudmundsson, M.~Majkowski, and E.~Hunt, ``Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY,'' RFC~8482, Internet Engineering Task Force, Jan. 2019, doi: \href{https://doi.org/10.17487/RFC8482}{10.17487/RFC8482}.

\bibitem{rfc5358}
J.~Damas and F.~Neves, ``Preventing Use of Recursive Nameservers in Reflector Attacks,'' RFC~5358 (BCP~140), Internet Engineering Task Force, Oct. 2008, doi: \href{https://doi.org/10.17487/RFC5358}{10.17487/RFC5358}.

\bibitem{rfc2827}
P.~Ferguson and D.~Senie, ``Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing,'' RFC~2827 (BCP~38), Internet Engineering Task Force, May 2000, doi: \href{https://doi.org/10.17487/RFC2827}{10.17487/RFC2827}.

\bibitem{rizvi2022anycast}
A.~S.~M.~Rizvi, L.~Bertholdo, J.~Ceron, and J.~Heidemann, ``Anycast Agility: Network Playbooks to Fight DDoS,'' in \textit{Proc. 31st USENIX Security Symposium (USENIX Security 22)}, Aug. 2022, pp.~4201--4218. [Online]. Available: \url{https://www.usenix.org/conference/usenixsecurity22/presentation/rizvi}

\bibitem{rfc4786}
J.~Abley and K.~Lindqvist, ``Operation of Anycast Services,'' RFC~4786 (BCP~126), Internet Engineering Task Force, Dec. 2006, doi: \href{https://doi.org/10.17487/RFC4786}{10.17487/RFC4786}.

\bibitem{ding2021tracking}
D.~Ding, M.~Savi, and D.~Siracusa, ``Tracking Normalized Network Traffic Entropy to Detect DDoS Attacks in P4,'' \textit{IEEE Transactions on Dependable and Secure Computing}, vol.~19, no.~6, pp.~4019--4031, Nov. 2022, doi: \href{https://doi.org/10.1109/TDSC.2021.3116345}{10.1109/TDSC.2021.3116345}.

\bibitem{rfc7999}
T.~King, C.~Dietzel, J.~Snijders, G.~Doering, and G.~Hankins, ``BLACKHOLE Community,'' RFC~7999, Internet Engineering Task Force, Oct. 2016, doi: \href{https://doi.org/10.17487/RFC7999}{10.17487/RFC7999}.

\bibitem{nginx_core}
NGINX, ``Module ngx\_http\_core\_module (\texttt{client\_header\_timeout}, \texttt{client\_body\_timeout}),'' nginx documentation. [Online]. Available: \url{https://nginx.org/en/docs/http/ngx_http_core_module.html} (accessed: Oct. 28, 2026).

\bibitem{nginx_proxy}
NGINX, ``Module ngx\_http\_proxy\_module (\texttt{proxy\_request\_buffering}),'' nginx documentation. [Online]. Available: \url{https://nginx.org/en/docs/http/ngx_http_proxy_module.html} (accessed: Oct. 28, 2026).

\bibitem{nvd2023cve44487}
National Institute of Standards and Technology, ``CVE-2023-44487,'' National Vulnerability Database, Oct. 10, 2023. [Online]. Available: \url{https://nvd.nist.gov/vuln/detail/CVE-2023-44487} (accessed: Oct. 28, 2026).

\bibitem{rfc9113}
M.~Thomson, Ed., and C.~Benfield, Ed., ``HTTP/2,'' RFC~9113, Internet Engineering Task Force, Jun. 2022, doi: \href{https://doi.org/10.17487/RFC9113}{10.17487/RFC9113}.

\bibitem{arora2024tbps}
M.~Arora, S.~Bohrer, O.~Yoachimik, C.~Doucette, A.~Forster, and N.~Wood, ``How Cloudflare auto-mitigated a world record 3.8 Tbps DDoS attack,'' \textit{Cloudflare Blog}, Oct. 2, 2024. [Online]. Available: \url{https://blog.cloudflare.com/how-cloudflare-auto-mitigated-world-record-3-8-tbps-ddos-attack/} (accessed: Oct. 28, 2026).

\bibitem{liu2021jaqen}
% OPCJONALNE (obrona w sieci: przełączniki programowalne)
Z.~Liu \textit{et al.}, ``Jaqen: A High-Performance Switch-Native Approach for Detecting and Mitigating Volumetric DDoS Attacks with Programmable Switches,'' in \textit{Proc. 30th USENIX Security Symposium (USENIX Security 21)}, Aug. 2021, pp.~3829--3846. [Online]. Available: \url{https://www.usenix.org/conference/usenixsecurity21/presentation/liu-zaoxing}

\bibitem{rfc8701}
% OPCJONALNE (tylko jeśli akapit o JA3/JA4 i GREASE pozostanie)
D.~Benjamin, ``Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility,'' RFC~8701, Internet Engineering Task Force, Jan. 2020, doi: \href{https://doi.org/10.17487/RFC8701}{10.17487/RFC8701}.

\bibitem{iptables_ext}
Netfilter Project, ``iptables-extensions(8): list of extensions in the standard iptables distribution (\texttt{limit}, \texttt{hashlimit}, \texttt{connlimit}),'' manual page, iptables~1.8.3. [Online]. Available: \url{https://ipset.netfilter.org/iptables-extensions.man.html} (accessed: Oct. 28, 2026).

\bibitem{feraudo2024mitigating}
A.~Feraudo, D.~A.~Popescu, P.~Yadav, R.~Mortier, and P.~Bellavista, ``Mitigating IoT Botnet DDoS Attacks through MUD and eBPF based Traffic Filtering,'' in \textit{Proc. 25th International Conference on Distributed Computing and Networking (ICDCN '24)}, Jan. 2024, pp.~164--173, doi: \href{https://doi.org/10.1145/3631461.3631549}{10.1145/3631461.3631549}.

\bibitem{kernel_conntrack}
The Linux Kernel Documentation, ``Netfilter Conntrack Sysfs variables (\texttt{nf\_conntrack\_max}).'' [Online]. Available: \url{https://docs.kernel.org/networking/nf_conntrack-sysctl.html} (accessed: Oct. 28, 2026).

\bibitem{scholz2018performance}
D.~Scholz, D.~Raumer, P.~Emmerich, A.~Kurtz, K.~Lesiak, and G.~Carle, ``Performance Implications of Packet Filtering with Linux eBPF,'' in \textit{Proc. 30th International Teletraffic Congress (ITC 30)}, Sep. 2018, pp.~209--217, doi: \href{https://doi.org/10.1109/ITC30.2018.00039}{10.1109/ITC30.2018.00039}.

\bibitem{kostopoulos2026ebpf}
S.~Kostopoulos, P.~Tsakonas, and E.~K.~Markakis, ``eBPF-Based Cybersecurity Mechanisms: A Systematic Literature Review,'' \textit{International Journal of Information Security}, vol.~25, no.~5, Art. no.~150, Aug. 2026, doi: \href{https://doi.org/10.1007/s10207-026-01326-x}{10.1007/s10207-026-01326-x}.

\bibitem{hadisalim2021acl}
J.~Hadi~Salim and N.~Bitar, ``Linux ACL Performance Analysis,'' presented at \textit{Netdev 0x15, The Technical Conference on Linux Networking}, Jul. 2021. [Online]. Available: \url{https://netdevconf.info/0x15/slides/7/LinuxACLPerformanceAnalysis.pdf}

\bibitem{fabre2018l4drop}
A.~Fabre, ``L4Drop: XDP DDoS Mitigations,'' \textit{Cloudflare Blog}, Nov. 28, 2018. [Online]. Available: \url{https://blog.cloudflare.com/l4drop-xdp-ebpf-based-ddos-mitigations/} (accessed: Oct. 28, 2026).

\bibitem{majkowski2017gatebot}
% OPCJONALNE (tylko jeśli Gatebot pozostanie w tekście)
M.~Majkowski, ``Meet Gatebot -- a bot that allows us to sleep,'' \textit{Cloudflare Blog}, Sep. 25, 2017. [Online]. Available: \url{https://blog.cloudflare.com/meet-gatebot-a-bot-that-allows-us-to-sleep/} (accessed: Oct. 28, 2026).

\bibitem{goldschmidt2025network}
P.~Goldschmidt and D.~Chudá, ``Network Intrusion Datasets: A Survey, Limitations, and Recommendations,'' \textit{Computers \& Security}, vol.~156, Art. no.~104510, Sep. 2025, doi: \href{https://doi.org/10.1016/j.cose.2025.104510}{10.1016/j.cose.2025.104510}.

\bibitem{cantone2024machine}
M.~Cantone, C.~Marrocco, and A.~Bria, ``Machine Learning in Network Intrusion Detection: A Cross-Dataset Generalization Study,'' \textit{IEEE Access}, vol.~12, pp.~144489--144508, 2024, doi: \href{https://doi.org/10.1109/ACCESS.2024.3472907}{10.1109/ACCESS.2024.3472907}.

\bibitem{almarazrivera2022transport}
J.~G.~Almaraz-Rivera, J.~A.~Perez-Diaz, and J.~A.~Cantoral-Ceballos, ``Transport and Application Layer DDoS Attacks Detection to IoT Devices by Using Machine Learning and Deep Learning Models,'' \textit{Sensors}, vol.~22, no.~9, Art. no.~3367, Apr. 2022, doi: \href{https://doi.org/10.3390/s22093367}{10.3390/s22093367}.

\bibitem{hochreiter1997long}
S.~Hochreiter and J.~Schmidhuber, ``Long Short-Term Memory,'' \textit{Neural Computation}, vol.~9, no.~8, pp.~1735--1780, Nov. 1997, doi: \href{https://doi.org/10.1162/neco.1997.9.8.1735}{10.1162/neco.1997.9.8.1735}.

\bibitem{cho2014learning}
K.~Cho, B.~van~Merriënboer, C.~Gulcehre, D.~Bahdanau, F.~Bougares, H.~Schwenk, and Y.~Bengio, ``Learning Phrase Representations using RNN Encoder--Decoder for Statistical Machine Translation,'' in \textit{Proc. 2014 Conference on Empirical Methods in Natural Language Processing (EMNLP)}, 2014, pp.~1724--1734, doi: \href{https://doi.org/10.3115/v1/D14-1179}{10.3115/v1/D14-1179}.

\bibitem{satpathy2025cloud}
% OPCJONALNE (jedno zdanie o DRL/TD3/SHAP; inaczej usunąć)
S.~Satpathy, U.~Tripathy, and P.~K.~Swain, ``Cloud-based DDoS detection using hybrid feature selection with deep reinforcement learning (DRL),'' \textit{Scientific Reports}, vol.~15, Art. no.~36546, Oct. 2025, doi: \href{https://doi.org/10.1038/s41598-025-18857-3}{10.1038/s41598-025-18857-3}.

\bibitem{doriguzzicorin2020lucid}
R.~Doriguzzi-Corin, S.~Millar, S.~Scott-Hayward, J.~Martínez-del-Rincón, and D.~Siracusa, ``Lucid: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection,'' \textit{IEEE Transactions on Network and Service Management}, vol.~17, no.~2, pp.~876--889, Jun. 2020, doi: \href{https://doi.org/10.1109/TNSM.2020.2971776}{10.1109/TNSM.2020.2971776}.

\bibitem{karrakchou2025collaborative}
O.~Karrakchou, A.~Zniber, A.~Sebbar, and M.~Ghogho, ``Collaborative P4-SDN DDoS Detection and Mitigation with Early-Exit Neural Networks,'' in \textit{Proc. 2025 IEEE Global Communications Conference (GLOBECOM)}, Dec. 2025, pp.~6081--6086, doi: \href{https://doi.org/10.1109/GLOBECOM59602.2025.11431920}{10.1109/GLOBECOM59602.2025.11431920}.

\bibitem{arp2022dos}
D.~Arp \textit{et al.}, ``Dos and Don'ts of Machine Learning in Computer Security,'' in \textit{Proc. 31st USENIX Security Symposium (USENIX Security 22)}, Aug. 2022, pp.~3971--3988. [Online]. Available: \url{https://www.usenix.org/conference/usenixsecurity22/presentation/arp}

\bibitem{emmerich2015moongen}
% OPCJONALNE (generowanie ruchu wolumetrycznego w testbedach)
P.~Emmerich, S.~Gallenmüller, D.~Raumer, F.~Wohlfart, and G.~Carle, ``MoonGen: A Scriptable High-Speed Packet Generator,'' in \textit{Proc. 2015 Internet Measurement Conference (IMC '15)}, Oct. 2015, pp.~275--287, doi: \href{https://doi.org/10.1145/2815675.2815692}{10.1145/2815675.2815692}.

\bibitem{panggabean2024intelligent}
% OPCJONALNE (przykład raportowania wyników na łączonych zbiorach danych)
C.~Panggabean, C.~Venkatachalam, P.~Shah, S.~John, P.~Renuka~Devi, and S.~Venkatachalam, ``Intelligent DoS and DDoS Detection: A Hybrid GRU-NTM Approach to Network Security,'' in \textit{Proc. 5th International Conference on Smart Electronics and Communication (ICOSEC)}, Sep. 2024, pp.~658--665, doi: \href{https://doi.org/10.1109/ICOSEC61587.2024.10722438}{10.1109/ICOSEC61587.2024.10722438}.

\end{thebibliography}
```

---

## 6. LaTeX integrity verification

### 6.1 What was tested

A script (Appendix B) built two scratch variants of the unmodified `thesis/main.tex`:
1. every old `\cite` key replaced per §5.1, the bibliography replaced by §5.3, and the two
   `fig:placeholder` labels renamed;
2. the same, plus every new key cited once at the start of §2 in block order, to test numbering.

Each was compiled twice with `pdflatex -interaction=nonstopmode`. The repository was not touched.

| Check | Draft (baseline) | Proposed (both variants) |
|---|---|---|
| LaTeX errors | 12 (UTF-8 in listings, l.633/636) | 12, **the same pre-existing errors**; none new |
| Undefined citations after pass 2 | 0 | **0** |
| Multiply-defined labels | 1 (`fig:placeholder`) | **0** |
| Missing glyphs (Polish/diacritics) | 0 | **0** |
| IEEE first-citation order (Appendix A) | FAIL (mismatch at [9]; 1 orphan) | **OK** (50 cited, 50 `\bibitem`s; order variant) |
| Overfull boxes in the bibliography | — | **0** |
| Pages | 37 | 40 (bibliography grows from 21 to 50 entries) |

The rendered bibliography (pp. 36–40 of the test PDF) was inspected. Diacritics, URLs, DOIs and the
2-digit label column render correctly.

### 6.2 What the rewrite must preserve

* **Environments.** Untouched outside §2–4, and the rewrite introduces none beyond `itemize`/`enumerate`
  and one `table` + `tabularx` (Table 1):
  - all 6 `lstlisting`s (l.397–923);
  - `\includepdf` (l.380);
  - the `equation` (l.300–302);
  - the display math (l.108).
* **Packages.** None added. `tabularx`, `booktabs`, `hyperref` (`\url`, `\href`) and `amsmath` are
  already loaded.
* **Figures.** The 6 `figure` environments keep their files, widths and captions. Only two labels change
  (`fig:tcp_handshake`, `fig:udp_flood`), and one caption says RFC 9293 instead of RFC 793. No
  `\ref{fig:…}` exists, so nothing else changes.
* **Cross-references.** `\label{Netflow}` and its two `\ref`s stay valid as long as l.139–146 remain in
  §2.2.2 (planned).
* **Edit discipline.** One `\cite{}` per claim position. Keys contain no spaces. No `#` or `%` in URLs.

### 6.3 Optional, separate fix: make the draft build without errors

The 12 pre-existing errors disappear when a `literate` table for Polish letters is added to `\lstset`
(tested: 0 errors, 37 pages, and the listing comments render as "Przekształcamy…pewności"). The fix is
in the preamble, outside the SotA scope, and needs approval (decision D5):

```latex
    rulecolor=\color{codegray},          % kolor ramki (dodany przecinek)
    literate={ą}{{\k{a}}}1 {ć}{{\'c}}1 {ę}{{\k{e}}}1 {ł}{{\l{}}}1 {ń}{{\'n}}1 {ó}{{\'o}}1 {ś}{{\'s}}1 {ź}{{\'z}}1 {ż}{{\.z}}1
             {Ą}{{\k{A}}}1 {Ć}{{\'C}}1 {Ę}{{\k{E}}}1 {Ł}{{\L{}}}1 {Ń}{{\'N}}1 {Ó}{{\'O}}1 {Ś}{{\'S}}1 {Ź}{{\'Z}}1 {Ż}{{\.Z}}1
```

---

## 7. Implementation sequence (after approval) and open decisions

**Sequence.** One commit per step on `feat/hg1c`. Each step must leave the pdfLaTeX build at ≤12 errors
(0 if D5 is approved) with 0 undefined citations.

1. Bibliography block, key migration and the two labels (mechanical; tested above).
2. §2: taxonomy, corrections F1–F12 and the new L7 subsections.
3. §3.1–3.2: placement and in-kernel filtering (F13–F18).
4. §3.3–3.4: ML and methodology (F19–F23, the new paragraphs).
5. §4: conclusions.
6. Final pass: Appendix A order check, rendered-PDF review, and a diff confined to l.71–355 and the
   bibliography.

**Decisions for you:**

| ID | Question | Recommendation |
|---|---|---|
| D1 | Keep the 4 retained grey/official sources (NVD, 2 Cloudflare reports, L4Drop) as labelled grey literature? | Yes. They are primary records with no academic equivalent |
| D2 | Which optional entries to include (QUICsand, Jaqen, RFC 8701, Gatebot, Satpathy, MoonGen, Panggabean)? | QUICsand and Jaqen yes; the others only if their sentence stays |
| D3 | JA3/JA4 detail in §3.1: condense, or keep and add verified primary sources? | Condense: it is not part of the implemented system |
| D4 | `thebibliography` (tested) or BibTeX + `IEEEtran.bst`? | `thebibliography`, to keep the current toolchain |
| D5 | Apply the `listings` UTF-8 fix (§6.3)? | Yes, as its own commit |
| D6 | Rename section 2 to "…o technikach ataków DDoS"? | Optional |
| D7 | "Robert Hansen, 2009" (F10): drop, or supply a primary source? | Drop unless you have the source |

---

## Appendix A. IEEE order checker (run on the edited `thesis/main.tex`)

```python
"""Check IEEE ordering: the n-th \bibitem must be the n-th distinct key cited in the text,
and every cited key must exist (and every \bibitem must be cited)."""
import re, sys
t = open(sys.argv[1], encoding="utf-8").read()
body, bib = t.split("\\begin{thebibliography}", 1)
body = re.sub(r"(?m)(?<!\\)%.*$", "", body)          # drop comments
cited = []
for grp in re.findall(r"\\cite\{([^}]*)\}", body, flags=re.S):
    for k in (" ".join(x.split()) for x in grp.split(",")):
        if k not in cited: cited.append(k)
items = [" ".join(k.split()) for k in re.findall(r"\\bibitem\{([^}]*)\}", bib, flags=re.S)]
ok = True
for k in cited:
    if k not in items: print("cited but no \\bibitem:", k); ok = False
for k in items:
    if k not in cited: print("\\bibitem never cited:", k); ok = False
for i, (a, b) in enumerate(zip(cited, [k for k in items if k in cited]), 1):
    if a != b: print(f"order mismatch at [{i}]: first cited {a!r}, bibitem {b!r}"); ok = False; break
print("OK" if ok else "FAIL", f"({len(cited)} cited, {len(items)} bibitems)")
sys.exit(0 if ok else 1)
```

## Appendix B. How the compile test was run

```bash
pdflatex -interaction=nonstopmode main.tex && pdflatex -interaction=nonstopmode main.tex
```

```bash
grep -c '^!' main.log; grep -c 'Citation.*undefined' main.log; grep -c 'multiply defined' main.log; grep -c 'Missing character' main.log
```

These ran in scratch copies of `thesis/` with TeX Live 2023 (pdfTeX 1.40.25, Debian packages): `texlive-latex-base`,
`-latex-recommended`, `-latex-extra`, `-lang-polish` and `-fonts-recommended`. The variant generator
replaced the keys per §5.1 and the bibliography per §5.3. It refused to run if any draft key was left
unmapped.
