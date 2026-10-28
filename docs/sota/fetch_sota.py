#!/usr/bin/env python3
"""Retrieve, store and verify the literature for the Phase 1 state-of-the-art review.

Four subcommands, run in this order:

  plan    Print the search protocol (queries per pillar, seed titles, filters) as Markdown.
  search  Query arXiv, OpenAlex and Semantic Scholar with the per-pillar queries; keep
          2021-2026 records plus resolved foundational seeds; merge duplicates by DOI,
          arXiv id and title; tag each record with a venue tier; write
          corpus/candidates.json for screening.
  fetch   For the papers screened into corpus/selected.json, store the abstract and,
          where an open-access PDF exists, its full text (pdftotext), with URL, time
          and SHA-256 in corpus/manifest.json. Crossref fills the IEEE citation.
  verify  Check every quote in docs/sota_broad_review.md against the stored text of
          its paper. A quote passes only if it occurs contiguously, either exactly (up
          to whitespace) or after typographic normalisation (ligatures, curly quotes,
          dashes, line-end hyphenation). Anything else fails.

HTTP uses the standard library only (urllib); PDFs are converted with pdftotext.
Seed titles are lookup queries, not citations: a seed enters the corpus only when an
API returns a record whose title matches it; unresolved seeds are logged and dropped.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import difflib
import hashlib
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CORPUS = HERE / "corpus"
DEFAULT_REVIEW = HERE.parent / "sota_broad_review.md"

YEAR_MIN, YEAR_MAX = 2021, 2026
USER_AGENT = "fetch_sota/1.0 (engineering-thesis literature review; python-urllib)"

PILLARS = {
    "P1": "Modern attack vectors and dynamics",
    "P2": "Mitigation paradigms and architectures",
    "P3": "Detection algorithms and ML/DL models",
    "P4": "Empirical evaluation, testbeds and benchmarks",
}

# Keyword queries restricted to 2021-2026. arXiv ANDs the terms as phrases; OpenAlex
# and Semantic Scholar receive them as one free-text query.
QUERIES = [
    ("P1", ["reflection", "amplification", "DDoS"]),
    ("P1", ["DNS amplification", "DDoS"]),
    ("P1", ["carpet bombing", "DDoS"]),
    ("P1", ["SYN flood", "TCP"]),
    ("P1", ["state exhaustion", "denial of service"]),
    ("P1", ["application layer", "DDoS", "HTTP flood"]),
    ("P1", ["slow HTTP", "denial of service"]),
    ("P1", ["Slowloris"]),
    ("P1", ["HTTP/2", "denial of service"]),
    ("P2", ["XDP", "DDoS"]),
    ("P2", ["eBPF", "DDoS", "mitigation"]),
    ("P2", ["P4", "programmable switch", "DDoS"]),
    ("P2", ["programmable data plane", "DDoS", "mitigation"]),
    ("P2", ["software-defined networking", "DDoS", "mitigation"]),
    ("P2", ["OpenFlow", "DDoS", "controller"]),
    ("P2", ["BGP FlowSpec", "DDoS"]),
    ("P2", ["blackholing", "DDoS"]),
    ("P2", ["anycast", "DDoS"]),
    ("P2", ["scrubbing", "DDoS"]),
    ("P3", ["entropy", "DDoS detection"]),
    ("P3", ["machine learning", "DDoS detection", "CIC-DDoS2019"]),
    ("P3", ["deep learning", "DDoS detection", "LSTM"]),
    ("P3", ["autoencoder", "DDoS detection"]),
    ("P3", ["transformer", "DDoS detection"]),
    ("P3", ["in-network", "machine learning", "DDoS"]),
    ("P3", ["lightweight", "DDoS detection", "real-time"]),
    ("P4", ["DDoS", "testbed", "evaluation"]),
    ("P4", ["Mininet", "DDoS"]),
    ("P4", ["CICIDS2017", "dataset", "errors"]),
    ("P4", ["intrusion detection dataset", "flaws"]),
    ("P4", ["TON_IoT", "dataset"]),
    ("P4", ["DPDK", "traffic generator"]),
    ("P4", ["DDoS", "dataset", "benchmark"]),
]

# Foundational and landmark titles, looked up by title with no year filter.
SEEDS = [
    ("P1", "Amplification Hell: Revisiting Network Protocols for DDoS Abuse"),
    ("P1", "Understanding the Mirai Botnet"),
    ("P1", "Weaponizing Middleboxes for TCP Reflected Amplification"),
    ("P1", "The Far Side of DNS Amplification: Tracing the DDoS Attack Ecosystem from the Internet Core"),
    ("P1", "Application Layer Denial-of-Service Attacks and Defense Mechanisms: A Survey"),
    ("P1", "The Age of DDoScovery: An Empirical Comparison of Industry and Academic DDoS Assessments"),
    ("P2", "The eXpress Data Path: Fast Programmable Packet Processing in the Operating System Kernel"),
    ("P2", "Performance Implications of Packet Filtering with Linux eBPF"),
    ("P2", "United We Stand: Collaborative Detection and Mitigation of Amplification DDoS Attacks at Scale"),
    ("P2", "Jaqen: A High-Performance Switch-Native Approach for Detecting and Mitigating Volumetric DDoS Attacks with Programmable Switches"),
    ("P2", "Ripple: A Programmable, Decentralized Link-Flooding Defense Against Adaptive Adversaries"),
    ("P2", "Anycast Agility: Network Playbooks to Fight DDoS"),
    ("P2", "Aggregate-Based Congestion Control for Pulse-Wave DDoS Defense"),
    ("P3", "LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection"),
    ("P3", "Euclid: A Fully In-Network, P4-Based Approach for Real-Time DDoS Attack Detection and Mitigation"),
    ("P3", "IXP Scrubber: Learning from Blackholing Traffic for ML-Driven DDoS Detection at Scale"),
    ("P3", "Dos and Don'ts of Machine Learning in Computer Security"),
    ("P3", "A flow-based IDS using Machine Learning in eBPF"),
    ("P4", "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy"),
    ("P4", "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"),
    ("P4", "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study"),
    ("P4", "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018"),
    ("P4", "A new distributed architecture for evaluating AI-based security systems at the edge: Network TON_IoT datasets"),
    ("P4", "MoonGen: A Scriptable High-Speed Packet Generator"),
]
SEED_MATCH = 0.92  # minimum title similarity for a seed to count as resolved

PEER_TYPES = {"journal", "conference", "book series", "ebook platform"}
TOP_VENUE = re.compile(
    r"\b(ieee|acm|usenix|springer|elsevier|ndss)\b|institute of electrical|"
    r"association for computing machinery|internet society|network and distributed system security",
    re.I,
)
TIER_WEIGHT = {"top": 1.0, "peer-reviewed": 0.6, "preprint": 0.4}
ABSTRACT_RANK = {"arxiv": 0, "semanticscholar": 1, "openalex": 2}  # openalex is rebuilt from an index
ARXIV_ID = re.compile(r"(\d{4}\.\d{4,5}|[a-z\-]+(?:\.[A-Z]{2})?/\d{7})")
ATOM = {"a": "http://www.w3.org/2005/Atom", "arxiv": "http://arxiv.org/schemas/atom"}
MONTHS = ["Jan.", "Feb.", "Mar.", "Apr.", "May", "Jun.", "Jul.", "Aug.", "Sep.", "Oct.", "Nov.", "Dec."]
STOPWORDS = {"a", "an", "the", "on", "of", "for", "in", "to", "and", "with", "towards", "toward"}


def squash(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def norm_title(t: str) -> str:
    t = unicodedata.normalize("NFKD", t or "").encode("ascii", "ignore").decode()
    return squash(re.sub(r"[^a-z0-9]+", " ", t.lower()))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Logger:
    """Timestamped lines to stdout and to corpus/logs/<command>_<time>.log."""

    def __init__(self, corpus: Path, command: str):
        logs = corpus / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = logs / f"{command}_{stamp}.log"
        self._fh = self.path.open("w", encoding="utf-8")

    def __call__(self, msg: str) -> None:
        line = f"[{dt.datetime.now(dt.timezone.utc):%H:%M:%S}] {msg}"
        print(line, flush=True)
        self._fh.write(line + "\n")
        self._fh.flush()


class FetchError(Exception):
    pass


class Http:
    """urllib GET with per-host pacing and retries. A host the egress proxy refuses, or
    that does not resolve, is marked blocked and receives no further requests."""

    SPACING = {"export.arxiv.org": 3.1, "arxiv.org": 3.1, "api.semanticscholar.org": 1.1}

    def __init__(self, log: Logger):
        self.log = log
        self.blocked: dict[str, str] = {}
        self.ok: collections.Counter = collections.Counter()
        self.failed: collections.Counter = collections.Counter()
        self._last: dict[str, float] = {}

    def get(self, url: str, accept: str = "application/json", headers: dict | None = None) -> bytes:
        host = urllib.parse.urlsplit(url).hostname or ""
        if host in self.blocked:
            raise FetchError(f"{host} skipped (blocked earlier: {self.blocked[host]})")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept, **(headers or {})})
        delay = 2.0
        for attempt in range(1, 5):
            wait = self.SPACING.get(host, 0.2) - (time.monotonic() - self._last.get(host, -1e9))
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.monotonic()
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = resp.read()
                self.ok[host] += 1
                return body
            except urllib.error.HTTPError as e:
                err, retry = f"HTTP {e.code}", e.code in (429, 500, 502, 503, 504)
            except urllib.error.URLError as e:
                err = str(e.reason)
                if "Tunnel connection failed" in err or isinstance(e.reason, socket.gaierror):
                    # Refused by the egress proxy or no DNS answer: a retry cannot help.
                    self.blocked[host] = err
                    self.failed[host] += 1
                    raise FetchError(f"{host}: {err}") from None
                retry = True
            except (TimeoutError, ConnectionError) as e:
                err, retry = repr(e), True
            if not retry or attempt == 4:
                self.failed[host] += 1
                raise FetchError(f"{host}: {err}")
            self.log(f"    {host}: {err}; retry {attempt}/3 in {delay:.0f} s")
            time.sleep(delay)
            delay *= 2
        raise AssertionError("unreachable")

    def json(self, url: str, headers: dict | None = None):
        return json.loads(self.get(url, headers=headers))


# ---------------------------------------------------------------- source adapters

def record(**fields) -> dict:
    base = dict(title="", year=None, date=None, authors=[], venue="", venue_type="unknown", publisher="",
                doi=None, arxiv_id=None, url=None, oa_pdf=[], citations=None, abstract=None,
                abstract_source=None, biblio={}, openalex_id=None, s2_id=None)
    base.update(fields)
    return base


def arxiv_from(text: str | None) -> str | None:
    if not text:
        return None
    if text.lower().startswith("10.48550/arxiv."):
        return text[len("10.48550/arxiv."):]
    m = re.search(r"arxiv\.org/(?:abs|pdf)/" + ARXIV_ID.pattern, text)
    return m.group(1) if m else None


def search_arxiv(http: Http, terms: list[str], n: int) -> list[dict]:
    q = " AND ".join(f'all:"{t}"' for t in terms) + " AND (cat:cs.CR OR cat:cs.NI OR cat:cs.LG)"
    url = "https://export.arxiv.org/api/query?" + urllib.parse.urlencode(
        {"search_query": q, "start": 0, "max_results": n, "sortBy": "relevance"})
    return parse_arxiv(http.get(url, accept="application/atom+xml"))


def parse_arxiv(xml_bytes: bytes) -> list[dict]:
    out = []
    for e in ET.fromstring(xml_bytes).findall("a:entry", ATOM):
        aid = re.sub(r"v\d+$", "", e.findtext("a:id", "", ATOM).rsplit("/abs/", 1)[-1])
        published = e.findtext("a:published", "", ATOM)
        doi = e.findtext("arxiv:doi", None, ATOM)
        out.append(record(
            title=squash(e.findtext("a:title", "", ATOM)),
            year=int(published[:4]) if published[:4].isdigit() else None,
            date=published[:10] or None,
            authors=[squash(a.findtext("a:name", "", ATOM)) for a in e.findall("a:author", ATOM)],
            venue=squash(e.findtext("arxiv:journal_ref", "", ATOM)),
            venue_type="repository",
            doi=doi.lower() if doi else None,
            arxiv_id=aid,
            url=f"https://arxiv.org/abs/{aid}",
            oa_pdf=[f"https://arxiv.org/pdf/{aid}"],
            abstract=squash(e.findtext("a:summary", "", ATOM)) or None,
            abstract_source="arxiv",
        ))
    return out


OPENALEX_FIELDS = ("id,doi,display_name,publication_year,publication_date,primary_location,best_oa_location,"
                   "locations,authorships,cited_by_count,abstract_inverted_index,biblio")


def search_openalex(http: Http, text: str, n: int, mailto: str | None, years: bool = True) -> list[dict]:
    params = {"search": text, "per-page": n, "select": OPENALEX_FIELDS}
    if years:
        params["filter"] = f"from_publication_date:{YEAR_MIN}-01-01,to_publication_date:{YEAR_MAX}-12-31"
    if mailto:
        params["mailto"] = mailto
    return parse_openalex(http.json("https://api.openalex.org/works?" + urllib.parse.urlencode(params)))


def rebuild_abstract(index: dict | None) -> str | None:
    if not index:
        return None
    words = sorted((pos, word) for word, positions in index.items() for pos in positions)
    return " ".join(w for _, w in words) or None


def parse_openalex(js: dict) -> list[dict]:
    out = []
    for w in js.get("results", []):
        loc = w.get("primary_location") or {}
        src = loc.get("source") or {}
        best = w.get("best_oa_location") or {}
        doi = (w.get("doi") or "").removeprefix("https://doi.org/").lower() or None
        arxiv = arxiv_from(doi)
        for other in w.get("locations") or []:
            arxiv = arxiv or arxiv_from(other.get("landing_page_url")) or arxiv_from(other.get("pdf_url"))
        abstract = rebuild_abstract(w.get("abstract_inverted_index"))
        b = w.get("biblio") or {}
        out.append(record(
            title=squash(w.get("display_name") or ""),
            year=w.get("publication_year"),
            date=w.get("publication_date"),
            authors=[(a.get("author") or {}).get("display_name", "") for a in w.get("authorships") or []],
            venue=src.get("display_name") or "",
            venue_type="repository" if doi and doi.startswith("10.48550/") else (src.get("type") or "unknown"),
            publisher=src.get("host_organization_name") or "",
            doi=doi,
            arxiv_id=arxiv,
            url=f"https://doi.org/{doi}" if doi else loc.get("landing_page_url") or w.get("id"),
            oa_pdf=[u for u in (best.get("pdf_url"), loc.get("pdf_url")) if u],
            citations=w.get("cited_by_count"),
            abstract=abstract,
            abstract_source="openalex" if abstract else None,
            biblio={k: b.get(k) for k in ("volume", "issue", "first_page", "last_page") if b.get(k)},
            openalex_id=w.get("id"),
        ))
    return out


S2_FIELDS = ("title,year,publicationDate,venue,publicationVenue,externalIds,citationCount,abstract,authors,"
             "openAccessPdf,publicationTypes,journal")


def s2_headers() -> dict:
    key = os.environ.get("S2_API_KEY")
    return {"x-api-key": key} if key else {}


def search_s2(http: Http, text: str, n: int) -> list[dict]:
    url = "https://api.semanticscholar.org/graph/v1/paper/search?" + urllib.parse.urlencode(
        {"query": text, "year": f"{YEAR_MIN}-{YEAR_MAX}", "fields": S2_FIELDS, "limit": n})
    return parse_s2(http.json(url, headers=s2_headers()).get("data") or [])


def parse_s2(papers: list[dict]) -> list[dict]:
    out = []
    for p in papers:
        ext = p.get("externalIds") or {}
        pv = p.get("publicationVenue") or {}
        types = p.get("publicationTypes") or []
        vtype = pv.get("type") or ("journal" if "JournalArticle" in types else
                                   "conference" if "Conference" in types else "unknown")
        doi = (ext.get("DOI") or "").lower() or None
        journal = p.get("journal") or {}
        pages = (journal.get("pages") or "").replace(" ", "")
        first, _, last = pages.partition("-")
        oa = (p.get("openAccessPdf") or {}).get("url")
        out.append(record(
            title=squash(p.get("title") or ""),
            year=p.get("year"),
            date=p.get("publicationDate"),
            authors=[a.get("name", "") for a in p.get("authors") or []],
            venue=pv.get("name") or p.get("venue") or "",
            venue_type="repository" if (doi or "").startswith("10.48550/") or not (pv or types) else vtype,
            doi=doi,
            arxiv_id=ext.get("ArXiv") or arxiv_from(doi),
            url=f"https://doi.org/{doi}" if doi else f"https://www.semanticscholar.org/paper/{p.get('paperId')}",
            oa_pdf=[oa] if oa else [],
            citations=p.get("citationCount"),
            abstract=squash(p.get("abstract") or "") or None,
            abstract_source="semanticscholar" if p.get("abstract") else None,
            biblio={k: v for k, v in (("volume", (journal.get("volume") or "").strip()),
                                      ("first_page", first), ("last_page", last)) if v},
            s2_id=p.get("paperId"),
        ))
    return out


def title_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, norm_title(a), norm_title(b)).ratio()


def resolve_seed(http: Http, title: str, mailto: str | None, log: Logger) -> dict | None:
    found: list[dict] = []
    try:
        found += search_openalex(http, title, 10, mailto, years=False)
    except FetchError as e:
        log(f"    openalex: {e}")
    if not any(title_similarity(title, r["title"]) >= SEED_MATCH for r in found):
        url = "https://api.semanticscholar.org/graph/v1/paper/search/match?" + urllib.parse.urlencode(
            {"query": title, "fields": S2_FIELDS})
        try:
            found += parse_s2(http.json(url, headers=s2_headers()).get("data") or [])
        except FetchError as e:
            log(f"    semanticscholar: {e}")
    scored = [(title_similarity(title, r["title"]), r) for r in found]
    best = max(scored, key=lambda x: x[0], default=(0.0, None))
    return best[1] if best[0] >= SEED_MATCH else None


# ---------------------------------------------------------------- corpus

def is_published(r: dict) -> bool:
    return r["venue_type"] in PEER_TYPES


def tier(r: dict) -> str:
    if is_published(r) or r["venue"]:  # an arXiv journal-ref also names a venue
        return "top" if TOP_VENUE.search(f"{r['publisher']} {r['venue']}") else "peer-reviewed"
    return "preprint"


class Corpus:
    def __init__(self):
        self.records: list[dict] = []
        self._index: dict[str, dict] = {}

    @staticmethod
    def _ids(r: dict) -> list[str]:
        ids = [f"title:{norm_title(r['title'])}"]
        if r.get("doi"):
            ids.insert(0, f"doi:{r['doi']}")
        if r.get("arxiv_id"):
            ids.insert(0, f"arxiv:{r['arxiv_id']}")
        return ids

    def add(self, r: dict, pillar: str, query: str, source: str, seed: bool = False) -> None:
        cur = next((self._index[k] for k in self._ids(r) if k in self._index), None)
        if cur is None:
            cur = dict(r, pillars=[], hits=[], seed=False)
            self.records.append(cur)
        else:
            merge(cur, r)
        if pillar not in cur["pillars"]:
            cur["pillars"].append(pillar)
        cur["hits"].append({"source": source, "query": query})
        cur["seed"] = cur["seed"] or seed
        for k in self._ids(cur):
            self._index.setdefault(k, cur)


def merge(cur: dict, new: dict) -> None:
    if is_published(new) and not is_published(cur):
        for f in ("title", "year", "date", "venue", "venue_type", "publisher", "url", "biblio"):
            if new.get(f):
                cur[f] = new[f]
    for f in ("date", "venue", "publisher", "biblio", "arxiv_id", "openalex_id", "s2_id", "url"):
        if not cur.get(f) and new.get(f):
            cur[f] = new[f]
    if new.get("doi") and (not cur.get("doi") or cur["doi"].startswith("10.48550/")):
        cur["doi"] = new["doi"]
    if new.get("abstract") and ABSTRACT_RANK[new["abstract_source"]] < ABSTRACT_RANK.get(cur["abstract_source"], 9):
        cur["abstract"], cur["abstract_source"] = new["abstract"], new["abstract_source"]
    if new.get("citations") is not None:
        cur["citations"] = max(cur.get("citations") or 0, new["citations"])
    cur["oa_pdf"] = list(dict.fromkeys(cur["oa_pdf"] + new["oa_pdf"]))
    if len(new["authors"]) > len(cur["authors"]):
        cur["authors"] = new["authors"]


def make_key(r: dict, taken: set[str]) -> str:
    first = r["authors"][0] if r["authors"] else "anon"
    surname = norm_title(first.split()[-1] if first.split() else "anon").replace(" ", "") or "anon"
    word = next((w for w in norm_title(r["title"]).split() if w not in STOPWORDS), "x")
    base = f"{surname}{r['year'] or 'nd'}{word}"
    key, i = base, 0
    while key in taken:
        i += 1
        key = f"{base}{chr(96 + i)}"
    taken.add(key)
    return key


def score(r: dict) -> float:
    this_year = dt.date.today().year
    age = max(1, this_year - (r["year"] or this_year) + 1)
    per_year = (r["citations"] or 0) / age
    return round(TIER_WEIGHT[r["tier"]] * math.log1p(per_year) + 0.1 * len(r["hits"]), 3)


# ---------------------------------------------------------------- commands

def query_text(terms: list[str]) -> str:
    return " ".join(terms)


def cmd_plan(_args) -> int:
    print(f"Years: {YEAR_MIN}-{YEAR_MAX} for keyword queries; seeds are looked up by title with no year filter.\n")
    print("| Pillar | arXiv query (cs.CR, cs.NI, cs.LG) | OpenAlex / Semantic Scholar query |")
    print("|---|---|---|")
    for pillar, terms in QUERIES:
        arxiv = " AND ".join(f'all:"{t}"' for t in terms)
        print(f"| {pillar} | `{arxiv}` | `{query_text(terms)}` |")
    print("\n| Pillar | Seed title (lookup only; kept if an API returns it, similarity >= "
          f"{SEED_MATCH}) |\n|---|---|")
    for pillar, title in SEEDS:
        print(f"| {pillar} | {title} |")
    return 0


def cmd_search(args) -> int:
    log = Logger(args.corpus, "search")
    http = Http(log)
    corpus = Corpus()
    per_source = collections.Counter()
    log(f"search: {len(QUERIES)} queries x 3 sources, {len(SEEDS)} seeds, years {YEAR_MIN}-{YEAR_MAX}, "
        f"max {args.max_per_query} per query; log {log.path}")
    sources = [
        ("arxiv", lambda terms: search_arxiv(http, terms, args.max_per_query)),
        ("openalex", lambda terms: search_openalex(http, query_text(terms), args.max_per_query, args.mailto)),
        ("semanticscholar", lambda terms: search_s2(http, query_text(terms), args.max_per_query)),
    ]
    for pillar, terms in QUERIES:
        label = query_text(terms)
        for name, run in sources:
            try:
                hits = [r for r in run(terms) if r["year"] and YEAR_MIN <= r["year"] <= YEAR_MAX]
            except FetchError as e:
                log(f"[{pillar}] {label!r} | {name}: FAILED {e}")
                continue
            except (ET.ParseError, json.JSONDecodeError, KeyError, TypeError) as e:
                log(f"[{pillar}] {label!r} | {name}: UNPARSEABLE RESPONSE {e!r}")
                continue
            for r in hits:
                corpus.add(r, pillar, label, name)
            per_source[name] += len(hits)
            log(f"[{pillar}] {label!r} | {name}: {len(hits)} records")
    unresolved = []
    for pillar, title in SEEDS:
        r = resolve_seed(http, title, args.mailto, log)
        if r is None:
            unresolved.append(title)
            log(f"[seed {pillar}] UNRESOLVED {title!r}")
            continue
        corpus.add(r, pillar, f"seed: {title}", "seed", seed=True)
        per_source["seed"] += 1
        log(f"[seed {pillar}] resolved {title!r} -> {r['venue'] or 'arXiv'} ({r['year']})")

    log("---- summary")
    for host in sorted(set(http.ok) | set(http.failed) | set(http.blocked)):
        state = f"BLOCKED ({http.blocked[host]})" if host in http.blocked else "reachable"
        log(f"host {host}: {http.ok[host]} ok, {http.failed[host]} failed, {state}")
    log(f"records per source (before merging): {dict(per_source) or 'none'}")
    log(f"seeds resolved: {len(SEEDS) - len(unresolved)}/{len(SEEDS)}")
    if not corpus.records:
        log("NOTHING RETRIEVED: candidates.json was not written (an existing one is left as it was).")
        return 2

    taken: set[str] = set()
    for r in corpus.records:
        r["tier"] = tier(r)
        r["score"] = score(r)
        r["key"] = make_key(r, taken)
    corpus.records.sort(key=lambda r: (min(r["pillars"]), -r["score"]))
    out = {"generated": now_utc(), "years": [YEAR_MIN, YEAR_MAX], "queries": QUERIES, "seeds": SEEDS,
           "unresolved_seeds": unresolved, "hosts_blocked": http.blocked, "records": corpus.records}
    path = args.corpus / "candidates.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    log(f"{len(corpus.records)} unique records -> {path}")
    for pillar, name in PILLARS.items():
        rows = [r for r in corpus.records if pillar in r["pillars"]]
        log(f"== {pillar} {name}: {len(rows)} records, top {min(len(rows), args.show)} by score")
        for r in rows[:args.show]:
            log(f"   {r['key']:<32} {r['year']} {r['tier']:<13} cites={r['citations'] or 0:<5} "
                f"{r['venue'][:38]:<38} {r['title'][:90]}")
    return 0


def ieee_names(names: list[tuple[str, str]]) -> str:
    def initials(given: str) -> str:
        return " ".join("-".join(f"{p[0]}." for p in part.split("-") if p) for part in given.split())

    def fmt(given: str, family: str) -> str:
        return f"{initials(given)} {family}".strip()

    if len(names) > 6:
        return f"{fmt(*names[0])} et al."
    shown = [fmt(g, f) for g, f in names]
    if len(shown) <= 2:
        return " and ".join(shown)
    return ", ".join(shown[:-1]) + ", and " + shown[-1]


def ieee_citation(r: dict, cr: dict | None) -> str:
    if cr:
        names = [(a.get("given", ""), a.get("family", a.get("name", ""))) for a in cr.get("author", [])]
        title = squash((cr.get("title") or [r["title"]])[0])
        container = squash((cr.get("container-title") or [r["venue"]])[0])
        parts = (cr.get("issued") or {}).get("date-parts") or [[r["year"]]]
        year, month = parts[0][0], (parts[0][1] if len(parts[0]) > 1 else None)
        volume, issue, pages = cr.get("volume"), cr.get("issue"), cr.get("page")
        kind = cr.get("type", "")
    else:
        names = [(" ".join(n.split()[:-1]), n.split()[-1]) for n in r["authors"] if n.split()]
        title, container, year, kind = r["title"], r["venue"], r["year"], ""
        month = int(r["date"][5:7]) if r.get("date") and len(r["date"]) >= 7 else None
        b = r.get("biblio") or {}
        volume, issue = b.get("volume"), b.get("issue")
        pages = "-".join(p for p in (b.get("first_page"), b.get("last_page")) if p)
    when = f"{MONTHS[month - 1]} {year}" if month else f"{year}"
    pages = f"pp. {pages.replace('-', '–')}" if pages and "-" in pages else (f"p. {pages}" if pages else "")
    doi = (cr or {}).get("DOI") or r.get("doi")
    tail = f", doi: {doi}." if doi and not doi.lower().startswith("10.48550/") else (
        f". [Online]. Available: {r['url']}" if r.get("url") else ".")
    if not is_published(r) and not cr:
        venue = f"arXiv:{r['arxiv_id']}" if r.get("arxiv_id") else (container or "preprint")
        body = [venue, when]
    elif kind == "proceedings-article" or r["venue_type"] == "conference":
        body = [f"in *{container}*", when, pages]
    else:
        body = [f"*{container}*", f"vol. {volume}" if volume else "", f"no. {issue}" if issue else "", pages, when]
    return f'{ieee_names(names)}, "{title}," ' + ", ".join(b for b in body if b) + tail


def pdf_to_text(pdf: Path, txt: Path) -> None:
    subprocess.run(["pdftotext", "-enc", "UTF-8", str(pdf), str(txt)], check=True, capture_output=True)


def cmd_fetch(args) -> int:
    log = Logger(args.corpus, "fetch")
    http = Http(log)
    cand_path, sel_path = args.corpus / "candidates.json", args.corpus / "selected.json"
    if not cand_path.exists() or not sel_path.exists():
        log(f"fetch needs {cand_path} (from `search`) and {sel_path} (the screening decisions).")
        return 2
    by_key = {r["key"]: r for r in json.loads(cand_path.read_text(encoding="utf-8"))["records"]}
    selected = json.loads(sel_path.read_text(encoding="utf-8"))
    man_path = args.corpus / "manifest.json"
    manifest = json.loads(man_path.read_text(encoding="utf-8")) if man_path.exists() else {}
    for d in ("abstracts", "fulltext", "pdf"):
        (args.corpus / d).mkdir(parents=True, exist_ok=True)
    missing = 0
    for s in selected:
        key, r = s["key"], by_key.get(s["key"])
        if r is None:
            log(f"{s['paper_id']} {key}: not in candidates.json")
            missing += 1
            continue
        entry = manifest.setdefault(key, {})
        entry.update(paper_id=s["paper_id"], title=r["title"])
        cr = None
        if r.get("doi") and not r["doi"].startswith("10.48550/"):
            try:
                cr = http.json("https://api.crossref.org/works/" + urllib.parse.quote(r["doi"]))["message"]
                entry["crossref"] = {k: cr.get(k) for k in ("DOI", "type", "title", "container-title", "volume",
                                                             "issue", "page", "publisher", "issued", "author")}
            except FetchError as e:
                log(f"{s['paper_id']} {key}: crossref {e}")
        entry["ieee_citation"] = ieee_citation(r, cr)
        if r.get("abstract"):
            data = r["abstract"].encode("utf-8")
            (args.corpus / "abstracts" / f"{key}.txt").write_bytes(data)
            entry["abstract"] = {"source": r["abstract_source"], "sha256": sha256(data)}
        urls = ([f"https://arxiv.org/pdf/{r['arxiv_id']}"] if r.get("arxiv_id") else []) + r["oa_pdf"]
        for url in dict.fromkeys(urls):
            try:
                data = http.get(url, accept="application/pdf")
            except FetchError as e:
                log(f"{s['paper_id']} {key}: pdf {e}")
                continue
            if not data.startswith(b"%PDF"):
                log(f"{s['paper_id']} {key}: {url} did not return a PDF")
                continue
            pdf, txt = args.corpus / "pdf" / f"{key}.pdf", args.corpus / "fulltext" / f"{key}.txt"
            pdf.write_bytes(data)
            pdf_to_text(pdf, txt)
            text = txt.read_bytes()
            entry["fulltext"] = {"url": url, "retrieved": now_utc(), "pdf_sha256": sha256(data),
                                 "text_sha256": sha256(text), "pages": text.count(b"\f")}
            break
        have = [k for k in ("abstract", "fulltext") if k in entry]
        if not have:
            missing += 1
        log(f"{s['paper_id']} {key}: {', '.join(have) or 'NO TEXT'}; {entry['ieee_citation']}")
    man_path.write_text(json.dumps(manifest, indent=1, ensure_ascii=False), encoding="utf-8")
    log(f"manifest -> {man_path}; {len(selected) - missing}/{len(selected)} papers have text to verify against")
    return 1 if missing else 0


_TYPO = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-",
                       "—": "-", "−": "-", "­": None, " ": " "})


def typo_norm(s: str, join_hyphens: bool) -> str:
    s = unicodedata.normalize("NFKC", s).translate(_TYPO)
    if join_hyphens:
        s = re.sub(r"(\w)-[ \t]*\n\s*(\w)", r"\1\2", s)
    return squash(s)


def find_quote(quote: str, text: str) -> tuple[str, str] | None:
    """Return (level, where) for the first match of quote in text, or None.

    where is a 1-based PDF page ("p. 3", "pp. 3-4") when text has form feeds."""
    pages = text.split("\f")
    windows = [(f"p. {i + 1}", p) for i, p in enumerate(pages)]
    windows += [(f"pp. {i + 1}-{i + 2}", pages[i] + "\n" + pages[i + 1]) for i in range(len(pages) - 1)]
    if "\f" not in text:
        windows = [("abstract", text)]
    q_exact, q_norm = squash(quote), typo_norm(quote, False)
    for where, chunk in windows:
        if q_exact and q_exact in squash(chunk):
            return "exact", where
    for where, chunk in windows:
        if q_norm and (q_norm in typo_norm(chunk, False) or q_norm in typo_norm(chunk, True)):
            return "normalized", where
    return None


def parse_review(path: Path) -> dict[str, list[str]]:
    quotes: dict[str, list[str]] = collections.OrderedDict()
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^###\s+(P\d-\d{2})\b", line)
        if m:
            current = m.group(1)
            quotes[current] = []
        elif line.startswith("## "):
            current = None
        elif current and line.lstrip().startswith(">"):
            body = line.lstrip()[1:].strip()
            if len(body) > 2 and body[0] == '"' and body[-1] == '"':
                quotes[current].append(body[1:-1])
    return quotes


def cmd_verify(args) -> int:
    log = Logger(args.corpus, "verify")
    if not args.review.exists():
        log(f"no review at {args.review}")
        return 2
    quotes = parse_review(args.review)
    sel_path = args.corpus / "selected.json"
    selected = json.loads(sel_path.read_text(encoding="utf-8")) if sel_path.exists() else []
    key_of = {s["paper_id"]: s["key"] for s in selected}
    failures = 0
    for pid, qs in quotes.items():
        key = key_of.get(pid)
        texts = []
        if key:
            for kind in ("fulltext", "abstracts"):
                p = args.corpus / kind / f"{key}.txt"
                if p.exists():
                    texts.append((kind, p.read_text(encoding="utf-8", errors="replace")))
        if not texts:
            log(f"{pid}: FAIL no stored text (key {key or 'missing from selected.json'})")
            failures += 1
            continue
        if len(qs) < 2:
            log(f"{pid}: FAIL {len(qs)} quote(s); the schema needs 2")
            failures += 1
        for i, q in enumerate(qs, 1):
            hit = next(((kind, *m) for kind, t in texts if (m := find_quote(q, t))), None)
            if hit:
                log(f"{pid} q{i}: PASS {hit[1]} in {hit[0]} ({hit[2]})")
            else:
                log(f"{pid} q{i}: FAIL not found: {q[:100]!r}")
                failures += 1
    log(f"{len(quotes)} papers, {sum(map(len, quotes.values()))} quotes, {failures} failure(s)")
    return 1 if failures or not quotes else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS, help="corpus directory (default: %(default)s)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print the search protocol as Markdown")
    p = sub.add_parser("search", help="query the APIs and write corpus/candidates.json")
    p.add_argument("--max-per-query", type=int, default=25)
    p.add_argument("--show", type=int, default=25, help="records listed per pillar in the log")
    p.add_argument("--mailto", help="contact address for the OpenAlex polite pool (optional)")
    sub.add_parser("fetch", help="store abstracts, full texts and citations for corpus/selected.json")
    p = sub.add_parser("verify", help="check every review quote against the stored texts")
    p.add_argument("--review", type=Path, default=DEFAULT_REVIEW)
    args = ap.parse_args(argv)
    return {"plan": cmd_plan, "search": cmd_search, "fetch": cmd_fetch, "verify": cmd_verify}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
