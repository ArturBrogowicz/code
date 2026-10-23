#!/usr/bin/env python3
"""A cost-calibrated origin for the harm benchmark (docs/BENCHMARK_HARM_DESIGN.md section 5,
docs/HG1B_MINIMAL_DESIGN.md 5.1).

The suite's backend answers every request with the same 31 bytes, so no request costs the server
anything and no attack can hurt it. This origin serves routes whose costs differ by about two orders
of magnitude, as real applications' do: a static asset, a rendered page, an API read, a search that
scans a table, and a CSV export. It is a WSGI app, stdlib only:

    gunicorn --chdir bench origin:app           # knobs from ORIGIN_CALIBRATION / ORIGIN_KNOBS / ORIGIN_SEED
    python3 bench/origin.py --calibrate         # the unloaded cost of every route on this host
    python3 bench/origin.py --check CAL.json    # is this host still within 25 % of a frozen calibration?

  C0  GET /static/<n>         a fixed body, no work
  C1  GET /page/<id>          renders `page_rows` table rows into a page
  C2  GET /api/item/<id>      an indexed lookup, JSON, and `api_burn` units of work
  C3  GET /search?q=<term>    scans `search_rows` rows with ranking
  C5  GET /export[?r=<n>]     builds a CSV of `export_rows` rows (`r` changes nothing but the URL's work factor)

(C4 login and C6 upload need POST, which the engine cannot send; they are not here.)

Real work, not sleeps: a sleep costs no CPU and would hide the saturation the harm gate must see. The
one exception is an explicit I/O wait (`io_wait_ms`, default 0) on C2 and C3, which models a blocked
worker slot. Bytes and the amount of work depend only on (route, parameters, data seed, knobs); the
work is returned in `X-Work`. Each URL's work is scaled by a log-normal factor with mean 1, drawn from a
hash of the URL, so the same URL always costs the same and a replayed schedule replays its costs.

The costs the knobs produce are measured, not assumed: `measure_unloaded` times every route with an
injectable clock, and a frozen calibration makes the app refuse to start when a route is more than
25 % off its frozen cost (host drift, another CPU). Without a frozen calibration the answers carry
`X-Origin-Calibration: placeholder`.
"""
import argparse
import csv
import dataclasses
import hashlib
import html
import io
import itertools
import json
import math
import os
import random
import re
import sqlite3
import sys
import threading
import time
import urllib.parse

CLASSES = ("C0", "C1", "C2", "C3", "C5")
TOLERANCE = 0.25                         # a route may be this far off its frozen cost at start-up
WORDS = ("alpha", "bravo", "cedar", "delta", "ember", "fjord", "gamma", "harbor", "indigo", "jasper",
         "kestrel", "lumen", "meadow", "nectar", "onyx", "prairie", "quartz", "raven", "saffron", "tundra",
         "umber", "velvet", "willow", "xenon", "yarrow", "zephyr", "amber", "basalt", "coral", "dune",
         "elm", "flint", "glacier", "heron", "iris", "juniper", "kelp", "lichen", "moss", "nettle",
         "opal", "pebble", "quill", "reed", "sage", "thistle", "urchin", "violet", "wren", "yucca",
         "ash", "birch", "clover", "dusk", "echo", "fern", "grove", "hazel", "isle", "jade", "knoll", "loam")
SEARCH_TERM = re.compile(r"[A-Za-z0-9 _-]{1,32}")
ROUTES = (("C0", re.compile(r"/static/(\d{1,6})")), ("C1", re.compile(r"/page/(\d{1,9})")),
          ("C2", re.compile(r"/api/item/(\d{1,9})")), ("C3", re.compile(r"/search")),
          ("C5", re.compile(r"/export")))
SAMPLE_URLS = {"C0": "/static/1", "C1": "/page/7", "C2": "/api/item/11", "C3": "/search?q=alpha",
               "C5": "/export"}
_instances = itertools.count(1)


class CalibrationError(RuntimeError):
    """A route's measured cost is further from the frozen one than the tolerance allows."""


@dataclasses.dataclass(frozen=True)
class CostKnobs:
    """What sets each route's cost. The defaults are placeholders; calibration chooses the values."""
    rows_total: int = 100_000      # size of the data set (generated from the data seed)
    static_bytes: int = 2048       # C0 body
    page_rows: int = 300           # C1: rows rendered
    page_burn: int = 6500          # C1: extra units of work (cost without a larger page)
    api_burn: int = 4000           # C2: units of work on top of the lookup
    search_rows: int = 50_000      # C3: rows scanned
    search_burn: int = 0           # C3: extra units of work
    export_rows: int = 6000        # C5: rows written (about 1.3 MB)
    export_burn: int = 330_000     # C5: extra units of work
    io_wait_ms: float = 0.0        # C2 and C3: a blocking wait, 0 = off
    spread_sigma: float = 0.25     # log-normal sigma of the per-URL work factor (assumed)


def burn(seed, units):
    """`units` iterations of a hash chain: deterministic CPU work."""
    h = seed
    for _ in range(units):
        h = hashlib.blake2b(h, digest_size=16).digest()
    return h


def spread_factor(url, data_seed, sigma):
    """exp(sigma z - sigma^2 / 2), z from a generator seeded by a hash of the URL: mean 1."""
    if not sigma:
        return 1.0
    key = hashlib.blake2b(f"{data_seed}|{url}".encode(), digest_size=8).digest()
    z = random.Random(int.from_bytes(key, "big")).gauss(0.0, 1.0)
    return math.exp(sigma * z - sigma * sigma / 2)


def _scaled(base, factor, cap):
    return max(1, min(cap, round(base * factor)))


class Origin:
    """The routes, the data set and the work. Call it as a WSGI app."""

    def __init__(self, knobs=None, data_seed=1, tag="placeholder", sleep=None):
        self.knobs = knobs or CostKnobs()
        self.data_seed = data_seed
        self.tag = tag
        self._sleep = sleep or time.sleep
        self._name = f"file:origin_{os.getpid()}_{next(_instances)}?mode=memory&cache=shared"
        self._local = threading.local()
        self._open, self._lock = [], threading.Lock()
        self._anchor = self._connect()
        self._build()

    # --- the data ----------------------------------------------------------------------------

    def _connect(self):
        con = sqlite3.connect(self._name, uri=True, check_same_thread=False)
        with self._lock:
            self._open.append(con)
        return con

    def _db(self):
        con = getattr(self._local, "con", None)
        if con is None:
            con = self._local.con = self._connect()
        return con

    def _build(self):
        rng = random.Random(self.data_seed)
        rows = []
        for i in range(1, self.knobs.rows_total + 1):
            title = " ".join(rng.choice(WORDS) for _ in range(3))
            body = " ".join(rng.choice(WORDS) for _ in range(rng.randint(14, 20)))
            rows.append((i, title, body, rng.randrange(1000)))
        self._anchor.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, title TEXT, body TEXT, score INTEGER)")
        self._anchor.executemany("INSERT INTO items VALUES (?, ?, ?, ?)", rows)
        self._anchor.commit()

    def checksum(self, n=50):
        """A digest of the first rows, to show that the data depend on the seed alone."""
        h = hashlib.sha256()
        for row in self._db().execute("SELECT id, title, body, score FROM items ORDER BY id LIMIT ?", (n,)):
            h.update(repr(row).encode())
        return h.hexdigest()

    def close(self):
        with self._lock:
            for con in self._open:
                con.close()
            self._open.clear()

    # --- the routes: each returns (content type, body, work) --------------------------------

    def _seed_bytes(self, route, key):
        return hashlib.blake2b(f"{self.data_seed}|{route}|{key}".encode(), digest_size=16).digest()

    def _c0(self, n, _query, _f):
        k = self.knobs
        body = hashlib.shake_128(self._seed_bytes("C0", n)).digest(k.static_bytes)
        return "application/octet-stream", body, k.static_bytes // 64

    def _c1(self, ident, _query, f):
        k = self.knobs
        rows = _scaled(k.page_rows, f, max(1, k.rows_total - 1))
        start = int.from_bytes(self._seed_bytes("C1", ident)[:4], "big") % max(1, k.rows_total - rows) + 1
        parts = ["<html><body><table>"]
        for rid, title, body in self._db().execute(
                "SELECT id, title, body FROM items WHERE id >= ? ORDER BY id LIMIT ?", (start, rows)):
            parts.append(f"<tr><td>{rid}</td><td>{html.escape(title)}</td><td>{html.escape(body)}</td></tr>")
        parts.append("</table></body></html>")
        burn_units = _scaled(k.page_burn, f, 10**9) if k.page_burn else 0
        burn(self._seed_bytes("C1b", ident), burn_units)
        return "text/html; charset=utf-8", "".join(parts).encode(), rows + burn_units

    def _c2(self, ident, _query, f):
        k = self.knobs
        rid = int(ident) % k.rows_total + 1
        row = self._db().execute("SELECT id, title, body, score FROM items WHERE id = ?", (rid,)).fetchone()
        if k.io_wait_ms:
            self._sleep(k.io_wait_ms / 1000)
        units = _scaled(k.api_burn, f, 10**9) if k.api_burn else 0
        digest = burn(self._seed_bytes("C2", ident), units).hex()
        body = json.dumps({"id": row[0], "title": row[1], "body": row[2], "score": row[3], "etag": digest},
                          sort_keys=True, separators=(",", ":")).encode()
        return "application/json", body, 1 + units

    def _c3(self, _ident, query, f):
        k = self.knobs
        rows = _scaled(k.search_rows, f, k.rows_total)
        term = query.lower()
        if k.io_wait_ms:
            self._sleep(k.io_wait_ms / 1000)
        hits = self._db().execute(
            "SELECT id, title, (length(body) - length(replace(lower(body), ?, ''))) / length(?) AS hits "
            "FROM items WHERE id <= ? ORDER BY hits DESC, id LIMIT 20", (term, term, rows)).fetchall()
        units = _scaled(k.search_burn, f, 10**9) if k.search_burn else 0
        burn(self._seed_bytes("C3", query), units)
        body = json.dumps([{"id": i, "title": t, "hits": h} for i, t, h in hits],
                          separators=(",", ":")).encode()
        return "application/json", body, rows + units

    def _c5(self, _ident, _query, f):
        k = self.knobs
        rows = _scaled(k.export_rows, f, k.rows_total)
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(("id", "title", "body", "score"))
        for row in self._db().execute("SELECT id, title, body, score FROM items WHERE id <= ? ORDER BY id", (rows,)):
            writer.writerow(row)
        units = _scaled(k.export_burn, f, 10**9) if k.export_burn else 0
        burn(self._seed_bytes("C5", "export"), units)
        return "text/csv; charset=utf-8", out.getvalue().encode(), rows + units

    def handle(self, klass, ident, query, factor):
        """One route's answer (content type, body, work) at a given work factor."""
        return getattr(self, "_" + klass.lower())(ident, query, factor)

    # --- the WSGI face ------------------------------------------------------------------------

    def __call__(self, environ, start_response):
        method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
        qs = environ.get("QUERY_STRING", "")
        if method not in ("GET", "HEAD"):
            return self._reply(start_response, "405 Method Not Allowed", "text/plain", b"GET and HEAD only\n",
                               extra=[("Allow", "GET, HEAD")])
        for klass, pattern in ROUTES:
            m = pattern.fullmatch(path)
            if not m:
                continue
            query = ""
            if klass == "C5" and qs and not re.fullmatch(r"r=\d{1,6}", qs):
                return self._reply(start_response, "400 Bad Request", "text/plain", b"bad parameter\n")
            if klass == "C3":
                query = urllib.parse.parse_qs(qs, keep_blank_values=True).get("q", [""])[0]
                if not SEARCH_TERM.fullmatch(query):
                    return self._reply(start_response, "400 Bad Request", "text/plain", b"bad search term\n")
            factor = spread_factor(f"{path}?{qs}", self.data_seed, self.knobs.spread_sigma)
            ctype, body, work = self.handle(klass, m.group(1) if m.groups() else "", query, factor)
            return self._reply(start_response, "200 OK", ctype, body, klass=klass, work=work,
                               head=method == "HEAD")
        return self._reply(start_response, "404 Not Found", "text/plain", b"no such route\n")

    def _reply(self, start_response, status, ctype, body, klass="", work=None, extra=(), head=False):
        headers = [("Content-Type", ctype), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"),
                   ("X-Origin-Calibration", self.tag), *extra]
        if klass:
            headers += [("X-Route-Class", klass), ("X-Work", str(work))]
        start_response(status, headers)
        return [b""] if head else [body]


# --- measuring and checking ------------------------------------------------------------------

def measure_unloaded(origin, repeats=5, clock=time.process_time):
    """The unloaded cost of every route in ms (the median of `repeats`), at the nominal work: the spread
    factor is held at 1. `clock` is injectable, so that a test can say how long things took."""
    out = {}
    patterns = dict(ROUTES)
    for klass, url in SAMPLE_URLS.items():
        parsed = urllib.parse.urlsplit(url)
        m = patterns[klass].fullmatch(parsed.path)
        ident = m.group(1) if m.groups() else ""
        query = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
        times = []
        for _ in range(repeats):
            t0 = clock()
            origin.handle(klass, ident, query, 1.0)
            times.append((clock() - t0) * 1000)
        out[klass] = sorted(times)[len(times) // 2]
    return out


def self_check(measured_ms, frozen_ms, tol=TOLERANCE):
    """The routes whose measured cost is more than `tol` off the frozen one."""
    bad = []
    for klass, frozen in frozen_ms.items():
        got = measured_ms.get(klass)
        if got is None or not frozen > 0 or abs(got - frozen) / frozen > tol:
            bad.append({"class": klass, "measured_ms": got, "frozen_ms": frozen,
                        "off": None if got is None or not frozen > 0 else (got - frozen) / frozen})
    return bad


def make_app(knobs=None, data_seed=1, frozen_costs_ms=None, tag="placeholder", clock=time.process_time,
             sleep=None):
    """The origin as a WSGI app. With frozen costs it measures itself first and refuses to start when
    a route is more than 25 % off (host drift, another CPU); without them it does not check."""
    origin = Origin(knobs, data_seed, tag, sleep)
    if frozen_costs_ms:
        bad = self_check(measure_unloaded(origin, clock=clock), frozen_costs_ms)
        if bad:
            origin.close()
            raise CalibrationError("; ".join(
                f"{b['class']}: {b['measured_ms']:.3g} ms against {b['frozen_ms']:.3g} ms frozen"
                if b["measured_ms"] is not None else f"{b['class']}: not measured" for b in bad))
    return origin


def app_from_env(environ=None, clock=time.process_time):
    """The app gunicorn serves: ORIGIN_CALIBRATION (a calibration record), ORIGIN_SEED, ORIGIN_KNOBS
    (a JSON object of knob overrides, for tests). No calibration means the placeholder."""
    environ = os.environ if environ is None else environ
    fields = {f.name for f in dataclasses.fields(CostKnobs)}
    knobs, frozen, tag = {}, None, "placeholder"
    if environ.get("ORIGIN_CALIBRATION"):
        with open(environ["ORIGIN_CALIBRATION"], encoding="utf-8") as fh:
            cal = json.load(fh)
        knobs.update({k: v for k, v in cal.get("knobs", {}).items() if k in fields})
        if cal.get("status") == "frozen":
            frozen, tag = cal["route_costs_ms"], f"frozen:{cal['sha256'][:8]}"
    knobs.update(json.loads(environ.get("ORIGIN_KNOBS", "{}")))
    return make_app(CostKnobs(**knobs), int(environ.get("ORIGIN_SEED", "1")), frozen, tag, clock)


def __getattr__(name):
    """`app` is built on first use, so that importing the module costs nothing."""
    if name == "app":
        globals()["app"] = app_from_env()
        return globals()["app"]
    raise AttributeError(name)


def main(argv=None, clock=time.process_time):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--calibrate", action="store_true", help="print the unloaded cost of every route")
    group.add_argument("--check", metavar="CAL.json", help="exit 1 when a route is more than 25 %% off the frozen cost")
    group.add_argument("--routes", action="store_true", help="print the route table")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--knobs", default="{}", help="JSON object of knob overrides")
    args = ap.parse_args(argv)
    if args.routes:
        for klass, pattern in ROUTES:
            print(f"{klass}  {pattern.pattern}")
        return 0
    knobs = CostKnobs(**json.loads(args.knobs))
    origin = Origin(knobs, args.seed)
    measured = measure_unloaded(origin, args.repeats, clock)
    report = {"knobs": dataclasses.asdict(knobs), "measured_ms": measured, "data_seed": args.seed,
              "python": sys.version.split()[0], "clock": getattr(clock, "__name__", "injected")}
    if args.check:
        with open(args.check, encoding="utf-8") as fh:
            frozen = json.load(fh)["route_costs_ms"]
        report["frozen_ms"], report["off"] = frozen, self_check(measured, frozen)
    print(json.dumps(report, indent=1, sort_keys=True))
    return 1 if report.get("off") else 0


if __name__ == "__main__":
    sys.exit(main())
