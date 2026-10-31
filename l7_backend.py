"""The costed backend of the L7 app (docs/L7V2_DESIGN.md section 4, D-V1).

l7_webapp keeps its URL space. With L7_BACKEND=costed, each of its routes calls the harm benchmark origin's work by
route class (bench/origin.py Origin.handle), with the knobs of a calibration record, and every answer says which record
it was served under. The route-to-class map is the site map in l7_webapp (route_class):

  GET /static/...            C0  Origin._c0's work; the body keeps l7_webapp's deterministic size (asset waves, sizes)
  GET /, GET /page/<n>       C1  Origin._c1, ident = crc32(n); an HTML answer sets the session cookie `sid` when the
                                 request carries no valid one (random, HttpOnly)
  GET /api/<name>            C2  Origin._c2, ident = crc32(name)
  GET /search?q=<term>       C3  Origin._c3 with the term (no sleep); a term the origin refuses is a 400
  GET /export[?r=<n>]        C5  Origin._c5; another query is a 400
  POST /upload               C6  only with L7_UPLOAD=streamed (profile R, P4): the body is read as it arrives, then C2's
                                 work (see below); without it uncosted like the rest
  anything else              uncosted: l7_webapp's own answer, unchanged (download, upload, login, robots, 404)

Each URL's work factor is the origin's: a log-normal factor drawn from a hash of the URL (spread_sigma stays an
ASSUMPTION), so a replayed URL costs the same. Costed answers carry X-Route-Class and X-Work; every answer carries
X-Origin-Calibration.

The record (L7_CALIBRATION, a path; default bench/calibration/placeholder.json) has one of three statuses:
  placeholder  the design's illustrative numbers (the default until HG2 is frozen); answers say "placeholder"
  measured     measured unloaded costs that are NOT frozen (ml/l7v2_records/): for offline arithmetic only;
               bench/calibration.py refuses the status, and the verdict code here refuses the record
  frozen       a frozen HG2 (or L7 v2) record: its knobs, its costs and the 25 % start-up self-check
               (bench/origin.make_app), answers "frozen:<sha8>"
No verdict code accepts anything but a frozen record (require_frozen). Without L7_BACKEND=costed, l7_webapp serves the
2026-10 app unchanged, so the published P5/P5c captures and their legacy pipeline stay as they were.

The upload route of profile R (docs/P4_SLOW_DESIGN.md §4.1, §5; L7_UPLOAD=streamed, which gunicorn_profile_r.py sets; the
default, "legacy", leaves POST /upload to l7_webapp exactly as before, so the L7 v2 harness is unchanged). Nginx streams
an upload's body to the backend there (proxy_request_buffering off), and this route reads it as it arrives, at most
UPLOAD_CHUNK bytes a read and never past the Content-Length (a chunked body: to its end), so a slow body holds one of
R's sync workers for as long as it lasts: the worker-slot harm of the slow-POST family. Its class is C6, whose SLO every
record holds; no record holds a C6 cost (bench/calibration.py lists C6 for its SLO only, and route_costs_ms is C0-C5),
so once the body is in, the route does C2's work (an indexed write acknowledged like an API call, ident = crc32 of the
byte count): the per-class cost the record sets and, with a frozen record, the 25 % start-up self-check covers. It
answers {"received": n} with X-Route-Class C6, X-Work (C2's units) and the record's X-Origin-Calibration. A body that
ends before its Content-Length (the client went away) is a 400 and costs no work.
"""
import dataclasses
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.parse
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "bench"))
import calibration as CAL
import origin as O

ENV_BACKEND = "L7_BACKEND"
ENV_RECORD = "L7_CALIBRATION"
ENV_UPLOAD = "L7_UPLOAD"
BACKENDS = ("legacy", "costed")
UPLOADS = ("legacy", "streamed")          # POST /upload: l7_webapp's answer, or read as it arrives (profile R)
UPLOAD_PATH, UPLOAD_CLASS, UPLOAD_WORK_CLASS = "/upload", "C6", "C2"
UPLOAD_CHUNK = 64 * 1024                  # at most this many bytes a read
STATUSES = ("placeholder", "measured", "frozen")
MEASURED_FORMAT = "l7v2-measured/1"
SID_COOKIE = "sid"
SID_RE = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
LABELS = {"placeholder": "PLACEHOLDER", "measured": "MEASURED, NOT FROZEN", "frozen": "frozen"}


class RecordError(ValueError):
    """A record is malformed, or is not frozen where a verdict needs one."""


# --- records --------------------------------------------------------------------------------------------------------

def measured_problems(rec):
    """What is wrong with a 'measured, not frozen' record (empty when nothing is)."""
    p = []
    if not isinstance(rec, dict):
        return ["the record is not an object"]
    if rec.get("format") != MEASURED_FORMAT or rec.get("status") != "measured":
        p.append(f"format {MEASURED_FORMAT} and status measured")
    costs = rec.get("route_costs_ms")
    if not isinstance(costs, dict) or set(costs) != set(O.CLASSES) or not all(
            isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 for v in costs.values()):
        p.append(f"route_costs_ms: a positive number for each of {', '.join(O.CLASSES)}")
    try:
        O.CostKnobs(**rec.get("knobs", {}))
    except TypeError as exc:
        p.append(f"knobs: {exc}")
    prov = rec.get("provenance")
    if not isinstance(prov, dict) or not HEX64.fullmatch(str(prov.get("sha256"))) or not prov.get("path"):
        p.append("provenance: the source file's path and sha256")
    if not p and rec.get("sha256") != CAL.digest(rec):
        p.append(f"sha256: {rec.get('sha256')!r} is not the hash of the record ({CAL.digest(rec)})")
    return p


def load_record(path=None):
    """(record, status, tag) of the record at `path` (None: the placeholder). A placeholder or frozen record goes through
    bench/calibration.validate (schema and hash); a measured one through measured_problems."""
    path = path or CAL.PLACEHOLDER
    with open(path, encoding="utf-8") as fh:
        rec = json.load(fh)
    status = rec.get("status") if isinstance(rec, dict) else None
    if status == "measured":
        probs = measured_problems(rec)
        if probs:
            raise RecordError(f"{path}: " + "; ".join(probs))
        return rec, status, f"measured:{rec['sha256'][:8]}"
    try:
        CAL.validate(rec)
    except CAL.RecordError as exc:
        raise RecordError(f"{path}: {exc}") from exc
    return rec, status, "placeholder" if status == "placeholder" else f"frozen:{rec['sha256'][:8]}"


def require_frozen(rec):
    """The verdict code's precondition: a placeholder or a measured record gives no verdict."""
    if rec.get("status") != "frozen":
        raise RecordError(f"the record is {LABELS.get(rec.get('status'), rec.get('status'))}: no verdict is given on it")
    return rec


def label(rec):
    """The label a report carries in its title for this record."""
    return LABELS.get(rec.get("status"), "UNKNOWN RECORD")


def arithmetic_record(costs_rec, base_rec):
    """For offline arithmetic only: `base_rec`'s capacity, mix and SLOs with `costs_rec`'s route costs. The result is
    labelled with the weaker status of the two and is never a calibration record."""
    out = {k: base_rec[k] for k in ("capacity", "mix", "slo_ms", "gate", "judged_profiles")}
    out["route_costs_ms"] = dict(costs_rec["route_costs_ms"])
    weakest = min(STATUSES.index(costs_rec["status"]), STATUSES.index(base_rec["status"]))
    out["status"] = STATUSES[weakest]
    out["sources"] = {"route_costs_ms": costs_rec.get("sha256"), "capacity": base_rec.get("sha256")}
    return out


# --- the costed WSGI app ---------------------------------------------------------------------------------------------

def _ident(text):
    return str(zlib.crc32(text.encode("utf-8")))


def valid_sid(value):
    return bool(value) and bool(SID_RE.fullmatch(value))


def request_sid(environ):
    """The sid cookie the request carries, or None."""
    jar = environ.get("HTTP_COOKIE", "")
    for part in jar.split(";"):
        name, _, value = part.strip().partition("=")
        if name == SID_COOKIE:
            return value
    return None


class CostedApp:
    """l7_webapp's URL space over the origin's work (see the module docstring). `knobs` overrides the record's knobs
    (tests use small data sets); `sid_factory` makes session ids (tests make them deterministic)."""

    def __init__(self, record_path=None, *, knobs=None, data_seed=1, clock=time.process_time, sid_factory=None,
                 upload="legacy"):
        if upload not in UPLOADS:
            raise ValueError(f"{ENV_UPLOAD}={upload!r}: {' or '.join(UPLOADS)}")
        self.upload = upload
        import l7_webapp
        self.site = l7_webapp
        self.record, self.status, self.tag = load_record(record_path)
        fields = {f.name for f in dataclasses.fields(O.CostKnobs)}
        merged = {k: v for k, v in self.record["knobs"].items() if k in fields}
        merged.update(knobs or {})
        frozen = self.record["route_costs_ms"] if self.status == "frozen" else None
        self.origin = O.make_app(O.CostKnobs(**merged), data_seed, frozen, self.tag, clock)
        self.knobs = self.origin.knobs
        self.data_seed = data_seed
        self.new_sid = sid_factory or (lambda: secrets.token_hex(16))

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        return cls(environ.get(ENV_RECORD) or None, data_seed=int(environ.get("ORIGIN_SEED", "1")),
                   upload=environ.get(ENV_UPLOAD) or "legacy")

    def _reply(self, start_response, status, ctype, body, *, klass=None, work=None, cache=None, cookie=None,
               head=False):
        headers = [("Content-Type", ctype), ("Content-Length", str(len(body))), ("X-Origin-Calibration", self.tag)]
        if cache:
            headers.append(("Cache-Control", cache))
        if klass:
            headers += [("X-Route-Class", klass), ("X-Work", str(work))]
        if cookie:
            headers.append(("Set-Cookie", f"{SID_COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Lax"))
        start_response(status, headers)
        return [b""] if head else [body]

    def __call__(self, environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        qs = environ.get("QUERY_STRING", "")
        if self.upload == "streamed" and method == "POST" and path == UPLOAD_PATH:
            return self._upload(environ, start_response)
        klass = self.site.route_class("GET", path)
        if klass is None:
            def tagged(status, headers, exc_info=None):
                return start_response(status, [*headers, ("X-Origin-Calibration", self.tag)], exc_info)
            return self.site.legacy_app(environ, tagged)
        if method not in ("GET", "HEAD"):
            return self._reply(start_response, "405 Method Not Allowed", "text/plain", b"GET and HEAD only\n")
        head = method == "HEAD"
        query, ident = "", "0"
        if klass == "C3":
            query = urllib.parse.parse_qs(qs, keep_blank_values=True).get("q", [""])[0]
            if not O.SEARCH_TERM.fullmatch(query):
                return self._reply(start_response, "400 Bad Request", "text/plain", b"bad search term\n")
        elif klass == "C5":
            if qs and not re.fullmatch(r"r=\d{1,6}", qs):
                return self._reply(start_response, "400 Bad Request", "text/plain", b"bad parameter\n")
        elif klass == "C1":
            ident = _ident(path[len("/page/"):] if path.startswith("/page/") else "")
        elif klass == "C2":
            ident = _ident(path[len("/api/"):])
        factor = O.spread_factor(f"{path}?{qs}", self.data_seed, self.knobs.spread_sigma)
        ctype, body, work = self.origin.handle(klass, ident, query, factor)
        if klass == "C0":                          # the asset keeps l7_webapp's deterministic size
            body = b"s" * self.site.static_size(path)
            return self._reply(start_response, "200 OK", "application/octet-stream", body, klass=klass, work=work,
                               cache="public, max-age=3600", head=head)
        cookie = None
        if klass == "C1" and not valid_sid(request_sid(environ)):
            cookie = self.new_sid()
        return self._reply(start_response, "200 OK", ctype, body, klass=klass, work=work, cache="no-store",
                           cookie=cookie, head=head)


    def _upload(self, environ, start_response):
        """POST /upload with L7_UPLOAD=streamed (see the module docstring): the body read as it arrives, then C2's work."""
        try:
            want = int(environ.get("CONTENT_LENGTH") or -1)
        except ValueError:
            return self._reply(start_response, "400 Bad Request", "text/plain", b"bad content length\n")
        inp, got = environ.get("wsgi.input"), 0
        while inp is not None and (want < 0 or got < want):
            chunk = inp.read(UPLOAD_CHUNK if want < 0 else min(UPLOAD_CHUNK, want - got))
            if not chunk:
                break
            got += len(chunk)
        if got < want:
            return self._reply(start_response, "400 Bad Request", "text/plain", b"incomplete body\n")
        factor = O.spread_factor(f"{UPLOAD_PATH}#{got}", self.data_seed, self.knobs.spread_sigma)
        _ctype, _body, work = self.origin.handle(UPLOAD_WORK_CLASS, _ident(f"upload|{got}"), "", factor)
        return self._reply(start_response, "200 OK", "application/json", json.dumps({"received": got}).encode(),
                           klass=UPLOAD_CLASS, work=work, cache="no-store")


def record_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()
