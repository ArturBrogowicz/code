"""Layer-7 request-log ingestion for the control plane (design: docs/L7_GRU_DESIGN.md).

Phase P1, shadow mode: read Nginx's extended JSON access log from a Unix-domain
datagram socket, maintain per-(IP, User-Agent) request windows, and count what
arrives. No GRU, no feature vectors, no bans — this module only observes, so it
can run beside the live detection paths without touching them.

Standard library only and free of import-time side effects, like ban_events.py:
control_plane.py imports it (venv python) and the unit tests import it (system
python3). control_plane.py attaches XDP at import, so all of this lives here to
stay unit-testable.

Keying is (IP, ua_hash): clients behind one NAT IP are separated by User-Agent
(docs/L7_GRU_DESIGN.md §5.3, confirmed decision 3). A ban decided later still
maps to the source IP, which is what XDP enforces on.

The User-Agent and URI are hashed *here*, on ingest, never used as raw strings
(the anti-fingerprint rule, §5.4). P1 logs them raw over the socket because this
Nginx build has no njs to hash them in the log; moving the hash into Nginx is a
P2 decision. Raw values are dropped immediately after hashing.

L7 v2 (docs/L7V2_DESIGN.md 8.2-8.4, ml/l7v2_model_prereg.json): normalise() also
hashes the Referer's path (ref_h, comparable with uri_h) and the session cookie
(sid_h: the cookie the answer set, `sid_set`, else the request's `sid`), and keeps
the route class of the raw URI (rc, the site map of l7_webapp.route_class) before
the raw strings are dropped. key_v2() is the L7 v2 key (IP, ua_hash, sid_hash); the
sid is a key component only, never a feature. key_of() stays the P5 key (IP, ua_hash).
"""

import hashlib
import json
import os
import socket
import stat
import time
from collections import defaultdict, deque

# Numeric fields the normalised record keeps, with their legacy json_ml_format
# aliases (raw "uri"/"ua" are hashed and dropped, see normalise()).
_NUMERIC = {"msec": ("msec",), "status": ("status",), "conn": ("conn",), "creq": ("creq",),
            "rt": ("rt", "request_time"), "uct": ("uct",), "urt": ("urt",),
            "rlen": ("rlen", "request_length"), "bsent": ("bsent", "bytes_sent")}

DEFAULT_SOCKET_PATH = "/run/ddos_l7.sock"
DEFAULT_WINDOW = 20          # requests kept per (ip, ua) key
DEFAULT_IDLE_TIMEOUT = 60.0  # seconds; evict a key idle this long
DEFAULT_RCVBUF = 4 * 1024 * 1024
# The daemon binds the socket as root, but Nginx worker processes run unprivileged
# (user nobody) and must be able to send to it, so make it world-writable. This is a
# local testbed socket; a production deployment would instead run the sender and
# receiver under a shared group and use 0o660.
DEFAULT_SOCKET_MODE = 0o666
_RECV_SIZE = 65536           # max datagram we read; Nginx caps its own syslog line far below


def stable_hash32(value):
    """A deterministic 32-bit hash of a string, for URI/UA diversity statistics.

    blake2b (not Python's salted hash()) so the value is stable across processes
    and runs — a capture and the daemon must bucket the same URI identically.
    """
    if value is None:
        value = ""
    return int.from_bytes(hashlib.blake2b(value.encode("utf-8", "replace"),
                                          digest_size=4).digest(), "big")


def parse_l7_line(raw):
    """Parse one access-log datagram into a dict, or return None if it is not
    usable JSON.

    Accepts bytes or str. Nginx's syslog framing (`<PRI>timestamp tag: {json}`)
    is stripped by starting at the first '{'. A datagram that begins a JSON
    object but does not end with '}' is treated as truncated (None); the caller
    counts it separately via looks_truncated().
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    start = raw.find("{")
    if start < 0:
        return None
    payload = raw[start:].strip()
    try:
        obj = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def looks_truncated(raw):
    """True if the datagram looks like a JSON object cut short (open brace, no
    close). Used only to classify a parse failure as truncation vs garbage."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    start = raw.find("{")
    if start < 0:
        return False
    return not raw[start:].rstrip().endswith("}")


def _num(val):
    """Coerce a log value to float. Upstream timings can list several values —
    "0.002, 0.004" across retries, "0.002 : 0.003" across internal redirects —
    and are summed (total upstream work). "-", blanks and junk count as 0."""
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    total = 0.0
    for part in str(val).replace(":", ",").split(","):
        part = part.strip()
        if part in ("", "-"):
            continue
        try:
            total += float(part)
        except ValueError:
            continue
    return total


NO_SID = -1                     # sid_h without a session: the v2 key is then (IP, ua_h, NO_SID)
ABSENT = ("", "-")              # how nginx logs an absent header, cookie or upstream cookie
SID_FIELDS = ("sid_set", "sid")  # the cookie the answer set wins: it names the session of a first request


def _present(val):
    return val is not None and str(val).strip() not in ABSENT


def route_class(method, uri):
    """The route class of a request (C0 assets, C1 pages, C2 API, C3 search, C5 export; None = uncosted): the site
    map of l7_webapp.route_class, restated here so this module stays standard library only and never imports the app
    (which builds its backend at import under L7_BACKEND=costed); tests/test_l7v2_ingest.py keeps the two equal."""
    path = (uri or "").split("?", 1)[0]
    if method not in ("GET", "HEAD"):
        return None
    if path.startswith("/static/"):
        return "C0"
    if path == "/" or path.startswith("/page/"):
        return "C1"
    if path.startswith("/api/"):
        return "C2"
    if path.startswith("/search"):
        return "C3"
    if path == "/export":
        return "C5"
    return None


def ref_path(ref):
    """The path and query a Referer names, its scheme and authority dropped, so that its hash equals the uri_h of the
    page it names (`http://10.0.0.1/page/3` -> `/page/3`; a bare authority -> `/`)."""
    ref = str(ref).strip()
    if "://" in ref:
        rest = ref.split("://", 1)[1]
        cut = rest.find("/")
        return rest[cut:] if cut >= 0 else "/"
    return ref


def sid_hash(obj):
    """stable_hash32 of the session id of a log object: `sid_set` (the cookie the answer set, so a session's first,
    cookie-less request joins its session), else the request's `sid` cookie, else NO_SID."""
    for name in SID_FIELDS:
        if _present(obj.get(name)):
            return stable_hash32(str(obj[name]).strip())
    return NO_SID


# The text fields nginx's log formats write as JSON strings. Another JSON type in one of them can only come from a
# forged datagram; it used to raise here (stable_hash32 calls .encode) or in the engine (a key with an int IP is not
# sortable with the others), which restarted the shadow thread with a fresh engine (T-042 E07). Such a record is dropped.
TEXT_FIELDS = ("ip", "client_ip", "ua", "user_agent", "uri", "request_uri", "method", "request_method", "proto",
               "server_protocol", "compl", "request_completion", "lreq", "limit_req_status", "tls", "reused", "ref",
               "sid", "sid_set")


def normalise(obj):
    """Turn a parsed log object into the slim record the window store keeps:
    numeric fields coerced, URI and UA replaced by 32-bit hashes, raw strings
    dropped. L7 v2: the Referer's path (ref_h, None when absent) and the session id
    (sid_h, NO_SID when absent) are hashed too, and the raw URI's route class is kept
    (rc). Returns None if there is no client IP to key on, or if a text field holds
    another JSON type than a string (TEXT_FIELDS)."""
    if any(obj.get(k) is not None and not isinstance(obj[k], str) for k in TEXT_FIELDS):
        return None
    ip = obj.get("ip") or obj.get("client_ip")
    if not ip:
        return None
    uri = obj.get("uri") or obj.get("request_uri") or ""
    method = obj.get("method") or obj.get("request_method") or ""
    ref = obj.get("ref")
    rec = {"ip": ip, "ua_h": stable_hash32(obj.get("ua") or obj.get("user_agent") or ""),
           "uri_h": stable_hash32(uri),
           "method": method,
           "proto": obj.get("proto") or obj.get("server_protocol") or "",
           "compl": obj.get("compl") or obj.get("request_completion") or "",
           "lreq": obj.get("lreq") or obj.get("limit_req_status") or "",
           "tls": obj.get("tls") or "", "reused": obj.get("reused") or "",
           "ref_h": stable_hash32(ref_path(ref)) if _present(ref) else None,
           "sid_h": sid_hash(obj), "rc": route_class(method, uri)}
    for key, names in _NUMERIC.items():
        rec[key] = _num(next((obj[n] for n in names if n in obj), None))
    return rec


def key_of(rec):
    """The window key: (IP, ua_hash). Bans map back to rec['ip'] for XDP."""
    return (rec["ip"], rec["ua_h"])


def key_v2(rec):
    """The L7 v2 key (docs/L7V2_DESIGN.md 8.3): (IP, ua_hash, sid_hash), which is (IP, ua_hash, NO_SID) for a request
    without a session. A ban decided on it still maps back to rec['ip']."""
    return (rec["ip"], rec["ua_h"], rec.get("sid_h", NO_SID))


class L7Counters:
    """Plain counters for the shadow monitor's periodic event."""

    __slots__ = ("bytes_total", "parse_errors", "parsed", "received", "truncated")

    def __init__(self):
        self.received = self.parsed = self.parse_errors = self.truncated = 0
        self.bytes_total = 0

    def as_dict(self):
        return {"received": self.received, "parsed": self.parsed,
                "parse_errors": self.parse_errors, "truncated": self.truncated,
                "bytes_total": self.bytes_total}


class L7WindowStore:
    """Per-(IP, ua_hash) sliding window of the last `maxlen` request records.

    P1 only fills and evicts these windows; P2 turns a full window into a feature
    vector. Idle keys are evicted (as control_plane already does for its per-IP
    dicts) so memory is bounded by the number of *active* clients.
    """

    def __init__(self, maxlen=DEFAULT_WINDOW, idle_timeout=DEFAULT_IDLE_TIMEOUT):
        self.maxlen = maxlen
        self.idle_timeout = idle_timeout
        self._windows = defaultdict(lambda: deque(maxlen=maxlen))
        self._last_seen = {}

    def add(self, rec, now=None):
        """Append a record; return its key. `now` defaults to the record's msec."""
        key = key_of(rec)
        self._windows[key].append(rec)
        self._last_seen[key] = now if now is not None else rec.get("msec") or time.time()
        return key

    def window(self, key):
        return self._windows.get(key)

    def evict_keys(self, now):
        """Drop keys idle for longer than idle_timeout. Return the dropped keys."""
        stale = [k for k, ts in self._last_seen.items() if now - ts > self.idle_timeout]
        for key in stale:
            self._windows.pop(key, None)
            self._last_seen.pop(key, None)
        return stale

    def evict(self, now):
        """Drop keys idle for longer than idle_timeout. Return the count dropped."""
        return len(self.evict_keys(now))

    def stats(self):
        full = sum(1 for w in self._windows.values() if len(w) >= self.maxlen)
        return {"active_keys": len(self._windows),
                "distinct_ips": len({ip for ip, _ in self._windows}),
                "full_windows": full}


V2_IDLE_TIMEOUT = 300.0      # s; L7 v2 sessions (ml/l7v2_model_prereg.json ingest.idle_timeout_s)
V2_MAX_RECORDS = 2048        # records kept per v2 key at most (engine.max_records_per_key)
V2_MAX_VIEWS = 32            # view tokens a v2 window holds (views.max_views)
V2_PAGE_CLASSES = ("C1",)    # the route classes that open a view (site_map.page)


class L7KeyStore:
    """L7 v2: per (IP, ua_hash, sid_hash) key, the key's records in arrival order, for the view engine.

    The engine prunes a key to the history its next windows need (prune_before); a record that started before a
    key's pruning point is dropped on arrival (`late`), so a pruned key never grows a spurious token at its front.
    At most `max_records` records are kept per key (the oldest go first, counted as `truncated`). Idle keys are
    evicted as in L7WindowStore. Tokens are counted on arrival (a page request, or any request before the key's
    first page, opens one) for the `full_windows` statistic only.
    """

    def __init__(self, idle_timeout=V2_IDLE_TIMEOUT, max_records=V2_MAX_RECORDS, max_views=V2_MAX_VIEWS):
        self.idle_timeout = idle_timeout
        self.max_records = max_records
        self.max_views = max_views
        self._recs = {}
        self._last_seen = {}
        self._cut = {}
        self._opened = {}
        self.late = self.truncated = 0

    def add(self, rec, now=None):
        """Append a record; return its key. `now` defaults to the record's msec."""
        key = key_v2(rec)
        if rec["msec"] - rec["rt"] < self._cut.get(key, float("-inf")):
            self.late += 1
            return key
        seq = self._recs.setdefault(key, [])
        seq.append(rec)
        if len(seq) > self.max_records:
            del seq[:len(seq) - self.max_records]
            self.truncated += 1
        tokens, page_seen = self._opened.get(key, (0, False))
        is_page = rec.get("rc") in V2_PAGE_CLASSES
        if is_page or not page_seen:
            self._opened[key] = (tokens + 1, page_seen or is_page)
        self._last_seen[key] = now if now is not None else rec.get("msec") or time.time()
        return key

    def records(self, key):
        return self._recs.get(key, [])

    def prune_before(self, key, start):
        """Drop the key's records that started before `start`, and drop later arrivals that did."""
        seq = self._recs.get(key)
        if seq is not None:
            seq[:] = [r for r in seq if r["msec"] - r["rt"] >= start]
            self._cut[key] = start

    def evict_keys(self, now):
        """Drop keys idle for longer than idle_timeout. Return the dropped keys."""
        stale = [k for k, ts in self._last_seen.items() if now - ts > self.idle_timeout]
        for key in stale:
            for d in (self._recs, self._last_seen, self._cut, self._opened):
                d.pop(key, None)
        return stale

    def evict(self, now):
        return len(self.evict_keys(now))

    def stats(self):
        full = sum(1 for n, _ in self._opened.values() if n - 1 >= self.max_views)
        return {"active_keys": len(self._recs), "distinct_ips": len({k[0] for k in self._recs}),
                "full_windows": full, "late_dropped": self.late, "truncated": self.truncated}


def group_id(group):
    """The gid of a group given by name or number; ValueError if there is no such group."""
    if isinstance(group, int):
        return group
    import grp
    try:
        return grp.getgrnam(str(group)).gr_gid
    except KeyError as e:
        raise ValueError(f"no group {group!r}") from e


class SyslogDatagramReader:
    """Bind a Unix-domain datagram socket and yield raw access-log datagrams.

    SOCK_DGRAM, so a slow reader never blocks Nginx: the kernel drops datagrams
    past the socket buffer (and max_dgram_qlen) instead. Drops are not visible to
    the receiver; P1 measures them by comparing `received` with the durable file
    sink's line count (docs/L7_GRU_DESIGN.md §4.3).
    """

    def __init__(self, path=DEFAULT_SOCKET_PATH, rcvbuf=DEFAULT_RCVBUF,
                 unlink_stale=True, mode=DEFAULT_SOCKET_MODE, group=None):
        self.path = path
        if unlink_stale:
            self._unlink()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except OSError:
            pass
        self.sock.bind(path)
        if group is not None:
            # The L7 v2 enforcing arm binds 0660 with nginx's group (T-042 E06): a datagram here can drive a ban.
            os.chown(path, -1, group_id(group))
        if mode is not None:
            # Let the unprivileged Nginx worker send to a root-bound socket.
            os.chmod(path, mode)
        self.mode = stat.S_IMODE(os.stat(path).st_mode)
        self.rcvbuf = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)

    def _unlink(self):
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass

    def messages(self, stop=None, timeout=0.5, yield_timeouts=False):
        """Yield raw datagrams (bytes) until `stop` (a callable → bool) is true.

        `timeout` bounds how often `stop` is re-checked while idle. With
        `yield_timeouts=True`, an idle timeout yields None, so a caller can do
        periodic work (e.g. emit a heartbeat) even when no datagrams arrive.
        """
        self.sock.settimeout(timeout)
        while not (stop() if stop else False):
            try:
                data = self.sock.recv(_RECV_SIZE)
            except TimeoutError:
                if yield_timeouts:
                    yield None
                continue
            except OSError:
                break
            if data:
                yield data

    def close(self):
        try:
            self.sock.close()
        finally:
            self._unlink()
