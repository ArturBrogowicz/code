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


def normalise(obj):
    """Turn a parsed log object into the slim record the window store keeps:
    numeric fields coerced, URI and UA replaced by 32-bit hashes, raw strings
    dropped. Returns None if there is no client IP to key on."""
    ip = obj.get("ip") or obj.get("client_ip")
    if not ip:
        return None
    rec = {"ip": ip, "ua_h": stable_hash32(obj.get("ua") or obj.get("user_agent") or ""),
           "uri_h": stable_hash32(obj.get("uri") or obj.get("request_uri") or ""),
           "method": obj.get("method") or obj.get("request_method") or "",
           "proto": obj.get("proto") or obj.get("server_protocol") or "",
           "compl": obj.get("compl") or obj.get("request_completion") or "",
           "lreq": obj.get("lreq") or obj.get("limit_req_status") or "",
           "tls": obj.get("tls") or "", "reused": obj.get("reused") or ""}
    for key, names in _NUMERIC.items():
        rec[key] = _num(next((obj[n] for n in names if n in obj), None))
    return rec


def key_of(rec):
    """The window key: (IP, ua_hash). Bans map back to rec['ip'] for XDP."""
    return (rec["ip"], rec["ua_h"])


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


class SyslogDatagramReader:
    """Bind a Unix-domain datagram socket and yield raw access-log datagrams.

    SOCK_DGRAM, so a slow reader never blocks Nginx: the kernel drops datagrams
    past the socket buffer (and max_dgram_qlen) instead. Drops are not visible to
    the receiver; P1 measures them by comparing `received` with the durable file
    sink's line count (docs/L7_GRU_DESIGN.md §4.3).
    """

    def __init__(self, path=DEFAULT_SOCKET_PATH, rcvbuf=DEFAULT_RCVBUF,
                 unlink_stale=True, mode=DEFAULT_SOCKET_MODE):
        self.path = path
        if unlink_stale:
            self._unlink()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except OSError:
            pass
        self.sock.bind(path)
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
