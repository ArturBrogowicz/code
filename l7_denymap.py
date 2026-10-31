"""L7 v2 enforcing arm, level 1: the deny map that nginx includes (docs/L7V2_DESIGN.md 9.2 and 9.4, F-V7; T-025c).

A protected run's nginx conf maps "$remote_addr|$http_user_agent|$cookie_sid" through
`map ... $l7_deny { default 0; include <run dir>/deny.map; }` and answers 429 when $l7_deny is 1 (l7_conf.py renders
it). The daemon writes deny.map: one line `"<ip>|<ua>|<sid>" 1;` per denied (IP, UA, sid) key, and nothing else. The
User-Agent and the session cookie are client-chosen bytes written into nginx's configuration, so only keys that pass
the write rules of 9.4 are written (key_problem):
  * the IP is a canonical dotted IPv4 address (the testbed's only family, and the XDP ban path's);
  * the UA is printable ASCII (0x20-0x7E), at most 256 bytes, without any of  " \\ { } $  (a ';' is allowed since
    D-038, below);
  * the sid is empty (no cookie) or the server's own format, l7_backend.SID_RE (restated here, so this module stays
    standard library only; tests/test_l7_denymap.py keeps the two equal).
Any other key is refused here; the decision policy (l7_enforce.py) logs it as unenforceable at level 1.

Amendment D-038 (2026-10-31, the user's decision "Allow ';'"): 9.4 as written also excluded ';'. Every User-Agent of
ml/l7_benign.UA_TABLE contains one, so no testbed browser key could have been denied at level 1 (T-025c report F3).
Inside nginx's double quotes ';' is an ordinary character (below), so it is now written; '"', '\\', '$', '{', '}',
bytes outside 0x20-0x7E and UAs over 256 bytes stay excluded.

nginx's semantics this module follows (nginx 1.28.3, the installed version; the map page,
https://nginx.org/en/docs/http/ngx_http_map_module.html, and the source where the page is silent):
  * "Strings are matched ignoring the case" (the page): nginx lower-cases a key when it builds the map
    (ngx_hash_add_key, src/core/ngx_hash.c:804-808) and the source value when it looks it up (ngx_http_map_find,
    src/http/ngx_http_variables.c:2490). Two keys that differ only in case are one key to nginx, and a map that lists
    both does not load ("conflicting parameter", src/http/modules/ngx_http_map_module.c:571-588). The map therefore
    holds one entry per lower-cased key (DenyMap.add answers "present" for the second).
  * "A regular expression should either start from the "~" symbol ... or from the "~*" symbols" (the page), and a
    leading "\\" is dropped from a source value (ngx_http_map_module.c:566-569). Every key here starts with the
    client's IPv4 address, a digit, so no key is a regular expression or loses a character, and none can be one of the
    special parameters (default, hostnames, include, volatile), which are single words.
  * Quoting (src/core/ngx_conf_file.c:729-800; the page does not describe it): inside a double-quoted parameter only
    `"` (it ends the parameter) and `\\` (it escapes the next character; \\t \\r \\n become control characters) are
    special, and the parameter may span lines; `;`, `{`, `}`, `$` and `#` are ordinary characters there. The write
    rules exclude `"`, `\\` and every control character, so a key can neither end its string early nor span a line.
  * Size: an entry needs map_hash_bucket_size >= 8 + align(len + 2, 8) + 8 bytes (NGX_HASH_ELT_SIZE,
    src/core/ngx_hash.c:248-288), and the default bucket size is one cache line (32|64|128, the page). The longest key
    written here is 15 + 1 + 256 + 1 + 32 = 305 bytes, so the rendered conf sets the bucket size (l7_conf.py).

The raw side table (RawKeys; T-025b F7). The engine keys on hashes (l7_ingest.key_v2: IP, stable_hash32 of the UA
and of the session id) and drops the raw strings at ingest; the map needs them. RawKeys keeps, per key, the raw (UA,
sid) that nginx will compare, in memory only and only for keys that pass the write rules; a key that fails keeps only
the name of the rule (it is "unenforceable" at level 1). It is a bounded LRU, and nothing in it is logged or written
anywhere but the deny map.

The file is replaced atomically (a temporary file in the same directory, fsync, rename), so nginx never reads a half
written map. TTL bookkeeping: an entry expires DENY_TTL_S after it was added (the daemon's BAN_TTL_SECONDS), and at most
MAX_DENIES entries are active.
"""
import contextlib
import ipaddress
import os
import re
import stat
import tempfile
from collections import OrderedDict

import l7_ingest

DENY_FILE = "deny.map"
MAX_DENIES = 2000              # 9.3: active denies at most
DENY_TTL_S = 300               # 9.2: like control_plane.BAN_TTL_SECONDS
MAX_UA_BYTES = 256             # 9.4
MAX_RAW_KEYS = 16384           # the raw side table's LRU bound (keys)
FORBIDDEN_UA_CHARS = frozenset('"\\{}$')    # 9.4 with D-038 (';' allowed); only `"` and `\` are special to nginx in quotes
SID_RE = re.compile(r"[0-9a-f]{32}")       # l7_backend.SID_RE
SEP = "|"
# what one line of deny.map is, exactly (the tests read the file with this and with a port of nginx's tokenizer)
LINE_RE = re.compile(r'"((?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}'
                     r'\|[\x20\x21\x23\x25-\x5b\x5d-\x7a\x7c\x7e]*\|(?:[0-9a-f]{32})?)" 1;')


def ip_problem(ip):
    """None if `ip` is a canonical dotted IPv4 address (what $remote_addr prints), else why not."""
    if not isinstance(ip, str) or not ip.isascii():
        return "ip_format"
    try:
        canonical = str(ipaddress.IPv4Address(ip))
    except ValueError:
        return "ip_format"
    return None if canonical == ip else "ip_format"


def ua_problem(ua):
    """None if the User-Agent may be written into the map (9.4), else why not."""
    if not isinstance(ua, str):
        return "ua_type"
    if not all(0x20 <= ord(c) <= 0x7E for c in ua):
        return "ua_not_printable_ascii"
    if len(ua) > MAX_UA_BYTES:                # printable ASCII: one byte per character
        return "ua_too_long"
    if any(c in FORBIDDEN_UA_CHARS for c in ua):
        return "ua_forbidden_char"
    return None


def sid_problem(sid):
    """None if the session id is empty (no cookie) or in the server's own format, else why not."""
    if sid == "":
        return None
    if not isinstance(sid, str) or not SID_RE.fullmatch(sid):
        return "sid_format"
    return None


def key_problem(ip, ua, sid):
    """None if the (IP, UA, sid) key passes the write rules of 9.4, else the first rule it fails."""
    return ip_problem(ip) or ua_problem(ua) or sid_problem(sid)


def map_key(ip, ua, sid):
    """The source value nginx computes for this client: "$remote_addr|$http_user_agent|$cookie_sid"."""
    problem = key_problem(ip, ua, sid)
    if problem:
        raise ValueError(f"the key fails the write rules: {problem}")
    return f"{ip}{SEP}{ua}{SEP}{sid}"


def line(key):
    """One line of deny.map."""
    return f'"{key}" 1;\n'


class Entry:
    """One active deny: the key's parts, its map key, when it was added and when a reload first published it."""

    __slots__ = ("ip", "key", "sid", "t_added", "t_loaded", "ua")

    def __init__(self, ip, ua, sid, t_added):
        self.ip, self.ua, self.sid = ip, ua, sid
        self.key = map_key(ip, ua, sid)
        self.t_added = t_added
        self.t_loaded = None

    @property
    def ident(self):
        return self.key.lower()


def prepare_run_dir(run_dir):
    """Create the run directory (mode 0700) and an empty deny.map if they are missing, and return the map's path. A run
    directory the daemon does not own, or one that others may write to, is refused: whoever can write there can write
    nginx's configuration."""
    if not os.path.lexists(run_dir):
        os.makedirs(run_dir, mode=0o700)
    st = os.lstat(run_dir)
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"{run_dir}: not a directory")
    if st.st_uid != os.geteuid():
        raise ValueError(f"{run_dir}: owned by uid {st.st_uid}, not by this process ({os.geteuid()})")
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise ValueError(f"{run_dir}: writable by group or others (mode {stat.S_IMODE(st.st_mode):o})")
    path = os.path.join(run_dir, DENY_FILE)
    if not os.path.lexists(path):
        write_atomic(path, b"")
    return path


def write_atomic(path, data):
    """Replace `path` with `data`: a temporary file in the same directory, fsync, rename. On any error the old file is
    left as it was and the temporary file is removed."""
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class DenyMap:
    """The active denies of one run and the file nginx includes. Not thread-safe: one thread (the arm's) owns it."""

    def __init__(self, run_dir, ttl=DENY_TTL_S, cap=MAX_DENIES):
        self.run_dir = run_dir
        self.path = os.path.join(run_dir, DENY_FILE)
        self.ttl = ttl
        self.cap = cap
        self._entries = {}             # ident (the lower-cased map key) -> Entry
        self.dirty = False             # changed since the last successful reload

    def __len__(self):
        return len(self._entries)

    def __iter__(self):
        return iter(list(self._entries.values()))

    def get(self, ident):
        return self._entries.get(ident)

    def add(self, ip, ua, sid, now):
        """(status, detail): ("added", entry), ("present", the entry that already covers this key, nginx matching
        case-insensitively), ("capped", None) at `cap` active denies, or ("refused", the rule the key fails)."""
        problem = key_problem(ip, ua, sid)
        if problem:
            return "refused", problem
        ident = map_key(ip, ua, sid).lower()
        if ident in self._entries:
            return "present", self._entries[ident]
        if len(self._entries) >= self.cap:
            return "capped", None
        entry = Entry(ip, ua, sid, now)
        self._entries[ident] = entry
        self.dirty = True
        return "added", entry

    def expire(self, now):
        """Remove and return the entries added more than `ttl` seconds ago (strictly, as the daemon's TTL sweep)."""
        gone = [e for e in self._entries.values() if now - e.t_added > self.ttl]
        for e in gone:
            del self._entries[e.ident]
        if gone:
            self.dirty = True
        return gone

    def clear(self):
        """Remove and return every entry."""
        gone = list(self._entries.values())
        self._entries.clear()
        if gone:
            self.dirty = True
        return gone

    def loaded(self, now):
        """Record a successful reload at `now`: every entry not yet published is from now in effect."""
        for e in self._entries.values():
            if e.t_loaded is None:
                e.t_loaded = now
        self.dirty = False

    def text(self):
        """The file's content: one `"key" 1;` line per entry, sorted, nothing else (an empty map is an empty file)."""
        return "".join(line(self._entries[i].key) for i in sorted(self._entries))

    def write(self):
        """Write the file atomically; returns its path."""
        write_atomic(self.path, self.text().encode("ascii"))
        return self.path


def raw_strings(obj):
    """(UA, sid) as nginx's map will see them for the client of this parsed l7json log object: the User-Agent field as
    logged (the value l7_ingest.normalise hashes), and the session id of the key: `sid_set`, the cookie the answer set,
    if present, else the request's `sid` cookie, as l7_ingest.sid_hash chooses. Without either, the sid is the `sid`
    field as logged: "" when the client sent no cookie (escape=json logs an absent variable as nothing,
    ngx_http_log_module.c:1059-1061 of nginx 1.28.3), or a literal value such as "-", which then fails the write rules
    (the hash reads "-" as absent, the map would not)."""
    ua = obj.get("ua") or obj.get("user_agent") or ""
    for name in l7_ingest.SID_FIELDS:
        value = obj.get(name)
        if value is not None and str(value).strip() not in l7_ingest.ABSENT:
            return ua, value
    return ua, obj.get("sid") or ""


class RawKeys:
    """The enforcement-only side table: (IP, ua_hash, sid_hash) -> the raw (UA, sid) of a key that passes the write
    rules, or the rule it fails, and the start of its first request seen (the key-age gate). Bounded LRU. Not
    thread-safe: the caller holds its lock."""

    def __init__(self, max_keys=MAX_RAW_KEYS):
        self.max_keys = max_keys
        self._keys = OrderedDict()     # key -> (ua or None, sid or None, failed rule or None, first start)
        self.evicted = 0
        self.ambiguous = 0

    def __len__(self):
        return len(self._keys)

    def note(self, key, ua, sid, start):
        """Record one request of `key` (its IP is key[0]) with these raw strings, started at `start`."""
        problem = key_problem(key[0], ua, sid)
        old = self._keys.get(key)
        if old is None:
            self._keys[key] = (None, None, problem, start) if problem else (ua, sid, None, start)
            if len(self._keys) > self.max_keys:
                self._keys.popitem(last=False)
                self.evicted += 1
            return
        self._keys.move_to_end(key)
        o_ua, o_sid, o_problem, first = old
        first = min(first, start)
        if o_problem is None and (ua, sid) != (o_ua, o_sid) or o_problem not in (None, "ambiguous") and not problem:
            # two raw forms under one key (a hash collision, or a sid the hash and the map read differently):
            # nginx would deny only one of them, so the key is not written
            self._keys[key] = (None, None, "ambiguous", first)
            self.ambiguous += 1
        else:
            self._keys[key] = (o_ua, o_sid, o_problem, first)

    def lookup(self, key):
        """("ok", ua, sid) for a key the map can deny, else ("unenforceable", the rule, None); "no_raw" when the key is
        not (or no longer) in the table."""
        entry = self._keys.get(key)
        if entry is None:
            return "unenforceable", "no_raw", None
        ua, sid, problem, _first = entry
        return ("unenforceable", problem, None) if problem else ("ok", ua, sid)

    def first_seen(self, key):
        """The start time of the key's first request seen, or None."""
        entry = self._keys.get(key)
        return None if entry is None else entry[3]
