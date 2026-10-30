"""The per-connection slow-connection rule of P4 (docs/P4_SLOW_DESIGN.md §6-§7).

The deployed slow rules key on the source address: SlowConn counts an address's established
connections (control_plane.py) and bans every subscriber behind a shared address with it. This
rule keys on the connection instead. It judges each established socket of nginx on :80/:443
from the kernel's own counters (`ss -tinpH`), closes the one connection that holds a slot
without being served, and bans an address only on a high-confidence aggregate.

This module is pure and has no side effects at import, so the daemon, the tests and an offline
replay of recorded `ss` snapshots all run the same code.

Frozen before any data (§6.4, §13 rows 1 and 3): the grid of thresholds, the fixed constants
and the rule that picks one grid point from the validation runs. They come first, in their own
commit, and a test pins them: the values are chosen on the validation seeds, never tuned on
the evaluation seeds, and the grid is not widened after seeing data.

Re-registration record. 2026-10-30: T_mit 30 → 90 s, decided by the user BEFORE any data,
because the frozen detector's dribble leg needs 2 data segments after the first poll. At the
frozen pacing: W-SLOW's dry run (T-023, seed 1): median closes 55 s (Slowloris) / 39 s
(slow POST); the independent re-simulation (T-029): 52 s / 36 s, with a median ban at 66 s
at K = 2. The share within 30 s stays reported as a secondary figure.
The same record is in the frozen block, under the pin.
"""
import collections
import gzip
import ipaddress
import json
import re
from fractions import Fraction
from typing import NamedTuple

import l7_ingest

# ── Frozen 2026-10-30, before any data (docs/P4_SLOW_DESIGN.md §6.4, D-S4 to D-S6) ──
T_GRID_S = (5, 10, 15, 20)         # T: a connection older than T s can be suspect (set for T_mit 30 s)
F_GRID_BPS = (16, 64, 256, 1024)   # F: ... if it brought fewer than F bytes/s on average
K_GRID = (2, 3, 4, 6)              # K: closes of one address within BAN_WINDOW_S that ban it
GRID = tuple((t, f, k) for t in T_GRID_S for f in F_GRID_BPS for k in K_GRID)

ANSWERED_MAX_BYTES_80 = 64     # A(80): bytes_acked <= 64 is "unanswered" (a 100 Continue is 25 B)
DRIBBLE_MIN_SEGS = 2           # data segments received after the first poll that saw the socket
PERSISTENCE_POLLS = 3          # consecutive suspect polls before the close (= SLOWCONN_CONSECUTIVE)
BAN_WINDOW_S = 60.0            # the closes of one address are counted over this window
SHARED_UA_KEYS = 3             # an address with this many UA keys or more is never banned ...
UA_WINDOW_S = 600.0            # ... counted in the access log over the last 10 minutes
BAN_TTL_S = 300                # = control_plane.BAN_TTL_SECONDS
MAX_CLOSES_PER_POLL = 500      # caps: above them the decision is logged as "capped"
MAX_BANS_PER_MIN = 20
DEADLINE_S = 90.0              # T_mit: the objective, banned within 90 s, and §10's recovery
# Re-registration record. 2026-10-30: T_mit 30 → 90 s, decided by the user BEFORE any data,
# because the frozen detector's dribble leg needs 2 data segments after the first poll. At the
# frozen pacing: W-SLOW's dry run (T-023, seed 1): median closes 55 s (Slowloris) / 39 s
# (slow POST); the independent re-simulation (T-029): 52 s / 36 s, with a median ban at 66 s
# at K = 2. The share within 30 s stays reported as a secondary figure.
BENIGN_CLOSE_BUDGET = (1, 1000)   # benign connections closed <= 1/1000 (0.1 %) of them
VALIDATION_SEEDS = (4001, 4002)
VALIDATION_RUNS = ("C", "U_loris", "U_post")   # per seed, on profile R, the rule in shadow


class Outcome(NamedTuple):
    """What the rule did at one grid point, summed over every validation run (2 seeds x C,
    U_loris, U_post), the rule replayed offline on the recorded `ss` snapshots. In the replay a
    connection is closed at most once and skipped afterwards, and an address the rule banned is
    skipped for BAN_TTL_S, as if the shadow decisions had been enforced.

    attack_addresses           attacking addresses with at least one established connection to
                               :80 or :443 in the snapshots
    attack_banned_in_time      ... that the rule banned at most DEADLINE_S after the first poll
                               that saw one of their connections
    benign_addresses_banned    benign addresses (every non-attacking one: browser devices, the
                               CGNAT pools, the uploaders and the slow uploaders) banned at least
                               once
    benign_connections         distinct benign connections (5-tuples) in the snapshots
    benign_connections_closed  ... that the rule closed
    slow_uploader_closed       ... of them, connections of the slow_uploader clients
    """
    attack_addresses: int
    attack_banned_in_time: int
    benign_addresses_banned: int
    benign_connections: int
    benign_connections_closed: int
    slow_uploader_closed: int


class Selection(NamedTuple):
    point: tuple | None      # the chosen (T, F, K), or None: no grid point meets the constraints
    share: Fraction | None   # attack_banned_in_time / attack_addresses at that point
    feasible: int            # how many grid points meet the constraints


def feasible(o):
    """The constraints of §6.4, all of which must hold: no benign address banned (the CGNAT
    pools included), at most 0.1 % of the benign connections closed, no slow_uploader
    connection closed. Integer arithmetic, so 1 in 1000 passes and 2 in 1999 does not."""
    num, den = BENIGN_CLOSE_BUDGET
    return (o.benign_addresses_banned == 0 and o.slow_uploader_closed == 0
            and o.benign_connections_closed * den <= o.benign_connections * num)


def select_thresholds(outcomes):
    """The frozen selection rule of §6.4. `outcomes` maps every point of GRID, and nothing
    else, to its Outcome. Among the points that meet the constraints, the one that bans the
    largest share of the attacking addresses in time wins; ties go to the larger T, then the
    smaller F, then the larger K (the more conservative point). If no point meets the
    constraints the rule fails its budget: the result is point=None, reported as such, and the
    grid is not widened."""
    if set(outcomes) != set(GRID) or len(outcomes) != len(GRID):
        raise ValueError(f"outcomes must cover exactly the {len(GRID)} grid points")
    totals = set()
    for point, o in outcomes.items():
        if not isinstance(o, Outcome) or any(type(v) is not int or v < 0 for v in o):
            raise ValueError(f"{point}: an Outcome of non-negative ints is required")
        if (o.attack_banned_in_time > o.attack_addresses
                or o.benign_connections_closed > o.benign_connections
                or o.slow_uploader_closed > o.benign_connections_closed):
            raise ValueError(f"{point}: a part exceeds its whole")
        totals.add((o.attack_addresses, o.benign_connections))
    if len(totals) != 1:
        raise ValueError("the attacking addresses and the benign connections are properties of "
                         "the data and must be the same at every grid point")
    if next(iter(totals))[0] == 0:
        raise ValueError("no attacking address in the validation runs")
    ok = [(Fraction(o.attack_banned_in_time, o.attack_addresses), t, -f, k)
          for (t, f, k), o in outcomes.items() if feasible(o)]
    if not ok:
        return Selection(None, None, 0)
    share, t, neg_f, k = max(ok)
    return Selection((t, -neg_f, k), share, len(ok))
# ── End of the frozen block (tests/test_slow_pc_rule.py pins its text) ──


# ── Reading `ss -tinpH` (§6.1, §6.3; F-S3): one record per established socket ──
# The daemon runs this in server_ns as root once per poll; -p needs root to see nginx's sockets.
SS_ARGV = ["ss", "-tinpH", "state", "established", "( sport = :80 or sport = :443 )"]
PORTS = (80, 443)
OWNER = "nginx"            # the process name of nginx's workers in the `users:` field
INFO_FIELDS = ("bytes_acked", "bytes_received", "bytes_sent", "data_segs_in", "segs_in",
               "segs_out", "lastsnd", "lastrcv", "lastack", "notsent", "rcv_space")
_USERS = re.compile(r'users:\(((?:\("[^"]*",pid=\d+,fd=\d+\),?)+)\)')
_USER_NAME = re.compile(r'\("([^"]*)",pid=\d+,fd=\d+\)')


class Sock(NamedTuple):
    """One established socket of a public listener, as `ss -tinpH` printed it."""
    ip: str          # the client's IPv4 address
    port: int        # the client's port
    local: str       # the server's address
    sport: int       # the server's port, 80 or 443
    owned: bool      # an nginx process holds it; False: still in the listen backlog (F-S5)
    info: dict       # INFO_FIELDS -> int; a token that ss did not print counts as 0 (F-S3)

    @property
    def key(self):
        return (self.ip, self.port, self.local, self.sport)


def _addr(token):
    """(host, port) of ss's "host:port", or None. The brackets of an IPv6 address and the
    IPv4-mapped prefix ::ffff: are removed."""
    host, sep, port = token.rpartition(":")
    if not sep or not (port.isascii() and port.isdigit()) or len(port) > 5:
        return None
    host = host.removeprefix("[").removesuffix("]")
    if host.lower().startswith("::ffff:"):
        host = host[7:]
    return host, int(port)


def _ipv4(host):
    """True for a dotted-quad IPv4 address in its canonical form, the only family the XDP
    ban path takes."""
    try:
        return str(ipaddress.IPv4Address(host)) == host
    except ValueError:
        return False


def parse_block(lines):
    """One socket: its line and the indented lines after it. Returns None when its
    addresses cannot be read (or the server port is not public, or the client is not IPv4),
    else (key, Sock), where Sock is None when a tcp_info token is malformed: that socket is
    then present but not judged this poll (§6.3)."""
    main = lines[0]
    users = _USERS.search(main)
    if users:
        head, tail = main[:users.start()], main[users.end():]
        names = _USER_NAME.findall(users.group(1))
    elif "users:" in main:
        return None
    else:
        head, tail, names = main, "", []
    cols = head.split()           # [State] Recv-Q Send-Q Local Peer: the last two are ours
    if len(cols) < 2:
        return None
    local, peer = _addr(cols[-2]), _addr(cols[-1])
    if local is None or peer is None:
        return None
    (lhost, lport), (ip, port) = local, peer
    if lport not in PORTS or not _ipv4(ip) or not 0 < port < 65536:
        return None
    key = (ip, port, lhost, lport)
    info, seen = dict.fromkeys(INFO_FIELDS, 0), set()
    for tok in " ".join([tail, *lines[1:]]).split():
        name, sep, value = tok.partition(":")
        if not sep or name not in info or name in seen:
            continue
        if not (value.isascii() and value.isdigit()) or len(value) > 20:
            return key, None
        info[name] = int(value)
        seen.add(name)
    return key, Sock(ip, port, lhost, lport, OWNER in names, info)


def parse_ss(text):
    """(socks, present, skipped, bad) of one `ss -tinpH` output: the sockets it listed; the
    keys of every socket whose addresses were readable; how many socket lines were skipped
    (unreadable, repeated, or with a malformed token); and the first skipped line, cut to 160
    characters, for the log."""
    blocks, skipped, bad = [], 0, None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if blocks:
                blocks[-1].append(line)
            else:
                skipped, bad = skipped + 1, bad or line
            continue
        blocks.append([line])
    socks, present = [], set()
    for block in blocks:
        parsed = parse_block(block)
        if parsed is None or parsed[0] in present:
            skipped, bad = skipped + 1, bad or block[0]
            continue
        key, sock = parsed
        present.add(key)
        if sock is None:
            skipped, bad = skipped + 1, bad or block[0]
        else:
            socks.append(sock)
    return socks, present, skipped, (bad[:160] if bad else None)


# ── The rule: the five legs and the persistence (§6.2), the guards (§6.3), the address
#    aggregate, the shared-address guard and the caps (§7) ──
ANSWERED_SLACK_S = 2.0     # :443: a request logged up to this long before the first poll that saw
                           # its connection still answers it (the poll's resolution, with margin)
ANSWERED_KEEP_S = 120.0    # how long a logged (client, port) waits for its socket to be seen
CLOSE_BATCH = 32           # connections per `ss -K` call in the daemon


class Close(NamedTuple):
    """A connection the rule closes (enforcing) or would close (shadow)."""
    ip: str
    port: int
    local: str
    sport: int
    age_s: float           # since the first poll that saw it
    bytes_received: int
    bytes_acked: int
    segs_after: int        # data segments received since that poll
    streak: int            # consecutive suspect polls
    ua_keys: int           # the address's UA keys in the access log, last UA_WINDOW_S


class Ban(NamedTuple):
    ip: str
    closes: int            # its connections closed within BAN_WINDOW_S
    ua_keys: int


class PollResult(NamedTuple):
    closes: list           # Close, the oldest connection first
    capped_closes: int     # suspects over MAX_CLOSES_PER_POLL: still candidates next poll
    bans: list             # Ban
    capped_bans: list      # addresses over MAX_BANS_PER_MIN: judged again next poll
    spared: list           # Ban: the K closes were reached, but the address is shared


class _Conn:
    __slots__ = ("answered", "decided", "first_seen", "segs0", "streak")

    def __init__(self, first_seen, segs0):
        self.first_seen, self.segs0 = first_seen, segs0
        self.streak, self.decided, self.answered = 0, False, False


def l7_item(obj, t):
    """(ip, port or None, UA key, t) of one access-log record, or None without a usable client
    address. It reads the daemon's json_ml_format (client_ip, user_agent, and the client port
    where the format has one, as profile R's does) and the l7json format (ip, port, ua). The UA
    key is the L7 engine's (l7_ingest.stable_hash32), so "UA keys" mean the same thing here."""
    if not isinstance(obj, dict):
        return None
    ip = obj.get("client_ip", obj.get("ip"))
    if not isinstance(ip, str) or not _ipv4(ip):
        return None
    port = obj.get("port", obj.get("client_port"))
    if isinstance(port, str) and port.isascii() and port.isdigit() and len(port) <= 5:
        port = int(port)
    if type(port) is not int or not 0 < port < 65536:
        port = None
    ua = obj.get("user_agent", obj.get("ua"))
    return ip, port, l7_ingest.stable_hash32(ua if isinstance(ua, str) else ""), t


class Detector:
    """The rule at one grid point (t_s, f_bps, k). Each poll, call poll() with the text that
    `ss -tinpH` printed, or skip() when that call failed. The detector decides; its caller
    enforces the decisions or only logs them, and reports the closes it issued with closed().
    Pure: the caller passes the time, and nothing here touches the system."""

    def __init__(self, t_s, f_bps, k, ttl_s=BAN_TTL_S):
        if (t_s, f_bps, k) not in GRID:
            raise ValueError(f"({t_s}, {f_bps}, {k}) is not a point of the frozen grid")
        self.t_s, self.f_bps, self.k, self.ttl_s = t_s, f_bps, k, ttl_s
        self.conns = {}          # key -> _Conn
        self.closes = {}         # ip -> deque of (t, key): its connections closed
        self.ua = {}             # ip -> {UA key: the last t it was logged}
        self.answered = {}       # (ip, port) -> the last t a request on that client port completed
        self.banned_until = {}   # ip -> t: the rule's own bans, whose sockets it skips meanwhile
        self.ban_times = collections.deque()   # the t of each ban, for MAX_BANS_PER_MIN
        self.pending = set()     # addresses whose ban was capped
        self.issued = set()      # keys the caller closed after the last poll
        self.ports_seen = False  # has the access log shown a client port yet? (_suspect, :443)
        self.stats = collections.Counter()
        self.gauges = {"sockets": 0, "owned": 0}
        self.bad_sample = None

    # ── inputs ──
    def take_l7(self, items):
        for ip, port, ua_key, t in items:
            seen = self.ua.setdefault(ip, {})
            seen[ua_key] = max(t, seen.get(ua_key, t))
            if port is not None:
                self.ports_seen = True
                self.answered[(ip, port)] = max(t, self.answered.get((ip, port), t))

    def ua_keys(self, ip, now):
        return sum(1 for t in self.ua.get(ip, {}).values() if t >= now - UA_WINDOW_S)

    def closed(self, keys):
        """The caller closed these connections: the next poll checks that they are gone."""
        self.issued = set(keys)

    def skip(self, now, l7_items=()):
        """A poll whose `ss` call failed: the access-log items are kept, and nothing else
        changes. In particular no streak is reset to clean (§6.3)."""
        self.take_l7(l7_items)
        self.stats["ss_failed"] += 1

    # ── one poll ──
    def poll(self, now, text, l7_items=(), banned=()):
        """Judge every socket of one `ss -tinpH` output at time `now`. `banned` are the
        addresses other engines banned: their sockets are not judged."""
        self.take_l7(l7_items)
        self._expire(now)
        socks, present, skipped, bad = parse_ss(text)
        st = self.stats
        st["polls"] += 1
        st["skipped_lines"] += skipped
        self.bad_sample = self.bad_sample or bad
        st["close_failed"] += len(self.issued & present)
        self.issued = set()
        out = set(banned) | set(self.banned_until)
        candidates, owned = [], 0
        for s in socks:
            if s.ip in out:
                self.conns.pop(s.key, None)
                continue
            c = self.conns.get(s.key)
            if c is None:
                c = self.conns[s.key] = _Conn(now, s.info["data_segs_in"])
            owned += s.owned
            if c.decided:
                continue
            if self._suspect(s, c, now):
                c.streak += 1
                st["suspect"] += 1
                if c.streak >= PERSISTENCE_POLLS:
                    candidates.append((c.first_seen, s.key, s, c))
            else:
                c.streak = 0
        for key in [k for k in self.conns if k not in present]:
            del self.conns[key]
        self.gauges = {"sockets": len(socks), "owned": owned}
        candidates.sort(key=lambda x: (x[0], x[1]))
        closes = []
        for first_seen, key, s, c in candidates[:MAX_CLOSES_PER_POLL]:
            c.decided = True
            self.closes.setdefault(s.ip, collections.deque()).append((now, key))
            closes.append(Close(s.ip, s.port, s.local, s.sport, round(now - first_seen, 3),
                                s.info["bytes_received"], s.info["bytes_acked"],
                                s.info["data_segs_in"] - c.segs0, c.streak,
                                self.ua_keys(s.ip, now)))
        capped = max(0, len(candidates) - MAX_CLOSES_PER_POLL)
        bans, capped_bans, spared = self._judge({cl.ip for cl in closes} | self.pending, out, now)
        st["closes"] += len(closes)
        st["capped_closes"] += capped
        st["bans"] += len(bans)
        st["capped_bans"] += len(capped_bans)
        st["spared"] += len(spared)
        return PollResult(closes, capped, bans, capped_bans, spared)

    def _suspect(self, s, c, now):
        """The five legs of §6.2: owned, old, unanswered, slow, dribbling. On :443 only the
        access log can answer a connection (§6.3), and only a log that carries the client port:
        until one record with a port has arrived, no :443 connection is judged unanswered (with
        the deployed json_ml_format, which has no port, every one would be)."""
        if s.sport == 443 and not c.answered:
            t = self.answered.get((s.ip, s.port))
            c.answered = t is not None and t >= c.first_seen - ANSWERED_SLACK_S
        age = now - c.first_seen
        unanswered = (s.info["bytes_acked"] <= ANSWERED_MAX_BYTES_80 if s.sport == 80
                      else self.ports_seen and not c.answered)
        return (s.owned and age > self.t_s and unanswered
                and s.info["bytes_received"] < self.f_bps * age
                and s.info["data_segs_in"] - c.segs0 >= DRIBBLE_MIN_SEGS)

    def _judge(self, ips, out, now):
        """The address aggregate of §7.2: >= K closes within BAN_WINDOW_S and fewer than
        SHARED_UA_KEYS UA keys; at most MAX_BANS_PER_MIN bans in any 60 s."""
        bans, capped, spared = [], [], []
        for ip in sorted(ips):
            n = len(self.closes.get(ip, ()))
            if n < self.k or ip in out:
                self.pending.discard(ip)
                continue
            keys = self.ua_keys(ip, now)
            if keys >= SHARED_UA_KEYS:
                self.pending.discard(ip)
                spared.append(Ban(ip, n, keys))
                continue
            if len(self.ban_times) >= MAX_BANS_PER_MIN:
                self.pending.add(ip)
                capped.append(ip)
                continue
            self.pending.discard(ip)
            self.ban_times.append(now)
            self.banned_until[ip] = now + self.ttl_s
            self.closes.pop(ip, None)
            for key in [k for k in self.conns if k[0] == ip]:
                del self.conns[key]
            bans.append(Ban(ip, n, keys))
        return bans, capped, spared

    def _expire(self, now):
        for ip in list(self.ua):
            seen = {u: t for u, t in self.ua[ip].items() if t >= now - UA_WINDOW_S}
            if seen:
                self.ua[ip] = seen
            else:
                del self.ua[ip]
        self.answered = {k: t for k, t in self.answered.items() if t >= now - ANSWERED_KEEP_S}
        for ip in [ip for ip, until in self.banned_until.items() if until < now]:
            del self.banned_until[ip]
        while self.ban_times and self.ban_times[0] <= now - 60.0:
            self.ban_times.popleft()
        for ip in list(self.closes):
            q = self.closes[ip]
            while q and q[0][0] < now - BAN_WINDOW_S:
                q.popleft()
            if not q:
                del self.closes[ip]

    def take_stats(self):
        """The counters since the last call (then reset), the gauges and the first skipped line."""
        names = ("polls", "ss_failed", "suspect", "closes", "capped_closes", "bans",
                 "capped_bans", "spared", "skipped_lines", "close_failed")
        out = {n: self.stats.get(n, 0) for n in names}
        out.update(self.gauges, tracked=len(self.conns), bad_sample=self.bad_sample)
        self.stats.clear()
        self.bad_sample = None
        return out


# ── Recording and replay (§6.1: every poll's input is recorded, so every rule can be replayed) ──
def record_member(now, text, items, banned, enforce):
    """One poll's input as one gzip member of a SLOW_PC_RECORD file: the `ss -tinpH` text (None
    when the call failed), the access-log items, the addresses the daemon had banned and whether
    the rule enforced. Concatenated members make one gzip file, and a run that ends mid-write
    loses at most the member it was writing."""
    line = json.dumps({"t": now, "ss": text, "l7": [list(i) for i in items],
                       "banned": sorted(banned), "enforce": enforce}, separators=(",", ":"))
    return gzip.compress((line + "\n").encode("utf-8"))


def read_record(path):
    """The polls of a SLOW_PC_RECORD file, oldest first; a cut last member is dropped."""
    polls = []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        try:
            for line in fh:
                polls.append(json.loads(line))
        except (EOFError, OSError, ValueError):
            pass
    return polls


def replay(polls, t_s, f_bps, k, ttl_s=BAN_TTL_S):
    """The rule at (t_s, f_bps, k) over recorded polls, with every decision taken as enforced (a
    closed connection is skipped afterwards, a banned address for ttl_s): [(t, PollResult)] of the
    polls whose read succeeded. A failed read is a skipped poll, as in the daemon."""
    det = Detector(t_s, f_bps, k, ttl_s)
    out = []
    for p in polls:
        items = [tuple(i) for i in p.get("l7", ())]
        if p.get("ss") is None:
            det.skip(p["t"], items)
        else:
            out.append((p["t"], det.poll(p["t"], p["ss"], items, p.get("banned", ()))))
    return out
