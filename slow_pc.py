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
"""
import ipaddress
import re
from fractions import Fraction
from typing import NamedTuple

# ── Frozen 2026-10-30, before any data (docs/P4_SLOW_DESIGN.md §6.4, D-S4 to D-S6) ──
T_GRID_S = (5, 10, 15, 20)         # T: a connection older than T s can be suspect (T_mit 30 s)
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
DEADLINE_S = 30.0              # the objective: banned within T_mit = 30 s (D-S6)
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
