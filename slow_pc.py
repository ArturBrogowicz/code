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
