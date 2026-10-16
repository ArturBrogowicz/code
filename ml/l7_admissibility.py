"""Benign admissibility gate for P5b (docs/L7_GRU_DESIGN.md §7.2, §7.2.1).

A benign client that trips a deterministic rule is the deterministic layer's false
positive, and one nginx shapes carries the rate-limit signal the GRU learned from
attackers; neither is a fair comparison. So each P5b benign kind must stay under the
deployed limits with margin, like the attacks (§7). This module checks that by
SIMULATING the exact plan the generator will run (ml/l7_benign.plan_client) against
replicas of the deployed mechanisms:

  l7_rate     control_plane's rule, verbatim: per IP, a 10 s window of (time, is_error);
              with >= 5 entries, rps = n / max(span, 1 s); bans at rps > 50, or at error
              ratio > 0.8 with rps > 10 (503 is not an error). Margin: rps <= 45.
  limit_req   nginx's bucket (30 r/s, burst 100, nodelay): excess = max(0, excess -
              rate*dt + 1); a request is rejected when excess > burst.
  limit_conn  nginx counts requests in flight (not idle connections). Margin: <= 45.
  slowconn    control_plane: >= 8 ESTABLISHED connections and < 250 B ingress in a 1 s
              interval, 3 intervals in a row. Connections stay ESTABLISHED until nginx's
              15 s keep-alive timeout; an interval is idle iff no request starts in it (one
              request is already > 250 B on the wire, so this is conservative). Checked
              at four poll phases; any phase that bans is a trip.

Timing model (the worst case is the fastest client): each request takes SERVICE_S on its
connection — the median $request_time of benign requests in the P3 capture — and a
browser device issues a wave over BROWSER_CONNS connections, most-recently-used first
(urllib3's pool is LIFO), the next wave only after the previous one finished. Network
latency only stretches this timeline.

Rates are reported the way the baselines measure them: the 1 s peak and the maximum mean
over 10 / 30 / 60 s. Stdlib only; pure.
"""
import bisect
import collections
import random

import l7_benign
import l7_traffic

import l7_webapp

SERVICE_S = 0.002          # median benign $request_time, results/2026-10-15_l7-p3-capture
KEEPALIVE_S = float(l7_traffic.THRESHOLDS["nginx_keepalive_timeout_s"])
POLL_PHASES = (0.0, 0.25, 0.5, 0.75)
SUSTAIN_WINDOWS = (10, 30, 60)

LIMITS = l7_traffic.THRESHOLDS     # mirrors control_plane.py / nginx.conf (test-checked)
RPS_MARGIN = 5
CONN_MARGIN = 5


# ───────────────────────── plan → requests on the wire ─────────────────────────

def _device_requests(views, conns):
    """Simulate one browser device: [(start, end, slot, path)] and its connections
    [(open_t, close_t)]."""
    reqs, conn_spans = [], []
    free_at = [0.0] * conns
    last_used = [None] * conns        # end time of the slot's last request
    opened = [None] * conns
    t = views[0]["t"] if views else 0.0
    for v in views:
        for wave in v["waves"]:
            if not wave:
                continue
            wave_end = t
            for path in wave:
                ready = [i for i in range(conns) if free_at[i] <= t]
                if ready:      # LIFO: the most recently used free connection
                    i = max(ready, key=lambda k: (last_used[k] is not None, last_used[k] or 0.0))
                    start = t
                else:
                    i = min(range(conns), key=lambda k: free_at[k])
                    start = free_at[i]
                if last_used[i] is None or start - last_used[i] > KEEPALIVE_S:
                    if opened[i] is not None:
                        conn_spans.append((opened[i], last_used[i] + KEEPALIVE_S))
                    opened[i] = start
                end = start + SERVICE_S
                free_at[i], last_used[i] = end, end
                reqs.append((start, end, i, path))
                wave_end = max(wave_end, end)
            t = wave_end
        t += v["pause_s"]
    for i in range(conns):
        if opened[i] is not None:
            conn_spans.append((opened[i], last_used[i] + KEEPALIVE_S))
    return reqs, conn_spans


def _paced_requests(requests):
    reqs, t = [], 0.0
    for path, gap in requests:
        reqs.append((t, t + SERVICE_S, 0, path))
        t += SERVICE_S + gap
    spans = [(0.0, reqs[-1][1] + KEEPALIVE_S)] if reqs else []
    return reqs, spans


def client_wire(plan, duration_s):
    """All requests of one client IP: (starts, ends, statuses, inflight spans,
    connection spans), cut at duration_s."""
    starts, ends, statuses, spans = [], [], [], []
    for user in plan["users"]:
        if "views" in user:
            reqs, conns = _device_requests(user["views"], l7_benign.BROWSER_CONNS)
        else:
            reqs, conns = _paced_requests(user["requests"])
        for s, e, _slot, path in reqs:
            if s >= duration_s:
                continue
            starts.append(s)
            ends.append(e)
            statuses.append(l7_webapp.route_status("GET", path))
        spans.extend((o, min(c, duration_s)) for o, c in conns if o < duration_s)
    order = sorted(range(len(starts)), key=starts.__getitem__)
    return ([starts[i] for i in order], [ends[i] for i in order],
            [statuses[i] for i in order], spans)


# ───────────────────────── replicas of the deployed mechanisms ─────────────────────────

def l7_rate_scan(times, statuses, lim=LIMITS):
    """control_plane's L7 rate rule over request completion times. Returns (max_rps,
    banned). 503 is not an error, as in the daemon."""
    window = collections.deque()
    max_rps, banned = 0.0, False
    for t, st in sorted(zip(times, statuses, strict=True)):
        window.append((t, st >= 400 and st != 503))
        while window and t - window[0][0] > lim["l7_rate_window_s"]:
            window.popleft()
        if len(window) >= lim["l7_rate_min_requests"]:
            span = t - window[0][0]
            if span > 0:
                rps = len(window) / max(span, 1.0)
                err = sum(1 for _, e in window if e) / len(window)
                max_rps = max(max_rps, rps)
                if rps > lim["l7_rate_ban_rps"] or (err > lim["l7_error_ratio"]
                                                    and rps > lim["l7_error_min_rps"]):
                    banned = True
    return max_rps, banned


def limit_req_scan(starts, lim=LIMITS):
    """nginx limit_req (nodelay): returns (rejected, max_excess)."""
    rate, burst = lim["nginx_limit_req_rps"], lim["nginx_limit_req_burst"]
    excess, last, rejected, peak = 0.0, None, 0, 0.0
    for t in sorted(starts):
        e = 0.0 if last is None else max(0.0, excess - rate * (t - last) + 1.0)
        if e > burst:
            rejected += 1
            continue
        excess, last = e, t
        peak = max(peak, e)
    return rejected, peak


def max_concurrent(intervals):
    """Largest number of [start, end) intervals open at once."""
    events = sorted([(s, 1) for s, _ in intervals] + [(e, -1) for _, e in intervals])
    cur = best = 0
    for _, d in events:
        cur += d
        best = max(best, cur)
    return best


def slowconn_scan(conn_spans, starts, duration_s, lim=LIMITS):
    """(banned, max_established). Established count sampled at each poll; an interval
    is idle iff no request starts in it."""
    opens = sorted(o for o, _ in conn_spans)
    closes = sorted(c for _, c in conn_spans)
    st = sorted(starts)
    step = lim["l4_poll_interval_s"]
    max_est, banned = 0, False
    for phase in POLL_PHASES:
        streak, t = 0, phase + step
        while t <= duration_s:
            est = bisect.bisect_right(opens, t) - bisect.bisect_right(closes, t)
            max_est = max(max_est, est)
            idle = bisect.bisect_left(st, t) == bisect.bisect_left(st, t - step)
            streak = streak + 1 if (est >= lim["slowconn_ban_conns"] and idle) else 0
            if streak >= lim["slowconn_consecutive"]:
                banned = True
            t += step
    return banned, max_est


def rate_profile(times):
    """1 s peak and the maximum mean rps over each SUSTAIN_WINDOWS window."""
    ts = sorted(times)
    out = {"peak_1s": _max_in_window(ts, 1.0)}
    for w in SUSTAIN_WINDOWS:
        out[f"sustained_{w}s"] = round(_max_in_window(ts, float(w)) / w, 3)
    return out


def _max_in_window(ts, w):
    best = j = 0
    for i in range(len(ts)):
        while ts[i] - ts[j] > w:
            j += 1
        best = max(best, i - j + 1)
    return best


# ───────────────────────── the gate ─────────────────────────

def check_client(kind, params, duration_s, seed, lim=LIMITS):
    """Simulate one client (one seed) against every mechanism, at the thresholds `lim`."""
    plan = l7_benign.plan_client(kind, params, duration_s, random.Random(seed))
    starts, ends, statuses, conns = client_wire(plan, duration_s)
    max_rps, rule_ban = l7_rate_scan(ends, statuses, lim)
    rejected, _peak = limit_req_scan(starts, lim)
    inflight = max_concurrent(list(zip(starts, ends, strict=True)))
    slow_ban, max_est = slowconn_scan(conns, starts, duration_s, lim)
    viol = []
    if rule_ban or max_rps > lim["l7_rate_ban_rps"] - RPS_MARGIN:
        viol.append("l7_rate")
    if rejected:
        viol.append("limit_req")
    if inflight > lim["nginx_limit_conn"] - CONN_MARGIN:
        viol.append("limit_conn")
    if slow_ban:
        viol.append("slowconn")
    return {"requests": len(starts), "rule_rps_max": round(max_rps, 2), "rule_ban": rule_ban,
            "limit_req_rejected": rejected, "inflight_max": inflight,
            "established_max": max_est, "slowconn_ban": slow_ban,
            **rate_profile(ends), "violations": viol}


def check_spec(kind, params, duration_s, seeds, lim=LIMITS):
    """A spec is admissible iff no simulated seed violates anything. Returns the
    aggregate: per-mechanism trip counts, medians of the rate profile, worst values."""
    runs = [check_client(kind, params, duration_s, s, lim) for s in seeds]
    trips = collections.Counter(v for r in runs for v in r["violations"])

    def med(key):
        xs = sorted(r[key] for r in runs)
        return xs[len(xs) // 2]
    return {"kind": kind, "params": dict(params), "seeds": len(runs),
            "admissible": not trips, "trips": dict(trips),
            "median": {k: med(k) for k in ("peak_1s", *(f"sustained_{w}s" for w in SUSTAIN_WINDOWS),
                                           "rule_rps_max", "requests")},
            "worst": {"rule_rps_max": max(r["rule_rps_max"] for r in runs),
                      "inflight_max": max(r["inflight_max"] for r in runs),
                      "established_max": max(r["established_max"] for r in runs),
                      "sustained_10s": max(r["sustained_10s"] for r in runs),
                      "limit_req_rejected": max(r["limit_req_rejected"] for r in runs)}}


def bucket_excess(starts, rate):
    """The largest excess nginx's limit_req bucket reaches at `rate` with no burst cap:
    the smallest burst that would reject none of these requests."""
    excess, last, peak = 0.0, None, 0.0
    for t in sorted(starts):
        excess = 0.0 if last is None else max(0.0, excess - rate * (t - last) + 1.0)
        last = t
        peak = max(peak, excess)
    return peak


TOLERANCE = 1.3          # §7.3.3: benign worst case x 1.3, rounded up; relax only


def derive_tolerant(specs, duration_s, seeds, base=LIMITS):
    """The production-tolerable profile (P5c.2, §7.3.3 as amended in §7.3.2.1): for each
    mechanism that the benign specs trip at the `base` thresholds, the threshold becomes the
    simulated worst case over all specs and seeds x TOLERANCE, rounded up; nothing is ever
    tightened, and a mechanism nothing trips keeps its base value. L3/L4 flood thresholds
    are not part of this. Returns (profile, evidence)."""
    import math

    def up(x):
        return math.ceil(x * TOLERANCE - 1e-9)

    reports = [check_spec(k, p, duration_s, seeds, base) for k, p in specs]
    tripped = {m for r in reports for m in r["trips"]}
    worst = {key: max(r["worst"][key] for r in reports)
             for key in ("rule_rps_max", "established_max", "inflight_max", "sustained_10s")}
    prof = dict(base)
    ev = {"tripped": sorted(tripped), "worst": worst, "tolerance": TOLERANCE}
    if "l7_rate" in tripped:
        prof["l7_rate_ban_rps"] = max(base["l7_rate_ban_rps"], up(worst["rule_rps_max"]))
    if "slowconn" in tripped:
        prof["slowconn_ban_conns"] = max(base["slowconn_ban_conns"], up(worst["established_max"]))
    if "limit_conn" in tripped:
        prof["nginx_limit_conn"] = max(base["nginx_limit_conn"], up(worst["inflight_max"]))
    if "limit_req" in tripped:
        rate = max(base["nginx_limit_req_rps"], up(worst["sustained_10s"]))
        excess = 0.0
        for k, p in specs:
            for sd in seeds:
                plan = l7_benign.plan_client(k, p, duration_s, random.Random(sd))
                excess = max(excess, bucket_excess(client_wire(plan, duration_s)[0], rate))
        prof["nginx_limit_req_rps"] = rate
        prof["nginx_limit_req_burst"] = max(base["nginx_limit_req_burst"], up(excess))
        ev["worst"]["bucket_excess_at_rate"] = round(excess, 2)
    return prof, ev


def attack_profile(rps, span_s, seeds):
    """Median rate profile of a closed-loop rate attacker (l7_gen.attack_rate_get:
    request, then an exponential gap) at the same SERVICE_S — for the overlap check."""
    profs = []
    for s in seeds:
        rng, t, ends = random.Random(s), 0.0, []
        while t < span_s:
            ends.append(t + SERVICE_S)
            t += SERVICE_S + rng.expovariate(rps)
        profs.append(rate_profile(ends))
    return {k: sorted(p[k] for p in profs)[len(profs) // 2] for k in profs[0]}


def overlap_check(benign_reports, attack_profiles):
    """O1 (1 s peak) and O2 (60 s sustained): does some ADMISSIBLE benign kind reach the
    lowest fast attacker? A design check that the test can be informative (§7.2 V0); it
    is computed on the plan, never on a model."""
    adm = [r for r in benign_reports if r["admissible"]]
    out = {}
    for key, name in (("peak_1s", "O1_peak"), ("sustained_60s", "O2_sustained")):
        lowest_attack = min(p[key] for p in attack_profiles.values())
        best = max((r["median"][key] for r in adm), default=0)
        out[name] = {"lowest_fast_attacker": lowest_attack, "highest_admissible_benign": best,
                     "overlap": best >= lowest_attack}
    return out
