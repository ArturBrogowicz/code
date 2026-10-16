"""Benign client plans for the P5b benign-overlap re-test (docs/L7_GRU_DESIGN.md §7.2).

Pure and seeded. plan_client(kind, params, duration_s, rng) turns one client's spec into
the exact plan its generator (ml/l7_gen.py) executes, and the admissibility gate
(ml/l7_admissibility.py) simulates that same plan — one definition, so the gate checks
what will actually run. The generator builds the plan from its --seed exactly as the gate
does from the same seed.

Kinds (§7.2):
  browser_page    one device on an asset-heavy site: page views in visits, a cache that
                  persists for the run, a cold first view of `level` same-origin assets
  cgnat_browsers  `users` such devices behind one address, each with its own UA
  api_bulk        a legitimate integration job: steady Poisson requests to 2-3 endpoints
  crawler_polite  /robots.txt, then each page and its images at a slow, jittered rate

Model values, frozen by the P5b.0 build commit before any capture (§7.2 rule 4). Sources
are in §7.2 and §7.2.2; an [ASSUMPTION] there is declared, not measured:
  * site: PAGE_UNIVERSE pages with Zipf-like popularity (ZIPF_ALPHA, the middle of the
    0.64-0.83 range reported for web proxy traces); page assets from l7_webapp;
  * user: think time negative-exponential, mean THINK_MEAN_S, capped at THINK_CAP_S (the
    TPC-W convention); VIEWS_PER_VISIT views per visit; VISIT_GAP_S between visits;
    static assets carry max-age=3600, longer than any run, so a device never re-requests
    an asset it has loaded;
  * transport: HTTP/1.1 keep-alive with BROWSER_CONNS connections per device (§7.2.1);
  * UAs: UA_TABLE, reduced (frozen) browser UA strings with approximate global shares, so
    devices on the same browser and OS collide as they do in the wild.
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import l7_webapp

PAGE_UNIVERSE = 200
ZIPF_ALPHA = 0.75
THINK_MEAN_S = 7.0
THINK_CAP_S = 70.0
VIEWS_PER_VISIT = (3, 15)
VISIT_GAP_S = (30.0, 120.0)
BROWSER_CONNS = 6

API_ENDPOINTS = ("/api/sync", "/api/items", "/api/status")
API_UA = "SyncAgent/3.2 (integration)"
CRAWLER_UA = "TestbedCrawler/1.0 (+http://10.0.0.1/robots.txt)"
CRAWLER_JITTER = (0.8, 1.2)

_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
_ANDROID = "Mozilla/5.0 (Linux; Android 10; K)"
_WEBKIT = "AppleWebKit/537.36 (KHTML, like Gecko)"
_SAFARI_KIT = "AppleWebKit/605.1.15 (KHTML, like Gecko)"


def _chrome(platform, v, tail="Safari/537.36"):
    return f"{platform} {_WEBKIT} Chrome/{v}.0.0.0 {tail}"


def _ios(o, v):
    return (f"Mozilla/5.0 (iPhone; CPU iPhone OS {o} like Mac OS X) {_SAFARI_KIT} "
            f"Version/{v} Mobile/15E148 Safari/604.1")


# (weight, UA). Chrome-family strings are in the reduced form (minor/build/patch "0.0.0",
# Windows NT 10.0, macOS 10_15_7, "Android 10; K"). Weights approximate public browser
# share snapshots (Chrome ~65-70 %, Safari, Edge ~10 %, Firefox ~4 %, others) and two
# versions per browser (current and previous; auto-update keeps most users current).
UA_TABLE = (
    (0.27, _chrome(_WIN, 141)),
    (0.08, _chrome(_WIN, 140)),
    (0.16, _chrome(_ANDROID, 141, "Mobile Safari/537.36")),
    (0.05, _chrome(_ANDROID, 140, "Mobile Safari/537.36")),
    (0.06, _chrome(_MAC, 141)),
    (0.02, _chrome(_MAC, 140)),
    (0.02, _chrome("Mozilla/5.0 (X11; Linux x86_64)", 141)),
    (0.07, _ios("18_6", "18.6")),
    (0.03, _ios("18_5", "18.5")),
    (0.03, _ios("26_0", "26.0")),
    (0.03, f"{_MAC} {_SAFARI_KIT} Version/18.6 Safari/605.1.15"),
    (0.07, _chrome(_WIN, 141, "Safari/537.36 Edg/141.0.0.0")),
    (0.02, _chrome(_WIN, 140, "Safari/537.36 Edg/140.0.0.0")),
    (0.03, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"),
    (0.01, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0"),
    (0.02, f"{_ANDROID} {_WEBKIT} SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36"),
    (0.02, _chrome(_WIN, 141, "Safari/537.36 OPR/125.0.0.0")),
)


def _cdf(weights):
    total, out = 0.0, []
    for w in weights:
        total += w
        out.append(total)
    return [c / total for c in out]


_UA_CDF = _cdf([w for w, _ in UA_TABLE])
_ZIPF_CDF = _cdf([1.0 / (k ** ZIPF_ALPHA) for k in range(1, PAGE_UNIVERSE + 1)])


def draw_ua(rng):
    """One UA string from UA_TABLE by weight."""
    return UA_TABLE[min(bisect.bisect_left(_UA_CDF, rng.random()), len(UA_TABLE) - 1)][1]


def zipf_page(rng):
    """A page id in 1..PAGE_UNIVERSE with Zipf-like popularity (page 1 most popular)."""
    return min(bisect.bisect_left(_ZIPF_CDF, rng.random()), PAGE_UNIVERSE - 1) + 1


def think_time(rng):
    return min(rng.expovariate(1.0 / THINK_MEAN_S), THINK_CAP_S)


def browser_views(level, duration_s, rng, first_visit_s=(0.0, 30.0)):
    """One device's page views, in order: [{"t", "page", "waves", "pause_s"}].

    `t` is the nominal start (zero load time); `waves` are the request paths in dependency
    order — [HTML], then CSS/JS, then fonts + page images — minus what the device has
    already loaded; `pause_s` is what the device waits after the view has loaded (think
    time, plus the gap to the next visit after a visit's last view)."""
    wave1_all, fonts = l7_webapp.site_assets(level)
    cached = set()
    views = []
    t = rng.uniform(*first_visit_s)
    while t < duration_s:
        n = rng.randint(*VIEWS_PER_VISIT)
        for i in range(n):
            page = zipf_page(rng)
            wave1 = [p for p in wave1_all if p not in cached]
            wave2 = [p for p in fonts + l7_webapp.page_assets(level, page) if p not in cached]
            cached.update(wave1)
            cached.update(wave2)
            pause = think_time(rng)
            if i == n - 1:
                pause += rng.uniform(*VISIT_GAP_S)
            views.append({"t": round(t, 4), "page": page,
                          "waves": [[f"/page/{page}"], wave1, wave2], "pause_s": round(pause, 4)})
            t += pause
            if t >= duration_s:
                break
    return views


def _paced(paths, rps, duration_s, rng, jitter=None):
    """[(path, gap_s)]: issue `path`, then wait gap_s; Poisson gaps, or 1/rps x jitter."""
    out, t, i = [], 0.0, 0
    while t < duration_s:
        gap = (rng.uniform(*jitter) / rps) if jitter else rng.expovariate(rps)
        out.append((paths(i, rng), round(gap, 5)))
        t += gap
        i += 1
    return out


def plan_client(kind, params, duration_s, rng):
    """The plan for one client. Every kind returns {"kind", "users": [...]}; a user is
    {"ua", "views"} (browser-like) or {"ua", "requests": [(path, gap_s)]} (paced)."""
    if kind == "browser_page":
        ua = draw_ua(rng)
        views = browser_views(params["level"], duration_s, rng,
                              tuple(params.get("first_visit_s", (0.0, 30.0))))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
    if kind == "cgnat_browsers":
        users = []
        for _ in range(params["users"]):
            urng = type(rng)(rng.randrange(2**31))
            ua = draw_ua(urng)
            users.append({"ua": ua, "views": browser_views(
                params["level"], duration_s, urng, tuple(params.get("first_visit_s", (0.0, 60.0))))})
        return {"kind": kind, "users": users}
    if kind == "api_bulk":
        rps = rng.uniform(*params["rps"])
        k = rng.randint(*params.get("endpoints", (2, 3)))
        eps = rng.sample(API_ENDPOINTS, k)
        reqs = _paced(lambda _i, r: r.choice(eps), rps, duration_s, rng)
        return {"kind": kind, "rps": round(rps, 3), "endpoints": eps,
                "users": [{"ua": API_UA, "requests": reqs}]}
    if kind == "crawler_polite":
        rps = rng.uniform(*params["rps"])
        level = params.get("level", 30)
        order = ["/robots.txt"]
        for page in range(1, PAGE_UNIVERSE + 1):
            order.append(f"/page/{page}")
            order.extend(l7_webapp.page_assets(level, page))
        reqs = _paced(lambda i, _r: order[i % len(order)], rps, duration_s, rng, CRAWLER_JITTER)
        return {"kind": kind, "rps": round(rps, 3), "users": [{"ua": CRAWLER_UA, "requests": reqs}]}
    raise ValueError(f"not a P5b benign kind: {kind}")


KINDS = ("browser_page", "cgnat_browsers", "api_bulk", "crawler_polite")
