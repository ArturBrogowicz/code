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

L7 v2 (docs/L7V2_DESIGN.md §7.2, §8.4, §12; frozen in ml/l7v2_prereg.json) adds, all opt-in through
params, so a client without them gets exactly its P5b plan:
  * "nav": "tpcw:browsing" | "tpcw:shopping" on browser_page and cgnat_browsers: page views follow the
    TPC-W v1.8 chain of that mix (ml/l7_tpcw.py), in-session from Home, watched on the mapped states,
    think time negative-exponential (mean think_mean_s, the spec's 7-8 s), product pages Zipf as above;
  * "referer": true with the i.i.d. Zipf model ("nav" absent or "zipf"): views carry their Referer;
  * kinds tpcw_browsing and tpcw_shopping (one TPC-W device of that mix, Referer on: distinct names, so a
    held-out mix is labelled apart), search_user, exporter and flash_crowd (TPC-W browsing devices
    arriving within 60 s).
Every L7 v2 view carries "ref" (the Referer of its first wave: the device's previous document, None at
entry) and "doc" (its document, the Referer of its later waves); an "inpage" view is one request
(/search or /export) issued from the current document. The device's requests.Session keeps the cookies
the server sets.
"""
import bisect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import l7_webapp

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import l7_tpcw
import l7v2_prereg

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


def think_time(rng, mean_s=THINK_MEAN_S):
    return min(rng.expovariate(1.0 / mean_s), THINK_CAP_S)


# Per-entity model values (docs/P3_DATASET_DESIGN.md §4.3): a P3 plan may draw these per device and
# pass them in the client's params; a client without them gets the frozen module values above, so
# every earlier plan (P5b, P5c) is unchanged draw for draw.
MODEL_KEYS = ("think_mean_s", "views_per_visit", "visit_gap_s")


def model_values(params):
    """The browser model values a client's params override, as browser_views() keywords."""
    out = {}
    if "think_mean_s" in params:
        out["think_mean_s"] = float(params["think_mean_s"])
    if "views_per_visit" in params:
        out["views_per_visit"] = tuple(int(x) for x in params["views_per_visit"])
    if "visit_gap_s" in params:
        out["visit_gap_s"] = tuple(float(x) for x in params["visit_gap_s"])
    return out


def browser_views(level, duration_s, rng, first_visit_s=(0.0, 30.0), *, think_mean_s=THINK_MEAN_S,
                  views_per_visit=VIEWS_PER_VISIT, visit_gap_s=VISIT_GAP_S, referer=False):
    """One device's page views, in order: [{"t", "page", "waves", "pause_s"}].

    `t` is the nominal start (zero load time); `waves` are the request paths in dependency
    order — [HTML], then CSS/JS, then fonts + page images — minus what the device has
    already loaded; `pause_s` is what the device waits after the view has loaded (think
    time, plus the gap to the next visit after a visit's last view). The keyword model
    values default to the frozen module values. With `referer` (L7 v2) each view also
    carries "ref" (the previous page of its visit, None for a visit's first view) and "doc";
    the draws are the same either way."""
    wave1_all, fonts = l7_webapp.site_assets(level)
    cached = set()
    views = []
    t = rng.uniform(*first_visit_s)
    while t < duration_s:
        n = rng.randint(*views_per_visit)
        prev = None
        for i in range(n):
            page = zipf_page(rng)
            wave1 = [p for p in wave1_all if p not in cached]
            wave2 = [p for p in fonts + l7_webapp.page_assets(level, page) if p not in cached]
            cached.update(wave1)
            cached.update(wave2)
            pause = think_time(rng, think_mean_s)
            if i == n - 1:
                pause += rng.uniform(*visit_gap_s)
            views.append({"t": round(t, 4), "page": page,
                          "waves": [[f"/page/{page}"], wave1, wave2], "pause_s": round(pause, 4)})
            if referer:
                views[-1]["ref"], views[-1]["doc"] = prev, f"/page/{page}"
                prev = f"/page/{page}"
            t += pause
            if t >= duration_s:
                break
    return views


def page_key(path):
    """The key of a document path for its page images: "/" is "home", "/page/<n>" is n (an int when n is digits)."""
    if path == "/":
        return "home"
    key = path[len("/page/"):]
    return int(key) if key.isdigit() else key


class _Device:
    """One L7 v2 browser device being planned: its asset cache, its current document and its views."""

    def __init__(self, level):
        self.level = level
        self.wave1_all, self.fonts = l7_webapp.site_assets(level)
        self.cached, self.views, self.doc = set(), [], None

    def page(self, t, path, pause, state=None, ref="current"):
        """A page view of `path`: HTML, then the CSS/JS and the fonts and images not yet cached. Its Referer is the
        device's current document unless `ref` is given (None: a direct navigation)."""
        key = page_key(path)
        wave1 = [p for p in self.wave1_all if p not in self.cached]
        wave2 = [p for p in self.fonts + l7_webapp.page_assets(self.level, key) if p not in self.cached]
        self.cached.update(wave1)
        self.cached.update(wave2)
        self._add(t, key, [[path], wave1, wave2], pause, self.doc if ref == "current" else ref, path, state)
        self.doc = path

    def inpage(self, t, path, pause, state=None):
        """One request issued from the current document (a search or an export)."""
        self._add(t, page_key(self.doc), [[path]], pause, self.doc, self.doc, state)

    def _add(self, t, key, waves, pause, ref, doc, state):
        v = {"t": round(t, 4), "page": key, "waves": waves, "pause_s": round(pause, 4), "ref": ref, "doc": doc}
        if state is not None:
            v["state"] = state
        self.views.append(v)


def inpage_path(target, rng):
    """The request of an in-page interaction: a search (one word) or an export."""
    return l7_webapp.search_path(rng) if target == "search" else l7_webapp.export_path(rng)


def tpcw_views(level, duration_s, rng, mix, first_visit_s=(0.0, 30.0), *, think_mean_s=THINK_MEAN_S):
    """One device on the TPC-W v1.8 `mix` chain (docs/L7V2_DESIGN.md §12.1): in-session from Home, the chain watched
    on the mapped states (ml/l7v2_prereg.json), a think time after every interaction, product pages Zipf."""
    routes = l7v2_prereg.routes()
    dev = _Device(level)
    t = rng.uniform(*first_visit_s)
    steps = l7_tpcw.walk(mix, rng, set(routes))
    while t < duration_s:
        state = next(steps)
        kind, target = routes[state]
        if kind == "inpage":
            path = inpage_path(target, rng)
            pause = think_time(rng, think_mean_s)
            dev.inpage(t, path, pause, state)
        else:
            path = f"/page/{zipf_page(rng)}" if kind == "product" else target
            pause = think_time(rng, think_mean_s)
            dev.page(t, path, pause, state)
        t += pause
    return dev.views


def search_views(level, duration_s, rng, first_visit_s=(0.0, 30.0), *, think_mean_s=THINK_MEAN_S):
    """A search user (L7 v2 §7.2, ml/l7v2_prereg.json benign_kinds.search_user): Home, the search page, then searches
    issued from it; after a search, a product page with probability p_detail and back to the search page."""
    p_detail = l7v2_prereg.load()["benign_kinds"]["search_user"]["p_detail"]
    form = l7v2_prereg.routes()["Search Request"][1]
    dev = _Device(level)
    t = rng.uniform(*first_visit_s)
    step = "home"
    while t < duration_s:
        pause = think_time(rng, think_mean_s)
        if step == "home":
            dev.page(t, "/", pause, "Home")
            step = "form"
        elif step == "form":
            dev.page(t, form, pause, "Search Request")
            step = "search"
        elif step == "search":
            dev.inpage(t, l7_webapp.search_path(rng), pause, "Search Results")
            step = "detail" if rng.random() < p_detail else "search"
        else:
            dev.page(t, f"/page/{zipf_page(rng)}", pause, "Product Detail")
            step = "form"
        t += pause
    return dev.views


def export_views(level, duration_s, rng, first_visit_s=None, *, think_mean_s=THINK_MEAN_S, visit_gap_s=None):
    """An exporter (L7 v2 §7.2, ml/l7v2_prereg.json benign_kinds.exporter): visits a uniform gap apart; a visit is a
    direct navigation to the account page, a think time, then one export issued from it."""
    spec = l7v2_prereg.load()["benign_kinds"]["exporter"]
    first_visit_s = tuple(spec["first_visit_s"] if first_visit_s is None else first_visit_s)
    visit_gap_s = tuple(spec["visit_gap_s"] if visit_gap_s is None else visit_gap_s)
    account = l7v2_prereg.routes()["Order Inquiry"][1]
    dev = _Device(level)
    t = rng.uniform(*first_visit_s)
    while t < duration_s:
        pause = think_time(rng, think_mean_s)
        dev.page(t, account, pause, "Order Inquiry", ref=None)
        t += pause
        if t >= duration_s:
            break
        pause = think_time(rng, think_mean_s) + rng.uniform(*visit_gap_s)
        dev.inpage(t, l7_webapp.export_path(rng), pause, "Order Display")
        t += pause
    return dev.views


def _nav_views(params, duration_s, rng, first_visit_s):
    """The views of one browser device by its "nav" param: the P5b i.i.d. Zipf model (absent or "zipf"), or a TPC-W
    mix ("tpcw:<mix>")."""
    nav = params.get("nav", "zipf")
    mv = model_values(params)
    if nav == "zipf":
        return browser_views(params["level"], duration_s, rng, first_visit_s, referer=bool(params.get("referer")), **mv)
    if nav.startswith("tpcw:") and nav[5:] in l7_tpcw.mixes():
        return tpcw_views(params["level"], duration_s, rng, nav[5:], first_visit_s,
                          think_mean_s=mv.get("think_mean_s", THINK_MEAN_S))
    raise ValueError(f"unknown nav {nav!r}")


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
        views = _nav_views(params, duration_s, rng, tuple(params.get("first_visit_s", (0.0, 30.0))))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
    if kind == "cgnat_browsers":
        users = []
        for _ in range(params["users"]):
            urng = type(rng)(rng.randrange(2**31))
            ua = draw_ua(urng)
            users.append({"ua": ua, "views": _nav_views(params, duration_s, urng,
                                                        tuple(params.get("first_visit_s", (0.0, 60.0))))})
        return {"kind": kind, "users": users}
    if kind in ("tpcw_browsing", "tpcw_shopping"):
        ua = draw_ua(rng)
        views = tpcw_views(params["level"], duration_s, rng, kind[5:], tuple(params.get("first_visit_s", (0.0, 30.0))),
                           think_mean_s=model_values(params).get("think_mean_s", THINK_MEAN_S))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
    if kind == "zipf_browser":                # the held-out i.i.d. Zipf model with Referer, under its own name
        ua = draw_ua(rng)
        views = browser_views(params["level"], duration_s, rng, tuple(params.get("first_visit_s", (0.0, 30.0))),
                              referer=True, **model_values(params))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
    if kind == "flash_crowd":
        ua = draw_ua(rng)
        spec = l7v2_prereg.load()["benign_kinds"]["flash_crowd"]
        mix = params.get("nav", "tpcw:" + l7v2_prereg.load()["navigation"]["train_mix"])[5:]
        views = tpcw_views(params["level"], duration_s, rng, mix, (0.0, spec["arrive_within_s"]),
                           think_mean_s=model_values(params).get("think_mean_s", THINK_MEAN_S))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
    if kind == "search_user":
        ua = draw_ua(rng)
        views = search_views(params["level"], duration_s, rng, tuple(params.get("first_visit_s", (0.0, 30.0))),
                             think_mean_s=model_values(params).get("think_mean_s", THINK_MEAN_S))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
    if kind == "exporter":
        ua = draw_ua(rng)
        views = export_views(params["level"], duration_s, rng, params.get("first_visit_s"),
                             think_mean_s=model_values(params).get("think_mean_s", THINK_MEAN_S),
                             visit_gap_s=params.get("visit_gap_s"))
        return {"kind": kind, "users": [{"ua": ua, "views": views}]}
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
L7V2_KINDS = ("tpcw_browsing", "tpcw_shopping", "zipf_browser", "search_user", "exporter", "flash_crowd")


# ── Uploads (the P5 `uploader`, and P4's two upload kinds on profile R: docs/P4_SLOW_DESIGN.md §4.2) ──
# An uploader posts one body to /upload, then thinks. P4's `uploader` takes bodies up to 2 MB; its `slow_uploader`
# is the same client behind a 16 kbit/s link: ml/l7_gen.py paces its body at `rate_Bps` bytes/s on the client side,
# standing for the link, and the runner shapes its namespace with netem at that rate. Nothing else tells them apart.
UPLOAD_DEFAULTS = {"think_s": (4.0, 10.0), "body_bytes": (200, 60000)}     # the P5 uploader (ml/l7_traffic.py)
SLOW_UPLOAD_RATE_BPS = 2000                                                # 16 kbit/s [ASSUMPTION, §4.2]
UPLOAD_KINDS = ("uploader", "slow_uploader")


def upload_plan(params, duration_s, rng):
    """[(body_bytes, think_s)]: one uploader's uploads over `duration_s` of nominal time (the sum of the think times),
    drawn as the P5 uploader always drew them: the body's size, then the pause after it. A generator that runs out of
    time executes a prefix of this list, so its draws are the P5 uploader's draw for draw."""
    lo, hi = params.get("think_s", UPLOAD_DEFAULTS["think_s"])
    blo, bhi = params.get("body_bytes", UPLOAD_DEFAULTS["body_bytes"])
    out, t = [], 0.0
    while t < duration_s:
        body = rng.randint(blo, bhi)
        think = rng.uniform(lo, hi)
        out.append((body, think))
        t += think
    return out
