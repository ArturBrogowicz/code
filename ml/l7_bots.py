"""The L7 v2 attack classes C2, C3a and C3b as request plans for this testbed's generator (docs/L7V2_DESIGN.md §7.1,
§12 items 2 and 4; frozen in ml/l7v2_prereg.json).

Content level (ledger D-006): evaluation parameters for the in-repo generator only. Each class is a seeded plan of
paths, gaps and Referers against the testbed origin; ml/l7_gen.py executes it inside the testbed's namespaces with
its existing machinery (closed-loop paced requests, or the browser-device executor for C3b), under its scope lock.

  C2   request-cost abuse: Poisson requests to one costly route (C3 /search; C5 /export as the variant), no assets,
       one browser UA, cookies kept; the Referer names the route's form page, which the bot never loads
  C3a  browser-claiming HTTP-library bots: a product page every U[2, 8] s, each followed at once by one costly
       request; no assets, no JS; cookies kept; Referer = the previous page (the costly request: its page)
  C3b  headless-browser bots, a request-level emulation: views that load like a browser's (asset waves, a cache,
       six keep-alive connections), one costly request per view after its assets, Referer and cookies like the
       benign browser; the navigation is the mimicry level's:
         M1     product pages uniform without replacement (deep links), a constant 3 s dwell (a sanity level)
         M2     as M1 with a uniform U[2, 12] s dwell (primary)
         M3     the TPC-W browsing chain watched on its page states, product pages uniform without replacement (no
                back-navigation), U[2, 12] s dwell (held out, evaluation only)
         M2exp  as M2 with the benign think law, exponential mean 7 s capped at 70 s (held out, evaluation only)

The circularity guard (§12 item 2): this module is specified apart from the benign planner and imports nothing from
it. It uses the site map and the asset waves (l7_webapp), the published TPC-W chain (l7_tpcw) and the frozen values
(l7v2_prereg); the UA a bot claims is drawn by the population (ml/l7_pools.py) and arrives in its params.
"""
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import l7_tpcw
import l7v2_prereg

import l7_webapp

FAMILIES = ("C2", "C3a", "C3b@M1", "C3b@M2", "C3b@M3", "C3b@M2exp")
PRODUCT_PAGES = 200                     # the product pages of the site (ml/l7v2_prereg.json product_popularity)
FORM_PAGE = {"C3": "/page/search", "C5": "/page/account"}


class BotPlanError(ValueError):
    """A bot's parameters do not describe a plan of its class."""


def mimicry_of(family):
    """"C3b@M2" -> "M2"; None for C2 and C3a."""
    return family.split("@", 1)[1] if family.startswith("C3b@") else None


def costly_path(route, rng):
    """One costly request: a search (C3) or an export (C5), drawn as the benign users draw theirs."""
    if route == "C3":
        return l7_webapp.search_path(rng)
    if route == "C5":
        return l7_webapp.export_path(rng)
    raise BotPlanError(f"costly route {route!r}: C3 or C5")


class _Products:
    """Product pages without replacement; a new uniform permutation once all were visited."""

    def __init__(self, rng):
        self.rng, self.left = rng, []

    def next(self):
        if not self.left:
            self.left = list(range(1, PRODUCT_PAGES + 1))
            self.rng.shuffle(self.left)
        return f"/page/{self.left.pop()}"


def c2_requests(params, duration_s, rng):
    """C2: [(path, gap_s, referer)], Poisson at params['rps'] to params['route']."""
    rps, route = float(params["rps"]), params.get("route", "C3")
    if not rps > 0:
        raise BotPlanError(f"C2 rps {rps!r}")
    out, t = [], 0.0
    while t < duration_s:
        gap = rng.expovariate(rps)
        out.append((costly_path(route, rng), round(gap, 5), FORM_PAGE[route]))
        t += gap
    return out


def c3a_requests(params, duration_s, rng):
    """C3a: a uniform product page, then at once one costly request, then a page gap U[lo, hi]."""
    lo, hi = params.get("page_gap_s", l7v2_prereg.load()["classes"]["C3a"]["page_gap_s"])
    route = params.get("route", "C3")
    out, t, prev = [], 0.0, None
    while t < duration_s:
        page = f"/page/{rng.randint(1, PRODUCT_PAGES)}"
        gap = rng.uniform(lo, hi)
        out.append((page, 0.0, prev))
        out.append((costly_path(route, rng), round(gap, 5), page))
        prev, t = page, t + gap
    return out


def c3b_views(params, duration_s, rng, mimicry):
    """C3b at `mimicry`: browser views [{"t", "page", "waves", "pause_s", "ref", "doc"}], each with one costly request
    as its last wave."""
    level, route = params["level"], params.get("route", "C3")
    first = params.get("first_view_s", l7v2_prereg.load()["classes"]["C3b"]["first_view_s"])
    wave1_all, fonts = l7_webapp.site_assets(level)
    products, cached, views, doc = _Products(rng), set(), [], None
    walk = None
    if mimicry == "M3":
        walk = l7_tpcw.walk(l7v2_prereg.load()["navigation"]["train_mix"], rng, l7v2_prereg.page_states())
        routes = l7v2_prereg.routes()
    t = rng.uniform(*first)
    while t < duration_s:
        if walk is not None:
            kind, target = routes[next(walk)]
            path = products.next() if kind == "product" else target
        else:
            path = products.next()
        key = "home" if path == "/" else path[len("/page/"):]
        key = int(key) if isinstance(key, str) and key.isdigit() else key
        wave1 = [p for p in wave1_all if p not in cached]
        wave2 = [p for p in fonts + l7_webapp.page_assets(level, key) if p not in cached]
        cached.update(wave1)
        cached.update(wave2)
        dwell = l7v2_prereg.dwell(mimicry, rng)
        views.append({"t": round(t, 4), "page": key, "waves": [[path], wave1, wave2, [costly_path(route, rng)]],
                      "pause_s": round(dwell, 4), "ref": doc, "doc": path})
        doc, t = path, t + dwell
    return views


def plan_bot(family, params, duration_s, rng):
    """The plan of one bot: {"family", "users": [{"ua", "requests": [(path, gap, ref)]} | {"ua", "views": [...]}]}.
    `params` carries the UA the population drew ("ua")."""
    if family not in FAMILIES:
        raise BotPlanError(f"not an L7 v2 class: {family!r} (have {FAMILIES})")
    ua = params.get("ua")
    if not ua:
        raise BotPlanError(f"{family}: params carry no ua (the population draws it)")
    if family == "C2":
        return {"family": family, "users": [{"ua": ua, "requests": c2_requests(params, duration_s, rng)}]}
    if family == "C3a":
        return {"family": family, "users": [{"ua": ua, "requests": c3a_requests(params, duration_s, rng)}]}
    mimicry = mimicry_of(family)
    if params.get("mimicry", mimicry) != mimicry:
        raise BotPlanError(f"{family}: params say mimicry {params['mimicry']!r}")
    return {"family": family, "users": [{"ua": ua, "views": c3b_views(params, duration_s, rng, mimicry)}]}


def demo(family, params, duration_s=60.0, seed=0):
    """A plan for review (--plan style), seeded."""
    return plan_bot(family, params, duration_s, random.Random(seed))
