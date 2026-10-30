"""Multi-path WSGI app for the L7 capture testbed (docs/L7_GRU_DESIGN.md §6, Phase P3).

The suite's inline `dummy_app` serves one path with one response size, so in the P2
feature review URI diversity and response size carried no signal
(`results/2026-10-15_l7-p2-smoke/`). This app gives the capture several routes with
deterministic, varied response sizes, a few status classes, an artificial upstream
delay on one route (so `$upstream_response_time` means something), a large download
and an upload endpoint — the behaviours an L7 model needs to see in benign traffic
and that some sub-threshold attacks exercise.

Pure stdlib WSGI (gunicorn serves `l7_webapp:app`); responses are deterministic given
the path, so a capture is reproducible. It is a benign origin server: it does not
authenticate anyone (every `/login` POST returns 401, which is what a credential-
stuffing *probe* sees) and holds no data.

Routes:
  GET  /                      home, small HTML
  GET  /page/<n>              one of a set of content pages, size varies with <n>
  GET  /api/<name>            small JSON
  GET  /static/<id>.<ext>     "asset" of a deterministic size (caching/scraping target)
  GET  /search?q=...          "expensive": ~UPSTREAM_DELAY_MS before a small result
  GET  /download/large        a large body (DOWNLOAD_BYTES), for big-response benign flows
  POST /upload                accepts a body up to the size nginx allows; echoes the count
  POST /login                 always 401 (no accounts exist)
  GET  /export[?r=<n>]        a small CSV (L7 v2: the C5 export route, docs/L7V2_DESIGN.md 4.1)
  GET  /robots.txt            allow-all robots file (the P5b polite crawler reads it)
  *                           404

L7 v2 (docs/L7V2_DESIGN.md section 4): route_class() is the site map, the route class (C0 assets, C1 pages,
C2 API, C3 search, C5 export; None = uncosted) of every route. With the environment variable L7_BACKEND=costed,
app() serves the same URL space through l7_backend.CostedApp: each costed route calls the harm benchmark origin's
work for its class, answers carry the calibration record's label, and an HTML answer sets the session cookie `sid`.
Without it (the default), app() is legacy_app(), the 2026-10 app, unchanged, so published captures stay reproducible.

The site's page resources (P5b, docs/L7_GRU_DESIGN.md §7.2) are defined here too:
site_assets() / page_assets() list the same-origin assets a browser loads for a page, so
the browser-like generators and the admissibility gate use one definition. route_status()
is the status app() returns for a request, as a pure function (the gate predicts error
ratios with it; a test checks it against app()).
"""
import json
import os
import zlib

DOWNLOAD_BYTES = 1_500_000      # ~1.5 MB, above nginx's 64 KiB body cap but a response
UPSTREAM_DELAY_MS = 40          # artificial work on /search, so upstream_response_time > 0
_PAGE_BASE = 800                # bytes; /page/<n> size grows with n
_PAGES = 12


def _stable_hash(s):
    """A process-independent hash. Python's builtin hash() is salted per process
    (PYTHONHASHSEED), so it would give different response sizes across gunicorn
    workers and runs; a capture must reproduce, so use crc32."""
    return zlib.crc32(s.encode("utf-8"))


def _size_for(path):
    """A deterministic response size for a path, so captures reproduce."""
    return _PAGE_BASE + (_stable_hash(path) & 0xFFFF)


def site_assets(level):
    """The site-wide assets of a site whose cold first view loads `level` same-origin
    assets: (wave1, wave2_common). Wave 1 is CSS/JS (half of `level`), discovered from
    the HTML; wave 2's common part is fonts (a sixth), discovered from the CSS. The rest
    (a third) are per-page images, page_assets(). Every path is served by /static/."""
    n_cj, n_font = level // 2, level // 6
    wave1 = [f"/static/site{level}/{'app' if i % 2 else 'style'}{i}.{'js' if i % 2 else 'css'}"
             for i in range(n_cj)]
    fonts = [f"/static/site{level}/font{i}.woff2" for i in range(n_font)]
    return wave1, fonts


def page_assets(level, page):
    """The images of one page (wave 2), so a cold view loads exactly `level` assets."""
    n_img = level - level // 2 - level // 6
    return [f"/static/site{level}/p{page}/img{i}.png" for i in range(n_img)]


def static_size(path):
    """The body size of the asset at `path` (both backends serve it)."""
    return _size_for(path)


def route_class(method, path):
    """The site map (docs/L7V2_DESIGN.md 4.1, 8.2): the origin work class of a GET or HEAD request for `path` (a query
    string is ignored), or None for an uncosted route. The route classes are the costed backend's and the navigation
    features' only source of route semantics."""
    path = path.split("?", 1)[0]
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


def route_status(method, path):
    """The HTTP status legacy_app() returns for (method, path), without running the handler (a query string is
    ignored). The costed backend answers the same, except a 400 for a search term or export query the origin refuses,
    which no generator sends."""
    path = path.split("?", 1)[0]
    if path in ("/", "/robots.txt", "/export") or path.startswith(("/page/", "/api/", "/static/",
                                                                    "/search")):
        return 200
    if path == "/download/large":
        return 200
    if path == "/upload" and method == "POST":
        return 200
    if path == "/login" and method == "POST":
        return 401
    return 404


def _resp(start_response, status, body, ctype="text/html; charset=utf-8", extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    headers = [("Content-Type", ctype), ("Content-Length", str(len(body)))]
    if extra:
        headers.extend(extra)
    start_response(status, headers)
    return [body]


_BACKEND = []


def _backend():
    """The costed backend when L7_BACKEND=costed (built once per process), else None."""
    if not _BACKEND:
        mode = os.environ.get("L7_BACKEND", "legacy")
        if mode not in ("legacy", "costed"):
            raise ValueError(f"L7_BACKEND={mode!r}: legacy or costed")
        if mode == "costed":
            import l7_backend
            _BACKEND.append(l7_backend.CostedApp.from_env())
        else:
            _BACKEND.append(None)
    return _BACKEND[0]


def app(environ, start_response):
    """The WSGI entry gunicorn serves: the costed backend when L7_BACKEND=costed, else legacy_app."""
    backend = _backend()
    if backend is None:
        return legacy_app(environ, start_response)
    return backend(environ, start_response)


def legacy_app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")

    if path == "/":
        return _resp(start_response, "200 OK",
                     "<html><body><h1>Testbed origin</h1>"
                     "<p>L7 capture app.</p></body></html>")

    if path == "/robots.txt":
        return _resp(start_response, "200 OK", "User-agent: *\nAllow: /\n",
                     ctype="text/plain; charset=utf-8")

    if path.startswith("/page/"):
        n = path[len("/page/"):]
        size = _PAGE_BASE * (1 + (_stable_hash(n) % _PAGES))
        return _resp(start_response, "200 OK", "x" * size)

    if path.startswith("/api/"):
        body = json.dumps({"path": path, "ok": True, "items": list(range(5))})
        return _resp(start_response, "200 OK", body, ctype="application/json")

    if path.startswith("/static/"):
        return _resp(start_response, "200 OK", "s" * _size_for(path),
                     ctype="application/octet-stream",
                     extra=[("Cache-Control", "public, max-age=3600")])

    if path.startswith("/search"):
        import time
        time.sleep(UPSTREAM_DELAY_MS / 1000.0)      # stand in for a real expensive query
        return _resp(start_response, "200 OK",
                     json.dumps({"results": [], "q": environ.get("QUERY_STRING", "")}),
                     ctype="application/json")

    if path == "/export":
        body = "id,score\n" + "".join(f"{i},{_stable_hash(f'export|{i}') % 1000}\n" for i in range(1, 21))
        return _resp(start_response, "200 OK", body, ctype="text/csv; charset=utf-8")

    if path == "/download/large":
        return _resp(start_response, "200 OK", b"L" * DOWNLOAD_BYTES,
                     ctype="application/octet-stream")

    if path == "/upload" and method == "POST":
        try:
            n = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            n = 0
        read = environ["wsgi.input"].read(n) if n else b""
        return _resp(start_response, "200 OK",
                     json.dumps({"received": len(read)}), ctype="application/json")

    if path == "/login" and method == "POST":
        try:
            environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
        except (ValueError, OSError):
            pass
        return _resp(start_response, "401 Unauthorized",
                     json.dumps({"error": "invalid credentials"}),
                     ctype="application/json")

    return _resp(start_response, "404 Not Found",
                 json.dumps({"error": "not found", "path": path}),
                 ctype="application/json")


if os.environ.get("L7_BACKEND") == "costed":     # build the backend at worker boot, not on the first request
    _backend()
