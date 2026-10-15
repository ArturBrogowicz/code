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
  *                           404
"""
import json
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


def _resp(start_response, status, body, ctype="text/html; charset=utf-8", extra=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    headers = [("Content-Type", ctype), ("Content-Length", str(len(body)))]
    if extra:
        headers.extend(extra)
    start_response(status, headers)
    return [body]


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")

    if path == "/":
        return _resp(start_response, "200 OK",
                     "<html><body><h1>Testbed origin</h1>"
                     "<p>L7 capture app.</p></body></html>")

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
