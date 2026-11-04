"""Gunicorn settings of profile R (docs/P4_SLOW_DESIGN.md §4.1, D-S2).

Five sync workers (2 x 2 CPUs + 1, the server's CPU set being CPUs 0-1) bound to 127.0.0.1:8080:
nginx's upstream and nothing else (the loopback bind, H-03). A sync worker serves one request at
a time, so a slow body that nginx streams to the backend (proxy_request_buffering off on /upload,
nginx_profile_r.conf) holds one of the five for as long as it lasts. Every other value is
gunicorn's own default [CLAIMED, gunicorn documentation], written out for the run's provenance:
in particular a worker silent for `timeout` seconds is killed and replaced, which bounds how long
one slow body can hold one worker.

The frozen record's self-check runs once per server start, here in the master (on_starting), before gunicorn listens: a refusal stops
it before it serves. A worker builds the app at boot (l7_webapp at import), and in each worker the check would cost about 1.4 CPU-seconds
per replacement on the server's CPUs, and a replacement that failed it in mid-run would stop the whole server (a worker that exits
3 before it has booted: gunicorn's Arbiter raises HaltServer). The marker tells the workers the master has done it (D-063).

The backend is the costed L7 app (l7_backend.py, docs/L7V2_DESIGN.md §4) with the upload route of
profile R: `raw_env` sets L7_BACKEND=costed and L7_UPLOAD=streamed in the server's environment
before the workers load `wsgi_app`, so POST /upload reads its body as it arrives and a slow body
holds a worker (P4 part 2b). The calibration record is the runner's (L7_CALIBRATION, the
placeholder by default), and so is the CPU set.

Re-registration record (D-063, 2026-11-04T13:04Z, the orchestrator's decision, before any data; the user may overrule), committed
before the code it judges: the frozen record's self-check runs once per server start, in the master, not in each worker.

Usage: gunicorn -c gunicorn_profile_r.py           (the runner sets L7_CALIBRATION and the CPU set)
"""
bind = "127.0.0.1:8080"
workers = 5
worker_class = "sync"
threads = 1
timeout = 30
graceful_timeout = 30
keepalive = 2
backlog = 2048
wsgi_app = "l7_webapp:app"
raw_env = ["L7_BACKEND=costed", "L7_UPLOAD=streamed"]


def on_starting(server):
    """Gunicorn's hook, before the master makes its sockets or its workers (raw_env is set by then). A refusal ends the process with
    the line eval/p4_runner.py reads in gunicorn.log."""
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import l7_backend
    try:
        l7_backend.check_at_server_start()
    except l7_backend.O.CalibrationError as exc:
        raise SystemExit(f"CalibrationError: {exc}") from None
