"""Gunicorn settings of profile R (docs/P4_SLOW_DESIGN.md §4.1, D-S2).

Five sync workers (2 x 2 CPUs + 1, the server's CPU set being CPUs 0-1) bound to 127.0.0.1:8080:
nginx's upstream and nothing else (the loopback bind, H-03). A sync worker serves one request at
a time, so a slow body that nginx streams to the backend (proxy_request_buffering off on /upload,
nginx_profile_r.conf) holds one of the five for as long as it lasts. Every other value is
gunicorn's own default [CLAIMED, gunicorn documentation], written out for the run's provenance:
in particular a worker silent for `timeout` seconds is killed and replaced, which bounds how long
one slow body can hold one worker.

Usage: gunicorn -c gunicorn_profile_r.py <app>    (the runner names the app and the CPU set)
"""
bind = "127.0.0.1:8080"
workers = 5
worker_class = "sync"
threads = 1
timeout = 30
graceful_timeout = 30
keepalive = 2
backlog = 2048
