#!/usr/bin/env python3
"""Verification of the HTTP load generators: tests V0-V7 of docs/BENCHMARK_HARM_DESIGN.md, 8.4.

A generator may carry a benchmark number only if it was shown, against an origin whose behaviour
is known, to send what it says it sends and to report what it measured. Each tool is run through
bench/loadtools.py on loopback (127.0.0.1, nothing else) against one of two origins:

  S1  a user-level Nginx that returns a fixed body; its stub_status counter is the ground truth
      for how many requests arrived (rate and ceiling tests);
  S2  a scripted Python server (serve-s2) with a known service time, an optional stall that holds
      every response, an optional error status for every n-th request and an optional capacity;
      its own log of arrivals and responses is the ground truth (latency, stall, overload and
      status tests).

  V0  the binary matches the manifest and prints the pinned version
  V1  smoke: 100 requests/s for 10 s, no errors, sent and counted within 2 % of intended
  V2  rate accuracy: 200, 1000 and 5000 requests/s for 20 s, 3 repeats, origin count within 1 %
  V3  latency accuracy: p50 and p99 against the origin's own service times
  V4  coordinated omission: S2 holds every response for 3 s; an open-loop tool must report the
      analytic p99 (2.6 s at 500 requests/s for 40 s), the closed-loop wrk control must not
  V5  overload honesty: twice the origin's capacity; arrivals follow the intended rate or the
      tool reports what it dropped
  V6  status accounting: S2 answers every 10th request with 503; the tool's count must agree
  V7  ceiling and cost: 1k to 20k requests/s on one pinned core; the highest rate held, and the
      CPU time per 1000 requests

The pass criteria are CRITERIA below, written before any measurement. A tool that fails V0-V2 is
unfit; one that fails only V3-V6 is verified with restrictions (no latency or overload claims).
Nothing is tuned until it passes. CPUs: S1 on 0-1, S2 on 2-3, the tools on 4-7 (V7: on 4).

Each test gives a tool the settings it needs (limits_for: workers or VUs for a 0.3 s late wake-up,
or for the whole stall; 5000 in flight at most; an idle pool as large as the workers). A job starts
only when fewer than 5000 sockets are in TIME_WAIT (it waits up to 90 s and records what it found),
the CPU time of a job is that of the load step, and `run` waits for the environment gate of the
design (up 30 minutes, 1-minute load below 0.3) or refuses.

    ./venv/bin/python bench/loadtool_validate.py plan [--tools vegeta,k6,wrk] [--tests V1,V4]
    ./venv/bin/python bench/loadtool_validate.py run --out DIR --yes [--tools ...] [--tests ...]
    ./venv/bin/python bench/loadtool_validate.py reanalyse DIR

`run` starts Nginx and S2 on loopback and generates load for about a quarter of an hour; it needs
the owner's approval and --yes. plan and reanalyse start nothing. serve-s2 is the origin process
that `run` starts. The results directory is laid out like a published campaign (README.md,
results.json, one directory per job, SHA256SUMS).
"""
import argparse
import asyncio
import collections
import contextlib
import dataclasses
import datetime
import gzip
import hashlib
import json
import math
import os
import platform
import random
import shutil
import signal
import socket
import subprocess
import sys
import time

try:
    import loadtools as LT
except ImportError:                       # imported from the repository root
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import loadtools as LT

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = "127.0.0.1"
S1_PORT, S2_PORT = 18081, 18083
CPUS = {"s1": "0-1", "s2": "2-3", "tools": "4-7", "one_core": "4"}

# The pass criteria, fixed before any measurement (docs/BENCHMARK_HARM_DESIGN.md, 8.4).
CRITERIA = {
    "v1_rate": 0.02,            # tool and origin counts within 2 % of rate x duration
    "v2_rate": 0.01,            # origin count within 1 %
    "v3_abs_s": 0.001,          # p50 and p99 within the larger of 1 ms ...
    "v3_rel": 0.10,             # ... and 10 % of the origin's own
    "v4_rel": 0.15,             # reported p99 within 15 % of the analytic value
    "v4_control": 0.10,         # the closed-loop control must report below 10 % of it
    "v4_stall_arrivals": 0.10,  # arrivals in the stall within 10 % of rate x stall
    "v5_rate": 0.02,            # arrivals (plus reported drops) within 2 % of intended
    "v6_rel": 0.01,             # non-2xx within 1 % (or 2) of the 503s sent
    "v6_abs": 2,
    "v7_rate": 0.01,            # origin count within 1 % at a step that counts as held
}
REASON = {200: b"OK", 503: b"Service Unavailable"}
S2_BASE = {"service_ms": 5.0, "jitter_ms": 5.0}
TESTS = {
    "V1": {"origin": "s1", "rates": (100,), "duration": 10, "repeats": 1,
           "tools": ("vegeta", "k6", "loadgen")},
    "V2": {"origin": "s1", "rates": (200, 1000, 5000), "duration": 20, "repeats": 3,
           "tools": ("vegeta", "k6", "loadgen")},
    "V3": {"origin": "s2", "rates": (500,), "duration": 30, "repeats": 1,
           "tools": ("vegeta", "k6", "loadgen"), "s2": S2_BASE},
    "V4": {"origin": "s2", "rates": (500,), "duration": 40, "repeats": 1,
           "tools": ("vegeta", "k6", "loadgen", "wrk"), "control": ("wrk",),
           "s2": {**S2_BASE, "stall_after": 15.0, "stall_for": 3.0}},
    "V5": {"origin": "s2", "rates": (2000,), "duration": 20, "repeats": 1,
           "tools": ("vegeta", "k6", "loadgen"),
           "s2": {"service_ms": 50.0, "jitter_ms": 0.0, "capacity": 50}},
    "V6": {"origin": "s2", "rates": (500,), "duration": 20, "repeats": 1,
           "tools": ("vegeta", "k6", "loadgen"), "s2": {**S2_BASE, "error_every": 10}},
    "V7": {"origin": "s1", "rates": (1000, 2000, 5000, 10000, 20000), "duration": 10,
           "repeats": 1, "tools": ("vegeta", "k6", "loadgen"), "cpus": CPUS["one_core"]},
}


class InfraError(RuntimeError):
    """The origin or the environment is wrong; the run stops (a tool failing is a result)."""


@dataclasses.dataclass(frozen=True)
class Job:
    test: str
    tool: str
    rate: float
    duration: float
    repeat: int
    origin: str                       # "s1" or "s2"
    s2: tuple = ()                    # S2 settings as sorted (key, value) pairs
    cpus: str = CPUS["tools"]
    role: str = "subject"             # "control" for the closed-loop wrk in V4
    limits: tuple = ()                # workers, max_workers, connections as sorted pairs

    @property
    def key(self):
        return f"{self.test}/{self.tool}/r{self.rate:g}_{self.repeat}"

    def as_dict(self):
        d = dataclasses.asdict(self)
        d["s2"] = dict(self.s2)
        d["limits"] = dict(self.limits)
        d["key"] = self.key
        return d


def limits_for(tool, rate, s2=None):
    """The settings a test needs, by one rule for every test (docs/BENCHMARK_HARM_DESIGN.md, 8.4):
    workers (initial workers of vegeta, pre-allocated VUs of k6) enough for a late wake-up of
    0.3 s, rate x 0.3, or for the whole stall and 0.2 s more when the origin stalls, at least 100
    and at most 2000; 5000 in flight at most for every tool (what a tool does at its cap is what V5
    looks at); an idle connection pool as large as the workers, so that a burst is not connection
    churn. The closed-loop wrk control keeps 50 connections."""
    if tool == "wrk":
        return {"workers": 100, "max_workers": 5000, "connections": 50}
    need = rate * 0.3
    if s2 and s2.get("stall_for"):
        need = max(need, rate * (s2["stall_for"] + 0.2))
    workers = max(100, min(2000, math.ceil(need)))
    return {"workers": workers, "max_workers": 5000, "connections": workers}


def spec_for(job, url):
    """The LoadSpec of a job; `run` and `plan` both build it here."""
    lim = dict(job.limits)
    return LT.LoadSpec(url=url, rate=job.rate, duration=job.duration, cpus=job.cpus,
                       connections=lim["connections"], workers=lim["workers"],
                       max_workers=lim["max_workers"], threads=2, allow_loopback=True,
                       name=job.test)


def expand(tools=None, tests=None):
    """The jobs of the matrix, test by test and tool by tool, so that the tools of one test
    run next to each other."""
    jobs = []
    for tid, t in TESTS.items():
        if tests and tid not in tests:
            continue
        for tool in t["tools"]:
            if tools and tool not in tools:
                continue
            for rate in t["rates"]:
                for rep in range(t["repeats"]):
                    jobs.append(Job(tid, tool, rate, t["duration"], rep, t["origin"],
                                    tuple(sorted(t.get("s2", {}).items())),
                                    t.get("cpus", CPUS["tools"]),
                                    "control" if tool in t.get("control", ()) else "subject",
                                    tuple(sorted(limits_for(tool, rate, t.get("s2")).items()))))
    return jobs


# --- S2: the scripted origin ---------------------------------------------------------------

class ScriptedOrigin:
    """HTTP/1.1 origin whose behaviour is a function of the request number and of the time
    since the first request: a service time, a stall that holds every response written inside
    it, an error status for every error_every-th request, a capacity (concurrent slots)."""

    def __init__(self, service_ms=5.0, jitter_ms=5.0, stall_after=None, stall_for=0.0,
                 error_every=0, capacity=0, seed=1, clock=time.monotonic):
        self.params = {"service_ms": service_ms, "jitter_ms": jitter_ms,
                       "stall_after": stall_after, "stall_for": stall_for,
                       "error_every": error_every, "capacity": capacity, "seed": seed}
        self.clock = clock
        rng = random.Random(seed)
        self._u = [rng.random() for _ in range(65536)]
        self._slots = asyncio.Semaphore(capacity) if capacity else None
        self.t0 = None
        self.n = 0
        self.arrivals = []            # [seq, seconds since the first request]
        self.responses = []           # [seq, seconds since the first request, status]
        self.port = None

    def _stall_end(self, offset):
        a = self.params["stall_after"]
        if a is not None and a <= offset < a + self.params["stall_for"]:
            return a + self.params["stall_for"]
        return None

    async def handle(self, reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                now = self.clock()
                if self.t0 is None:
                    self.t0 = now
                seq = self.n
                self.n += 1
                self.arrivals.append([seq, round(now - self.t0, 6)])
                words = head.split(b"\r\n", 1)[0].split()
                method = words[0] if words else b""
                close = b"connection: close" in head.lower() or words[-1:] == [b"HTTP/1.0"]
                every = self.params["error_every"]
                status = 503 if every and seq % every == every - 1 else 200
                service = (self.params["service_ms"]
                           + self.params["jitter_ms"] * self._u[seq & 0xFFFF]) / 1000
                if self._slots is not None:
                    async with self._slots:
                        await asyncio.sleep(service)
                else:
                    await asyncio.sleep(service)
                end = self._stall_end(self.clock() - self.t0)
                if end is not None:
                    await asyncio.sleep(max(0.0, end - (self.clock() - self.t0)))
                body = b"" if method == b"HEAD" else (b"ok\n" if status == 200 else b"no\n")
                writer.write(b"HTTP/1.1 %d %s\r\nContent-Length: 3\r\n%s\r\n" % (
                    status, REASON[status], b"Connection: close\r\n" if close else b"") + body)
                await writer.drain()
                self.responses.append([seq, round(self.clock() - self.t0, 6), status])
                if close:
                    break
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()

    async def start(self, host=HOST, port=0):
        server = await asyncio.start_server(self.handle, host, port, backlog=4096,
                                            reuse_address=True)
        self.port = server.sockets[0].getsockname()[1]
        return server

    def dump(self, path):
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "wt") as f:
            json.dump({"schema": 1, "params": self.params, "arrivals": self.arrivals,
                       "responses": self.responses}, f, separators=(",", ":"))


def _quantiles(sorted_values):
    return {"p50": LT.quantile(sorted_values, .5), "p90": LT.quantile(sorted_values, .9),
            "p95": LT.quantile(sorted_values, .95), "p99": LT.quantile(sorted_values, .99),
            "max": sorted_values[-1] if sorted_values else None}


def summarise_s2(log):
    """What the evaluators need from an S2 log."""
    p = log["params"]
    at = {seq: t for seq, t in log["arrivals"]}
    service = sorted(t - at[seq] for seq, t, _ in log["responses"] if seq in at)
    times = list(at.values())
    stall = ((p["stall_after"], p["stall_after"] + p["stall_for"])
             if p.get("stall_after") is not None else None)
    per_s = collections.Counter(int(t) for t in times)
    return {"kind": "s2", "arrivals": len(times), "responses": len(log["responses"]),
            "status": dict(collections.Counter(str(s) for _, _, s in log["responses"])),
            "service_s": _quantiles(service),
            "first_arrival_s": min(times, default=None), "last_arrival_s": max(times, default=None),
            "arrivals_per_s": [per_s.get(i, 0) for i in range(int(max(times, default=-1)) + 1)],
            "arrivals_in_stall": (sum(1 for t in times if stall[0] <= t < stall[1])
                                  if stall else None),
            "params": p}


# --- origins as processes ------------------------------------------------------------------

def wait_port(port, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with socket.socket() as s:
            s.settimeout(0.2)
            if s.connect_ex((HOST, port)) == 0:
                return True
        time.sleep(0.05)
    return False


def port_in_use(port):
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex((HOST, port)) == 0


def _stop(proc, timeout=10):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class Nginx:
    """S1: Nginx on loopback returning a fixed body; stub_status counts what arrived."""

    def __init__(self, workdir, port=S1_PORT, cpus=CPUS["s1"]):
        self.dir = os.path.join(workdir, "s1")
        self.port, self.cpus = port, cpus
        self.url = f"http://{HOST}:{port}/"
        self.proc = None
        self.before = None

    def config(self):
        d = self.dir
        return f"""\
daemon off;
worker_processes 2;
pid {d}/nginx.pid;
error_log {d}/error.log;
events {{ worker_connections 8192; }}
http {{
  access_log off;
  keepalive_requests 1000000;
  client_body_temp_path {d}/t1; proxy_temp_path {d}/t2; fastcgi_temp_path {d}/t3;
  uwsgi_temp_path {d}/t4; scgi_temp_path {d}/t5;
  server {{
    listen {HOST}:{self.port} backlog=4096;
    location = /status {{ stub_status; }}
    location / {{ return 200 "ok\\n"; }}
  }}
}}
"""

    def command(self):
        return ["taskset", "-c", self.cpus, "nginx", "-p", self.dir, "-c",
                os.path.join(self.dir, "nginx.conf"), "-e", os.path.join(self.dir, "error.log")]

    def counter(self):
        import http.client
        conn = http.client.HTTPConnection(HOST, self.port, timeout=5)
        try:
            conn.request("GET", "/status")
            return int(conn.getresponse().read().decode().splitlines()[2].split()[2])
        finally:
            conn.close()

    def __enter__(self):
        if port_in_use(self.port):
            raise InfraError(f"port {self.port} is already in use")
        os.makedirs(self.dir, exist_ok=True)
        conf = os.path.join(self.dir, "nginx.conf")
        with open(conf, "w") as f:
            f.write(self.config())
        self.proc = subprocess.Popen(self.command(), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        if not wait_port(self.port):
            _stop(self.proc)
            raise InfraError("nginx did not start (see s1/error.log)")
        self.before = self.counter()
        return self

    def finish(self):
        time.sleep(0.5)                                   # let the last responses leave
        after = self.counter()
        return {"kind": "s1", "requests": after - self.before - 1,    # minus the poll itself
                "counter_before": self.before, "counter_after": after}

    def __exit__(self, *exc):
        _stop(self.proc)


class S2Process:
    """S2 as its own process, so that it can be pinned and its log is written at SIGTERM."""

    def __init__(self, workdir, params, port=S2_PORT, cpus=CPUS["s2"]):
        self.dir, self.params, self.port, self.cpus = workdir, params, port, cpus
        self.url = f"http://{HOST}:{port}/"
        self.log = os.path.join(workdir, "s2.log.json.gz")
        self.proc = None

    def command(self):
        return ["taskset", "-c", self.cpus, sys.executable, os.path.abspath(__file__),
                "serve-s2", "--port", str(self.port), "--log", self.log, "--params",
                json.dumps(self.params, sort_keys=True)]

    def __enter__(self):
        if port_in_use(self.port):
            raise InfraError(f"port {self.port} is already in use")
        self.proc = subprocess.Popen(self.command(), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE)
        if not wait_port(self.port):
            _stop(self.proc)
            raise InfraError("S2 did not start")
        return self

    def finish(self):
        time.sleep(0.5)
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(30)
        except subprocess.TimeoutExpired:
            _stop(self.proc)
            raise InfraError("S2 did not exit after SIGTERM") from None
        if not os.path.exists(self.log):
            raise InfraError("S2 wrote no log: " + self.proc.stderr.read().decode()[-500:])
        with gzip.open(self.log, "rt") as f:
            return summarise_s2(json.load(f))

    def __exit__(self, *exc):
        _stop(self.proc)
        if self.proc.stderr:
            self.proc.stderr.close()


# --- the evaluators (pure) -----------------------------------------------------------------

def analytic_stall_p99(rate, duration, stall_for, q=0.99, service=0.0):
    """The quantile an open-loop tool should report when the origin holds every response for
    `stall_for` seconds of a `duration` run at `rate`. The requests that arrive in the stall
    (a fraction f = stall_for / duration, uniformly) wait for the rest of it, so their latency
    is uniform on (0, stall_for); the q-quantile of all requests lies in that tail unless f is
    below 1 - q. 500 requests/s for 40 s with a 3 s stall: f = 0.075, p99 = 3 x (1 - 1/7.5) = 2.6 s."""
    f = stall_for / duration
    if f <= 1 - q:
        return service
    return stall_for * (1 - (1 - q) / f) + service


def _rel(observed, expected):
    return abs(observed - expected) / expected if expected else float("inf")


def _check(name, observed, expected, ok, tolerance=None):
    return {"name": name, "observed": observed, "expected": expected, "tolerance": tolerance,
            "pass": bool(ok)}


def _v1(job, res, origin):
    n, tol = job["rate"] * job["duration"], CRITERIA["v1_rate"]
    return [_check("the tool reports no errors", res["errors"], 0, res["errors"] == 0),
            _check("requests the tool sent", res["requests"], n,
                   _rel(res["requests"], n) <= tol, tol),
            _check("requests the origin counted", origin["requests"], n,
                   _rel(origin["requests"], n) <= tol, tol)], []


def _v2(job, res, origin):
    n, tol = job["rate"] * job["duration"], CRITERIA["v2_rate"]
    return [_check("requests the origin counted", origin["requests"], n,
                   _rel(origin["requests"], n) <= tol, tol)], [
        f"the tool counted {res['requests']} and reported {res['errors']} errors"]


def _v3(job, res, origin):
    checks = []
    for q in ("p50", "p99"):
        got, truth = res["latency"].get(q), origin["service_s"][q]
        tol = max(CRITERIA["v3_abs_s"], CRITERIA["v3_rel"] * truth)
        checks.append(_check(f"reported {q} against the origin's own", got, truth,
                             got is not None and abs(got - truth) <= tol, tol))
    return checks, [f"percentiles from: {res['quantiles']}"]


def _v4(job, res, origin):
    s2 = job["s2"]
    service = (s2["service_ms"] + s2["jitter_ms"] / 2) / 1000
    expected = analytic_stall_p99(job["rate"], job["duration"], s2["stall_for"], service=service)
    got = res["latency"].get("p99")
    notes = [f"percentiles from: {res['quantiles']}"]
    if job["role"] == "control":
        tol = CRITERIA["v4_control"] * expected
        return [_check("the closed-loop control reports far below the analytic p99", got,
                       expected, got is not None and got <= tol, tol)], notes + [
            "pass means the control behaved as a closed-loop tool does, so the test can tell"]
    tol = CRITERIA["v4_rel"] * expected
    want = job["rate"] * s2["stall_for"]
    in_stall = origin["arrivals_in_stall"]
    return [_check("reported p99 against the analytic value", got, expected,
                   got is not None and abs(got - expected) <= tol, tol),
            _check("arrivals during the stall (the tool kept sending)", in_stall, want,
                   _rel(in_stall, want) <= CRITERIA["v4_stall_arrivals"],
                   CRITERIA["v4_stall_arrivals"])], notes


def _v5(job, res, origin):
    n, tol = job["rate"] * job["duration"], CRITERIA["v5_rate"]
    arrivals, dropped = origin["arrivals"], res["dropped"]
    ok = arrivals >= (1 - tol) * n or arrivals + dropped >= (1 - tol) * n
    return [_check("arrivals follow the intended rate, or the tool reports the difference",
                   arrivals, n, ok, tol)], [
        f"tool-reported drops: {dropped}", f"silent shortfall: {max(0, n - arrivals - dropped):g}",
        f"tool errors: {res['errors']}"]


def _v6(job, res, origin):
    truth = origin["status"].get("503", 0)
    tol = max(CRITERIA["v6_abs"], CRITERIA["v6_rel"] * truth)
    return [_check("non-2xx the tool counted against the 503s the origin sent", res["non2xx"],
                   truth, abs(res["non2xx"] - truth) <= tol, tol),
            _check("requests the tool counted against the origin's arrivals", res["requests"],
                   origin["arrivals"],
                   _rel(res["requests"], origin["arrivals"]) <= CRITERIA["v6_rel"],
                   CRITERIA["v6_rel"])], []


def _load_cpu(res):
    """CPU seconds of the load step; for runs that did not separate it, of all the steps."""
    extra = res.get("extra") or {}
    cpu = extra.get("load_cpu_s")
    if cpu is None and extra.get("children_cpu_s"):
        cpu = extra["children_cpu_s"]["user"] + extra["children_cpu_s"]["system"]
    return cpu


def _v7(job, res, origin):
    n, tol = job["rate"] * job["duration"], CRITERIA["v7_rate"]
    cpu_s = _load_cpu(res)
    notes = ([f"CPU per 1000 requests: {cpu_s / (res['requests'] / 1000):.3f} s"]
             if cpu_s is not None and res["requests"] else [])
    return [_check("requests the origin counted", origin["requests"], n,
                   _rel(origin["requests"], n) <= tol, tol),
            _check("no tool errors and no non-2xx", res["errors"] + res["non2xx"], 0,
                   res["errors"] + res["non2xx"] == 0)], notes


EVALUATORS = {"V1": _v1, "V2": _v2, "V3": _v3, "V4": _v4, "V5": _v5, "V6": _v6, "V7": _v7}


def evaluate(job, res, origin):
    """The verdict of one job from its parameters (a dict), the tool's parsed result and the
    origin's summary."""
    checks, notes = EVALUATORS[job["test"]](job, res, origin)
    extra = res.get("extra") or {}
    raised = sorted(k for k, v in (extra.get("flags") or {}).items() if v)
    if raised:
        notes = [*notes, "the tool's own validity flags: " + ", ".join(raised)]
    sock = origin.get("sockets") or {}
    if sock.get("settled") is False:
        notes = [*notes, (f"started with {sock['tw_start']} sockets in TIME_WAIT (limit "
                          f"{sock['limit']}) after waiting {sock['waited_s']:g} s")]
    if any("cannot assign requested address" in str(e) for e in extra.get("error_set") or []):
        notes = [*notes, ("ephemeral ports were exhausted (the tool reported 'cannot assign "
                          "requested address')")]
    metrics = {}
    cpu_s = _load_cpu(res)
    if cpu_s is not None and res["requests"]:
        metrics["cpu_per_1000"] = cpu_s / (res["requests"] / 1000)
    return {"key": job["key"], "test": job["test"], "tool": job["tool"], "role": job["role"],
            "rate": job["rate"], "repeat": job["repeat"], "pass": all(c["pass"] for c in checks),
            "checks": checks, "notes": notes, "metrics": metrics}


def summarise(evals, tools_info):
    """Per tool: the verdict of every test, the V7 ceiling, and the status the results suggest.
    The manifest is edited by hand; nothing here writes it."""
    out = {}
    for tool in sorted({e["tool"] for e in evals} | set(tools_info)):
        mine = [e for e in evals if e["tool"] == tool]
        tests = {}
        for tid in TESTS:
            es = [e for e in mine if e["test"] == tid]
            if not es:
                continue
            if any("error" in e for e in es):
                tests[tid] = {"verdict": "error", "jobs": len(es)}
            elif tid == "V7":
                tests[tid] = {"verdict": "measured", "jobs": len(es), **_ceiling(es)}
            elif es[0]["role"] == "control":
                tests[tid] = {"verdict": "control ok" if all(e["pass"] for e in es)
                              else "control NOT as expected", "jobs": len(es)}
            else:
                tests[tid] = {"verdict": "pass" if all(e["pass"] for e in es) else "fail",
                              "jobs": len(es)}
        info = tools_info.get(tool, {})
        v0 = info.get("v0_ok")
        verdicts = {t: v["verdict"] for t, v in tests.items()}
        if v0 is False or "error" in verdicts.values():
            suggested, why = "error", "V0 failed or a job could not run"
        elif tool == "wrk":
            suggested, why = "control", "closed-loop negative control"
        elif not all(t in verdicts for t in ("V1", "V2")):
            suggested, why = "incomplete", "V1 and V2 were not both run"
        elif any(verdicts[t] != "pass" for t in ("V1", "V2")):
            suggested, why = "unfit", "failed V1 or V2"
        else:
            suggested, why = "verified", ""
        restrictions = [r for t, r in (("V3", "no latency claims"),
                                       ("V4", "no latency claims under stalls"),
                                       ("V5", "no overload claims"),
                                       ("V6", "no error-rate claims")) if verdicts.get(t) == "fail"]
        out[tool] = {"tests": tests, "v0_ok": v0, "suggested_status": suggested,
                     "restrictions": restrictions, "why": why}
    return out


def _ceiling(es):
    """Highest rate such that it and every lower one counted the intended requests with no
    errors, and the CPU cost per 1000 requests at each rate."""
    ceiling = None
    for e in sorted(es, key=lambda e: e["rate"]):
        if not e["pass"]:
            break
        ceiling = e["rate"]
    return {"ceiling": ceiling, "cpu_per_1000": {f"{e['rate']:g}": e["metrics"].get("cpu_per_1000")
                                                 for e in sorted(es, key=lambda e: e["rate"])}}


# --- running a job -------------------------------------------------------------------------

def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")


def read_json(path):
    with open(path) as f:
        return json.load(f)


# TIME_WAIT sockets tolerated at the start of a job, and how long to wait for fewer: a sixth of the
# 28 232 ephemeral ports (32768-60999), so that the residue of one job plus the 5000 connections
# of the largest cannot exhaust them
TW_LIMIT, TW_WAIT_S = 5000, 90
GATE = {"uptime_s": 1800, "load1": 0.3}   # the environment gate of the design (7.2, step 0)


def timewait_count(text=None):
    """Sockets in TIME_WAIT: the "tw" of the TCP line of /proc/net/sockstat."""
    if text is None:
        with open("/proc/net/sockstat") as f:
            text = f.read()
    for line in text.splitlines():
        if line.startswith("TCP:"):
            words = line.split()
            return int(words[words.index("tw") + 1])
    raise ValueError("no TCP line in /proc/net/sockstat")


def load_cpu(tool, res, prov):
    """CPU seconds of the load step of a run: the engine's own figure for its run, else the
    first step of the provenance (vegeta's attack, the single step of k6 and wrk), else all."""
    if tool == "loadgen":
        return ((res.get("extra") or {}).get("cpu") or {}).get("process_s")
    steps = prov.get("steps") or []
    if steps and "cpu_s" in steps[0]:
        return steps[0]["cpu_s"]["user"] + steps[0]["cpu_s"]["system"]
    c = prov.get("children_cpu_s")
    return c["user"] + c["system"] if c else None


def read_uptime():
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def read_load1():
    with open("/proc/loadavg") as f:
        return float(f.read().split()[0])


def wait_for_gate(wait_min, read_up=None, read_load=None, sleep=time.sleep, clock=time.monotonic,
                  say=None):
    """The environment gate of the design: up at least 30 minutes, 1-minute load below 0.3.
    Waits up to `wait_min` minutes for it; returns what was seen and whether it was met."""
    read_up, read_load = read_up or read_uptime, read_load or read_load1
    say = say or (lambda m: print(m, flush=True))
    t0, told = clock(), False
    while True:
        up, load = read_up(), read_load()
        met = up >= GATE["uptime_s"] and load < GATE["load1"]
        waited = clock() - t0
        if met or waited >= wait_min * 60:
            return {"met": met, "uptime_s": up, "load1": load, "waited_s": round(waited, 1),
                    "limit_uptime_s": GATE["uptime_s"], "limit_load1": GATE["load1"]}
        if not told:
            say(f"gate: uptime {up:.0f} s, load {load:.2f}; waiting up to {wait_min:g} min for "
                f"uptime {GATE['uptime_s']} s and load below {GATE['load1']}")
            told = True
        sleep(20)


class RealEnv:
    """The real environment: Nginx and S2 on loopback, the tools through bench/loadtools.py."""

    def __init__(self, manifest, root=None):
        self.manifest, self.root = manifest, root

    def tools_info(self, tools):
        info = {}
        for tool in tools:
            entry = {"status": self.manifest["tools"][tool]["status"]}
            try:
                LT.resolve_tool(self.manifest, tool, self.root, allow_unverified=True)
                out, ok = LT.probe_version(self.manifest, tool, self.root)
                entry.update(hash_ok=True, version_output=out, version_ok=ok, v0_ok=ok)
            except LT.ToolError as exc:
                entry.update(hash_ok=False, error=str(exc), v0_ok=False)
            entry["sha256"] = self.manifest["tools"][tool]["sha256"]
            entry["pinned_version"] = self.manifest["tools"][tool]["version"]
            info[tool] = entry
        return info

    def origin(self, job, workdir):
        if job.origin == "s1":
            return Nginx(workdir)
        return S2Process(workdir, dict(job.s2))

    def settle(self, limit=TW_LIMIT, max_wait=TW_WAIT_S, read=None, sleep=time.sleep,
               clock=time.monotonic):
        """Wait until fewer than `limit` sockets are in TIME_WAIT, so that a job does not start
        while the ephemeral ports of the one before are still held; at most `max_wait` s."""
        read = read or self.timewait
        t0 = clock()
        first = last = read()
        while last >= limit and clock() - t0 < max_wait:
            sleep(2)
            last = read()
        return {"tw_first": first, "tw_start": last, "limit": limit,
                "waited_s": round(clock() - t0, 1), "settled": last < limit}

    def timewait(self):
        try:
            return timewait_count()
        except (OSError, ValueError) as exc:
            raise InfraError(f"cannot read the TIME_WAIT sockets: {exc}") from exc

    def launch(self, job, url, workdir):
        plan = LT.build_plan(job.tool, spec_for(job, url), workdir, self.manifest, self.root,
                             allow_unverified=True)
        prov = LT.run_plan(plan)
        if not prov["ok"]:
            raise LT.ToolError(f"{job.tool} failed: {[s['returncode'] for s in prov['steps']]}")
        return LT.parse_dir(job.tool, workdir), prov


RAW = ("vegeta.bin", "vegeta.csv", "vegeta.targets", "loadgen.records.csv.gz")


def run_job(env, job, out_dir, keep_raw=False):
    """Run one job and return its evaluation, or {"key", "error"} when the tool failed.
    An InfraError propagates: the origin is part of the instrument."""
    wd = os.path.join(out_dir, *job.key.split("/"))
    os.makedirs(wd, exist_ok=True)
    write_json(os.path.join(wd, "job.json"), job.as_dict())
    settle = getattr(env, "settle", None)
    sockets = settle() if settle else {}
    try:
        with env.origin(job, wd) as origin:
            result, prov = env.launch(job, origin.url, wd)
            summary = origin.finish()
    except LT.ToolError as exc:
        write_json(os.path.join(wd, "error.json"), {"error": str(exc)})
        return {"key": job.key, "test": job.test, "tool": job.tool, "role": job.role,
                "rate": job.rate, "repeat": job.repeat, "error": str(exc), "pass": False,
                "checks": [], "notes": [], "metrics": {}}
    res = result.to_dict()
    res["extra"]["children_cpu_s"] = prov["children_cpu_s"]
    res["extra"]["load_cpu_s"] = load_cpu(job.tool, res, prov)
    if settle:
        sockets["tw_end"] = env.timewait()
        summary["sockets"] = sockets
    write_json(os.path.join(wd, "tool_result.json"), res)
    write_json(os.path.join(wd, "origin.json"), summary)
    if not keep_raw:
        for name in RAW:
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(wd, name))
    return evaluate(job.as_dict(), res, summary)


def reanalyse_job(wd):
    """The evaluation of a job directory, from the files a run left."""
    job = read_json(os.path.join(wd, "job.json"))
    if os.path.exists(os.path.join(wd, "error.json")):
        return {"key": job["key"], "test": job["test"], "tool": job["tool"], "role": job["role"],
                "rate": job["rate"], "repeat": job["repeat"],
                "error": read_json(os.path.join(wd, "error.json"))["error"], "pass": False,
                "checks": [], "notes": [], "metrics": {}}
    return evaluate(job, read_json(os.path.join(wd, "tool_result.json")),
                    read_json(os.path.join(wd, "origin.json")))


# --- the results directory -----------------------------------------------------------------

def fmt(x):
    if x is None:
        return "-"
    if isinstance(x, bool):
        return "yes" if x else "no"
    if isinstance(x, float):
        return f"{x:.4g}"
    return str(x)


def timer_lines(env):
    out = []
    for label, key in (("before", "timer"), ("after", "timer_after")):
        t = env.get(key)
        if t:
            warn = " **above the limit: schedules will slip**" if t["p99_ms"] > TIMER_WARN_MS else ""
            out.append(f"* Timer wake-up lateness {label} the run (sleep {t['interval_s'] * 1e3:g} ms, "
                       f"{t['samples']} samples): p50 {t['p50_ms']:.1f} ms, p99 {t['p99_ms']:.1f} ms, "
                       f"max {t['max_ms']:.1f} ms.{warn}")
    return out


def gate_lines(env):
    g = env.get("gate")
    if not g:
        return []
    if g.get("skipped"):
        return ["* Environment gate: **skipped** (--no-gate)."]
    return [f"* Environment gate (up at least {g['limit_uptime_s']:g} s, load below "
            f"{g['limit_load1']:g}): uptime {g['uptime_s']:.0f} s, load {g['load1']:.2f}, waited "
            f"{g['waited_s']:g} s: " + ("met." if g["met"] else "**not met**.")]


def render_readme(results):
    s, env = results["summary"], results["environment"]
    lines = ["# Verification of the HTTP load generators (V0-V7)", "",
             ("Produced by `bench/loadtool_validate.py` against loopback origins; the tests and "
              "the pass criteria are in `docs/BENCHMARK_HARM_DESIGN.md`, 8.4. The criteria are "
              "constants of that script, fixed before any measurement."), "",
             (f"* Commit: `{env.get('git_commit')}` (dirty: {fmt(env.get('git_dirty'))}); "
              f"host: {env.get('uname')}; created {env.get('created_utc')}."),
             *gate_lines(env), *timer_lines(env), "",
             "## Verdict per tool and test", "",
             "| Tool | V0 | " + " | ".join(TESTS) + " | Suggested status |",
             "|---|---|" + "---|" * len(TESTS) + "---|"]
    for tool, v in s.items():
        cells = [v["tests"].get(t, {}).get("verdict", "n.a.") for t in TESTS]
        status = v["suggested_status"] + (f" ({'; '.join(v['restrictions'])})"
                                          if v["restrictions"] else "")
        lines.append(f"| {tool} | {fmt(v['v0_ok'])} | " + " | ".join(cells) + f" | {status} |")
    lines += ["", ("`control ok` means the closed-loop control failed the stall test the way a "
                   "closed-loop tool should. The manifest (`bench/loadtools.json`) is edited by "
                   "hand from these suggestions; nothing here writes it."),
              "", "## V7: ceiling and cost", "",
              "| Tool | Highest rate held (requests/s) | CPU s per 1000 requests (load step), by rate |",
              "|---|---|---|"]
    for tool, v in s.items():
        t = v["tests"].get("V7")
        if t and t["verdict"] == "measured":
            cpu = ", ".join(f"{r}: {fmt(c)}" for r, c in t["cpu_per_1000"].items())
            lines.append(f"| {tool} | {fmt(t['ceiling'])} | {cpu} |")
    lines += ["", "## Checks", "", "| Job | Check | Observed | Expected | Tolerance | Pass |",
              "|---|---|---|---|---|---|"]
    for e in results["jobs"]:
        if "error" in e:
            lines.append(f"| {e['key']} | **did not run** | {e['error']} | | | no |")
            continue
        for c in e["checks"]:
            lines.append(f"| {e['key']} | {c['name']} | {fmt(c['observed'])} | "
                         f"{fmt(c['expected'])} | {fmt(c['tolerance'])} | {fmt(c['pass'])} |")
    notes = [(e["key"], n) for e in results["jobs"] for n in e.get("notes", [])]
    if notes:
        lines += ["", "## Notes", ""] + [f"* `{k}`: {n}" for k, n in notes]
    lines += ["", "## Tools", "", "| Tool | Pinned version | Printed | Manifest status | sha256 |",
              "|---|---|---|---|---|"]
    for tool, i in results["tools"].items():
        printed = (i.get("version_output") or i.get("error") or "").splitlines()
        lines.append(f"| {tool} | {i.get('pinned_version')} | {printed[0] if printed else '-'} | "
                     f"{i.get('status')} | `{i.get('sha256', '')[:16]}...` |")
    return "\n".join(lines) + "\n"


def tree_hashes(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            if rel != "SHA256SUMS":
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return dict(sorted(out.items()))


def finalize(out_dir, evals, tools_info, environment):
    """Write results.json, README.md and SHA256SUMS of a results directory."""
    evals = sorted(evals, key=lambda e: (e["test"], e["tool"], e["rate"], e["repeat"]))
    results = {"schema": 1, "environment": environment, "criteria": CRITERIA,
               "tools": tools_info, "jobs": evals, "summary": summarise(evals, tools_info)}
    write_json(os.path.join(out_dir, "results.json"), results)
    with open(os.path.join(out_dir, "README.md"), "w") as f:
        f.write(render_readme(results))
    with open(os.path.join(out_dir, "SHA256SUMS"), "w") as f:
        f.writelines(f"{h}  {rel}\n" for rel, h in tree_hashes(out_dir).items())
    return results


def timer_lateness(samples=200, interval=0.01):
    """How late the OS wakes this process from time.sleep(interval), in ms. A VM whose idle
    vCPUs wake late makes every open-loop schedule slip, whatever the tool: read the verdicts
    of a run together with this."""
    late = []
    for _ in range(samples):
        t0 = time.monotonic()
        time.sleep(interval)
        late.append(max(0.0, time.monotonic() - t0 - interval))
    late.sort()
    return {"interval_s": interval, "samples": samples, "p50_ms": LT.quantile(late, .5) * 1e3,
            "p99_ms": LT.quantile(late, .99) * 1e3, "max_ms": late[-1] * 1e3}


TIMER_WARN_MS = 10.0                      # p99 above this: schedules of any tool will slip


def environment(timer=True, gate=None):
    def git(*a):
        try:
            cp = subprocess.run(["git", "-C", REPO, *a], capture_output=True, text=True,
                                timeout=10, check=False)
            return cp.stdout.strip() if cp.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None
    dirty = git("status", "--porcelain", "--untracked-files=no")
    return {"created_utc": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "uname": " ".join(platform.uname()), "cpus": os.cpu_count(),
            "python": sys.version.split()[0], "git_commit": git("rev-parse", "HEAD"),
            "git_dirty": None if dirty is None else bool(dirty),
            "gate": gate, "timer": timer_lateness() if timer else None}


def run_all(env, jobs, out_dir, tools_info, keep_raw=False, stop_on_error=False):
    """Run the jobs of tools whose V0 passed, in order; returns the evaluations."""
    evals = []
    for job in jobs:
        if tools_info.get(job.tool, {}).get("v0_ok") is False:
            evals.append({"key": job.key, "test": job.test, "tool": job.tool, "role": job.role,
                          "rate": job.rate, "repeat": job.repeat, "pass": False, "checks": [],
                          "notes": [], "metrics": {},
                          "error": f"V0 failed for {job.tool}: not run"})
            continue
        e = run_job(env, job, out_dir, keep_raw)
        evals.append(e)
        print(f"[{'+' if e['pass'] else '-'}] {job.key}" + (f"  {e['error']}" if "error" in e else ""),
              flush=True)
        if stop_on_error and "error" in e:
            break
    return evals


# --- command line --------------------------------------------------------------------------

def _csv(text, universe):
    if not text:
        return None
    items = [x.strip() for x in text.split(",") if x.strip()]
    bad = [x for x in items if x not in universe]
    if bad:
        raise SystemExit(f"[-] unknown {bad}; known: {', '.join(universe)}")
    return items


def serve_s2(a):
    origin = ScriptedOrigin(**json.loads(a.params))

    async def main():
        server = await origin.start(HOST, a.port)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        server.close()

    asyncio.run(main())
    origin.dump(a.log)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    tools_all = sorted({t for v in TESTS.values() for t in v["tools"]})
    for name in ("plan", "run"):
        s = sub.add_parser(name)
        s.add_argument("--tools", help=f"comma list of {', '.join(tools_all)} (default all)")
        s.add_argument("--tests", help=f"comma list of {', '.join(TESTS)} (default all)")
        s.add_argument("--manifest", default=LT.MANIFEST)
        s.add_argument("--root", default=None)
        if name == "run":
            s.add_argument("--out", required=True, help="new results directory")
            s.add_argument("--yes", action="store_true", help="confirm: this generates load")
            s.add_argument("--keep-raw", action="store_true")
            s.add_argument("--stop-on-error", action="store_true")
            s.add_argument("--gate-wait", type=float, default=60.0,
                           help="minutes to wait for the environment gate (default 60)")
            s.add_argument("--no-gate", action="store_true",
                           help="skip the environment gate; the README says so")
    s = sub.add_parser("reanalyse", help="re-evaluate a results directory, offline")
    s.add_argument("dir")
    s = sub.add_parser("serve-s2", help="the S2 origin process (started by run)")
    s.add_argument("--port", type=int, default=S2_PORT)
    s.add_argument("--log", required=True)
    s.add_argument("--params", default="{}")
    a = ap.parse_args(argv)

    if a.cmd == "serve-s2":
        return serve_s2(a)
    if a.cmd == "reanalyse":
        evals = [reanalyse_job(d) for d in
                 sorted(d for d, _, files in os.walk(a.dir) if "job.json" in files)]
        prev = read_json(os.path.join(a.dir, "results.json"))
        finalize(a.dir, evals, prev["tools"], prev["environment"])
        print(f"[+] re-evaluated {len(evals)} jobs in {a.dir}")
        return 0

    tools = _csv(a.tools, tools_all)
    tests = _csv(a.tests, list(TESTS))
    jobs = expand(tools, tests)
    manifest = LT.load_manifest(a.manifest)
    if a.cmd == "plan":
        for job in jobs:
            wd = "/OUT/" + job.key
            print(f"{job.key}: origin {job.origin} {job.role} limits {dict(job.limits)}")
            origin = Nginx(wd) if job.origin == "s1" else S2Process(wd, dict(job.s2))
            print("    origin: " + " ".join(origin.command()))
            plan = LT.build_plan(job.tool, spec_for(job, origin.url), wd, manifest, a.root,
                                 allow_unverified=True, check=False)
            for step in plan.steps:
                print("    " + " ".join(step.argv))
        print(f"{len(jobs)} jobs, {sum(j.duration for j in jobs) / 60:.1f} minutes of load")
        return 0

    if not a.yes:
        print("[-] run generates load on loopback; read `plan`, get approval, pass --yes",
              file=sys.stderr)
        return 2
    if os.path.exists(a.out) and os.listdir(a.out):
        print(f"[-] {a.out} exists and is not empty; results are never overwritten",
              file=sys.stderr)
        return 2
    if shutil.which("nginx") is None or shutil.which("taskset") is None:
        print("[-] nginx and taskset are needed", file=sys.stderr)
        return 2
    gate = {"skipped": True} if a.no_gate else wait_for_gate(a.gate_wait)
    if not gate.get("skipped") and not gate["met"]:
        print(f"[-] environment gate not met: uptime {gate['uptime_s']:.0f} s (need "
              f"{GATE['uptime_s']}), load {gate['load1']:.2f} (need below {GATE['load1']}); "
              "wait, or pass --no-gate", file=sys.stderr)
        return 2
    os.makedirs(a.out, exist_ok=True)
    env_before = environment(gate=gate)
    env = RealEnv(manifest, a.root)
    tools_info = env.tools_info(sorted({j.tool for j in jobs}))
    write_json(os.path.join(a.out, "tools.json"), tools_info)
    shutil.copy(a.manifest, os.path.join(a.out, "loadtools.manifest.json"))
    try:
        evals = run_all(env, jobs, a.out, tools_info, a.keep_raw, a.stop_on_error)
    except InfraError as exc:
        print(f"[-] stopped: {exc}", file=sys.stderr)
        return 1
    finalize(a.out, evals, tools_info, {**env_before, "timer_after": timer_lateness()})
    print(f"[+] {a.out}/README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
